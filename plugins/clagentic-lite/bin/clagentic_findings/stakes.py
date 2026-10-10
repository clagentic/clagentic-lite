"""The stakes profile.

What is at stake on a path is not something a model can see in a diff: whether
it is served to the internet or only to staff behind SSO, whether it handles
customer data, who can merge to it. That is recorded, optionally, in one
committed file, .clagentic/risk-profile.json, and read here in code. The file
is optional and agent-maintained (the `profile` command drafts and updates it
from the tree and the operator's answers, as a reviewable change); it cannot
apply itself (the version at the merge base is the one that counts, exactly as
for dispositions); an unstated dimension means the worst case, so an absent
profile changes nothing; and a claim the tree contradicts in the unsafe
direction is ignored, loudly.
"""
import json

from .dates import parse_date
from .fileio import dumps, positive_int_env
from .gitstate import git_reader, is_repo_toplevel, worktree_reader
from .globs import compile_glob, glob_match_compiled
from .infer import changed_paths, infer_markers, touches_exposure_surface
from .paths import norm_path
from .rubric import DIMENSIONS, WORST_DIMS, worse_value, worst_dims
from .sanitize import UNSAFE_RE, terminal_text

PROFILE_REL = ".clagentic/risk-profile.json"
PROFILE_SCHEMA = 1
PROFILE_MAX_ENTRIES = 500
PROFILE_DEFAULT_MAX_AGE_DAYS = 180
CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", ".gitea/CODEOWNERS", ".forgejo/CODEOWNERS",
                        ".gitlab/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
_PROFILE_ENTRY_KEYS = ("glob", "inferred", "evidence", "note")


def parse_profile(text):
    """(profile, problems) for the text of a risk profile. PROFILE is None when
    the text cannot be used at all; otherwise it holds the repo-wide 'default'
    dimensions, the per-glob 'entries' [(glob, dims)] and 'confirmed_at'. A
    dimension with a value outside its vocabulary is set to its worst case (and
    reported), so a typo can only ever make the profile stricter."""
    problems = []
    try:
        document = json.loads(text)
    except ValueError as exc:
        return None, ["is not valid JSON: %s" % exc]
    if not isinstance(document, dict):
        return None, ["is not a JSON object"]

    def read_dims(container, label):
        found = {}
        for dimension, allowed in DIMENSIONS.items():
            if dimension not in container:
                continue
            value = container[dimension]
            if isinstance(value, str) and value.strip().lower() in allowed:
                found[dimension] = value.strip().lower()
            else:
                found[dimension] = WORST_DIMS[dimension]
                problems.append("%s: %s=%s is not one of %s; the worst case (%s) applies" % (
                    label, dimension, terminal_text(dumps(value), 60), ", ".join(allowed),
                    WORST_DIMS[dimension]))
        return found

    raw_default = document.get("default", {})
    if not isinstance(raw_default, dict):
        problems.append("'default' is not an object; ignored (unstated dimensions are the worst case)")
        raw_default = {}
    default = read_dims(raw_default, "default")
    raw_paths = document.get("paths", [])
    if not isinstance(raw_paths, list):
        problems.append("'paths' is not an array; ignored")
        raw_paths = []
    if len(raw_paths) > PROFILE_MAX_ENTRIES:
        problems.append("more than %d 'paths' entries; the rest are ignored" % PROFILE_MAX_ENTRIES)
    entries = []
    for index, item in enumerate(raw_paths[:PROFILE_MAX_ENTRIES]):
        label = "paths[%d]" % index
        if not isinstance(item, dict):
            problems.append("%s is not an object; ignored" % label)
            continue
        glob = item.get("glob")
        if (not isinstance(glob, str) or not glob.strip() or len(glob) > 500
                or UNSAFE_RE.search(glob)):
            problems.append("%s has no usable 'glob'; ignored" % label)
            continue
        dims = read_dims(item, label)
        if not dims:
            problems.append("%s states no dimension; ignored" % label)
            continue
        entries.append((glob.strip(), dims))
    confirmed = document.get("confirmed_at")
    return {"default": default, "entries": entries,
            "confirmed_at": confirmed if isinstance(confirmed, str) else None}, problems


def codeowners_globs(pattern):
    """The path globs a CODEOWNERS pattern covers: an unanchored name matches at
    any depth, a name with a slash is anchored to the root, a trailing slash or
    a plain name covers everything under it."""
    anchored = pattern.startswith("/")
    body = pattern.lstrip("/")
    is_dir = body.endswith("/")
    body = body.rstrip("/")
    if not body:
        return []
    if "/" in body:
        anchored = True
    base = body if anchored else "**/" + body
    if is_dir:
        return [base + "/**"]
    globs = [base]
    if not any(char in body for char in "*?"):
        globs.append(base + "/**")
    return globs


class Codeowners(object):
    """CODEOWNERS rules. covers(path) is true when the last rule matching the
    path names at least one owner, the way the git hosts read the file."""

    def __init__(self, texts):
        self.rules = []
        for text in texts:
            for line in text.splitlines()[:5000]:
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("[") or line.startswith("^["):
                    continue
                parts = line.split()
                globs = [compile_glob(glob) for glob in codeowners_globs(parts[0])]
                if globs:
                    self.rules.append((globs, len(parts) > 1))

    def covers(self, path):
        owned = False
        for globs, has_owner in self.rules:
            if any(glob_match_compiled(compiled, path) for compiled in globs):
                owned = has_owner
        return owned


class Stakes(object):
    """The stakes in force for one run: the profile read at the merge base, the
    markers inferred from the tree, and the warnings and notes about both. With
    no profile present it is inert: every path resolves to the worst case."""

    def __init__(self):
        self.present = False
        self.default = {}
        self.entries = []
        self.markers = []
        self.codeowners = None
        self.warnings = []
        self.notes = []
        self.confirmed_at = None
        self._warned = set()

    def warn_once(self, message):
        if message not in self._warned:
            self._warned.add(message)
            self.warnings.append(message)

    def dims_for(self, path):
        """{dimension: (value, where it came from)} for the repo path PATH."""
        path = norm_path(path)
        if not self.present:
            return worst_dims()
        dims, stated = {}, {}
        for dimension in DIMENSIONS:
            value, via, claimed = WORST_DIMS[dimension], "no profile statement", False
            hits = [(glob, dims_[dimension]) for glob, compiled, dims_ in self.entries
                    if dimension in dims_ and glob_match_compiled(compiled, path)]
            if hits:
                glob, value = hits[0]
                for other_glob, other in hits[1:]:
                    if worse_value(dimension, other, value) != value:
                        glob, value = other_glob, other
                via, claimed = glob, True
            elif dimension in self.default:
                value, via, claimed = self.default[dimension], "the repo-wide default", True
            dims[dimension], stated[dimension] = (value, via), claimed
        self._apply_inference(path, dims, stated)
        self._apply_codeowners(path, dims)
        return dims

    def _apply_inference(self, path, dims, stated):
        # A path the profile says nothing about on exposure, and which is a
        # test path, is not served: the one inference that LOWERS, and only
        # where an operator has opted in by keeping a profile at all.
        if not stated["exposure"] and is_test_path(path):
            dims["exposure"] = ("local_or_ci_only", "tree inference (a test path)")
        for marker in self.markers:
            if not glob_match_compiled(marker["compiled"], path):
                continue
            current, _ = dims[marker["dimension"]]
            if worse_value(marker["dimension"], marker["value"], current) != current:
                dims[marker["dimension"]] = (marker["value"], "tree inference (%s)" % marker["why"])

    def _apply_codeowners(self, path, dims):
        value, via = dims["merge_control"]
        if value != "code_owner_review_required":
            return
        if self.codeowners is None:
            self.warn_once("the profile claims merge_control=code_owner_review_required but no "
                           "CODEOWNERS file exists in any conventional location (%s); the claim is "
                           "ignored and the worst case applies"
                           % ", ".join(CODEOWNERS_LOCATIONS))
        elif self.codeowners.covers(path):
            return
        else:
            self.warn_once("the profile claims merge_control=code_owner_review_required for %s but "
                           "no CODEOWNERS rule with an owner covers %s; the claim is ignored and the "
                           "worst case applies there" % (via, terminal_text(path, 120)))
        dims["merge_control"] = (WORST_DIMS["merge_control"], "CODEOWNERS does not cover the path")


def is_test_path(path):
    parts = path.split("/")
    name = parts[-1]
    if any(part in ("test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata")
           for part in parts[:-1]):
        return True
    return (name.startswith("test_") or "_test." in name or ".test." in name
            or ".spec." in name)


def _codeowners_texts(root, base):
    """The CODEOWNERS files at BASE (the version the merge will be judged by),
    or None when there are none. A change that adds one cannot support a claim
    in the same change."""
    reader = git_reader(root, base) if base else worktree_reader(root)
    texts = []
    for rel in CODEOWNERS_LOCATIONS:
        try:
            text = reader(rel)
        except (OSError, ValueError):
            continue
        if text is not None:
            texts.append(text)
    return texts or None


def load_stakes(root, base, today, max_age_days=None):
    """The Stakes for a run: the risk profile as of BASE, inference over the
    tree, CODEOWNERS coverage, and the re-confirmation warnings (a profile older
    than MAX_AGE_DAYS, else the environment's, else 180). Returns an inert
    Stakes when there is no usable profile; never raises."""
    stakes = Stakes()
    try:
        work_text = worktree_reader(root)(PROFILE_REL)
    except (OSError, ValueError) as exc:
        stakes.warnings.append("%s cannot be read from the working tree (%s)" % (PROFILE_REL, exc))
        work_text = None
    # A directory inside some other repository's work tree is not a repository
    # of its own: a base resolved there names the ancestor's commit, and a
    # profile read at it would be the ancestor's, deciding this tree's severity.
    if base and not is_repo_toplevel(root):
        base = None
    base_text, base_failed = None, False
    if base:
        try:
            base_text = git_reader(root, base)(PROFILE_REL)
        except (OSError, ValueError) as exc:
            stakes.warnings.append("%s cannot be read at the base commit (%s); no profile applies"
                                   % (PROFILE_REL, exc))
            base_failed = True
    elif work_text is not None:
        stakes.warnings.append(
            "%s exists but the base commit could not be resolved; the profile is ignored (a profile "
            "applies only as of the merge base) and the worst case applies" % PROFILE_REL)
        return stakes
    if base_failed:
        return stakes
    if base_text is None:
        if work_text is not None:
            stakes.notes.append("%s is not in the base commit; it applies once it is merged, and "
                                "the worst case applies to this change" % PROFILE_REL)
        return stakes
    if work_text != base_text:
        stakes.notes.append("%s differs from its base version in this change; the base version "
                            "applies to this change" % PROFILE_REL)
    profile, problems = parse_profile(base_text)
    for problem in problems:
        stakes.warnings.append("%s %s" % (PROFILE_REL, terminal_text(problem, 300)))
    if profile is None:
        return stakes
    stakes.present = True
    stakes.default = profile["default"]
    stakes.entries = [(glob, compile_glob(glob), dims) for glob, dims in profile["entries"]]
    stakes.confirmed_at = profile["confirmed_at"]
    stakes.codeowners = None
    texts = _codeowners_texts(root, base)
    if texts:
        stakes.codeowners = Codeowners(texts)
    stakes.markers, inference_notes = infer_markers(root)
    stakes.notes.extend(inference_notes)
    _warn_contradictions(stakes)
    _warn_reconfirmation(stakes, root, base, today, max_age_days)
    return stakes


def _warn_contradictions(stakes):
    """A claim the tree contradicts in the unsafe direction is ignored. Say so
    once per marker, naming both sides."""
    for marker in stakes.markers:
        probe = marker["file"]
        dims = {}
        stated = False
        for glob, compiled, entry in stakes.entries:
            if marker["dimension"] in entry and glob_match_compiled(compiled, probe):
                dims[glob] = entry[marker["dimension"]]
                stated = True
        if not stated and marker["dimension"] in stakes.default:
            dims["the repo-wide default"] = stakes.default[marker["dimension"]]
        for where, claimed in dims.items():
            if worse_value(marker["dimension"], marker["value"], claimed) != claimed:
                stakes.warn_once(
                    "the profile claims %s=%s for %s but the tree contradicts it (%s); the claim is "
                    "ignored and %s=%s applies there"
                    % (marker["dimension"], claimed, terminal_text(where, 120),
                       terminal_text(marker["why"], 200), marker["dimension"], marker["value"]))


def _warn_reconfirmation(stakes, root, base, today, max_age_days=None):
    if isinstance(max_age_days, int) and not isinstance(max_age_days, bool) and max_age_days > 0:
        max_age = max_age_days
    else:
        max_age = positive_int_env("CLAGENTIC_RISK_PROFILE_MAX_AGE_DAYS", PROFILE_DEFAULT_MAX_AGE_DAYS)
    confirmed = parse_date(stakes.confirmed_at) if stakes.confirmed_at else None
    if confirmed is None:
        stakes.warnings.append("the risk profile has no valid confirmed_at date; re-confirm it with "
                               "'findings.py profile' (clagentic-lite gates profile)")
    elif (today - confirmed).days > max_age:
        stakes.warnings.append("the risk profile was last confirmed on %s, more than %d days ago; "
                               "re-confirm it with 'findings.py profile' (clagentic-lite gates profile)"
                               % (confirmed.isoformat(), max_age))
    marker_files = {marker["file"] for marker in stakes.markers}
    touched = changed_paths(root, base, lambda p: touches_exposure_surface(p, marker_files))
    if touched:
        stakes.warnings.append(
            "this change touches the exposure surface (%d path(s): %s); re-confirm the risk profile "
            "with 'findings.py profile' (clagentic-lite gates profile). This is a prompt, not a block."
            % (len(touched), ", ".join(terminal_text(p, 80) for p in touched[:5])))
