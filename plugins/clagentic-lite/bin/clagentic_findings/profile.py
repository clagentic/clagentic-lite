"""Drafting and writing the stakes profile: the operator's answers plus what
the tree implies, as a change to review and commit."""
import json
import os
import re

from .fileio import dumps, write_file_atomic
from .gitstate import worktree_reader
from .globs import compile_glob, glob_match_compiled
from .infer import infer_markers
from .rubric import DIMENSIONS, worse_value
from .sanitize import UNSAFE_RE, terminal_text
from .stakes import PROFILE_REL, PROFILE_SCHEMA

_ANSWER_RE = re.compile(r"^(?:(.+):)?([a-z_]+)=([a-z_]+)$")


def parse_answer(spec):
    """(glob or None, dimension, value) for an answer written
    '[GLOB:]DIMENSION=VALUE', or raises ValueError naming what is wrong."""
    match = _ANSWER_RE.match(spec.strip())
    if not match:
        raise ValueError("answer %r is not [GLOB:]DIMENSION=VALUE" % terminal_text(spec, 80))
    glob, dimension, value = match.groups()
    if dimension not in DIMENSIONS:
        raise ValueError("answer %r: dimension must be one of %s"
                         % (terminal_text(spec, 80), ", ".join(DIMENSIONS)))
    if value not in DIMENSIONS[dimension]:
        raise ValueError("answer %r: %s must be one of %s"
                         % (terminal_text(spec, 80), dimension, ", ".join(DIMENSIONS[dimension])))
    if glob is not None and (not glob.strip() or len(glob) > 500 or UNSAFE_RE.search(glob)):
        raise ValueError("answer %r: the glob is not usable" % terminal_text(spec, 80))
    return (glob.strip() if glob else None), dimension, value


def build_profile(root, answers, confirm, today):
    """Draft or update the risk profile: the existing working-tree file (if
    any), plus the operator's ANSWERS, plus what the tree implies. Returns
    (document, report lines). Existing statements are never rewritten by
    inference; inference only adds entries, each marked inferred with its
    evidence, and a stated claim the tree contradicts is reported. Raises
    ValueError when the existing file cannot be read as a profile or an answer
    is malformed."""
    existing = None
    try:
        text = worktree_reader(root)(PROFILE_REL)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read %s: %s" % (PROFILE_REL, exc))
    if text is not None:
        try:
            existing = json.loads(text)
        except ValueError as exc:
            raise ValueError("%s is not valid JSON (%s); fix or remove it first" % (PROFILE_REL, exc))
        if not isinstance(existing, dict):
            raise ValueError("%s is not a JSON object; fix or remove it first" % PROFILE_REL)
    document = {"version": PROFILE_SCHEMA}
    default = dict(existing.get("default", {})) if existing and isinstance(existing.get("default"), dict) else {}
    paths = [dict(p) for p in existing.get("paths", []) if isinstance(p, dict)] \
        if existing and isinstance(existing.get("paths"), list) else []
    lines = []
    parsed = [parse_answer(spec) for spec in answers]
    for glob, dimension, value in parsed:
        if glob is None:
            default[dimension] = value
            continue
        for entry in paths:
            if entry.get("glob") != glob:
                continue
            if entry.get("inferred"):
                if dimension not in entry:
                    # An inferred entry for another dimension keeps its
                    # inferred status; the answer gets an entry of its own.
                    continue
                # The operator now states this value: it is no longer
                # inferred, and the evidence described the old value.
                entry.pop("inferred", None)
                entry.pop("evidence", None)
            entry[dimension] = value
            break
        else:
            paths.append({"glob": glob, dimension: value})
    markers, notes = infer_markers(root)
    lines.extend("note: " + n for n in notes)
    added = 0
    stated = {(e.get("glob"), d) for e in paths for d in DIMENSIONS if d in e}
    for marker in markers:
        key = (marker["glob"], marker["dimension"])
        if key in stated:
            continue
        stated.add(key)
        paths.append({"glob": marker["glob"], marker["dimension"]: marker["value"],
                      "inferred": True, "evidence": marker["why"]})
        added += 1
    if added:
        lines.append("inferred %d entr%s from the tree (marked inferred, with their evidence); they "
                     "only ever state the stricter value, so they cannot lower anything"
                     % (added, "y" if added == 1 else "ies"))
    for marker in markers:
        for entry in paths:
            if entry.get("inferred") or marker["dimension"] not in entry:
                continue
            if not glob_match_compiled(compile_glob(str(entry.get("glob", ""))), marker["file"]):
                continue
            claimed = entry[marker["dimension"]]
            if claimed in DIMENSIONS[marker["dimension"]] \
                    and worse_value(marker["dimension"], marker["value"], claimed) != claimed:
                lines.append("WARN: %s=%s for %s is contradicted by the tree (%s); the gate will "
                             "ignore that claim and apply %s there" % (
                                 marker["dimension"], claimed, terminal_text(entry.get("glob"), 120),
                                 terminal_text(marker["why"], 200), marker["value"]))
        claimed = default.get(marker["dimension"])
        if claimed in DIMENSIONS[marker["dimension"]] \
                and worse_value(marker["dimension"], marker["value"], claimed) != claimed:
            lines.append("WARN: the default %s=%s is contradicted by the tree (%s); the gate will "
                         "ignore it for the paths the marker covers" % (
                             marker["dimension"], claimed, terminal_text(marker["why"], 200)))
    if default:
        document["default"] = default
    document["paths"] = paths
    confirmed = existing.get("confirmed_at") if existing else None
    if parsed or confirm:
        confirmed = today.isoformat()
    if confirmed:
        document["confirmed_at"] = confirmed
    unstated = [d for d in DIMENSIONS if d not in default]
    if unstated:
        lines.append("unstated (the worst case applies until answered): " + "; ".join(
            "%s (%s)" % (d, " | ".join(DIMENSIONS[d])) for d in unstated))
        lines.append("answer with: profile --answer DIMENSION=VALUE for the whole repository, or "
                     "--answer 'GLOB:DIMENSION=VALUE' for a path; add --write to save the file, "
                     "then review and commit it")
    return document, lines


def write_profile(root, document):
    """Write the profile atomically, only inside ROOT: the .clagentic directory
    may be a symlink, and a profile must never be written through one to
    somewhere else."""
    target = os.path.join(root, PROFILE_REL)
    directory = os.path.dirname(target)
    real_root = os.path.realpath(root)
    real_dir = os.path.realpath(directory)
    # Checked before makedirs: creating the directory through a symlink that
    # leaves the repository would already be a write outside it.
    if real_dir != real_root and not real_dir.startswith(real_root + os.sep):
        raise ValueError("%s resolves outside the repository; not written" % os.path.dirname(PROFILE_REL))
    os.makedirs(directory, exist_ok=True)
    write_file_atomic(target, dumps(document, indent=2) + "\n")
    return target
