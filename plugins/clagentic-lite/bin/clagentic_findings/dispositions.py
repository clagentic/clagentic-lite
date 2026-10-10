"""The dispositions store.

ONE committed file records what an operator decided about a class of
findings: .clagentic/dispositions.json. Matching is done here, in code, and
never by a model. The legacy files (deferrals.json, adversarial-acks.json,
accepted-risks.md) are still read for one release, converted to the same
entries, with a deprecation warning. Which revision these files are read from
is policy.py's decision, not this module's.
"""
import datetime
import json
import os
import re

from .dates import parse_date, today_date
from .digest import sha256_hex, sha256_stream
from .fileio import dumps, write_file_atomic
from .gitstate import read_text_bounded, worktree_reader
from .globs import compile_glob, glob_escape, glob_match_compiled, matches_every_probe
from .paths import norm_path, norm_text, open_contained_regular, plain_relative_path
from .sanitize import UNSAFE_RE, terminal_text
from .unify import is_floor

DISPOSITIONS_REL = ".clagentic/dispositions.json"
LEGACY_DEFERRALS_REL = ".clagentic/deferrals.json"
LEGACY_ACKS_REL = ".clagentic/adversarial-acks.json"
LEGACY_RISKS_REL = ".clagentic/accepted-risks.md"
DISPOSITION_KINDS = ("by_design", "false_positive", "accepted_risk", "mitigated")
DISPOSITION_GATES = ("review", "adversarial")
DISPOSITIONS_SCHEMA = 1
MAX_ENTRIES = 1000
MAX_TEXT = 2000
_PLACEHOLDER_RE = re.compile(r"^<[^<>]*>$")
_HINT_RE = re.compile(r"^[0-9a-f]{8,64}$")


def validate_entry(raw):
    """(entry, errors). An entry is either valid in every required field and
    returned in its normalized form, or None with every reason it is not. Fail
    closed: an invalid entry is ignored, loudly, never half-applied."""
    if not isinstance(raw, dict):
        return None, ["not a JSON object"]
    errors = []

    def text(container, key, limit=MAX_TEXT, label=None):
        label = label or key
        value = container.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append("missing or empty '%s'" % label)
            return None
        if len(value) > limit:
            errors.append("'%s' is longer than %d characters" % (label, limit))
            return None
        if UNSAFE_RE.search(value):
            errors.append("'%s' contains control characters" % label)
            return None
        value = value.strip()
        if _PLACEHOLDER_RE.match(value):
            errors.append("'%s' is still a <placeholder>; write the real value" % label)
            return None
        return value

    entry_id = text(raw, "id", 200)
    gates = raw.get("gates")
    if (not isinstance(gates, list) or not gates
            or any(not isinstance(g, str) or g not in DISPOSITION_GATES for g in gates)):
        errors.append("'gates' must be a non-empty list drawn from %s" % ", ".join(DISPOSITION_GATES))
        gates = None
    kind = raw.get("kind")
    if kind not in DISPOSITION_KINDS:
        errors.append("'kind' must be one of %s" % ", ".join(DISPOSITION_KINDS))
        kind = None
    rationale = text(raw, "rationale")
    by = text(raw, "by", 200)
    at = text(raw, "at", 64)
    if at is not None and parse_date(at) is None:
        errors.append("'at' is not a date (YYYY-MM-DD)")
        at = None
    expires = raw.get("expires")
    if expires is not None:
        if parse_date(expires) is None:
            errors.append("'expires' is not a date (YYYY-MM-DD)")
            expires = None
        else:
            expires = expires.strip()
    control = None
    if kind == "mitigated":
        control = text(raw, "control")
    match_raw = raw.get("match")
    match = {}
    if not isinstance(match_raw, dict):
        errors.append("'match' must be an object with path_glob and category")
    else:
        glob = text(match_raw, "path_glob", 500, "match.path_glob")
        category = text(match_raw, "category", 100, "match.category")
        hint = match_raw.get("fingerprint_hint")
        message = match_raw.get("message")
        if glob is not None:
            match["path_glob"] = glob
        if category is not None:
            match["category"] = category
        if hint is not None:
            if isinstance(hint, str) and _HINT_RE.match(hint.strip().lower()):
                match["fingerprint_hint"] = hint.strip().lower()
            else:
                errors.append("'match.fingerprint_hint' must be 8 to 64 lowercase hex characters")
        if message is not None:
            message = text(match_raw, "message", 500, "match.message")
            if message is not None:
                match["message"] = message
        if (match.get("path_glob") and match.get("category") == "*"
                and "fingerprint_hint" not in match and "message" not in match
                and matches_every_probe(match["path_glob"])):
            errors.append("'match' is a catch-all (any path, any category); narrow it")
    if errors:
        return None, errors
    entry = {"id": entry_id, "gates": sorted(set(gates)), "match": match, "kind": kind,
             "rationale": rationale, "by": by, "at": at}
    if expires is not None:
        entry["expires"] = expires
    if control is not None:
        entry["control"] = control
    return entry, []


def entry_key(entry):
    """The entry's content, for telling an entry the base commit already had
    from one added or changed since."""
    return dumps(entry, sort_keys=True)


def convert_legacy_deferrals(text, root, check_hash):
    """Raw dispositions for the deferrals that were ever mechanically
    matched (scope 'stable-contract', with file, message and file_sha256).
    The others were prompt-context hints a model weighed; nothing applied them
    in code and they stay that way. With CHECK_HASH a deferral whose file no
    longer has the recorded content is dropped (the lapse-on-edit it always
    had). Returns (raw_entries, notes)."""
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("deferrals file is not a JSON array")
    raws, notes, prompt_only = [], [], 0
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            notes.append("deferrals entry %d is not an object; ignored" % index)
            continue
        eligible = (item.get("scope") == "stable-contract"
                    and all(isinstance(item.get(k), str) and item.get(k)
                            for k in ("id", "file", "message", "file_sha256")))
        if not eligible:
            prompt_only += 1
            continue
        fname = plain_relative_path(item["file"])
        if fname is None:
            notes.append("deferral %r ignored: its file %r is not a plain relative path inside "
                         "the repository" % (terminal_text(item["id"], 80),
                                             terminal_text(item["file"], 120)))
            continue
        if check_hash:
            # The whole file is hashed: the recorded digest is of the full
            # content, so a prefix could never equal it for a large file.
            handle = open_contained_regular(root, fname)
            try:
                actual = sha256_stream(handle) if handle is not None else None
            except OSError:
                actual = None
            finally:
                if handle is not None:
                    handle.close()
            if actual != item["file_sha256"]:
                notes.append("deferral %r lapsed: %s no longer has the recorded content"
                             % (terminal_text(item["id"], 80), terminal_text(fname, 120)))
                continue
        try:
            mtime = datetime.date.fromtimestamp(
                os.stat(os.path.join(root, LEGACY_DEFERRALS_REL)).st_mtime).isoformat()
        except OSError:
            mtime = ""
        raw = {
            "id": "deferral-" + item["id"],
            "gates": ["review"],
            "match": {"path_glob": glob_escape(fname),
                      "category": str(item.get("category") or "") or "*",
                      "message": item["message"]},
            "kind": "accepted_risk",
            "rationale": item.get("description") or "migrated from deferrals.json (no description recorded)",
            "by": item.get("acknowledged_by") or "legacy deferrals.json (no author recorded)",
            "at": mtime,
        }
        if item.get("expires") is not None:
            raw["expires"] = item["expires"]
        raws.append(raw)
    if prompt_only:
        notes.append("%d deferral(s) without scope 'stable-contract' were prompt-context hints, "
                     "never applied in code, and are not migrated" % prompt_only)
    return raws, notes


def convert_legacy_acks(text):
    """Raw dispositions for adversarial-acks.json entries (a CWE, an optional
    path glob, a rationale, who and when)."""
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("acks file is not a JSON array")
    raws, notes = [], []
    for index, ack in enumerate(data):
        if not isinstance(ack, dict):
            notes.append("acks entry %d is not an object; ignored" % index)
            continue
        cwe, glob = ack.get("cwe"), ack.get("path_glob") or "**"
        ident = sha256_hex("%s|%s" % (cwe, glob))[:10]
        raws.append({
            "id": "ack-" + ident,
            "gates": ["adversarial"],
            "match": {"path_glob": glob, "category": cwe},
            "kind": "accepted_risk",
            "rationale": ack.get("rationale"),
            "by": ack.get("acknowledged_by"),
            "at": ack.get("acknowledged_at"),
        })
    return raws, notes


def load_store(root, reader, check_hash=True):
    """The dispositions in force, read through READER. Returns a dict with the
    valid 'entries', every 'invalid' record (source, id, errors), 'warnings'
    (deprecations and migration notes) and the 'legacy' files that were read.
    A file that cannot be read or parsed contributes no entries and one
    invalid record: nothing in it applies."""
    store = {"entries": [], "invalid": [], "warnings": [], "legacy": []}
    seen = set()

    def invalid(source, label, errors):
        store["invalid"].append({"source": source, "id": terminal_text(label, 120),
                                 "errors": [terminal_text(e, 300) for e in errors]})

    def add(raw, source):
        entry, errors = validate_entry(raw)
        label = raw.get("id") if isinstance(raw, dict) and isinstance(raw.get("id"), str) else "<no id>"
        if entry is not None and entry["id"] in seen:
            entry, errors = None, ["duplicate id (the first entry with this id wins)"]
        if entry is None:
            invalid(source, label, errors)
            return
        seen.add(entry["id"])
        store["entries"].append(entry)

    def read(rel):
        try:
            return reader(rel), None
        except (OSError, ValueError) as exc:
            return None, str(exc)

    text, problem = read(DISPOSITIONS_REL)
    if problem:
        invalid(DISPOSITIONS_REL, "<file>", ["cannot read the file: " + problem])
    elif text is not None:
        try:
            document = json.loads(text)
            items = document.get("entries") if isinstance(document, dict) else document
            if not isinstance(items, list):
                raise ValueError("expected a JSON array of entries or an object with an 'entries' array")
            if len(items) > MAX_ENTRIES:
                raise ValueError("more than %d entries" % MAX_ENTRIES)
        except ValueError as exc:
            invalid(DISPOSITIONS_REL, "<file>", ["not usable: %s; no entry in it applies" % exc])
        else:
            for raw in items:
                add(raw, DISPOSITIONS_REL)

    for rel, convert in ((LEGACY_DEFERRALS_REL, "deferrals"), (LEGACY_ACKS_REL, "acks")):
        text, problem = read(rel)
        if problem:
            invalid(rel, "<file>", ["cannot read the file: " + problem])
            continue
        if text is None or not text.strip():
            continue
        store["legacy"].append(rel)
        try:
            if convert == "deferrals":
                raws, notes = convert_legacy_deferrals(text, root, check_hash)
            else:
                raws, notes = convert_legacy_acks(text)
        except ValueError as exc:
            invalid(rel, "<file>", ["not usable: %s; no entry in it applies" % exc])
            continue
        store["warnings"].extend(notes)
        for raw in raws[:MAX_ENTRIES]:
            add(raw, rel)
    text, problem = read(LEGACY_RISKS_REL)
    if problem:
        invalid(LEGACY_RISKS_REL, "<file>", ["cannot read the file: " + problem])
    elif text is not None and text.strip():
        store["legacy"].append(LEGACY_RISKS_REL)
        store["warnings"].append(
            "%s is freetext and was only ever read by the merge-gate model; it clears nothing "
            "in code. Record each accepted risk as an entry in %s." % (LEGACY_RISKS_REL, DISPOSITIONS_REL))
    for rel in store["legacy"]:
        if rel != LEGACY_RISKS_REL:
            store["warnings"].append(
                "DEPRECATED: %s is read for one more release; move its entries with "
                "'python3 findings.py dispositions migrate --root . --write' and delete it" % rel)
    return store


_GLOB_CACHE = {}


def _compiled_glob(entry):
    key = entry["match"]["path_glob"]
    if key not in _GLOB_CACHE:
        _GLOB_CACHE[key] = compile_glob(key)
    return _GLOB_CACHE[key]


def entry_matches(entry, finding):
    if finding.get("source") not in entry["gates"]:
        return False
    match = entry["match"]
    if not glob_match_compiled(_compiled_glob(entry), norm_path(finding.get("file", ""))):
        return False
    category = match["category"]
    if category != "*" and category.strip().lower() != str(finding.get("category", "")).strip().lower():
        return False
    if "message" in match and norm_text(match["message"]) != norm_text(finding.get("message", "")):
        return False
    hint = match.get("fingerprint_hint")
    if hint and not str(finding.get("fingerprint", "")).startswith(hint):
        return False
    return True


def entry_can_clear(entry, finding):
    """A security-floor finding is cleared by a mitigation that names its
    control; by_design, false_positive and accepted_risk do not reach it."""
    return entry["kind"] == "mitigated" if is_floor(finding) else True


def lint_dispositions(root, path=None):
    """Validate the dispositions in force (or the one file PATH). Returns
    (exit_code, lines): nonzero when any entry is invalid or a file is
    unusable, with every reason; deprecations and expiries are reported but
    are not problems."""
    if path:
        try:
            text = read_text_bounded(path)
        except (OSError, ValueError) as exc:
            return 1, ["[gates/dispositions-lint] cannot read %s: %s" % (path, exc)]
        rel = DISPOSITIONS_REL

        def reader(wanted):
            return text if wanted == rel else None
        store = load_store(root, reader)
    else:
        store = load_store(root, worktree_reader(root))
    today = today_date()
    lines = []
    for record in store["invalid"]:
        lines.append("  - %s (%s): %s" % (record["id"], record["source"], "; ".join(record["errors"])))
    code = 1 if store["invalid"] else 0
    out = []
    if code:
        out.append("[gates/dispositions-lint] %d problem(s):" % len(store["invalid"]))
        out.extend(lines)
    else:
        out.append("[gates/dispositions-lint] %d entries, no problems" % len(store["entries"]))
    for entry in store["entries"]:
        until = parse_date(entry.get("expires")) if entry.get("expires") else None
        if until is not None and until < today:
            out.append("[gates/dispositions-lint] entry %s expired on %s and no longer applies"
                       % (entry["id"], entry["expires"]))
    for warning in store["warnings"]:
        out.append("[gates/dispositions-lint] note: " + terminal_text(warning, 400))
    return code, out


def migrate_dispositions(root, write):
    """The dispositions file as it would read with every legacy entry folded
    in. Returns (exit_code, text, lines): the new file's text, and the report.
    Refuses to write over an existing file that has invalid entries."""
    store = load_store(root, worktree_reader(root))
    if any(rec["source"] == DISPOSITIONS_REL for rec in store["invalid"]):
        return 1, "", ["[dispositions/migrate] %s has invalid entries; fix them first (dispositions lint)"
                       % DISPOSITIONS_REL]
    document = {"version": DISPOSITIONS_SCHEMA, "entries": store["entries"]}
    text = dumps(document, indent=2) + "\n"
    report = ["[dispositions/migrate] %d entries (%d legacy file(s) folded in)"
              % (len(store["entries"]), len(store["legacy"]))]
    for record in store["invalid"]:
        report.append("[dispositions/migrate] not migrated: %s (%s): %s"
                      % (record["id"], record["source"], "; ".join(record["errors"])))
    for warning in store["warnings"]:
        if not warning.startswith("DEPRECATED"):
            report.append("[dispositions/migrate] " + terminal_text(warning, 400))
    if store["invalid"]:
        # Deleting a legacy file after a migration that left entries behind
        # drops them silently, so nothing is written and nothing is advised
        # until every entry can move.
        report.append("[dispositions/migrate] %d entr%s could not be migrated: nothing was written, "
                      "and the legacy files must be kept; fix them and run this again"
                      % (len(store["invalid"]), "y" if len(store["invalid"]) == 1 else "ies"))
        return 1, text, report
    if write:
        target = os.path.join(root, DISPOSITIONS_REL)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        write_file_atomic(target, text)
        report.append("[dispositions/migrate] wrote %s; review it, commit it, then delete the legacy files"
                      % DISPOSITIONS_REL)
    return 0, text, report
