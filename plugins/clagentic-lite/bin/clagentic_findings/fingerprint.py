"""Fingerprinting findings across rounds: content-addressed window keys from
the diff, location keys, deduplication, seen-key files and round counts."""
import os
import re

from .digest import sha256_hex
from .fileio import dumps, load_json_file, warn, write_file_atomic
from .severity import severity_rank

_HUNK_RE = re.compile(r"\+(\d+)")
_HUNK_COUNTS_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffIndex(object):
    """'+' lines of a unified diff, numbered by their line in the new file and
    grouped by file. Built once per diff per process."""

    def __init__(self, path):
        self.by_file = {}
        try:
            with open(path, "rb") as handle:
                text = handle.read().decode("utf-8", "surrogateescape")
        except OSError:
            return
        current, number = "", 0
        # Inside a hunk the declared line counts say where it ends, so an added
        # line whose content begins with '++ ' (shown as '+++ ...') is never
        # mistaken for the next file's header. Numbers advance on context and
        # '+' lines and not on '-' lines: they are new-file line numbers.
        old_left = new_left = 0
        for line in text.split("\n"):
            if old_left > 0 or new_left > 0:
                lead = line[:1]
                if lead == "+":
                    number += 1
                    new_left -= 1
                    self.by_file.setdefault(current, []).append((number, line))
                    continue
                if lead == "-":
                    old_left -= 1
                    continue
                if lead in (" ", ""):
                    number += 1
                    old_left -= 1
                    new_left -= 1
                    continue
                if lead == "\\":
                    continue
                old_left = new_left = 0
            if line.startswith("+++ "):
                current = line[4:]
                if current.startswith("b/"):
                    current = current[2:]
                number = 0
            elif line.startswith("@@ "):
                counted = _HUNK_COUNTS_RE.match(line)
                if counted:
                    number = int(counted.group(3)) - 1
                    old_left = int(counted.group(2) or 1)
                    new_left = int(counted.group(4) or 1)
                else:
                    hunk = _HUNK_RE.search(line)
                    number = int(hunk.group(1)) - 1 if hunk else 0
            elif line.startswith("+"):
                number += 1
                self.by_file.setdefault(current, []).append((number, line))

    def window(self, fname, target):
        """The added lines within two lines of TARGET in FNAME."""
        return [text for number, text in self.by_file.get(fname, ())
                if abs(number - target) <= 2]


_DIFF_INDEXES = {}


def diff_index(path):
    if path not in _DIFF_INDEXES:
        _DIFF_INDEXES[path] = DiffIndex(path)
    return _DIFF_INDEXES[path]


def window_key(finding, diff_path):
    """sha256 of the +-2 line window around the finding in DIFF_PATH, or None
    when the diff has no such window. Content-addressed, so it survives line
    renumbering as long as the surrounding lines are unchanged."""
    fname = finding.get("file", "")
    line = int(finding.get("line", 0) or 0)
    window = diff_index(diff_path).window(fname, line)
    return sha256_hex("\n".join(window)) if window else None


def location_key(finding):
    raw = "{}:{}:{}:{}".format(finding.get("file", ""), str(finding.get("line") or 0),
                               finding.get("category", ""),
                               str(finding.get("message", "")).lower())
    return sha256_hex(raw)


def finding_key(finding, strategy, diff_path):
    """Key for one finding, or None when it cannot be computed. None means
    'retain without deduplicating': a finding is never dropped on a key we
    could not derive."""
    try:
        if strategy == "content-hash" and diff_path and os.path.isfile(diff_path):
            key = window_key(finding, diff_path)
            if key:
                return key
        return location_key(finding)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return None


def dedup_findings(findings, strategy, seen, diff_path, annotate):
    """Collapse findings sharing a key; the higher severity wins.

    DROP mode also removes a finding whose key an earlier run recorded; only
    safe where the result never feeds a verdict. ANNOTATE mode keeps it,
    flagged with _seen_before/_seen_key: a key is a link hint, never an
    identity to drop a blocking finding on, or re-running at the same HEAD
    would pass by forgetting what the first run found.

    Returns (kept, new_keys)."""
    kept, new_keys, position = [], [], {}
    for finding in findings:
        key = finding_key(finding, strategy, diff_path)
        if key is None:
            kept.append(finding)
            continue
        rank = severity_rank(finding.get("severity"))
        if key in seen and not annotate:
            if key in position:
                at = position[key]
                if rank > severity_rank(kept[at].get("severity")):
                    kept[at] = finding
            continue
        if key not in position:
            position[key] = len(kept)
            kept.append(finding)
            if key not in seen:
                new_keys.append(key)
        else:
            at = position[key]
            if rank > severity_rank(kept[at].get("severity")):
                kept[at] = finding
    if annotate:
        for key, at in position.items():
            if key in seen and isinstance(kept[at], dict):
                kept[at] = dict(kept[at], _seen_before=True, _seen_key=key)
    return kept, new_keys


def read_key_file(path):
    keys = set()
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                key = line.strip()
                if key:
                    keys.add(key)
    except OSError:
        pass
    return keys


def append_key_file(path, keys):
    if not keys:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            for key in keys:
                handle.write(key + "\n")
    except OSError as exc:
        warn("[findings] could not record seen keys in %s: %s; later rounds will not "
             "see this round's findings" % (path, exc))


def tsv_clean(value):
    return str(value).replace("\t", " ").replace("\n", " ").replace("\r", " ")


def content_key_rows(findings, diff_path):
    """(key, file, category, message) for every finding whose window key can be
    computed; others are omitted. Fields are cleaned of tab and newline so a
    row is always one TSV line."""
    rows = []
    if not diff_path or not os.path.isfile(diff_path):
        return rows
    for finding in findings:
        try:
            key = window_key(finding, diff_path)
            if key:
                rows.append((key, tsv_clean(finding.get("file", "") or ""),
                             tsv_clean(finding.get("category", "") or ""),
                             tsv_clean(finding.get("message", "") or "")))
        except (AttributeError, TypeError, ValueError):
            continue
    return rows


def read_counts(counts_path):
    """The persisted round counts. A missing, corrupt or non-object counts file
    reads as empty, so a count can only be undercounted."""
    try:
        loaded = load_json_file(counts_path)
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def write_counts(counts_path, counts):
    try:
        write_file_atomic(counts_path, dumps(counts))
    except OSError as exc:
        warn("[findings] could not persist round counts to %s: %s" % (counts_path, exc))
        return False
    return True


def next_counts(counts, keys):
    """Mutate COUNTS to add one round for each key in KEYS and return the new
    count per key in order. A non-integer entry reads as zero."""
    result = []
    for key in keys:
        prior = counts.get(key, 0)
        if not isinstance(prior, int) or isinstance(prior, bool):
            prior = 0
        counts[key] = prior + 1
        result.append(prior + 1)
    return result


def bump_counts(counts_path, keys):
    """Increment the persisted round count of each key; returns the new count
    per key in order."""
    counts = read_counts(counts_path)
    result = next_counts(counts, keys)
    write_counts(counts_path, counts)
    return result
