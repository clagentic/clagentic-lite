#!/usr/bin/env python3
"""clagentic-lite finding pipeline: one self-contained, stdlib-only file.

Every decision the gates make about a finding lives here: how a model's
findings are ingested and cleaned, how a finding is fingerprinted across
rounds, which dispositions (seen before, recurring, deferred) apply, what
counts toward a verdict, and how a verdict is rendered. The shell gates
(scripts/gates.sh, scripts/review-merge.sh) call this file through thin
wrappers; a bare Reviewer or Auditor agent can call it directly from any git
repository, enrolled or not. It reads no clagentic-lite state it is not
handed as an argument and imports nothing outside the standard library.

Usage: findings.py STAGE OP [ARGS]

  ingest        review-envelope FILE | findings FILE [--strict]
                adversarial-parse FILE | adversarial-sanitize | adversarial-sort
                cap --max N | length | is-array | merge DIR [--strategy S]
                sanitize-text [--max N] | allowlist FIELD... | sanitize-fields FIELD...
  fingerprint   dedup --strategy S --seen FILE [--diff FILE] [--mode drop|annotate]
                keys --diff FILE | bump COUNTS_FILE
  dispositions  cross-round FILE --diff FILE --seen FILE
                recurrence FILE --diff FILE --counts FILE --threshold N
                deferrals FILE --root DIR [--deferrals FILE]
                ledger-recurrence --ledger FILE --branch NAME | lint FILE
  verdict       blockers FILE THRESHOLD | blocking-json THRESHOLD | rank NAME
                ledger-entries|ledger-latest|ledger-field|ledger-state|ledger-pass|
                ledger-pass-head|ledger-append|ledger-entry
  render        review FILE | verdict-lines HEAD | sanitize-review FILE
                sanitize-report FILE | fence-data LABEL KIND | fence-findings
                json-field KEY | stale-report FILE | gate-summary OPTIONS

Findings and other payloads of unbounded size arrive on stdin or as file
paths, never as argv: one argv string over the kernel's MAX_ARG_STRLEN fails
exec. Exit status is the contract: 0 ok, 1 refused or failed closed, 2 unreadable
input where the caller must tell that apart from empty.
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import tempfile

SEVERITY_RANKS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_THRESHOLD_RANK = 3
# A severity that is present but not a string cannot be ranked; it counts as
# blocking so a malformed value can never slip under the threshold.
UNRANKABLE_RANK = 4
FAIL_CLOSED_BLOCKERS = 99
CLASS_ISOLATED = "none — isolated"
DEFAULT_MAX_FIELD_CHARS = 500
DEFAULT_FINDINGS_MAX = 200
TRUNCATION_SUFFIX = "...[truncated]"

REVIEW_FINDING_FIELDS = (
    "severity", "file", "line:number", "category", "message", "evidence",
    "suggestion", "issue_class", "class_fix",
)
# Free-text review fields that reach the merge-gate prompt, and the closed set
# of keys a finding may carry into that payload (the review schema plus the
# gate-written annotations, which are not free text).
PROMPT_REVIEW_TEXT_FIELDS = (
    "severity", "file", "category", "message", "evidence", "suggestion",
    "issue_class", "class_fix", "_deferral_id",
)
PROMPT_REVIEW_KEEP_KEYS = (
    "severity", "file", "line", "category", "message", "evidence", "suggestion",
    "issue_class", "class_fix", "_recurrence_demoted", "_recurrence_count",
    "_deferral_matched", "_deferral_id",
)

SANITIZE_FAILED_ENVELOPE = (
    '{"degraded": true, "sanitize_failed": true, "summary": "[clagentic-lite '
    'degraded] review findings could not be sanitized", "checked": [], "findings": []}\n'
)

# Fence labels any prompt-bound payload must not be able to forge. Defanged
# unconditionally: one planted payload can round-trip through any pipeline.
_FENCE_LABELS = (
    "INVARIANTS:", "DEFERRED FINDINGS:", "END INVARIANTS", "END DEFERRED FINDINGS",
    "===BEGIN INVARIANTS DATA===", "===END INVARIANTS DATA===",
    "===BEGIN ADVERSARIAL FINDINGS DATA===", "===END ADVERSARIAL FINDINGS DATA===",
    "===BEGIN CHANGE-CLASS HINT DATA===", "===END CHANGE-CLASS HINT DATA===",
    "===BEGIN DEFERRED FINDINGS DATA===", "===END DEFERRED FINDINGS DATA===",
    "===BEGIN DETERMINISTIC GATES DATA===", "===END DETERMINISTIC GATES DATA===",
    "===BEGIN REVIEW FINDINGS DATA===", "===END REVIEW FINDINGS DATA===",
    "===BEGIN ADVERSARIAL REPORT DATA===", "===END ADVERSARIAL REPORT DATA===",
)
_FENCE_PATTERNS = [re.compile(re.escape(label), re.IGNORECASE) for label in _FENCE_LABELS]
_CSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)")
_ESC_RE = re.compile(r"\x1b.")
_HUNK_RE = re.compile(r"\+(\d+)")
_FILE_LINE_RE = re.compile(r"^(.+):(\d+)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ADVERSARIAL_HEADER_RE = re.compile(
    r"^\[FINDING\]\s*([^|]+)\|\s*([^|]+)\|\s*severity:\s*([^|]+?)\s*"
    r"(?:\|\s*reachable:\s*([^|]+?)\s*)?"
    r"(?:\|\s*tier:\s*([^|]+?)\s*)?"
    r"(?:\|\s*class:\s*([^|]+?)\s*)?"
    r"\|\s*title:\s*(.+)$"
)


# --------------------------------------------------------------------------- io

def setup_io():
    """Pin UTF-8 on every stream. A lone surrogate decoded from a JSON escape
    must reach a file or pipe byte-for-byte rather than abort the run."""
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="surrogatepass", newline="\n")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8",
                                  errors="backslashreplace", newline="\n",
                                  write_through=True)


def dumps(obj, indent=None, sort_keys=False):
    """Compact JSON, non-ASCII kept as-is: the shape the gates have always
    consumed from jq -c, so consumers and ledger lines stay byte-stable."""
    if indent:
        return json.dumps(obj, indent=indent, sort_keys=sort_keys,
                          ensure_ascii=False, separators=(",", ": "))
    return json.dumps(obj, sort_keys=sort_keys, ensure_ascii=False, separators=(",", ":"))


def read_stdin_text():
    return sys.stdin.buffer.read().decode("utf-8")


def load_json_file(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def write_file_atomic(path, text):
    """Replace PATH with TEXT without ever exposing a half-written file."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".findings-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8", "surrogatepass"))
        if os.path.exists(path):
            os.chmod(tmp, os.stat(path).st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def warn(message):
    sys.stderr.write(message + "\n")


def positive_int_env(name, default):
    """Positive integer from the environment; a rejected value warns and falls
    back to DEFAULT (0 must never reach a cap or a timeout as 'unbounded')."""
    raw = os.environ.get(name, "")
    if raw == "":
        return default
    if re.fullmatch(r"[0-9]+", raw) and int(raw) > 0:
        return int(raw)
    warn("[clagentic-lite] WARN: %s=%s is not a positive integer; using the default (%s)."
         % (name, raw, default))
    return default


_MAX_FIELD_CHARS = []


def max_field_chars():
    """Per-field length cap; resolved once per process so a rejected
    environment value warns once, not once per sanitized field."""
    if not _MAX_FIELD_CHARS:
        _MAX_FIELD_CHARS.append(positive_int_env(
            "CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS", DEFAULT_MAX_FIELD_CHARS))
    return _MAX_FIELD_CHARS[0]


# ------------------------------------------------------------------- severity

def severity_rank(severity):
    """The one severity ranking. None is rank 0; a non-string value cannot be
    ranked and counts as blocking; a string is matched case-insensitively
    because models routinely return 'HIGH'."""
    if severity is None:
        return 0
    if not isinstance(severity, str):
        return UNRANKABLE_RANK
    return SEVERITY_RANKS.get(severity.lower(), 0)


def threshold_rank(name):
    """Threshold name -> rank; anything unknown means 'high'."""
    return SEVERITY_RANKS.get(name, 0) or DEFAULT_THRESHOLD_RANK


def counts_toward_verdict(finding, threshold):
    """A finding blocks when it meets the threshold and no gate-written
    annotation excuses it. The annotations are thresholds, not suppression:
    the finding stays visible with its honest severity."""
    return (severity_rank(finding.get("severity")) >= threshold
            and finding.get("_recurrence_demoted") is not True
            and finding.get("_deferral_matched") is not True)


def triple(finding):
    """(file, category, message): the match key for every cross-round
    comparison that must survive line-number drift."""
    return (str(finding.get("file", "")), str(finding.get("category", "")),
            str(finding.get("message", "")))


# ----------------------------------------------------------------- sanitizing

def sanitize_text(text, limit=None):
    """Neutralize text before it is written to a file or interpolated into a
    prompt a later model reads: strip terminal escapes and control bytes (tab
    and newline stay), defang every fence label, cap the length."""
    if limit is None:
        limit = max_field_chars()
    text = _CSI_RE.sub("", text)
    text = _OSC_RE.sub("", text)
    text = _ESC_RE.sub("", text)
    text = "".join(ch for ch in text if ch in ("\t", "\n") or 0x20 <= ord(ch) != 0x7F)
    for pattern in _FENCE_PATTERNS:
        text = pattern.sub(lambda m: " ".join(m.group(0)), text)
    if len(text) > limit:
        text = text[:max(limit - len(TRUNCATION_SUFFIX), 0)] + TRUNCATION_SUFFIX
    return text


def _shell_value(text):
    """Trailing newlines are not part of a value the shell gates ever carried
    (command substitution strips them); keep that so output is unchanged."""
    return text.rstrip("\n")


def _parse_field_specs(fields):
    specs = {}
    for field in fields:
        if field.endswith(":number"):
            specs[field[:-len(":number")]] = "number"
        else:
            specs[field] = "string"
    return specs


def allowlist_fields(array, fields):
    """Reduce every object to the named fields, dropping every other key and
    every value of the wrong declared type. 'name:number' declares a number;
    a bare name declares a string. Booleans never pass as numbers."""
    if not fields:
        raise ValueError("empty field list")
    if not isinstance(array, list):
        raise ValueError("not an array")
    specs = _parse_field_specs(fields)
    reduced = []
    for item in array:
        if not isinstance(item, dict):
            reduced.append({})
            continue
        kept = {}
        for key, value in item.items():
            kind = specs.get(key)
            if kind is None or isinstance(value, bool):
                continue
            if kind == "string" and isinstance(value, str):
                kept[key] = value
            elif kind == "number" and isinstance(value, (int, float)):
                kept[key] = value
        reduced.append(kept)
    return reduced


def sanitize_fields_strict(array, fields):
    """Run sanitize_text over each named string field of every object. Fails
    closed: a non-array, a non-object element or an empty field list raises,
    so a caller can never mistake a failure for 'sanitized' or 'no entries'.
    Fields not named pass through untouched, so a caller whose field set an
    attacker can influence must allowlist first."""
    if not fields:
        raise ValueError("empty field list")
    if not isinstance(array, list):
        raise ValueError("not an array")
    cleaned = []
    for item in array:
        if not isinstance(item, dict):
            raise ValueError("array element is not an object")
        item = dict(item)
        for field in fields:
            value = item.get(field, "")
            raw = _shell_value(value if isinstance(value, str) else "")
            clean = _shell_value(sanitize_text(raw))
            if field in item:
                item[field] = clean
        cleaned.append(item)
    return cleaned


# ------------------------------------------------------------ envelope access

def extract_findings(path):
    """The .findings of an envelope file, or [] on any failure."""
    try:
        document = load_json_file(path)
    except (OSError, ValueError):
        return []
    if not isinstance(document, dict):
        return []
    value = document.get("findings")
    if value is None or value is False:
        return []
    return value


def extract_findings_strict(path):
    """Like extract_findings but fail closed. An absent key is a genuine empty
    list; a present non-array (null, object, string, number) raises, because a
    present-but-null key must not be read as a clean review."""
    document = load_json_file(path)
    if not isinstance(document, dict):
        raise ValueError("envelope is not an object")
    value = document["findings"] if "findings" in document else []
    if not isinstance(value, list):
        raise ValueError("findings is not an array")
    return value


def splice_findings(path, findings):
    """Write FINDINGS back as the envelope's .findings."""
    document = load_json_file(path)
    if not isinstance(document, dict) or not isinstance(findings, list):
        raise ValueError("cannot splice")
    document["findings"] = findings
    write_file_atomic(path, dumps(document) + "\n")


def mark_review_sanitize_failed(path):
    """Replace PATH with the degraded stub that says its findings could not be
    reduced to the closed schema. The raw findings are still in PATH and must
    not survive, and an empty list must not read as 'no findings'."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(SANITIZE_FAILED_ENVELOPE)
    except OSError as exc:
        warn("[findings] could not rewrite %s: %s" % (path, exc))
    warn("[gates/review] review findings could not be reduced to the closed schema; "
         "marked the envelope degraded")


def ingest_review_envelope(path):
    """Reduce an envelope's findings to the closed review schema in place. This
    is the choke point: a model must not be able to forge a gate-owned
    annotation (_recurrence_demoted and friends) in its own response."""
    if not os.path.isfile(path):
        return 0
    try:
        findings = extract_findings_strict(path)
        clean = allowlist_fields(findings, REVIEW_FINDING_FIELDS)
        splice_findings(path, clean)
    except (OSError, ValueError, KeyError):
        mark_review_sanitize_failed(path)
    return 0


# ---------------------------------------------------------------- adversarial

def parse_adversarial_findings(path):
    """Loose-parse [FINDING] header lines of the Auditor's markdown into
    structured findings. Every enum-shaped field is force-corrected to a member
    of its closed set; tier is clamped by two mechanical rules so neither the
    model nor an injected diff can move a finding across the blocking line."""
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().split("\n")
    except (OSError, ValueError) as exc:
        warn("_parse_adversarial_findings: could not read %s: %s" % (path, exc))
        raise
    findings = []
    for line in lines:
        match = _ADVERSARIAL_HEADER_RE.match(line.strip())
        if not match:
            continue
        cwe = match.group(1).strip()
        fileline = match.group(2).strip()
        severity_raw = match.group(3).strip().lower()
        reachable_raw = (match.group(4) or "").strip().lower()
        tier_raw = (match.group(5) or "").strip().lower()
        class_raw = (match.group(6) or "").strip().lower()
        title = match.group(7).strip()
        located = _FILE_LINE_RE.match(fileline)
        if located:
            fname, lineno = located.group(1), int(located.group(2))
        else:
            fname, lineno = fileline, 0
        severity = severity_raw if severity_raw in SEVERITY_RANKS else "unknown"
        reachable = reachable_raw if reachable_raw in ("yes", "no") else "no"
        tier = tier_raw if tier_raw in ("blocking", "advisory") else "advisory"
        # Reachability is the precondition for blocking, never a judgment the
        # tier field alone can override.
        if reachable != "yes":
            tier = "advisory"
        # An absent or unparseable class defaults to the one that relaxes
        # nothing, so a parser gap can only leave the full bar in place.
        change_class = class_raw if class_raw in ("durable", "ephemeral") else "durable"
        # Security floor: reachable and high/critical is always blocking,
        # whatever tier or class the model wrote.
        if reachable == "yes" and severity in ("high", "critical"):
            tier = "blocking"
        findings.append({
            "file": fname, "line": lineno, "category": cwe, "message": title,
            "severity": severity, "reachable": reachable, "tier": tier,
            "class": change_class,
        })
    return findings


def sort_blocking_first(array):
    """Blocking tier first, severity descending within a tier, parse order
    within a bucket. The order a model lists findings in is attacker-
    influenceable, so the count cap must only ever drop the least-severe,
    non-blocking tail."""
    def order(pair):
        index, item = pair
        is_dict = isinstance(item, dict)
        blocking = 1 if is_dict and item.get("tier") == "blocking" else 0
        severity = SEVERITY_RANKS.get(item.get("severity") if is_dict else None, 0)
        return (-blocking, -severity, index)
    return [item for _, item in sorted(enumerate(array), key=order)]


# ------------------------------------------------------------- fingerprinting

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
        for line in text.split("\n"):
            if line.startswith("+++ "):
                current = line[4:]
                if current.startswith("b/"):
                    current = current[2:]
                number = 0
            elif line.startswith("@@ "):
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


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


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
    except OSError:
        pass


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


def bump_counts(counts_path, keys):
    """Increment the persisted round count of each key; returns the new count
    per key in order. A missing, corrupt or non-object counts file reads as
    empty and a non-integer entry as zero, so the count can only be
    undercounted, which can only under-demote."""
    counts = {}
    try:
        loaded = load_json_file(counts_path)
        if isinstance(loaded, dict):
            counts = loaded
    except (OSError, ValueError):
        counts = {}
    result = []
    for key in keys:
        prior = counts.get(key, 0)
        if not isinstance(prior, int) or isinstance(prior, bool):
            prior = 0
        counts[key] = prior + 1
        result.append(prior + 1)
    try:
        write_file_atomic(counts_path, dumps(counts))
    except OSError:
        pass
    return result


# ---------------------------------------------------------------- envelopes

def merge_envelopes(env_dir, strategy):
    """Merge envelope-NNN.json chunk files into one envelope. A chunk that is
    unreadable or malformed counts as degraded rather than as clean."""
    try:
        names = sorted(n for n in os.listdir(env_dir)
                       if n.startswith("envelope-") and n.endswith(".json"))
    except OSError:
        names = []
    if not names:
        return 1, {"_no_envelopes": True, "degraded": True, "chunked": True,
                   "chunks": 0, "chunks_degraded": 0,
                   "summary": "[clagentic-lite] no valid envelopes found",
                   "checked": [], "findings": []}
    degraded_count = 0
    summaries, checked, findings = [], [], []
    for name in names:
        try:
            envelope = load_json_file(os.path.join(env_dir, name))
        except (OSError, ValueError):
            envelope = None
        if (not isinstance(envelope, dict)
                or not isinstance(envelope.get("findings", []), list)
                or not isinstance(envelope.get("checked", []), list)):
            degraded_count += 1
            continue
        if envelope.get("degraded"):
            degraded_count += 1
        elif envelope.get("summary"):
            summaries.append(envelope["summary"])
        for item in envelope.get("checked", []):
            if item not in checked:
                checked.append(item)
        findings.extend(envelope.get("findings", []))
    kept, _ = dedup_findings(findings, strategy, set(), "", False)
    return 0, {"summary": " | ".join(summaries), "checked": checked, "findings": kept,
               "degraded": degraded_count > 0, "chunked": True, "chunks": len(names),
               "chunks_degraded": degraded_count}


# -------------------------------------------------------------- dispositions

KEYS_FAILED = 10
SPLICE_FAILED = 11


class StageFailure(Exception):
    """A stage step failed in a way the shell caller words differently; CODE
    is the exit status that tells it which."""

    def __init__(self, code):
        Exception.__init__(self, "stage failed with %d" % code)
        self.code = code


def cross_round(env_path, diff_path, seen_path):
    """Annotate findings an earlier run recorded and persist this run's keys.
    Returns (before, after, seen_before) counts. Any failure raises
    StageFailure and leaves the envelope's findings as they were."""
    try:
        findings = load_json_file(env_path).get("findings")
    except (OSError, ValueError, AttributeError):
        raise StageFailure(KEYS_FAILED)
    if findings is None or findings is False:
        findings = []
    if not isinstance(findings, list):
        raise StageFailure(SPLICE_FAILED)
    seen = read_key_file(seen_path)
    kept, new_keys = dedup_findings(findings, "content-hash", seen, diff_path, True)
    append_key_file(seen_path, new_keys)
    try:
        splice_findings(env_path, kept)
    except (OSError, ValueError):
        raise StageFailure(SPLICE_FAILED)
    seen_before = sum(1 for f in kept if isinstance(f, dict) and f.get("_seen_before") is True)
    return len(findings), len(kept), seen_before


def recurrence_demote(env_path, diff_path, counts_path, threshold):
    """Count how many rounds each surviving finding has been reported in and
    mark those at or past THRESHOLD _recurrence_demoted. Severity is never
    touched: demotion only changes eligibility to block. Findings dedup kept
    only because an earlier run saw them are not counted again, or a plain
    re-run would demote a finding by repetition alone. Returns the demoted
    count, or None when nothing had a computable key (envelope untouched)."""
    findings = extract_findings(env_path)
    if not isinstance(findings, list):
        return None
    unseen = [f for f in findings
              if isinstance(f, dict) and f.get("_seen_before") is not True]
    rows = content_key_rows(unseen, diff_path)
    if not rows:
        return None
    counts = bump_counts(counts_path, [row[0] for row in rows])
    # Matched by value against the cleaned row fields, so a finding whose text
    # carries a tab or newline never matches and is never demoted.
    counts_by_triple = {}
    for row, count in zip(rows, counts):
        counts_by_triple[(row[1], row[2], row[3])] = count
    demoted = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        count = counts_by_triple.get(triple(finding))
        # Own the field for every finding touched: a value left over from the
        # object is never trusted.
        if count is None:
            finding["_recurrence_count"] = 0
            finding["_recurrence_demoted"] = False
            continue
        finding["_recurrence_count"] = count
        finding["_recurrence_demoted"] = count >= threshold
        if count >= threshold:
            demoted += 1
    try:
        splice_findings(env_path, findings)
    except (OSError, ValueError):
        pass
    return demoted


def _live_deferrals(deferrals, root):
    """Deferral entries eligible for mechanical matching whose file still has
    the content hash recorded at grant time. Anything doubtful is left out,
    which keeps the finding blocking."""
    live = []
    if not isinstance(deferrals, list):
        return live
    for entry in deferrals:
        if not isinstance(entry, dict):
            continue
        did, fname = entry.get("id"), entry.get("file")
        fsha, message = entry.get("file_sha256"), entry.get("message")
        category = str(entry.get("category", ""))
        eligible = (isinstance(did, str) and did and isinstance(fname, str) and fname
                    and isinstance(fsha, str) and fsha and isinstance(message, str)
                    and message and entry.get("scope") == "stable-contract")
        if not eligible:
            continue
        # Tab and newline cannot be carried in the row format these entries
        # have always matched through; such an entry has never matched.
        if any(c in field for field in (did, fname, category, message) for c in "\t\n\r"):
            continue
        try:
            with open(root + "/" + fname, "rb") as handle:
                actual = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            continue
        if actual == fsha:
            live.append((did, fname, category, message))
    return live


def deferral_match(env_path, deferrals_path, root):
    """Mark findings that match exactly one live operator deferral. Threshold,
    not suppression: the finding stays in the envelope, annotated. Two live
    entries claiming one finding is ambiguous and matches neither. Returns the
    matched count, or None when there is nothing to match against."""
    if not os.path.isfile(deferrals_path):
        return None
    try:
        deferrals = load_json_file(deferrals_path)
    except (OSError, ValueError):
        return None
    live = _live_deferrals(deferrals, root)
    if not live:
        return None
    findings = extract_findings(env_path)
    if not isinstance(findings, list):
        return None
    ids_by_triple = {}
    for did, fname, category, message in live:
        ids_by_triple.setdefault((fname, category, message), []).append(did)
    matched = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        candidates = ids_by_triple.get(triple(finding), [])
        if len(candidates) == 1:
            finding["_deferral_matched"] = True
            finding["_deferral_id"] = candidates[0]
            matched += 1
        else:
            finding["_deferral_matched"] = False
    try:
        splice_findings(env_path, findings)
    except (OSError, ValueError):
        return 0
    return matched


def mark_ledger_recurrence(findings, ledger_path, branch):
    """Annotate each finding _ledger_recurring when its (file, category,
    message) appears in an earlier ledger entry for BRANCH. Informational
    only: never changes which findings exist or their severity."""
    prior = set()
    for entry in ledger_entries(ledger_path, branch):
        prior_findings = entry.get("findings", [])
        if isinstance(prior_findings, list):
            prior.update(triple(f) for f in prior_findings if isinstance(f, dict))
    for finding in findings:
        if isinstance(finding, dict):
            finding["_ledger_recurring"] = triple(finding) in prior
    return findings


def lint_deferrals(path):
    """Validate a deferrals file against the schema mechanical matching needs.
    Returns (exit_code, lines)."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
    except (OSError, ValueError) as exc:
        return 1, ["[gates/deferrals-lint] cannot read {}: {}".format(path, exc)]
    if not raw.strip():
        return 0, []
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return 1, [
            "[gates/deferrals-lint] {} is not valid JSON: {}".format(path, exc),
            "[gates/deferrals-lint] the reviewer prompt will still receive it (fail-open, "
            "sanitized as opaque text), but NO entry in it can be gate-code-matched until "
            "this is fixed"]
    if not isinstance(data, list):
        return 1, ["[gates/deferrals-lint] {} must be a JSON array of deferral objects, "
                   "got {}".format(path, type(data).__name__)]
    problems = []
    for index, entry in enumerate(data):
        where = "entry {}".format(index)
        if not isinstance(entry, dict):
            problems.append("{}: not a JSON object".format(where))
            continue
        eid = entry.get("id")
        if isinstance(eid, str) and eid:
            where = "entry {} (id={!r})".format(index, eid)
        else:
            problems.append("{}: missing or empty required field 'id'".format(where))
        scope = entry.get("scope")
        if scope is None:
            continue
        if scope != "stable-contract":
            problems.append(
                "{}: scope={!r} is not a supported gate-code scope (only \"stable-contract\" "
                "is). REFUSED LOUDLY per design: a conditional or scope-boundary acceptance "
                "whose validity depends on code OUTSIDE this file (e.g. reset logic living "
                "elsewhere) is not safely matchable by a single-file content hash -- see "
                "docs/GATES.md 'Reviewer-consulted deferrals' for why this class is "
                "deliberately unsupported rather than silently mis-honored. Either remove the "
                "'scope' field (valid prompt-context-only deferral, weighed by the model each "
                "round, never mechanically matched) or, if this acceptance's rationale "
                "genuinely depends only on the named file's own content, set scope to "
                "\"stable-contract\" and provide file/message/file_sha256.".format(where, scope))
            continue
        fname = entry.get("file")
        if not (isinstance(fname, str) and fname):
            problems.append("{}: scope is \"stable-contract\" but 'file' is missing or empty "
                            "-- required to identify what gate code should re-hash".format(where))
        message = entry.get("message")
        if not (isinstance(message, str) and message):
            problems.append(
                "{}: scope is \"stable-contract\" but 'message' is missing or empty -- "
                "gate-code matching keys on (file, category, message) verbatim against the "
                "Reviewer's own finding text; without it this entry can never be "
                "mechanically matched".format(where))
        fsha = entry.get("file_sha256")
        if not (isinstance(fsha, str) and _SHA256_RE.match(fsha)):
            problems.append(
                "{}: scope is \"stable-contract\" but file_sha256 is missing or not a "
                "64-hex-char sha256 digest -- required for gate-code matching to detect the "
                "named file changing since this deferral was granted (lapse-on-edit). "
                "Compute it from the SAME file this entry names: "
                "sha256sum <file> | cut -d' ' -f1".format(where))
    if problems:
        lines = ["[gates/deferrals-lint] {} problem(s) in {}:".format(len(problems), path)]
        lines.extend("  - " + p for p in problems)
        return 1, lines
    return 0, ["[gates/deferrals-lint] {} entries, no problems".format(len(data))]


# ----------------------------------------------------------- verdict: blockers

def count_blockers(path, threshold_name):
    """Number of findings that block at the threshold; FAIL_CLOSED_BLOCKERS on
    any failure to read, so an unreadable review is never counted as clean."""
    threshold = threshold_rank(threshold_name)
    try:
        document = load_json_file(path)
        if not isinstance(document, dict):
            return FAIL_CLOSED_BLOCKERS
        findings = document.get("findings")
        if findings is None:
            return 0
        if not isinstance(findings, list):
            return FAIL_CLOSED_BLOCKERS
        total = 0
        for finding in findings:
            if not isinstance(finding, dict):
                return FAIL_CLOSED_BLOCKERS
            if counts_toward_verdict(finding, threshold):
                total += 1
        return total
    except (OSError, ValueError):
        return FAIL_CLOSED_BLOCKERS


def _clean_listing(value):
    return re.sub(r"[\x00-\x1f\x7f]", " ", "" if value is None else str(value))[:300]


def blocking_findings_listing(document_text, threshold_name):
    """The findings count_blockers would count, reduced to file, line,
    severity and message with control bytes stripped (the text is model-
    authored and ends up on a terminal). None, not [], when the input cannot
    be read: an empty list would read as 'nothing blocked'."""
    threshold = threshold_rank(threshold_name)
    try:
        document = json.loads(document_text)
        if not isinstance(document, dict):
            return None
        findings = document.get("findings")
        findings = [] if findings is None else findings
        if not isinstance(findings, list):
            return None
        listing = []
        for finding in findings:
            if not isinstance(finding, dict):
                return None
            if counts_toward_verdict(finding, threshold):
                listing.append({"file": _clean_listing(finding.get("file")),
                                "line": finding.get("line") or 0,
                                "severity": _clean_listing(finding.get("severity")),
                                "message": _clean_listing(finding.get("message"))})
        return listing
    except ValueError:
        return None


# ------------------------------------------------------------- verdict: ledger

def ledger_entries(path, branch):
    """Every entry for BRANCH, oldest first. A line that is not a JSON object
    is skipped; branch names are compared whole, never as substrings."""
    entries = []
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().split("\n")
    except (OSError, ValueError):
        return entries
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("branch") == branch:
            entries.append(entry)
    return entries


def latest_gate_entry(path, branch, gate):
    """The most recent entry BRANCH has from GATE, or None. An entry with no
    gate field matches no gate: defaulting it to 'review' would let a legacy
    entry anchor a lookup it never belonged to."""
    best = None
    for entry in ledger_entries(path, branch):
        if entry.get("gate") == gate:
            best = entry
    return best


def field_text(entry, name):
    value = entry.get(name)
    if value is None or value is False:
        return ""
    return value if isinstance(value, str) else dumps(value)


def anchored_pass(path, branch, head, gate):
    """True only when the latest GATE entry for BRANCH is anchored to HEAD and
    its verdict is pass. The one sanctioned 'is there a valid verdict'
    predicate."""
    if not head:
        return False
    latest = latest_gate_entry(path, branch, gate)
    if latest is None:
        return False
    entry_head = field_text(latest, "head_sha")
    return bool(entry_head) and entry_head == head and field_text(latest, "verdict") == "pass"


def head_verdict_state(path, branch, head, gate):
    """Why anchored_pass failed, as one token: pass, missing_stamp, sha_mismatch
    or review_blocked_at_head (the gate ran at this commit and blocked, so
    running it again cannot help)."""
    if anchored_pass(path, branch, head, gate):
        return "pass"
    latest = latest_gate_entry(path, branch, gate)
    if latest is None:
        return "missing_stamp"
    entry_head = field_text(latest, "head_sha")
    if not entry_head:
        return "missing_stamp"
    if entry_head != head:
        return "sha_mismatch"
    if field_text(latest, "verdict") == "block":
        return "review_blocked_at_head"
    return "missing_stamp"


def latest_passing_head(path, branch, gate):
    """head_sha of the latest anchored pass of GATE on BRANCH. Scans all
    history, not just the last row: the right re-review base is the last point
    the branch was known clean, however many blocked rounds followed."""
    best = ""
    for entry in ledger_entries(path, branch):
        if (entry.get("verdict") == "pass" and entry.get("head_sha")
                and entry.get("gate") == gate):
            best = entry["head_sha"]
    return best


def ledger_append(path, line, max_per_branch):
    """Append one JSON line, then drop the oldest entries of the same branch
    past MAX_PER_BRANCH (0 disables). The ledger exists to show churn, so its
    own storage must not grow without bound. Never raises: a lost entry
    degrades recurrence visibility and nothing else."""
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line.replace("\n", "") + "\n")
    except OSError:
        return
    if max_per_branch <= 0:
        return
    try:
        entry = json.loads(line)
        branch = entry.get("branch", "") if isinstance(entry, dict) else ""
    except ValueError:
        return
    if not branch:
        return

    def on_branch(raw):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return False
        return isinstance(parsed, dict) and parsed.get("branch") == branch

    try:
        with open(path, encoding="utf-8") as handle:
            lines = [raw.rstrip("\n") for raw in handle if raw.strip()]
        matches = sum(1 for raw in lines if on_branch(raw))
        drop = max(matches - max_per_branch, 0)
        kept, seen = [], 0
        for raw in lines:
            if on_branch(raw):
                seen += 1
                if seen <= drop:
                    continue
            kept.append(raw)
        if kept:
            write_file_atomic(path, "".join(raw + "\n" for raw in kept))
    except (OSError, ValueError):
        return


def build_ledger_entry(ts, branch, gate, base, head, verdict, findings_text, config_text):
    try:
        findings = json.loads(findings_text)
        if not isinstance(findings, list):
            findings = []
    except ValueError:
        findings = []
    try:
        config = json.loads(config_text)
    except ValueError:
        config = {}
    return dumps({"ts": ts, "branch": branch, "gate": gate, "base_sha": base,
                  "head_sha": head, "verdict": verdict, "findings": findings,
                  "config": config})


# --------------------------------------------------------------------- render

def _jq_text(value):
    """String concatenation as the render has always done it: null adds
    nothing, anything but a string is an error."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    raise TypeError("cannot concatenate %s" % type(value).__name__)


def _jq_tostring(value):
    if isinstance(value, str):
        return value
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return dumps(value)


def _class_named(finding):
    value = finding.get("issue_class")
    return value is not None and value != "" and value != CLASS_ISOLATED


def render_review(path):
    """Human-readable review. A demoted, deferral-matched or seen-before
    finding gets a suffix saying why it did or did not gate, so a threshold
    decision is never silent. Returns (exit_code, output_lines)."""
    document = load_json_file(path)
    findings = document.get("findings")
    count = len(findings) if findings is not None else 0
    lines = ["== clagentic-lite review ==\nsummary: " + _jq_text(document.get("summary"))
             + "\nfindings: " + str(count) + "\n"]
    code = 0
    try:
        if findings is None:
            raise TypeError("cannot iterate over null")
        for finding in findings:
            text = ("[" + _jq_text(finding.get("severity")) + "] " + _jq_text(finding.get("file"))
                    + ":" + _jq_tostring(finding.get("line")) + " "
                    + _jq_text(finding.get("message")))
            if finding.get("_recurrence_demoted") is True:
                text += (" (reported " + _jq_tostring(finding.get("_recurrence_count"))
                         + " rounds running — decide)")
            if finding.get("_deferral_matched") is True:
                deferral_id = finding.get("_deferral_id")
                text += " (matched deferral " + (deferral_id if deferral_id else "?") + ")"
            if finding.get("_seen_before") is True:
                text += " (reported in a prior run; still counted)"
            if _class_named(finding):
                text += "\n    class: " + _jq_text(finding.get("issue_class"))
                fix = finding.get("class_fix")
                if fix is not None and fix != "":
                    text += " -> " + _jq_text(fix)
            lines.append(text)
    except (TypeError, AttributeError):
        code = 1
    if code == 0 and any(_class_named(f) for f in findings):
        lines.append(None)
    return code, lines


CLASS_FOOTER = ("\nFindings above name a class -- fix via class_fix across every site, "
                "not per-line\n")


def render_verdict_lines(head, findings_text):
    """head_sha, a per-severity count and the recurring findings, for the
    review-verdict comment and the ship PR body. Returns (code, text): 2 with
    no text when the findings cannot be read, because 'Findings: none' is a
    claim about the review and is only printed for a list that was read and
    is empty."""
    try:
        findings = json.loads(findings_text)
    except ValueError:
        return 2, ""
    if not isinstance(findings, list):
        return 2, ""
    by_severity, recurring = {}, []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "unknown"))
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if finding.get("_ledger_recurring"):
            recurring.append(finding)
    lines = ["head_sha: `%s`" % (head or "<unresolved>"), ""]
    if findings:
        lines.append("Findings: %d total (%s)" % (
            len(findings),
            ", ".join("%s: %d" % (k, v) for k, v in sorted(by_severity.items()))))
    else:
        lines.append("Findings: none")
    if recurring:
        lines.append("")
        lines.append("Recurring from a prior round (%d):" % len(recurring))
        for finding in recurring:
            lines.append("- [%s] %s: %s" % (finding.get("severity", "unknown"),
                                            finding.get("file", "?"),
                                            finding.get("message", "")))
    return 0, "\n".join(lines) + "\n"


def sanitize_review_for_prompt(path):
    """last-review.json reduced to what the Merge Gate may read, every free
    text field sanitized. 'null' when the file is absent. Raises when the
    file exists but cannot be fully extracted and sanitized: a degraded source
    must never read as an empty findings list."""
    if not os.path.isfile(path):
        return "null"
    document = load_json_file(path)
    if not isinstance(document, dict) or document.get("sanitize_failed") is True:
        raise ValueError("review envelope unusable")
    value = document.get("findings")
    reduced = [{k: v for k, v in item.items() if k in PROMPT_REVIEW_KEEP_KEYS}
               if isinstance(item, dict) else {}
               for item in (value if isinstance(value, list) else [])]
    findings = sanitize_fields_strict(reduced, PROMPT_REVIEW_TEXT_FIELDS)
    out = {}
    summary = document.get("summary")
    if isinstance(summary, str):
        out["summary"] = _shell_value(sanitize_text(_shell_value(summary)))
    out["findings"] = findings
    sha = document.get("_clagentic_diff_sha")
    if isinstance(sha, str):
        out["_clagentic_diff_sha"] = _shell_value(sanitize_text(_shell_value(sha)))
    return dumps(out)


def sanitize_report_for_prompt(path):
    """The adversarial markdown report, sanitized. It is the Merge Gate's
    fallback refusal basis, so it is not held to the per-field cap: the bound
    is three times the file's length, because defanging a forged fence label
    roughly doubles that label."""
    with open(path, "rb") as handle:
        raw = handle.read()
    size = len(raw) or 1
    text = _shell_value(raw.decode("utf-8"))
    return sanitize_text(text, size * 3)


def fence_data_block(label, kind, text):
    """TEXT wrapped in a ===BEGIN/END <label> DATA=== fence, as a JSON string
    literal. KIND json pretty-prints the document first, with sorted keys."""
    body = text
    if kind == "json":
        try:
            body = dumps(json.loads(text), indent=2, sort_keys=True)
        except ValueError:
            body = text
    block = "===BEGIN %s DATA===\n%s\n===END %s DATA===\n" % (label, body, label)
    return dumps(block)


def fence_findings(raw):
    try:
        pretty = json.dumps(json.loads(raw), indent=2)
    except ValueError:
        pretty = raw
    return dumps("===BEGIN ADVERSARIAL FINDINGS DATA===\n" + pretty
                 + "\n===END ADVERSARIAL FINDINGS DATA===")


def json_string_field(text, key):
    value = json.loads(text).get(key)
    return value if isinstance(value, str) else ""


def stale_report(summary_path):
    """Turn a stale-payload gate summary into the operator-facing refusal:
    returns (primary_reason, refusal_text, audit_detail). The reasons are a
    closed set and each gets its own wording because the right next step
    differs: sha_mismatch, missing_stamp and empty_head mean the gate output
    does not describe HEAD (re-run fixes it); review_blocked_at_head means the
    review ran at HEAD and blocked (re-running cannot help, so the findings
    are listed instead)."""
    try:
        summary = load_json_file(summary_path)
        if not isinstance(summary, dict):
            summary = {}
    except (OSError, ValueError):
        summary = {}
    primary = str(summary.get("stale_reason") or "")
    head = str(summary.get("current_sha") or "")
    reasons = summary.get("stale_reasons")
    reasons = reasons if isinstance(reasons, dict) else {}
    listing = summary.get("blocking_findings")
    unlisted = listing is None
    listing = listing if isinstance(listing, list) else []

    gates = {"sha_mismatch": [], "missing_stamp": [], "empty_head": []}
    blocked = False
    for gate, reason in reasons.items():
        reason = str(reason)
        if reason in gates:
            gates[reason].append(str(gate))
        elif reason == "review_blocked_at_head":
            blocked = True
    # No per-gate reasons at all: the legacy single-cause wording.
    if not any(gates.values()) and not blocked:
        gates["sha_mismatch"] = ["review", "adversarial"]
    by_sha, by_stamp, by_head = (", ".join(gates[k]) for k in
                                 ("sha_mismatch", "missing_stamp", "empty_head"))

    entries = []
    for item in listing:
        if isinstance(item, dict):
            entries.append((str(item.get("file", "")), str(item.get("line", "")),
                            str(item.get("severity", "")), str(item.get("message", ""))))
    text, audit = [], []
    if blocked:
        short = head[:12]
        if unlisted:
            text.append("the review at HEAD %s has unresolved blocking findings; blocking "
                        "findings could not be listed; see last-review.json. Running the "
                        "review again at the same commit does not clear them." % short)
            audit.append("review blocked at HEAD [review_blocked_at_head]: blocking findings "
                         "could not be listed")
        elif entries:
            listed = "; ".join("%s:%s [%s] %s" % e for e in entries)
            names = ", ".join("%s:%s" % e[:2] for e in entries)
            text.append("the review at HEAD %s has unresolved blocking findings (%d): %s. Fix "
                        "them (or record a deferral in .clagentic/deferrals.json) and commit; "
                        "running the review again at the same commit does not clear them."
                        % (short, len(entries), listed))
            audit.append("review blocked at HEAD [review_blocked_at_head]: %d unresolved "
                         "blocking finding(s): %s" % (len(entries), names))
        else:
            text.append("the review at HEAD %s recorded a blocking verdict but no blocking "
                        "findings are on record (an infra-degraded run records one); see "
                        "'clagentic-lite gates digest' for the cause." % short)
            audit.append("review blocked at HEAD [review_blocked_at_head]: no blocking "
                         "findings on record (degraded run?)")
    if by_sha:
        text.append("stale gate payload (SHA mismatch): %s was produced for a different "
                    "commit than HEAD — re-run clagentic-lite gates review and gates "
                    "adversarial first." % by_sha)
        audit.append("stale payload [sha_mismatch]: %s — re-run review + adversarial "
                     "(SHA mismatch)" % by_sha)
    if by_stamp:
        text.append("stale gate payload (no SHA stamp or no passing verdict recorded for "
                    "HEAD): %s — re-run clagentic-lite gates review and gates "
                    "adversarial first." % by_stamp)
        audit.append("stale payload [missing_stamp]: %s — no SHA stamp or passing "
                     "verdict at HEAD, re-run review + adversarial" % by_stamp)
    if by_head:
        text.append("stale gate payload: HEAD could not be resolved in this git repository, "
                    "so no gate output can be matched to it.")
        audit.append("stale payload [empty_head]: HEAD unresolved")

    if blocked:
        primary = "review_blocked_at_head"
    elif not primary:
        primary = "sha_mismatch" if by_sha else ("missing_stamp" if by_stamp else "empty_head")
    return primary, " ".join(text), " | ".join(audit)


# --------------------------------------------------------------- gate summary

DETGATES_FENCE_BEGIN = "===BEGIN DETERMINISTIC GATES DATA===\n"
DETGATES_FENCE_END = "\n===END DETERMINISTIC GATES DATA===\n"


def _flag(value):
    return str(value).lower() == "true"


def _load_fenced(path, unavailable_literal, degraded_in):
    """(value, degraded). A source already marked degraded, or whose staged
    payload cannot be read back as a string, becomes the fixed 'source
    unavailable' marker: never None and never an empty string a caller could
    read as 'no findings'."""
    marker = json.loads(unavailable_literal)
    if degraded_in:
        return marker, True
    if not path:
        return None, False
    try:
        value = load_json_file(path)
    except (OSError, ValueError):
        return marker, True
    if value is None or (isinstance(value, str) and value):
        return value, False
    return marker, True


def build_gate_summary(opts):
    """The payload handed to the Merge Gate. Mechanical counts are computed
    here from the structured sidecar rather than asking the model to re-derive
    the blocking/advisory split from prose."""
    review_fenced, review_degraded = _load_fenced(
        opts.review_fenced_file, opts.review_unavailable, _flag(opts.review_degraded))
    adversarial_fenced, adversarial_report_degraded = _load_fenced(
        opts.adversarial_fenced_file, opts.adversarial_unavailable,
        _flag(opts.adversarial_report_degraded))
    try:
        if not opts.det_gates:
            raise ValueError("empty deterministic_gates payload")
        deterministic_gates = json.loads(opts.det_gates)
        deterministic_gates_fenced = json.loads(opts.det_gates_fenced)
    except ValueError:
        deterministic_gates = {"secrets": None, "deps": None, "sast": None,
                               "audit_db_unavailable": True}
        deterministic_gates_fenced = (DETGATES_FENCE_BEGIN
                                      + json.dumps(deterministic_gates, indent=2)
                                      + DETGATES_FENCE_END)
    findings = []
    if opts.adf:
        try:
            loaded = load_json_file(opts.adf)
            if isinstance(loaded, list):
                findings = loaded
        except (OSError, ValueError):
            findings = []
    dicts = [f for f in findings if isinstance(f, dict)]
    blocking = sum(1 for f in dicts if f.get("tier") == "blocking")
    advisory = sum(1 for f in dicts if f.get("tier") == "advisory")
    # One diff has one resolved class: any ephemeral finding means the Auditor
    # read the diff as ephemeral. Null when there is nothing to resolve.
    resolved_class = None
    if findings:
        resolved_class = ("ephemeral" if any(f.get("class") == "ephemeral" for f in dicts)
                          else "durable")
    # The parser's security-floor clamp makes this shape impossible for a
    # sidecar it wrote; computing it independently is a cross-check that
    # should always read 0, and a nonzero value is itself a signal.
    downgraded = sum(1 for f in dicts
                     if f.get("class") == "ephemeral" and f.get("tier") == "advisory"
                     and f.get("reachable") == "yes"
                     and f.get("severity") in ("high", "critical"))
    dropped = 0
    if opts.adf_meta:
        try:
            value = load_json_file(opts.adf_meta).get("dropped_count", 0)
            dropped = value if isinstance(value, int) else 0
        except (OSError, ValueError, AttributeError):
            dropped = 0
    findings_fenced = ("===BEGIN ADVERSARIAL FINDINGS DATA===\n"
                       + json.dumps(findings, indent=2)
                       + "\n===END ADVERSARIAL FINDINGS DATA===")
    if _flag(opts.adf_degraded):
        findings = []
        findings_fenced = json.loads(opts.adf_unavailable)
    acks = []
    if opts.acks:
        try:
            acks = load_json_file(opts.acks)
        except (OSError, ValueError):
            acks = []
    accepted_risks = ""
    if opts.accepted_risks:
        try:
            with open(opts.accepted_risks, encoding="utf-8") as handle:
                accepted_risks = handle.read()
        except (OSError, ValueError):
            accepted_risks = ""
    return json.dumps({
        "review_fenced": review_fenced,
        "review_sha": opts.review_sha,
        "review_degraded": review_degraded,
        "adversarial_fenced": adversarial_fenced,
        "adversarial_report_degraded": adversarial_report_degraded,
        "adversarial_missing": _flag(opts.adversarial_missing),
        "adversarial_degraded": _flag(opts.adversarial_degraded),
        "adversarial_findings": findings,
        "adversarial_findings_fenced": findings_fenced,
        "adversarial_blocking_count": blocking,
        "adversarial_advisory_count": advisory,
        "resolved_change_class": resolved_class,
        "adversarial_downgraded_by_class_count": downgraded,
        "adversarial_findings_dropped_count": dropped,
        "adversarial_acks": acks,
        "accepted_risks": accepted_risks,
        "deterministic_gates": deterministic_gates,
        "deterministic_gates_fenced": deterministic_gates_fenced,
        "introduces_ack_file": _flag(opts.introduces_ack),
        "threshold": opts.threshold,
    })


# ------------------------------------------------------------------------ CLI

def _print(text):
    sys.stdout.write(text)


def cmd_ingest_review_envelope(args):
    return ingest_review_envelope(args.file)


def cmd_ingest_findings(args):
    if args.strict:
        try:
            _print(dumps(extract_findings_strict(args.file)))
        except (OSError, ValueError, KeyError):
            return 1
        return 0
    _print(dumps(extract_findings(args.file)))
    return 0


def cmd_ingest_adversarial_parse(args):
    try:
        _print(dumps(parse_adversarial_findings(args.file)))
    except (OSError, ValueError):
        return 1
    return 0


def _stdin_json_array():
    """(text, array); array is None when stdin is not a JSON array."""
    try:
        text = read_stdin_text()
    except UnicodeDecodeError:
        return "", None
    try:
        value = json.loads(text)
    except ValueError:
        return text, None
    return text, value if isinstance(value, list) else None


def cmd_ingest_adversarial_sanitize(args):
    _, array = _stdin_json_array()
    if array is None:
        return 1
    try:
        _print(dumps(sanitize_fields_strict(array, ("file", "category", "message"))))
    except ValueError:
        return 1
    return 0


def cmd_ingest_adversarial_sort(args):
    text, array = _stdin_json_array()
    _print(dumps(sort_blocking_first(array)) if array is not None else text)
    return 0


def cmd_ingest_cap(args):
    text, array = _stdin_json_array()
    _print(dumps(array[:args.max]) if array is not None else text)
    return 0


def cmd_ingest_is_array(args):
    _, array = _stdin_json_array()
    return 0 if array is not None else 1


def cmd_ingest_length(args):
    _, array = _stdin_json_array()
    _print(str(len(array)) if array is not None else "0")
    return 0


def cmd_ingest_merge(args):
    code, envelope = merge_envelopes(args.dir, args.strategy)
    _print(dumps(envelope) + "\n")
    return code


def cmd_ingest_sanitize_text(args):
    limit = args.max if args.max and args.max > 0 else None
    try:
        _print(sanitize_text(read_stdin_text(), limit))
    except UnicodeDecodeError:
        return 1
    return 0


def cmd_ingest_allowlist(args):
    _, array = _stdin_json_array()
    if array is None:
        return 1
    try:
        _print(dumps(allowlist_fields(array, args.fields)))
    except ValueError:
        return 1
    return 0


def cmd_ingest_sanitize_fields(args):
    _, array = _stdin_json_array()
    if array is None:
        return 1
    try:
        _print(dumps(sanitize_fields_strict(array, args.fields)))
    except ValueError:
        return 1
    return 0


def cmd_fingerprint_dedup(args):
    try:
        text = read_stdin_text()
    except UnicodeDecodeError:
        return 1
    try:
        findings = json.loads(text)
        if not isinstance(findings, list):
            raise ValueError("not a list")
    except ValueError:
        # Conservative: never suppress on input we cannot parse.
        _print(text)
        return 0
    seen = read_key_file(args.seen) if args.seen else set()
    kept, new_keys = dedup_findings(findings, args.strategy, seen, args.diff,
                                    args.mode == "annotate")
    append_key_file(args.seen, new_keys)
    _print(dumps(kept) + "\n")
    return 0


def cmd_fingerprint_keys(args):
    try:
        findings = json.loads(read_stdin_text())
    except ValueError:
        return 0
    if not isinstance(findings, list):
        return 0
    for row in content_key_rows(findings, args.diff):
        _print("\t".join(row) + "\n")
    return 0


def cmd_fingerprint_bump(args):
    rows = [line for line in read_stdin_text().split("\n") if line]
    keyed = [row for row in rows if row.split("\t")[0]]
    new_counts = iter(bump_counts(args.counts, [row.split("\t")[0] for row in keyed]))
    for row in rows:
        count = next(new_counts) if row.split("\t")[0] else 1
        _print("%s\t%d\n" % (row, count))
    return 0


def cmd_dispositions_cross_round(args):
    try:
        before, after, seen_before = cross_round(args.file, args.diff, args.seen)
    except StageFailure as failure:
        return failure.code
    _print("%d %d %d\n" % (before, after, seen_before))
    return 0


def cmd_dispositions_recurrence(args):
    demoted = recurrence_demote(args.file, args.diff, args.counts, args.threshold)
    _print("none\n" if demoted is None else "demoted=%d\n" % demoted)
    return 0


def cmd_dispositions_deferrals(args):
    path = args.deferrals or args.root + "/.clagentic/deferrals.json"
    matched = deferral_match(args.file, path, args.root)
    _print("none\n" if matched is None else "matched=%d\n" % matched)
    return 0


def cmd_dispositions_ledger_recurrence(args):
    text = read_stdin_text()
    try:
        findings = json.loads(text)
        if not isinstance(findings, list):
            raise ValueError("not a list")
    except ValueError:
        _print(text)
        return 0
    _print(dumps(mark_ledger_recurrence(findings, args.ledger, args.branch)))
    return 0


def cmd_dispositions_lint(args):
    code, lines = lint_deferrals(args.file)
    for line in lines:
        _print(line + "\n")
    return code


def cmd_verdict_blockers(args):
    _print(str(count_blockers(args.file, args.threshold)) + "\n")
    return 0


def cmd_verdict_blocking_json(args):
    try:
        text = read_stdin_text()
    except UnicodeDecodeError:
        text = ""
    listing = blocking_findings_listing(text, args.threshold)
    _print("null" if listing is None else dumps(listing))
    return 0


def cmd_verdict_rank(args):
    _print(str(SEVERITY_RANKS.get(args.name, 0)) + "\n")
    return 0


def cmd_verdict_ledger_entries(args):
    for entry in ledger_entries(args.ledger, args.branch):
        _print(dumps(entry) + "\n")
    return 0


def cmd_verdict_ledger_latest(args):
    entry = latest_gate_entry(args.ledger, args.branch, args.gate)
    if entry is not None:
        _print(dumps(entry) + "\n")
    return 0


def cmd_verdict_ledger_field(args):
    try:
        entry = json.loads(read_stdin_text())
        if not isinstance(entry, dict):
            raise ValueError("entry is not an object")
    except ValueError:
        return 1
    if args.json_default is not None:
        value = entry.get(args.field)
        _print(args.json_default if value is None or value is False else dumps(value))
    else:
        _print(field_text(entry, args.field))
    return 0


def cmd_verdict_ledger_state(args):
    _print(head_verdict_state(args.ledger, args.branch, args.head, args.gate))
    return 0


def cmd_verdict_ledger_pass(args):
    return 0 if anchored_pass(args.ledger, args.branch, args.head, args.gate) else 1


def cmd_verdict_ledger_pass_head(args):
    _print(latest_passing_head(args.ledger, args.branch, args.gate))
    return 0


def cmd_verdict_ledger_append(args):
    ledger_append(args.ledger, read_stdin_text(), args.max)
    return 0


def cmd_verdict_ledger_entry(args):
    _print(build_ledger_entry(args.ts, args.branch, args.gate, args.base, args.head,
                              args.verdict, read_stdin_text(), args.config))
    return 0


def cmd_render_review(args):
    try:
        code, lines = render_review(args.file)
    except (OSError, ValueError, AttributeError) as exc:
        warn("[findings] cannot render %s: %s" % (args.file, exc))
        return 1
    for line in lines:
        _print(CLASS_FOOTER if line is None else line + "\n")
    return code


def cmd_render_class_footer(args):
    """The static hand-off line, printed iff some finding names a class."""
    try:
        findings = load_json_file(args.file).get("findings")
        named = any(_class_named(f) for f in (findings or []))
    except (OSError, ValueError, AttributeError, TypeError):
        warn("review class footer: cannot read %s" % args.file)
        return 1
    if named:
        _print(CLASS_FOOTER)
    return 0


def cmd_render_verdict_lines(args):
    try:
        text = read_stdin_text()
    except UnicodeDecodeError:
        return 2
    code, out = render_verdict_lines(args.head, text)
    _print(out)
    return code


def cmd_render_sanitize_review(args):
    try:
        _print(sanitize_review_for_prompt(args.file))
    except (OSError, ValueError):
        return 1
    return 0


def cmd_render_sanitize_report(args):
    try:
        _print(sanitize_report_for_prompt(args.file))
    except (OSError, ValueError):
        return 1
    return 0


def cmd_render_fence_data(args):
    try:
        _print(fence_data_block(args.label, args.kind, read_stdin_text()))
    except UnicodeDecodeError:
        return 1
    return 0


def cmd_render_fence_findings(args):
    _print(fence_findings(read_stdin_text()))
    return 0


def cmd_render_json_field(args):
    try:
        _print(json_string_field(read_stdin_text(), args.key))
    except (ValueError, AttributeError):
        pass
    return 0


def cmd_render_stale_report(args):
    _print("\x1f".join(stale_report(args.file)))
    return 0


def cmd_render_gate_summary(args):
    try:
        _print(build_gate_summary(args) + "\n")
    except (OSError, ValueError):
        return 1
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="findings.py", description=__doc__.split("\n")[0])
    stages = parser.add_subparsers(dest="stage", required=True)

    def op(stage, name, func, *arguments):
        sub = stage.add_parser(name)
        for spec, kwargs in arguments:
            sub.add_argument(spec, **kwargs)
        sub.set_defaults(func=func)
        return sub

    ingest = stages.add_parser("ingest").add_subparsers(dest="op", required=True)
    op(ingest, "review-envelope", cmd_ingest_review_envelope, ("file", {}))
    sub = op(ingest, "findings", cmd_ingest_findings, ("file", {}))
    sub.add_argument("--strict", action="store_true")
    op(ingest, "adversarial-parse", cmd_ingest_adversarial_parse, ("file", {}))
    op(ingest, "adversarial-sanitize", cmd_ingest_adversarial_sanitize)
    op(ingest, "adversarial-sort", cmd_ingest_adversarial_sort)
    sub = op(ingest, "cap", cmd_ingest_cap)
    sub.add_argument("--max", type=int, default=DEFAULT_FINDINGS_MAX)
    op(ingest, "length", cmd_ingest_length)
    op(ingest, "is-array", cmd_ingest_is_array)
    sub = op(ingest, "merge", cmd_ingest_merge, ("dir", {}))
    sub.add_argument("--strategy", default="location")
    sub = op(ingest, "sanitize-text", cmd_ingest_sanitize_text)
    sub.add_argument("--max", type=int, default=0)
    op(ingest, "allowlist", cmd_ingest_allowlist, ("fields", {"nargs": "+"}))
    op(ingest, "sanitize-fields", cmd_ingest_sanitize_fields, ("fields", {"nargs": "+"}))

    fingerprint = stages.add_parser("fingerprint").add_subparsers(dest="op", required=True)
    sub = op(fingerprint, "dedup", cmd_fingerprint_dedup)
    sub.add_argument("--strategy", default="location")
    sub.add_argument("--seen", default="")
    sub.add_argument("--diff", default="")
    sub.add_argument("--mode", default="drop")
    sub = op(fingerprint, "keys", cmd_fingerprint_keys)
    sub.add_argument("--diff", default="")
    op(fingerprint, "bump", cmd_fingerprint_bump, ("counts", {}))

    dispositions = stages.add_parser("dispositions").add_subparsers(dest="op", required=True)
    sub = op(dispositions, "cross-round", cmd_dispositions_cross_round, ("file", {}))
    sub.add_argument("--diff", required=True)
    sub.add_argument("--seen", required=True)
    sub = op(dispositions, "recurrence", cmd_dispositions_recurrence, ("file", {}))
    sub.add_argument("--diff", required=True)
    sub.add_argument("--counts", required=True)
    sub.add_argument("--threshold", type=int, required=True)
    sub = op(dispositions, "deferrals", cmd_dispositions_deferrals, ("file", {}))
    sub.add_argument("--root", required=True)
    sub.add_argument("--deferrals", default="")
    sub = op(dispositions, "ledger-recurrence", cmd_dispositions_ledger_recurrence)
    sub.add_argument("--ledger", required=True)
    sub.add_argument("--branch", required=True)
    op(dispositions, "lint", cmd_dispositions_lint, ("file", {}))

    verdict = stages.add_parser("verdict").add_subparsers(dest="op", required=True)
    op(verdict, "blockers", cmd_verdict_blockers, ("file", {}), ("threshold", {}))
    op(verdict, "blocking-json", cmd_verdict_blocking_json, ("threshold", {}))
    op(verdict, "rank", cmd_verdict_rank, ("name", {}))
    op(verdict, "ledger-entries", cmd_verdict_ledger_entries, ("ledger", {}), ("branch", {}))
    op(verdict, "ledger-latest", cmd_verdict_ledger_latest,
       ("ledger", {}), ("branch", {}), ("gate", {}))
    sub = op(verdict, "ledger-field", cmd_verdict_ledger_field, ("field", {}))
    sub.add_argument("--json-default", default=None)
    op(verdict, "ledger-state", cmd_verdict_ledger_state,
       ("ledger", {}), ("branch", {}), ("head", {}), ("gate", {}))
    op(verdict, "ledger-pass", cmd_verdict_ledger_pass,
       ("ledger", {}), ("branch", {}), ("head", {}), ("gate", {}))
    op(verdict, "ledger-pass-head", cmd_verdict_ledger_pass_head,
       ("ledger", {}), ("branch", {}), ("gate", {}))
    op(verdict, "ledger-append", cmd_verdict_ledger_append,
       ("ledger", {}), ("max", {"type": int}))
    sub = op(verdict, "ledger-entry", cmd_verdict_ledger_entry)
    for name in ("ts", "branch", "gate", "base", "head", "verdict", "config"):
        sub.add_argument("--" + name, required=True)

    render = stages.add_parser("render").add_subparsers(dest="op", required=True)
    op(render, "review", cmd_render_review, ("file", {}))
    op(render, "class-footer", cmd_render_class_footer, ("file", {}))
    op(render, "verdict-lines", cmd_render_verdict_lines, ("head", {}))
    op(render, "sanitize-review", cmd_render_sanitize_review, ("file", {}))
    op(render, "sanitize-report", cmd_render_sanitize_report, ("file", {}))
    op(render, "fence-data", cmd_render_fence_data, ("label", {}), ("kind", {}))
    op(render, "fence-findings", cmd_render_fence_findings)
    op(render, "json-field", cmd_render_json_field, ("key", {}))
    op(render, "stale-report", cmd_render_stale_report, ("file", {}))
    sub = op(render, "gate-summary", cmd_render_gate_summary)
    sub.add_argument("--threshold", default="high")
    for name in ("introduces-ack", "adversarial-missing", "adversarial-degraded",
                 "review-degraded", "adversarial-report-degraded", "adf-degraded"):
        sub.add_argument("--" + name, default="false")
    for name in ("acks", "accepted-risks", "adf", "adf-meta", "review-fenced-file",
                 "adversarial-fenced-file", "review-sha", "det-gates", "det-gates-fenced",
                 "review-unavailable", "adversarial-unavailable", "adf-unavailable"):
        sub.add_argument("--" + name, default="")
    return parser


def main(argv=None):
    setup_io()
    args = build_parser().parse_args(argv)
    try:
        code = args.func(args)
    finally:
        sys.stdout.flush()
    return code


if __name__ == "__main__":
    sys.exit(main())
