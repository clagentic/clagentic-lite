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
                union-samples FILE... [--root DIR] [--base REF]  (N review samples)
  fingerprint   dedup --strategy S --seen FILE [--diff FILE] [--mode drop|annotate]
                keys --diff FILE | bump COUNTS_FILE
  dispositions  cross-round FILE --diff FILE --seen FILE
                recurrence FILE --diff FILE --counts FILE
                ledger-recurrence --ledger FILE --branch NAME
                lint [FILE] [--root DIR] | migrate --root DIR [--write]
  verdict       blockers FILE THRESHOLD | blocking-json THRESHOLD | rank NAME
                ledger-entries|ledger-latest|ledger-field|ledger-state|ledger-pass|
                ledger-pass-head|ledger-append|ledger-entry
  render        review FILE | verdict-lines HEAD | sanitize-review FILE
                sanitize-report FILE | fence-data LABEL KIND | fence-findings
                json-field KEY | stale-report FILE | gate-summary OPTIONS
  evaluate      [--gate review|adversarial|merge-gate] [--format json|markdown]
                [--no-input] [--root DIR] [--head SHA] [--base REF] [--json]
                the code verdict: unified findings on stdin, dispositions and
                guardrails, per-HEAD accumulation; exits 1 when BLOCKED. A
                finding that states facts (attacker_precondition, impact,
                reachable, class) has its severity decided by the rubric from
                those facts and the stakes profile, never by its own claim.
  profile       [--root DIR] [--write] [--confirm] [--answer [GLOB:]DIM=VALUE]...
                draft or update .clagentic/risk-profile.json from the tree and
                the operator's answers; prints it, or writes it with --write
                as a change to review and commit

Findings and other payloads of unbounded size arrive on stdin or as file
paths, never as argv: one argv string over the kernel's MAX_ARG_STRLEN fails
exec. Exit status is the contract: 0 ok, 1 refused or failed closed (for
evaluate: BLOCKED), 2 unreadable or refused input where the caller must tell
that apart from empty or BLOCKED, 70 an internal crash.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile

CRASH_STATUS = 70
SEVERITY_RANKS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_THRESHOLD_RANK = 3
# A severity that is present but is not a known rank name (a non-string, or a
# string like 'blocker' or 'crit') cannot be ranked; it counts as blocking so a
# malformed value can never slip under the threshold.
UNRANKABLE_RANK = 4
FAIL_CLOSED_BLOCKERS = 99
CLASS_ISOLATED = "none — isolated"
DEFAULT_MAX_FIELD_CHARS = 500
DEFAULT_FINDINGS_MAX = 200
TRUNCATION_SUFFIX = "...[truncated]"

# severity_claimed is the model's own severity, kept for display; the facts
# (reachable, attacker_precondition, impact, class) are what the rubric reads.
REVIEW_FINDING_FIELDS = (
    "severity", "severity_claimed", "file", "line:number", "category", "message",
    "evidence", "suggestion", "issue_class", "class_fix", "reachable",
    "attacker_precondition", "impact", "class",
)
# Free-text review fields that reach the merge-gate prompt, and the closed set
# of keys a finding may carry into that payload (the review schema plus the
# gate-written annotations, which are not free text).
PROMPT_REVIEW_TEXT_FIELDS = (
    "severity", "severity_claimed", "file", "category", "message", "evidence",
    "suggestion", "issue_class", "class_fix", "reachable", "attacker_precondition",
    "impact", "class", "severity_moved",
)
PROMPT_REVIEW_KEEP_KEYS = (
    "severity", "severity_claimed", "file", "line", "category", "message", "evidence",
    "suggestion", "issue_class", "class_fix", "reachable", "attacker_precondition",
    "impact", "class", "severity_moved", "_recurrence_count",
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
    "===BEGIN CODE VERDICT DATA===", "===END CODE VERDICT DATA===",
)
_FENCE_PATTERNS = [re.compile(re.escape(label), re.IGNORECASE) for label in _FENCE_LABELS]
# Characters that never belong in text a person or a model reads as a finding:
# C0 controls, DEL, the C1 block (U+009B is a one-byte CSI on some terminals)
# and the bidirectional overrides and isolates that reorder what a reader sees.
# The one definition both text sanitizers below derive from.
_C1_AND_BIDI = ("\x7f-\x9f" + chr(0x202A) + "-" + chr(0x202E) + chr(0x2066) + "-" + chr(0x2069))
# Prompt text keeps tab and newline; terminal text keeps neither.
_UNSAFE_RE = re.compile("[\x00-\x08\x0b-\x1f" + _C1_AND_BIDI + "]")
_CONTROL_RE = re.compile("[\x00-\x1f" + _C1_AND_BIDI + "]")
_CSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)")
_ESC_RE = re.compile(r"\x1b.")
_HUNK_RE = re.compile(r"\+(\d+)")
_HUNK_COUNTS_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_FILE_LINE_RE = re.compile(r"^(.+):(\d+)$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ADVERSARIAL_HEADER_RE = re.compile(
    r"^\[FINDING\]\s*([^|]+)\|\s*([^|]+)\|\s*severity:\s*([^|]+?)\s*"
    r"(?:\|\s*reachable:\s*([^|]+?)\s*)?"
    r"(?:\|\s*precondition:\s*([^|]+?)\s*)?"
    r"(?:\|\s*impact:\s*([^|]+?)\s*)?"
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

def canonical_severity(severity):
    """A severity string reduced to a known rank name, or None when it is not
    one. Whitespace and case are normalized because models routinely return
    'HIGH' or 'high '; nothing else is guessed at ('crit' is not 'critical')."""
    if not isinstance(severity, str):
        return None
    name = severity.strip().lower()
    return name if name in SEVERITY_RANKS else None


def severity_rank(severity):
    """The one severity ranking. None is rank 0 (the field is absent). Anything
    present that is not a known rank name once stripped and lowercased, whether
    a non-string or a string like 'blocker', cannot be ranked and counts as
    blocking."""
    if severity is None:
        return 0
    name = canonical_severity(severity)
    if name is None:
        return UNRANKABLE_RANK
    return SEVERITY_RANKS[name]


def threshold_rank(name):
    """Threshold name -> rank; anything unknown means 'high'."""
    return SEVERITY_RANKS.get(name, 0) or DEFAULT_THRESHOLD_RANK


def counts_toward_verdict(finding, threshold):
    """A review finding blocks when its severity meets the threshold. Whether a
    disposition clears it is decided later, by the verdict; no field a finding
    carries can excuse it, so a model cannot write its own exemption."""
    return severity_rank(finding.get("severity")) >= threshold


def triple(finding):
    """(file, category, message): the match key for every cross-round
    comparison that must survive line-number drift."""
    return (str(finding.get("file", "")), str(finding.get("category", "")),
            str(finding.get("message", "")))


# ----------------------------------------------------------------- sanitizing

def sanitize_text(text, limit=None):
    """Neutralize text before it is written to a file or interpolated into a
    prompt a later model reads: strip terminal escapes, control bytes, C1
    controls and bidirectional overrides (tab and newline stay), defang every
    fence label, cap the length."""
    if limit is None:
        limit = max_field_chars()
    text = _CSI_RE.sub("", text)
    text = _OSC_RE.sub("", text)
    text = _ESC_RE.sub("", text)
    text = _UNSAFE_RE.sub("", text)
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
    if isinstance(value, list):
        return value
    if "findings" in document:
        # Lenient callers still get [], but never silently: a present non-array
        # is a malformed envelope, and the strict path is what fails closed on it.
        warn("[findings] %s: 'findings' is not an array; read as no findings here "
             "(the strict path refuses it)" % path)
    return []


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
    not survive, and an empty list must not read as 'no findings'. Returns
    False when the stub could not be written: the raw findings may then still
    be in PATH, and the caller must not let the run go on with them."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(SANITIZE_FAILED_ENVELOPE)
    except OSError as exc:
        warn("[findings] could not rewrite %s: %s" % (path, exc))
        try:
            os.unlink(path)
        except OSError as unlink_exc:
            warn("[findings] could not remove %s either: %s; it may still hold raw "
                 "unsanitized findings" % (path, unlink_exc))
        return False
    warn("[gates/review] review findings could not be reduced to the closed schema; "
         "marked the envelope degraded")
    return True


def ingest_review_envelope(path):
    """Reduce an envelope's findings to the closed review schema in place. This
    is the choke point: a model must not be able to forge a gate-owned
    annotation in its own response. Exit 1 when the envelope could neither be
    reduced nor replaced by the degraded stub: raw findings are never left as
    the answer."""
    if not os.path.isfile(path):
        return 0
    try:
        findings = extract_findings_strict(path)
        clean = allowlist_fields(findings, REVIEW_FINDING_FIELDS)
        splice_findings(path, clean)
    except (OSError, ValueError, KeyError):
        return 0 if mark_review_sanitize_failed(path) else 1
    return 0


# ---------------------------------------------------------------- adversarial

def parse_adversarial_findings(path):
    """Loose-parse [FINDING] header lines of the Auditor's markdown into
    structured findings. Every enum-shaped field is force-corrected to a member
    of its closed set; tier is clamped by two mechanical rules so neither the
    model nor an injected diff can move a finding across the blocking line."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, ValueError) as exc:
        warn("_parse_adversarial_findings: could not read %s: %s" % (path, exc))
        raise
    return parse_adversarial_text(text)


def parse_adversarial_text(text):
    """The findings in the Auditor's markdown, one per [FINDING] header line."""
    findings = []
    for line in text.split("\n"):
        match = _ADVERSARIAL_HEADER_RE.match(line.strip())
        if not match:
            continue
        cwe = match.group(1).strip()
        fileline = match.group(2).strip()
        severity_raw = match.group(3).strip().lower()
        reachable_raw = (match.group(4) or "").strip().lower()
        precondition_raw = match.group(5)
        impact_raw = match.group(6)
        tier_raw = (match.group(7) or "").strip().lower()
        class_raw = (match.group(8) or "").strip().lower()
        title = match.group(9).strip()
        located = _FILE_LINE_RE.match(fileline)
        if located:
            fname, lineno = located.group(1), int(located.group(2))
        else:
            fname, lineno = fileline, 0
        severity = severity_raw if severity_raw in SEVERITY_RANKS else "unknown"
        # A header that states facts is read by the rubric, where an unstated or
        # invalid reachable is the worst case (unknown, treated as reachable). A
        # header without facts keeps the older reading, where it is "no".
        facts_stated = precondition_raw is not None or impact_raw is not None
        if reachable_raw in ("yes", "no"):
            reachable = reachable_raw
        else:
            reachable = "unknown" if facts_stated else "no"
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
        record = {
            "file": fname, "line": lineno, "category": cwe, "message": title,
            "severity": severity, "reachable": reachable, "tier": tier,
            "class": change_class,
        }
        if facts_stated:
            # The closed vocabulary is enforced here too, so free text in a fact
            # position never reaches a sidecar. The severity and tier written
            # above are the model's; the rubric replaces them at evaluation, and
            # the unprofiled reading below is what a sidecar shows until then.
            record["severity_claimed"] = severity
            record["attacker_precondition"] = fact_value(
                precondition_raw, PRECONDITIONS, UNKNOWN_FACT)
            record["impact"] = fact_value(impact_raw, IMPACTS, UNKNOWN_FACT)
            provisional = rubric_for_record(record, None)
            record["severity"] = provisional["severity"]
            record["tier"] = provisional["tier"]
        findings.append(record)
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
    try:
        splice_findings(env_path, kept)
    except (OSError, ValueError):
        raise StageFailure(SPLICE_FAILED)
    # Recorded only once the annotated findings are in the envelope: a failed
    # splice must not leave this round's keys behind, or the next run would
    # report these findings as seen in a round whose result never landed.
    append_key_file(seen_path, new_keys)
    seen_before = sum(1 for f in kept if isinstance(f, dict) and f.get("_seen_before") is True)
    return len(findings), len(kept), seen_before


def recurrence_count(env_path, diff_path, counts_path):
    """Record how many rounds each surviving finding has been reported in, as
    an informational _recurrence_count. The count never changes whether a
    finding blocks: an open finding stays open until it is fixed or
    dispositioned, so repetition is context for the reader, not an exemption.
    Findings dedup kept only because an earlier run saw them are not counted
    again. Counts are per finding (by content key, once per round per key) and
    are persisted only after the envelope was rewritten. Returns the number of
    findings counted, or None when nothing was counted (envelope untouched
    apart from clearing a stale count). An envelope whose findings are not an
    array is never touched: None, no exception, nothing rewritten."""
    try:
        findings = extract_findings_strict(env_path)
    except (OSError, ValueError, KeyError):
        return None
    stale = [f for f in findings if isinstance(f, dict) and "_recurrence_count" in f]
    for finding in stale:
        del finding["_recurrence_count"]
    keyed = []
    if diff_path and os.path.isfile(diff_path):
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict) or finding.get("_seen_before") is True:
                continue
            try:
                key = window_key(finding, diff_path)
            except (AttributeError, TypeError, ValueError):
                continue
            if key:
                keyed.append((index, key))
    counts = read_counts(counts_path)
    distinct = list(dict.fromkeys(key for _, key in keyed))
    new = dict(zip(distinct, next_counts(counts, distinct)))
    for index, key in keyed:
        findings[index]["_recurrence_count"] = new[key]
    if not keyed and not stale:
        return None
    try:
        splice_findings(env_path, findings)
    except (OSError, ValueError):
        return None
    if not keyed:
        return None
    write_counts(counts_path, counts)
    return len(keyed)


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


# ----------------------------------------------------- unified finding schema
#
# Review findings (JSON) and adversarial findings (markdown [FINDING] headers)
# are reduced to ONE record shape before anything decides about them:
#
#   source, file, line, category (a CWE or rule class), message, evidence,
#   reachable (yes|no|unknown), class (durable|ephemeral), severity_claimed
#   (the model's own value, display only), severity (that value as a known
#   rank name, or "unknown" when it is not one), tier (adversarial only), and
#   the pipeline-added fingerprint (a link hint, never an identity to drop a
#   finding on).
#
# The record is rebuilt from the input field by field: whatever else a model
# or another producer wrote (a forged "disposition", a forged "fingerprint")
# is not carried over.

SOURCES = ("review", "adversarial")
REACHABLE_VALUES = ("yes", "no", "unknown")
CHANGE_CLASSES = ("durable", "ephemeral")
# Reachable at this rank (high) or above is the security floor.
FLOOR_RANK = 3
EVALUATE_MAX_FINDINGS = 1000
STATE_MAX_FINDINGS = 5000
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_ENTRIES = 1000
MAX_TEXT = 2000
GIT_TIMEOUT_SEC = 60
STATE_SCHEMA = 1
DISPOSITIONS_SCHEMA = 1


class InputRefused(Exception):
    """The input cannot be evaluated; the verdict is never computed from it."""


def norm_text(text):
    return " ".join(str(text).lower().split())


def norm_path(path):
    """A finding's file as a normalized relative path, so 'src/../auth.py' and
    './auth.py' cannot reach a glob that was written for another file."""
    text = str(path).strip().replace("\\", "/")
    normal = posixpath.normpath(text) if text else ""
    return "" if normal == "." else normal


def plain_relative_path(path):
    """PATH as a normalized repo-relative path when it is a plain one, else
    None: no '..' segment, not absolute, no NUL, not empty. Used for every path
    that is read from a file the repository holds and then opened, where
    norm_path's forgiving collapse of 'a/../b' would hide an escape attempt."""
    text = str(path).strip().replace("\\", "/")
    if not text or "\x00" in text or text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        return None
    if ".." in text.split("/"):
        return None
    normal = norm_path(text)
    return normal or None


def open_contained_regular(root, rel):
    """A binary read handle on REL under ROOT, or None when REL is not a plain
    relative path, resolves (through symlinks) outside ROOT, or is not a
    regular file. The kind check is made on the opened descriptor and the open
    does not block, so a FIFO or a device node can neither hang nor be read."""
    plain = plain_relative_path(rel)
    if plain is None:
        return None
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(real_root, plain))
    if real != real_root and not real.startswith(real_root + os.sep):
        return None
    try:
        fd = os.open(real, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        # 0o170000 is S_IFMT and 0o100000 is S_IFREG: spelled out so this file
        # keeps to the imports it already has.
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            os.close(fd)
            return None
        return os.fdopen(fd, "rb")
    except OSError:
        os.close(fd)
        return None


def sha256_stream(handle, chunk=1024 * 1024):
    """sha256 hex digest of everything HANDLE yields, read in chunks."""
    digest = hashlib.sha256()
    for block in iter(lambda: handle.read(chunk), b""):
        digest.update(block)
    return digest.hexdigest()


def finding_identity(source, fname, category, message):
    """The fingerprint hint: stable across line drift and across runs, so the
    same observation reported twice links to itself. Source is part of it: a
    review finding and an adversarial finding about one issue are two open
    items, each cleared on its own terms."""
    raw = "\x1f".join((source, norm_path(fname), norm_text(category), norm_text(message)))
    return sha256_hex(raw)[:32]


def _clean(value, limit):
    return sanitize_text(value if isinstance(value, str) else "", limit)


def _line_number(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float) and value.is_integer():
        return max(int(value), 0)
    return 0


def adversarial_tier(reachable, severity, given):
    """Reachability is the precondition for blocking; reachable at high or
    above is the security floor and always blocks. Between the two the
    model's own tier stands."""
    if reachable != "yes":
        return "advisory"
    if severity_rank(severity) >= FLOOR_RANK:
        return "blocking"
    return given if given in ("blocking", "advisory") else "advisory"


def unify_finding(raw, source, stakes=None):
    """One input finding as a unified record. Raises ValueError for an input
    that is not an object: a finding that cannot be read is never skipped.

    A finding that states facts (attacker_precondition or impact) has its
    severity (and, for the Auditor, its tier) decided by the rubric from those
    facts and STAKES; the model's own severity is kept as severity_claimed for
    display. A finding with neither fact is from a producer that predates the
    vocabulary and keeps the severity it claimed."""
    if not isinstance(raw, dict):
        raise ValueError("a finding is not an object")
    claimed = raw.get("severity_claimed", raw.get("severity"))
    if claimed is None:
        shown, severity = "", None
    elif isinstance(claimed, str):
        shown, severity = claimed, canonical_severity(claimed) or "unknown"
    else:
        shown, severity = dumps(claimed), "unknown"
    reachable = raw.get("reachable")
    reachable = reachable.strip().lower() if isinstance(reachable, str) else ""
    if reachable not in REACHABLE_VALUES:
        reachable = "unknown"
    change_class = raw.get("class")
    change_class = change_class.strip().lower() if isinstance(change_class, str) else ""
    if change_class not in CHANGE_CLASSES:
        change_class = "durable"
    record = {
        "source": source,
        "file": _clean(raw.get("file"), 300),
        "line": _line_number(raw.get("line")),
        "category": _clean(raw.get("category"), 100),
        "message": _clean(raw.get("message"), 500),
        "evidence": _clean(raw.get("evidence"), 1000),
        "reachable": reachable,
        "class": change_class,
        "severity_claimed": sanitize_text(shown, 40),
        "severity": severity,
    }
    if source == "adversarial":
        given = raw.get("tier")
        record["tier"] = adversarial_tier(
            reachable, severity, given.strip().lower() if isinstance(given, str) else "")
    for key in ("suggestion", "issue_class", "class_fix"):
        if isinstance(raw.get(key), str):
            record[key] = _clean(raw[key], 500)
    record["schema"] = FINDING_SCHEMA
    if has_facts(raw):
        record["attacker_precondition"] = fact_value(
            raw.get("attacker_precondition"), PRECONDITIONS, UNKNOWN_FACT)
        record["impact"] = fact_value(raw.get("impact"), IMPACTS, UNKNOWN_FACT)
        apply_rubric(record, stakes)
    record["fingerprint"] = finding_identity(
        source, record["file"], record["category"], record["message"])
    return record


def unify_findings(raw_findings, source, stakes=None):
    if not isinstance(raw_findings, list):
        raise ValueError("findings is not an array")
    if len(raw_findings) > EVALUATE_MAX_FINDINGS:
        raise ValueError("more than %d findings" % EVALUATE_MAX_FINDINGS)
    return [unify_finding(raw, source, stakes) for raw in raw_findings]


def is_floor(finding):
    """The security floor. A finding on it can be cleared by a fix, or by a
    mitigation that names the control, and by nothing that merely calls it
    acceptable. For a finding the rubric decided, it is reachable, high impact
    and an EFFECTIVE precondition of none or network (the finding's own
    precondition raised only by what the profile genuinely establishes); for
    one from a producer without facts it is reachable at severity high or
    above, as before."""
    if finding.get("rubric_applied"):
        return bool(finding.get("floor"))
    return finding.get("reachable") == "yes" and severity_rank(finding.get("severity")) >= FLOOR_RANK


def is_blocking(finding, threshold):
    """Whether an unaddressed finding blocks. An adversarial finding blocks by
    its tier (clamped, or decided by the rubric); a review finding blocks when
    its severity (the rubric's, when it has facts) meets the threshold."""
    if finding.get("source") == "adversarial":
        return finding.get("tier") == "blocking"
    return severity_rank(finding.get("severity")) >= threshold


# ----------------------------------------------- facts and the deterministic rubric
#
# A model is asked for facts, never for a severity it would have to defend. The
# facts are drawn from closed vocabularies; a value outside its vocabulary, or
# a missing one, resolves to the WORST case, so a model cannot lower a finding
# by garbling a field. The severity of a finding that states facts is then a
# pure function of those facts and the stakes profile (below):
#
#     severity = RUBRIC_TABLE[impact weight][effective precondition]
#
# where the impact weight is the impact scaled by the data the path handles,
# and the effective precondition is what the attacker must already have once
# the profile's exposure, visibility and merge control are taken into account
# (the CVSS Attack Vector / Privileges Required and Confidentiality /
# Integrity Requirement analogues). The same facts and the same profile always
# give the same severity, on the gate path and in a standalone agent.

FINDING_SCHEMA = 2
UNKNOWN_FACT = "unknown"
PRECONDITIONS = ("none", "network", "authenticated_user", "repo_write_can_merge",
                 "maintainer_admin", "local_ci_only")
IMPACTS = ("code_exec", "data_read", "data_write", "integrity", "availability",
           "quality_only")
EXPOSURES = ("internet", "internal_authenticated", "local_or_ci_only")
DATA_LEVELS = ("regulated_or_customer", "internal", "public_or_none")
VISIBILITIES = ("public", "private")
MERGE_CONTROLS = ("code_owner_review_required", "review_required", "unrestricted")
DIMENSIONS = {"exposure": EXPOSURES, "data": DATA_LEVELS, "visibility": VISIBILITIES,
              "merge_control": MERGE_CONTROLS}
# Unstated dimensions mean the worst case, so an absent profile is today's
# behavior. Each tuple lists a dimension's values worst first.
WORST_DIMS = {"exposure": "internet", "data": "regulated_or_customer",
              "visibility": "public", "merge_control": "unrestricted"}
WORST_ORDER = {"exposure": EXPOSURES, "data": DATA_LEVELS, "visibility": VISIBILITIES,
               "merge_control": ("unrestricted", "review_required", "code_owner_review_required")}
WORST_PRECONDITION = "none"
WORST_IMPACT = "code_exec"

IMPACT_WEIGHT = {"quality_only": 0, "availability": 1, "data_read": 2, "data_write": 3,
                 "integrity": 3, "code_exec": 4}
IMPACT_WEIGHT_NAMES = ("negligible", "low", "moderate", "high", "severe")
DATA_SCALED_IMPACTS = ("data_read", "data_write", "integrity")
DATA_SHIFT = {"regulated_or_customer": 1, "internal": 0, "public_or_none": -1}
# Impact weights at or above this one are "high impact" for the security floor.
FLOOR_IMPACT_WEIGHT = 3
PRECONDITION_COLUMN = {"none": 0, "network": 0, "authenticated_user": 1,
                       "repo_write_can_merge": 2, "maintainer_admin": 3, "local_ci_only": 4}
# Rows are impact weights 0..4. Columns: none or network (open to anyone),
# authenticated_user, repo_write_can_merge, maintainer_admin, local_ci_only.
RUBRIC_TABLE = (
    ("medium", "low", "low", "low", "low"),
    ("medium", "medium", "low", "low", "low"),
    ("high", "medium", "medium", "low", "low"),
    ("critical", "high", "medium", "medium", "low"),
    ("critical", "high", "high", "medium", "medium"),
)
UNREACHABLE_CAP = "medium"
SEVERITY_NAMES = ("low", "medium", "high", "critical")


def fact_value(raw, allowed, worst):
    """RAW as a member of ALLOWED (case and surrounding space ignored), else
    WORST. The one place a fact is checked against its vocabulary."""
    if isinstance(raw, str):
        value = raw.strip().lower()
        if value in allowed:
            return value
    return worst


def has_facts(raw):
    """A finding states facts when it carries either of the two the rubric
    cannot do without; one without is from a producer that predates them."""
    return "attacker_precondition" in raw or "impact" in raw


def worst_dims():
    return {dim: (WORST_DIMS[dim], "no profile statement") for dim in DIMENSIONS}


def evaluate_rubric(precondition, impact, reachable, change_class, dims):
    """The rubric as a pure function. PRECONDITION and IMPACT are fact values
    (anything outside the vocabulary reads as the worst case), REACHABLE is
    yes, no or unknown (unknown reads as yes), CHANGE_CLASS durable or
    ephemeral, DIMS maps each stakes dimension to (value, where it came from).
    Returns severity, whether the finding is on the security floor, the
    effective precondition and the steps by which the profile moved it."""
    precondition = precondition if precondition in PRECONDITIONS else WORST_PRECONDITION
    impact = impact if impact in IMPACTS else WORST_IMPACT
    is_reachable = reachable != "no"
    exposure, exposure_via = dims["exposure"]
    visibility, visibility_via = dims["visibility"]
    merge, merge_via = dims["merge_control"]
    data, data_via = dims["data"]
    moves = []
    effective = precondition

    def move(new, dimension, value, via):
        if new != effective:
            moves.append("precondition %s -> %s via %s=%s for %s"
                         % (effective, new, dimension, value, via))
        return new

    # A private repository has no anonymous reader, but only where the path is
    # not itself exposed to the internet: an internet-facing path keeps its
    # anonymous attacker whoever can read the source.
    if visibility == "private" and exposure != "internet" and effective == "none":
        effective = move("authenticated_user", "visibility", visibility, visibility_via)
    if exposure == "internal_authenticated" and effective == "network":
        effective = move("authenticated_user", "exposure", exposure, exposure_via)
    elif exposure == "local_or_ci_only" and effective in ("network", "authenticated_user"):
        effective = move("local_ci_only", "exposure", exposure, exposure_via)
    if merge == "code_owner_review_required" and effective == "repo_write_can_merge":
        effective = move("maintainer_admin", "merge_control", merge, merge_via)

    weight = IMPACT_WEIGHT[impact]
    scaled = weight
    if impact in DATA_SCALED_IMPACTS:
        scaled = min(max(weight + DATA_SHIFT[data], 0), 4)
        worst_case = min(weight + DATA_SHIFT[WORST_DIMS["data"]], 4)
        if scaled != worst_case:
            moves.append("impact weight %s -> %s via data=%s for %s"
                         % (IMPACT_WEIGHT_NAMES[worst_case], IMPACT_WEIGHT_NAMES[scaled],
                            data, data_via))
    # A throwaway change excuses only what longevity makes matter; it never
    # touches an impact an attacker uses.
    if change_class == "ephemeral" and impact in ("availability", "quality_only"):
        scaled = max(scaled - 1, 0)
    severity = RUBRIC_TABLE[scaled][PRECONDITION_COLUMN[effective]]
    # The profile can raise the weight (regulated data) but never lower a
    # high-impact finding out of the floor: the floor reads the larger of the
    # unscaled and scaled weight.
    floor = (is_reachable and effective in ("none", "network")
             and max(weight, scaled) >= FLOOR_IMPACT_WEIGHT)
    if floor and severity_rank(severity) < FLOOR_RANK:
        severity = "high"
    if not is_reachable and severity_rank(severity) > severity_rank(UNREACHABLE_CAP):
        severity = UNREACHABLE_CAP
    return {"severity": severity, "floor": floor, "effective_precondition": effective,
            "moves": moves}


def rubric_for_record(record, stakes):
    """The rubric's reading of one unified RECORD under STAKES (None means no
    profile: the worst case in every dimension). Adds the tier an Auditor
    finding takes (blocking exactly when it is reachable and at least high) and
    the severity the same facts get with no profile, which is what 'moved by
    the profile' is measured against."""
    dims = stakes.dims_for(record.get("file", "")) if stakes is not None else worst_dims()
    facts = (record.get("attacker_precondition"), record.get("impact"),
             record.get("reachable"), record.get("class"))
    result = evaluate_rubric(*facts, dims=dims)
    result["unprofiled"] = evaluate_rubric(*facts, dims=worst_dims())["severity"]
    reachable = record.get("reachable") != "no"
    result["tier"] = ("blocking" if reachable and severity_rank(result["severity"]) >= FLOOR_RANK
                      else "advisory")
    return result


def apply_rubric(record, stakes):
    """Replace RECORD's severity (and an Auditor finding's tier) with the
    rubric's. The model's own severity stays in severity_claimed, display only."""
    result = rubric_for_record(record, stakes)
    record["rubric_applied"] = True
    record["severity"] = result["severity"]
    record["floor"] = result["floor"]
    record["effective_precondition"] = result["effective_precondition"]
    record["severity_unprofiled"] = result["unprofiled"]
    record["moves"] = result["moves"]
    if record.get("source") == "adversarial":
        record["tier"] = result["tier"]
    return record


def rubric_moved_text(record):
    """What moved a finding below its no-profile severity, or '' when nothing
    did: the steps, each naming the dimension and the path glob or default that
    moved it."""
    if not record.get("rubric_applied") or not record.get("moves"):
        return ""
    if severity_rank(record.get("severity")) >= severity_rank(record.get("severity_unprofiled")):
        return ""
    return "; ".join(record["moves"])


_IMPACT_ORDER = {name: index for index, name in enumerate(IMPACTS)}


def _stronger_precondition(first, second):
    if first not in PRECONDITIONS or second not in PRECONDITIONS:
        return UNKNOWN_FACT
    return first if PRECONDITIONS.index(first) <= PRECONDITIONS.index(second) else second


def _stronger_impact(first, second):
    if first not in IMPACTS or second not in IMPACTS:
        return UNKNOWN_FACT
    rank = lambda name: (IMPACT_WEIGHT[name], -_IMPACT_ORDER[name])  # noqa: E731
    return first if rank(first) >= rank(second) else second


def merge_facts(known, record):
    """Fold RECORD's facts into KNOWN toward the stronger reading of each (the
    easier precondition, the larger impact; a value outside its vocabulary on
    either side stays the worst case). The rubric then reads the merged facts,
    so a re-run can only raise a finding, never lower it."""
    known["attacker_precondition"] = _stronger_precondition(
        known.get("attacker_precondition"), record.get("attacker_precondition"))
    known["impact"] = _stronger_impact(known.get("impact"), record.get("impact"))


# ------------------------------------------------------------ the stakes profile
#
# What is at stake on a path is not something a model can see in a diff: whether
# it is served to the internet or only to staff behind SSO, whether it handles
# customer data, who can merge to it. That is recorded, optionally, in one
# committed file, .clagentic/risk-profile.json, and read here in code. The file
# is optional and agent-maintained (the `profile` command drafts and updates it
# from the tree and the operator's answers, as a reviewable change); it cannot
# apply itself (the version at the merge base is the one that counts, exactly as
# for dispositions); an unstated dimension means the worst case, so an absent
# profile changes nothing; and a claim the tree contradicts in the unsafe
# direction is ignored, loudly.

PROFILE_REL = ".clagentic/risk-profile.json"
PROFILE_SCHEMA = 1
PROFILE_MAX_ENTRIES = 500
PROFILE_DEFAULT_MAX_AGE_DAYS = 180
INFER_MAX_FILES = 20000
INFER_MAX_FILE_BYTES = 64 * 1024
INFER_MAX_TOTAL_BYTES = 64 * 1024 * 1024
CHANGED_PATHS_MAX = 5000
CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", ".gitea/CODEOWNERS", ".forgejo/CODEOWNERS",
                        ".gitlab/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
_PROFILE_ENTRY_KEYS = ("glob", "inferred", "evidence", "note")


def _worse_value(dimension, first, second):
    order = WORST_ORDER[dimension]
    return first if order.index(first) <= order.index(second) else second


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
                or _UNSAFE_RE.search(glob)):
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
                    if _worse_value(dimension, other, value) != value:
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
            if _worse_value(marker["dimension"], marker["value"], current) != current:
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


# Tree inference. Heuristics, deliberately few; each is a marker that a path is
# exposed or handles sensitive data, found by reading the committed tree. A
# marker can only RAISE a dimension (and contradict a profile that says
# otherwise), except the test-path fill above.

_SOURCE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java", ".kt", ".php",
                ".rs", ".cs", ".scala", ".ex", ".exs")
_MANIFEST_EXTS = (".yaml", ".yml", ".tpl")
_SCHEMA_EXTS = (".sql", ".prisma", ".proto", ".graphql", ".avsc", ".xsd")
_SCHEMA_DIRS = ("models", "model", "schemas", "schema", "entities", "migrations", "migrate")
_SCHEMA_NAMES = ("models.py", "schema.py", "schema.rb", "models.ts", "models.js")
_WORKFLOW_DIRS = (".github/workflows/", ".gitea/workflows/", ".forgejo/workflows/")
_SKIP_DIRS = (".git", "node_modules", "vendor", ".clagentic", ".venv", "venv", "__pycache__")
_INGRESS_RE = re.compile(
    r"^\s*kind:\s*[\"']?(?:Ingress|IngressRoute|HTTPRoute|VirtualService|Gateway|Route)[\"']?\s*$",
    re.M)
_LOADBALANCER_RE = re.compile(r"^\s*type:\s*[\"']?LoadBalancer[\"']?\s*$", re.M)
# Signs that an ingress or load balancer is internal or sits behind an auth
# layer; with one present the file is not read as a public ingress.
_INTERNAL_SIGNAL_RE = re.compile(
    r"ingressClassName:\s*[\"']?[\w./-]*internal|kubernetes\.io/ingress\.class:\s*[\"']?[\w./-]*internal"
    r"|load-balancer-internal|load-balancer-type:\s*[\"']?internal|\bauth-url\b|\bauth-signin\b"
    r"|oauth2-proxy|whitelist-source-range|allowlist-source-range|loadBalancerSourceRanges",
    re.I)
_EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+\d", re.M | re.I)
_SERVER_RE = re.compile(
    r"\b(?:Flask|FastAPI|Sanic|Starlette|Bottle)\(|\bexpress\(\)|\b[Ff]astify\(|http\.ListenAndServe"
    r"|http\.createServer|\bapp\.listen\(|@(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete)\("
    r"|\bgin\.(?:Default|New)\(|\becho\.New\(|\bfiber\.New\(|\buvicorn\.run\(|Rails\.application\.routes"
    r"|@(?:Get|Post|Put|Delete|Request)Mapping")
_PUBLIC_TRIGGER_RE = re.compile(r"\bpull_request_target\b|\bissue_comment\b")
_PII_RE = re.compile(
    r"\b(?:ssn|social_security(?:_number)?|date_of_birth|dob|birth_?date|passport(?:_number)?"
    r"|national_id|tax_id|drivers?_?licen[cs]e|credit_card|card_number|cvv|iban|account_number"
    r"|email(?:_address)?|phone(?:_number)?|home_address|street_address|salary|diagnosis)\b", re.I)
_PAYMENT_RE = re.compile(
    r"^\s*(?:import|from|use|using)\b[^\n]*\b(?:stripe|braintree|paypal|adyen)\b"
    r"|require\(\s*[\"'](?:stripe|braintree|paypal|adyen)[\"']\s*\)", re.I | re.M)
_CREDENTIAL_RE = re.compile(
    r"\b(?:bcrypt|argon2|scrypt|pbkdf2|password_hash|hashpw|check_password_hash"
    r"|generate_password_hash)\b", re.I)
_SURFACE_AUTH_RE = re.compile(
    r"(?:^|[/_.-])(?:auth|authn|authz|oauth|oidc|saml|sso|login|session|rbac|acl|permission)s?"
    r"(?:[/_.-]|$)", re.I)
_SURFACE_EXPOSURE_RE = re.compile(
    r"(?:ingress|route|gateway|virtualservice|dockerfile|containerfile|docker-compose"
    r"|loadbalancer)", re.I)


def list_repo_files(root):
    """Repo-relative paths of the tracked and untracked-but-not-ignored files,
    up to INFER_MAX_FILES, or None when git cannot list them."""
    proc = git_run(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    if proc is None or proc.returncode != 0:
        return None
    names = [n for n in proc.stdout.decode("utf-8", "replace").split("\0") if n]
    names = sorted(set(names))
    return [n for n in names
            if not any(part in _SKIP_DIRS for part in n.split("/")[:-1])][:INFER_MAX_FILES]


def _dir_glob(path):
    directory = posixpath.dirname(path)
    return "**" if not directory else glob_escape(directory) + "/**"


def _read_head(root, rel, budget):
    """Up to INFER_MAX_FILE_BYTES of REL as text, or None; BUDGET is a one-item
    list of the bytes still allowed to be read in this scan."""
    if budget[0] <= 0:
        return None
    handle = open_contained_regular(root, rel)
    if handle is None:
        return None
    try:
        data = handle.read(INFER_MAX_FILE_BYTES)
    except OSError:
        return None
    finally:
        handle.close()
    budget[0] -= len(data)
    return data.decode("utf-8", "replace")


def infer_markers(root, files=None):
    """(markers, notes) read from the working tree. A marker is a dict with
    dimension, value (the worse value it implies), glob, compiled, file, why."""
    notes = []
    if files is None:
        files = list_repo_files(root)
    if files is None:
        return [], ["the tree could not be listed; nothing was inferred from it"]
    if len(files) >= INFER_MAX_FILES:
        notes.append("the tree has more than %d files; inference read only the first %d"
                     % (INFER_MAX_FILES, INFER_MAX_FILES))
    budget = [INFER_MAX_TOTAL_BYTES]
    markers = []

    def add(dimension, value, glob, rel, why):
        markers.append({"dimension": dimension, "value": value, "glob": glob,
                        "compiled": compile_glob(glob), "file": rel, "why": why})

    for rel in files:
        name = posixpath.basename(rel)
        lowered = name.lower()
        ext = posixpath.splitext(lowered)[1]
        wants_exposure_text = (ext in _MANIFEST_EXTS or lowered.startswith(("dockerfile", "containerfile"))
                               or ext in _SOURCE_EXTS or rel.startswith(_WORKFLOW_DIRS))
        schema_like = (ext in _SCHEMA_EXTS or lowered in _SCHEMA_NAMES
                       or any(part in _SCHEMA_DIRS for part in rel.split("/")[:-1]))
        if not (wants_exposure_text or schema_like):
            continue
        text = _read_head(root, rel, budget)
        if text is None:
            continue
        if ext in _MANIFEST_EXTS:
            public = _INGRESS_RE.search(text) or _LOADBALANCER_RE.search(text)
            if public and not _INTERNAL_SIGNAL_RE.search(text):
                what = "an ingress or route" if _INGRESS_RE.search(text) else "a LoadBalancer service"
                add("exposure", "internet", _dir_glob(rel), rel, "%s declares %s with no internal marker" % (rel, what))
        if lowered.startswith(("dockerfile", "containerfile")) and _EXPOSE_RE.search(text):
            add("exposure", "internet", _dir_glob(rel), rel, "%s EXPOSEs a port" % rel)
        if ext in _SOURCE_EXTS and _SERVER_RE.search(text):
            add("exposure", "internet", _dir_glob(rel), rel, "%s starts a server or declares routes" % rel)
        if rel.startswith(_WORKFLOW_DIRS) and _PUBLIC_TRIGGER_RE.search(text):
            add("exposure", "internet", glob_escape(rel), rel,
                "%s runs on a trigger any outsider can cause (pull_request_target or issue_comment)" % rel)
        if schema_like and _PII_RE.search(text):
            add("data", "regulated_or_customer", _dir_glob(rel), rel,
                "%s defines PII-shaped fields" % rel)
        if ext in _SOURCE_EXTS and (_PAYMENT_RE.search(text) or _CREDENTIAL_RE.search(text)):
            add("data", "regulated_or_customer", _dir_glob(rel), rel,
                "%s handles payments or credentials" % rel)
    return markers, notes


def changed_paths(root, base):
    """Paths that differ between BASE and the working tree, plus untracked
    ones: what the gated change touches. [] when BASE is unknown."""
    if not base:
        return []
    paths = set()
    for args in (["diff", "--name-only", "-z", base], ["ls-files", "-z", "--others", "--exclude-standard"]):
        proc = git_run(root, args)
        if proc is not None and proc.returncode == 0:
            paths.update(n for n in proc.stdout.decode("utf-8", "replace").split("\0") if n)
    return sorted(paths)[:CHANGED_PATHS_MAX]


def touches_exposure_surface(path, marker_files):
    """Whether PATH is part of what the profile's exposure and data claims
    describe: an ingress, route or service manifest, a container or workflow
    definition, auth code, a data schema, or a file inference drew a marker
    from."""
    if path in marker_files:
        return True
    lowered = path.lower()
    name = posixpath.basename(lowered)
    if _SURFACE_EXPOSURE_RE.search(name) or path.startswith(_WORKFLOW_DIRS):
        return True
    if _SURFACE_AUTH_RE.search(lowered):
        return True
    ext = posixpath.splitext(name)[1]
    return (ext in _SCHEMA_EXTS or name in _SCHEMA_NAMES
            or any(part in _SCHEMA_DIRS for part in lowered.split("/")[:-1]))


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
            if _worse_value(marker["dimension"], marker["value"], claimed) != claimed:
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
    touched = [p for p in changed_paths(root, base) if touches_exposure_surface(p, marker_files)]
    if touched:
        stakes.warnings.append(
            "this change touches the exposure surface (%d path(s): %s); re-confirm the risk profile "
            "with 'findings.py profile' (clagentic-lite gates profile). This is a prompt, not a block."
            % (len(touched), ", ".join(terminal_text(p, 80) for p in touched[:5])))


# ------------------------------------------------------- dispositions store
#
# ONE committed file records what an operator decided about a class of
# findings: .clagentic/dispositions.json. Matching is done here, in code, and
# never by a model. The legacy files (deferrals.json, adversarial-acks.json,
# accepted-risks.md) are still read for one release, converted to the same
# entries, with a deprecation warning.

DISPOSITIONS_REL = ".clagentic/dispositions.json"
LEGACY_DEFERRALS_REL = ".clagentic/deferrals.json"
LEGACY_ACKS_REL = ".clagentic/adversarial-acks.json"
LEGACY_RISKS_REL = ".clagentic/accepted-risks.md"
STATE_REL = ".clagentic/lite/findings-state.json"
DISPOSITION_KINDS = ("by_design", "false_positive", "accepted_risk", "mitigated")
DISPOSITION_GATES = ("review", "adversarial")
_PLACEHOLDER_RE = re.compile(r"^<[^<>]*>$")
_HINT_RE = re.compile(r"^[0-9a-f]{8,64}$")
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ].*)?$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/~^-]+$")


def parse_date(value):
    """The calendar date a string starts with (YYYY-MM-DD, optionally followed
    by a time), or None."""
    if not isinstance(value, str):
        return None
    match = _DATE_RE.match(value.strip())
    if not match:
        return None
    try:
        return datetime.date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def today_date(override=None):
    """Today, from OVERRIDE or CLAGENTIC_FINDINGS_TODAY when given (tests and
    reproducible runs), else the local date. An override that is not a date is
    refused rather than ignored."""
    text = override or os.environ.get("CLAGENTIC_FINDINGS_TODAY", "")
    if not text:
        return datetime.date.today()
    parsed = parse_date(text)
    if parsed is None:
        raise InputRefused("the date override %r is not YYYY-MM-DD" % text)
    return parsed


_GLOBSTAR = "**"


def compile_glob(glob):
    """A path glob as a list of path segments. A segment that is exactly '**'
    matches zero or more whole path segments; within any other segment '*'
    matches any run of characters and '?' one character, neither crossing a
    '/'; a backslash escapes the next character. Matching is by dynamic
    programming (see glob_matches), never by a backtracking regex, because the
    glob comes from a file the matcher does not trust."""
    segments, tokens, stars_only = [], [], True
    i = 0

    def close():
        segments.append(_GLOBSTAR if (stars_only and len(tokens) >= 2) else tokens[:])
        del tokens[:]

    while i < len(glob):
        char = glob[i]
        if char == "\\" and i + 1 < len(glob):
            tokens.append(("lit", glob[i + 1]))
            stars_only = False
            i += 2
            continue
        if char == "/":
            close()
            stars_only = True
            i += 1
            continue
        if char == "*":
            tokens.append(("star", char))
        else:
            stars_only = False
            tokens.append(("any", char) if char == "?" else ("lit", char))
        i += 1
    close()
    # '*' runs inside an ordinary segment collapse to one: they match the same.
    out = []
    for segment in segments:
        if segment is _GLOBSTAR:
            out.append(_GLOBSTAR)
            continue
        collapsed = []
        for token in segment:
            if token[0] == "star" and collapsed and collapsed[-1][0] == "star":
                continue
            collapsed.append(token)
        out.append(collapsed)
    return out


def _segment_matches(tokens, text):
    """Wildcard match of one path segment: linear in the text per backtrack
    point, no exponential case."""
    ti = si = 0
    star, mark = -1, 0
    while si < len(text):
        if ti < len(tokens) and (tokens[ti][0] == "any" or (tokens[ti][0] == "lit"
                                                              and tokens[ti][1] == text[si])):
            ti += 1
            si += 1
        elif ti < len(tokens) and tokens[ti][0] == "star":
            star, mark = ti, si
            ti += 1
        elif star != -1:
            ti = star + 1
            mark += 1
            si = mark
        else:
            return False
    while ti < len(tokens) and tokens[ti][0] == "star":
        ti += 1
    return ti == len(tokens)


def glob_match_compiled(segments, path):
    parts = path.split("/")
    count = len(parts)
    reachable = {0}
    for segment in segments:
        following = set()
        if segment is _GLOBSTAR:
            following = set(range(min(reachable), count + 1))
        else:
            for index in reachable:
                if index < count and _segment_matches(segment, parts[index]):
                    following.add(index + 1)
        if not following:
            return False
        reachable = following
    return count in reachable


def glob_matches(glob, path):
    return glob_match_compiled(compile_glob(glob), path)


# Paths of every shape a repository holds, dotted and hidden names included.
# '*' stays within one segment, so a catch-all is a glob that matches every
# top-level name or every nested path; the two probe sets test each.
_PROBE_TOP_LEVEL = ("a", "0", "z", "README.md", ".env", "x.y")
_PROBE_NESTED = ("a/b", "a/b/c", ".github/workflows/ci.yml", "src/app/main.go",
                 "docs/a.b/c.d.e", "deep/" * 8 + "file.txt")


def matches_every_probe(glob):
    """True when GLOB is a catch-all: it matches every top-level probe name or
    every nested probe path. Decided by the compiled matcher, so '*', '?*',
    '**', '**/*', '***', '**/**' and '*/*/**' are all caught however they are
    spelled."""
    compiled = compile_glob(glob)
    for probes in (_PROBE_TOP_LEVEL, _PROBE_NESTED):
        if all(glob_match_compiled(compiled, probe) for probe in probes):
            return True
    return False


def glob_escape(path):
    return re.sub(r"([*?\\])", r"\\\1", path)


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
        if _UNSAFE_RE.search(value):
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


def read_text_bounded(path):
    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise OSError("%s is larger than %d bytes" % (path, MAX_FILE_BYTES))
    return data.decode("utf-8")


def worktree_reader(root):
    """A reader of repo-relative files from the working tree: text, or None
    for an absent file. A path that resolves outside the repository is an
    error, not a file."""
    real_root = os.path.realpath(root)

    def read(rel):
        path = os.path.join(root, rel)
        if not os.path.lexists(path):
            return None
        real = os.path.realpath(path)
        if real != real_root and not real.startswith(real_root + os.sep):
            raise OSError("%s resolves outside the repository" % rel)
        return read_text_bounded(real)
    return read


def git_run(root, args):
    """A completed git process, or None when git cannot run or times out. The
    variables that redirect which repository git touches are dropped so
    '-C root' decides."""
    drop = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE")
    env = {k: v for k, v in os.environ.items() if k not in drop}
    try:
        return subprocess.run(["git", "-C", root] + list(args), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=GIT_TIMEOUT_SEC, env=env)
    except (OSError, subprocess.SubprocessError):
        return None


def git_reader(root, base):
    """A reader of repo-relative files as they were at commit BASE."""
    def read(rel):
        listing = git_run(root, ["ls-tree", base, "--", rel])
        if listing is None or listing.returncode != 0:
            raise OSError("cannot read %s at %s" % (rel, base[:12]))
        if not listing.stdout.strip():
            return None
        blob = git_run(root, ["cat-file", "blob", "%s:%s" % (base, rel)])
        if blob is None or blob.returncode != 0:
            raise OSError("cannot read %s at %s" % (rel, base[:12]))
        if len(blob.stdout) > MAX_FILE_BYTES:
            raise OSError("%s is larger than %d bytes" % (rel, MAX_FILE_BYTES))
        return blob.stdout.decode("utf-8")
    return read


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


def introduced_entry_keys(root, base):
    """The set of entry contents the BASE commit already had, or None when the
    base is unknown. None means every entry counts as added in this change."""
    if not base:
        return None
    base_store = load_store(root, git_reader(root, base), check_hash=False)
    return {entry_key(entry) for entry in base_store["entries"]}


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


# ------------------------------------------------------------------ git state

def is_repo_toplevel(root):
    """Whether ROOT is itself the top level of a git repository. 'git -C' only
    changes directory before git walks upward looking for a repository, so a
    directory inside an ancestor's work tree would otherwise be answered with
    the ancestor's refs and files."""
    top = git_run(root, ["rev-parse", "--show-toplevel"])
    if top is None or top.returncode != 0:
        return False
    return os.path.realpath(top.stdout.decode("utf-8", "replace").strip()) == os.path.realpath(root)


def repo_head(root):
    """HEAD of the repository ROOT is the top level of, or None. The top level
    must be ROOT itself: an ancestor repository is not ROOT's."""
    if not is_repo_toplevel(root):
        return None
    head = git_run(root, ["rev-parse", "HEAD"])
    if head is None or head.returncode != 0:
        return None
    sha = head.stdout.decode("utf-8", "replace").strip()
    return sha if re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", sha) else None


def resolve_base(root, explicit, default_branch):
    """The commit the gated change is measured against, or None. An explicit
    ref wins; otherwise the merge base of HEAD with origin/<default> or
    <default>."""
    if explicit:
        if not _BRANCH_RE.match(explicit) or explicit.startswith("-"):
            return None
        proc = git_run(root, ["rev-parse", "--verify", "--quiet", explicit + "^{commit}"])
        if proc is None or proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace").strip() or None
    name = default_branch or os.environ.get("CLAGENTIC_DEFAULT_BRANCH") or "main"
    if not _BRANCH_RE.match(name) or name.startswith("-"):
        return None
    for ref in ("origin/" + name, name):
        proc = git_run(root, ["merge-base", "HEAD", ref])
        if proc is not None and proc.returncode == 0:
            sha = proc.stdout.decode("utf-8", "replace").strip()
            if sha:
                return sha
    return None


# ------------------------------------------------- per-HEAD accumulation state
#
# Open findings accumulate per HEAD: once a run has found something at a
# commit it stays on the list until the commit changes or a disposition
# clears it, and a re-run can only add. The state is a small file under
# .clagentic/lite/, created on demand, owned by this file alone, so the
# accumulation works in a repository that was never enrolled.

class StateError(Exception):
    """The accumulation state exists but cannot be trusted."""


def state_file(root):
    return os.path.join(root, STATE_REL)


def fresh_state(head):
    return {"schema": STATE_SCHEMA, "head": head, "runs": [], "findings": []}


def load_state(root, head):
    """The state for HEAD. A state recorded at another HEAD starts fresh (a
    new commit is a new question); one that cannot be read is an error, never
    an empty list, because losing the accumulation would silently clear every
    open finding."""
    path = state_file(root)
    if not os.path.exists(path):
        return fresh_state(head)
    try:
        data = load_json_file(path)
    except (OSError, ValueError) as exc:
        raise StateError("%s cannot be read (%s); remove it to start a fresh accumulation" % (path, exc))
    if (not isinstance(data, dict) or data.get("schema") != STATE_SCHEMA
            or not isinstance(data.get("head"), str) or not isinstance(data.get("runs"), list)
            or not isinstance(data.get("findings"), list)):
        raise StateError("%s is not a recognized findings state; remove it to start a fresh accumulation" % path)
    if data["head"] != head:
        return fresh_state(head)
    for item in data["findings"]:
        if (not isinstance(item, dict) or item.get("source") not in SOURCES
                or not isinstance(item.get("fingerprint"), str)):
            raise StateError("%s holds a malformed finding; remove it to start a fresh accumulation" % path)
    return data


class StateLock(object):
    """An exclusive lock around a read-modify-write of the state file, on a
    sibling lock file (the state itself is replaced by rename)."""

    def __init__(self, root):
        self.path = state_file(root) + ".lock"
        self.handle = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        # A run that cannot take the lock must not go on: a concurrent
        # read-modify-write would then lose accumulated findings, and a lost
        # finding reads as a cleared one.
        try:
            import fcntl
            self.handle = open(self.path, "a", encoding="utf-8")
            fcntl.flock(self.handle, fcntl.LOCK_EX)
        except (ImportError, OSError) as exc:
            if self.handle is not None:
                self.handle.close()
                self.handle = None
            raise StateError("could not lock the findings state (%s); refusing to run without "
                             "it because a concurrent run could lose accumulated findings" % exc)
        return self

    def __exit__(self, *exc_info):
        if self.handle is not None:
            self.handle.close()
        return False


def save_state(root, state):
    path = state_file(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_file_atomic(path, dumps(state) + "\n")


_REACHABLE_ORDER = {"no": 0, "unknown": 1, "yes": 2}


def accumulate(state, incoming, gate, caller):
    """Add INCOMING (unified records) to STATE. A finding already there (the
    same source and fingerprint, or the same source, file, line and category)
    is merged toward the stronger reading of each field; nothing is removed.
    Returns the number of findings that were new."""
    by_print = {(f["source"], f["fingerprint"]): f for f in state["findings"]}
    by_place = {(f["source"], f.get("file"), f.get("line"), str(f.get("category", "")).lower()): f
                for f in state["findings"]}
    new = 0
    for record in incoming:
        place = (record["source"], record["file"], record["line"], record["category"].lower())
        known = by_print.get((record["source"], record["fingerprint"])) or by_place.get(place)
        if known is None:
            if len(state["findings"]) >= STATE_MAX_FINDINGS:
                raise InputRefused("more than %d findings at this HEAD" % STATE_MAX_FINDINGS)
            state["findings"].append(record)
            by_print[(record["source"], record["fingerprint"])] = record
            by_place[place] = record
            new += 1
            continue
        if known.get("rubric_applied") and record.get("rubric_applied"):
            # Both carry facts: the stronger facts win and the verdict re-derives
            # the severity from them, so the merge can only raise a finding.
            merge_facts(known, record)
        else:
            # Facts on only one side: fall back to the older reading (the
            # higher claimed or computed severity wins), which can only raise.
            if severity_rank(record["severity"]) > severity_rank(known.get("severity")):
                known["severity"], known["severity_claimed"] = record["severity"], record["severity_claimed"]
            if known.get("rubric_applied"):
                known["rubric_applied"] = False
        if _REACHABLE_ORDER[record["reachable"]] > _REACHABLE_ORDER.get(known.get("reachable"), 1):
            known["reachable"] = record["reachable"]
        if record.get("tier") == "blocking" and not known.get("rubric_applied"):
            known["tier"] = "blocking"
        if record["class"] == "durable":
            known["class"] = "durable"
    state["runs"].append({"gate": gate, "caller": caller, "count": len(incoming), "new": new})
    del state["runs"][:-200]
    return new


# ---------------------------------------------------------------- the verdict

def _public_finding(finding):
    keys = ("source", "file", "line", "category", "message", "severity", "severity_claimed",
            "reachable", "fingerprint")
    out = {key: finding.get(key) for key in keys}
    if finding.get("rubric_applied"):
        out["rubric_applied"] = True
        out["attacker_precondition"] = finding.get("attacker_precondition")
        out["impact"] = finding.get("impact")
    return out


def _public_entry(entry):
    out = {key: entry[key] for key in ("id", "kind", "by", "at", "rationale")}
    for key in ("control", "expires"):
        if key in entry:
            out[key] = entry[key]
    return out


def clearing_stanza(finding, today):
    """The exact disposition entry that would clear FINDING, with its
    judgment fields left as placeholders that the validator refuses, so a
    stanza pasted in unedited clears nothing."""
    fingerprint = finding["fingerprint"]
    floor = is_floor(finding)
    stanza = {
        "id": "disp-" + fingerprint[:10],
        "gates": [finding["source"]],
        "match": {"path_glob": glob_escape(norm_path(finding.get("file", "")) or "**"),
                  "category": finding.get("category") or "*",
                  "fingerprint_hint": fingerprint[:16]},
        "kind": "mitigated" if floor else "by_design",
        "rationale": "<how the named control prevents exploitation>" if floor
                     else "<why this finding does not need a code change>",
        "by": "<who accepts this>",
        "at": today.isoformat(),
    }
    if floor:
        stanza["control"] = "<the external control that mitigates it>"
    return stanza


def build_verdict(state, store, base_keys, threshold_name, today, scope, head, base, stakes=None):
    """The code verdict. Open blocking findings at HEAD, minus the ones a valid,
    live, already-merged disposition clears. A finding that carries facts has
    its severity re-derived here from the (merged) facts and STAKES, so the
    verdict never depends on which run wrote the severity down."""
    threshold = threshold_rank(threshold_name)
    findings = []
    for stored in state["findings"]:
        if scope not in (None, stored["source"]):
            continue
        if stored.get("rubric_applied"):
            stored = apply_rubric(dict(stored), stakes)
        findings.append(stored)
    live, expired = [], []
    for entry in store["entries"]:
        until = parse_date(entry.get("expires")) if entry.get("expires") else None
        (expired if until is not None and until < today else live).append(entry)

    def introduced(entry):
        return base_keys is None or entry_key(entry) not in base_keys

    opened, cleared, pending, refused, advisory = [], [], [], [], 0
    expired_hits = {}
    status = {}
    for finding in findings:
        key = (finding["source"], finding["fingerprint"])
        if not is_blocking(finding, threshold):
            advisory += 1
            status[key] = {"status": "advisory"}
            continue
        winner, added, refusals = None, [], []
        for entry in live:
            if not entry_matches(entry, finding):
                continue
            if not entry_can_clear(entry, finding):
                refusals.append(entry)
            elif introduced(entry):
                added.append(entry)
            elif winner is None:
                winner = entry
        for entry in expired:
            if entry_matches(entry, finding) and entry_can_clear(entry, finding):
                expired_hits[entry["id"]] = expired_hits.get(entry["id"], 0) + 1
        if winner is not None:
            cleared.append(dict(_public_finding(finding), entry=_public_entry(winner)))
            status[key] = {"status": "cleared", "id": winner["id"], "kind": winner["kind"]}
            continue
        for entry in refusals:
            refused.append(dict(_public_finding(finding), entry_id=entry["id"], kind=entry["kind"]))
        for entry in added:
            pending.append(dict(_public_finding(finding), entry_id=entry["id"]))
        record = _public_finding(finding)
        record["floor"] = is_floor(finding)
        record["stanza"] = clearing_stanza(finding, today)
        opened.append(record)
        status[key] = {"status": "open"}
    warnings = list(store["warnings"])
    if base_keys is None and store["entries"]:
        warnings.append("the base commit could not be resolved: every disposition entry is treated "
                        "as added in this change and clears nothing")
    adjusted = []
    for finding in findings:
        moved = rubric_moved_text(finding)
        if moved:
            adjusted.append(dict(_public_finding(finding), moved=moved,
                                 severity_unprofiled=finding["severity_unprofiled"],
                                 outcome="blocking" if is_blocking(finding, threshold) else "advisory"))
    if stakes is not None:
        warnings.extend(stakes.warnings)
        warnings.extend(stakes.notes)
    return {
        "verdict": "BLOCKED" if opened else "PASS",
        "head": head,
        "base": base,
        "threshold": [name for name, rank in SEVERITY_RANKS.items() if rank == threshold][0],
        "scope": scope or "head",
        "total": len(findings),
        "open": opened,
        "cleared": cleared,
        "advisory": advisory,
        "pending_in_change": pending,
        "refused": refused,
        "expired": [dict(_public_entry(e), would_have_cleared=expired_hits.get(e["id"], 0))
                    for e in expired],
        "invalid": store["invalid"],
        "adjusted": adjusted,
        "warnings": warnings,
        "runs": len(state["runs"]),
        "_status": status,
    }


def render_verdict_text(verdict, caller):
    """The verdict as the lines an operator or an agent reads. Every piece of
    model- or operator-authored text goes through terminal_text."""
    t = terminal_text
    lines = []
    head12 = (verdict["head"] or "")[:12]
    if verdict["verdict"] == "BLOCKED":
        lines.append("VERDICT: BLOCKED (%d open blocking finding(s) at HEAD %s)"
                     % (len(verdict["open"]), head12))
    else:
        lines.append("VERDICT: PASS (no open blocking findings at HEAD %s)" % head12)
    lines.append("findings at HEAD (%s): %d, open blocking: %d, cleared by dispositions: %d, "
                 "advisory: %d, threshold: %s"
                 % (verdict["scope"], verdict["total"], len(verdict["open"]),
                    len(verdict["cleared"]), verdict["advisory"], verdict["threshold"]))
    if verdict["open"]:
        lines.append("Open blocking findings:")
        for item in verdict["open"]:
            if item.get("rubric_applied"):
                shown = item["severity"]
                claimed = item.get("severity_claimed")
                if claimed and claimed != shown:
                    shown = "%s; model claimed %s" % (shown, claimed)
            else:
                shown = item["severity_claimed"] or item["severity"] or "unrated"
            lines.append("  [%s] [%s] %s:%s %s: %s (fingerprint %s)%s" % (
                t(item["source"]), t(shown),
                t(item["file"]), t(item["line"]), t(item["category"]), t(item["message"], 300),
                t(item["fingerprint"][:12]), "  [security floor]" if item["floor"] else ""))
    if verdict.get("adjusted"):
        lines.append("Severity set below its no-profile reading by the stakes profile (always listed):")
        for item in verdict["adjusted"]:
            lines.append("  - %s: %s (%s:%s %s; severity %s -> %s)" % (
                t(item["outcome"]), t(item["moved"], 400), t(item["file"]), t(item["line"]),
                t(item["message"], 120), t(item["severity_unprofiled"]), t(item["severity"])))
    if verdict["cleared"]:
        lines.append("Cleared by dispositions (always listed):")
        for item in verdict["cleared"]:
            entry = item["entry"]
            lines.append("  - %s [%s] %s by %s on %s: %s:%s %s -- %s" % (
                t(entry["id"]), t(entry["kind"]), t(item["category"]), t(entry["by"]), t(entry["at"]),
                t(item["file"]), t(item["line"]), t(item["message"], 200), t(entry["rationale"], 300)))
    if verdict["pending_in_change"]:
        count = len(set((p["source"], p["fingerprint"]) for p in verdict["pending_in_change"]))
        lines.append("%d finding%s would be cleared by entries added in this PR. Entries added in "
                     "the gated change do not clear that change's findings; they apply once they "
                     "are on the base branch." % (count, "" if count == 1 else "s"))
        for item in verdict["pending_in_change"]:
            lines.append("  - entry %s would clear %s:%s %s" % (
                t(item["entry_id"]), t(item["file"]), t(item["line"]), t(item["message"], 200)))
    for item in verdict["refused"]:
        lines.append("  - security-floor finding %s:%s %s cannot be cleared by entry %s (kind %s): "
                     "fix it, or record kind mitigated naming the external control"
                     % (t(item["file"]), t(item["line"]), t(item["message"], 200),
                        t(item["entry_id"]), t(item["kind"])))
    for entry in verdict["expired"]:
        lines.append("Expired: entry %s (%s) expired on %s and no longer applies%s" % (
            t(entry["id"]), t(entry["kind"]), t(entry.get("expires")),
            "; it would have cleared %d finding(s)" % entry["would_have_cleared"]
            if entry["would_have_cleared"] else ""))
    for record in verdict["invalid"]:
        lines.append("Invalid disposition ignored (%s, %s): %s" % (
            t(record["source"]), t(record["id"]), "; ".join(record["errors"])))
    for warning in verdict["warnings"]:
        lines.append("note: " + t(warning, 400))
    if verdict["open"]:
        lines.append("To clear a finding, a reviewed change merged to the base branch must add an entry "
                     "to %s. The exact stanza for each open finding (fill in the <placeholders>):"
                     % DISPOSITIONS_REL)
        for item in verdict["open"]:
            lines.append(dumps(item["stanza"], indent=2))
    if caller == "standalone":
        lines.append("note: run outside 'gates'; this verdict does not count toward 'gates ship', "
                     "which requires its own review run and ledger entry.")
    return "\n".join(lines) + "\n"


def cleared_summary(text):
    """One line naming the dispositions a saved code verdict (the JSON that
    evaluate --json-out writes) cleared findings by, for the audit trail.
    Empty when nothing was cleared; raises ValueError for an unreadable one."""
    document = json.loads(text)
    cleared = document.get("cleared") if isinstance(document, dict) else None
    if not isinstance(cleared, list):
        raise ValueError("not a code verdict")
    seen, parts = set(), []
    for item in cleared:
        entry = item.get("entry") if isinstance(item, dict) else None
        if not isinstance(entry, dict) or entry.get("id") in seen:
            continue
        seen.add(entry.get("id"))
        parts.append("%s %s by %s on %s" % (terminal_text(entry.get("id"), 80),
                                            terminal_text(entry.get("kind"), 20),
                                            terminal_text(entry.get("by"), 60),
                                            terminal_text(entry.get("at"), 20)))
    if not parts:
        return ""
    return terminal_text("%d finding(s) cleared by disposition: %s" % (len(cleared), "; ".join(parts)), 400)


def sanitize_tree(value, limit=1000):
    """Every string in a JSON value sanitized for a prompt."""
    if isinstance(value, str):
        return sanitize_text(value, limit)
    if isinstance(value, list):
        return [sanitize_tree(v, limit) for v in value]
    if isinstance(value, dict):
        return {str(k): sanitize_tree(v, limit) for k, v in value.items()}
    return value


def prompt_verdict(verdict):
    """The part of the verdict a model may read: no stanzas, every string
    sanitized, fenced by the caller."""
    keep = ("verdict", "head", "threshold", "scope", "total", "advisory", "runs")
    out = {key: verdict[key] for key in keep}
    out["open"] = [{k: v for k, v in item.items() if k != "stanza"} for item in verdict["open"]]
    out["cleared"] = verdict["cleared"]
    out["pending_in_change"] = verdict["pending_in_change"]
    out["refused"] = verdict["refused"]
    out["expired"] = verdict["expired"]
    out["invalid_entries"] = len(verdict["invalid"])
    out["adjusted_by_profile"] = verdict["adjusted"]
    return sanitize_tree(out)


def _write_rubric_fields(item, record):
    """Copy what the rubric decided about RECORD onto the input finding ITEM:
    the severity it now has (the model's own moves to severity_claimed), the
    tier of an Auditor finding, and what moved it. A finding without facts is
    left as it was, except that a model which wrote only severity_claimed gets
    that reading under the name every renderer and count reads."""
    if not record.get("rubric_applied"):
        if "severity" not in item and record.get("severity"):
            item["severity"] = record["severity"]
        return
    item["severity_claimed"] = record["severity_claimed"]
    item["severity"] = record["severity"]
    if record.get("source") == "adversarial":
        item["tier"] = record["tier"]
    moved = rubric_moved_text(record)
    if moved:
        item["severity_moved"] = sanitize_text(moved, 400)
    else:
        item.pop("severity_moved", None)


def annotate_file(path, unified, verdict):
    """Write each input finding's fingerprint, disposition status and rubric
    reading back into PATH (an envelope object or a bare array), index-aligned
    with the input."""
    document = load_json_file(path)
    items = document.get("findings") if isinstance(document, dict) else document
    if not isinstance(items, list) or len(items) != len(unified):
        raise ValueError("cannot annotate %s: its findings do not match the evaluated input" % path)
    for item, record in zip(items, unified):
        if not isinstance(item, dict):
            continue
        item["fingerprint"] = record["fingerprint"]
        _write_rubric_fields(item, record)
        found = verdict["_status"].get((record["source"], record["fingerprint"]))
        if found:
            item["disposition"] = {k: sanitize_text(str(v), 120) for k, v in found.items()}
    write_file_atomic(path, dumps(document) + "\n")


def annotate_rubric_file(path, unified):
    """Like annotate_file but writes only the rubric reading: for the Auditor's
    sidecar, which must carry the tier the code decided and nothing else new."""
    document = load_json_file(path)
    items = document.get("findings") if isinstance(document, dict) else document
    if not isinstance(items, list) or len(items) != len(unified):
        raise ValueError("cannot annotate %s: its findings do not match the evaluated input" % path)
    for item, record in zip(items, unified):
        if isinstance(item, dict):
            _write_rubric_fields(item, record)
    write_file_atomic(path, dumps(document) + "\n")


def attach_verdict(path, verdict):
    """Splice the model-readable verdict into the JSON object at PATH."""
    document = load_json_file(path)
    if not isinstance(document, dict):
        raise ValueError("cannot attach to %s: not a JSON object" % path)
    shown = prompt_verdict(verdict)
    document["code_verdict"] = shown
    document["code_verdict_fenced"] = "===BEGIN CODE VERDICT DATA===\n%s\n===END CODE VERDICT DATA===" % (
        dumps(shown, indent=2, sort_keys=True))
    write_file_atomic(path, dumps(document) + "\n")


def read_stdin_bounded():
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise InputRefused("the input is larger than %d bytes" % MAX_INPUT_BYTES)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputRefused("the input is not valid UTF-8")


def findings_from_text(text, fmt):
    """The raw finding list in TEXT. JSON is an array, or an object whose
    'findings' key holds one (a review envelope); an envelope marked degraded
    is not a review. Markdown is the Auditor's report."""
    if fmt == "markdown":
        if not text.strip():
            raise InputRefused("the report is empty")
        return parse_adversarial_text(text)
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise InputRefused("the input is not JSON: %s" % exc)
    if isinstance(document, dict):
        if document.get("degraded") is True or document.get("sanitize_failed") is True:
            raise InputRefused("the envelope is marked degraded: it is not a review and holds no findings")
        if "findings" not in document:
            raise InputRefused("the input is an object without a 'findings' array")
        document = document["findings"]
    if not isinstance(document, list):
        raise InputRefused("the findings are not an array")
    return document


def run_evaluate(args):
    """The evaluate command. Returns (exit_status, text)."""
    try:
        root = os.path.realpath(args.root or os.getcwd())
        if not os.path.isdir(root):
            raise InputRefused("%s is not a directory" % root)
        today = today_date(args.today)
        gate = args.gate
        if gate == "merge-gate" and not args.no_input:
            raise InputRefused("the merge-gate reads the accumulated state and takes no input (--no-input)")
        head = args.head or repo_head(root)
        # A read-only verdict with no commit to accumulate against (the merge
        # gate in a directory that is not a repository) has nothing open by
        # construction; a run that brings findings still needs a HEAD to keep them.
        headless = args.no_input and not head
        if not headless and (not head or not re.fullmatch(r"[0-9a-f]{7,64}", head)):
            raise InputRefused("%s is not a git repository with a commit; the accumulation is "
                               "per HEAD and cannot be kept without one" % root)
        threshold_name = args.threshold or os.environ.get("CLAGENTIC_BLOCK_SEVERITY") or "high"
        # The merge base is resolved first: the stakes profile that applies is
        # the one as of that commit, and the rubric reads it while the findings
        # are unified.
        base = resolve_base(root, args.base, args.default_branch)
        stakes = load_stakes(root, base, today, args.profile_max_age_days)
        incoming, unified = None, []
        if not args.no_input:
            incoming = findings_from_text(read_stdin_bounded(), args.format)
            try:
                unified = unify_findings(incoming, gate, stakes)
            except ValueError as exc:
                raise InputRefused(str(exc))
        try:
            if headless:
                head = ""
                state = fresh_state(head)
            elif args.no_input:
                state = load_state(root, head)
            else:
                with StateLock(root):
                    state = load_state(root, head)
                    accumulate(state, unified, gate, args.caller)
                    save_state(root, state)
        except StateError as exc:
            raise InputRefused(str(exc))
        except OSError as exc:
            raise InputRefused("the findings state cannot be written: %s" % exc)
        store = load_store(root, worktree_reader(root))
        base_keys = introduced_entry_keys(root, base)
        scope = gate if args.scope == "gate" and gate in SOURCES else None
        verdict = build_verdict(state, store, base_keys, threshold_name, today, scope, head, base,
                                stakes)
        if args.annotate:
            annotate_file(args.annotate, unified, verdict)
        if args.rubric_into:
            annotate_rubric_file(args.rubric_into, unified)
        if args.attach_to:
            attach_verdict(args.attach_to, verdict)
        public = {k: v for k, v in verdict.items() if k != "_status"}
        if args.json_out:
            write_file_atomic(args.json_out, dumps(public) + "\n")
    except InputRefused as exc:
        return 2, "evaluate refused: %s\n" % exc
    except (OSError, ValueError) as exc:
        return 2, "evaluate failed closed: %s\n" % exc
    text = dumps(public) + "\n" if args.json else render_verdict_text(verdict, args.caller)
    return (1 if verdict["verdict"] == "BLOCKED" else 0), text


# --------------------------------------------------------- dispositions lint

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


# ------------------------------------------------------------ the profile command

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
    if glob is not None and (not glob.strip() or len(glob) > 500 or _UNSAFE_RE.search(glob)):
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
            if entry.get("glob") == glob:
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
                    and _worse_value(marker["dimension"], marker["value"], claimed) != claimed:
                lines.append("WARN: %s=%s for %s is contradicted by the tree (%s); the gate will "
                             "ignore that claim and apply %s there" % (
                                 marker["dimension"], claimed, terminal_text(entry.get("glob"), 120),
                                 terminal_text(marker["why"], 200), marker["value"]))
        claimed = default.get(marker["dimension"])
        if claimed in DIMENSIONS[marker["dimension"]] \
                and _worse_value(marker["dimension"], marker["value"], claimed) != claimed:
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
    os.makedirs(directory, exist_ok=True)
    real_root = os.path.realpath(root)
    real_dir = os.path.realpath(directory)
    if real_dir != real_root and not real_dir.startswith(real_root + os.sep):
        raise ValueError("%s resolves outside the repository; not written" % os.path.dirname(PROFILE_REL))
    write_file_atomic(target, dumps(document, indent=2) + "\n")
    return target


def cmd_profile(args):
    root = os.path.realpath(args.root or os.getcwd())
    try:
        if not is_repo_toplevel(root):
            raise ValueError("%s is not the top level of a git repository; run it from the repository "
                             "root (or pass --root)" % terminal_text(root, 200))
        today = today_date(args.today)
        document, lines = build_profile(root, args.answer or [], args.confirm, today)
        if args.write:
            write_profile(root, document)
            lines.append("wrote %s; review it and commit it as a change (it applies once merged)"
                         % PROFILE_REL)
    except (InputRefused, ValueError, OSError) as exc:
        sys.stderr.write("profile refused: %s\n" % exc)
        return 2
    for line in lines:
        warn("[profile] " + line)
    if not args.write:
        _print(dumps(document, indent=2) + "\n")
    return 0


# --------------------------------------------------------- review sample union

def union_review_samples(paths, stakes):
    """Union the findings of N review samples of one diff. Returns (envelope,
    report lines); envelope is None when no sample was usable. Findings are
    linked by fingerprint hint OR by location (file, line, category); of a
    linked group the one whose RUBRIC severity is highest is kept (the model's
    claimed severity never decides), ties to the earliest sample. A sample that
    is unreadable or marked degraded contributes nothing and is reported."""
    lines, usable, groups, by_key = [], 0, [], {}
    summaries, checked = [], []
    for index, path in enumerate(paths, 1):
        label = "sample %d/%d" % (index, len(paths))
        try:
            document = load_json_file(path)
            raw = extract_findings_strict(path)
        except (OSError, ValueError, KeyError) as exc:
            lines.append("%s: unreadable (%s)" % (label, terminal_text(exc, 120)))
            continue
        if document.get("degraded") is True or document.get("sanitize_failed") is True:
            lines.append("%s: degraded; its findings are not used" % label)
            continue
        usable += 1
        if isinstance(document.get("summary"), str) and document["summary"] not in summaries:
            summaries.append(document["summary"])
        for item in document.get("checked", []) if isinstance(document.get("checked"), list) else []:
            if item not in checked:
                checked.append(item)
        cleaned = allowlist_fields(raw, REVIEW_FINDING_FIELDS)
        lines.append("%s: %d finding(s)" % (label, len(cleaned)))
        for item in cleaned:
            record = unify_finding(item, "review", stakes)
            keys = [("print", record["fingerprint"]),
                    ("place", record["file"], record["line"], record["category"].lower())]
            hit = next((by_key[k] for k in keys if k in by_key), None)
            if hit is None:
                hit = len(groups)
                groups.append({"item": item, "rank": severity_rank(record["severity"])})
            elif severity_rank(record["severity"]) > groups[hit]["rank"]:
                groups[hit] = {"item": item, "rank": severity_rank(record["severity"])}
            for k in keys:
                by_key.setdefault(k, hit)
    if not usable:
        return None, lines
    union = [group["item"] for group in groups]
    lines.append("union of %d usable sample(s): %d distinct finding(s)" % (usable, len(union)))
    summary = " | ".join(summaries)
    return {"summary": summary, "checked": checked, "findings": union, "samples": len(paths)}, lines


def cmd_ingest_union_samples(args):
    root = os.path.realpath(args.root or os.getcwd())
    try:
        today = today_date(None)
        base = resolve_base(root, args.base, args.default_branch)
        stakes = load_stakes(root, base, today)
        envelope, lines = union_review_samples(args.files, stakes)
    except (InputRefused, ValueError, OSError) as exc:
        warn("[gates/review] could not union the review samples: %s" % terminal_text(exc, 200))
        return 1
    for line in lines:
        warn("[gates/review] " + line)
    if envelope is None:
        return 1
    _print(dumps(envelope) + "\n")
    return 0


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


def is_cleared(finding):
    """Whether the verdict annotated FINDING as cleared by a disposition. The
    one definition both the refusal listing and the review render use; display
    only, no count or verdict ever reads the annotation."""
    disposition = finding.get("disposition")
    return isinstance(disposition, dict) and disposition.get("status") == "cleared"


def terminal_text(value, limit=None):
    """Model-authored text made safe to print on a terminal: every control
    byte (escape sequences, newlines that could forge a second finding line),
    C1 control and bidirectional override becomes a space. The one helper every
    renderer uses for such text."""
    text = _CONTROL_RE.sub(" ", "" if value is None else str(value))
    return text if limit is None else text[:limit]


def _clean_listing(value):
    return terminal_text(value, 300)


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
            # A finding the verdict recorded as cleared by a disposition is not
            # one that blocked, so a refusal does not list it. This is display
            # only: the count above never reads the annotation.
            if counts_toward_verdict(finding, threshold) and not is_cleared(finding):
                line = finding.get("line") or 0
                if not isinstance(line, (int, float)) or isinstance(line, bool):
                    line = _clean_listing(line)
                listing.append({"file": _clean_listing(finding.get("file")),
                                "line": line,
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
    degrades recurrence visibility and nothing else.

    The append and the trim run under one exclusive lock on a sibling lock
    file (the ledger itself is replaced by rename, so it cannot carry the
    lock), which keeps a concurrent gate's append from being lost between the
    trim's read and its replace. Where flock is unavailable the lock is
    skipped with a warning and the old unlocked behavior applies."""
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
    except OSError:
        return
    lock = _ledger_lock(path)
    try:
        _ledger_append_locked(path, line, max_per_branch)
    finally:
        if lock is not None:
            lock.close()


def _ledger_lock(path):
    """An open, exclusively flock-ed handle on PATH's lock file, or None."""
    try:
        import fcntl
    except ImportError:
        warn("[findings] flock unavailable; ledger trim is not protected against a "
             "concurrent append")
        return None
    try:
        handle = open(path + ".lock", "a", encoding="utf-8")
    except OSError as exc:
        warn("[findings] could not lock the ledger (%s); a concurrent append may be lost" % exc)
        return None
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
    except OSError as exc:
        handle.close()
        warn("[findings] could not lock the ledger (%s); a concurrent append may be lost" % exc)
        return None
    return handle


def _ledger_append_locked(path, line, max_per_branch):
    try:
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


def _shown(value):
    """_jq_text for text that reaches a terminal."""
    return terminal_text(_jq_text(value))


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
    """Human-readable review. A cleared, repeated or seen-before finding gets a
    suffix saying so, so a decision is never silent. Returns (exit_code,
    output_lines)."""
    document = load_json_file(path)
    findings = document.get("findings")
    if findings is not None and not isinstance(findings, list):
        raise ValueError("'findings' is not an array")
    count = len(findings) if findings is not None else 0
    lines = ["== clagentic-lite review ==\nsummary: " + _shown(document.get("summary"))
             + "\nfindings: " + str(count) + "\n"]
    code = 0
    try:
        if findings is None:
            raise TypeError("cannot iterate over null")
        for finding in findings:
            text = ("[" + _shown(finding.get("severity")) + "] " + _shown(finding.get("file"))
                    + ":" + terminal_text(_jq_tostring(finding.get("line"))) + " "
                    + _shown(finding.get("message")))
            rounds = finding.get("_recurrence_count")
            if isinstance(rounds, int) and not isinstance(rounds, bool) and rounds > 1:
                text += " (reported " + str(rounds) + " rounds running)"
            if is_cleared(finding):
                disposition = finding["disposition"]
                text += (" (cleared by disposition " + terminal_text(disposition.get("id"), 80)
                         + " [" + terminal_text(disposition.get("kind"), 40) + "])")
            if finding.get("_seen_before") is True:
                text += " (reported in a prior run; still counted)"
            if _class_named(finding):
                text += "\n    class: " + _shown(finding.get("issue_class"))
                fix = finding.get("class_fix")
                if fix is not None and fix != "":
                    text += " -> " + _shown(fix)
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
        severity = terminal_text(finding.get("severity", "unknown"))
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
            lines.append("- [%s] %s: %s" % (terminal_text(finding.get("severity", "unknown")),
                                            terminal_text(finding.get("file", "?")),
                                            terminal_text(finding.get("message", ""))))
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
            entries.append((terminal_text(item.get("file", "")),
                            terminal_text(item.get("line", "")),
                            terminal_text(item.get("severity", "")),
                            terminal_text(item.get("message", ""))))
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
                        "them (or have a reviewed disposition for them merged to the base "
                        "branch, see .clagentic/dispositions.json) and commit; "
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
    sidecar_degraded = False
    if opts.adf:
        try:
            loaded = load_json_file(opts.adf)
        except (OSError, ValueError) as exc:
            warn("[findings] adversarial findings sidecar %s is unreadable: %s" % (opts.adf, exc))
            sidecar_degraded = True
        else:
            if isinstance(loaded, list):
                findings = loaded
            else:
                warn("[findings] adversarial findings sidecar %s is not a JSON array" % opts.adf)
                sidecar_degraded = True
    # A sidecar that cannot be read as a list must not read as "no findings"
    # with zero blockers: the whole adversarial source is degraded, exactly as
    # when cmd_adversarial itself recorded findings_degraded. A missing report
    # has no sidecar to trust or distrust.
    if sidecar_degraded and not _flag(opts.adversarial_missing):
        opts.adf_degraded = "true"
        adversarial_report_degraded = True
        if opts.adversarial_unavailable:
            adversarial_fenced = json.loads(opts.adversarial_unavailable)
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
        "deterministic_gates": deterministic_gates,
        "deterministic_gates_fenced": deterministic_gates_fenced,
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
    counted = recurrence_count(args.file, args.diff, args.counts)
    _print("none\n" if counted is None else "counted=%d\n" % counted)
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
    code, lines = lint_dispositions(os.path.realpath(args.root or os.getcwd()), args.file or None)
    for line in lines:
        _print(line + "\n")
    return code


def cmd_dispositions_migrate(args):
    root = os.path.realpath(args.root or os.getcwd())
    try:
        code, text, report = migrate_dispositions(root, args.write)
    except OSError as exc:
        warn("[dispositions/migrate] failed: %s" % exc)
        return 1
    for line in report:
        warn(line)
    if not args.write:
        _print(text)
    return code


def cmd_evaluate(args):
    code, text = run_evaluate(args)
    # A refusal is an error message, not a verdict: it goes to stderr so a
    # caller that discards stdout on a failed stage still shows the cause.
    if code == 2:
        sys.stderr.write(text)
    else:
        _print(text)
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


def cmd_render_cleared_summary(args):
    try:
        _print(cleared_summary(read_stdin_text()))
    except (ValueError, UnicodeDecodeError) as exc:
        warn("[findings] cleared-summary: %s" % exc)
        return 1
    return 0


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
        value = json_string_field(read_stdin_text(), args.key)
    except (ValueError, AttributeError) as exc:
        # Malformed JSON is a failure; an absent key is an empty value and exit 0.
        warn("[findings] json-field: input is not a JSON object: %s" % exc)
        return 1
    _print(value)
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
    sub = op(ingest, "union-samples", cmd_ingest_union_samples, ("files", {"nargs": "+"}))
    sub.add_argument("--root", default="")
    sub.add_argument("--base", default="")
    sub.add_argument("--default-branch", default="")

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
    sub = op(dispositions, "ledger-recurrence", cmd_dispositions_ledger_recurrence)
    sub.add_argument("--ledger", required=True)
    sub.add_argument("--branch", required=True)
    sub = op(dispositions, "lint", cmd_dispositions_lint)
    sub.add_argument("file", nargs="?", default="")
    sub.add_argument("--root", default="")
    sub = op(dispositions, "migrate", cmd_dispositions_migrate)
    sub.add_argument("--root", default="")
    sub.add_argument("--write", action="store_true")

    sub = stages.add_parser("evaluate")
    sub.set_defaults(func=cmd_evaluate)
    sub.add_argument("--gate", choices=("review", "adversarial", "merge-gate"), default="review")
    sub.add_argument("--format", choices=("json", "markdown"), default="json")
    sub.add_argument("--no-input", action="store_true")
    sub.add_argument("--scope", choices=("head", "gate"), default="head")
    sub.add_argument("--caller", choices=("standalone", "gates"), default="standalone")
    sub.add_argument("--json", action="store_true")
    sub.add_argument("--profile-max-age-days", type=int, default=0)
    for name in ("root", "head", "base", "default-branch", "threshold", "today",
                 "annotate", "rubric-into", "attach-to", "json-out"):
        sub.add_argument("--" + name, default="")

    sub = stages.add_parser("profile")
    sub.set_defaults(func=cmd_profile)
    sub.add_argument("--root", default="")
    sub.add_argument("--today", default="")
    sub.add_argument("--write", action="store_true")
    sub.add_argument("--confirm", action="store_true")
    sub.add_argument("--answer", action="append", default=[])

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
    op(render, "cleared-summary", cmd_render_cleared_summary)
    op(render, "verdict-lines", cmd_render_verdict_lines, ("head", {}))
    op(render, "sanitize-review", cmd_render_sanitize_review, ("file", {}))
    op(render, "sanitize-report", cmd_render_sanitize_report, ("file", {}))
    op(render, "fence-data", cmd_render_fence_data, ("label", {}), ("kind", {}))
    op(render, "fence-findings", cmd_render_fence_findings)
    op(render, "json-field", cmd_render_json_field, ("key", {}))
    op(render, "stale-report", cmd_render_stale_report, ("file", {}))
    sub = op(render, "gate-summary", cmd_render_gate_summary)
    sub.add_argument("--threshold", default="high")
    for name in ("adversarial-missing", "adversarial-degraded",
                 "review-degraded", "adversarial-report-degraded", "adf-degraded"):
        sub.add_argument("--" + name, default="false")
    for name in ("adf", "adf-meta", "review-fenced-file",
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
    try:
        sys.exit(main())
    except Exception:
        # Python's own uncaught-exception status is 1, which callers read as a
        # refused answer; a crash gets its own status so it can never pass for one.
        sys.excepthook(*sys.exc_info())
        sys.exit(CRASH_STATUS)
