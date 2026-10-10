"""Ingesting what a model wrote: review envelopes reduced to the closed schema,
the Auditor's markdown parsed into findings, envelopes of chunked reviews
merged, and the order in which a count cap may drop findings."""
import os
import re

from .fileio import dumps, load_json_file, warn, write_file_atomic
from .fingerprint import dedup_findings
from .rubric import (IMPACTS, PRECONDITIONS, UNKNOWN_FACT, fact_value,
                     rubric_for_record)
from .sanitize import allowlist_fields
from .severity import SEVERITY_RANKS, severity_rank

DEFAULT_FINDINGS_MAX = 200

# severity_claimed is the model's own severity, kept for display; the facts
# (reachable, attacker_precondition, impact, class) are what the rubric reads.
REVIEW_FINDING_FIELDS = (
    "severity", "severity_claimed", "file", "line:number", "category", "message",
    "evidence", "suggestion", "issue_class", "class_fix", "reachable",
    "attacker_precondition", "impact", "class",
)

SANITIZE_FAILED_ENVELOPE = (
    '{"degraded": true, "sanitize_failed": true, "summary": "[clagentic-lite '
    'degraded] review findings could not be sanitized", "checked": [], "findings": []}\n'
)

_FILE_LINE_RE = re.compile(r"^(.+):(\d+)$")
_ADVERSARIAL_HEADER_RE = re.compile(
    r"^\[FINDING\]\s*([^|]+)\|\s*([^|]+)\|\s*severity:\s*([^|]+?)\s*"
    r"(?:\|\s*reachable:\s*([^|]+?)\s*)?"
    r"(?:\|\s*precondition:\s*([^|]+?)\s*)?"
    r"(?:\|\s*impact:\s*([^|]+?)\s*)?"
    r"(?:\|\s*tier:\s*([^|]+?)\s*)?"
    r"(?:\|\s*class:\s*([^|]+?)\s*)?"
    r"\|\s*title:\s*(.+)$"
)


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
        write_file_atomic(path, SANITIZE_FAILED_ENVELOPE)
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
        # An unstated or invalid reachable is the worst case, never "no": a
        # header that states facts is read by the rubric as unknown (treated as
        # reachable); a header without facts has no rubric reading, so it is
        # "yes" and the severity floor applies to it.
        facts_stated = precondition_raw is not None or impact_raw is not None
        if reachable_raw in ("yes", "no"):
            reachable = reachable_raw
        else:
            reachable = "unknown" if facts_stated else "yes"
        tier = tier_raw if tier_raw in ("blocking", "advisory") else "advisory"
        # Reachability is the precondition for blocking, never a judgment the
        # tier field alone can override.
        if reachable != "yes":
            tier = "advisory"
        # An absent or unparseable class defaults to the one that relaxes
        # nothing, so a parser gap can only leave the full bar in place.
        change_class = class_raw if class_raw in ("durable", "ephemeral") else "durable"
        # Security floor for a header that states no facts: reachable and
        # high/critical is always blocking, whatever tier or class the model
        # wrote. A header that does state facts is decided by the rubric below,
        # whose own floor (open to anyone, high impact: at least high, and
        # blocking) is the one it holds; the rubric is the only thing that may
        # move a finding that states facts, and only from those facts.
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
        # severity_rank, not a dict lookup: an unhashable severity (a list or
        # object from a model) would raise, and an unrankable one must sort
        # with the blocking end, never past the count cap.
        severity = severity_rank(item.get("severity") if is_dict else None)
        return (-blocking, -severity, index)
    return [item for _, item in sorted(enumerate(array), key=order)]


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
