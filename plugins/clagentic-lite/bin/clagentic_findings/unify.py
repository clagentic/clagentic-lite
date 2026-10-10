"""The unified finding record.

Review findings (JSON) and adversarial findings (markdown [FINDING] headers)
are reduced to ONE record shape before anything decides about them:

  source, file, line, category (a CWE or rule class), message, evidence,
  reachable (yes|no|unknown), class (durable|ephemeral), severity_claimed
  (the model's own value, display only), severity (that value as a known
  rank name, or "unknown" when it is not one), tier (adversarial only), and
  the pipeline-added fingerprint (a link hint, never an identity to drop a
  finding on).

The record is rebuilt from the input field by field: whatever else a model
or another producer wrote (a forged "disposition", a forged "fingerprint")
is not carried over.
"""
from .digest import sha256_hex
from .fileio import dumps
from .paths import norm_path, norm_text
from .rubric import (FINDING_SCHEMA, IMPACTS, PRECONDITIONS, UNKNOWN_FACT,
                     apply_rubric, fact_value)
from .sanitize import sanitize_text
from .severity import canonical_severity, severity_rank

SOURCES = ("review", "adversarial")
REACHABLE_VALUES = ("yes", "no", "unknown")
CHANGE_CLASSES = ("durable", "ephemeral")
EVALUATE_MAX_FINDINGS = 1000


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


def unify_finding(raw, source, stakes=None):
    """One input finding as a unified record. Raises ValueError for an input
    that is not an object: a finding that cannot be read is never skipped.

    Every finding has its severity (and, for the Auditor, its tier) decided by
    the rubric from its facts and STAKES; the model's own severity is kept as
    severity_claimed for display and decides nothing. A fact that is absent or
    outside its vocabulary is the worst case, so a finding that states neither
    attacker_precondition nor impact is rated as if it were reachable by
    anyone with the largest impact: omitting the facts never lowers a finding
    and never keeps what the model claimed."""
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
    for key in ("suggestion", "issue_class", "class_fix"):
        if isinstance(raw.get(key), str):
            record[key] = _clean(raw[key], 500)
    record["schema"] = FINDING_SCHEMA
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
    acceptable. As the rubric decided it: reachable, high impact and an
    EFFECTIVE precondition of none or network (the finding's own precondition
    raised only by what the profile genuinely establishes)."""
    return bool(finding.get("floor"))


def is_blocking(finding, threshold):
    """Whether an unaddressed finding blocks. An adversarial finding blocks by
    its rubric tier; a review finding blocks when its rubric severity meets the
    threshold."""
    if finding.get("source") == "adversarial":
        return finding.get("tier") == "blocking"
    return severity_rank(finding.get("severity")) >= threshold
