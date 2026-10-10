"""The gate summary handed to the Merge Gate: mechanical counts computed from
the structured sidecars rather than re-derived by the model from prose."""
import json

from .fileio import load_json_file, warn

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
    if isinstance(value, str) and value:
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
    except (ValueError, TypeError):
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
    # Applied before any count is taken: a degraded source reports no
    # findings, so the counts must say zero in step with the empty list rather
    # than describe findings the payload no longer carries.
    adf_unavailable_fenced = None
    if _flag(opts.adf_degraded):
        findings = []
        adf_unavailable_fenced = json.loads(opts.adf_unavailable)
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
    if adf_unavailable_fenced is not None:
        findings_fenced = adf_unavailable_fenced
    else:
        findings_fenced = ("===BEGIN ADVERSARIAL FINDINGS DATA===\n"
                           + json.dumps(findings, indent=2)
                           + "\n===END ADVERSARIAL FINDINGS DATA===")
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
