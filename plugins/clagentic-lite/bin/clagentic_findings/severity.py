"""The one severity ranking and the threshold arithmetic built on it."""

SEVERITY_RANKS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_THRESHOLD_RANK = 3
# A severity that is present but is not a known rank name (a non-string, or a
# string like 'blocker' or 'crit') cannot be ranked; it counts as blocking so a
# malformed value can never slip under the threshold.
UNRANKABLE_RANK = 4
FAIL_CLOSED_BLOCKERS = 99
# Reachable at this rank (high) or above is the security floor.
FLOOR_RANK = 3


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
