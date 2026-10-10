"""Facts and the deterministic severity rubric.

A model is asked for facts, never for a severity it would have to defend. The
facts are drawn from closed vocabularies; a value outside its vocabulary, or
a missing one, resolves to the WORST case, so a model cannot lower a finding
by garbling a field. The severity of a finding that states facts is then a
pure function of those facts and the stakes profile (see stakes.py):

    severity = RUBRIC_TABLE[impact weight][effective precondition]

where the impact weight is the impact scaled by the data the path handles,
and the effective precondition is what the attacker must already have once
the profile's exposure, visibility and merge control are taken into account
(the CVSS Attack Vector / Privileges Required and Confidentiality /
Integrity Requirement analogues). The same facts and the same profile always
give the same severity, on the gate path and in a standalone agent.
"""
from .severity import FLOOR_RANK, severity_rank

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


def worst_dims():
    return {dim: (WORST_DIMS[dim], "no profile statement") for dim in DIMENSIONS}


def worse_value(dimension, first, second):
    order = WORST_ORDER[dimension]
    return first if order.index(first) <= order.index(second) else second


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
