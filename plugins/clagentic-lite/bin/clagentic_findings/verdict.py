"""The code verdict: which open findings block, which a base-revision
disposition clears, and the blocker counts the gates ask for."""
import json

from .dates import parse_date
from .dispositions import entry_can_clear, entry_matches
from .fileio import load_json_file
from .globs import glob_escape
from .paths import norm_path
from .rubric import apply_rubric, rubric_moved_text
from .sanitize import terminal_text
from .severity import (FAIL_CLOSED_BLOCKERS, SEVERITY_RANKS, counts_toward_verdict,
                       threshold_rank)
from .unify import is_blocking, is_floor


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


def build_verdict(state, store, proposed, threshold_name, today, scope, head, base, stakes=None,
                  policy_notes=()):
    """The code verdict. Open blocking findings at HEAD, minus the ones a valid,
    live disposition from the base revision clears (STORE, see load_policy).
    PROPOSED entries (in the working tree, not in the base) clear nothing; the
    findings they would clear are reported. Every finding has its severity
    re-derived here from its (merged) facts and STAKES, so the verdict never
    depends on which run wrote the severity down."""
    threshold = threshold_rank(threshold_name)
    findings = []
    for stored in state["findings"]:
        if scope not in (None, stored["source"]):
            continue
        findings.append(apply_rubric(dict(stored), stakes))
    live, expired = [], []
    for entry in store["entries"]:
        until = parse_date(entry.get("expires")) if entry.get("expires") else None
        (expired if until is not None and until < today else live).append(entry)
    live_proposed = [e for e in proposed
                     if not (e.get("expires") and (parse_date(e["expires"]) or today) < today)]

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
            elif winner is None:
                winner = entry
        for entry in live_proposed:
            if not entry_matches(entry, finding):
                continue
            if not entry_can_clear(entry, finding):
                refusals.append(entry)
            else:
                added.append(entry)
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
    warnings.extend(policy_notes)
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
