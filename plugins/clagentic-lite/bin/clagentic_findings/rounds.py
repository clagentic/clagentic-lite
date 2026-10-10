"""Cross-round state of a finding: whether an earlier run saw it, how many
rounds it has been reported in, and whether the review ledger already holds
it."""
import os

from .errors import KEYS_FAILED, SPLICE_FAILED, StageFailure
from .fileio import load_json_file
from .fingerprint import (append_key_file, dedup_findings, next_counts,
                          read_counts, read_key_file, window_key, write_counts)
from .ingest import extract_findings_strict, splice_findings
from .ledger import ledger_entries
from .severity import triple


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
