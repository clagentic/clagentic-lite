"""The union of N review samples of one diff."""
from .fileio import load_json_file
from .ingest import REVIEW_FINDING_FIELDS, extract_findings_strict
from .sanitize import allowlist_fields, terminal_text
from .severity import severity_rank
from .unify import unify_finding


def _read_usable_sample(path, stakes):
    """(envelope, cleaned findings, unified records) of one review sample, or
    None for one marked degraded. Raises OSError or ValueError for anything
    else that is not a usable envelope object (a bare array, a scalar, an
    unreadable file, a finding that is not an object): the caller excludes
    that sample whole, so a half-read sample never contributes."""
    document = load_json_file(path)
    if not isinstance(document, dict):
        raise ValueError("the sample is not a JSON object")
    if document.get("degraded") is True or document.get("sanitize_failed") is True:
        return None
    raw = extract_findings_strict(path)
    cleaned = allowlist_fields(raw, REVIEW_FINDING_FIELDS)
    records = [unify_finding(item, "review", stakes) for item in cleaned]
    return document, cleaned, records


def union_review_samples(paths, stakes):
    """Union the findings of N review samples of one diff. Returns (envelope,
    report lines); envelope is None when no sample was usable. Findings are
    linked by fingerprint hint OR by location (file, line, category); of a
    linked group the one whose RUBRIC severity is highest is kept (the model's
    claimed severity never decides), ties to the earliest sample. A sample that
    is unreadable, not an object, malformed or marked degraded contributes
    nothing and is reported; the usable ones are still unioned, and none usable
    fails closed (None)."""
    lines, usable, groups, by_key = [], 0, [], {}
    summaries, checked = [], []
    for index, path in enumerate(paths, 1):
        label = "sample %d/%d" % (index, len(paths))
        try:
            sample = _read_usable_sample(path, stakes)
        except (OSError, ValueError, KeyError) as exc:
            lines.append("%s: unreadable or unusable, excluded (%s)" % (label, terminal_text(exc, 120)))
            continue
        if sample is None:
            lines.append("%s: degraded; its findings are not used" % label)
            continue
        usable += 1
        document, cleaned, records = sample
        if isinstance(document.get("summary"), str) and document["summary"] not in summaries:
            summaries.append(document["summary"])
        for item in document.get("checked", []) if isinstance(document.get("checked"), list) else []:
            if item not in checked:
                checked.append(item)
        lines.append("%s: %d finding(s)" % (label, len(cleaned)))
        for item, record in zip(cleaned, records):
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
