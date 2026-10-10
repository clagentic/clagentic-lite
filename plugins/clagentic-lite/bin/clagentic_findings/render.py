"""Rendering: the review and the verdict as text, payloads sanitized and fenced
for a prompt, and the refusal wording for a stale gate summary."""
import json
import os

from .dispositions import DISPOSITIONS_REL
from .fileio import dumps, load_json_file
from .sanitize import sanitize_fields_strict, sanitize_text, sanitize_tree, shell_value, terminal_text
from .verdict import is_cleared

CLASS_ISOLATED = "none — isolated"
CLASS_FOOTER = ("\nFindings above name a class -- fix via class_fix across every site, "
                "not per-line\n")

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


def class_named(finding):
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
            if class_named(finding):
                text += "\n    class: " + _shown(finding.get("issue_class"))
                fix = finding.get("class_fix")
                if fix is not None and fix != "":
                    text += " -> " + _shown(fix)
            lines.append(text)
    except (TypeError, AttributeError):
        code = 1
    if code == 0 and any(class_named(f) for f in findings):
        lines.append(None)
    return code, lines


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
        out["summary"] = shell_value(sanitize_text(shell_value(summary)))
    out["findings"] = findings
    sha = document.get("_clagentic_diff_sha")
    if isinstance(sha, str):
        out["_clagentic_diff_sha"] = shell_value(sanitize_text(shell_value(sha)))
    return dumps(out)


def sanitize_report_for_prompt(path):
    """The adversarial markdown report, sanitized. It is the Merge Gate's
    fallback refusal basis, so it is not held to the per-field cap: the bound
    is three times the file's length, because defanging a forged fence label
    roughly doubles that label."""
    with open(path, "rb") as handle:
        raw = handle.read()
    size = len(raw) or 1
    text = shell_value(raw.decode("utf-8"))
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
