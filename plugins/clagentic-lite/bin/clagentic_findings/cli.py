"""clagentic-lite finding pipeline: stdlib-only, no dependency on the shell gates.

Every decision the gates make about a finding lives in this package: how a
model's findings are ingested and cleaned, how a finding is fingerprinted
across rounds, which dispositions (seen before, recurring, deferred) apply,
what counts toward a verdict, and how a verdict is rendered. The shell gates
(scripts/gates.sh, scripts/review-merge.sh) call it through thin wrappers; a
bare Reviewer or Auditor agent can call it directly from any git repository,
enrolled or not. It reads no clagentic-lite state it is not handed as an
argument and imports nothing outside the standard library.

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
import json
import os
import sys

from .dates import today_date
from .dispositions import lint_dispositions, migrate_dispositions
from .errors import InputRefused, StageFailure
from .evaluate import run_evaluate
from .fileio import (dumps, load_json_file, read_stdin_text, setup_io, warn)
from .fingerprint import (append_key_file, bump_counts, content_key_rows, dedup_findings,
                          read_key_file)
from .gitstate import is_repo_toplevel, resolve_base
from .ingest import (DEFAULT_FINDINGS_MAX, extract_findings, extract_findings_strict,
                     ingest_review_envelope, merge_envelopes, parse_adversarial_findings,
                     sort_blocking_first)
from .ledger import (anchored_pass, build_ledger_entry, field_text, head_verdict_state,
                     latest_gate_entry, latest_passing_head, ledger_append, ledger_entries)
from .policy import read_policy_file_at_base
from .profile import build_profile, write_profile
from .render import (CLASS_FOOTER, class_named, cleared_summary, fence_data_block,
                     fence_findings, json_string_field, render_review, render_verdict_lines,
                     sanitize_report_for_prompt, sanitize_review_for_prompt, stale_report)
from .rounds import cross_round, mark_ledger_recurrence, recurrence_count
from .samples import union_review_samples
from .sanitize import (allowlist_fields, sanitize_fields_strict, sanitize_text,
                       terminal_text)
from .severity import SEVERITY_RANKS
from .stakes import PROFILE_REL, load_stakes
from .summary import build_gate_summary
from .verdict import blocking_findings_listing, count_blockers

CRASH_STATUS = 70


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


def cmd_ingest_policy_file(args):
    root = os.path.realpath(args.root or os.getcwd())
    try:
        base = resolve_base(root, args.base, args.default_branch)
        text = read_policy_file_at_base(root, base, args.rel)
    except (ValueError, OSError) as exc:
        warn("[findings] policy-file: %s" % terminal_text(exc, 200))
        return 1
    _print(text)
    return 0


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
        named = any(class_named(f) for f in (findings or []))
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
    sub = op(ingest, "policy-file", cmd_ingest_policy_file, ("rel", {}))
    sub.add_argument("--root", default="")
    sub.add_argument("--base", default="")
    sub.add_argument("--default-branch", default="")
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


def run(argv=None):
    """main() with the crash contract: an uncaught exception prints its
    traceback and returns CRASH_STATUS. Python's own status for it is 1, which
    callers read as a refused answer; a crash gets its own so it can never
    pass for one."""
    try:
        return main(argv)
    except Exception:
        sys.excepthook(*sys.exc_info())
        return CRASH_STATUS
