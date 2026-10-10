"""The evaluate command: unified findings in, per-HEAD accumulation, dispositions
and guardrails applied, the code verdict out."""
import json
import os
import re
import sys

from .dates import today_date
from .errors import InputRefused, StateError
from .fileio import dumps, load_json_file, write_file_atomic
from .gitstate import repo_head, resolve_base
from .ingest import parse_adversarial_text
from .policy import load_policy
from .render import prompt_verdict, render_verdict_text
from .rubric import rubric_moved_text
from .sanitize import sanitize_text
from .stakes import load_stakes
from .state import StateLock, accumulate, fresh_state, load_state, save_state
from .unify import SOURCES, unify_findings
from .verdict import build_verdict

MAX_INPUT_BYTES = 16 * 1024 * 1024


def _write_rubric_fields(item, record):
    """Copy what the rubric decided about RECORD onto the input finding ITEM:
    the severity it now has (the model's own moves to severity_claimed), the
    tier of an Auditor finding, and what moved it."""
    item["severity_claimed"] = record["severity_claimed"]
    item["severity"] = record["severity"]
    if record.get("source") == "adversarial":
        item["tier"] = record["tier"]
    moved = rubric_moved_text(record)
    if moved:
        item["severity_moved"] = sanitize_text(moved, 400)
    else:
        item.pop("severity_moved", None)


def annotate_file(path, unified, verdict):
    """Write each input finding's fingerprint, disposition status and rubric
    reading back into PATH (an envelope object or a bare array), index-aligned
    with the input."""
    document = load_json_file(path)
    items = document.get("findings") if isinstance(document, dict) else document
    if not isinstance(items, list) or len(items) != len(unified):
        raise ValueError("cannot annotate %s: its findings do not match the evaluated input" % path)
    for item, record in zip(items, unified):
        if not isinstance(item, dict):
            continue
        item["fingerprint"] = record["fingerprint"]
        _write_rubric_fields(item, record)
        found = verdict["_status"].get((record["source"], record["fingerprint"]))
        if found:
            item["disposition"] = {k: sanitize_text(str(v), 120) for k, v in found.items()}
    write_file_atomic(path, dumps(document) + "\n")


def annotate_rubric_file(path, unified):
    """Like annotate_file but writes only the rubric reading: for the Auditor's
    sidecar, which must carry the tier the code decided and nothing else new."""
    document = load_json_file(path)
    items = document.get("findings") if isinstance(document, dict) else document
    if not isinstance(items, list) or len(items) != len(unified):
        raise ValueError("cannot annotate %s: its findings do not match the evaluated input" % path)
    for item, record in zip(items, unified):
        if isinstance(item, dict):
            _write_rubric_fields(item, record)
    write_file_atomic(path, dumps(document) + "\n")


def attach_verdict(path, verdict):
    """Splice the model-readable verdict into the JSON object at PATH."""
    document = load_json_file(path)
    if not isinstance(document, dict):
        raise ValueError("cannot attach to %s: not a JSON object" % path)
    shown = prompt_verdict(verdict)
    document["code_verdict"] = shown
    document["code_verdict_fenced"] = "===BEGIN CODE VERDICT DATA===\n%s\n===END CODE VERDICT DATA===" % (
        dumps(shown, indent=2, sort_keys=True))
    write_file_atomic(path, dumps(document) + "\n")


def read_stdin_bounded():
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise InputRefused("the input is larger than %d bytes" % MAX_INPUT_BYTES)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputRefused("the input is not valid UTF-8")


def findings_from_text(text, fmt):
    """The raw finding list in TEXT. JSON is an array, or an object whose
    'findings' key holds one (a review envelope); an envelope marked degraded
    is not a review. Markdown is the Auditor's report."""
    if fmt == "markdown":
        if not text.strip():
            raise InputRefused("the report is empty")
        return parse_adversarial_text(text)
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise InputRefused("the input is not JSON: %s" % exc)
    if isinstance(document, dict):
        if document.get("degraded") is True or document.get("sanitize_failed") is True:
            raise InputRefused("the envelope is marked degraded: it is not a review and holds no findings")
        if "findings" not in document:
            raise InputRefused("the input is an object without a 'findings' array")
        document = document["findings"]
    if not isinstance(document, list):
        raise InputRefused("the findings are not an array")
    return document


def run_evaluate(args):
    """The evaluate command. Returns (exit_status, text)."""
    try:
        root = os.path.realpath(args.root or os.getcwd())
        if not os.path.isdir(root):
            raise InputRefused("%s is not a directory" % root)
        today = today_date(args.today)
        gate = args.gate
        if gate == "merge-gate" and not args.no_input:
            raise InputRefused("the merge-gate reads the accumulated state and takes no input (--no-input)")
        head = args.head or repo_head(root)
        # A read-only verdict with no commit to accumulate against (the merge
        # gate in a directory that is not a repository) has nothing open by
        # construction; a run that brings findings still needs a HEAD to keep them.
        headless = args.no_input and not head
        if not headless and (not head or not re.fullmatch(r"[0-9a-f]{7,64}", head)):
            raise InputRefused("%s is not a git repository with a commit; the accumulation is "
                               "per HEAD and cannot be kept without one" % root)
        threshold_name = args.threshold or os.environ.get("CLAGENTIC_BLOCK_SEVERITY") or "high"
        # The merge base is resolved first: the stakes profile that applies is
        # the one as of that commit, and the rubric reads it while the findings
        # are unified.
        base = resolve_base(root, args.base, args.default_branch)
        stakes = load_stakes(root, base, today, args.profile_max_age_days)
        incoming, unified = None, []
        if not args.no_input:
            incoming = findings_from_text(read_stdin_bounded(), args.format)
            try:
                unified = unify_findings(incoming, gate, stakes)
            except ValueError as exc:
                raise InputRefused(str(exc))
        try:
            if headless:
                head = ""
                state = fresh_state(head)
            elif args.no_input:
                state = load_state(root, head)
            else:
                with StateLock(root):
                    state = load_state(root, head)
                    accumulate(state, unified, gate, args.caller)
                    save_state(root, state)
        except StateError as exc:
            raise InputRefused(str(exc))
        except OSError as exc:
            raise InputRefused("the findings state cannot be written: %s" % exc)
        store, proposed, policy_notes = load_policy(root, base)
        scope = gate if args.scope == "gate" and gate in SOURCES else None
        verdict = build_verdict(state, store, proposed, threshold_name, today, scope, head, base,
                                stakes, policy_notes)
        if args.annotate:
            annotate_file(args.annotate, unified, verdict)
        if args.rubric_into:
            annotate_rubric_file(args.rubric_into, unified)
        if args.attach_to:
            attach_verdict(args.attach_to, verdict)
        public = {k: v for k, v in verdict.items() if k != "_status"}
        if args.json_out:
            write_file_atomic(args.json_out, dumps(public) + "\n")
    except InputRefused as exc:
        return 2, "evaluate refused: %s\n" % exc
    except (OSError, ValueError) as exc:
        return 2, "evaluate failed closed: %s\n" % exc
    text = dumps(public) + "\n" if args.json else render_verdict_text(verdict, args.caller)
    return (1 if verdict["verdict"] == "BLOCKED" else 0), text
