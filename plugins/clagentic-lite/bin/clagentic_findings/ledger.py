"""The review ledger: one JSON line per gate run, read back to anchor a pass to
a HEAD and to show churn, and trimmed per branch under a lock."""
import json
import os

from .fileio import dumps, warn, write_file_atomic


def ledger_entries(path, branch):
    """Every entry for BRANCH, oldest first. A line that is not a JSON object
    is skipped; branch names are compared whole, never as substrings."""
    entries = []
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().split("\n")
    except (OSError, ValueError):
        return entries
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("branch") == branch:
            entries.append(entry)
    return entries


def latest_gate_entry(path, branch, gate):
    """The most recent entry BRANCH has from GATE, or None. An entry with no
    gate field matches no gate: defaulting it to 'review' would let a legacy
    entry anchor a lookup it never belonged to."""
    best = None
    for entry in ledger_entries(path, branch):
        if entry.get("gate") == gate:
            best = entry
    return best


def field_text(entry, name):
    value = entry.get(name)
    if value is None or value is False:
        return ""
    return value if isinstance(value, str) else dumps(value)


def anchored_pass(path, branch, head, gate):
    """True only when the latest GATE entry for BRANCH is anchored to HEAD and
    its verdict is pass. The one sanctioned 'is there a valid verdict'
    predicate."""
    if not head:
        return False
    latest = latest_gate_entry(path, branch, gate)
    if latest is None:
        return False
    entry_head = field_text(latest, "head_sha")
    return bool(entry_head) and entry_head == head and field_text(latest, "verdict") == "pass"


def head_verdict_state(path, branch, head, gate):
    """Why anchored_pass failed, as one token: pass, missing_stamp, sha_mismatch
    or review_blocked_at_head (the gate ran at this commit and blocked, so
    running it again cannot help)."""
    if anchored_pass(path, branch, head, gate):
        return "pass"
    latest = latest_gate_entry(path, branch, gate)
    if latest is None:
        return "missing_stamp"
    entry_head = field_text(latest, "head_sha")
    if not entry_head:
        return "missing_stamp"
    if entry_head != head:
        return "sha_mismatch"
    if field_text(latest, "verdict") == "block":
        return "review_blocked_at_head"
    return "missing_stamp"


def latest_passing_head(path, branch, gate):
    """head_sha of the latest anchored pass of GATE on BRANCH. Scans all
    history, not just the last row: the right re-review base is the last point
    the branch was known clean, however many blocked rounds followed."""
    best = ""
    for entry in ledger_entries(path, branch):
        if (entry.get("verdict") == "pass" and entry.get("head_sha")
                and entry.get("gate") == gate):
            best = entry["head_sha"]
    return best


def ledger_append(path, line, max_per_branch):
    """Append one JSON line, then drop the oldest entries of the same branch
    past MAX_PER_BRANCH (0 disables). The ledger exists to show churn, so its
    own storage must not grow without bound. Never raises: a lost entry
    degrades recurrence visibility and nothing else.

    The append and the trim run under one exclusive lock on a sibling lock
    file (the ledger itself is replaced by rename, so it cannot carry the
    lock), which keeps a concurrent gate's append from being lost between the
    trim's read and its replace. Where flock is unavailable the lock is
    skipped with a warning and the old unlocked behavior applies."""
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
    except OSError:
        return
    lock = _ledger_lock(path)
    try:
        _ledger_append_locked(path, line, max_per_branch)
    finally:
        if lock is not None:
            lock.close()


def _ledger_lock(path):
    """An open, exclusively flock-ed handle on PATH's lock file, or None."""
    try:
        import fcntl
    except ImportError:
        warn("[findings] flock unavailable; ledger trim is not protected against a "
             "concurrent append")
        return None
    try:
        handle = open(path + ".lock", "a", encoding="utf-8")
    except OSError as exc:
        warn("[findings] could not lock the ledger (%s); a concurrent append may be lost" % exc)
        return None
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
    except OSError as exc:
        handle.close()
        warn("[findings] could not lock the ledger (%s); a concurrent append may be lost" % exc)
        return None
    return handle


def _ledger_append_locked(path, line, max_per_branch):
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line.replace("\n", "") + "\n")
    except OSError:
        return
    if max_per_branch <= 0:
        return
    try:
        entry = json.loads(line)
        branch = entry.get("branch", "") if isinstance(entry, dict) else ""
    except ValueError:
        return
    if not branch:
        return

    def on_branch(raw):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return False
        return isinstance(parsed, dict) and parsed.get("branch") == branch

    try:
        with open(path, encoding="utf-8") as handle:
            lines = [raw.rstrip("\n") for raw in handle if raw.strip()]
        matches = sum(1 for raw in lines if on_branch(raw))
        drop = max(matches - max_per_branch, 0)
        kept, seen = [], 0
        for raw in lines:
            if on_branch(raw):
                seen += 1
                if seen <= drop:
                    continue
            kept.append(raw)
        if kept:
            write_file_atomic(path, "".join(raw + "\n" for raw in kept))
    except (OSError, ValueError):
        return


def build_ledger_entry(ts, branch, gate, base, head, verdict, findings_text, config_text):
    try:
        findings = json.loads(findings_text)
        if not isinstance(findings, list):
            findings = []
    except ValueError:
        findings = []
    try:
        config = json.loads(config_text)
    except ValueError:
        config = {}
    return dumps({"ts": ts, "branch": branch, "gate": gate, "base_sha": base,
                  "head_sha": head, "verdict": verdict, "findings": findings,
                  "config": config})
