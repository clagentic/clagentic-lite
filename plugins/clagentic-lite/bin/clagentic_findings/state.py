"""Per-HEAD accumulation state.

Open findings accumulate per HEAD: once a run has found something at a
commit it stays on the list until the commit changes or a disposition
clears it, and a re-run can only add. The state is a small file under
.clagentic/lite/, created on demand, owned by this package alone, so the
accumulation works in a repository that was never enrolled.
"""
import os

from .errors import InputRefused, StateError
from .fileio import dumps, load_json_file, write_file_atomic
from .rubric import UNKNOWN_FACT, apply_rubric, merge_facts
from .unify import SOURCES

STATE_REL = ".clagentic/lite/findings-state.json"
STATE_SCHEMA = 1
STATE_MAX_FINDINGS = 5000
_REACHABLE_ORDER = {"no": 0, "unknown": 1, "yes": 2}


def state_file(root):
    return os.path.join(root, STATE_REL)


def fresh_state(head):
    return {"schema": STATE_SCHEMA, "head": head, "runs": [], "findings": []}


def load_state(root, head):
    """The state for HEAD. A state recorded at another HEAD starts fresh (a
    new commit is a new question); one that cannot be read is an error, never
    an empty list, because losing the accumulation would silently clear every
    open finding."""
    path = state_file(root)
    if not os.path.exists(path):
        return fresh_state(head)
    try:
        data = load_json_file(path)
    except (OSError, ValueError) as exc:
        raise StateError("%s cannot be read (%s); remove it to start a fresh accumulation" % (path, exc))
    if (not isinstance(data, dict) or data.get("schema") != STATE_SCHEMA
            or not isinstance(data.get("head"), str) or not isinstance(data.get("runs"), list)
            or not isinstance(data.get("findings"), list)):
        raise StateError("%s is not a recognized findings state; remove it to start a fresh accumulation" % path)
    if data["head"] != head:
        return fresh_state(head)
    for item in data["findings"]:
        if (not isinstance(item, dict) or item.get("source") not in SOURCES
                or not isinstance(item.get("fingerprint"), str)):
            raise StateError("%s holds a malformed finding; remove it to start a fresh accumulation" % path)
        if not item.get("rubric_applied"):
            # Written by a version that kept the model's severity when no
            # facts were stated. Without facts the worst case applies, so the
            # record is read as one that states none; no user action needed.
            item["attacker_precondition"] = item["impact"] = UNKNOWN_FACT
            item["rubric_applied"] = True
    return data


class StateLock(object):
    """An exclusive lock around a read-modify-write of the state file, on a
    sibling lock file (the state itself is replaced by rename)."""

    def __init__(self, root):
        self.path = state_file(root) + ".lock"
        self.handle = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        # A run that cannot take the lock must not go on: a concurrent
        # read-modify-write would then lose accumulated findings, and a lost
        # finding reads as a cleared one.
        try:
            import fcntl
            self.handle = open(self.path, "a", encoding="utf-8")
            fcntl.flock(self.handle, fcntl.LOCK_EX)
        except (ImportError, OSError) as exc:
            if self.handle is not None:
                self.handle.close()
                self.handle = None
            raise StateError("could not lock the findings state (%s); refusing to run without "
                             "it because a concurrent run could lose accumulated findings" % exc)
        return self

    def __exit__(self, *exc_info):
        if self.handle is not None:
            self.handle.close()
        return False


def save_state(root, state):
    path = state_file(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_file_atomic(path, dumps(state) + "\n")


def accumulate(state, incoming, gate, caller):
    """Add INCOMING (unified records) to STATE. A finding already there (the
    same source and fingerprint, or the same source, file, line and category)
    is merged toward the stronger reading of each field; nothing is removed.
    Returns the number of findings that were new."""
    by_print = {(f["source"], f["fingerprint"]): f for f in state["findings"]}
    by_place = {(f["source"], f.get("file"), f.get("line"), str(f.get("category", "")).lower()): f
                for f in state["findings"]}
    new = 0
    for record in incoming:
        place = (record["source"], record["file"], record["line"], record["category"].lower())
        known = by_print.get((record["source"], record["fingerprint"])) or by_place.get(place)
        if known is None:
            if len(state["findings"]) >= STATE_MAX_FINDINGS:
                raise InputRefused("more than %d findings at this HEAD" % STATE_MAX_FINDINGS)
            state["findings"].append(record)
            by_print[(record["source"], record["fingerprint"])] = record
            by_place[place] = record
            new += 1
            continue
        # The stronger facts win and the verdict re-derives the severity (and
        # an Auditor finding's tier) from them, so the merge can only raise a
        # finding.
        merge_facts(known, record)
        if _REACHABLE_ORDER[record["reachable"]] > _REACHABLE_ORDER.get(known.get("reachable"), 1):
            known["reachable"] = record["reachable"]
        if record["class"] == "durable":
            known["class"] = "durable"
        # The stored severity is the unprofiled reading of the merged facts;
        # the verdict re-reads it with the profile of the day.
        apply_rubric(known, None)
    state["runs"].append({"gate": gate, "caller": caller, "count": len(incoming), "new": new})
    del state["runs"][:-200]
    return new
