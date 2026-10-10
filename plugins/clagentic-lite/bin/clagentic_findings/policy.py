"""Which revision the policy files are read from: the trusted base, through
git, and never the working tree or the branch."""
from .dispositions import (DISPOSITIONS_REL, LEGACY_ACKS_REL, LEGACY_DEFERRALS_REL,
                           LEGACY_RISKS_REL, entry_key, load_store)
from .fileio import dumps
from .gitstate import git_reader, worktree_reader
from .stakes import PROFILE_REL

POLICY_FILES = (DISPOSITIONS_REL, LEGACY_DEFERRALS_REL, LEGACY_ACKS_REL, LEGACY_RISKS_REL, PROFILE_REL)


def load_policy(root, base):
    """The dispositions that apply, and the ones that only could.

    Policy (the dispositions file and the legacy deferral and ack files) is
    read ONLY from the trusted base revision, through git, never from the
    working tree or the branch: whatever wrote a policy file, by whatever
    channel, a change to it applies only once it is merged. That is the
    guarantee; the Builder write blocks (W-007, R-021) are a best-effort
    deterrent on top of it, not part of it. With no resolvable BASE nothing
    applies (the worst case) and the third element says so.

    Returns (store, proposed, notes): STORE is what load_store reads at BASE
    (empty without one); PROPOSED are the entries in the working tree that the
    base does not have, which clear nothing and are only reported as what this
    change would clear once merged; NOTES are lines for the verdict. Problems
    found in the working tree's copy are appended to STORE's 'invalid' list so
    the author sees them before merging; they decide nothing."""
    notes = []
    if base:
        store = load_store(root, git_reader(root, base))
        base_keys = {entry_key(entry) for entry in store["entries"]}
    else:
        store = {"entries": [], "invalid": [], "warnings": [], "legacy": []}
        base_keys = set()
    branch = load_store(root, worktree_reader(root), check_hash=False)
    proposed = [entry for entry in branch["entries"] if entry_key(entry) not in base_keys]
    known_invalid = {dumps(record, sort_keys=True) for record in store["invalid"]}
    unread = [record for record in branch["invalid"] if dumps(record, sort_keys=True) not in known_invalid]
    # Problems in the working tree's copy are shown so the author sees them
    # before merging; they cannot change a verdict, which only the base decides.
    store["invalid"] = store["invalid"] + unread
    if not base and (branch["entries"] or branch["invalid"] or branch["legacy"]):
        notes.append("the base commit could not be resolved: no disposition entry applies (the "
                     "worst case); entries are read only from the base revision, so every entry "
                     "in the working tree is treated as added in this change and clears nothing")
    return store, proposed, notes


def read_policy_file_at_base(root, base, rel):
    """The text of policy file REL as the trusted base revision has it, or ""
    when there is no base or the base does not have it. A prompt that quotes a
    policy file reads it here, through the same revision load_policy uses, so
    what the model is shown is what the gate would honour; the working tree's
    copy is never consulted. Raises ValueError for a path that is not a policy
    file and OSError when the base cannot be read."""
    if rel not in POLICY_FILES:
        raise ValueError("%s is not a policy file" % rel)
    if not base:
        return ""
    return git_reader(root, base)(rel) or ""
