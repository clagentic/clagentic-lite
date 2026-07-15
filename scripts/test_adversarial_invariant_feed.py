"""
Acceptance replay for lr-24c80e: adversarial gate invariant-feed.

Root problem (verdict ef-2026-07-15-deduploop): the adversarial gate
(cmd_adversarial in gates.sh -> ds_adversarial_prompt in llm-client.sh) is
context-free by construction. It re-derives threats from the diff alone every
round, with no memory of what a prior round already found and fixed. This lets
a fix in round N get silently re-violated in round N+2 (or recur at a wider
scope), because nothing tells the Auditor to check for that specific
regression class again.

This test replays a SYNTHETIC 6-round fixture (generic, in-repo, no external
project/host names) modeling that failure mode as an abstract CWE trace:

  R1 CWE-807 (trusting client-settable input in a skip/dedup decision)
  R2 fix -> CWE-697 (dedup key too coarse, drops distinct items)
  R3 fix -> CWE-354 (lossy normalization collides distinct inputs)
  R4 fix -> CWE-770 at item scope (fail-open sentinel path, unbounded rows)
  R5 fix -> CWE-759 (unsalted brute-forceable hash of sensitive value)
  R6 -> CWE-798 (hardcoded key fallback) + CWE-770 recurring at a wider
       aggregation scope

The two reintroductions under test:
  (a) R4's diff re-violates the invariant established when R2 was fixed
      (dedup key coarseness).
  (b) R6's diff re-violates the invariant established when R4 was fixed
      (unbounded-growth fail-open), but at a wider (fleet/aggregate) scope.

We do not have a real LLM in the test harness, so we cannot literally ask a
model to "notice" these. Instead we exercise the REAL prompt-construction and
REAL gate-invocation code paths (ds_adversarial_prompt, cmd_adversarial) with a
stub CLI standing in for the LLM. The stub's canned behavior is a deterministic
proxy for "the model was shown the invariant text and correctly matched it
against the diff": it only reports a reintroduction finding for round N when
the exact invariant statement text for the violated round appears somewhere in
its stdin (prompt + diff). This proves the invariant text actually reaches the
model call in the code path that matters, without requiring a live model in CI.

Assertions:
  - feed ON: round 4 output flags a re-violation of the round-2 invariant,
    AND round 6 output flags a re-violation of the round-4 invariant at wider
    scope, BEFORE those changes would ship (i.e. the adversarial pass would
    have surfaced them). No unrelated/false-violation flooding: rounds 1, 2,
    3, 5 must not spuriously claim a reintroduction they don't contain, and
    the flagged rounds must not claim MORE reintroductions than the two real
    ones.
  - feed OFF: rounds 4 and 6 do NOT flag the reintroductions (demonstrating
    the regression this feature closes -- the stub has no invariant text to
    match against, mirroring the context-free status quo).

Run with: python3 -m unittest scripts.test_adversarial_invariant_feed -v
"""
import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# One invariant statement per resolved round, matching the schema documented
# in docs/GATES.md / share/config.example. Statements are generic — no
# external project or host names, per the operator correction on lr-24c80e.
INVARIANTS = [
    {
        "id": "inv-r2",
        "category": "correctness",
        "file": "app/dedup.py",
        "statement": "The dedup key must be granular enough that two distinct "
                      "input items never collapse onto the same key (CWE-697 "
                      "dedup-key-too-coarse class).",
    },
    {
        "id": "inv-r3",
        "category": "correctness",
        "file": "app/dedup.py",
        "statement": "Key normalization must not lossily collide distinct "
                      "inputs onto the same normalized form (CWE-354 class).",
    },
    {
        "id": "inv-r4",
        "category": "security",
        "file": "app/dedup.py",
        "statement": "The fail-open sentinel path must bound the number of "
                      "rows it can affect; it must never fail open across an "
                      "unbounded or wider-than-originally-scoped set of items "
                      "(CWE-770 uncontrolled-resource-consumption class).",
    },
    {
        "id": "inv-r5",
        "category": "security",
        "file": "app/dedup.py",
        "statement": "Any hash of a sensitive value used in the dedup key must "
                      "be salted; an unsalted hash is brute-forceable "
                      "(CWE-759 class).",
    },
]


def _invariant_text():
    return json.dumps(INVARIANTS)


# ------------------------------------------------------------ fixture snapshots

# Each round is the FULL working-tree content of app/dedup.py after that
# round's change. The harness writes the snapshot, stages it, runs the gate
# against the resulting incremental diff (this round's snapshot vs. the prior
# round's committed snapshot), then commits so the next round's diff is clean
# and incremental rather than cumulative. Content is invented sample code for
# a generic dedup-key hardening sequence; it does not name any real project,
# host, or organization.

SNAPSHOT_R0 = textwrap.dedent("""\
    def process(item):
        pass
""")

SNAPSHOT_R1 = textwrap.dedent("""\
    def should_skip(item, client_flags):
        # NEW BUG (CWE-807): trusts a client-settable flag for a dedup decision.
        return client_flags.get("already_seen", False)

    def process(item):
        pass
""")

SNAPSHOT_R2 = textwrap.dedent("""\
    def dedup_key(item):
        # Fix for CWE-807: server-derived key, ignores client flags.
        # NEW BUG (CWE-697): key is just the item type, too coarse -- distinct
        # items of the same type collapse onto one key and get dropped.
        return item.type
""")

SNAPSHOT_R3 = textwrap.dedent("""\
    def dedup_key(item):
        # Fix for CWE-697: key includes item id, granular per-item.
        # NEW BUG (CWE-354): id is lowercased+trimmed before hashing, so
        # "Widget-1" and "widget-1" (distinct upstream ids) collide.
        return item.type + ":" + item.id.lower().strip()
""")

# R4 fixes CWE-354 (normalization collision) but in the same diff RE-VIOLATES
# the round-2 invariant (inv-r2): it narrows the key back down to something
# too coarse again via a fail-open sentinel path, at ITEM scope (one item
# type at a time, not yet fleet-wide).
SNAPSHOT_R4 = textwrap.dedent("""\
    def dedup_key(item):
        # Fix for CWE-354: preserve original case, no lossy normalization.
        try:
            return item.type + ":" + item.id
        except AttributeError:
            # NEW BUG: fail-open sentinel collapses ALL items of this type back onto one coarse key when .id is missing -- re-violates the round-2 dedup-key-granularity invariant, scoped to one item type.
            return item.type
""")

SNAPSHOT_R5 = textwrap.dedent("""\
    def dedup_key(item):
        try:
            return item.type + ":" + item.id
        except AttributeError:
            # Fix for the item-scope fail-open: raise instead of collapsing.
            raise ValueError("item missing id, cannot compute dedup key")

    def hash_sensitive(value):
        # NEW BUG (CWE-759): unsalted hash of a sensitive value used in the key.
        import hashlib
        return hashlib.sha256(value.encode()).hexdigest()
""")

# R6 introduces CWE-798 (hardcoded fallback key) AND re-violates the round-4
# invariant (inv-r4, unbounded fail-open), but at a WIDER scope: the fail-open
# path now spans the whole fleet/aggregate batch, not one item.
SNAPSHOT_R6 = textwrap.dedent("""\
    def dedup_key(item):
        try:
            return item.type + ":" + item.id
        except AttributeError:
            raise ValueError("item missing id, cannot compute dedup key")

    def hash_sensitive(value, salt="default-fallback-key-2026"):
        # NEW BUG (CWE-798): hardcoded fallback salt.
        import hashlib
        return hashlib.sha256((salt + value).encode()).hexdigest()

    def process_batch(items):
        try:
            return [dedup_key(i) for i in items]
        except ValueError:
            # NEW BUG: fail-open now spans the ENTIRE batch (fleet-wide
            # aggregation scope), not one item -- re-violates the round-4
            # unbounded fail-open invariant at a wider scope.
            return []
""")

ROUNDS = {
    1: SNAPSHOT_R1,
    2: SNAPSHOT_R2,
    3: SNAPSHOT_R3,
    4: SNAPSHOT_R4,
    5: SNAPSHOT_R5,
    6: SNAPSHOT_R6,
}


# ------------------------------------------------------------------- stub CLI
#
# Unlike test_merge_gate_recheck.py (which stubs the whole llm-client.sh
# wrapper), THIS replay must exercise the real ds_adversarial_prompt function
# in the real llm-client.sh -- that's the code under test (the invariant
# injection itself). So llm-client.sh is the REAL file (symlinked, unmodified)
# and only the underlying model CLI it shells out to (`claude`) is faked, the
# same pattern test_llm_client_sh.py uses for invoke_claude. invoke_claude
# passes the fully-built prompt (including any injected invariants block) as
# a `--append-system-prompt` argv value and the diff on stdin -- the fake
# `claude` binary reads both and decides what to "find" as a deterministic
# proxy for model judgment.

_FAKE_CLAUDE_SCRIPT = r"""#!/bin/sh
# fake claude CLI standing in for the real model for replay testing.
# argv contains --append-system-prompt "<full prompt text, invariants included>"
# stdin is the diff.
#
# A real model reasons about diff polarity: a marker line that is REMOVED
# (a `-` line) means the round FIXED that issue, not reintroduced it. This
# fake proxies that distinction by checking reintroduction markers only
# against ADDED lines (`+`, excluding the `+++ b/...` file header) of the
# diff -- not the raw combined text -- so a fix that merely deletes a prior
# bad line does not get misread as a reintroduction. Fresh-finding markers
# are similarly scoped to added lines, since a marker appearing only in a
# deleted line was fixed away this round, not introduced.
ARGV_STR="$*"
DIFF_TEXT=$(cat)
# grep -F (fixed string) for the "+++ b/..." file-header exclusion: a BRE
# pattern here would need \+\+\+ , where \+ is a GNU one-or-more extension
# with no preceding atom -- unreliable across greps. -F avoids the ambiguity.
ADDED=$(printf '%s\n' "$DIFF_TEXT" | grep -E '^\+' | grep -vF '+++ ')

emit() {
    printf '[FINDING] %s | app/dedup.py:1 | severity: high | title: %s\n\n%s\n\n' "$1" "$2" "$3"
}

# Fresh-this-round CWE markers: content-derived from ADDED diff lines only.
# Every round's diff literally names the CWE it introduces in a `+` line,
# standing in for what a competent adversarial pass would derive from the
# code alone.
case "$ADDED" in *"NEW BUG (CWE-807)"*) emit "CWE-807" "trusts client flag" "fresh finding" ;; esac
case "$ADDED" in *"NEW BUG (CWE-697)"*) emit "CWE-697" "dedup key too coarse" "fresh finding" ;; esac
case "$ADDED" in *"NEW BUG (CWE-354)"*) emit "CWE-354" "lossy normalization collision" "fresh finding" ;; esac
case "$ADDED" in *"NEW BUG: fail-open sentinel collapses"*) emit "CWE-770" "item-scope fail-open" "fresh finding" ;; esac
case "$ADDED" in *"NEW BUG (CWE-759)"*) emit "CWE-759" "unsalted hash" "fresh finding" ;; esac
case "$ADDED" in *"NEW BUG (CWE-798)"*) emit "CWE-798" "hardcoded fallback salt" "fresh finding" ;; esac
case "$ADDED" in *"NEW BUG: fail-open now spans the ENTIRE batch"*) emit "CWE-770" "fleet-wide fail-open" "fresh finding" ;; esac

# Invariant-feed reintroduction checks -- ONLY fire if (a) the invariant's own
# statement text (injected into argv by ds_adversarial_prompt) is present,
# AND (b) the diff's ADDED lines (not the whole combined text) contain the
# marker for that specific reintroduction. (a) proves the invariant text
# from invariants.json actually reaches the model-call input; (b) proves the
# reintroduction is really being added this round, not just referenced in
# text a prior round removed.
case "$ARGV_STR" in
  *"never collapse onto the same key"*)
    case "$ADDED" in
      *"collapses ALL items of this type back onto one coarse key"*)
        emit "CWE-697" "REINTRODUCES inv-r2: dedup key too coarse (item scope)" "reintroduction finding"
        ;;
    esac
    ;;
esac
case "$ARGV_STR" in
  *"must never fail open across an unbounded or wider-than-originally-scoped set"*)
    case "$ADDED" in
      *"fail-open now spans the ENTIRE batch"*)
        emit "CWE-770" "REINTRODUCES inv-r4: unbounded fail-open (wider fleet-aggregate scope)" "reintroduction finding"
        ;;
    esac
    ;;
esac
exit 0
"""


def _write_fake_claude(bin_dir):
    fake = os.path.join(bin_dir, "claude")
    with open(fake, "w") as f:
        f.write(_FAKE_CLAUDE_SCRIPT)
    os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return fake


def _setup_fake_tool_home(fake_tool_home):
    """Symlink the REAL scripts/ and share/ trees into fake_tool_home.

    llm-client.sh is the real, unmodified file -- ds_adversarial_prompt (the
    code under test) must actually run. Only the `claude` binary is faked
    (via bin_dir on PATH, set by the caller), not the wrapper script.
    """
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
    for fname in os.listdir(real_scripts_dir):
        if not fname.endswith(".sh"):
            continue
        src = os.path.join(real_scripts_dir, fname)
        dst = os.path.join(scripts_dir, fname)
        if not os.path.exists(dst):
            os.symlink(src, dst)
    real_share = os.path.join(TOOL_HOME, "share")
    fake_share = os.path.join(fake_tool_home, "share")
    if not os.path.exists(fake_share) and os.path.isdir(real_share):
        os.symlink(real_share, fake_share)


def _init_git_repo(project_root):
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    subprocess.run(["git", "init", "-q", project_root], check=True, env=env)
    subprocess.run(
        ["git", "commit", "--allow-empty", "-q", "-m", "initial"],
        check=True, env=env, cwd=project_root,
    )


_GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _seed_dedup_file(project_root):
    """Commit SNAPSHOT_R0 (the pre-trace baseline) so round 1's diff is a
    clean incremental change rather than a file-creation diff."""
    target = os.path.join(project_root, "app", "dedup.py")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w") as f:
        f.write(SNAPSHOT_R0)
    subprocess.run(["git", "add", "app/dedup.py"], check=True, cwd=project_root)
    subprocess.run(
        ["git", "commit", "-q", "-m", "seed dedup.py"], check=True, cwd=project_root,
        env={**os.environ, **_GIT_IDENTITY_ENV},
    )


def _run_adversarial_round(snapshot_text, fake_tool_home, bin_dir, project_root, invariants_on):
    """Run gates.sh adversarial for one round's snapshot via the fake claude CLI.

    cmd_adversarial calls `get_review_diff | llm-client.sh adversarial`, which
    (the real, unmodified llm-client.sh) resolves the AUDITOR role chain and
    invokes the configured CLI. We point CLAGENTIC_AUDITOR_CMD at `claude` and
    put the fake claude binary (bin_dir) first on PATH, with no CHAIN
    configured, so the real ds_adversarial_prompt runs and its output
    (including any injected invariants block) reaches the fake claude via
    --append-system-prompt argv + diff stdin.

    get_review_diff prefers the staged diff. Each round REPLACES the tracked
    file's full content with that round's snapshot and stages it, so
    `git diff --cached` reflects only that round's incremental change versus
    the previously committed snapshot -- not a cumulative diff across all
    rounds seen so far. After running the gate, the round is committed so the
    next round's staged diff is clean.
    """
    target = os.path.join(project_root, "app", "dedup.py")
    with open(target, "w") as f:
        f.write(snapshot_text)
    subprocess.run(["git", "add", "app/dedup.py"], check=True, cwd=project_root)

    invariants_dir = os.path.join(project_root, ".clagentic", "lite")
    os.makedirs(invariants_dir, exist_ok=True)
    invariants_path = os.path.join(invariants_dir, "invariants.json")
    if invariants_on:
        with open(invariants_path, "w") as f:
            f.write(_invariant_text())
    elif os.path.exists(invariants_path):
        os.remove(invariants_path)

    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ADVERSARIAL_INVARIANTS"] = "1" if invariants_on else "0"
    env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    env["CLAGENTIC_AUDITOR_CMD"] = "claude"
    env["CLAGENTIC_AUDITOR_TIER"] = "default"
    env["CLAGENTIC_AUDITOR_CHAIN"] = ""
    env["CLAGENTIC_LLM_TIMEOUT_SEC"] = "30"

    result = subprocess.run(
        ["sh", fake_gates, "adversarial"],
        capture_output=True, text=True, env=env, cwd=project_root,
    )

    # Commit this round's staged snapshot so the next round's diff is
    # incremental, not cumulative.
    subprocess.run(
        ["git", "commit", "-q", "-m", "round snapshot"], check=True, cwd=project_root,
        env={**os.environ, **_GIT_IDENTITY_ENV},
    )
    return result


class TestAdversarialInvariantFeedReplay(unittest.TestCase):
    """Acceptance test for lr-24c80e: replay the 6-round synthetic CWE trace."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-invfeed-")
        self._project = os.path.join(self._tmpdir, "project")
        os.makedirs(self._project, exist_ok=True)
        _init_git_repo(self._project)
        _seed_dedup_file(self._project)
        self._fake_tool_home = os.path.join(self._tmpdir, "toolhome")
        _setup_fake_tool_home(self._fake_tool_home)
        self._bin_dir = os.path.join(self._tmpdir, "bin")
        os.makedirs(self._bin_dir, exist_ok=True)
        _write_fake_claude(self._bin_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_all_rounds(self, invariants_on):
        outputs = {}
        for n in range(1, 7):
            result = _run_adversarial_round(
                ROUNDS[n], self._fake_tool_home, self._bin_dir, self._project, invariants_on
            )
            self.assertEqual(
                result.returncode, 0,
                f"round {n} gates.sh adversarial exited non-zero: {result.stderr}",
            )
            outputs[n] = result.stdout
        return outputs

    def test_feed_on_catches_both_reintroductions_without_flooding(self):
        outputs = self._run_all_rounds(invariants_on=True)

        # (a) Round 4 must flag reintroduction of the round-2 invariant.
        self.assertIn(
            "REINTRODUCES inv-r2", outputs[4],
            "feed ON: round 4 must flag re-violation of the round-2 "
            "dedup-key-granularity invariant before it ships",
        )
        # (b) Round 6 must flag reintroduction of the round-4 invariant, at
        # wider scope.
        self.assertIn(
            "REINTRODUCES inv-r4", outputs[6],
            "feed ON: round 6 must flag re-violation of the round-4 "
            "unbounded-fail-open invariant (wider fleet-aggregate scope) "
            "before it ships",
        )

        # No false-violation flooding: rounds that do not actually reintroduce
        # anything must not claim a REINTRODUCES finding.
        for n in (1, 2, 3, 5):
            self.assertNotIn(
                "REINTRODUCES", outputs[n],
                f"feed ON: round {n} must not report a false reintroduction "
                f"(output: {outputs[n]!r})",
            )
        # The two flagged rounds must not over-claim beyond the one real
        # reintroduction each round actually contains.
        self.assertEqual(
            outputs[4].count("REINTRODUCES"), 1,
            "round 4 must report exactly one reintroduction, not more",
        )
        self.assertEqual(
            outputs[6].count("REINTRODUCES"), 1,
            "round 6 must report exactly one reintroduction, not more",
        )

    def test_feed_off_lets_reintroductions_pass(self):
        """Demonstrates the regression this feature closes: with the feed
        off, the adversarial pass has no memory of prior invariants and the
        two reintroductions ship undetected."""
        outputs = self._run_all_rounds(invariants_on=False)

        self.assertNotIn(
            "REINTRODUCES", outputs[4],
            "feed OFF: round 4's reintroduction must NOT be caught "
            "(demonstrates the closed regression)",
        )
        self.assertNotIn(
            "REINTRODUCES", outputs[6],
            "feed OFF: round 6's reintroduction must NOT be caught "
            "(demonstrates the closed regression)",
        )

    def test_feed_on_still_reports_fresh_findings_each_round(self):
        """Sanity check: the invariant feed must not suppress or replace the
        normal fresh-finding behavior of the adversarial pass -- it is
        additive."""
        outputs = self._run_all_rounds(invariants_on=True)
        expected_fresh_cwe = {
            1: "CWE-807", 2: "CWE-697", 3: "CWE-354",
            4: "CWE-770", 5: "CWE-759", 6: "CWE-798",
        }
        for n, cwe in expected_fresh_cwe.items():
            self.assertIn(
                cwe, outputs[n],
                f"round {n} must still report its fresh {cwe} finding "
                f"with the invariant feed on (output: {outputs[n]!r})",
            )


if __name__ == "__main__":
    unittest.main()
