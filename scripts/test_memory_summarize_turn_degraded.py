"""
Regression coverage for lr-7047bf (fold-in, BOBBIE PR #141 review finding 2):
scripts/memory.sh's cmd_summarize_turn was an unwired fifth consumer of
walk_chain's outcome channel -- the exact defect class this task exists to
close, invisible to the gates.sh-scoped sweep test.

Root cause: `SUMMARY=$("$TOOL_HOME/scripts/llm-client.sh" summarize | head -c
200)` discarded llm-client.sh's exit status on TWO levels -- the inner
`walk_chain | head -c 200; echo` pipeline inside cmd_summarize
(llm-client.sh) reported echo's status, not walk_chain's, and the outer
`$(... | head -c 200)` in memory.sh reported the trailing `head -c 200`'s
status, not llm-client.sh's. memory.sh's only guard was "is $SUMMARY
empty" -- but emit_degraded's line-mode payload
("[clagentic-lite degraded] <reason>") is NON-empty, so a genuinely
degraded chain (chain configured, every step failed) sailed past that
guard and was truncated to 200 chars and written into the turns table via
cmd_log_turn as a FABRICATED SUMMARY, polluting session memory and lore
recall with an infra-failure banner disguised as real content.

The FIX has two parts, both exercised here against the REAL scripts:
  1. llm-client.sh's cmd_summarize now propagates walk_chain's real exit
     status as its own (previously always 0, since it ended in `| head -c
     200; echo`).
  2. memory.sh's cmd_summarize_turn now checks that status (and, as
     defense in depth, the degraded text marker) BEFORE calling
     cmd_log_turn, and skips (does not write to the turns table) on a
     genuine degraded chain -- while the benign no-chain-configured skip
     (empty stdout, status 0) remains a silent, correct no-op with no
     write either way.

These tests invoke the REAL memory.sh and llm-client.sh binaries as
subprocesses (not a Python mirror of the shell logic) against a scratch
git repo and a scratch memory.db, with a fake `claude` CLI on PATH so no
live model call is made. This is the same "exercise the real script"
discipline test_walk_chain_degraded_status.py and test_llm_client_sh.py
already use.

Run with: python3 -m unittest scripts.test_memory_summarize_turn_degraded -v
"""
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MEMORY_SH = os.path.join(TOOL_HOME, "scripts", "memory.sh")


def _write_always_failing_claude(bin_dir):
    """A `claude` stub that drains stdin and exits 1 unconditionally --
    drives walk_chain's every-step-failed degraded path deterministically,
    mirroring test_walk_chain_degraded_status.py's identical fixture."""
    path = os.path.join(bin_dir, "claude")
    with open(path, "w") as f:
        f.write(textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            exit 1
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _init_scratch_repo(repo_dir):
    """A minimal git repo -- memory.sh/gates.sh resolve REPO_ROOT via
    CLAGENTIC_PROJECT_ROOT (set explicitly below) or `git show-toplevel`;
    a real repo keeps both resolution paths valid."""
    subprocess.run(["git", "init", "-q", repo_dir], check=True)
    subprocess.run(
        ["git", "-C", repo_dir, "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", repo_dir, "config", "user.name", "test"], check=True
    )


def _run_summarize_turn(chain_configured, transcript="assistant turn text"):
    """Run the REAL `memory.sh summarize-turn` against a scratch repo, with
    a fake `claude` on PATH. When chain_configured is True,
    CLAGENTIC_SUMMARIZER_CMD=claude drives the always-failing stub (a
    genuinely degraded chain -- status 3, non-empty payload). When False,
    every summarizer/builder env var is unset (the benign no-chain skip --
    status 0, empty payload).

    Returns (returncode, stdout, stderr, turns_row_count, turns_summaries).
    """
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-memsummarize-")
    try:
        repo_dir = os.path.join(tmpdir, "repo")
        os.makedirs(repo_dir)
        _init_scratch_repo(repo_dir)

        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        _write_always_failing_claude(bin_dir)

        env = dict(os.environ)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
        env["CLAGENTIC_PROJECT_ROOT"] = repo_dir
        # Isolate from any real operator config (~/.config/clagentic) so
        # the test's env vars are the only source of chain configuration.
        env["CLAGENTIC_LITE_HOME"] = os.path.join(tmpdir, "clagentic-home")
        env.pop("CLAGENTIC_SUMMARIZER_CMD", None)
        env.pop("CLAGENTIC_SUMMARIZER_TIER", None)
        env.pop("CLAGENTIC_SUMMARIZER_CHAIN", None)
        env.pop("CLAGENTIC_BUILDER_CMD", None)
        if chain_configured:
            env["CLAGENTIC_SUMMARIZER_CMD"] = "claude"

        r = subprocess.run(
            ["sh", MEMORY_SH, "summarize-turn"],
            input=transcript,
            capture_output=True,
            text=True,
            cwd=repo_dir,
            env=env,
        )

        db_path = os.path.join(repo_dir, ".clagentic", "lite", "memory.db")
        row_count = 0
        summaries = []
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            try:
                cur = conn.execute("SELECT summary FROM turns")
                summaries = [row[0] for row in cur.fetchall()]
                row_count = len(summaries)
            except sqlite3.OperationalError:
                pass  # table never created -- zero rows either way
            finally:
                conn.close()

        return r.returncode, r.stdout, r.stderr, row_count, summaries
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestDegradedSummarizerChainDoesNotPolluteTurnsTable(unittest.TestCase):
    """The primary fix: a configured-but-fully-failing summarizer chain
    must not write a fabricated summary to the turns table."""

    def test_degraded_chain_writes_no_row(self):
        rc, out, err, row_count, summaries = _run_summarize_turn(chain_configured=True)
        self.assertEqual(
            row_count, 0,
            f"a genuinely degraded summarizer chain must not write ANY row "
            f"to the turns table -- a missing summary is correct, a "
            f"fabricated one is not. rows written: {summaries!r}. "
            f"stdout={out!r} stderr={err!r}",
        )

    def test_degraded_chain_exits_cleanly_not_as_a_hard_failure(self):
        """A degraded chain is non-fatal (memory is best-effort) -- the
        script must still exit 0, not abort the caller's session."""
        rc, out, err, row_count, summaries = _run_summarize_turn(chain_configured=True)
        self.assertEqual(
            rc, 0,
            f"memory.sh summarize-turn must exit 0 on a degraded chain "
            f"(best-effort, non-fatal) even though it skips the write. "
            f"stdout={out!r} stderr={err!r}",
        )

    def test_degraded_chain_surfaces_on_stderr(self):
        """The failure must be visible (stderr), not silently indistinguishable
        from the benign no-chain skip -- an operator debugging 'why is memory
        empty' needs to see WHICH case happened."""
        rc, out, err, row_count, summaries = _run_summarize_turn(chain_configured=True)
        self.assertIn(
            "degraded", err.lower(),
            f"a genuinely degraded chain must be surfaced on stderr, "
            f"distinct from the benign empty-summary skip message. stderr={err!r}",
        )
        self.assertIn(
            "not writing a fabricated summary", err,
            f"stderr should explicitly say why nothing was written. stderr={err!r}",
        )


class TestBenignNoChainSkipIsUnaffected(unittest.TestCase):
    """Control: the pre-existing, deliberate no-chain-configured silent
    skip (test_walk_chain_degraded_status.py
    ::test_summarizer_role_with_no_chain_still_returns_0) must remain
    exactly as before -- this fix must not make an unconfigured summarizer
    start failing or start writing anything either."""

    def test_no_chain_configured_writes_no_row(self):
        rc, out, err, row_count, summaries = _run_summarize_turn(chain_configured=False)
        self.assertEqual(
            row_count, 0,
            f"the benign no-chain skip must still write zero rows (this "
            f"was already true pre-fix; asserting it stays true). "
            f"rows written: {summaries!r}. stdout={out!r} stderr={err!r}",
        )

    def test_no_chain_configured_exits_cleanly(self):
        rc, out, err, row_count, summaries = _run_summarize_turn(chain_configured=False)
        self.assertEqual(
            rc, 0,
            f"the benign no-chain skip must still exit 0. stdout={out!r} stderr={err!r}",
        )

    def test_no_chain_configured_says_empty_summary_not_degraded(self):
        """Distinguishes the two skip reasons on stderr -- an unconfigured
        summarizer is not an infra failure and must not be reported as one."""
        rc, out, err, row_count, summaries = _run_summarize_turn(chain_configured=False)
        self.assertIn(
            "empty summary", err,
            f"the benign no-chain path's stderr message must still say "
            f"'empty summary', not the degraded-chain message. stderr={err!r}",
        )
        self.assertNotIn(
            "chain degraded", err,
            f"the benign no-chain skip must NOT be reported as a degraded "
            f"chain -- it is a different, non-error outcome. stderr={err!r}",
        )


def _run_log_turn(summary, tags="", source="manual"):
    """Run the REAL `memory.sh log-turn` against a scratch repo/DB. Returns
    (returncode, stdout, stderr, turns_row_count, turns_summaries)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-logturn-chokepoint-")
    try:
        repo_dir = os.path.join(tmpdir, "repo")
        os.makedirs(repo_dir)
        _init_scratch_repo(repo_dir)

        env = dict(os.environ)
        env["CLAGENTIC_PROJECT_ROOT"] = repo_dir
        env["CLAGENTIC_LITE_HOME"] = os.path.join(tmpdir, "clagentic-home")

        r = subprocess.run(
            ["sh", MEMORY_SH, "log-turn", summary, tags, source],
            capture_output=True,
            text=True,
            cwd=repo_dir,
            env=env,
        )

        db_path = os.path.join(repo_dir, ".clagentic", "lite", "memory.db")
        row_count = 0
        summaries = []
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            try:
                cur = conn.execute("SELECT summary FROM turns")
                summaries = [row[0] for row in cur.fetchall()]
                row_count = len(summaries)
            except sqlite3.OperationalError:
                pass
            finally:
                conn.close()

        return r.returncode, r.stdout, r.stderr, row_count, summaries
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestLogTurnChokepointRejectsADegradedMarkedPayload(unittest.TestCase):
    """BOBBIE finding 3 (lr-7047bf fold-in, PR #141 review #2): log-turn is
    the single sink every summarizer-role caller in this repo funnels
    through -- memory.sh's own cmd_summarize_turn (already exercised above,
    which never reaches log-turn on a degraded chain), plus every EXTERNAL
    caller (.claude/hooks/stop-summarize.sh, .claude/hooks/post-tool-
    nudge.sh) that pipes llm-client.sh's `summarize` output here directly.
    Requiring every caller to remember its own degraded check is the exact
    defect class this task closes -- discovered twice, in two separate
    hook files, after cmd_adversarial's own in-process fix shipped. This
    class proves the chokepoint itself: log-turn refuses to write a
    payload carrying the unforgeable DEGRADED_MARKER byte (0x01), no
    matter which caller handed it one -- making the wrong form unwritable
    at the one place they all converge, not just documented per-caller."""

    def test_marker_prefixed_summary_is_rejected_not_written(self):
        degraded_payload = "\x01[clagentic-lite degraded] all chain steps failed for role summarizer"
        rc, out, err, row_count, summaries = _run_log_turn(degraded_payload)
        self.assertEqual(
            row_count, 0,
            f"log-turn must refuse to write a payload carrying the "
            f"DEGRADED_MARKER byte -- a caller that forgets its own "
            f"degraded check must still be caught here. rows written: "
            f"{summaries!r}. stdout={out!r} stderr={err!r}",
        )

    def test_marker_prefixed_summary_returns_nonzero(self):
        degraded_payload = "\x01[clagentic-lite degraded] all chain steps failed for role summarizer"
        rc, out, err, row_count, summaries = _run_log_turn(degraded_payload)
        self.assertNotEqual(
            rc, 0,
            f"log-turn must signal refusal via a nonzero exit, not silently "
            f"no-op. stdout={out!r} stderr={err!r}",
        )
        self.assertIn(
            "degraded", err.lower(),
            f"the refusal must be visible on stderr. stderr={err!r}",
        )

    def test_a_real_summary_that_merely_mentions_the_word_degraded_is_still_written(self):
        """Negative control, mirroring the marker-byte hardening's own
        injection-resistance property (BOBBIE finding 1): the chokepoint
        keys on the leading CONTROL BYTE, not the word "degraded" anywhere
        in the text -- a real, legitimate summary that happens to discuss
        a degraded chain (e.g. session notes about debugging this very
        feature) must not be silently dropped just because it contains
        that word."""
        real_payload = "session summary: investigated why the summarizer chain degraded under load"
        rc, out, err, row_count, summaries = _run_log_turn(real_payload)
        self.assertEqual(
            row_count, 1,
            f"a real summary containing the word 'degraded' (but no marker "
            f"byte) must still be written -- the chokepoint must not "
            f"pattern-match on banner text. rows written: {summaries!r}. "
            f"stdout={out!r} stderr={err!r}",
        )
        self.assertEqual(summaries[0], real_payload)

    def test_a_normal_summary_is_unaffected(self):
        rc, out, err, row_count, summaries = _run_log_turn("refactored the widget loader")
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertEqual(row_count, 1, f"summaries={summaries!r}")


if __name__ == "__main__":
    unittest.main()
