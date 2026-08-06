"""
Regression coverage for lr-7047bf (fold-in, BOBBIE + HOLDEN, PR #141 review
#2): .claude/hooks/stop-summarize.sh's summarizer call was an unwired
consumer of walk_chain's outcome channel -- invisible to a scripts/-and-
bin/-scoped sweep because .claude/ is a dotfile directory that sweep never
walked. A genuinely degraded summarizer chain must not write a fabricated
summary to memory.db, and the audit trail must not report "pass" for a run
that produced no real summary.

The hook detaches into a backgrounded subshell after a debounce sleep
(CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC, default 20s) so Claude Code's Stop event
returns immediately. These tests set the debounce to 0 and poll (bounded)
for the backgrounded work to land, rather than sleeping a fixed duration --
mirroring this repo's poll-for-completion discipline elsewhere
(scoped-test-wait) instead of a flaky fixed sleep.

Run with: python3 -m unittest scripts.test_stop_summarize_degraded -v
"""
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HOOK = os.path.join(TOOL_HOME, ".claude", "hooks", "stop-summarize.sh")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _init_scratch_repo(repo_dir):
    subprocess.run(["git", "init", "-q", repo_dir], check=True)
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(
        ["git", "-C", repo_dir, "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(["git", "-C", repo_dir, "config", "user.name", "test"], check=True)
    return env


def _write_transcript(path, assistant_text):
    """One JSONL line matching the Claude Code transcript shape the hook's
    embedded python3 parser reads (top-level role/content)."""
    with open(path, "w") as f:
        f.write(json.dumps({"role": "assistant", "content": assistant_text}) + "\n")


def _write_fake_llm_client(scripts_dir, degraded):
    path = os.path.join(scripts_dir, "llm-client.sh")
    if degraded:
        body = (
            "#!/bin/sh\n"
            "cat > /dev/null\n"
            "printf '\\001[clagentic-lite degraded] all chain steps failed for role summarizer'\n"
            "exit 3\n"
        )
    else:
        body = (
            "#!/bin/sh\n"
            "cat > /dev/null\n"
            "printf 'a real summary of the assistant turn'\n"
            "exit 0\n"
        )
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)


def _make_audit_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE gate_runs "
        "(ts TEXT, gate TEXT, outcome TEXT, details TEXT, session_id TEXT);"
    )
    conn.commit()
    conn.close()


def _poll_until(predicate, timeout_s=5, interval_s=0.05):
    """Poll predicate() until truthy or timeout_s elapses. Returns the last
    (possibly falsy) predicate() result -- bounded, not a fixed sleep."""
    deadline = time.time() + timeout_s
    result = predicate()
    while not result and time.time() < deadline:
        time.sleep(interval_s)
        result = predicate()
    return result


class _StopSummarizeFixture(unittest.TestCase):
    """Shared scratch-repo setup for both degraded and clean hook runs."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-stopsumm-")
        self._repo = os.path.join(self._tmpdir, "repo")
        os.makedirs(self._repo)
        self._git_env = _init_scratch_repo(self._repo)

        self._scripts_dir = os.path.join(self._repo, "scripts")
        os.makedirs(self._scripts_dir)
        # memory.sh + platform.sh: real files, so log-turn's own chokepoint
        # guard is exercised too (defense in depth, same rationale as the
        # post-tool-nudge.sh coverage in test_context_budget.py).
        for fname in ("memory.sh", "platform.sh"):
            shutil.copy(os.path.join(TOOL_HOME, "scripts", fname), self._scripts_dir)
            os.chmod(os.path.join(self._scripts_dir, fname), 0o755)

        self._clagentic_dir = os.path.join(self._repo, ".clagentic", "lite")
        os.makedirs(self._clagentic_dir, exist_ok=True)
        self._audit_db = os.path.join(self._clagentic_dir, "audit.db")
        _make_audit_db(self._audit_db)
        self._memory_db = os.path.join(self._clagentic_dir, "memory.db")

        self._transcript = os.path.join(self._tmpdir, "transcript.jsonl")
        _write_transcript(self._transcript, "This is the assistant's last turn text.")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_hook(self, degraded, session_id="sess-stop-test"):
        _write_fake_llm_client(self._scripts_dir, degraded=degraded)
        payload = {
            "session_id": session_id,
            "transcript_path": self._transcript,
            "stop_hook_active": False,
        }
        env = dict(os.environ)
        env.update(self._git_env)
        env["CLAGENTIC_ENV_LOADED"] = "1"
        env["CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC"] = "0"
        env["CLAGENTIC_DISABLE_HANDOFF"] = "1"
        env.pop("GIT_DIR", None)
        env.pop("GIT_WORK_TREE", None)
        result = subprocess.run(
            ["sh", HOOK],
            input=json.dumps(payload).encode(),
            capture_output=True,
            env=env,
            cwd=self._repo,
        )
        # The hook backgrounds its real work (`) >/dev/null 2>&1 &`) and
        # returns immediately (exit 0) regardless of outcome, so the
        # backgrounded subshell may still be in flight -- or may have
        # ALREADY finished and removed its own lock file (debounce=0 makes
        # this genuinely fast) -- by the time this call returns. Tracking
        # the lock file's PID lifecycle races both ways: the lock can
        # appear-then-vanish entirely between two polls, or vanish before
        # the first poll ever observes it. Poll directly for this session's
        # own audit_log row instead (the hook's own LAST durable write,
        # written after either the degraded-skip branch or the log-turn
        # branch) -- a fact about outcome, not about process lifecycle.
        _poll_until(lambda: len(self._audit_rows(session_id)) > 0)
        return result

    def _turns_rows(self):
        if not os.path.exists(self._memory_db):
            return []
        conn = sqlite3.connect(self._memory_db)
        try:
            rows = conn.execute("SELECT summary FROM turns;").fetchall()
        except sqlite3.OperationalError:
            rows = []
        conn.close()
        return rows

    def _audit_rows(self, session_id):
        conn = sqlite3.connect(self._audit_db)
        rows = conn.execute(
            "SELECT gate, outcome, details FROM gate_runs WHERE session_id=?;",
            (session_id,),
        ).fetchall()
        conn.close()
        return rows


class TestDegradedSummarizerChainDoesNotPolluteMemory(_StopSummarizeFixture):
    def test_degraded_chain_writes_no_row(self):
        self._run_hook(degraded=True, session_id="sess-degraded-1")
        rows = self._turns_rows()
        self.assertEqual(
            rows, [],
            f"a genuinely degraded summarizer chain must not write ANY row "
            f"to memory.db's turns table. rows={rows!r}",
        )

    def test_degraded_chain_does_not_log_audit_pass(self):
        """The specific fix in stop-summarize.sh:96 (pre-fix): the audit
        trail unconditionally logged 'summarize pass' even for a run that
        produced a fabricated/degraded summary -- an audit-vocabulary lie
        on top of the fabrication. A degraded run must log 'skip', never
        'pass'."""
        self._run_hook(degraded=True, session_id="sess-degraded-2")
        rows = self._audit_rows("sess-degraded-2")
        outcomes = [r[1] for r in rows if r[0] == "summarize"]
        self.assertNotIn(
            "pass", outcomes,
            f"a degraded chain must never be logged as 'pass' -- that is "
            f"exactly the audit-vocabulary lie this fix closes. "
            f"gate_runs rows={rows!r}",
        )
        self.assertIn(
            "skip", outcomes,
            f"a degraded chain must be logged as 'skip', distinct from a "
            f"real pass. gate_runs rows={rows!r}",
        )


class TestCleanSummarizerChainIsUnaffected(_StopSummarizeFixture):
    """Negative control: a real, successful summarizer response must still
    be written and logged as pass -- proves the degraded check does not
    simply suppress the whole feature."""

    def test_clean_chain_writes_one_row(self):
        self._run_hook(degraded=False, session_id="sess-clean-1")
        rows = self._turns_rows()
        self.assertEqual(len(rows), 1, f"rows={rows!r}")
        self.assertIn("a real summary", rows[0][0])

    def test_clean_chain_logs_audit_pass(self):
        self._run_hook(degraded=False, session_id="sess-clean-2")
        rows = self._audit_rows("sess-clean-2")
        outcomes = [r[1] for r in rows if r[0] == "summarize"]
        self.assertIn("pass", outcomes, f"gate_runs rows={rows!r}")


if __name__ == "__main__":
    unittest.main()
