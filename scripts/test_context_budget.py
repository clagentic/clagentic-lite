"""
Tests for the context-budget monitor in post-tool-nudge.sh.

Each test runs the hook with a synthetic JSON payload (via subprocess) against
a temporary audit.db and verifies the expected stdout and db row contents.

These tests require: sh, sqlite3, python3 (all project dependencies).
"""
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest


# Absolute path to the hook — resolved from this file's location.
_HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".claude", "hooks", "post-tool-nudge.sh")


def _run_hook(payload: dict, env_overrides: dict | None = None) -> subprocess.CompletedProcess:
    """Run the hook with the given payload dict and return the CompletedProcess."""
    env = dict(os.environ)
    # Suppress real ds_load_env config loading to keep tests hermetic.
    env["CLAGENTIC_ENV_LOADED"] = "1"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["/bin/sh", _HOOK],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=env,
    )


def _make_audit_db(path: str) -> None:
    """Create a minimal audit.db at path with the gate_runs table."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE gate_runs "
        "(ts TEXT, gate TEXT, outcome TEXT, details TEXT, session_id TEXT);"
    )
    conn.commit()
    conn.close()


class TestContextBudgetMonitor(unittest.TestCase):
    """Tests for the context-budget monitor section of post-tool-nudge.sh."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        # Minimal .clagentic/lite/ structure so the hook resolves audit.db.
        lite_dir = os.path.join(self._tmp, ".clagentic", "lite")
        os.makedirs(lite_dir, exist_ok=True)
        self._audit_db = os.path.join(lite_dir, "audit.db")
        _make_audit_db(self._audit_db)
        # Initialize a real git repo so ds_repo_root (git rev-parse --show-toplevel)
        # resolves self._tmp correctly.  Use a bare-minimum init so no network or
        # signing is needed.
        subprocess.run(
            ["git", "init", "-q", self._tmp],
            check=True, capture_output=True,
        )

    def _env(self, **overrides):
        env = {
            "HOME": os.environ.get("HOME", "/root"),
            "CLAGENTIC_ENV_LOADED": "1",
        }
        env.update(overrides)
        return env

    def _payload(self, output: str = "", session_id: str = "sess-test",
                 tool_name: str = "Bash", command: str = "") -> dict:
        p = {
            "session_id": session_id,
            "tool_name": tool_name,
            "output": output,
        }
        if command:
            p["command"] = command
        return p

    def _run(self, payload: dict, env: dict | None = None) -> subprocess.CompletedProcess:
        full_env = dict(os.environ)
        full_env["CLAGENTIC_ENV_LOADED"] = "1"
        full_env["HOME"] = os.environ.get("HOME", "/root")
        # Unset GIT_DIR/GIT_WORK_TREE so git uses the real repo at self._tmp (cwd).
        full_env.pop("GIT_DIR", None)
        full_env.pop("GIT_WORK_TREE", None)
        if env:
            full_env.update(env)
        return subprocess.run(
            ["/bin/sh", _HOOK],
            input=json.dumps(payload).encode(),
            capture_output=True,
            env=full_env,
            cwd=self._tmp,
        )

    # ------------------------------------------------------------------
    # Threshold crossing detection
    # ------------------------------------------------------------------

    def test_below_thresholds_emits_nothing(self):
        """When both result and session are below thresholds, hook exits silently."""
        output = "a" * 1000  # 1000 bytes => 250 tokens (below 8000 default)
        result = self._run(self._payload(output=output))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"",
                         f"expected no output, got: {result.stdout!r}")

    def test_large_result_emits_result_warn(self):
        """A single large tool result crossing RESULT_WARN emits RESULT_WARN label."""
        output = "x" * 40000  # 40000 bytes => 10000 tokens (exceeds 8000 default)
        result = self._run(self._payload(output=output))
        self.assertEqual(result.returncode, 0)
        stdout = result.stdout.decode()
        self.assertIn("CLAGENTIC BUDGET", stdout)
        self.assertIn("RESULT_WARN", stdout)
        self.assertIn("additionalContext", stdout)

    def test_large_result_does_not_emit_session_warn_on_first_call(self):
        """A first large result crossing RESULT_WARN but not SESSION_WARN should not include SESSION_WARN."""
        # 10000 tokens: exceeds RESULT_WARN=8000 but not SESSION_WARN=50000
        output = "x" * 40000
        result = self._run(self._payload(output=output),
                           env={"CLAGENTIC_SESSION_TOKEN_WARN": "50000"})
        stdout = result.stdout.decode()
        self.assertIn("RESULT_WARN", stdout)
        self.assertNotIn("SESSION_WARN", stdout)

    def test_session_warn_triggered_by_accumulation(self):
        """Accumulated session total crossing SESSION_WARN emits SESSION_WARN label."""
        # Pre-populate audit.db with a large prior total for this session.
        conn = sqlite3.connect(self._audit_db)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS context_budget "
            "(session_id TEXT, ts TEXT DEFAULT (datetime('now')), tool TEXT, "
            "result_tokens INTEGER, cumulative_tokens INTEGER);"
        )
        conn.execute(
            "INSERT INTO context_budget (session_id, tool, result_tokens, cumulative_tokens) "
            "VALUES ('sess-heavy', 'Bash', 49000, 49000);"
        )
        conn.commit()
        conn.close()

        # New result: 2000 tokens (8000 bytes) — small enough to not trigger RESULT_WARN
        # but pushes cumulative from 49000 to 51000 which exceeds SESSION_WARN=50000.
        output = "y" * 8000
        result = self._run(
            self._payload(output=output, session_id="sess-heavy"),
            env={"CLAGENTIC_RESULT_TOKEN_WARN": "8000",
                 "CLAGENTIC_SESSION_TOKEN_WARN": "50000"},
        )
        stdout = result.stdout.decode()
        self.assertIn("SESSION_WARN", stdout)

    def test_opt_out_via_disable_budget(self):
        """CLAGENTIC_DISABLE_BUDGET=1 suppresses all budget output."""
        output = "x" * 400000  # massive output that would normally warn
        result = self._run(self._payload(output=output),
                           env={"CLAGENTIC_DISABLE_BUDGET": "1"})
        self.assertEqual(result.returncode, 0)
        # Only git nudge could fire — but no command, so nothing at all.
        self.assertEqual(result.stdout, b"")

    def test_custom_thresholds_respected(self):
        """Custom threshold via env var: RESULT_WARN=100 fires on 101-byte output."""
        output = "z" * 404  # 404 bytes => 101 tokens (exceeds custom threshold of 100)
        result = self._run(self._payload(output=output),
                           env={"CLAGENTIC_RESULT_TOKEN_WARN": "100"})
        stdout = result.stdout.decode()
        self.assertIn("RESULT_WARN", stdout)

    # ------------------------------------------------------------------
    # Audit DB persistence
    # ------------------------------------------------------------------

    def test_db_row_inserted_when_threshold_crossed(self):
        """A row is written to context_budget table when a threshold is crossed."""
        output = "x" * 40000
        self._run(self._payload(output=output, session_id="sess-db-test"))
        conn = sqlite3.connect(self._audit_db)
        rows = conn.execute(
            "SELECT session_id, tool, result_tokens FROM context_budget "
            "WHERE session_id='sess-db-test';"
        ).fetchall()
        conn.close()
        self.assertTrue(len(rows) >= 1, "expected at least one context_budget row")
        self.assertEqual(rows[0][0], "sess-db-test")
        self.assertEqual(rows[0][1], "Bash")
        self.assertGreater(rows[0][2], 8000)

    def test_db_row_inserted_below_threshold(self):
        """A row is still written to context_budget even when below threshold (silent tracking)."""
        output = "a" * 1000  # below threshold
        self._run(self._payload(output=output, session_id="sess-quiet"))
        conn = sqlite3.connect(self._audit_db)
        rows = conn.execute(
            "SELECT result_tokens FROM context_budget WHERE session_id='sess-quiet';"
        ).fetchall()
        conn.close()
        # The hook inserts even when silent — for cumulative tracking purposes.
        self.assertTrue(len(rows) >= 1, "expected a context_budget row even below threshold")

    def test_cumulative_tokens_correct_after_two_calls(self):
        """Cumulative tokens after two calls equals sum of both result_tokens."""
        output1 = "a" * 4000  # 1000 tokens
        output2 = "b" * 8000  # 2000 tokens

        self._run(self._payload(output=output1, session_id="sess-cumul"))
        self._run(self._payload(output=output2, session_id="sess-cumul"))

        conn = sqlite3.connect(self._audit_db)
        rows = conn.execute(
            "SELECT result_tokens, cumulative_tokens FROM context_budget "
            "WHERE session_id='sess-cumul' ORDER BY rowid;"
        ).fetchall()
        conn.close()

        self.assertEqual(len(rows), 2)
        # First call: result=1000, cumulative=1000
        self.assertEqual(rows[0][0], 1000)
        self.assertEqual(rows[0][1], 1000)
        # Second call: result=2000, cumulative=3000
        self.assertEqual(rows[1][0], 2000)
        self.assertEqual(rows[1][1], 3000)

    # ------------------------------------------------------------------
    # Coexistence with git nudge
    # ------------------------------------------------------------------

    def test_git_commit_nudge_still_fires(self):
        """Git commit nudge is still emitted even when budget is below threshold."""
        result = self._run(self._payload(command="git commit -m 'test'", output=""))
        stdout = result.stdout.decode()
        self.assertIn("changes committed", stdout)
        self.assertIn("additionalContext", stdout)

    def test_both_budget_and_git_nudge_in_one_response(self):
        """When both budget warn and git commit match, both appear in additionalContext."""
        output = "x" * 40000  # triggers RESULT_WARN
        result = self._run(self._payload(
            output=output, command="git commit -m 'big file'"))
        stdout = result.stdout.decode()
        self.assertIn("CLAGENTIC BUDGET", stdout)
        self.assertIn("changes committed", stdout)

    # ------------------------------------------------------------------
    # Robustness: no DB
    # ------------------------------------------------------------------

    def test_no_audit_db_exits_clean(self):
        """When audit.db does not exist, hook exits 0 without error."""
        os.remove(self._audit_db)
        output = "x" * 40000
        result = self._run(self._payload(output=output))
        self.assertEqual(result.returncode, 0)
        # Warning should still be emitted (uses result-only cumulative fallback).
        stdout = result.stdout.decode()
        self.assertIn("CLAGENTIC BUDGET", stdout)

    def test_empty_payload_exits_clean(self):
        """Empty stdin exits 0 silently."""
        result = subprocess.run(
            ["/bin/sh", _HOOK],
            input=b"",
            capture_output=True,
            env={**os.environ, "CLAGENTIC_ENV_LOADED": "1"},
            cwd=self._tmp,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
