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


# Absolute path to the tool's own checkout root -- the hook script's source
# of truth moved from a tracked, live .claude/hooks/post-tool-nudge.sh to
# share/hook-shims/post-tool-nudge.sh.template (lr-57db23; see AGENTS.md
# INV-7). The template resolves its own CLAGENTIC_LITE_HOME via
# `${CLAGENTIC_LITE_HOME:=__CLAGENTIC_LITE_HOME__}` -- run it directly with
# CLAGENTIC_LITE_HOME set to this checkout so platform.sh (and everything it
# provides: ds_json_field, ds_repo_root, ds_load_env, $DS_TIMEOUT_CMD)
# resolves against the REAL, current tracked scripts/, exactly as it would
# once materialized into $CLAGENTIC_LITE_HOME/.claude/hooks/ by
# _stamp_claude_hooks. Testing the template directly (not a materialized
# copy) is deliberate: it is the tracked file a diff review actually sees.
_TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_HOOK = os.path.join(_TOOL_HOME, "share", "hook-shims", "post-tool-nudge.sh.template")


def _run_hook(payload: dict, env_overrides: dict | None = None) -> subprocess.CompletedProcess:
    """Run the hook with the given payload dict and return the CompletedProcess."""
    env = dict(os.environ)
    # Suppress real ds_load_env config loading to keep tests hermetic.
    env["CLAGENTIC_ENV_LOADED"] = "1"
    env["CLAGENTIC_LITE_HOME"] = _TOOL_HOME
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
        full_env["CLAGENTIC_LITE_HOME"] = _TOOL_HOME
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
            env={**os.environ, "CLAGENTIC_ENV_LOADED": "1", "CLAGENTIC_LITE_HOME": _TOOL_HOME},
            cwd=self._tmp,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


class TestAutosummarizeDegradedHandling(unittest.TestCase):
    """Regression coverage for lr-7047bf (fold-in, BOBBIE + HOLDEN, PR #141
    review #2): the auto-summarize section (section 3) of post-tool-
    nudge.sh was one of two unwired llm-client.sh consumers a scripts/-and-
    bin/-scoped sweep could not see, because .claude/ is a dotfile
    directory that sweep never walked. A genuinely degraded summarizer
    chain must not write a fabricated digest to memory.db, and must not
    surface it to the user via additionalContext either.

    Runs the REAL hook script end-to-end (subprocess), against a real git
    repo with a fake scripts/llm-client.sh and scripts/memory.sh under
    REPO_ROOT (the same paths the hook resolves via ds_repo_root) --
    mirrors this file's existing TestContextBudgetMonitor convention."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        lite_dir = os.path.join(self._tmp, ".clagentic", "lite")
        os.makedirs(lite_dir, exist_ok=True)
        self._audit_db = os.path.join(lite_dir, "audit.db")
        _make_audit_db(self._audit_db)
        self._memory_db = os.path.join(lite_dir, "memory.db")
        subprocess.run(
            ["git", "init", "-q", self._tmp],
            check=True, capture_output=True,
        )
        self._scripts_dir = os.path.join(self._tmp, "scripts")
        os.makedirs(self._scripts_dir, exist_ok=True)

    def _write_fake_llm_client(self, degraded):
        """A stub scripts/llm-client.sh: `degraded=True` emits the real
        emit_degraded line-mode shape (marker byte + banner, exit 3);
        `degraded=False` emits a plain digest, exit 0."""
        path = os.path.join(self._scripts_dir, "llm-client.sh")
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
                "printf 'a real digest of the large tool result'\n"
                "exit 0\n"
            )
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)

    def _write_real_memory_sh(self):
        """Copy the REAL scripts/memory.sh into the fake REPO_ROOT so
        log-turn's own chokepoint guard is exercised too, not bypassed by
        a stub -- proving the hook's own degraded check AND the sink's
        chokepoint agree (defense in depth, not either/or)."""
        real_memory_sh = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "memory.sh",
        )
        real_platform_sh = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "platform.sh",
        )
        with open(real_memory_sh) as src:
            content = src.read()
        dest = os.path.join(self._scripts_dir, "memory.sh")
        with open(dest, "w") as f:
            f.write(content)
        os.chmod(dest, 0o755)
        platform_dest = os.path.join(self._scripts_dir, "platform.sh")
        with open(real_platform_sh) as src, open(platform_dest, "w") as f:
            f.write(src.read())

    def _run(self, payload: dict, env: dict | None = None) -> subprocess.CompletedProcess:
        full_env = dict(os.environ)
        full_env["CLAGENTIC_ENV_LOADED"] = "1"
        full_env["HOME"] = os.environ.get("HOME", "/root")
        # This fixture's own scripts/platform.sh (written by
        # _write_real_memory_sh) is the one the hook should source -- not
        # the real checkout's -- so the hook's top-level platform.sh load
        # resolves against the SAME fake REPO_ROOT tree as the fake
        # llm-client.sh/real memory.sh this class deliberately substitutes.
        full_env["CLAGENTIC_LITE_HOME"] = self._tmp
        full_env.pop("GIT_DIR", None)
        full_env.pop("GIT_WORK_TREE", None)
        # Autosummarize threshold low enough that the 40000-byte fixture
        # output crosses it deterministically.
        full_env["CLAGENTIC_AUTOSUMMARIZE_BYTES"] = "100"
        if env:
            full_env.update(env)
        return subprocess.run(
            ["/bin/sh", _HOOK],
            input=json.dumps(payload).encode(),
            capture_output=True,
            env=full_env,
            cwd=self._tmp,
        )

    def test_degraded_chain_writes_no_digest_row(self):
        self._write_fake_llm_client(degraded=True)
        self._write_real_memory_sh()
        output = "x" * 40000
        self._run({"session_id": "sess-auto-degraded", "tool_name": "Bash", "output": output})
        conn = sqlite3.connect(self._memory_db)
        try:
            rows = conn.execute("SELECT summary FROM turns;").fetchall()
        except sqlite3.OperationalError:
            rows = []
        conn.close()
        self.assertEqual(
            rows, [],
            f"a genuinely degraded summarizer chain must not write ANY row "
            f"to memory.db's turns table. rows={rows!r}",
        )

    def test_degraded_chain_does_not_surface_fabricated_digest_to_user(self):
        self._write_fake_llm_client(degraded=True)
        self._write_real_memory_sh()
        output = "x" * 40000
        result = self._run({"session_id": "sess-auto-degraded-2", "tool_name": "Bash", "output": output})
        self.assertEqual(result.returncode, 0)
        stdout = result.stdout.decode()
        self.assertNotIn(
            "CLAGENTIC AUTOSUMMARIZE", stdout,
            f"a degraded chain must not surface a fabricated digest hint "
            f"via additionalContext. stdout={stdout!r}",
        )

    def test_clean_chain_writes_digest_row_and_surfaces_hint(self):
        """Negative control: a real, successful summarizer response must
        still be written and surfaced -- proves the degraded check does
        not simply suppress the whole feature."""
        self._write_fake_llm_client(degraded=False)
        self._write_real_memory_sh()
        output = "x" * 40000
        result = self._run({"session_id": "sess-auto-clean", "tool_name": "Bash", "output": output})
        stdout = result.stdout.decode()
        self.assertIn("CLAGENTIC AUTOSUMMARIZE", stdout, f"stdout={stdout!r}")
        conn = sqlite3.connect(self._memory_db)
        rows = conn.execute("SELECT summary FROM turns;").fetchall()
        conn.close()
        self.assertEqual(len(rows), 1, f"rows={rows!r}")
        self.assertIn("a real digest", rows[0][0])


if __name__ == "__main__":
    unittest.main()
