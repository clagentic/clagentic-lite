"""
Regression tests for .claude/hooks/pre-write-guard.sh (lr-a218d8, rule W-006).

W-006 is a warn-only, non-blocking rule: when the PreToolUse(Write|Edit)
payload omits `agent_type`, the orchestrator (main Claude Code loop) — not a
dispatched subagent — is authoring code directly. The hook prints an
AGGRESSIVE nudge to stderr directing delegation to the clagentic-lite:builder
subagent, logs a warn row via ds_audit_log, and always exits 0. Subagent
calls (agent_type present) pass through untouched: no W-006 warning.

These tests invoke the ACTUAL hook script via subprocess (not a Python
mirror of its logic), piping realistic PreToolUse JSON payloads on stdin,
exactly as Claude Code does. A regression in the shell logic — the wrong
field name, an accidental `exit 2`, a warn that fires when agent_type is
present — would be caught here; a Python reimplementation would not catch it.

Run with: python3 -m unittest scripts/test_pre_write_guard_sh.py -v
"""
import json
import os
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.join(os.path.dirname(__file__), "..")
HOOK_SH = os.path.join(TOOL_HOME, ".claude", "hooks", "pre-write-guard.sh")


def _run_hook(payload, cwd, env_extra=None):
    """Run the real pre-write-guard.sh with `payload` (dict) piped as JSON
    on stdin, from `cwd` (a git repo on a non-default branch). Returns
    (returncode, stdout, stderr)."""
    env = dict(os.environ)
    env.pop("CLAGENTIC_ENV_LOADED", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["sh", HOOK_SH],
        input=json.dumps(payload),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _init_feature_branch_repo(tmpdir):
    """Create a throwaway git repo on a feature branch (not main) so W-001
    does not fire and mask the W-006 assertions under test."""
    subprocess.run(["git", "init", "-q", "-b", "main", tmpdir], check=True)
    subprocess.run(
        ["git", "-C", tmpdir, "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", tmpdir, "config", "user.name", "Test"], check=True
    )
    readme = os.path.join(tmpdir, "README.md")
    with open(readme, "w") as f:
        f.write("init\n")
    subprocess.run(["git", "-C", tmpdir, "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", tmpdir, "commit", "-q", "-m", "init"], check=True
    )
    subprocess.run(
        ["git", "-C", tmpdir, "checkout", "-q", "-b", "feat/test-branch"],
        check=True,
    )


class TestW006AgentTypeAbsent(unittest.TestCase):
    """(a) agent_type absent + Write -> warn on stderr, exit 0."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-pwg-")
        _init_feature_branch_repo(self.tmpdir)

    def test_warns_and_exits_zero_when_agent_type_absent(self):
        payload = {"file_path": os.path.join(self.tmpdir, "scratch.txt")}
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 0, msg=f"stderr: {stderr}")
        self.assertIn("W-006", stderr)
        self.assertIn("clagentic-lite:builder", stderr)

    def test_warns_when_agent_type_is_empty_string(self):
        # Explicit empty string is functionally absent for this signal.
        payload = {
            "file_path": os.path.join(self.tmpdir, "scratch.txt"),
            "agent_type": "",
        }
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 0, msg=f"stderr: {stderr}")
        self.assertIn("W-006", stderr)


class TestW006AgentTypePresent(unittest.TestCase):
    """(b) agent_type present + Write -> no W-006 warn."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-pwg-")
        _init_feature_branch_repo(self.tmpdir)

    def test_no_warn_when_agent_type_present_general_purpose(self):
        payload = {
            "file_path": os.path.join(self.tmpdir, "scratch.txt"),
            "agent_type": "general-purpose",
        }
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 0, msg=f"stderr: {stderr}")
        self.assertNotIn("W-006", stderr)

    def test_no_warn_when_agent_type_present_builder(self):
        payload = {
            "file_path": os.path.join(self.tmpdir, "scratch.txt"),
            "agent_type": "clagentic-lite:builder",
        }
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 0, msg=f"stderr: {stderr}")
        self.assertNotIn("W-006", stderr)


class TestExistingBlockRulesUnaffected(unittest.TestCase):
    """(c) existing W-001..W-005 blocks still exit 2 (or warn, for W-005)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-pwg-")
        _init_feature_branch_repo(self.tmpdir)

    def test_w001_still_blocks_default_branch_write(self):
        subprocess.run(
            ["git", "-C", self.tmpdir, "checkout", "-q", "main"], check=True
        )
        payload = {
            "file_path": os.path.join(self.tmpdir, "scratch.txt"),
            "agent_type": "clagentic-lite:builder",
        }
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 2, msg=f"stderr: {stderr}")
        self.assertIn("W-001", stderr)

    def test_w002_still_blocks_outside_repo(self):
        outside = tempfile.mkdtemp(prefix="clagentic-test-pwg-outside-")
        payload = {
            "file_path": os.path.join(outside, "escape.txt"),
            "agent_type": "clagentic-lite:builder",
        }
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 2, msg=f"stderr: {stderr}")
        self.assertIn("W-002", stderr)

    def test_w003_still_blocks_env_write(self):
        payload = {
            "file_path": os.path.join(self.tmpdir, ".env"),
            "agent_type": "clagentic-lite:builder",
        }
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 2, msg=f"stderr: {stderr}")
        self.assertIn("W-003", stderr)

    def test_w004_still_blocks_credential_shaped_file(self):
        payload = {
            "file_path": os.path.join(self.tmpdir, "id_rsa"),
            "agent_type": "clagentic-lite:builder",
        }
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 2, msg=f"stderr: {stderr}")
        self.assertIn("W-004", stderr)

    def test_w005_cache_warn_still_fires_alongside_w006(self):
        # No agent_type -> W-006 fires. Path also matches W-005. Both should
        # be present; neither should cause a non-zero exit (warn-only).
        payload = {"file_path": os.path.join(self.tmpdir, "CLAUDE.md")}
        rc, _stdout, stderr = _run_hook(payload, cwd=self.tmpdir)
        self.assertEqual(rc, 0, msg=f"stderr: {stderr}")
        self.assertIn("W-005", stderr)
        self.assertIn("W-006", stderr)


if __name__ == "__main__":
    unittest.main()
