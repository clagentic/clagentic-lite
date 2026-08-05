"""
Regression tests for lr-caebc5: merge-gate state-identity cache.

ROOT CAUSE: gate results carried no notion of which commit/tree state they
validated, only the mtimes of last-review.json/last-adversarial.md. Any
incidental mtime change -- a checkout, a stash, an editor save with no
content change, or simply re-running gates ship/gates merge-gate again in
the same session -- was indistinguishable from a real change, so
cmd_merge_gate re-ran (and re-prompted the operator) every time. The prior
fix (lr-23c2, --recheck SHA-staleness guard) addressed one symptom path but
left the underlying gap: the non---recheck path never checked whether it
had already reached a verdict for the current state at all.

The fix: cmd_merge_gate computes a state identity (<HEAD SHA>:<content
hash>) before doing any work. The content hash is sha256(git diff HEAD +
git status --porcelain) -- covers staged/unstaged tracked changes and
untracked files, never a file's mtime. Every merge-gate `pass` audit row is
stamped `[state=<identity>]`; a subsequent invocation whose state identity
matches a stored PASS is a no-op: it reports the cached pass and returns
without calling the LLM. A stored `refuse` never short-circuits -- only a
pass is cacheable.

Acceptance criteria under test:
  1. Run to a pass; re-run with zero content changes -> zero re-prompts
     (LLM not invoked a second time), cached pass reported.
  2. An mtime-only touch (no content change) does not invalidate the cache.
  3. A real content change (dirty tree) is NOT a no-op -- it re-runs for
     real and calls the LLM again.
  4. A dirty-tree state is itself cacheable -- re-running again on the same
     dirty (uncommitted) state is a no-op, same as a clean-tree state.
  5. A cached REFUSE is never treated as a no-op -- every invocation after a
     refuse re-runs until a real pass is recorded.

Run with: python3 -m unittest scripts.test_merge_gate_state_cache -v
"""
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _make_fake_llm_client(tmpdir, decision="approve", reason="test"):
    """Write a stub llm-client.sh that records each invocation to
    llm_calls.txt (one line per call) and echoes a fixed JSON response.
    """
    scripts_dir = os.path.join(tmpdir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    calls_file = os.path.join(tmpdir, "llm_calls.txt")
    payload = json.dumps({"decision": decision, "reason": reason})
    with open(stub, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            # stub llm-client.sh -- records a call and returns a fixed decision
            echo called >> {calls_file}
            printf '%s\\n' '{payload}'
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return calls_file


def _setup_fake_tool_home(fake_tool_home):
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
    for fname in os.listdir(real_scripts_dir):
        if not fname.endswith(".sh"):
            continue
        if fname == "llm-client.sh":
            continue
        src = os.path.join(real_scripts_dir, fname)
        dst = os.path.join(scripts_dir, fname)
        if not os.path.exists(dst):
            os.symlink(src, dst)
    real_share = os.path.join(TOOL_HOME, "share")
    fake_share = os.path.join(fake_tool_home, "share")
    if not os.path.exists(fake_share) and os.path.isdir(real_share):
        os.symlink(real_share, fake_share)


def _setup_project(tmpdir):
    clagentic_dir = os.path.join(tmpdir, ".clagentic", "lite")
    os.makedirs(clagentic_dir, exist_ok=True)
    db_path = os.path.join(clagentic_dir, "audit.db")
    conn = sqlite3.connect(db_path)
    conn.execute(textwrap.dedent("""\
        CREATE TABLE IF NOT EXISTS gate_runs (
          id         INTEGER PRIMARY KEY,
          ts         TEXT NOT NULL,
          gate       TEXT NOT NULL,
          outcome    TEXT NOT NULL,
          details    TEXT,
          session_id TEXT,
          branch     TEXT
        )
    """))
    conn.commit()
    conn.close()
    return tmpdir


def _init_git_repo(project_root):
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    subprocess.run(["git", "init", "-q", project_root], check=True, env=env)
    with open(os.path.join(project_root, "f.txt"), "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "f.txt"], check=True, env=env, cwd=project_root)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, env=env, cwd=project_root)


def _run_merge_gate(fake_tool_home, project_root, extra_args=None):
    _setup_fake_tool_home(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    env["CLAGENTIC_MERGE_GATE_BLOCKING"] = "1"
    # Skip the build_gate_summary SHA-stamp staleness check -- these tests
    # exercise the state-identity cache directly, not that separate mechanism.
    env["CLAGENTIC_ALLOW_STALE_PAYLOAD"] = "1"
    cmd = ["sh", fake_gates, "merge-gate"] + (extra_args or [])
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=project_root)


def _call_count(calls_file):
    if not os.path.exists(calls_file):
        return 0
    with open(calls_file) as f:
        return f.read().count("called")


class TestMergeGateStateCache(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-sc-")
        self._project = _setup_project(self._tmpdir)
        _init_git_repo(self._project)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------ 1/2
    def test_rerun_on_unchanged_state_is_a_noop_and_mtime_touch_does_not_invalidate(self):
        calls_file = _make_fake_llm_client(self._tmpdir)

        r1 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r1.returncode, 0,
                         f"first run should pass\nstdout={r1.stdout}\nstderr={r1.stderr}")
        self.assertEqual(_call_count(calls_file), 1, "first run must call the LLM exactly once")

        r2 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r2.returncode, 0,
                         f"re-run on unchanged state should still pass\nstdout={r2.stdout}\nstderr={r2.stderr}")
        self.assertEqual(_call_count(calls_file), 1,
                         "re-run on unchanged state must NOT call the LLM again -- this is the "
                         "acceptance criterion: zero re-prompts on an unchanged state")
        self.assertIn("already passed for this exact commit+content state", r2.stderr)

        # mtime bump only (touch), no content change: still a cache hit.
        os.utime(os.path.join(self._project, "f.txt"), None)
        r3 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r3.returncode, 0)
        self.assertEqual(_call_count(calls_file), 1,
                         "an mtime-only touch must not invalidate the cached pass -- mtime is "
                         "never an input to state-identity validity")

    # -------------------------------------------------------------------- 3
    def test_content_change_forces_a_real_rerun(self):
        calls_file = _make_fake_llm_client(self._tmpdir)

        r1 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r1.returncode, 0)
        self.assertEqual(_call_count(calls_file), 1)

        with open(os.path.join(self._project, "f.txt"), "w") as f:
            f.write("hello world\n")

        r2 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r2.returncode, 0,
                         f"changed-content run should pass\nstdout={r2.stdout}\nstderr={r2.stderr}")
        self.assertEqual(_call_count(calls_file), 2,
                         "a real content change must trigger a fresh LLM call, not a cache hit")

    # -------------------------------------------------------------------- 4
    def test_dirty_tree_state_is_itself_cacheable(self):
        """A dirty working tree is the normal state while iterating, not an
        edge case -- re-running on the same dirty state must also be a
        no-op, exactly like a clean-tree state.
        """
        calls_file = _make_fake_llm_client(self._tmpdir)

        with open(os.path.join(self._project, "f.txt"), "w") as f:
            f.write("dirty content, never committed\n")

        r1 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r1.returncode, 0,
                         f"first run on dirty tree should pass\nstdout={r1.stdout}\nstderr={r1.stderr}")
        self.assertEqual(_call_count(calls_file), 1)

        r2 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r2.returncode, 0)
        self.assertEqual(_call_count(calls_file), 1,
                         "re-run on the same dirty (uncommitted) state must be a no-op -- a "
                         "dirty tree is representable state, not an always-fresh edge case")

    # -------------------------------------------------------------------- 5
    def test_cached_refuse_never_short_circuits(self):
        """Only a stored PASS is cacheable. A refuse must never be treated
        as a no-op -- every invocation after a refusal re-runs until a real
        pass is recorded, so a real problem can never be silently bypassed
        by invoking merge-gate again.
        """
        calls_file = _make_fake_llm_client(self._tmpdir, decision="refuse", reason="blocking finding")

        r1 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r1.returncode, 1, f"refuse should exit 1\nstdout={r1.stdout}\nstderr={r1.stderr}")
        self.assertEqual(_call_count(calls_file), 1)

        r2 = _run_merge_gate(self._tmpdir, self._project)
        self.assertEqual(r2.returncode, 1,
                         "a re-run after a refuse, with no content change, must re-run for real "
                         "and refuse again -- a refuse is never cached as a silent pass")
        self.assertEqual(_call_count(calls_file), 2,
                         "a cached refuse must never short-circuit the LLM call -- only a pass "
                         "is cacheable")


if __name__ == "__main__":
    unittest.main()
