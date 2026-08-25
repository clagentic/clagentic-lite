"""
Regression tests for lr-778f43: stop-summarize.sh.template and
post-tool-nudge.sh.template resolved their scripts/llm-client.sh and
scripts/memory.sh calls off REPO_ROOT (the enrolled repo's cwd) instead of
CLAGENTIC_LITE_HOME (the install dir). Enrolled repos never receive their
own copy of scripts/ -- only the ONE materialized copy under
CLAGENTIC_LITE_HOME/.claude/hooks/ and CLAGENTIC_LITE_HOME/scripts/ exists
(bin/clagentic-lite's _stamp_claude_hooks; share/hook-shims/claude-
settings.template wires every hook `command` to
__CLAGENTIC_LITE_HOME__/.claude/hooks/*.sh by absolute path). So on any
enrolled repo that is not itself the clagentic-lite checkout, the
REPO_ROOT-scoped calls silently failed and session memory never populated.

THE BLIND SPOT THIS CLOSES: every prior hook test in this repo
(test_stop_summarize_degraded.py, test_context_budget.py) sets
CLAGENTIC_LITE_HOME equal to the same directory the hook treats as its
REPO_ROOT (either the real checkout itself, or one fixture dir serving
double duty as both). That makes CLAGENTIC_LITE_HOME-scoped and
REPO_ROOT-scoped resolution indistinguishable -- both paths resolve to the
same tree, so a REPO_ROOT-scoped defect is invisible. This file uses TWO
SEPARATE directories: a fake install dir (CLAGENTIC_LITE_HOME, holding
scripts/llm-client.sh + scripts/memory.sh + scripts/platform.sh) and a
separate fixture git repo (the enrolled repo, REPO_ROOT, holding only
.clagentic/lite/). If the hook ever regresses to a REPO_ROOT-scoped call,
"$REPO_ROOT/scripts/llm-client.sh" does not exist in this fixture and the
call fails closed -- exactly the real-world enrolled-repo failure mode.

Mirrors the throwaway-fixture discipline used throughout this suite
(test_stop_summarize_degraded.py, test_context_budget.py): no test here
ever runs cmd_init/cmd_enroll/cmd_update, and CLAGENTIC_LITE_HOME/HOME never
resolve to the live checkout -- both hook shim templates are run directly
via subprocess against synthetic fixture directories built with shutil,
never a `git clone`/live-tree pointer.

Run with: python3 -m unittest scripts.test_hook_shims_install_dir_scoped -v
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
STOP_HOOK = os.path.join(TOOL_HOME, "share", "hook-shims", "stop-summarize.sh.template")
NUDGE_HOOK = os.path.join(TOOL_HOME, "share", "hook-shims", "post-tool-nudge.sh.template")


def _write_fake_llm_client(scripts_dir, digest_text="a real summary from the fixture install dir"):
    path = os.path.join(scripts_dir, "llm-client.sh")
    body = (
        "#!/bin/sh\n"
        "cat > /dev/null\n"
        f"printf '%s' '{digest_text}'\n"
        "exit 0\n"
    )
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)


def _make_fake_install_dir(root):
    """A fake CLAGENTIC_LITE_HOME: real platform.sh + real memory.sh (so
    log-turn's own chokepoint guard and schema init are exercised for
    real), plus a stub llm-client.sh. Deliberately NOT a git clone of the
    live checkout -- a synthetic directory built with shutil, same
    discipline as test_claude_hooks_materialization.py's
    _make_fake_checkout."""
    scripts_dir = os.path.join(root, "scripts")
    os.makedirs(scripts_dir)
    for fname in ("memory.sh", "platform.sh"):
        shutil.copy(os.path.join(TOOL_HOME, "scripts", fname), scripts_dir)
        os.chmod(os.path.join(scripts_dir, fname), 0o755)
    _write_fake_llm_client(scripts_dir)
    return scripts_dir


def _init_scratch_repo(repo_dir):
    subprocess.run(["git", "init", "-q", repo_dir], check=True)
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    subprocess.run(["git", "-C", repo_dir, "config", "user.email", "test@example.com"],
                    check=True, env=env)
    subprocess.run(["git", "-C", repo_dir, "config", "user.name", "test"], check=True, env=env)
    return env


def _make_audit_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE gate_runs "
        "(ts TEXT, gate TEXT, outcome TEXT, details TEXT, session_id TEXT);"
    )
    conn.commit()
    conn.close()


def _poll_until(predicate, timeout_s=5, interval_s=0.05):
    deadline = time.time() + timeout_s
    result = predicate()
    while not result and time.time() < deadline:
        time.sleep(interval_s)
        result = predicate()
    return result


class TestStopHookWritesMemoryInEnrolledRepoDistinctFromInstallDir(unittest.TestCase):
    """The acceptance criterion: a fixture ENROLLED repo, separate from
    CLAGENTIC_LITE_HOME, must end up with a real row in its own
    memory.db after the Stop hook runs -- proving the hook resolves
    scripts/llm-client.sh and scripts/memory.sh against the install dir,
    not the enrolled repo's own (nonexistent) scripts/ directory."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-hookscope-")
        self.addCleanup(shutil.rmtree, self._tmpdir, ignore_errors=True)

        # Install dir: separate from the enrolled repo. Holds the only
        # scripts/llm-client.sh and scripts/memory.sh in this fixture.
        self._install_dir = os.path.join(self._tmpdir, "install-dir")
        os.makedirs(self._install_dir)
        _make_fake_install_dir(self._install_dir)

        # Enrolled repo: a plain git repo with NO scripts/ directory at
        # all -- the real-world shape of an enrolled repo that is not the
        # clagentic-lite checkout itself.
        self._repo = os.path.join(self._tmpdir, "enrolled-repo")
        os.makedirs(self._repo)
        self._git_env = _init_scratch_repo(self._repo)
        self.assertFalse(
            os.path.isdir(os.path.join(self._repo, "scripts")),
            "fixture enrolled repo must have no scripts/ dir -- a "
            "REPO_ROOT-scoped call has nothing to fall back on here",
        )

        self._clagentic_dir = os.path.join(self._repo, ".clagentic", "lite")
        os.makedirs(self._clagentic_dir)
        self._audit_db = os.path.join(self._clagentic_dir, "audit.db")
        _make_audit_db(self._audit_db)
        self._memory_db = os.path.join(self._clagentic_dir, "memory.db")

        self._transcript = os.path.join(self._tmpdir, "transcript.jsonl")
        with open(self._transcript, "w") as f:
            f.write(json.dumps({"role": "assistant", "content": "the assistant's last turn"}) + "\n")

    def _audit_rows(self, session_id):
        conn = sqlite3.connect(self._audit_db)
        rows = conn.execute(
            "SELECT gate, outcome, details FROM gate_runs WHERE session_id=?;",
            (session_id,),
        ).fetchall()
        conn.close()
        return rows

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

    def test_stop_hook_writes_a_row_to_the_enrolled_repos_memory_db(self):
        session_id = "sess-install-scope-1"
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
        # The defect under test: CLAGENTIC_LITE_HOME (install dir) is a
        # DIFFERENT directory than cwd/REPO_ROOT (enrolled repo).
        env["CLAGENTIC_LITE_HOME"] = self._install_dir
        env.pop("GIT_DIR", None)
        env.pop("GIT_WORK_TREE", None)

        subprocess.run(
            ["sh", STOP_HOOK],
            input=json.dumps(payload).encode(),
            capture_output=True,
            env=env,
            cwd=self._repo,
        )
        _poll_until(lambda: len(self._audit_rows(session_id)) > 0)

        rows = self._turns_rows()
        self.assertEqual(
            len(rows), 1,
            f"Stop hook must write exactly one row to the ENROLLED repo's "
            f"own memory.db when CLAGENTIC_LITE_HOME differs from "
            f"REPO_ROOT -- this is the exact case a same-directory fixture "
            f"can never catch. rows={rows!r}",
        )
        self.assertIn("a real summary from the fixture install dir", rows[0][0])

        outcomes = [r[1] for r in self._audit_rows(session_id) if r[0] == "summarize"]
        self.assertIn("pass", outcomes)

    def test_stop_hook_surfaces_memory_write_failure_instead_of_swallowing_it(self):
        """The failure-observability half of the acceptance criteria: when
        memory.sh log-turn genuinely fails, that failure must be visible
        (stderr + audit 'skip'), not hidden behind an always-true guard."""
        # Replace the real memory.sh with one that always fails, so this
        # test exercises the hook's OWN failure-handling path deterministically
        # rather than depending on memory.sh's internal failure modes.
        broken_memory_sh = os.path.join(self._install_dir, "scripts", "memory.sh")
        with open(broken_memory_sh, "w") as f:
            f.write("#!/bin/sh\necho 'synthetic failure for lr-778f43 test' 1>&2\nexit 1\n")
        os.chmod(broken_memory_sh, 0o755)

        session_id = "sess-install-scope-fail"
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
        env["CLAGENTIC_LITE_HOME"] = self._install_dir
        env.pop("GIT_DIR", None)
        env.pop("GIT_WORK_TREE", None)

        subprocess.run(
            ["sh", STOP_HOOK],
            input=json.dumps(payload).encode(),
            capture_output=True,
            env=env,
            cwd=self._repo,
        )
        _poll_until(lambda: len(self._audit_rows(session_id)) > 0)

        rows = self._turns_rows()
        self.assertEqual(rows, [], f"a failed memory write must not appear as a row. rows={rows!r}")

        outcomes = self._audit_rows(session_id)
        summarize_outcomes = [r[1] for r in outcomes if r[0] == "summarize"]
        self.assertIn(
            "skip", summarize_outcomes,
            f"a genuine memory.sh log-turn failure must be logged as 'skip', "
            f"not silently absent from the audit trail. rows={outcomes!r}",
        )
        self.assertNotIn(
            "pass", summarize_outcomes,
            f"a failed write must never be logged as 'pass'. rows={outcomes!r}",
        )


class TestPostToolNudgeAutosummarizeWritesMemoryInEnrolledRepo(unittest.TestCase):
    """Same acceptance criterion, for the autosummarize path
    (post-tool-nudge.sh.template) -- the other of the four sites this task
    fixes."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-nudgescope-")
        self.addCleanup(shutil.rmtree, self._tmpdir, ignore_errors=True)

        self._install_dir = os.path.join(self._tmpdir, "install-dir")
        os.makedirs(self._install_dir)
        _make_fake_install_dir(self._install_dir)

        self._repo = os.path.join(self._tmpdir, "enrolled-repo")
        os.makedirs(self._repo)
        subprocess.run(["git", "init", "-q", self._repo], check=True)
        self.assertFalse(os.path.isdir(os.path.join(self._repo, "scripts")))

        self._clagentic_dir = os.path.join(self._repo, ".clagentic", "lite")
        os.makedirs(self._clagentic_dir)
        self._audit_db = os.path.join(self._clagentic_dir, "audit.db")
        _make_audit_db(self._audit_db)
        self._memory_db = os.path.join(self._clagentic_dir, "memory.db")

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

    def test_autosummarize_writes_a_row_to_the_enrolled_repos_memory_db(self):
        env = dict(os.environ)
        env["CLAGENTIC_ENV_LOADED"] = "1"
        env["HOME"] = os.environ.get("HOME", "/root")
        env["CLAGENTIC_LITE_HOME"] = self._install_dir
        env["CLAGENTIC_AUTOSUMMARIZE_BYTES"] = "100"
        env.pop("GIT_DIR", None)
        env.pop("GIT_WORK_TREE", None)

        payload = {"session_id": "sess-nudge-scope-1", "tool_name": "Bash", "output": "x" * 40000}
        result = subprocess.run(
            ["/bin/sh", NUDGE_HOOK],
            input=json.dumps(payload).encode(),
            capture_output=True,
            env=env,
            cwd=self._repo,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr.decode())
        stdout = result.stdout.decode()
        self.assertIn(
            "CLAGENTIC AUTOSUMMARIZE", stdout,
            f"autosummarize must fire when CLAGENTIC_LITE_HOME differs from "
            f"the enrolled repo's own (nonexistent) scripts/ dir. stdout={stdout!r}",
        )

        rows = self._turns_rows()
        self.assertEqual(len(rows), 1, f"rows={rows!r}")
        self.assertIn("a real summary from the fixture install dir", rows[0][0])


if __name__ == "__main__":
    unittest.main()
