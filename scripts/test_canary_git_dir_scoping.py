"""
Regression test for lr-dfd45f: _gitleaks_positive_control (scripts/gates.sh)
inherits GIT_DIR (and, when set, GIT_WORK_TREE / GIT_INDEX_FILE and related
GIT_* vars) from its caller's environment.

MECHANISM: when gates.sh runs as a git pre-commit hook, git exports GIT_DIR
pointing at the REAL repo under commit (GIT_WORK_TREE is implied from cwd in
the common case, not separately exported). The canary subshell in
_gitleaks_positive_control does `cd "$_gpc_dir"` and then runs `git
init`/`git add`/`git commit` to build a scratch repo seeded with synthetic,
detectable fake credentials -- but the exported GIT_DIR overrides `cd` for
every git invocation regardless, so the canary's `git add canary.env` /
`git commit -m "canary fixture"` silently operated on the CALLER's real
index/HEAD instead of the scratch dir: staging a fake-credential file into
real history and replacing the caller's own commit message.

This test builds a throwaway "real" repo with a staged file and a known
HEAD, exports GIT_DIR at it exactly the way git sets it for a hook
invocation (GIT_DIR only -- see _run_positive_control's docstring for why an
explicit GIT_WORK_TREE would mask the defect instead of reproducing it),
then runs _gitleaks_positive_control against a SEPARATE scratch dir and
asserts the "real" repo's HEAD, index, and commit message are all untouched,
and that canary.env was never added to it.

CONFIRMED TO FAIL PRE-FIX: reverting the `unset GIT_DIR GIT_WORK_TREE
GIT_INDEX_FILE ...` line added in scripts/gates.sh's
_gitleaks_positive_control (immediately after `cd "$_gpc_dir" || exit 1`)
reproduces the exact corruption this test asserts against -- the "real"
repo's HEAD moves to a new "canary fixture" commit containing canary.env.

Run with: python3 -m unittest scripts.test_canary_git_dir_scoping -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _gitleaks_available():
    return shutil.which("gitleaks") is not None


def _run(cmd, cwd=None, env=None, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=env, timeout=30)
    if check:
        assert r.returncode == 0, f"{cmd} failed: {r.stderr}"
    return r


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestCanaryDoesNotLeakIntoCallersGitDir(unittest.TestCase):
    """_gitleaks_positive_control must build/commit its scratch canary repo
    even when GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE point at an unrelated
    real repo, exactly as git exports them for a hook invocation."""

    def setUp(self):
        self._real_repo = tempfile.mkdtemp(prefix="clagentic-test-real-repo-")
        env = {**os.environ, **_GIT_ENV}
        _run(["git", "init", "-q", "-b", "main", self._real_repo], env=env)

        # Real, pre-existing tracked file + commit -- the caller's actual
        # history this test asserts stays untouched.
        with open(os.path.join(self._real_repo, "app.py"), "w") as f:
            f.write("def handle(x):\n    return x\n")
        _run(["git", "add", "app.py"], cwd=self._real_repo, env=env)
        _run(["git", "commit", "-q", "-m", "seed real history"], cwd=self._real_repo, env=env)
        self._real_head_before = _run(
            ["git", "rev-parse", "HEAD"], cwd=self._real_repo, env=env
        ).stdout.strip()

        # A second, staged-but-uncommitted file -- mirrors the caller's
        # real in-progress commit at hook time. Must survive untouched too.
        with open(os.path.join(self._real_repo, "staged.py"), "w") as f:
            f.write("x = 1\n")
        _run(["git", "add", "staged.py"], cwd=self._real_repo, env=env)
        self._real_index_before = _run(
            ["git", "ls-files", "--stage"], cwd=self._real_repo, env=env
        ).stdout

        self._scratch_parent = tempfile.mkdtemp(prefix="clagentic-test-canary-scratch-")

    def tearDown(self):
        shutil.rmtree(self._real_repo, ignore_errors=True)
        shutil.rmtree(self._scratch_parent, ignore_errors=True)

    def _run_positive_control(self):
        """Invoke _gitleaks_positive_control with GIT_DIR exported at the
        "real" repo, exactly as git actually sets it for a hook invocation:
        GIT_DIR only (absolute, ".../real_repo/.git"), with NO
        GIT_WORK_TREE/GIT_INDEX_FILE exported alongside it -- git implies
        the work tree from cwd when only GIT_DIR is set, which is precisely
        why the canary subshell's `cd "$_gpc_dir"` alone cannot protect it.

        Deliberately NOT also setting GIT_WORK_TREE/GIT_INDEX_FILE here:
        confirmed by direct reproduction against the pre-fix code that
        adding an explicit GIT_WORK_TREE makes git's own pathspec
        resolution refuse `git add canary.env` (rc=128, since canary.env
        lives outside that work tree) -- a safe, git-side failure that
        would make this test pass for the wrong reason and mask the actual
        reported defect. GIT_DIR-only is both the realistic hook shape and
        the shape that reproduces real corruption pre-fix."""
        env = os.environ.copy()
        env.update(source_env(gates=True))
        env.update(_GIT_ENV)
        env["GIT_DIR"] = os.path.join(self._real_repo, ".git")
        # cwd deliberately NOT the real repo -- mirrors the reported
        # mechanism, where the exported GIT_DIR alone (not cwd) is what
        # redirects the canary's git calls.
        script = f". '{GATES_SH}'\n_gitleaks_positive_control ''\n"
        return subprocess.run(
            ["sh", "-c", script, GATES_SH],
            capture_output=True, text=True, env=env,
            cwd=self._scratch_parent, timeout=120,
        )

    def test_real_repo_head_is_unchanged(self):
        self._run_positive_control()
        env = {**os.environ, **_GIT_ENV}
        head_after = _run(
            ["git", "rev-parse", "HEAD"], cwd=self._real_repo, env=env
        ).stdout.strip()
        self.assertEqual(
            self._real_head_before, head_after,
            msg="real repo's HEAD moved -- canary committed into caller's history",
        )

    def test_real_repo_commit_message_is_unchanged(self):
        self._run_positive_control()
        env = {**os.environ, **_GIT_ENV}
        subject = _run(
            ["git", "log", "-1", "--format=%s"], cwd=self._real_repo, env=env
        ).stdout.strip()
        self.assertEqual(subject, "seed real history")
        self.assertNotEqual(subject, "canary fixture")

    def test_real_repo_index_is_unchanged(self):
        self._run_positive_control()
        env = {**os.environ, **_GIT_ENV}
        index_after = _run(
            ["git", "ls-files", "--stage"], cwd=self._real_repo, env=env
        ).stdout
        self.assertEqual(
            self._real_index_before, index_after,
            msg="real repo's index changed -- canary staged into caller's index",
        )

    def test_canary_env_is_not_added_to_the_real_repo(self):
        self._run_positive_control()
        env = {**os.environ, **_GIT_ENV}
        tracked = _run(
            ["git", "ls-files"], cwd=self._real_repo, env=env
        ).stdout.splitlines()
        self.assertNotIn("canary.env", tracked)

    def test_positive_control_still_functions_against_its_own_scratch_dir(self):
        """Not just "nothing bad happened" -- the canary must still do its
        actual job (detect the planted fixtures) once correctly scoped,
        proving this isn't a fix that merely broke the canary instead of
        scoping it."""
        r = self._run_positive_control()
        self.assertEqual(r.returncode, 0, r.stderr)
        count_str, rule_ids = r.stdout.rstrip("\n").split("\t")
        self.assertGreaterEqual(int(count_str), 1)
        self.assertNotEqual(rule_ids, "")


if __name__ == "__main__":
    unittest.main()
