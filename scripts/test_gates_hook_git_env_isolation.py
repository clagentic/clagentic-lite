"""
Regression test (class guard) for lr-dfd45f: `gates.sh secrets`, run the way
a real git pre-commit hook actually invokes it, must never let an inherited
GIT_DIR (or any of the related GIT_* vars ds_git_env_scrub clears) redirect
the secrets gate's own git operations -- including the canary's scratch-repo
build -- into the caller's real repo.

BACKGROUND: git exports GIT_DIR (and, in some hook/worktree layouts,
GIT_WORK_TREE/GIT_INDEX_FILE) into the hook process's environment. VERIFIED
EMPIRICALLY (this task): an inherited GIT_DIR silently overrides an explicit
`git -C <dir> ...` -- not merely `cd`. The class fix is ds_git_env_scrub
(scripts/platform.sh), called once at gates.sh's own top level (after
REPO_ROOT is resolved) and again inside the secrets canary's scratch-repo
subshells (scripts/gates.sh, _gitleaks_positive_control).

This file is the CLASS guard: it drives the real `gates.sh secrets`
subcommand end-to-end (not just the internal canary function directly, see
scripts/test_canary_git_dir_scoping.py for that narrower guard) with GIT_DIR
exported exactly as git sets it for a hook, and asserts every observable
piece of the "real" repo's state is untouched afterward -- HEAD, commit
count, commit subject, staged file, `git status --porcelain`, AND the set of
loose objects under .git/objects (the assertion that fails if only the
reporter's original three vars -- GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE -- are
cleared but GIT_OBJECT_DIRECTORY is not: a scratch commit's blobs/trees/
commit object would land in the real repo's object store, unreferenced by
any real ref and invisible to `git log`, but present on disk and reachable
by a later full-history secret scan).

Parametrizes GIT_DIR as both an ABSOLUTE path and a RELATIVE path (".git")
-- a relative GIT_DIR combined with a `cd` into a different scratch
directory resolves against the NEW cwd, not the original one, which is a
different (and in some shapes worse, silently-repo-creating) failure mode
than the absolute case.

Both parametrized cases are confirmed to FAIL pre-fix (reverting
ds_git_env_scrub's body to a no-op reproduces real corruption in both).

Run with: python3 -m unittest scripts.test_gates_hook_git_env_isolation -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH  # noqa: E402

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


def _loose_objects(repo):
    """Every loose object path under .git/objects, excluding the pack/ and
    info/ housekeeping subdirs -- the set that grows when a NEW object
    (blob/tree/commit) is written, regardless of whether any ref reaches
    it."""
    objects_dir = os.path.join(repo, ".git", "objects")
    found = []
    for root, _dirs, files in os.walk(objects_dir):
        base = os.path.basename(root)
        if base in ("pack", "info"):
            continue
        for f in files:
            found.append(os.path.relpath(os.path.join(root, f), objects_dir))
    return sorted(found)


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestGatesSecretsHookGitEnvIsolation(unittest.TestCase):
    """`gates.sh secrets` end-to-end, driven exactly the way a real
    pre-commit hook invokes it, must never touch the caller's real repo."""

    def setUp(self):
        self._real_repo = tempfile.mkdtemp(prefix="clagentic-test-hookenv-real-")
        env = {**os.environ, **_GIT_ENV}
        _run(["git", "init", "-q", "-b", "main", self._real_repo], env=env)

        with open(os.path.join(self._real_repo, "app.py"), "w") as f:
            f.write("def handle(x):\n    return x\n")
        _run(["git", "add", "app.py"], cwd=self._real_repo, env=env)
        _run(["git", "commit", "-q", "-m", "seed real history"], cwd=self._real_repo, env=env)

        self._head_before = _run(
            ["git", "rev-parse", "HEAD"], cwd=self._real_repo, env=env
        ).stdout.strip()
        self._count_before = _run(
            ["git", "rev-list", "--count", "HEAD"], cwd=self._real_repo, env=env
        ).stdout.strip()

        # Stage a second file BEFORE snapshotting loose objects -- `git add`
        # itself writes the blob object immediately, so the object-set
        # snapshot must be taken after every deliberate setup write, or the
        # test would misattribute its own fixture-staging write to the
        # canary as a false positive.
        with open(os.path.join(self._real_repo, "staged.py"), "w") as f:
            f.write("x = 1\n")
        _run(["git", "add", "staged.py"], cwd=self._real_repo, env=env)
        self._status_before = _run(
            ["git", "status", "--porcelain"], cwd=self._real_repo, env=env
        ).stdout
        self._objects_before = _loose_objects(self._real_repo)

    def tearDown(self):
        shutil.rmtree(self._real_repo, ignore_errors=True)

    def _assert_real_repo_untouched(self):
        env = {**os.environ, **_GIT_ENV}
        head_after = _run(["git", "rev-parse", "HEAD"], cwd=self._real_repo, env=env).stdout.strip()
        self.assertEqual(self._head_before, head_after, "real repo HEAD moved")

        count_after = _run(
            ["git", "rev-list", "--count", "HEAD"], cwd=self._real_repo, env=env
        ).stdout.strip()
        self.assertEqual(self._count_before, count_after, "real repo commit count changed")

        subject = _run(
            ["git", "log", "-1", "--format=%s"], cwd=self._real_repo, env=env
        ).stdout.strip()
        self.assertNotEqual(subject, "canary fixture")

        status_after = _run(["git", "status", "--porcelain"], cwd=self._real_repo, env=env).stdout
        self.assertEqual(self._status_before, status_after, "real repo status changed")

        objects_after = _loose_objects(self._real_repo)
        self.assertEqual(
            self._objects_before, objects_after,
            msg="new loose objects appeared in the real repo's .git/objects -- "
                "a scratch commit's blobs/trees/commit object were written "
                "into the caller's real object store",
        )

    def _run_gates_secrets(self, git_dir_value, cwd):
        """Run `gates.sh secrets` with GIT_DIR exported exactly as git sets
        it for a hook -- GIT_DIR only, no GIT_WORK_TREE/GIT_INDEX_FILE (see
        scripts/test_canary_git_dir_scoping.py for why adding those masks
        the defect instead of reproducing it)."""
        env = os.environ.copy()
        env.update(_GIT_ENV)
        env["GIT_DIR"] = git_dir_value
        env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "0"
        return subprocess.run(
            [GATES_SH, "secrets"],
            capture_output=True, text=True, env=env, cwd=cwd, timeout=180,
        )

    def test_absolute_git_dir_does_not_corrupt_real_repo(self):
        scratch = tempfile.mkdtemp(prefix="clagentic-test-hookenv-scratch-")
        try:
            self._run_gates_secrets(os.path.join(self._real_repo, ".git"), scratch)
            self._assert_real_repo_untouched()
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def test_relative_git_dir_does_not_corrupt_real_repo(self):
        """A relative GIT_DIR (".git") is the shape git itself typically
        exports for a hook invocation, since the hook runs with cwd already
        at the repo root -- resolved relative to whatever cwd the canary's
        `cd "$_gpc_dir"` leaves it at, which is a DIFFERENT (and
        potentially repo-creating) failure mode than an absolute GIT_DIR."""
        scratch = tempfile.mkdtemp(prefix="clagentic-test-hookenv-scratch-rel-")
        try:
            self._run_gates_secrets(".git", scratch)
            self._assert_real_repo_untouched()
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
