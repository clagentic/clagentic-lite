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

Parametrizes GIT_DIR as both an ABSOLUTE path and a RELATIVE path (".git").

POSITIVE-EVIDENCE REQUIREMENT (PEACHES, PR #209 review, finding 2): the
original version of this file asserted ONLY that the real repo is
untouched -- it could not distinguish "the canary ran and was correctly
isolated" from "the canary never ran at all" (gitleaks missing, an early
return, a sourcing failure). A gate that silently never reaches the canary
would pass those assertions vacuously, which is exactly backwards for a bug
class that is itself about silent fail-open. Every test method here now
also asserts (a) the subprocess's own exit code, and (b) POSITIVE stderr
evidence the canary actually ran and reported success
("positive-control canary OK", the exact string `cmd_secrets` prints on
the canary's own success path, scripts/gates.sh) -- not merely that the
real repo happens to be unchanged.

REALISTIC-CWD CORRECTION (PEACHES, PR #209 review, finding 2): the
relative-GIT_DIR case previously ran with cwd=scratch while claiming to
model a real hook invocation -- but a real hook always runs with cwd at the
REPO ROOT (the repo under commit), which is where a relative GIT_DIR=".git"
actually resolves in practice. That case now sets cwd to the real repo
itself, matching the genuine hook shape; the absolute-GIT_DIR case keeps
cwd=scratch (an absolute GIT_DIR is location-independent by construction,
so cwd choice there is not part of what's under test).

test_absolute_git_dir_does_not_corrupt_real_repo is confirmed to FAIL
pre-fix (reverting ds_git_env_scrub's body to a no-op reproduces real
corruption -- the real repo's HEAD moves). test_relative_git_dir_does_not_
corrupt_real_repo, once corrected to the realistic cwd=repo-root shape
above, does NOT independently reproduce corruption pre-fix: with cwd
already at the real repo, a relative GIT_DIR=".git" re-resolves against the
canary's OWN `cd "$_gpc_dir"` before ds_git_env_scrub would run, landing on
"$_gpc_dir/.git" -- a location inside the scratch dir itself, not the real
repo -- so this specific relative+repo-root-cwd combination is not the
vector that corrupts (verified directly by disabling ds_git_env_scrub and
re-running: the real repo's HEAD does not move in this case, only in the
absolute case). It is kept as a test anyway because it is still the
realistic hook shape and still exercises the full gates.sh secrets path
end-to-end with a POSITIVE assertion that the canary actually ran and
passed -- a regression that broke isolation via THIS path would still be
caught by the corruption assertions, even though this particular pre-fix
baseline happens not to trip them.

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

# The exact string cmd_secrets (scripts/gates.sh) prints to stderr on the
# canary's own success path -- positive evidence the canary actually ran
# and passed, not merely that the real repo happens to be unchanged (which
# a gate that never reached the canary at all would also satisfy).
_CANARY_SUCCESS_MARKER = "positive-control canary OK"


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
    pre-commit hook invokes it, must never touch the caller's real repo --
    and must actually run the canary while doing so, not merely pass
    vacuously because it never got there."""

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

        # gates.sh unconditionally mkdir -p's REPO_ROOT/.clagentic/lite/ for
        # its own audit db, regardless of this bug -- a real, legitimate,
        # unrelated side effect of running gates.sh at all with cwd=the
        # real repo (only exercised by the relative-GIT_DIR case, whose cwd
        # is the real repo root to match a genuine hook invocation).
        # Filtered out here so this assertion stays meaningful for anything
        # ELSE that changes, rather than papering over a real corruption by
        # widening the comparison.
        status_lines_before = [
            ln for ln in self._status_before.splitlines() if ".clagentic/" not in ln
        ]
        status_after_raw = _run(["git", "status", "--porcelain"], cwd=self._real_repo, env=env).stdout
        status_lines_after = [
            ln for ln in status_after_raw.splitlines() if ".clagentic/" not in ln
        ]
        self.assertEqual(status_lines_before, status_lines_after, "real repo status changed")

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

    def _assert_canary_actually_ran_and_passed(self, result):
        """Positive evidence the canary executed and reached the isolated
        path, not merely that the real repo happens to be unchanged (which
        a gate that never got to the canary at all -- gitleaks missing, an
        early return, a sourcing failure -- would also satisfy)."""
        self.assertEqual(
            result.returncode, 0,
            msg=f"gates.sh secrets exited nonzero -- cannot trust the "
                f"real-repo-untouched assertions below to mean the canary "
                f"ran and was isolated, rather than never ran at all. "
                f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn(
            _CANARY_SUCCESS_MARKER, result.stderr,
            msg=f"gates.sh secrets exited 0 but never printed the canary's "
                f"own success marker -- the canary may not have run at all "
                f"(e.g. CLAGENTIC_SKIP_SECRETS_CANARY, an early return, or "
                f"a sourcing failure silently short-circuiting before the "
                f"canary). stderr={result.stderr!r}",
        )

    def test_absolute_git_dir_does_not_corrupt_real_repo(self):
        """Absolute GIT_DIR is location-independent by construction, so cwd
        choice is not part of what this case is exercising -- cwd=scratch,
        distinct from the real repo, models GIT_DIR alone doing the
        redirecting."""
        scratch = tempfile.mkdtemp(prefix="clagentic-test-hookenv-scratch-")
        try:
            result = self._run_gates_secrets(os.path.join(self._real_repo, ".git"), scratch)
            self._assert_canary_actually_ran_and_passed(result)
            self._assert_real_repo_untouched()
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def test_relative_git_dir_does_not_corrupt_real_repo(self):
        """A relative GIT_DIR (".git") is the shape git itself typically
        exports for a hook invocation -- and a real hook invocation always
        runs with cwd AT THE REPO ROOT (the repo under commit), which is
        where this actually resolves. cwd is therefore the real repo
        itself here, not an unrelated scratch dir -- the earlier version
        of this test ran with cwd=scratch, which is a different (and less
        realistic) failure mode than the one a real hook invocation
        produces."""
        result = self._run_gates_secrets(".git", self._real_repo)
        self._assert_canary_actually_ran_and_passed(result)
        self._assert_real_repo_untouched()


if __name__ == "__main__":
    unittest.main()
