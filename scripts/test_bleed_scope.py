"""
Regression tests for lr-caebc5: cmd_bleed change-scoping.

cmd_bleed (scripts/gates.sh) used to run `git ls-files` against the whole
repo on EVERY invocation -- every tracked file, every run, with no relation
to what changed. Its sibling gates already scope to the change under
review: cmd_secrets uses `git diff --cached --name-only` (staged) or a
branch-history scan; cmd_sast resolves a merge-base baseline; the merge-gate
uses a staged/branch diff for its own bootstrap-exemption detection. Bleed
was the outlier -- a one-line change anywhere re-scanned the entire
codebase.

The fix scopes cmd_bleed to the same fallback ladder cmd_secrets already
uses: staged diff first, then branch diff against the default branch, then
full tree. Full tree stays reachable (a fresh repo, no usable baseline, an
explicit --full-scan, or a pattern-file change) but is no longer the
default path.

These tests exercise the file-set resolution directly by pointing a bleed
pattern at a marker string, planting it in both a staged (in-scope) file and
an untouched (out-of-scope) tracked file, and asserting which one the gate
actually catches.

Run with: python3 -m unittest scripts.test_bleed_scope -v
"""
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REAL_SCRIPTS_DIR = os.path.join(TOOL_HOME, "scripts")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

_MARKER = "INTERNAL-BLEED-MARKER-4f1c9e"


def _run_cmd_bleed(project_root, extra_args=None, extra_env=None):
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    if extra_env:
        env.update(extra_env)
    gates_sh = os.path.join(REAL_SCRIPTS_DIR, "gates.sh")
    cmd = ["sh", gates_sh, "bleed"] + (extra_args or [])
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=project_root)


def _write_pattern_file(project_root):
    clagentic_dir = os.path.join(project_root, ".clagentic")
    os.makedirs(clagentic_dir, exist_ok=True)
    with open(os.path.join(clagentic_dir, "bleed-patterns"), "w") as f:
        f.write(_MARKER + "\n")


class TestBleedScopedToChangedFiles(unittest.TestCase):
    """A branch diff (no staged changes) should scan only files the branch
    actually touched -- an untouched tracked file containing the marker must
    NOT block, only the branch-changed file should.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-bleed-")
        origin = os.path.join(self._tmp, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", origin], check=True)

        self._work = os.path.join(self._tmp, "work")
        subprocess.run(["git", "clone", "-q", origin, self._work], check=True)
        env = {**os.environ, **_GIT_ENV}

        # Untouched file, present on main, never modified by the feature
        # branch -- carries the marker from before this feature existed.
        # A full-tree scan would have caught this; a scoped scan must not.
        untouched = os.path.join(self._work, "legacy.txt")
        with open(untouched, "w") as f:
            f.write(_MARKER + "\n")
        subprocess.run(["git", "add", "legacy.txt"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial (pre-existing bleed)"],
                        check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        clean = os.path.join(self._work, "new_feature.txt")
        with open(clean, "w") as f:
            f.write("nothing sensitive here\n")
        subprocess.run(["git", "add", "new_feature.txt"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "feature commit, no bleed"],
                        check=True, cwd=self._work, env=env)

        _write_pattern_file(self._work)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_branch_diff_scope_does_not_flag_pre_existing_untouched_file(self):
        result = _run_cmd_bleed(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 0,
                         f"scoped scan must not block on a pre-existing bleed hit outside the "
                         f"branch diff\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("branch diff", result.stderr)

    def test_branch_diff_scope_still_catches_a_hit_in_the_actual_diff(self):
        # Add a bleed hit INSIDE the branch's own diff -- this must still
        # block; scoping narrows what's scanned, never what's caught within
        # that scope.
        env = {**os.environ, **_GIT_ENV}
        dirty = os.path.join(self._work, "new_feature.txt")
        with open(dirty, "a") as f:
            f.write(_MARKER + "\n")
        subprocess.run(["git", "add", "new_feature.txt"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "introduces a real bleed hit"],
                        check=True, cwd=self._work, env=env)

        result = _run_cmd_bleed(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"a bleed hit inside the branch's own diff must still block\n"
                         f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("new_feature.txt", result.stderr)

    def test_full_scan_flag_catches_the_pre_existing_hit(self):
        result = _run_cmd_bleed(self._work, extra_args=["--full-scan"],
                                extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"--full-scan must still reach the pre-existing untouched hit\n"
                         f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("legacy.txt", result.stderr)


class TestBleedStagedScope(unittest.TestCase):
    """A staged diff takes priority over a branch diff, matching cmd_secrets."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-bleed-staged-")
        origin = os.path.join(self._tmp, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
        self._work = os.path.join(self._tmp, "work")
        subprocess.run(["git", "clone", "-q", origin, self._work], check=True)
        env = {**os.environ, **_GIT_ENV}

        readme = os.path.join(self._work, "README")
        with open(readme, "w") as f:
            f.write("hello\n")
        subprocess.run(["git", "add", "README"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=self._work, env=env)
        _write_pattern_file(self._work)
        subprocess.run(["git", "add", ".clagentic/bleed-patterns"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "add bleed patterns"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)

        # A tracked-but-not-staged file with the marker, committed to the
        # branch (so it IS part of the branch diff -- proving staged-scope
        # priority requires it to be reachable by the branch-diff fallback,
        # so we only test the case where it is genuinely NOT staged right
        # now while a real staged change exists alongside it).
        other = os.path.join(self._work, "other.txt")
        with open(other, "w") as f:
            f.write(_MARKER + "\n")
        subprocess.run(["git", "add", "other.txt"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "branch commit with marker, not staged now"],
                        check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_staged_file_with_marker_blocks_scoped_to_staged_diff_only(self):
        staged = os.path.join(self._work, "staged.txt")
        with open(staged, "w") as f:
            f.write("clean content, no marker\n")
        subprocess.run(["git", "add", "staged.txt"], check=True, cwd=self._work,
                        env={**os.environ, **_GIT_ENV})

        # Nothing staged carries the marker -- other.txt (which does) is
        # committed, not staged. Staged-diff scope must win over the branch
        # diff (which WOULD catch other.txt), matching cmd_secrets'
        # priority order: staged first, branch diff only when staged is
        # empty.
        result = _run_cmd_bleed(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 0,
                         f"staged-diff scope must not reach other.txt (committed, not staged) "
                         f"even though it carries the marker\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("staged diff", result.stderr)

    def test_no_staged_changes_falls_back_to_branch_diff_and_catches_it(self):
        # Nothing staged now -- falls back to branch diff, which DOES
        # include other.txt (committed on the feature branch).
        result = _run_cmd_bleed(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"with nothing staged, branch-diff scope must catch a marker committed "
                         f"on the branch\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("other.txt", result.stderr)
        self.assertIn("branch diff", result.stderr)


class TestBleedPatternFileChangeForcesFullScan(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-bleed-patchange-")
        origin = os.path.join(self._tmp, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
        self._work = os.path.join(self._tmp, "work")
        subprocess.run(["git", "clone", "-q", origin, self._work], check=True)
        env = {**os.environ, **_GIT_ENV}

        legacy = os.path.join(self._work, "legacy.txt")
        with open(legacy, "w") as f:
            f.write(_MARKER + "\n")
        subprocess.run(["git", "add", "legacy.txt"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_staged_pattern_file_change_forces_full_scan(self):
        _write_pattern_file(self._work)
        env = {**os.environ, **_GIT_ENV}
        subprocess.run(["git", "add", ".clagentic/bleed-patterns"], check=True, cwd=self._work, env=env)

        result = _run_cmd_bleed(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"a staged pattern-file change must force a full scan and catch the "
                         f"pre-existing hit\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("legacy.txt", result.stderr)
        self.assertIn("pattern file changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
