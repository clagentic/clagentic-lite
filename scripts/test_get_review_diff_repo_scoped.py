"""
Regression test for get_review_diff's REPO_ROOT scoping (lr-da1f28 sweep,
follow-up to lr-4a3f88).

lr-4a3f88 found and fixed one bare-git call site (gates.sh:1988, the
--recheck SHA-staleness guard) that bypassed the repo-scoped `_git` helper.
lr-da1f28 is the sweep across the rest of scripts/ for the same bug class.
That sweep found that USING `_git` is not automatically sufficient either:
`_git` is `git -C "$REPO_ROOT"`, and `-C <dir>` only changes cwd before
git's own ancestor-directory repo discovery runs -- so `_git diff`, `_git
rev-parse --abbrev-ref HEAD`, etc. still walk up the filesystem from
REPO_ROOT looking for a `.git` directory when REPO_ROOT itself is not a git
repo (the wrapper/.clagentic-project layout, ds_repo_root in platform.sh,
permits exactly this).

get_review_diff (gates.sh) is the worst instance of this in the codebase:
if REPO_ROOT is not a git repo but an ancestor of it is, `_git diff --cached`
and `_git rev-parse --abbrev-ref HEAD` would silently return the ANCESTOR
repo's staged diff / branch name instead of empty/REPO_ROOT's -- feeding the
review and adversarial gates a diff belonging to an entirely unrelated repo,
worse than merely mis-stamping a SHA.

The fix adds a _git_repo_root_is_scoped guard at the top of get_review_diff
that short-circuits to the documented "no staged changes" empty-diff
fallback when REPO_ROOT is not the git repo `_git` would actually resolve
to. This test proves that guard is in effect: it creates a real git repo
with staged changes as the *parent* of a non-git REPO_ROOT and asserts
get_review_diff returns empty rather than the ancestor's staged diff.

Run with:
  python3 -m unittest scripts/test_get_review_diff_repo_scoped.py -v
"""
import os
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")
REVIEW_MERGE_SH = os.path.join(TOOL_HOME, "scripts", "review-merge.sh")


def _functions_only_source(dest_dir):
    """Copy gates.sh up to (not including) the subcommand dispatch block,
    so its functions can be sourced and called directly without running
    the whole CLI. Same technique as
    test_review_findings_forged_field_stripped.py's _functions_only_source.
    """
    with open(GATES_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in gates.sh"
    dest = os.path.join(dest_dir, "gates.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    for src in (PLATFORM_SH, REVIEW_MERGE_SH):
        os.symlink(src, os.path.join(dest_dir, os.path.basename(src)))
    return dest


def _init_git_repo_with_staged_change(repo_dir):
    """Initialize a git repo at repo_dir with one committed file, then stage
    a modification to it -- so `git diff --cached` there is non-empty."""
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"

    subprocess.run(["git", "init", "-q", repo_dir], check=True, env=env)
    tracked = os.path.join(repo_dir, "tracked.txt")
    with open(tracked, "w") as f:
        f.write("original\n")
    subprocess.run(["git", "add", "tracked.txt"], check=True, cwd=repo_dir, env=env)
    subprocess.run(
        ["git", "commit", "-q", "-m", "initial"], check=True, cwd=repo_dir, env=env
    )
    with open(tracked, "w") as f:
        f.write("modified -- this must never appear in a different repo's diff\n")
    subprocess.run(["git", "add", "tracked.txt"], check=True, cwd=repo_dir, env=env)


def _call_get_review_diff(repo_root, cwd):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-grd-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{sourced_gates}'
            get_review_diff
        """)
        env = os.environ.copy()
        # CLAGENTIC_PROJECT_ROOT, not a pre-set REPO_ROOT var: the truncated
        # gates.sh re-derives REPO_ROOT itself at source time (gates.sh:39-43)
        # and would otherwise clobber a directly-assigned REPO_ROOT with
        # ds_repo_root()'s own resolution from cwd.
        env["CLAGENTIC_PROJECT_ROOT"] = repo_root
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True,
            text=True,
            cwd=cwd,
            env=env,
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestGetReviewDiffRepoScoped(unittest.TestCase):
    """get_review_diff must not fall back to an ancestor repo's diff/branch
    state when REPO_ROOT itself is not a git repo."""

    def setUp(self):
        self._parent = tempfile.mkdtemp(prefix="clagentic-test-grd-parent-")
        # REPO_ROOT: a non-git directory that is a child of a real git repo
        # with a staged change -- the exact shape ds_repo_root's
        # wrapper/.clagentic-project fallback can legitimately produce (a
        # REPO_ROOT that is not itself a git repo), except here the "trap"
        # is that walking further up from it *does* find a real `.git`.
        self._non_git_root = os.path.join(self._parent, "nogit-project-root")
        os.makedirs(self._non_git_root)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._parent, ignore_errors=True)

    def test_does_not_leak_ancestor_repos_staged_diff(self):
        _init_git_repo_with_staged_change(self._parent)

        self.assertFalse(
            os.path.isdir(os.path.join(self._non_git_root, ".git")),
            "REPO_ROOT must not itself be a git repo for this test",
        )

        stdout, stderr, rc = _call_get_review_diff(
            self._non_git_root, cwd=self._non_git_root
        )

        self.assertEqual(
            rc, 0,
            f"get_review_diff must exit 0 on the empty-diff fallback path; "
            f"stdout: {stdout}\nstderr: {stderr}",
        )
        self.assertEqual(
            stdout.strip(), "",
            "get_review_diff must not print the ancestor repo's staged diff "
            "when REPO_ROOT is not itself a git repo",
        )
        self.assertNotIn(
            "modified -- this must never appear", stdout,
            "get_review_diff leaked the ancestor repo's staged content",
        )
        self.assertIn(
            "REPO_ROOT is not a git repo", stderr,
            f"expected the not-a-git-repo diagnostic on stderr; stderr: {stderr}",
        )

    def test_still_returns_staged_diff_when_repo_root_is_the_git_repo(self):
        """Control case: when REPO_ROOT IS the git repo (no ancestor trap),
        get_review_diff must still return the real staged diff -- proving
        the new guard doesn't over-fire and break the normal path."""
        _init_git_repo_with_staged_change(self._non_git_root)

        stdout, stderr, rc = _call_get_review_diff(
            self._non_git_root, cwd=self._non_git_root
        )

        self.assertEqual(
            rc, 0,
            f"get_review_diff must exit 0; stdout: {stdout}\nstderr: {stderr}",
        )
        self.assertIn(
            "modified -- this must never appear", stdout,
            f"get_review_diff must return the real staged diff when REPO_ROOT "
            f"is the actual git repo; stdout: {stdout}\nstderr: {stderr}",
        )
        self.assertIn("using staged diff", stderr)


if __name__ == "__main__":
    unittest.main()
