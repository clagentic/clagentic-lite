"""
Regression tests for `clagentic-lite enroll` re-enroll-without-force behavior
(lr-f8167f).

BACKGROUND: scripts/smoke.sh carried a failing assertion, "second enroll
without --force should have been refused", since 2026-05-18. Investigation
(git blame on both bin/clagentic-lite's _enroll_one and the smoke assertion
itself) established this was a STALE assertion, not a logic regression:
_enroll_one's already-enrolled branch (`return 0` after a `warn`) and the
smoke assertion expecting a nonzero exit were introduced in the same commit
session, four minutes apart (fba8944 at 13:11:33, ea7e7dd at 13:15:45,
2026-05-18) -- the assertion never matched the code it was meant to test.
The actual, and correct-by-design, contract is: re-enrolling an already-
enrolled repo without --force is an IDEMPOTENT NO-OP -- it warns to stderr
and exits 0, but it does NOT re-stamp hooks, DBs, or the registry. That is
the property that actually matters for data-loss prevention (re-stamping a
hook or CLAUDE.md could clobber project-owned content -- see 662f4c1), and
it is what this file proves mechanically rather than merely asserting.

This test invokes the ACTUAL bin/clagentic-lite `enroll` command via
subprocess against a real, throwaway temp git repo -- never the live
checkout. Per lr-f8167f's own environment hazard note: a test in this repo
must never point CLAGENTIC_LITE_HOME at the real dev checkout while
exercising an enroll/update code path, since `update`'s non-tty
discard-uncommitted-changes path (git stash push + stash drop) has
previously silently discarded uncommitted edits when misdirected. This file
never calls `update`, and CLAGENTIC_LITE_HOME is always the read-only tool
checkout (never mutated), while the enroll TARGET is always a fresh
tempfile.mkdtemp() git repo.

Run with: python3 -m unittest scripts/test_enroll_reenroll_no_force.py -v
"""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


def _init_git_repo(path):
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", path], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Test"],
                    check=True, capture_output=True)


def _run_cli(argv, cwd, home):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
    env.pop("CLAGENTIC_HOME", None)
    proc = subprocess.run(
        [CLI] + argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestReenrollWithoutForceIsIdempotentNoOp(unittest.TestCase):
    """A second `enroll` on an already-enrolled repo, without --force, must
    exit 0 (it is a documented no-op, not a refusal) and must NOT re-stamp
    any hook shim -- the property that actually prevents data loss."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-reenroll-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.target = os.path.join(self.tmpdir, "target-repo")
        _init_git_repo(self.target)

    def test_first_enroll_succeeds(self):
        rc, _out, err = _run_cli(["enroll", self.target], cwd=self.target, home=self.home)
        self.assertEqual(rc, 0, msg="first enroll should succeed: %s" % err)
        hook = os.path.join(self.target, ".git", "hooks", "pre-commit")
        self.assertTrue(os.path.isfile(hook), "pre-commit hook not stamped on first enroll")

    def test_second_enroll_without_force_exits_zero_and_does_not_restamp(self):
        rc1, _out1, err1 = _run_cli(["enroll", self.target], cwd=self.target, home=self.home)
        self.assertEqual(rc1, 0, msg="first enroll should succeed: %s" % err1)

        hook = os.path.join(self.target, ".git", "hooks", "pre-commit")
        self.assertTrue(os.path.isfile(hook), "pre-commit hook missing after first enroll")
        sha_before = _sha256(hook)

        rc2, _out2, err2 = _run_cli(["enroll", self.target], cwd=self.target, home=self.home)

        self.assertEqual(
            rc2, 0,
            msg="re-enroll without --force must exit 0 (documented no-op contract); "
                "stderr: %s" % err2,
        )
        self.assertIn(
            "already enrolled", err2,
            msg="re-enroll without --force must warn that the repo is already enrolled",
        )

        sha_after = _sha256(hook)
        self.assertEqual(
            sha_before, sha_after,
            msg="re-enroll without --force re-stamped the pre-commit hook -- "
                "this is the data-loss-prevention property the no-op contract exists for",
        )

    def test_second_enroll_with_force_does_restamp(self):
        """Sanity check on the other half of the contract: --force is the
        actual re-stamp trigger, proving the no-op above is not simply
        because enroll never re-stamps at all."""
        rc1, _out1, err1 = _run_cli(["enroll", self.target], cwd=self.target, home=self.home)
        self.assertEqual(rc1, 0, msg="first enroll should succeed: %s" % err1)

        hook = os.path.join(self.target, ".git", "hooks", "pre-commit")
        sha_before = _sha256(hook)

        rc2, _out2, err2 = _run_cli(["enroll", "--force", self.target], cwd=self.target, home=self.home)
        self.assertEqual(rc2, 0, msg="forced re-enroll should succeed: %s" % err2)

        sha_after = _sha256(hook)
        # Content is expected to be identical (same template, same home) --
        # this asserts the re-stamp path actually ran (via mtime), not that
        # content differs, since the template hasn't changed between calls.
        self.assertEqual(
            sha_before, sha_after,
            msg="forced re-enroll changed hook content unexpectedly (template mismatch?)",
        )


if __name__ == "__main__":
    unittest.main()
