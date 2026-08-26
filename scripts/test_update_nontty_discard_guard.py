"""
Regression tests for lr-55a27a: `clagentic-lite update`'s non-tty
uncommitted-changes handling used to warn and discard unconditionally via
`git stash push` + `git stash drop` against CLAGENTIC_LITE_HOME. That
sequence destroys working-tree content IRRECOVERABLY and leaves NO reflog
entry once the stash is dropped. Every automated invocation (CI, a script,
any crew-agent dispatch) is non-tty, so the interactive confirmation path
was never reached in practice -- the destructive branch was the only branch
an automated caller could take, and CLAGENTIC_LITE_HOME can be repointed at
a real dev checkout by the bootstrap block at the top of bin/clagentic-lite
whenever the binary is invoked by its own path.

Fix: the non-tty branch now REFUSES (nonzero exit, uncommitted changes
left untouched) unless CLAGENTIC_UPDATE_ALLOW_DISCARD=1 is explicitly set.

This file follows the existing HAZARD discipline documented in
test_enroll_reenroll_no_force.py and test_router_bedrock_settings_stamp.py:
any test exercising `update`'s discard path must point CLAGENTIC_LITE_HOME
at a throwaway git clone of the real checkout, never at the live dev
checkout itself. `_clone_tool_home` (scripts/test_support.py) also overlays
the checkout's current on-disk content over the clone, so an uncommitted
edit to the discard-guard logic in bin/clagentic-lite itself is never
invisible to these tests -- note this is orthogonal to the deliberate
in-test dirtying of README.md below (that dirty edit is fixture content for
the discard mechanism under test, made to the clone AFTER cloning, not a
staleness gap).

Run with: python3 -m unittest scripts.test_update_nontty_discard_guard -v
"""
import os
import shutil
import subprocess
import tempfile
import unittest

from scripts.test_support import clone_this_tool_home_with_overlay

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")
_clone_tool_home = clone_this_tool_home_with_overlay


def _run_update(fake_tool_home, home, extra_env=None):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = fake_tool_home
    env.pop("CLAGENTIC_HOME", None)
    env.pop("CLAGENTIC_UPDATE_ALLOW_DISCARD", None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [os.path.join(fake_tool_home, "bin", "clagentic-lite"), "update"],
        cwd=fake_tool_home,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,  # force non-tty stdin, the exact branch under test
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestUpdateNonTtyDiscardGuard(unittest.TestCase):
    """Given CLAGENTIC_LITE_HOME pointing at a git checkout with an origin
    remote and uncommitted changes, cmd_update's non-tty path must REFUSE
    by default and leave the uncommitted changes in place."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-update-discard-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)

        # Dirty the clone -- a real, tracked file edit, not merely a
        # new untracked file, so `git diff` (what cmd_update checks) sees it.
        self.dirty_file = os.path.join(self.fake_tool_home, "README.md")
        with open(self.dirty_file, "a") as f:
            f.write("\nlocal edit for lr-55a27a test\n")

    def _dirty_content(self):
        with open(self.dirty_file) as f:
            return f.read()

    def test_refuses_and_preserves_uncommitted_changes_by_default(self):
        before = self._dirty_content()
        rc, _out, err = _run_update(self.fake_tool_home, self.home)

        self.assertNotEqual(rc, 0, msg=f"expected refusal, got rc=0; stderr={err!r}")
        self.assertIn(self.fake_tool_home, err,
                      msg="refusal message must name the resolved CLAGENTIC_LITE_HOME path")
        self.assertIn("CLAGENTIC_UPDATE_ALLOW_DISCARD", err)

        after = self._dirty_content()
        self.assertEqual(before, after,
                          msg="uncommitted changes must survive a refused non-tty update")

        diff = subprocess.run(["git", "-C", self.fake_tool_home, "diff", "--name-only"],
                               capture_output=True, text=True, check=True)
        self.assertIn("README.md", diff.stdout,
                       msg="git diff must still show the uncommitted edit after refusal")

        stash_list = subprocess.run(["git", "-C", self.fake_tool_home, "stash", "list"],
                                     capture_output=True, text=True, check=True)
        self.assertEqual(stash_list.stdout.strip(), "",
                          msg="refusal must never stash (and drop) the uncommitted edit")

    def test_explicit_opt_in_proceeds_with_discard(self):
        """The other half of the contract: CLAGENTIC_UPDATE_ALLOW_DISCARD=1
        preserves the original unattended-update behavior for a genuinely
        disposable install dir."""
        rc, _out, err = _run_update(
            self.fake_tool_home, self.home,
            extra_env={"CLAGENTIC_UPDATE_ALLOW_DISCARD": "1"},
        )
        # The run may still fail later (e.g. `git pull --ff-only` against a
        # clone with no new upstream commits, or network-dependent prereq
        # checks) -- this test only asserts on the discard step itself, not
        # the overall exit code.
        self.assertIn("discarding uncommitted changes", err, msg=err)

        after = self._dirty_content()
        self.assertNotIn("local edit for lr-55a27a test", after,
                          msg="opt-in path must actually discard the uncommitted edit")


if __name__ == "__main__":
    unittest.main()
