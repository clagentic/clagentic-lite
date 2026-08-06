"""
Regression tests for `clagentic-lite update`'s non-tty dirty-tree handling
(lr-dbf7f2).

BACKGROUND: cmd_update's non-tty branch ran `git stash push` immediately
followed by `git stash drop` against $CLAGENTIC_LITE_HOME whenever it found
uncommitted changes there -- unconditionally, with only a warning to stderr.
`git stash drop` is not recoverable through any normal git command. This
silently and irrecoverably destroyed uncommitted work in the real dev
checkout twice during a single session (PR #146's build), because a test
pointed CLAGENTIC_LITE_HOME at the live tree while exercising the non-tty
`update` path.

DIAGNOSIS (see PR body / task lr-dbf7f2 for full detail): the auto-discard
was INTENTIONAL, introduced in 4dd3210 ("fix(lr-32ef): plugin install guard,
stash prompt, robust version-bump commit", 2026-06-03) -- the commit message
explicitly states "Non-tty path warns and proceeds (CI-safe)". It was
reasoned about for CI/scripts, where a dirty CLAGENTIC_LITE_HOME is presumed
to be tool-internal noise (e.g. an uncommitted plugin.json version bump),
never a misdirected pointer at a real, human-owned checkout. That
presumption does not hold for every non-tty invocation (agent dispatch,
cron, a misconfigured env) -- and the blast radius of being wrong is
irrecoverable.

FIX: non-tty with a dirty CLAGENTIC_LITE_HOME now REFUSES by default (fail-
closed, `die`, nonzero exit) and requires an explicit opt-in --
--force-discard or CLAGENTIC_UPDATE_FORCE_DISCARD=1 -- to proceed with the
irrecoverable discard, with the exact dirty files loudly listed either way.
The interactive (tty) confirm-then-discard path is unchanged -- a human
typing "y" at a live prompt is informed consent, not the hazard this task
closes.

ENVIRONMENT HAZARD (mandatory, doubly so here -- this file's whole subject
is a code path that destroys the tree it points at): every test below
points CLAGENTIC_LITE_HOME at a throwaway `git clone` of the real checkout
under tempfile.mkdtemp(), NEVER at the real dev checkout itself, and forces
HOME + pops CLAGENTIC_HOME rather than inheriting any ambient value -- same
discipline as scripts/test_enroll_reenroll_no_force.py and
scripts/test_router_settings_stamp.py's TestRouterSettingsStampRestamp.

Run with: python3 -m unittest scripts/test_update_nontty_discard_refused.py -v
"""
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestUpdateNonTtyDirtyTreeHandling(unittest.TestCase):
    """All cases run update non-interactively (stdin closed, i.e. not a tty)
    against a throwaway clone of the real checkout with a dirty working tree,
    never against TOOL_HOME itself."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-update-nontty-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)

        # Throwaway clone of the real checkout -- cmd_update's git pull/stash
        # logic runs against THIS, never against TOOL_HOME.
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        subprocess.run(["git", "clone", "-q", TOOL_HOME, self.fake_tool_home],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", self.fake_tool_home, "config", "user.email", "test@example.com"],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", self.fake_tool_home, "config", "user.name", "Test"],
                        check=True, capture_output=True)

        # Dirty the clone's working tree -- this is the "uncommitted work"
        # under test. Modify a tracked file so `git diff` sees it.
        self.dirtied_file = os.path.join(self.fake_tool_home, "README.md")
        with open(self.dirtied_file, "a") as f:
            f.write("\n<!-- uncommitted test marker lr-dbf7f2 -->\n")

    def _run_cli(self, argv, env_extra=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env.pop("CLAGENTIC_HOME", None)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite")] + argv,
            cwd=self.fake_tool_home,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            stdin=subprocess.DEVNULL,  # non-tty: closed stdin, [ -t 0 ] is false
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _dirty_file_survives(self):
        with open(self.dirtied_file) as f:
            return "uncommitted test marker lr-dbf7f2" in f.read()

    def test_nontty_dirty_tree_refused_by_default(self):
        rc, out, err = self._run_cli(["update"])
        self.assertNotEqual(
            rc, 0,
            msg=f"non-tty update with a dirty CLAGENTIC_LITE_HOME must refuse "
                f"by default: stdout={out!r} stderr={err!r}",
        )
        self.assertIn("refused", err, msg=err)
        self.assertIn("README.md", err, msg="refusal must name the dirty file(s): %s" % err)
        self.assertTrue(
            self._dirty_file_survives(),
            "uncommitted change was destroyed despite the default-refuse contract",
        )

    def test_nontty_dirty_tree_refused_mentions_opt_in(self):
        rc, out, err = self._run_cli(["update"])
        self.assertNotEqual(rc, 0)
        self.assertIn("--force-discard", err, msg=err)
        self.assertIn("CLAGENTIC_UPDATE_FORCE_DISCARD", err, msg=err)

    def test_nontty_dirty_tree_proceeds_with_force_discard_flag(self):
        rc, out, err = self._run_cli(["update", "--force-discard"])
        # The dirty file must be gone (discarded via stash+drop) regardless
        # of whether the rest of update succeeds (pull/plugin steps may fail
        # in this sandboxed clone for unrelated reasons -- the property under
        # test is specifically that the opt-in path actually discards).
        self.assertFalse(
            self._dirty_file_survives(),
            "explicit --force-discard opt-in did not discard the dirty file",
        )
        self.assertIn("--force-discard", err, msg="opt-in path must loudly warn: %s" % err)
        self.assertIn("README.md", err, msg="opt-in warning must name the dirty file(s): %s" % err)

    def test_nontty_dirty_tree_proceeds_with_env_opt_in(self):
        rc, out, err = self._run_cli(["update"], env_extra={"CLAGENTIC_UPDATE_FORCE_DISCARD": "1"})
        self.assertFalse(
            self._dirty_file_survives(),
            "explicit CLAGENTIC_UPDATE_FORCE_DISCARD=1 opt-in did not discard the dirty file",
        )
        self.assertIn("CLAGENTIC_UPDATE_FORCE_DISCARD", err, msg=err)

    def test_nontty_clean_tree_unaffected_by_refusal(self):
        """Sanity check: the refusal is dirty-tree-gated, not a blanket
        non-tty refusal -- a clean CLAGENTIC_LITE_HOME must not hit the
        refuse path at all."""
        subprocess.run(["git", "-C", self.fake_tool_home, "checkout", "--", "README.md"],
                        check=True, capture_output=True)
        rc, out, err = self._run_cli(["update"])
        self.assertNotIn("refused", err, msg=err)
        self.assertNotIn("uncommitted changes", err, msg=err)


if __name__ == "__main__":
    unittest.main()
