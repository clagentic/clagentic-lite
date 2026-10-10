"""
The isolation fixture (scripts/isolated_env.py) really isolates, and no test
file reintroduces the pattern it replaces.

Run with: python3 -m unittest scripts.test_isolated_env -v
"""
import glob
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from isolated_env import (  # noqa: E402
    IsolatedEnv, points_at_live_checkout, shared_cli, shared_env, shared_home,
    shared_project, shared_tool_home)
from test_support import TOOL_HOME  # noqa: E402

AMBIENT = {
    "GIT_DIR": "/nonexistent-git-dir",
    "GIT_INDEX_FILE": "/nonexistent-index",
    "CLAGENTIC_PROJECT_ROOT": TOOL_HOME,
    "CLAGENTIC_LITE_HOME": TOOL_HOME,
    "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:1",
    "XDG_CONFIG_HOME": "/nonexistent-xdg",
}


class TestIsolatedEnv(unittest.TestCase):
    def test_env_points_all_three_locations_at_temp_dirs(self):
        iso = IsolatedEnv.for_test(self)
        with mock.patch.dict(os.environ, AMBIENT):
            env = iso.env()
        self.assertFalse(points_at_live_checkout(env))
        for key in ("HOME", "CLAGENTIC_PROJECT_ROOT", "CLAGENTIC_LITE_HOME"):
            self.assertTrue(env[key].startswith(iso.root), (key, env[key]))

    def test_env_drops_variables_that_redirect_git_or_the_tool(self):
        iso = IsolatedEnv.for_test(self)
        with mock.patch.dict(os.environ, AMBIENT):
            env = iso.env()
        for key in ("GIT_DIR", "GIT_INDEX_FILE", "CLAGENTIC_ROUTER_URL", "XDG_CONFIG_HOME"):
            self.assertNotIn(key, env)

    def test_extra_wins_and_project_can_be_replaced(self):
        iso = IsolatedEnv.for_test(self)
        env = iso.env(project="/elsewhere", CLAGENTIC_FOO="1")
        self.assertEqual(env["CLAGENTIC_PROJECT_ROOT"], "/elsewhere")
        self.assertEqual(env["CLAGENTIC_FOO"], "1")

    def test_project_is_a_git_repository(self):
        iso = IsolatedEnv.for_test(self)
        self.assertTrue(os.path.isdir(os.path.join(iso.project, ".git")))

    def test_cloned_tool_home_is_a_distinct_runnable_copy(self):
        iso = IsolatedEnv.for_test(self, clone_tool_home=True)
        self.assertTrue(os.access(iso.cli, os.X_OK), iso.cli)
        self.assertNotEqual(os.path.realpath(iso.tool_home), os.path.realpath(TOOL_HOME))

    def test_cleanup_removes_what_it_created(self):
        iso = IsolatedEnv()
        iso.cleanup()
        self.assertFalse(os.path.exists(iso.root))


class TestSharedEnv(unittest.TestCase):
    def test_shared_pair_is_not_the_live_checkout(self):
        with mock.patch.dict(os.environ, AMBIENT):
            env = shared_env(project=shared_project())
        self.assertFalse(points_at_live_checkout(env))
        self.assertEqual(env["HOME"], shared_home())
        self.assertEqual(env["CLAGENTIC_LITE_HOME"], shared_tool_home())
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("CLAGENTIC_ROUTER_URL", env)

    def test_project_root_is_left_unset_unless_given(self):
        with mock.patch.dict(os.environ, AMBIENT):
            self.assertNotIn("CLAGENTIC_PROJECT_ROOT", shared_env())

    def test_the_shared_cli_runs_from_the_clone_not_the_live_tree(self):
        self.assertTrue(shared_cli().startswith(shared_tool_home()))
        self.assertTrue(os.access(shared_cli(), os.X_OK))

    def test_shared_clone_carries_uncommitted_tracked_edits(self):
        # The overlay is what makes a test exercise the change under review.
        live = os.path.join(TOOL_HOME, "scripts", "gates.sh")
        copy = os.path.join(shared_tool_home(), "scripts", "gates.sh")
        with open(live) as a, open(copy) as b:
            self.assertEqual(a.read(), b.read())


class TestNoTestAimsTheCliAtTheLiveTree(unittest.TestCase):
    """Sweep: discovery is by glob, not a list. A test that hands the live
    checkout to the CLI as its tool home runs init/enroll/update/render against
    it (CLAUDE.local.md fact 2)."""

    PATTERNS = (
        re.compile(r"CLAGENTIC_LITE_HOME\"\]\s*=\s*_?TOOL_HOME\b"),
        re.compile(r"\"CLAGENTIC_LITE_HOME\"\s*:\s*_?TOOL_HOME\b"),
    )

    # A child run with the live checkout as its cwd resolves the project root,
    # the repository config it then sources, and audit.db from it. These files
    # use that cwd on purpose: read-only `git` history queries about this
    # repository, a file listing, and one test that asserts the tool is NOT
    # located through the working directory.
    LIVE_CWD = re.compile(r"cwd=(os\.path\.join\()?_?TOOL_HOME\b")
    LIVE_CWD_ALLOWED = {
        "test_findings_call_primitive.py",
        "test_llm_client_consumer_sweep.py",
        "test_secrets_positive_control.py",
    }

    def offenders(self, patterns, allowed=()):
        found = []
        for path in sorted(glob.glob(os.path.join(TOOL_HOME, "scripts", "test_*.py"))):
            if os.path.samefile(path, __file__) or os.path.basename(path) in allowed:
                continue
            with open(path) as handle:
                for number, line in enumerate(handle, 1):
                    if any(p.search(line) for p in patterns):
                        found.append("%s:%d: %s" % (os.path.relpath(path, TOOL_HOME), number,
                                                    line.strip()))
        return found

    def test_no_test_sets_the_tool_home_to_the_live_checkout(self):
        self.assertEqual(self.offenders(self.PATTERNS), [])

    def test_no_test_runs_a_child_with_the_live_checkout_as_its_cwd(self):
        self.assertEqual(self.offenders([self.LIVE_CWD], self.LIVE_CWD_ALLOWED), [])


if __name__ == "__main__":
    unittest.main()
