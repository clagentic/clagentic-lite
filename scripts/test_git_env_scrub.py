"""
The test process carries no git-redirecting variables, so a fixture's bare
`git init`/`commit` lands in its own temp repository even when the suite is run
from a git hook.

Run with: python3 -m unittest scripts.test_git_env_scrub -v
"""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import findings_test_support  # noqa: E402,F401  (scrubs on import, as every fixture user does)
from git_env_scrub import redirecting_git_vars, scrub_git_env  # noqa: E402

HOOK_ENV = {
    "GIT_DIR": "/nonexistent-git-dir",
    "GIT_INDEX_FILE": "/nonexistent-index",
    "GIT_WORK_TREE": "/nonexistent-tree",
    "GIT_PREFIX": "sub/",
}


class TestScrub(unittest.TestCase):
    def test_removes_redirecting_variables_and_keeps_identity(self):
        environ = dict(HOOK_ENV, GIT_AUTHOR_NAME="a", GIT_COMMITTER_EMAIL="c@example.com",
                       PATH="/bin")
        removed = scrub_git_env(environ)
        self.assertEqual(removed, sorted(HOOK_ENV))
        self.assertEqual(sorted(environ), ["GIT_AUTHOR_NAME", "GIT_COMMITTER_EMAIL", "PATH"])

    def test_the_test_process_itself_is_scrubbed(self):
        # conftest.py (pytest) or findings_test_support (unittest) ran first.
        self.assertEqual(redirecting_git_vars(), [])

    def test_a_bare_git_init_lands_in_its_own_directory_after_the_scrub(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, HOOK_ENV):
            scrub_git_env()
            subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)
            self.assertTrue(os.path.isdir(os.path.join(tmp, ".git")))


if __name__ == "__main__":
    unittest.main()
