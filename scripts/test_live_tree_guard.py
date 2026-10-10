"""
The suite-level guard (scripts/live_tree_guard.py) fires when a test writes
under the guarded directories, stays silent when none does, and names the test
that wrote.

The proof that it fires runs a nested pytest session in a throwaway project
whose conftest wires the same fixtures the real suite uses
(make_guard_fixtures) at a throwaway "live checkout": only a real session shows
that a session-teardown failure is reported and not swallowed.

Run with: python3 -m unittest scripts.test_live_tree_guard -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import live_tree_guard as guard  # noqa: E402
from findings_test_support import clean_env  # noqa: E402

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


def write(path, text="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)


class TestSnapshotAndChanges(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="clagentic-test-guard-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_a_new_file_is_created_and_a_rewritten_one_is_modified(self):
        write(os.path.join(self.root, ".clagentic", "keep.txt"), "a")
        before = guard.snapshot(self.root)
        write(os.path.join(self.root, ".clagentic", "keep.txt"), "bb")
        write(os.path.join(self.root, ".claude", "hooks", "new.sh"))
        found = dict(guard.changes(before, guard.snapshot(self.root)))
        self.assertEqual(found[os.path.join(self.root, ".clagentic", "keep.txt")], "modified")
        self.assertEqual(found[os.path.join(self.root, ".claude", "hooks", "new.sh")], "created")

    def test_ignored_and_untracked_files_are_seen_because_the_walk_is_not_git(self):
        before = guard.snapshot(self.root)
        write(os.path.join(self.root, ".clagentic", "rendered-plugin", "agents", "a.md"))
        paths = [p for p, _ in guard.changes(before, guard.snapshot(self.root))]
        self.assertIn(os.path.join(self.root, ".clagentic", "rendered-plugin", "agents", "a.md"), paths)

    def test_an_untouched_tree_and_a_deletion_report_nothing(self):
        victim = os.path.join(self.root, ".clagentic", "old.txt")
        write(victim)
        before = guard.snapshot(self.root)
        self.assertEqual(guard.changes(before, guard.snapshot(self.root)), [])
        os.remove(victim)
        self.assertEqual(guard.changes(before, guard.snapshot(self.root)), [])

    def test_paths_outside_the_guarded_directories_are_ignored(self):
        before = guard.snapshot(self.root)
        write(os.path.join(self.root, "elsewhere", "x.txt"))
        self.assertEqual(guard.changes(before, guard.snapshot(self.root)), [])

    def test_attribution_picks_the_window_holding_the_mtime(self):
        target = os.path.join(self.root, ".clagentic", "w.txt")
        start = time.time_ns()
        write(target)
        end = time.time_ns()
        after = guard.snapshot(self.root)
        windows = [(start - 10**12, start - 10**11, "tests::early"), (start, end, "tests::writer")]
        self.assertEqual(guard.attribute(after, target, windows), ["tests::writer"])
        self.assertEqual(guard.attribute(after, target, windows[:1]), [])


class TestTheFixtureFailsTheRun(unittest.TestCase):
    CONFTEST = textwrap.dedent("""\
        import sys
        sys.path.insert(0, %(scripts)r)
        from live_tree_guard import make_guard_fixtures
        live_tree_guard, live_tree_window = make_guard_fixtures(root=%(live)r)
        """)

    def run_session(self, test_body, seed=None):
        tmp = tempfile.mkdtemp(prefix="clagentic-test-guard-session-")
        self.addCleanup(shutil.rmtree, tmp, True)
        live = os.path.join(tmp, "live")
        os.makedirs(os.path.join(live, ".clagentic"))
        if seed:
            write(os.path.join(live, ".clagentic", seed), "seed")
        project = os.path.join(tmp, "nested")
        os.makedirs(project)
        write(os.path.join(project, "conftest.py"),
              self.CONFTEST % {"scripts": SCRIPTS_DIR, "live": live})
        write(os.path.join(project, "test_nested.py"),
              "import os\nLIVE = %r\n%s" % (live, textwrap.dedent(test_body)))
        env = clean_env()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--rootdir", project,
             project],
            capture_output=True, text=True, env=env, cwd=project, timeout=120)
        return proc.returncode, proc.stdout + proc.stderr

    def test_a_test_that_writes_into_the_live_tree_fails_the_run_and_is_named(self):
        rc, out = self.run_session("""\
            import time

            def test_innocent():
                assert True

            def test_writes_into_the_live_tree():
                time.sleep(0.1)  # keep the write clear of the neighbouring window
                with open(os.path.join(LIVE, ".clagentic", "litter.txt"), "w") as handle:
                    handle.write("x")
            """)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("created: .clagentic/litter.txt", out)
        self.assertIn("written during: test_nested.py::test_writes_into_the_live_tree", out)
        self.assertNotIn("written during: test_nested.py::test_innocent", out)

    def test_a_test_that_modifies_an_existing_file_fails_the_run(self):
        rc, out = self.run_session("""\
            def test_rewrites_state():
                path = os.path.join(LIVE, ".clagentic", "state.json")
                with open(path, "w") as handle:
                    handle.write("{\\"changed\\": true}")
            """, seed="state.json")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("modified: .clagentic/state.json", out)

    def test_a_clean_session_passes(self):
        rc, out = self.run_session("""\
            def test_clean():
                assert os.path.isdir(os.path.join(LIVE, ".clagentic"))
            """)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("changed the live checkout", out)


if __name__ == "__main__":
    unittest.main()
