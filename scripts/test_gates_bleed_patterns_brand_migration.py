"""
Regression coverage for cmd_bleed's global pattern-file brand/product
namespace split (lr-73fa40) -- third and final known instance of the class
lr-7939f8 (GLOBAL_CONFIG) and lr-8ee2df (osv-ignore/semgrep-exclude) already
closed.

cmd_bleed hardcoded its global pattern-file path at the shared brand root
($HOME/.config/clagentic/bleed-patterns) instead of this product's own
namespace ($HOME/.config/clagentic/lite/bleed-patterns). The fix routes
through the two helpers lr-8ee2df already added
(_gate_migrate_brand_root_file / _gate_resolve_global_ignore_path,
scripts/gates.sh, defined above cmd_deps) rather than a third copy of the
same migration logic.

This file does NOT re-test the helper functions themselves -- every edge
case (OLD absent, happy path, idempotency, both-exist-divergent, OLD/NEW
symlink in both directions, read-only OLD, unwritable-parent failure,
new-path-wins-with-fallback read precedence) is already covered by
test_gates_ignore_list_brand_migration.py against the exact same shared
helpers; duplicating that here would be the "two near-identical primitives"
problem the task dispatch explicitly warned against, just at the test layer
instead of the implementation layer. What this file DOES cover, and what
test_gates_ignore_list_brand_migration.py cannot, is the wiring specific to
cmd_bleed: that it actually calls the shared helpers (not a hand-rolled
`[ -f ... ]` check against the old brand-root path), that the `|| true`
guard keeps the gate running to completion under `set -e` on a migration
failure, and that the pattern file cmd_bleed ultimately reads/matches
against really is the resolved (migrated-or-fallback) path -- proven by
planting a pattern at the global path and asserting the gate actually
matches on it, not just that a file exists at some path afterward.

Same reason as the sibling suite for testing via a real gates.sh subprocess
for the wiring class (TestEndToEndViaRealCli there): clagentic-lite is
developed on this host, never run here (CLAUDE.local.md fact 6). Runs only
against a throwaway copy (_clone_tool_home, matching
test_gates_ignore_list_brand_migration.py and
test_update_nontty_discard_guard.py) with both CLAGENTIC_LITE_HOME and HOME
pointed at fresh tempdirs -- never this checkout, never the operator's real
HOME (TEST HAZARD in this task's dispatch).

PEACHES review finding (PR #207): `git clone` of a local path clones
COMMITTED history only -- it does not see uncommitted working-tree edits.
A change to scripts/gates.sh made but not yet committed on the feature
branch would be invisible to a test that only clones, so the test would
validate the wrong revision (the last commit, not the diff under review)
right up until the moment the change is committed. _clone_tool_home clones
first (to get a real git repo shape other subprocess calls in this suite
may rely on), then overlays every currently-tracked file's on-disk content
from TOOL_HOME on top -- so a test run always exercises what is actually on
disk in this checkout, committed or not.

Run with: python3 -m unittest scripts.test_gates_bleed_patterns_brand_migration -v
"""
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _clone_tool_home(dest):
    """Throwaway copy of this checkout -- never run the real CLI/gates.sh
    against the live checkout (test hazard, see module docstring).

    Clones committed history first (git rev-parse/log-dependent code paths
    elsewhere in this suite need a real repo), then overlays the CURRENT
    on-disk content of every tracked file over the clone. Without the
    overlay, an uncommitted edit to e.g. scripts/gates.sh is invisible to
    every test in this file -- they would silently validate the last
    commit instead of the change under review (PEACHES finding, PR #207).
    """
    subprocess.run(["git", "clone", "-q", TOOL_HOME, dest], check=True, capture_output=True)
    tracked = subprocess.run(
        ["git", "-C", TOOL_HOME, "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout
    for rel_raw in tracked.split(b"\0"):
        if not rel_raw:
            continue
        rel = rel_raw.decode()
        src = os.path.join(TOOL_HOME, rel)
        dst = os.path.join(dest, rel)
        # A tracked file can be deleted-but-uncommitted on disk; skip it
        # rather than fail the overlay -- ls-files still lists it (index
        # entry unchanged), but there is nothing to copy.
        if os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    subprocess.run(["git", "-C", dest, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.name", "Test"],
                    check=True, capture_output=True)


class TestBleedGlobalPatternFileMigration(unittest.TestCase):
    """Runs a real `gates.sh bleed` subprocess against a throwaway clone.
    Proves the migration wiring inside cmd_bleed actually fires end-to-end
    (the `|| true` guard, the resolved-path plumbing into the pattern-file
    read), not just that the shared helpers work in isolation."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gates-bleed-migrate-")
        self._fake_tool_home = os.path.join(self._tmp, "fake-tool-home")
        _clone_tool_home(self._fake_tool_home)
        self._home = os.path.join(self._tmp, "home")
        os.makedirs(self._home)
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        subprocess.run(["git", "-C", self._repo, "init", "-q"], check=True, capture_output=True)
        subprocess.run(["git", "-C", self._repo, "config", "user.email", "test@example.com"], check=True, capture_output=True)
        subprocess.run(["git", "-C", self._repo, "config", "user.name", "Test"], check=True, capture_output=True)
        with open(os.path.join(self._repo, "README.md"), "w") as f:
            f.write("test\n")
        subprocess.run(["git", "-C", self._repo, "add", "README.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", self._repo, "commit", "-q", "-m", "init"], check=True, capture_output=True)

        self._gates_sh = os.path.join(self._fake_tool_home, "scripts", "gates.sh")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _env(self):
        env = os.environ.copy()
        env["HOME"] = self._home
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        return env

    def _run_bleed(self, extra_args=None):
        args = ["sh", self._gates_sh, "bleed"]
        if extra_args:
            args += extra_args
        return subprocess.run(
            args, capture_output=True, text=True, env=self._env(), cwd=self._repo,
        )

    def test_migrates_legacy_pattern_file_on_real_run(self):
        """OLD (brand-root) has a pattern file; a real `gates.sh bleed`
        invocation must migrate it to NEW (product-namespace) -- proving
        cmd_bleed calls the shared helper rather than only reading the old
        hardcoded path."""
        old = os.path.join(self._home, ".config", "clagentic", "bleed-patterns")
        new = os.path.join(self._home, ".config", "clagentic", "lite", "bleed-patterns")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("# comment\nTOTALLYUNIQUEBLEEDTOKEN\n")

        result = self._run_bleed(["--full-scan"])

        self.assertTrue(os.path.isfile(new), f"expected migrated pattern file at {new}; stderr={result.stderr}")
        self.assertFalse(os.path.exists(old), "OLD must be removed after a successful migration")
        with open(new) as f:
            self.assertEqual(f.read(), "# comment\nTOTALLYUNIQUEBLEEDTOKEN\n")
        self.assertIn("migrated bleed-patterns:", result.stderr)

    def test_gate_actually_matches_against_migrated_pattern(self):
        """Not just 'a file exists at NEW afterward' -- the pattern the gate
        reads from the resolved path must be the one it scans with. Plants a
        unique token both at the OLD global path and inside a tracked repo
        file, then asserts the gate BLOCKS (exit 1) on the real match --
        proof the resolved path from _gate_resolve_global_ignore_path is
        what cmd_bleed actually greps with, not a stale/empty read."""
        old = os.path.join(self._home, ".config", "clagentic", "bleed-patterns")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("TOTALLYUNIQUEBLEEDTOKEN\n")

        with open(os.path.join(self._repo, "leaky.txt"), "w") as f:
            f.write("this file contains TOTALLYUNIQUEBLEEDTOKEN in it\n")
        subprocess.run(["git", "-C", self._repo, "add", "leaky.txt"], check=True, capture_output=True)
        subprocess.run(["git", "-C", self._repo, "commit", "-q", "-m", "add leaky file"], check=True, capture_output=True)

        result = self._run_bleed(["--full-scan"])

        self.assertEqual(result.returncode, 1, f"gate must block on a real pattern match; stdout={result.stdout} stderr={result.stderr}")
        self.assertIn("leaky.txt", result.stdout + result.stderr)

    def test_migration_failure_does_not_abort_gate_under_set_e(self):
        """The `|| true` guard around _gate_migrate_brand_root_file in
        cmd_bleed: an unwritable .../lite/ target (mkdir -p fails) must not
        kill the whole gate via `set -e` -- bleed must still run to
        completion, falling back to reading the old path directly, rather
        than exiting early with no gate_runs row at all."""
        old = os.path.join(self._home, ".config", "clagentic", "bleed-patterns")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("TOTALLYUNIQUEBLEEDTOKEN\n")
        # Root-safe injection (see test_gates_ignore_list_brand_migration.py's
        # matching comment for why chmod-based injection is unreliable under
        # a root test runner): plant a plain FILE at .config/clagentic/lite/,
        # the exact path `mkdir -p` needs to create as a directory, so the
        # migration's mkdir genuinely fails regardless of uid.
        brand_root = os.path.dirname(old)
        lite_ns_path = os.path.join(brand_root, "lite")
        with open(lite_ns_path, "w") as f:
            f.write("blocking file, not a directory\n")

        with open(os.path.join(self._repo, "leaky.txt"), "w") as f:
            f.write("this file contains TOTALLYUNIQUEBLEEDTOKEN in it\n")
        subprocess.run(["git", "-C", self._repo, "add", "leaky.txt"], check=True, capture_output=True)
        subprocess.run(["git", "-C", self._repo, "commit", "-q", "-m", "add leaky file"], check=True, capture_output=True)

        result = self._run_bleed(["--full-scan"])

        self.assertIn(
            result.returncode, (0, 1),
            f"bleed gate must complete (pass or genuinely block), not abort under set -e "
            f"with an unrelated shell error; stdout={result.stdout} stderr={result.stderr}",
        )
        self.assertIn("could not create", result.stderr)
        self.assertIn("deprecated path", result.stderr, "must still fall back to reading the old path")
        # PEACHES finding (PR #207): the fallback warning used to say "run
        # `clagentic-lite gates deps`/`sast`" -- accurate when cmd_deps and
        # cmd_sast were the only two callers of this shared helper, but
        # cmd_bleed becoming a third caller makes that text prescribe two
        # unrelated gates to a bleed user. The message must name no
        # specific gate command.
        self.assertNotIn("gates deps", result.stderr, "bleed fallback warning must not tell the operator to run an unrelated gate")
        self.assertNotIn("sast", result.stderr, "bleed fallback warning must not tell the operator to run an unrelated gate")
        # Falls back to reading OLD directly, so the pattern is still active
        # and the gate still finds it -- proving the fallback path is really
        # read, not just that the gate merely survives.
        self.assertEqual(result.returncode, 1, f"fallback-to-OLD read must still find the planted pattern; stderr={result.stderr}")

    def test_repo_level_pattern_file_still_wins_over_global(self):
        """Resolution order must be unchanged by this fix: repo-level
        .clagentic/bleed-patterns still checked first, ahead of either
        global path. Prevents a regression where the global-path plumbing
        accidentally reordered or short-circuited the existing precedence."""
        clagentic_dir = os.path.join(self._repo, ".clagentic")
        os.makedirs(clagentic_dir)
        with open(os.path.join(clagentic_dir, "bleed-patterns"), "w") as f:
            f.write("REPOLEVELTOKEN\n")
        subprocess.run(["git", "-C", self._repo, "add", ".clagentic/bleed-patterns"], check=True, capture_output=True)
        subprocess.run(["git", "-C", self._repo, "commit", "-q", "-m", "add repo pattern file"], check=True, capture_output=True)

        # Global path also present, with a DIFFERENT token -- if the global
        # path won, this token would never be scanned for and the test file
        # below (containing the global token, not the repo token) would not
        # trigger a block.
        old = os.path.join(self._home, ".config", "clagentic", "bleed-patterns")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("GLOBALONLYTOKEN\n")

        with open(os.path.join(self._repo, "has-repo-token.txt"), "w") as f:
            f.write("REPOLEVELTOKEN present here\n")
        subprocess.run(["git", "-C", self._repo, "add", "has-repo-token.txt"], check=True, capture_output=True)
        subprocess.run(["git", "-C", self._repo, "commit", "-q", "-m", "add file with repo token"], check=True, capture_output=True)

        result = self._run_bleed(["--full-scan"])

        self.assertEqual(result.returncode, 1, f"repo-level pattern file must still be honored; stdout={result.stdout} stderr={result.stderr}")
        self.assertIn("has-repo-token.txt", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
