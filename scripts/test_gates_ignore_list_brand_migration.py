"""
Regression coverage for the osv-ignore / semgrep-exclude global-path
brand/product namespace split (lr-8ee2df).

scripts/gates.sh hardcoded both global ignore-list paths at the shared
brand root ($HOME/.config/clagentic/osv-ignore in cmd_deps,
$HOME/.config/clagentic/semgrep-exclude in cmd_sast -- the latter's own
comment explicitly says it "mirrors cmd_deps' osv-ignore mechanism
exactly") rather than this product's own namespace
($HOME/.config/clagentic/lite/...), the same defect class lr-7939f8 fixed
for the global config (bin/clagentic-lite, GLOBAL_CONFIG /
_migrate_global_config_brand_path).

NOT the credentials case (see this task's own PR body / gates.sh's
_gate_migrate_brand_root_file doc comment for the explicit list of which
of lr-7939f8's requirements apply here and which do not). osv-ignore and
semgrep-exclude hold CVE/GHSA IDs and semgrep rule ids -- suppression
policy, not secrets -- so this suite does not test a chmod-600/
never-leak-a-value/process-kill-mid-migration bar the way
test_global_config_brand_migration.py does for GLOBAL_CONFIG. What DOES
still apply, and is covered below: migrate-and-warn with back-compat read
during the deprecation window (a silently-dropped ignore entry starts
re-firing a suppressed finding on a BLOCKING security gate -- the
wrong-direction failure mode), never a state where both locations exist
with different content, idempotency, and the symlink/read-only/
pre-existing-new-path edge cases.

Same reason test_sast_exclude_ladder.py gives for testing factored units
rather than executing gates.sh's `deps`/`sast` subcommands directly:
clagentic-lite is developed on this host, never run here (CLAUDE.local.md
fact 6). Every test in this file extracts and sources ONLY
_gate_migrate_brand_root_file / _gate_resolve_global_ignore_path directly
out of gates.sh (same extraction-by-marker-slice technique
test_sast_exclude_ladder.py and test_global_config_brand_migration.py both
use) -- no git repo, no fake osv-scanner/semgrep binary, no CLI needed for
that half of the suite.

TestEndToEndViaRealCli is the one class that runs a real cmd_deps/cmd_sast
subprocess, and per the TEST HAZARD in this task's dispatch, does so only
against a throwaway clone (_clone_tool_home, matching
scripts/test_update_nontty_discard_guard.py and
scripts/test_global_config_brand_migration.py) with both
CLAGENTIC_LITE_HOME and HOME pointed at fresh tempdirs -- never this
checkout, never the operator's real HOME.

Run with: python3 -m unittest scripts.test_gates_ignore_list_brand_migration -v
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")

# Extraction markers -- _gate_migrate_brand_root_file and
# _gate_resolve_global_ignore_path are defined back-to-back, immediately
# before cmd_deps(), same layout test_sast_exclude_ladder.py relies on for
# its own helpers immediately before cmd_sast().
_START_MARKER = "# _gate_migrate_brand_root_file OLD NEW LABEL"
_END_MARKER = "\ncmd_deps() {"


def _extract_helpers():
    with open(GATES_SH) as f:
        content = f.read()
    start = content.index(_START_MARKER)
    end = content.index(_END_MARKER)
    extracted = content[start:end]
    assert "_gate_migrate_brand_root_file() {" in extracted, (
        "extraction marker drifted -- _gate_migrate_brand_root_file "
        "definition not found between the expected markers; update this "
        "test's anchors"
    )
    assert "_gate_resolve_global_ignore_path() {" in extracted, (
        "extraction marker drifted -- _gate_resolve_global_ignore_path "
        "definition not found between the expected markers; update this "
        "test's anchors"
    )
    return extracted


def _clone_tool_home(dest):
    """Throwaway clone of this checkout for TestEndToEndViaRealCli -- never
    run the real CLI against the live checkout (test hazard, see module
    docstring)."""
    subprocess.run(["git", "clone", "-q", TOOL_HOME, dest], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.name", "Test"],
                    check=True, capture_output=True)


class _HelperTestBase(unittest.TestCase):
    """Shared sourcing/exec plumbing for the two migration helper functions."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gates-ignore-migrate-")
        self._helpers_sh = os.path.join(self._tmp, "gates-migrate-helpers.sh")
        with open(self._helpers_sh, "w") as f:
            f.write("#!/bin/sh\n")
            f.write(_extract_helpers())
        self._home = os.path.join(self._tmp, "home")
        os.makedirs(self._home)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, script_body, extra_env=None):
        env = os.environ.copy()
        env["HOME"] = self._home
        if extra_env:
            env.update(extra_env)
        script = textwrap.dedent(f"""\
            . '{self._helpers_sh}'
            {script_body}
        """)
        return subprocess.run(
            ["sh", "-c", script, "gates-migrate-helpers-test"],
            capture_output=True, text=True, env=env,
        )

    def _old_new(self, name="osv-ignore"):
        old = os.path.join(self._home, name)
        new = os.path.join(self._home, "lite-ns", name)
        return old, new


class TestMigrateOldAbsent(_HelperTestBase):
    """OLD absent -- no-op, NEW never created. Proves the unfixed code path
    this test suite guards: without the migration call, an install with
    NOTHING at the old path must not spuriously create a new one."""

    def test_no_op_when_old_absent(self):
        old, new = self._old_new()
        result = self._run(
            f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore; "
            f"echo status=$?"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status=0", result.stdout)
        self.assertFalse(os.path.exists(new), "NEW must not be created when OLD never existed")


class TestMigrateHappyPath(_HelperTestBase):
    """OLD exists, NEW absent -- migrates content byte-identical, removes
    OLD, creates NEW's parent directory. This is the FAILING case against
    the pre-fix gates.sh: before this change, GLOBAL_IGNORE/the semgrep
    global exclude path were a single hardcoded brand-root constant with no
    migration function at all -- calling a function named
    _gate_migrate_brand_root_file against unfixed gates.sh would be a
    'command not found' shell error, which is exactly the failure mode this
    test would surface if the function were reverted."""

    def test_content_migrated_and_old_removed(self):
        old, new = self._old_new()
        with open(old, "w") as f:
            f.write("CVE-2024-0001\n# a comment\nCVE-2024-0002\n")
        result = self._run(
            f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.isfile(new), "NEW must exist after migration")
        self.assertFalse(os.path.exists(old), "OLD must be removed after a successful migration")
        with open(new) as f:
            self.assertEqual(f.read(), "CVE-2024-0001\n# a comment\nCVE-2024-0002\n")
        self.assertIn("migrated osv-ignore:", result.stderr)

    def test_new_parent_dir_created(self):
        old, new = self._old_new()
        with open(old, "w") as f:
            f.write("CVE-2024-0003\n")
        self.assertFalse(os.path.isdir(os.path.dirname(new)))
        result = self._run(
            f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.isdir(os.path.dirname(new)))


class TestMigrateIdempotent(_HelperTestBase):
    """Running the migration twice must not double-migrate or corrupt --
    binding requirement from the task dispatch."""

    def test_second_run_after_full_migration_is_noop(self):
        old, new = self._old_new()
        with open(old, "w") as f:
            f.write("CVE-2024-0001\n")
        r1 = self._run(f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore")
        self.assertEqual(r1.returncode, 0, r1.stderr)
        with open(new) as f:
            content_after_first = f.read()

        # Second call: OLD is now gone, this must be the OLD-absent no-op path.
        r2 = self._run(
            f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore; echo status=$?"
        )
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("status=0", r2.stdout)
        with open(new) as f:
            self.assertEqual(f.read(), content_after_first, "second run must not alter NEW's content")

    def test_kill_between_mv_and_old_removal_recovers_on_rerun(self):
        """Simulates the one genuinely dangerous interrupted-migration state:
        content landed at NEW (mv succeeded) but OLD was never removed (a
        kill/crash right after the mv). Both paths hold identical content --
        a re-run must recognize this as the 'already migrated, identical
        content' case and finish the cleanup, not error or diverge."""
        old, new = self._old_new()
        os.makedirs(os.path.dirname(new))
        with open(old, "w") as f:
            f.write("CVE-2024-0001\n")
        with open(new, "w") as f:
            f.write("CVE-2024-0001\n")
        result = self._run(f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.exists(old), "cleanup must remove the now-redundant OLD copy")
        self.assertTrue(os.path.isfile(new))
        self.assertIn("removed redundant legacy osv-ignore", result.stderr)


class TestMigrateBothExistDivergent(_HelperTestBase):
    """Never a state where both locations exist with different content --
    the migration must refuse to overwrite NEW and must leave BOTH files
    untouched, byte-diffing (cmp) rather than trusting mtimes/presence."""

    def test_divergent_content_leaves_both_untouched_and_warns(self):
        old, new = self._old_new()
        os.makedirs(os.path.dirname(new))
        with open(old, "w") as f:
            f.write("CVE-OLD-0001\n")
        with open(new, "w") as f:
            f.write("CVE-NEW-0002\n")
        result = self._run(f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(old) as f:
            self.assertEqual(f.read(), "CVE-OLD-0001\n", "OLD must be untouched on divergence")
        with open(new) as f:
            self.assertEqual(f.read(), "CVE-NEW-0002\n", "NEW must be untouched on divergence")
        self.assertIn("DIFFERENT content", result.stderr)
        self.assertIn("not migrating", result.stderr)


class TestMigrateSymlinkOldPath(_HelperTestBase):
    """OLD is a symlink -- content read through it into NEW; only the
    symlink itself removed after, never whatever it pointed at."""

    def test_symlink_old_migrated_target_survives(self):
        old, new = self._old_new()
        real_target = os.path.join(self._tmp, "real-osv-ignore")
        with open(real_target, "w") as f:
            f.write("CVE-2024-0009\n")
        os.symlink(real_target, old)
        result = self._run(f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.lexists(old), "the symlink itself must be removed")
        self.assertTrue(os.path.isfile(real_target), "the symlink's TARGET must survive untouched")
        with open(real_target) as f:
            self.assertEqual(f.read(), "CVE-2024-0009\n", "target content must be untouched")
        with open(new) as f:
            self.assertEqual(f.read(), "CVE-2024-0009\n", "NEW must carry the symlink's content")


class TestMigrateSymlinkNewPath(_HelperTestBase):
    """NEW is a symlink -- the destructive counterpart to
    TestMigrateSymlinkOldPath (HOLDEN/PEACHES/Codex finding, PR #203
    review). A plausible operator setup: NEW symlinked to OLD to keep one
    ignore list readable from both locations during the migration window.

    Mechanism this proves against the pre-fix code: `[ -f "$_gmbrf_new" ]`
    (scripts/gates.sh, the branch guarding the cmp-then-delete-OLD path)
    FOLLOWS symlinks -- it is satisfied by a symlink pointing at a regular
    file, indistinguishable from NEW being a real file. Once inside that
    branch, `cmp -s "$_gmbrf_old" "$_gmbrf_new"` follows the symlink back
    to OLD itself, so when NEW -> OLD the comparison is OLD-against-itself
    and always reports identical -- unconditionally, regardless of content.
    The pre-fix code then ran `rm -f "$_gmbrf_old"`, deleting the symlink's
    TARGET (the only real copy of the ignore list) and leaving NEW a
    dangling symlink. The fix adds an `[ -L "$_gmbrf_new" ]` check (tests
    the path itself, not what it resolves to) before the cmp/rm sequence,
    refusing to migrate at all when NEW is a symlink.

    This test is shown to FAIL against the pre-fix implementation: with
    the `-L` guard removed, `cmp -s` always matches (self-comparison
    through the symlink), so `_gmbrf_old` is unconditionally deleted --
    this assertion (`OLD must survive`) would fail, and the ignore list
    would end up gone from BOTH paths (OLD deleted, NEW a dangling
    symlink) -- exactly the data-loss mode the task's own contract
    ("never overwrites... never a state where both locations exist with
    different content") is meant to prevent, reached by a route neither
    existing test (TestMigrateBothExistDivergent, which uses two REGULAR
    files with different content) exercises."""

    def test_new_as_symlink_to_old_does_not_delete_old(self):
        old, new = self._old_new()
        os.makedirs(os.path.dirname(new))
        with open(old, "w") as f:
            f.write("CVE-2024-0099\n")
        os.symlink(old, new)

        result = self._run(f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            os.path.isfile(old),
            "OLD must survive -- deleting it here destroys the ignore list, since NEW is only a symlink to it",
        )
        with open(old) as f:
            self.assertEqual(f.read(), "CVE-2024-0099\n", "OLD's content must be untouched")
        self.assertTrue(os.path.lexists(new), "NEW's symlink must not be removed either -- refuse, don't clean up")
        self.assertIn("symlink", result.stderr.lower())
        self.assertIn("not migrating", result.stderr.lower())

    def test_new_as_symlink_to_unrelated_file_does_not_delete_old(self):
        """NEW symlinked to some THIRD file (not OLD) with identical
        content -- still refused, not merely the OLD-self-comparison case.
        The fix's -L check triggers on NEW being a symlink at all, not on
        detecting the specific self-comparison mechanism, so this must
        refuse the same way."""
        old, new = self._old_new()
        os.makedirs(os.path.dirname(new))
        third_file = os.path.join(self._tmp, "third-file-same-content")
        with open(old, "w") as f:
            f.write("CVE-2024-0100\n")
        with open(third_file, "w") as f:
            f.write("CVE-2024-0100\n")
        os.symlink(third_file, new)

        result = self._run(f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.isfile(old), "OLD must survive when NEW is any symlink, not just one pointing at OLD")
        self.assertTrue(os.path.isfile(third_file), "the symlink's actual target must also survive untouched")
        self.assertIn("symlink", result.stderr.lower())


class TestMigrateReadOnlyOldPath(_HelperTestBase):
    """OLD is read-only (no owner-write bit) -- still migrates: only ever
    READS old, then unlinks it (needs write on the parent dir, not the
    file itself)."""

    def test_readonly_old_still_migrates(self):
        old, new = self._old_new()
        with open(old, "w") as f:
            f.write("CVE-2024-0010\n")
        os.chmod(old, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        try:
            result = self._run(f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(os.path.exists(old))
            with open(new) as f:
                self.assertEqual(f.read(), "CVE-2024-0010\n")
        finally:
            # tearDown's rmtree needs write on any surviving read-only file.
            if os.path.exists(old):
                os.chmod(old, stat.S_IRUSR | stat.S_IWUSR)


class TestMigrateUnwritableParentFailsClosedWithoutAborting(_HelperTestBase):
    """A migration failure (unwritable target parent dir) must leave OLD
    untouched and return non-zero -- and, per the task's cmd_deps/cmd_sast
    wiring (`|| true`), must never abort the whole blocking gate under
    gates.sh's `set -e`. This test exercises the helper function's own
    contract directly; the `|| true` wiring itself is covered by
    TestEndToEndViaRealCli below."""

    def test_unwritable_parent_leaves_old_intact_returns_nonzero(self):
        # File-mode permission bits don't reliably block a write when tests
        # run as root (common in a sandboxed/container test environment) --
        # `mkdir -p` under a read-only directory would silently succeed
        # there, making a chmod-based injection unreliable. Instead, plant a
        # plain FILE at the path NEW's parent directory needs to occupy:
        # `mkdir -p` genuinely cannot create a directory where a file
        # already exists, regardless of uid.
        old, new = self._old_new()
        new_parent = os.path.dirname(new)
        with open(new_parent, "w") as f:
            f.write("blocking file, not a directory\n")
        with open(old, "w") as f:
            f.write("CVE-2024-0011\n")
        result = self._run(
            f"_gate_migrate_brand_root_file '{old}' '{new}' osv-ignore; echo status=$?"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status=1", result.stdout, "a genuine migration failure must return non-zero")
        self.assertTrue(os.path.isfile(old), "OLD must survive a failed migration untouched")
        self.assertFalse(os.path.isdir(new_parent))
        self.assertIn("could not create", result.stderr)


class TestResolveGlobalIgnorePath(_HelperTestBase):
    """_gate_resolve_global_ignore_path -- new-path-wins-with-fallback read
    precedence, mirroring ds_load_global_env (scripts/platform.sh)."""

    def test_new_wins_when_both_exist(self):
        old, new = self._old_new()
        os.makedirs(os.path.dirname(new))
        with open(old, "w") as f:
            f.write("old\n")
        with open(new, "w") as f:
            f.write("new\n")
        result = self._run(f"_gate_resolve_global_ignore_path '{new}' '{old}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, new)
        self.assertNotIn("deprecated path", result.stderr)

    def test_falls_back_to_old_with_warning_when_new_absent(self):
        old, new = self._old_new()
        with open(old, "w") as f:
            f.write("old\n")
        result = self._run(f"_gate_resolve_global_ignore_path '{new}' '{old}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, old, "must fall back to reading OLD so an un-migrated ignore list is not silently lost")
        self.assertIn("deprecated path", result.stderr)
        self.assertIn(old, result.stderr)

    def test_resolves_to_new_path_when_neither_exists(self):
        old, new = self._old_new()
        result = self._run(f"_gate_resolve_global_ignore_path '{new}' '{old}' osv-ignore")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, new)
        self.assertNotIn("deprecated path", result.stderr)


class TestEndToEndViaRealCli(unittest.TestCase):
    """Runs a real gates.sh `deps`/`sast` subprocess against a throwaway
    clone of this checkout (test hazard: never the live checkout, never
    the operator's real HOME -- see module docstring). Fakes osv-scanner
    and semgrep on PATH so no real scan/network call happens; the point of
    this class is proving the migration wiring inside cmd_deps/cmd_sast
    actually fires end-to-end (the `|| true` guard, the resolved-path
    plumbing into the ignore-file loop), not re-testing scan behavior
    already covered by test_sast_baseline_scope.py."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gates-e2e-")
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

        self._bin = os.path.join(self._tmp, "fakebin")
        os.makedirs(self._bin)
        self._write_fake_osv_scanner()
        self._write_fake_semgrep()

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_fake_osv_scanner(self):
        path = os.path.join(self._bin, "osv-scanner")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""\
                #!/bin/sh
                case "$1" in
                  --version) echo "osv-scanner version: 2.0.0"; exit 0 ;;
                  scan)
                    for a in "$@"; do
                      case "$a" in --format=json) fmt=1 ;; esac
                    done
                    echo '{"results":[]}'
                    exit 0
                    ;;
                esac
                exit 0
            """))
        os.chmod(path, 0o755)

    def _write_fake_semgrep(self):
        path = os.path.join(self._bin, "semgrep")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""\
                #!/bin/sh
                case "$1" in
                  --help) echo "USAGE"; echo "--baseline-commit"; exit 0 ;;
                esac
                exit 0
            """))
        os.chmod(path, 0o755)

    def _env(self):
        env = os.environ.copy()
        env["HOME"] = self._home
        env["PATH"] = self._bin + os.pathsep + env["PATH"]
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        env["CLAGENTIC_ALLOW_MISSING_OSV"] = "0"
        env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "0"
        return env

    def test_deps_migrates_legacy_osv_ignore_on_real_run(self):
        old = os.path.join(self._home, ".config", "clagentic", "osv-ignore")
        new = os.path.join(self._home, ".config", "clagentic", "lite", "osv-ignore")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("CVE-2024-9999\n")

        gates_sh = os.path.join(self._fake_tool_home, "scripts", "gates.sh")
        result = subprocess.run(
            ["sh", gates_sh, "deps"],
            capture_output=True, text=True, env=self._env(), cwd=self._repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.isfile(new), f"expected migrated ignore list at {new}; stderr={result.stderr}")
        self.assertFalse(os.path.exists(old))
        with open(new) as f:
            self.assertEqual(f.read(), "CVE-2024-9999\n")
        self.assertIn("migrated osv-ignore:", result.stderr)

    def test_sast_migrates_legacy_semgrep_exclude_on_real_run(self):
        old = os.path.join(self._home, ".config", "clagentic", "semgrep-exclude")
        new = os.path.join(self._home, ".config", "clagentic", "lite", "semgrep-exclude")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("some.synthetic.rule.id\n")

        gates_sh = os.path.join(self._fake_tool_home, "scripts", "gates.sh")
        result = subprocess.run(
            ["sh", gates_sh, "sast"],
            capture_output=True, text=True, env=self._env(), cwd=self._repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.isfile(new), f"expected migrated exclude list at {new}; stderr={result.stderr}")
        self.assertFalse(os.path.exists(old))
        with open(new) as f:
            self.assertEqual(f.read(), "some.synthetic.rule.id\n")
        self.assertIn("migrated semgrep-exclude:", result.stderr)

    def test_deps_migration_failure_does_not_abort_gate_under_set_e(self):
        """The `|| true` guard around _gate_migrate_brand_root_file in
        cmd_deps: an unwritable ~/.config/clagentic/ (so mkdir -p for
        .../lite/ fails) must not kill the whole gate via `set -e` -- deps
        must still run to completion (falling back to reading the old path
        directly) rather than exiting early with no gate_runs row at all.
        This is the failure this test would catch if the `|| true` guard
        were removed: gates.sh has `set -e` at the top, so a bare call to a
        function returning 1 aborts the calling function immediately."""
        old = os.path.join(self._home, ".config", "clagentic", "osv-ignore")
        os.makedirs(os.path.dirname(old))
        with open(old, "w") as f:
            f.write("CVE-2024-8888\n")
        # Root-safe injection (see TestMigrateUnwritableParentFailsClosedWithoutAborting's
        # comment for why chmod-based injection is unreliable under a root
        # test runner): plant a plain FILE at .config/clagentic/lite/, the
        # exact path `mkdir -p` needs to create as a directory, so the
        # migration's mkdir genuinely fails regardless of uid.
        brand_root = os.path.dirname(old)
        lite_ns_path = os.path.join(brand_root, "lite")
        with open(lite_ns_path, "w") as f:
            f.write("blocking file, not a directory\n")

        gates_sh = os.path.join(self._fake_tool_home, "scripts", "gates.sh")
        result = subprocess.run(
            ["sh", gates_sh, "deps"],
            capture_output=True, text=True, env=self._env(), cwd=self._repo,
        )
        self.assertEqual(
            result.returncode, 0,
            f"deps gate must complete (falling back to the old ignore path) even when migration "
            f"fails, not abort under set -e; stderr={result.stderr}",
        )
        self.assertIn("could not create", result.stderr)
        self.assertIn("deprecated path", result.stderr, "must still fall back to reading the old path")


if __name__ == "__main__":
    unittest.main()
