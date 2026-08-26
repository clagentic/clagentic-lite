"""
Regression tests for lr-7939f8: the global config moves from the shared
BRAND root ~/.config/clagentic/config to the PRODUCT namespace
~/.config/clagentic/lite/config -- clagentic is a brand shared with other
tools (clagentic-loadout correctly uses ~/.config/clagentic/loadout/, 34
occurrences, zero exceptions); clagentic-lite's own global config was the
one holdout still claiming the bare brand root.

SAFETY BAR (this file holds live credentials -- CLAGENTIC_ROUTER_TOKEN,
CLAGENTIC_ROUTER_BEDROCK_TOKEN, on the operator's real machine in
production): chmod 600 before/during/after with no window; no configured
VALUE on any output stream including error paths; never a state where both
locations exist with different content silently; a back-compat READ of the
old path during the deprecation window; explicit handling for old-path
symlink / read-only / new-path-already-exists; idempotent.

BINDING REQUIREMENTS FROM THE LORE TASK THREAD (comment #1):
  1. Reuse the EXISTING _secret_tmp_create helper (bin/clagentic-lite,
     added by PR #195) -- do NOT roll a second temp-file primitive. This
     suite extracts and directly exercises _secret_tmp_create alongside
     _migrate_global_config_brand_path (never duplicates its logic) to
     prove the reuse, not merely assert it by code inspection.
  2. Test process-kill mid-migration at EVERY step boundary. Assert per
     kill point: (a) no file holding credential content exists at any mode
     other than 600, (b) the config is recoverable fully at the old path OR
     fully at the new path, never absent from both and never split, (c) a
     re-run after the kill completes cleanly and idempotently.

VERIFICATION SCOPE: this host is the dev host -- bin/clagentic-lite is
never executed as a subprocess for the process-kill tests (a full `update`
run is slow/non-deterministic to interrupt at a precise internal step).
Follows the established technique from scripts/test_unified_plugin_render.py
/ test_sast_exclude_ladder.py / test_review_ledger.py / test_host_adapter_
publish.py: extract the real function definitions verbatim out of
bin/clagentic-lite via string-slicing between stable markers, source them
into a throwaway shell script, and invoke as real POSIX sh functions with
`sh -c`. This proves the actual migration logic, not an approximation of
it, without ever dispatching bin/clagentic-lite's own cmd_update/cmd_init
entrypoints for the kill-timing tests. A smaller set of end-to-end tests
(TestEndToEndViaRealCli below) DOES invoke the real CLI via `update`/`init`
subcommands, exactly like every other suite in this repo, to prove the
extracted functions are wired up correctly in the shipped dispatch path --
never with CLAGENTIC_LITE_HOME/HOME resolving to the live checkout (see
HAZARD below).

HAZARD, read before editing this file: any test that runs cmd_init/
cmd_update/enroll must point CLAGENTIC_LITE_HOME at a throwaway `git clone`
of the real checkout via _clone_tool_home, check=True, no fallback to the
live tree, under every path including setup-failure and cleanup -- follows
test_update_nontty_discard_guard.py exactly. HOME is always a fresh tempdir,
never the operator's real HOME, which holds live credentials.

`_clone_tool_home` (scripts/test_support.py) also overlays the checkout's
CURRENT on-disk content over the clone -- `git clone` alone only picks up
COMMITTED history, so an uncommitted edit to bin/clagentic-lite would
otherwise be invisible to TestEndToEndViaRealCli below (PEACHES finding,
PR #207; this file previously claimed the HAZARD discipline above without
actually carrying the overlay -- lr-bca2ee).

Run with: python3 -m unittest scripts.test_global_config_brand_migration -v
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

from scripts.test_support import clone_this_tool_home_with_overlay

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")

_START_MARKER = "# _secret_tmp_create PATH"
_END_MARKER = "cmd_update() {"


def _extract_migration_functions():
    with open(CLI) as f:
        content = f.read()
    assert _START_MARKER in content, (
        "extraction marker drifted -- _secret_tmp_create doc header not "
        "found; update this test's start marker"
    )
    start = content.index(_START_MARKER)
    assert _END_MARKER in content, (
        "extraction marker drifted -- cmd_update() { not found; update "
        "this test's end marker"
    )
    end = content.index(_END_MARKER, start)
    extracted = content[start:end]
    for fn in (
        "_secret_tmp_create() {",
        "_mgcb_checkpoint() {",
        "_migrate_global_config_brand_path() {",
    ):
        assert fn in extracted, (
            f"extraction marker drifted -- {fn} definition not found "
            "between the expected markers; update this test's anchors"
        )
    return extracted


_clone_tool_home = clone_this_tool_home_with_overlay
"""Throwaway git clone of the real checkout, overlaid with its current
on-disk content (scripts/test_support.py), per the HAZARD discipline in
test_update_nontty_discard_guard.py. Used only by the end-to-end (real CLI)
tests below -- the extracted-function tests never invoke bin/clagentic-lite
as a subprocess at all."""


def _all_file_modes_under(root):
    """Every regular file's mode (octal, permission bits only) found under
    root, recursively. Used to assert NOTHING holding credential content is
    ever left at a mode other than 600."""
    modes = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p) and not os.path.exists(p):
                continue
            modes[p] = stat.S_IMODE(os.stat(p).st_mode)
    return modes


class _ExtractedFunctionTestBase(unittest.TestCase):
    """Sourcing/exec plumbing for the extracted _secret_tmp_create /
    _migrate_global_config_brand_path functions. Never invokes
    bin/clagentic-lite's own dispatch."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-gc-migrate-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.old_config_dir = os.path.join(self.home, ".config", "clagentic")
        self.new_config_dir = os.path.join(self.home, ".config", "clagentic", "lite")
        self.old_config = os.path.join(self.old_config_dir, "config")
        self.new_config = os.path.join(self.new_config_dir, "config")

        self.helpers_sh = os.path.join(self.tmp, "migrate-helpers.sh")
        with open(self.helpers_sh, "w") as f:
            f.write("#!/bin/sh\n")
            f.write(_extract_migration_functions())

    def _write_old_config(self, body, mode=0o600):
        os.makedirs(self.old_config_dir, exist_ok=True)
        with open(self.old_config, "w") as f:
            f.write(body)
        os.chmod(self.old_config, mode)

    def _preamble(self, checkpoint_body=":"):
        # say()/warn() are used by the extracted function but defined
        # elsewhere in bin/clagentic-lite -- minimal stand-ins so the
        # sourced block is self-contained, matching test_unified_plugin_
        # render.py's own convention.
        return (
            "say()  { printf '[clagentic-lite] %s\\n' \"$*\"; }\n"
            "warn() { printf '[clagentic-lite] WARN: %s\\n' \"$*\" 1>&2; }\n"
            f"_mgcb_checkpoint() {{ {checkpoint_body}; }}\n"
        )

    def _run(self, script_body, checkpoint_body=":", extra_env=None, timeout=15):
        env = os.environ.copy()
        env["HOME"] = self.home
        env["GLOBAL_CONFIG"] = self.new_config
        env["OLD_GLOBAL_CONFIG"] = self.old_config
        if extra_env:
            env.update(extra_env)
        script = (
            f". '{self.helpers_sh}'\n"
            f"{self._preamble(checkpoint_body)}\n"
            f"{textwrap.dedent(script_body)}\n"
        )
        return subprocess.run(
            ["sh", "-c", script, "gc-migrate-test"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
            timeout=timeout,
        )


class TestHappyPathMigration(_ExtractedFunctionTestBase):
    def test_migrates_content_byte_identical(self):
        body = "CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\nCLAGENTIC_ROUTER_TOKEN=tok123\n"
        self._write_old_config(body)
        proc = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertFalse(os.path.exists(self.old_config), msg="old path must be removed after migration")
        with open(self.new_config) as f:
            self.assertEqual(f.read(), body)

    def test_migrated_file_is_mode_600(self):
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=tok123\n")
        self._run("_migrate_global_config_brand_path")
        mode = stat.S_IMODE(os.stat(self.new_config).st_mode)
        self.assertEqual(mode, 0o600)

    def test_new_parent_dir_created_mode_700(self):
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=tok123\n")
        self._run("_migrate_global_config_brand_path")
        mode = stat.S_IMODE(os.stat(self.new_config_dir).st_mode)
        self.assertEqual(mode, 0o700)

    def test_says_migrated_names_paths_only(self):
        secret = "sk-super-secret-token-must-never-print"
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=%s\n" % secret)
        proc = self._run("_migrate_global_config_brand_path")
        self.assertIn(self.old_config, proc.stdout)
        self.assertIn(self.new_config, proc.stdout)
        self.assertNotIn(secret, proc.stdout)
        self.assertNotIn(secret, proc.stderr)

    def test_no_old_config_is_silent_noop(self):
        proc = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")

    def test_second_run_after_success_is_idempotent(self):
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=tok123\n")
        self._run("_migrate_global_config_brand_path")
        proc2 = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc2.returncode, 0, msg=proc2.stderr)
        with open(self.new_config) as f:
            self.assertEqual(f.read(), "CLAGENTIC_ROUTER_TOKEN=tok123\n")
        self.assertFalse(os.path.exists(self.old_config))


class TestBothPathsExist(_ExtractedFunctionTestBase):
    def test_identical_content_cleans_up_old_silently_correct(self):
        body = "CLAGENTIC_ROUTER_TOKEN=tok123\n"
        self._write_old_config(body)
        os.makedirs(self.new_config_dir, exist_ok=True)
        with open(self.new_config, "w") as f:
            f.write(body)
        os.chmod(self.new_config, 0o600)

        proc = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertFalse(os.path.exists(self.old_config),
                          msg="identical redundant old copy must be cleaned up")
        with open(self.new_config) as f:
            self.assertEqual(f.read(), body)

    def test_different_content_never_overwrites_either_file(self):
        """Never a state where both locations exist with different content
        -- the function must detect this and refuse to touch either file."""
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=OLD-VALUE\n")
        os.makedirs(self.new_config_dir, exist_ok=True)
        with open(self.new_config, "w") as f:
            f.write("CLAGENTIC_ROUTER_TOKEN=NEW-VALUE\n")
        os.chmod(self.new_config, 0o600)

        proc = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertTrue(os.path.exists(self.old_config), msg="old file must survive untouched")
        self.assertTrue(os.path.exists(self.new_config), msg="new file must survive untouched")
        with open(self.old_config) as f:
            self.assertEqual(f.read(), "CLAGENTIC_ROUTER_TOKEN=OLD-VALUE\n")
        with open(self.new_config) as f:
            self.assertEqual(f.read(), "CLAGENTIC_ROUTER_TOKEN=NEW-VALUE\n")

    def test_different_content_warning_names_paths_not_values(self):
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=OLD-SECRET-VALUE\n")
        os.makedirs(self.new_config_dir, exist_ok=True)
        with open(self.new_config, "w") as f:
            f.write("CLAGENTIC_ROUTER_TOKEN=NEW-SECRET-VALUE\n")
        os.chmod(self.new_config, 0o600)

        proc = self._run("_migrate_global_config_brand_path")
        combined = proc.stdout + proc.stderr
        self.assertIn(self.old_config, combined)
        self.assertIn(self.new_config, combined)
        self.assertNotIn("OLD-SECRET-VALUE", combined)
        self.assertNotIn("NEW-SECRET-VALUE", combined)


class TestSymlinkAndReadOnlyHandling(_ExtractedFunctionTestBase):
    def test_old_path_as_symlink_migrates_target_content_removes_only_link(self):
        real_target = os.path.join(self.tmp, "real-config-elsewhere")
        with open(real_target, "w") as f:
            f.write("CLAGENTIC_ROUTER_TOKEN=tok123\n")
        os.chmod(real_target, 0o600)
        os.makedirs(self.old_config_dir, exist_ok=True)
        os.symlink(real_target, self.old_config)

        proc = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertFalse(os.path.islink(self.old_config), msg="the symlink itself must be removed")
        self.assertFalse(os.path.exists(self.old_config))
        self.assertTrue(os.path.exists(real_target),
                         msg="whatever the symlink pointed at must survive untouched")
        with open(self.new_config) as f:
            self.assertEqual(f.read(), "CLAGENTIC_ROUTER_TOKEN=tok123\n")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                      "running as root -- permission bits do not block root's "
                      "own writes, so this scenario cannot be exercised here")
    def test_old_path_read_only_still_migrates(self):
        """Migrating only ever READS the old file, then unlinks it (which
        needs write permission on the parent DIRECTORY, not the file) --
        an old file with no owner-write bit must still migrate cleanly."""
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=tok123\n", mode=0o400)
        proc = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertFalse(os.path.exists(self.old_config))
        with open(self.new_config) as f:
            self.assertEqual(f.read(), "CLAGENTIC_ROUTER_TOKEN=tok123\n")
        mode = stat.S_IMODE(os.stat(self.new_config).st_mode)
        self.assertEqual(mode, 0o600)

    def test_new_path_already_exists_as_symlink_treated_as_existing_never_clobbered(self):
        """A new-path that is ALREADY a symlink still satisfies `[ -f
        "$GLOBAL_CONFIG" ]` when its target exists -- the function's
        both-paths-exist branch must apply, not a raw overwrite."""
        real_new_target = os.path.join(self.tmp, "real-new-config-elsewhere")
        with open(real_new_target, "w") as f:
            f.write("CLAGENTIC_ROUTER_TOKEN=tok123\n")
        os.chmod(real_new_target, 0o600)
        os.makedirs(self.new_config_dir, exist_ok=True)
        os.symlink(real_new_target, self.new_config)

        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=tok123\n")

        proc = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        # Identical content -> cleanup path: old removed, new (the symlink,
        # still resolving to the same content) survives.
        self.assertFalse(os.path.exists(self.old_config))
        self.assertTrue(os.path.islink(self.new_config))
        with open(self.new_config) as f:
            self.assertEqual(f.read(), "CLAGENTIC_ROUTER_TOKEN=tok123\n")


class TestProcessKillMidMigration(_ExtractedFunctionTestBase):
    """lore task lr-7939f8 comment #1, binding requirement 2: kill the
    migration mid-flight at EVERY step boundary and assert, for each: (a) no
    file holding credential content exists at any mode other than 600, (b)
    the config is recoverable fully at the old path OR fully at the new
    path, never absent from both and never split, (c) re-running after the
    kill completes cleanly and idempotently.

    Mechanism: _mgcb_checkpoint (bin/clagentic-lite) is a no-op in
    production, called at each step boundary inside
    _migrate_global_config_brand_path. Each test overrides it with a body
    that self-delivers SIGKILL via `kill -KILL $$` at the named step --
    deterministic, no sleep-and-race timing, and it exercises the REAL
    checkpoint call sites wired into the REAL function, not a re-derived
    approximation of its control flow.
    """

    SECRET_BODY = "CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\nCLAGENTIC_ROUTER_TOKEN=live-secret-value\n"

    def _kill_at(self, step_name):
        return (
            f'if [ "$1" = "{step_name}" ]; then kill -KILL $$; fi'
        )

    def _assert_no_file_other_than_600(self, exclude=()):
        for path, mode in _all_file_modes_under(self.home).items():
            if path in exclude:
                continue
            self.assertEqual(
                mode, 0o600,
                msg=f"{path} left at mode {oct(mode)}, not 600, after a kill mid-migration",
            )

    def _assert_config_recoverable_not_split(self):
        old_exists = os.path.isfile(self.old_config)
        new_exists = os.path.isfile(self.new_config)
        self.assertTrue(
            old_exists or new_exists,
            msg="config must be recoverable at the old OR new path after a kill -- found at neither",
        )
        if old_exists:
            with open(self.old_config) as f:
                self.assertEqual(f.read(), self.SECRET_BODY,
                                  msg="old-path content must be fully intact, not partially written")
        if new_exists:
            with open(self.new_config) as f:
                self.assertEqual(f.read(), self.SECRET_BODY,
                                  msg="new-path content must be fully intact, not partially written -- "
                                      "a partial/truncated write here would mean the kill landed mid-copy "
                                      "with no atomic guard, which _migrate_global_config_brand_path's temp"
                                      "-file-then-mv design must prevent")

    def _run_kill_then_rerun(self, step_name):
        self._write_old_config(self.SECRET_BODY)

        proc = self._run(
            "_migrate_global_config_brand_path; true",
            checkpoint_body=self._kill_at(step_name),
        )
        # A self-delivered SIGKILL surfaces to the parent as a negative
        # returncode (POSIX: -signum) under Python's subprocess -- never 0,
        # since the process never reaches its own `true`/exit.
        self.assertNotEqual(proc.returncode, 0,
                             msg=f"expected the checkpoint at {step_name!r} to actually kill the process")

        self._assert_config_recoverable_not_split()
        self._assert_no_file_other_than_600()

        # Re-run after the kill: must complete cleanly and idempotently,
        # converging on the same end state as an uninterrupted run.
        proc2 = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc2.returncode, 0, msg=proc2.stderr)
        self.assertFalse(os.path.exists(self.old_config),
                          msg="a clean re-run after the kill must finish the migration")
        with open(self.new_config) as f:
            self.assertEqual(f.read(), self.SECRET_BODY)
        self._assert_no_file_other_than_600()

        # Idempotency: a THIRD run (nothing left to do) must also be a
        # silent no-op, never re-touching or corrupting the result.
        proc3 = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc3.returncode, 0, msg=proc3.stderr)
        with open(self.new_config) as f:
            self.assertEqual(f.read(), self.SECRET_BODY)

    def test_kill_after_mkdir(self):
        """Killed right after the new parent directory is created, before
        any temp file exists. Old path must still hold the full config."""
        self._run_kill_then_rerun("after-mkdir")

    def test_kill_after_tmp_create(self):
        """Killed right after _secret_tmp_create makes the 600 temp file,
        before any content is written into it. Old path must still hold
        the full config; the empty 600 temp file is harmless orphan state."""
        self._run_kill_then_rerun("after-tmp-create")

    def test_kill_after_content_copied_before_mv(self):
        """Killed after the temp file holds the full copied content but
        BEFORE the atomic mv installs it at $GLOBAL_CONFIG -- the temp file
        is populated and 600, but is not yet the config; old path must
        still be the sole authoritative copy."""
        self._run_kill_then_rerun("after-content-copied")

    def test_kill_after_mv_before_old_removed(self):
        """Killed after the atomic mv lands the config at the NEW path
        (now fully authoritative) but before the old path is unlinked --
        both paths hold the full, identical, 600 content; a re-run must
        finish the cleanup, not re-copy or corrupt anything."""
        self._run_kill_then_rerun("after-mv-before-old-rm")

    def test_kill_before_cleanup_rm_in_both_exist_identical_path(self):
        """The both-paths-exist/identical-content cleanup branch (a
        redundant old copy after a prior kill, or a config manually copied
        into place) has its own checkpoint immediately before the final
        rm -- kill there and confirm both copies survive intact, then a
        re-run finishes the cleanup."""
        self._write_old_config(self.SECRET_BODY)
        os.makedirs(self.new_config_dir, exist_ok=True)
        with open(self.new_config, "w") as f:
            f.write(self.SECRET_BODY)
        os.chmod(self.new_config, 0o600)

        proc = self._run(
            "_migrate_global_config_brand_path; true",
            checkpoint_body=self._kill_at("before-cleanup-rm"),
        )
        self.assertNotEqual(proc.returncode, 0)

        self._assert_config_recoverable_not_split()
        self._assert_no_file_other_than_600()
        # Both must have survived this specific kill point (pre-rm).
        self.assertTrue(os.path.isfile(self.old_config))
        self.assertTrue(os.path.isfile(self.new_config))

        proc2 = self._run("_migrate_global_config_brand_path")
        self.assertEqual(proc2.returncode, 0, msg=proc2.stderr)
        self.assertFalse(os.path.exists(self.old_config))
        with open(self.new_config) as f:
            self.assertEqual(f.read(), self.SECRET_BODY)


class TestEndToEndViaRealCli(unittest.TestCase):
    """A smaller end-to-end pass proving the extracted functions above are
    actually wired into the shipped `update`/`init` dispatch, not merely
    correct in isolation. Every invocation here points CLAGENTIC_LITE_HOME
    at a throwaway git clone (per the HAZARD discipline, never the live
    checkout) and HOME at a fresh tempdir (never the operator's real HOME)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-gc-migrate-e2e-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)
        self.old_config = os.path.join(self.home, ".config", "clagentic", "config")
        self.new_config = os.path.join(self.home, ".config", "clagentic", "lite", "config")

    def _write_old_config(self, body):
        os.makedirs(os.path.dirname(self.old_config), exist_ok=True)
        with open(self.old_config, "w") as f:
            f.write(body)
        os.chmod(self.old_config, 0o600)

    def _run(self, argv, extra_env=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        # The overlaid clone (_clone_tool_home, scripts/test_support.py) is
        # unstaged-dirty against its own HEAD whenever this checkout has
        # uncommitted changes, tripping cmd_update's non-tty discard guard
        # (lr-55a27a) even though self.fake_tool_home is disposable
        # (shutil.rmtree'd in cleanup) -- no test in this class exercises
        # the discard-refusal behavior itself (test_update_nontty_discard_
        # guard.py owns that), so always allow it here rather than scrub it.
        env["CLAGENTIC_UPDATE_ALLOW_DISCARD"] = "1"
        env.pop("CLAGENTIC_ENV_LOADED", None)
        env.pop("CLAGENTIC_GLOBAL_ENV_LOADED", None)
        env.pop("CLAGENTIC_REPO_ENV_LOADED", None)
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite")] + argv,
            cwd=self.fake_tool_home,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_update_migrates_old_config_to_new_path(self):
        body = "CLAGENTIC_ROUTER_TOKEN=tok123\nCLAGENTIC_LITE_HOME=/fake/home\n"
        self._write_old_config(body)
        rc, out, err = self._run(["update"], extra_env={"CLAGENTIC_SKIP_FETCH": "1"})
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertFalse(os.path.exists(self.old_config))
        self.assertTrue(os.path.exists(self.new_config))
        with open(self.new_config) as f:
            self.assertEqual(f.read(), body)
        mode = stat.S_IMODE(os.stat(self.new_config).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertIn("migrated global config", out + err)

    def test_update_migration_never_leaks_a_configured_value(self):
        secret = "sk-live-secret-value-must-never-appear-in-output"
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=%s\n" % secret)
        rc, out, err = self._run(["update"], extra_env={"CLAGENTIC_SKIP_FETCH": "1"})
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, err)

    def test_doctor_warns_when_only_old_path_present(self):
        self._write_old_config("CLAGENTIC_ROUTER_TOKEN=tok123\n")
        rc, out, err = self._run(["doctor"])
        combined = out + err
        self.assertIn("deprecated brand-root path", combined, msg=combined)
        self.assertIn(self.old_config, combined)

    def test_doctor_clean_when_only_new_path_present(self):
        os.makedirs(os.path.dirname(self.new_config), exist_ok=True)
        with open(self.new_config, "w") as f:
            f.write("CLAGENTIC_ROUTER_TOKEN=tok123\n")
        os.chmod(self.new_config, 0o600)
        rc, out, err = self._run(["doctor"])
        combined = out + err
        self.assertIn("no legacy brand-root config found", combined, msg=combined)
        self.assertNotIn("deprecated brand-root path", combined)

    def test_init_on_unmigrated_install_migrates_rather_than_reprompting(self):
        body = "CLAGENTIC_ROUTER_TOKEN=tok123\nCLAGENTIC_LITE_HOME=/fake/home\n"
        self._write_old_config(body)
        rc, out, err = self._run(["init"])
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertFalse(os.path.exists(self.old_config))
        self.assertTrue(os.path.exists(self.new_config))
        with open(self.new_config) as f:
            after = f.read()
        self.assertIn("CLAGENTIC_ROUTER_TOKEN=tok123", after,
                       msg="init on an un-migrated install must preserve the existing config, "
                           "not silently re-prompt and discard it")

    def test_init_on_failed_migration_never_writes_divergent_new_config(self):
        """lore task lr-7939f8 comment #2 fold-in (BOBBIE bobbie.uncat.1):
        cmd_init's front-door gate used to check only `[ -f "$GLOBAL_CONFIG" ]`,
        never whether the migration it just ran actually SUCCEEDED. On a
        migration failure the old file is correctly left intact, but a plain
        file-presence check can't tell "migration never ran/succeeded" apart
        from "no config exists yet" -- falling through to _write_global_config
        would write a FRESH config at the new path alongside the operator's
        real, untouched credentials at the old path: exactly the
        both-paths-diverged state _migrate_global_config_brand_path itself
        refuses to create when it detects it directly, reached by a
        different route.

        Injection: the migration target's parent ("lite") pre-exists as a
        regular FILE where a directory is needed, so `mkdir -p` fails with
        ENOTDIR -- a type conflict, not a permission check, so this
        reproduces identically whether or not the test runs as root (unlike
        a chmod-based injection, which root bypasses -- see the read-only
        skipIf elsewhere in this file)."""
        body = "CLAGENTIC_ROUTER_TOKEN=REAL-SECRET-VALUE\n"
        self._write_old_config(body)
        lite_path = os.path.dirname(self.new_config)
        with open(lite_path, "w") as f:
            f.write("not a directory\n")

        rc, out, err = self._run(["init"])

        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertFalse(
            os.path.exists(self.new_config),
            msg="a failed migration must never leave a divergent fresh config at the new path",
        )
        self.assertTrue(
            os.path.isfile(self.old_config),
            msg="the operator's real config must survive untouched at the old path",
        )
        with open(self.old_config) as f:
            self.assertEqual(f.read(), body,
                              msg="old-path content must be byte-identical, not partially written or clobbered")
        combined = out + err
        self.assertIn(self.old_config, combined,
                       msg="the refusal must name the old path where the config actually is")
        self.assertNotIn("REAL-SECRET-VALUE", combined,
                          msg="no configured VALUE may appear in output, including this refusal path")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                      "running as root -- permission bits do not block root's "
                      "own writes, so this scenario cannot be exercised here; "
                      "test_init_on_failed_migration_never_writes_divergent_new_config "
                      "above covers the same defect via a root-proof injection")
    def test_init_on_migration_dir_creation_denied_never_writes_divergent_new_config(self):
        """Companion to the test above using a permission-bit injection
        (closer to a real-world unwritable-HOME scenario) rather than a
        type conflict -- skipped under root, where chmod cannot block the
        process's own writes."""
        body = "CLAGENTIC_ROUTER_TOKEN=REAL-SECRET-VALUE\n"
        self._write_old_config(body)
        clagentic_dir = os.path.dirname(os.path.dirname(self.new_config))
        os.chmod(clagentic_dir, 0o500)
        self.addCleanup(os.chmod, clagentic_dir, 0o700)

        rc, out, err = self._run(["init"])

        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertFalse(os.path.exists(self.new_config))
        self.assertTrue(os.path.isfile(self.old_config))
        with open(self.old_config) as f:
            self.assertEqual(f.read(), body)


if __name__ == "__main__":
    unittest.main()
