"""
Regression tests for GH #174 / lr-24f649: all six hook shim templates in
share/hook-shims/ guarded their `. "$CLAGENTIC_LITE_HOME/scripts/platform.sh"`
source with a pattern that does not survive dash/POSIX sh:

    : "${CLAGENTIC_LITE_HOME:=__CLAGENTIC_LITE_HOME__}"
    . "$CLAGENTIC_LITE_HOME/scripts/platform.sh" 2>/dev/null || true

Two independent defects, both fixed here:

  1. `:=` only fires when the var is UNSET. A stale/wrong CLAGENTIC_LITE_HOME
     left in ~/.bashrc or ~/.config/clagentic/lite/config (e.g. after the
     CLAGENTIC_HOME -> CLAGENTIC_LITE_HOME rename) is never validated.
  2. `.` is a POSIX special builtin. Under dash (and any POSIX-conformant
     shell -- NOT bash, which does not reproduce this), a file-not-found
     inside a bare `.` is a FATAL shell error that terminates the process
     immediately: exit 2, zero bytes of stdout AND stderr. `|| true`,
     `|| exit 0`, and `if ! . ...` all fail to catch it because control
     never returns to them, and the preceding `2>/dev/null` swallows dash's
     own diagnostic on the way out -- net effect: an undiagnosable silent
     abort.

The fix replaces every occurrence with an explicit existence guard
(`[ -f "$X" ] && . "$X"`, never a bare `.` relying on `||`), plus a
CLAGENTIC_LITE_HOME validation that emits an actionable message to stderr
naming the bad value and pointing at `clagentic-lite doctor` plus the two
usual drift sites (~/.bashrc, ~/.config/clagentic/lite/config) on failure.

Scope note: the upstream issue reported only session-start.sh and
prompt-inject.sh, but the same fatal pattern (in three shape variants: bare
`|| true`, bare `|| exit 0`, and `if ! . ... 2>/dev/null`) existed in all
six templates. This file sweeps all six -- discovered via
share/hook-shims/*.sh.template glob, never a hardcoded list -- so a future
seventh hook script (or a regression reintroducing the bare-`.`-with-||`
idiom in any of the six) is caught here rather than only at the two
originally-reported sites.

Each hook's asserted posture matches its PRE-EXISTING failure design
(unchanged by this fix, per AGENTS.md non-negotiable 3 -- fail-closed vs
fail-open is never flipped without asking):
  - session-start.sh, prompt-inject.sh, stop-summarize.sh,
    post-tool-nudge.sh: non-blocking informational/async hooks -- must
    exit 0.
  - pre-bash-guard.sh, pre-write-guard.sh: PreToolUse guards that fail
    OPEN by design when platform.sh is unavailable (call allowed,
    unaudited) -- must also exit 0, never exit 2, on a stale
    CLAGENTIC_LITE_HOME (a hard fail-closed here would be a posture flip
    the task explicitly forbids).

None of the six should ever reproduce the pre-fix signature: exit code 2
with EMPTY stdout and EMPTY stderr (the "undiagnosable" failure mode named
in the issue). Every one of them must now emit an actionable stderr
message identifying the bad CLAGENTIC_LITE_HOME value.

These tests invoke the ACTUAL templates via `dash` subprocess (not bash --
bash's `.` on a missing file returns 1, it does not abort the process, so a
bash-only test suite would never have caught this class of defect in the
first place). Templates are exercised directly with __CLAGENTIC_LITE_HOME__
substituted out via the CLAGENTIC_LITE_HOME env var default-assignment
idiom itself (same mechanism _stamp_claude_hooks uses), so a diff review
sees exactly the file under test.

Run with: python3 -m unittest scripts/test_hook_shim_stale_home_no_abort.py -v
"""
import glob
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HOOK_SHIMS_DIR = os.path.join(TOOL_HOME, "share", "hook-shims")
DASH = shutil.which("dash") or "/usr/bin/dash"

# Discover every hook shim template via glob -- never a hardcoded list, per
# AGENTS.md's "Sweeping-test discovery convention" and the task's own "fix
# the pattern, not the two reported lines" instruction.
HOOK_SHIM_TEMPLATES = sorted(
    glob.glob(os.path.join(HOOK_SHIMS_DIR, "*.sh.template"))
)

# Hooks whose pre-existing, unchanged-by-this-fix posture is fail-OPEN when
# platform.sh cannot be sourced (guard rules stay unenforced, but the tool
# call is still allowed through -- AGENTS.md non-negotiable 3).
FAIL_OPEN_GUARD_HOOKS = {"pre-bash-guard.sh.template", "pre-write-guard.sh.template"}

NONEXISTENT_HOME = "/tmp/nonexistent-clagentic-lr24f649"


class TestHookShimSurvivesStaleHomeUnderDash(unittest.TestCase):
    """env -i CLAGENTIC_LITE_HOME=/tmp/nonexistent-clagentic <shim>, run
    under dash (not bash -- bash does not reproduce the special-builtin
    abort), must never silently exit 2 with empty stdout/stderr."""

    def setUp(self):
        self.assertTrue(
            os.path.isfile(DASH),
            f"dash not found at {DASH} -- this regression only reproduces "
            f"under a POSIX-conformant shell, not bash",
        )
        self.assertGreaterEqual(
            len(HOOK_SHIM_TEMPLATES), 6,
            f"expected at least the six known hook shim templates, found "
            f"{len(HOOK_SHIM_TEMPLATES)}: {HOOK_SHIM_TEMPLATES}",
        )

    def _run_under_dash_with_stale_home(self, template_path, stdin_payload=""):
        """Run `template_path` under dash with a minimal env (equivalent to
        `env -i`) plus a nonexistent CLAGENTIC_LITE_HOME, exactly matching
        the issue's repro: `env -i CLAGENTIC_LITE_HOME=/tmp/nonexistent-clagentic <shim>`.
        A minimal env is used (not os.environ) because the whole point of
        `env -i` in the repro is to prove the guard doesn't depend on an
        ambient PATH/HOME masking the defect."""
        minimal_env = {
            "CLAGENTIC_LITE_HOME": NONEXISTENT_HOME,
            "PATH": "/usr/bin:/bin",
            "HOME": tempfile.mkdtemp(prefix="clagentic-test-hookshim-home-"),
        }
        proc = subprocess.run(
            [DASH, template_path],
            input=stdin_payload,
            env=minimal_env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_no_template_reproduces_the_silent_exit_2(self):
        """Sweep: none of the six templates may exit 2 with BOTH stdout and
        stderr empty -- that exact signature is the undiagnosable abort
        this task exists to close."""
        failures = []
        for template_path in HOOK_SHIM_TEMPLATES:
            name = os.path.basename(template_path)
            rc, out, err = self._run_under_dash_with_stale_home(template_path)
            if rc == 2 and out == "" and err == "":
                failures.append(name)
        self.assertEqual(
            failures, [],
            f"these hook shim templates reproduced the silent dash "
            f"special-builtin abort (exit 2, empty stdout, empty stderr) "
            f"on a stale CLAGENTIC_LITE_HOME: {failures}",
        )

    def test_non_blocking_hooks_exit_zero_on_stale_home(self):
        """session-start, prompt-inject, stop-summarize, post-tool-nudge
        are non-blocking by design -- a stale CLAGENTIC_LITE_HOME must still
        exit 0."""
        for template_path in HOOK_SHIM_TEMPLATES:
            name = os.path.basename(template_path)
            if name in FAIL_OPEN_GUARD_HOOKS:
                continue
            with self.subTest(hook=name):
                rc, out, err = self._run_under_dash_with_stale_home(template_path)
                self.assertEqual(
                    rc, 0,
                    f"{name}: non-blocking hook must exit 0 on stale "
                    f"CLAGENTIC_LITE_HOME, got rc={rc} stdout={out!r} "
                    f"stderr={err!r}",
                )

    def test_guard_hooks_fail_open_not_closed_on_stale_home(self):
        """pre-bash-guard and pre-write-guard fail OPEN by design when
        platform.sh is unavailable (unenforced but not blocking) -- this
        fix must not flip that to fail-closed (AGENTS.md non-negotiable 3).
        A stale CLAGENTIC_LITE_HOME must exit 0 (allow), never 2 (block)."""
        for name in sorted(FAIL_OPEN_GUARD_HOOKS):
            template_path = os.path.join(HOOK_SHIMS_DIR, name)
            self.assertTrue(os.path.isfile(template_path), template_path)
            with self.subTest(hook=name):
                # Both guards read a JSON payload from stdin; an empty
                # payload short-circuits before the fail-open path even
                # matters for the JSON-parse branch, but the platform.sh
                # source guard runs before that read, so this still
                # exercises the exact code path under test.
                rc, out, err = self._run_under_dash_with_stale_home(
                    template_path, stdin_payload=""
                )
                self.assertEqual(
                    rc, 0,
                    f"{name}: fail-OPEN guard hook must exit 0 (allow, "
                    f"unaudited) on stale CLAGENTIC_LITE_HOME, not block "
                    f"with a posture flip to fail-closed. Got rc={rc} "
                    f"stdout={out!r} stderr={err!r}",
                )

    def test_stale_home_produces_actionable_stderr(self):
        """Every hook must name the bad CLAGENTIC_LITE_HOME value and point
        at `clagentic-lite doctor` plus the two usual drift sites on a
        stale/unresolvable CLAGENTIC_LITE_HOME -- required by the task spec,
        distinct from the old undiagnosable silent-exit-2 behavior."""
        for template_path in HOOK_SHIM_TEMPLATES:
            name = os.path.basename(template_path)
            with self.subTest(hook=name):
                rc, out, err = self._run_under_dash_with_stale_home(template_path)
                self.assertIn(
                    NONEXISTENT_HOME, err,
                    f"{name}: stderr should name the bad CLAGENTIC_LITE_HOME "
                    f"value ({NONEXISTENT_HOME!r}). stdout={out!r} "
                    f"stderr={err!r}",
                )
                self.assertIn(
                    "clagentic-lite doctor", err,
                    f"{name}: stderr should point at `clagentic-lite doctor`. "
                    f"stderr={err!r}",
                )
                self.assertIn(
                    "~/.bashrc", err,
                    f"{name}: stderr should name ~/.bashrc as a usual drift "
                    f"site. stderr={err!r}",
                )
                self.assertIn(
                    "~/.config/clagentic/lite/config", err,
                    f"{name}: stderr should name ~/.config/clagentic/lite/config "
                    f"as a usual drift site. stderr={err!r}",
                )


class TestHookShimStillWorksWithValidHome(unittest.TestCase):
    """Sanity check: the existence-guard fix does not regress the happy
    path -- a valid CLAGENTIC_LITE_HOME must still source platform.sh."""

    def test_valid_home_sources_platform_sh_without_error(self):
        # Use pre-write-guard.sh.template with a minimal but valid payload
        # from outside any repo -- W-002's "cannot determine repo root"
        # fail-closed path is a DIFFERENT, pre-existing rule, not the
        # platform.sh-sourcing guard under test here, so we only assert
        # platform.sh loaded (ds_json_field available -> JF_EXIT handling
        # runs) rather than a specific W-00x outcome.
        template_path = os.path.join(
            HOOK_SHIMS_DIR, "pre-write-guard.sh.template"
        )
        minimal_env = {
            "CLAGENTIC_LITE_HOME": TOOL_HOME,
            "PATH": "/usr/bin:/bin",
            "HOME": tempfile.mkdtemp(prefix="clagentic-test-hookshim-home-"),
        }
        proc = subprocess.run(
            [DASH, template_path],
            input="{}",
            env=minimal_env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        # {} has no file_path -> RAW_PATH empty -> early "exit 0" before any
        # block() path. If platform.sh failed to source, ds_json_field
        # would be undefined and the script would error differently; exit 0
        # with no "CLAGENTIC_LITE_HOME does not resolve" stderr proves the
        # guard took the sourcing branch, not the missing-checkout branch.
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr!r}")
        self.assertNotIn("does not resolve to a real checkout", proc.stderr)


if __name__ == "__main__":
    unittest.main()
