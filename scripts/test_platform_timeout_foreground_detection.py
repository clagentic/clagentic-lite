"""
Regression coverage for lr-c65d8a (successor to lr-da3b7e). Covers TWO
generations of this fix -- see platform.sh's own comment at the detection
site for the full narrative:

GENERATION 1 (superseded): capability-detect `--foreground` into
DS_TIMEOUT_CMD itself, so "every caller picks it up for free".

GENERATION 2 (this file, current): PEACHES PR #214 review (finding 2,
verified independently by HOLDEN) found generation 1 traded lr-da3b7e's tty
assumption for a TIMEOUT-SEMANTICS assumption repo-wide -- --foreground
changes what `timeout` bounds (GNU's own --help: "children of COMMAND will
not be timed out" in foreground mode), so mutating DS_TIMEOUT_CMD silently
converted whole-process-group bounding into direct-child-only bounding for
every consumer, including scripts/gates.sh's run_bounded and
scripts/llm-client.sh's claude/codex/curl calls -- none of which have the
tty problem, all of which need to catch a hung DESCENDANT.

THE FIX NOW: DS_TIMEOUT_CMD is left COMPLETELY UNCHANGED (never gains
--foreground, whole-process-group bounding exactly as before lr-c65d8a). A
SEPARATE variable, DS_TIMEOUT_FOREGROUND_CMD, carries the capability-detected
--foreground augmentation, used only by the small set of callers
(bin/clagentic-lite's `claude plugin ...`/`claude --version` probes) that
actually touch a controlling terminal.

WHY --foreground MATTERS AT ALL (see platform.sh's own comment at the
detection site for the full mechanism): GNU/BSD `timeout` without
--foreground puts the wrapped command in a NEW PROCESS GROUP, so a command
that touches the controlling terminal (e.g. `claude`) gets SIGTTIN/SIGTTOU
and STOPS -- a stopped process cannot receive the SIGTERM `timeout` sends at
expiry, so the guard never fires and the call hangs forever in any
interactive terminal. --foreground keeps the wrapped command in timeout's
own foreground process group, avoiding the stop -- but only for its own
DIRECT CHILD, which is why it must not be applied to the generic bounding
primitive.

THIS FILE tests the DETECTION MECHANISM ITSELF against fake `timeout`
binaries whose --help output is controlled by the test -- proving
DS_TIMEOUT_FOREGROUND_CMD picks up `--foreground` when the binary advertises
it and falls back to the bare command when it does not (older coreutils, or
a `gtimeout` build without the flag), never assuming either way, AND proving
DS_TIMEOUT_CMD never gains the flag regardless. The SIGTTIN reproduction
itself (proving the fix's real-world effect) lives in
scripts/test_timeout_foreground_pty_regression.py, which drives a real pty.

Run with: python3 -m unittest scripts.test_platform_timeout_foreground_detection -v
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def _write_fake_timeout(bin_dir, name, supports_foreground, argv_file=None):
    """Fake `timeout`/`gtimeout` binary. --help output includes the
    --foreground line iff supports_foreground is True. If argv_file is
    given, every real invocation (not --help) appends its argv there before
    running the wrapped command, so a caller can assert what shape of
    invocation platform.sh actually produced."""
    path = os.path.join(bin_dir, name)
    help_text = (
        "Usage: timeout [OPTION] DURATION COMMAND [ARG]...\n"
        + ("  --foreground   when not running timeout directly from a shell prompt,\n"
           "                 allow COMMAND to read from the terminal and get TTY signals\n"
           if supports_foreground else "")
        + "  -k, --kill-after=DURATION\n"
        + "  --help     display this help and exit\n"
    )
    record_line = (
        f"printf '%s\\n' \"$*\" >> '{argv_file}'\n" if argv_file else ""
    )
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--help" ]; then
              cat <<'EOF'
{help_text}EOF
              exit 0
            fi
            {record_line}
            if [ "$1" = "--foreground" ]; then shift; fi
            shift  # duration
            "$@"
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


class _PlatformShDetectionTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-platform-fg-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin_dir = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin_dir)
        self.argv_file = os.path.join(self.tmp, "timeout-argv.log")
        open(self.argv_file, "w").close()

    def _run_and_print_var(self, var_name, extra_path=""):
        env = os.environ.copy()
        env["PATH"] = self.bin_dir + (os.pathsep + extra_path if extra_path else "") \
            + os.pathsep + "/usr/bin:/bin"
        script = f". '{PLATFORM_SH}'\nprintf '%s' \"${var_name}\"\n"
        result = subprocess.run(
            ["sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, env=env,
        )
        return result


class TestDsTimeoutCmdNeverGainsForeground(_PlatformShDetectionTestBase):
    """THE NARROWING (lr-c65d8a generation 2, PEACHES PR #214 finding 2):
    DS_TIMEOUT_CMD, the generic whole-process-group bounding primitive
    consumed by scripts/gates.sh's run_bounded and scripts/llm-client.sh,
    must stay bare regardless of what the local timeout binary advertises
    -- --foreground is scoped to DS_TIMEOUT_FOREGROUND_CMD only."""

    def test_ds_timeout_cmd_stays_bare_even_when_foreground_supported(self):
        _write_fake_timeout(self.bin_dir, "timeout", supports_foreground=True,
                             argv_file=self.argv_file)
        result = self._run_and_print_var("DS_TIMEOUT_CMD")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "timeout",
            f"DS_TIMEOUT_CMD must never gain --foreground -- that would "
            f"silently narrow every consumer (run_bounded, llm-client.sh) "
            f"from whole-process-group to direct-child-only bounding; "
            f"stderr={result.stderr!r}",
        )

    def test_ds_timeout_cmd_stays_bare_gtimeout_too(self):
        _write_fake_timeout(self.bin_dir, "gtimeout", supports_foreground=True,
                             argv_file=self.argv_file)
        minimal_dir = os.path.join(self.tmp, "minimal-bin")
        os.makedirs(minimal_dir)
        for tool in ("uname", "grep", "sed", "date", "stat", "wc", "tr", "cat"):
            for real_dir in ("/usr/bin", "/bin"):
                real_path = os.path.join(real_dir, tool)
                if os.path.exists(real_path):
                    os.symlink(real_path, os.path.join(minimal_dir, tool))
                    break
        env = os.environ.copy()
        env["PATH"] = self.bin_dir + os.pathsep + minimal_dir
        script = f". '{PLATFORM_SH}'\nprintf '%s' \"$DS_TIMEOUT_CMD\"\n"
        result = subprocess.run(
            ["/bin/sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "gtimeout", result.stderr)


class TestDsTimeoutForegroundCmdDetectsForegroundSupport(_PlatformShDetectionTestBase):
    def test_gains_foreground_flag_when_supported(self):
        _write_fake_timeout(self.bin_dir, "timeout", supports_foreground=True,
                             argv_file=self.argv_file)
        result = self._run_and_print_var("DS_TIMEOUT_FOREGROUND_CMD")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "timeout --foreground",
            f"expected DS_TIMEOUT_FOREGROUND_CMD to include --foreground "
            f"when the local timeout advertises it; stderr={result.stderr!r}",
        )

    def test_gtimeout_also_gains_foreground_flag_when_supported(self):
        """BSD `gtimeout` (macOS coreutils) is a separate probe path from
        GNU `timeout` -- must be detected independently, not assumed to
        inherit `timeout`'s result. PATH is restricted to this test's own
        stub dir (no real `timeout` binary present) so platform.sh's
        `command -v timeout` check genuinely falls through to the
        `gtimeout` branch, the same way a real macOS-without-coreutils-
        timeout host would."""
        _write_fake_timeout(self.bin_dir, "gtimeout", supports_foreground=True,
                             argv_file=self.argv_file)
        # `timeout` itself must be UNRESOLVABLE -- otherwise platform.sh's
        # `command -v timeout` check, which runs before the gtimeout
        # branch, would resolve to a real system `timeout` first and this
        # test would never exercise the gtimeout branch at all. Build a
        # minimal PATH containing ONLY this test's stub dir (which has
        # gtimeout but deliberately no `timeout`) plus a throwaway dir
        # symlinking just the other binaries platform.sh needs
        # (uname/grep/sed/date/stat/wc), so real /usr/bin:/bin -- which
        # does carry a real `timeout` on most hosts -- never appears on
        # PATH at all.
        minimal_dir = os.path.join(self.tmp, "minimal-bin")
        os.makedirs(minimal_dir)
        for tool in ("uname", "grep", "sed", "date", "stat", "wc", "tr", "cat"):
            for real_dir in ("/usr/bin", "/bin"):
                real_path = os.path.join(real_dir, tool)
                if os.path.exists(real_path):
                    os.symlink(real_path, os.path.join(minimal_dir, tool))
                    break
        env = os.environ.copy()
        env["PATH"] = self.bin_dir + os.pathsep + minimal_dir
        script = f". '{PLATFORM_SH}'\nprintf '%s' \"$DS_TIMEOUT_FOREGROUND_CMD\"\n"
        result = subprocess.run(
            ["/bin/sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "gtimeout --foreground", result.stderr)


class TestDsTimeoutForegroundCmdFallsBackWithoutAssuming(_PlatformShDetectionTestBase):
    def test_stays_bare_when_foreground_unsupported(self):
        """An older timeout build (pre coreutils 8.13) or a gtimeout build
        without --foreground must NOT get the flag appended -- appending it
        unconditionally would swap lr-da3b7e's tty assumption for an
        unverified coreutils-version assumption, the exact mistake the
        operator directive (lr-c65d8a seq 1) forbids."""
        _write_fake_timeout(self.bin_dir, "timeout", supports_foreground=False,
                             argv_file=self.argv_file)
        result = self._run_and_print_var("DS_TIMEOUT_FOREGROUND_CMD")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "timeout",
            f"expected DS_TIMEOUT_FOREGROUND_CMD to stay bare 'timeout' "
            f"when --foreground is not advertised; stderr={result.stderr!r}",
        )

    def test_no_timeout_binary_still_fails_closed(self):
        """INV-1a must be untouched by this detection: no timeout/gtimeout
        on PATH still resolves BOTH DS_TIMEOUT_CMD and
        DS_TIMEOUT_FOREGROUND_CMD to ds_timeout_missing, never a bare
        pass-through and never a crash in the --help probe itself."""
        env = os.environ.copy()
        env["PATH"] = "/nonexistent-empty-path-for-test"
        script = (
            f". '{PLATFORM_SH}'\n"
            f"printf '%s|%s' \"$DS_TIMEOUT_CMD\" \"$DS_TIMEOUT_FOREGROUND_CMD\"\n"
        )
        result = subprocess.run(
            ["/bin/sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "ds_timeout_missing|ds_timeout_missing", result.stderr
        )


class TestDetectedFlagActuallyThreadsThroughDurationAndCommand(_PlatformShDetectionTestBase):
    def test_foreground_flag_precedes_duration_and_command_still_runs(self):
        """Proves the resulting two-word DS_TIMEOUT_FOREGROUND_CMD value
        word-splits correctly at a real call site shape
        ($DS_TIMEOUT_FOREGROUND_CMD "$DURATION" cmd...), matching every
        caller's unquoted invocation -- not just that the printed variable
        value looks right."""
        _write_fake_timeout(self.bin_dir, "timeout", supports_foreground=True,
                             argv_file=self.argv_file)
        marker = os.path.join(self.tmp, "ran")
        env = os.environ.copy()
        env["PATH"] = self.bin_dir + os.pathsep + "/usr/bin:/bin"
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            $DS_TIMEOUT_FOREGROUND_CMD 5 touch '{marker}'
        """)
        result = subprocess.run(
            ["sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.exists(marker),
                         "wrapped command never ran through the "
                         "--foreground-augmented DS_TIMEOUT_FOREGROUND_CMD")
        with open(self.argv_file) as f:
            argv = f.read()
        self.assertIn("--foreground 5 touch", argv, f"recorded argv={argv!r}")

    def test_ds_timeout_cmd_call_site_shape_never_carries_foreground(self):
        """Same call-site shape, but through DS_TIMEOUT_CMD -- proves a
        run_bounded/llm-client.sh-style caller's invocation never carries
        --foreground even when the local timeout supports it."""
        _write_fake_timeout(self.bin_dir, "timeout", supports_foreground=True,
                             argv_file=self.argv_file)
        marker = os.path.join(self.tmp, "ran")
        env = os.environ.copy()
        env["PATH"] = self.bin_dir + os.pathsep + "/usr/bin:/bin"
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            $DS_TIMEOUT_CMD 5 touch '{marker}'
        """)
        result = subprocess.run(
            ["sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.exists(marker))
        with open(self.argv_file) as f:
            argv = f.read()
        self.assertNotIn("--foreground", argv, f"recorded argv={argv!r}")
        self.assertIn("5 touch", argv, f"recorded argv={argv!r}")


if __name__ == "__main__":
    unittest.main()
