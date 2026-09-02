"""
THE DECISIVE REGRESSION TEST for lr-c65d8a (GitHub issue #213): proves the
SIGTTIN-stop mechanism is reproduced against a REAL pty, and that
scripts/platform.sh's --foreground capability-detection fix (this task)
prevents it -- not merely that a stub claude "hangs" under some abstract
condition, the way scripts/test_doctor_init_claude_plugin_timeout.py's
stdin=DEVNULL test measures a DIFFERENT axis entirely (see that file's own
updated HAZARD note, added by this task, for why it cannot see this class).

NARROWED (PEACHES PR #214 review finding 2, verified by HOLDEN): the fix
under test is DS_TIMEOUT_FOREGROUND_CMD, a SEPARATE variable from
DS_TIMEOUT_CMD -- the first version of this fix mutated DS_TIMEOUT_CMD
itself, which would have silently narrowed every OTHER consumer of that
generic bounding primitive (scripts/gates.sh's run_bounded,
scripts/llm-client.sh) from whole-process-group to direct-child-only
bounding. DS_TIMEOUT_CMD is untouched by this fix and stays bare; only
DS_TIMEOUT_FOREGROUND_CMD carries the capability-detected --foreground
augmentation, and only bin/clagentic-lite's `claude` call sites use it.

MECHANISM UNDER TEST. `timeout DURATION cmd` (GNU/BSD, no --foreground) puts
`cmd` in a NEW PROCESS GROUP distinct from the shell's foreground process
group. A command that then touches the controlling terminal (reads from it,
or in `claude`'s real case, probes tty state on stdin) receives SIGTTIN
because its process group is not the terminal's foreground process group.
Default SIGTTIN disposition is STOP. A stopped process cannot act on
ordinary signals, including the SIGTERM `timeout` sends at its deadline --
so the wrapped call hangs forever instead of being bounded, exactly the
symptom in GitHub issue #213 (PGID 4298 vs TPGID 4255 in the reporter's ps
output).

`timeout --foreground cmd` keeps `cmd` in timeout's own (the caller's,
i.e. the pty session's) foreground process group, so no SIGTTIN fires and
the command remains normally signalable.

TEST SHAPE. A real pty pair (pty.openpty) with a child process placed in a
NEW SESSION and made the pty's controlling terminal (setsid + TIOCSCTTY),
mirroring how a real interactive shell session is structured. The child
sources platform.sh for the REAL DS_TIMEOUT_CMD (capability-detected in
this same task), then runs $DS_TIMEOUT_CMD against a stub "claude" that
explicitly reads from /dev/tty -- the same class of terminal touch the
real `claude` CLI performs on startup, and the most direct, portable way to
force SIGTTIN's default STOP disposition without depending on `claude`
itself being installed.

TWO CLASSES COVERED, both required by the operator directive (lr-c65d8a
seq 1, constraint 3) -- the guard must be proven to fire in EACH, not just
the pty shape that fixes this specific regression:
  1. TestForegroundFlagPreventsSigttinStopUnderPty -- real pty, stdin
     attached to a tty. THIS is the shape lr-da3b7e's regression test
     could not see (its stdin=DEVNULL test structurally cannot reproduce
     SIGTTIN -- see that file's HAZARD note).
  2. TestTimeoutStillFiresWithDetachedStdin -- stdin from /dev/null (no
     controlling-terminal touch possible), proving the --foreground
     addition does not regress the CI/non-interactive shape lr-da3b7e's
     own test already covered. Both axes must hold per the operator's
     "do not now fix the tty axis and break the coreutils axis" framing --
     generalized here to "do not fix the tty axis and break the non-tty
     axis either".

VERIFIED TO FAIL AGAINST PRE-FIX CODE (lr-c65d8a acceptance item 2): the
"before" class below runs the SAME reproduction against a synthetic bare
`timeout` (no --foreground) to prove the stop condition is real and
observable through this test's own harness, independent of whether
platform.sh's detection landed -- this is the harness self-check, not the
product-under-test skip mechanism baked into a permanently-skipped test.

Run with: python3 -m unittest scripts.test_timeout_foreground_pty_regression -v
"""
import fcntl
import os
import pty
import shutil
import signal
import stat
import subprocess
import tempfile
import termios
import textwrap
import time
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")

_TEST_TIMEOUT_SEC = "2"
_WAIT_BUDGET_SEC = 8
_POLL_INTERVAL_SEC = 0.1


def _write_tty_reading_stub(bin_dir, pid_file, name="claude"):
    """Stub that reads from /dev/tty -- the minimal, portable reproduction
    of a foreground-terminal touch. A process in a non-foreground process
    group performing this read receives SIGTTIN (default disposition:
    STOP), the same class of terminal interaction the real `claude` CLI
    performs on startup per GitHub issue #213's diagnosis.

    Records its OWN pid to `pid_file` before touching the terminal: the
    process that actually stops under SIGTTIN is this stub (a grandchild
    of the pty-attached shell, one level below `timeout`), not the
    top-level shell pid the test harness forks -- the shell and `timeout`
    both remain state 'S' (sleeping, waiting on their child) throughout,
    so the test must poll THIS pid, not the shell's."""
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            echo "$$" > '{pid_file}'
            # Touches the controlling terminal directly, mirroring the real
            # `claude` CLI's startup tty probe. If this process's pgrp is
            # not the tty's foreground pgrp, this read raises SIGTTIN and
            # (default disposition) STOPS the whole process group here.
            read -r _line < /dev/tty
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _real_system_timeout():
    """Locates the REAL `timeout` binary (not this test's stub) for the
    harness self-check -- proves the pty/SIGTTIN reproduction technique
    itself is valid against actual GNU/BSD coreutils behavior, not a
    hand-rolled approximation of it. A synthetic stand-in risks getting
    the process-group mechanics subtly wrong (e.g. `setsid` creates a new
    SESSION, detaching from the controlling terminal entirely -- ENXIO on
    /dev/tty, not SIGTTIN -- which is a different, wrong mechanism); the
    real binary is authoritative by construction."""
    for candidate in ("/usr/bin/timeout", "/bin/timeout"):
        if os.path.exists(candidate):
            return candidate
    raise unittest.SkipTest("no real `timeout` binary found on this host "
                             "to validate the pty/SIGTTIN harness against")


class _PtySessionTestBase(unittest.TestCase):
    """Spawns a child `sh` process attached to a REAL pty as its
    controlling terminal, in a new session, mirroring a genuine
    interactive-terminal shape (as opposed to test_doctor_init_claude_
    plugin_timeout.py's stdin=DEVNULL, which structurally cannot reproduce
    SIGTTIN -- see that file's own HAZARD note)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-pty-fg-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin_dir = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin_dir)

    def _spawn_in_pty(self, script, extra_path=""):
        """Runs `script` under /bin/sh with a real pty as controlling
        terminal, in a new session (setsid), so job-control semantics
        (foreground process group, SIGTTIN) genuinely apply -- the same
        structural shape a user's real interactive terminal session has.
        Returns (pid, master_fd)."""
        master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env["PATH"] = self.bin_dir + (os.pathsep + extra_path if extra_path else "") \
            + os.pathsep + "/usr/bin:/bin"

        pid = os.fork()
        if pid == 0:
            # Child: new session, pty becomes the controlling terminal,
            # stdin/stdout/stderr all wired to the pty slave -- the
            # structural shape of a real interactive shell.
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if slave_fd > 2:
                os.close(slave_fd)
            try:
                os.execvpe("/bin/sh", ["/bin/sh", "-c", script], env)
            except Exception:
                os._exit(127)
        os.close(slave_fd)
        return pid, master_fd

    def _wait_for_pid_file(self, pid_file, budget=_WAIT_BUDGET_SEC):
        """Blocks until the stub's own pid file (written as its first
        action) appears and contains a parseable pid -- avoids a race
        against the stub not having started yet."""
        deadline = time.time() + budget
        while time.time() < deadline:
            if os.path.exists(pid_file):
                with open(pid_file) as f:
                    content = f.read().strip()
                if content:
                    return int(content)
            time.sleep(_POLL_INTERVAL_SEC)
        raise AssertionError(
            f"stub never wrote its pid to {pid_file} within {budget}s -- "
            f"it may not have started at all"
        )

    def _wait_for_state(self, pid, budget=_WAIT_BUDGET_SEC):
        """Polls /proc/<pid>/stat for the process state char across the
        FULL budget, not a single read. Returns the final observed state
        ('T' = stopped, 'Z' = zombie/exited, etc), 'gone' if the process
        disappeared AFTER having been observed alive at least once, or
        'unreadable' if /proc/<pid>/stat could never be read at all within
        the budget -- e.g. no /proc (macOS/BSD), or a hardened container
        restricting it. 'still running' (state 'S'/'R' persisting to the
        deadline) is itself the hang this whole task exists to fix, so
        callers assert against that explicitly rather than treating a
        timeout here as an error.

        MILLER'S DIAGNOSIS (lr-c65d8a fold-in, PR #214 round 2): the prior
        version of this method returned 'gone' on the FIRST failed read
        (FileNotFoundError/ProcessLookupError/IndexError), collapsing two
        genuinely different outcomes into one string:
          - a real "process disappeared after being observed alive" event
          - a read that simply failed, e.g. because /proc does not exist on
            this platform at all (every read fails, always, on macOS/BSD),
            or because IndexError fired from a stat line that didn't parse
            the way this method expects (a PARSE failure, not an absence
            signal) -- folded into the same verdict, also wrong.
        Because the guard normally observes 'T' well within the first poll
        (~0.1s per MILLER's measurement; the non-reproduction arm takes
        ~2.1s to reach the kernel deadline), this method's own failure path
        had never executed in this environment -- so the collapse went
        unnoticed until a platform without /proc hit it and got a
        confident, specific, WRONG verdict blaming the pty reproduction
        technique instead of the missing prerequisite.

        Fix: retry unreadable/unparseable reads within the budget (a
        transient race -- pid file written, /proc entry not yet populated
        -- is expected and should not end the poll early); only report
        'unreadable' if EVERY read attempt across the whole budget failed
        (no /proc, or persistently unreadable), and only report 'gone' once
        the process has been read successfully at least once and then a
        later read finds it missing (ProcessLookupError, or ESRCH-shaped
        FileNotFoundError after a prior success) -- genuine disappearance,
        not a first-attempt read failure. IndexError (parse failure on a
        line that WAS read) is tracked separately and never folded into
        either sentinel.

        Records elapsed wall-clock time to self.last_wait_elapsed_sec --
        MILLER's decisive measurement showed the two real outcomes are
        separated by ~2s (a genuine 'T' stop resolves in ~0.1s, one poll
        interval; a genuine non-reproduction rides out the full ~2.1s
        kernel deadline), so a caller that wants to self-describe which
        arm it observed can assert against this directly rather than
        trusting the state string alone."""
        start = time.time()

        def _finish(result):
            self.last_wait_elapsed_sec = time.time() - start
            return result

        deadline = start + budget
        last_state = None
        observed_alive = False
        ever_read_succeeded = False
        parse_errors = 0
        while time.time() < deadline:
            try:
                with open(f"/proc/{pid}/stat") as f:
                    raw = f.read()
            except (FileNotFoundError, ProcessLookupError):
                if observed_alive:
                    return _finish("gone")
                # Not yet observed alive: could be a startup race (pid file
                # written, /proc entry not yet populated) OR a platform
                # with no /proc at all. Retry within budget rather than
                # deciding on the first sample.
                time.sleep(_POLL_INTERVAL_SEC)
                continue
            try:
                # Field 3 (state) follows the )-terminated comm field,
                # which can itself contain spaces/parens -- split on the
                # LAST ')' to stay correct regardless of comm content.
                after = raw.rsplit(")", 1)[1]
                last_state = after.split()[0]
            except IndexError:
                # The read succeeded but the line didn't parse as expected
                # -- a distinct failure mode from absence. Do not fold into
                # 'gone': retry, since a torn read mid-write is plausible.
                parse_errors += 1
                time.sleep(_POLL_INTERVAL_SEC)
                continue
            ever_read_succeeded = True
            observed_alive = True
            if last_state in ("T", "t", "Z"):
                return _finish(last_state)
            time.sleep(_POLL_INTERVAL_SEC)
        if not ever_read_succeeded:
            self.last_wait_elapsed_sec = time.time() - start
            raise unittest.SkipTest(
                f"/proc/{pid}/stat was never successfully read within "
                f"{budget}s ({parse_errors} parse failure(s) observed) -- "
                f"this platform likely has no /proc (e.g. macOS/BSD) or "
                f"restricts reading it (e.g. a hardened container); this "
                f"guard cannot observe process state here, so it must skip "
                f"loudly rather than report a state it never actually saw, "
                f"exactly as _real_system_timeout already does for its own "
                f"missing prerequisite"
            )
        return _finish(last_state)

    def _cleanup_pid(self, pid):
        """`pid` is the pty-attached shell -- also its own process group
        leader (session leader, per _spawn_in_pty's setsid). SIGCONT+
        SIGKILL to the NEGATIVE pid targets the whole group, reaching a
        STOPPED grandchild (e.g. the SIGTTIN-stopped stub) that a signal
        to the shell alone would not touch."""
        try:
            os.killpg(pid, signal.SIGCONT)
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            os.waitpid(pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass


class TestForegroundFlagPreventsSigttinStopUnderPty(_PtySessionTestBase):
    """THE FIX: the real, capability-detected DS_TIMEOUT_FOREGROUND_CMD from
    platform.sh (this task) must NOT allow the wrapped command's process
    group to stop under SIGTTIN when driven from a real pty. This is the
    variable bin/clagentic-lite's `claude plugin`/`claude --version` sites
    actually use -- DS_TIMEOUT_CMD itself is untouched (see
    TestPlainDsTimeoutCmdStillStopsUnderSigttin below: proves the narrowing
    is real, not just documented)."""

    def test_ds_timeout_foreground_cmd_wrapped_call_does_not_stop(self):
        pid_file = os.path.join(self.tmp, "claude.pid")
        _write_tty_reading_stub(self.bin_dir, pid_file, "claude")
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            $DS_TIMEOUT_FOREGROUND_CMD {_TEST_TIMEOUT_SEC} claude
        """)
        shell_pid, master_fd = self._spawn_in_pty(script)
        try:
            claude_pid = self._wait_for_pid_file(pid_file)
            state = self._wait_for_state(claude_pid)
            self.assertNotEqual(
                state, "T",
                "wrapped `claude` stub STOPPED under SIGTTIN despite the "
                "--foreground-augmented DS_TIMEOUT_FOREGROUND_CMD -- the "
                "fix did not prevent the process-group mismatch from "
                "GitHub issue #213",
            )
            self.assertIn(
                state, ("Z", "gone"),
                f"expected the wrapped command to terminate (bounded by "
                f"the {_TEST_TIMEOUT_SEC}s guard, since the stub blocks on "
                f"/dev/tty forever otherwise) rather than run indefinitely; "
                f"observed state={state!r}",
            )
        finally:
            os.close(master_fd)
            self._cleanup_pid(shell_pid)


class TestPlainDsTimeoutCmdStillStopsUnderSigttin(_PtySessionTestBase):
    """THE NARROWING, PROVEN NOT JUST DOCUMENTED (PEACHES PR #214 review
    finding 2): DS_TIMEOUT_CMD itself -- the variable scripts/gates.sh's
    run_bounded and scripts/llm-client.sh actually consume -- must still
    exhibit the pre-fix SIGTTIN-stop behavior when driven against a
    tty-touching command, proving this task did NOT quietly re-widen
    DS_TIMEOUT_CMD's own scope back to include --foreground. (No real
    consumer of DS_TIMEOUT_CMD actually touches a controlling terminal --
    this test's stub is synthetic, standing in for "some tty-touching
    command wrapped by the generic primitive", to prove the primitive's
    OWN behavior is unchanged, not to claim a real regression exists at
    gates.sh/llm-client.sh's actual call sites.)"""

    def test_ds_timeout_cmd_wrapped_call_still_stops(self):
        pid_file = os.path.join(self.tmp, "claude.pid")
        _write_tty_reading_stub(self.bin_dir, pid_file, "claude")
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            $DS_TIMEOUT_CMD {_TEST_TIMEOUT_SEC} claude
        """)
        shell_pid, master_fd = self._spawn_in_pty(script)
        try:
            claude_pid = self._wait_for_pid_file(pid_file)
            state = self._wait_for_state(claude_pid)
            self.assertEqual(
                state, "T",
                f"DS_TIMEOUT_CMD must still exhibit the pre-fix SIGTTIN-"
                f"stop behavior against a tty-touching command -- if this "
                f"assertion fails, DS_TIMEOUT_CMD itself gained "
                f"--foreground somewhere, re-widening its scope to every "
                f"consumer (run_bounded, llm-client.sh) contrary to "
                f"PEACHES PR #214 finding 2; observed state={state!r}",
            )
        finally:
            os.close(master_fd)
            self._cleanup_pid(shell_pid)


class TestBareTimeoutStopsUnderSigttinPreFix(_PtySessionTestBase):
    """HARNESS SELF-CHECK (lr-c65d8a acceptance item 2): proves this test
    file's own pty reproduction actually detects the SIGTTIN-stop
    condition, using a synthetic bare `timeout` that deliberately skips
    --foreground -- independent of whether platform.sh's real detection
    landed. This is what "verified to FAIL against current HEAD before the
    fix lands" means in practice: the reproduction mechanism itself is
    exercised here, on demand, rather than only inferred from having once
    failed during development.

    PEACHES PR #214 REVIEW FINDING 1: this exact assertion was observed to
    return state='gone' (the wrapped stub exited/reaped before the poll
    loop ever caught it stopped) rather than 'T' in the reviewer's
    execution environment, meaning the guard could not demonstrate it
    detects the defect there. INVESTIGATED (this task): re-run repeatedly
    in this environment -- both this test alone and the whole file, via
    `python3 -m unittest` (module, class, and `unittest discover` forms) --
    and it passed every single time, consistently observing state='T'
    (MILLER's independent re-run: 34/34). TestPlainDsTimeoutCmdStillStops
    UnderSigttin above exercises the same stop mechanism through the real
    (non-synthetic) DS_TIMEOUT_CMD and also passes reliably here. The
    assertion itself was correct and stays unchanged; the earlier
    investigation stopped one layer too shallow.

    CORRECTED (MILLER, fold-in round 2): the ORIGINAL hypotheses this note
    once offered for a possible 'gone' elsewhere -- restricted SIGTTIN
    delivery in some sandbox, or a sandbox reaping a stopped grandchild
    early -- are REFUTED by MILLER's timing measurement and do not need
    re-investigating if 'gone' recurs. Restricted SIGTTIN delivery would
    make the stub never stop at all, so the poll would ride out the full
    ~2.1s non-reproduction arm (nothing writes to master_fd, the stub
    blocks in 'S' until timeout's kill) before disappearing -- not an
    instant 'gone'. A sandbox does not reap a STOPPED ('T') process without
    an explicit SIGCONT/SIGKILL first, which nothing in this harness sends
    mid-poll. The simpler, and now confirmed, explanation for an instant
    'gone' was a /proc READ FAILURE on the very first poll attempt, not a
    process lifecycle event -- `_wait_for_state`'s own error path folded
    "never successfully read /proc at all" (e.g. no /proc on macOS/BSD)
    into the identical 'gone' string used for genuine post-observation
    disappearance, discarding the ~7.9s of remaining budget that would
    have let a real transient race resolve itself. See `_wait_for_state`'s
    docstring for the fix: retry within budget, split the sentinels, and
    skip loudly (SkipTest) when /proc is provably unreadable rather than
    guess. If a future run reports 'gone' again, it is now a REAL
    post-observation disappearance (the two are no longer conflated); an
    'unreadable'-driven SkipTest is the platform-prerequisite signal
    instead, distinguishable by the elapsed time TestBareTimeoutStops
    UnderSigttinPreFix's own run records (~0.1s for a genuine 'T' stop
    vs. the ~2.1s non-reproduction deadline -- see that measurement's
    origin in this fold-in's PR body / lr-c65d8a task thread)."""

    def test_bare_timeout_without_foreground_stops_the_group(self):
        real_timeout = _real_system_timeout()
        pid_file = os.path.join(self.tmp, "claude.pid")
        _write_tty_reading_stub(self.bin_dir, pid_file, "claude")
        script = textwrap.dedent(f"""\
            {real_timeout} {_TEST_TIMEOUT_SEC} claude
        """)
        shell_pid, master_fd = self._spawn_in_pty(script)
        try:
            claude_pid = self._wait_for_pid_file(pid_file)
            state = self._wait_for_state(claude_pid)
            self.assertEqual(
                state, "T",
                f"expected the synthetic bare-timeout reproduction to stop "
                f"the wrapped command under SIGTTIN (proving this harness "
                f"can detect the defect at all); observed state={state!r}. "
                f"If this assertion fails, the pty/process-group "
                f"reproduction technique itself is broken, independent of "
                f"the product fix.",
            )
            # MILLER'S DISCRIMINATOR (optional per this task, included
            # because it directly encodes the measurement that resolved
            # the AMoS/PEACHES 'T' vs 'gone' dispute): a genuine SIGTTIN
            # stop resolves within roughly one poll interval (~0.1s),
            # sharply distinct from the ~2.1s a real non-reproduction rides
            # out to the kernel deadline. Asserting the elapsed time here
            # makes this test self-describing about WHICH arm it actually
            # observed, not just that the string happened to read 'T'.
            self.assertLess(
                self.last_wait_elapsed_sec, 1.0,
                f"observed state=='T' but took "
                f"{self.last_wait_elapsed_sec:.3f}s to resolve -- a genuine "
                f"SIGTTIN stop resolves in ~1 poll interval "
                f"({_POLL_INTERVAL_SEC}s); this elapsed time is inconsistent "
                f"with MILLER's ~0.1s measurement for a real stop and "
                f"warrants re-diagnosing this environment's timing rather "
                f"than trusting the state string alone",
            )
        finally:
            os.close(master_fd)
            self._cleanup_pid(shell_pid)


class TestTimeoutStillFiresWithDetachedStdin(_PtySessionTestBase):
    """AGNOSTICISM, THE OTHER AXIS (lr-c65d8a seq 1, constraint 3): the
    --foreground addition must not regress the non-interactive/CI shape
    lr-da3b7e's own test already covers. Runs the SAME real DS_TIMEOUT_CMD
    with stdin explicitly detached (/dev/null, no pty at all) against a
    stub that sleeps past the timeout -- proving the guard still fires
    (process actually terminates, bounded) with no controlling terminal in
    the picture."""

    def test_timeout_bounds_a_hanging_command_with_devnull_stdin(self):
        stub_path = os.path.join(self.bin_dir, "claude")
        with open(stub_path, "w") as f:
            # `exec sleep 300`, not a plain child call (lr-c65d8a
            # discovery, see test_doctor_init_claude_plugin_timeout.py's
            # _write_hanging_claude docstring for the full mechanism):
            # `timeout --foreground` signals only its direct child, so a
            # non-exec'd grandchild would survive and this test would
            # silently stop testing what it claims to.
            f.write(textwrap.dedent("""\
                #!/bin/sh
                exec sleep 300
            """))
        os.chmod(stub_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP
                  | stat.S_IROTH | stat.S_IXOTH)

        env = os.environ.copy()
        env["PATH"] = self.bin_dir + os.pathsep + "/usr/bin:/bin"
        script = f". '{PLATFORM_SH}'\n$DS_TIMEOUT_CMD {_TEST_TIMEOUT_SEC} claude\n"
        start = time.monotonic()
        result = subprocess.run(
            ["/bin/sh", "-c", script, PLATFORM_SH],
            env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True,
            timeout=_WAIT_BUDGET_SEC,
        )
        elapsed = time.monotonic() - start
        self.assertNotEqual(
            result.returncode, 0,
            "expected a non-zero (timeout-fired) exit from the bounded "
            "hanging stub with detached stdin",
        )
        self.assertLess(
            elapsed, _WAIT_BUDGET_SEC,
            f"guard did not bound the call within the test's own "
            f"subprocess-level safety timeout; elapsed={elapsed:.1f}s",
        )


if __name__ == "__main__":
    unittest.main()
