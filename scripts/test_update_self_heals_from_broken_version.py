"""
THE DECISIVE DELIVERABILITY TEST for lr-c65d8a / lr-3bf7a4 (GitHub issue
#213), operator directive: "EVERYONE GETS TO RUN `clagentic-lite update`,
AS IS, PERIOD. No flag. No `</dev/null`. No env var. No documented
incantation."

WHY THIS TEST EXISTS AND WHY IT IS THE MOST IMPORTANT ONE IN THIS PR. Every
other test in this task proves the SIGTTIN fix is CORRECT once running.
This test proves the fix is REACHABLE at all -- that a user stuck on the
pre-fix, SIGTTIN-hanging version can actually receive the fix by running
the bare command they already know: `clagentic-lite update`, no flags, no
stdin redirection, from a real interactive terminal. If that is not true,
every other passing test in this task is validating a fix nobody stuck on
the broken version can ever reach, because `update` IS the delivery
mechanism for its own fix.

THE MECHANISM THIS RELIES ON, AND WHY IT WAS PREVIOUSLY ACCIDENTAL.
cmd_update (bin/clagentic-lite) does, in order: (1) `git pull --ff-only`
against CLAGENTIC_LITE_HOME; (2) if the SHA moved, `exec` the FRESHLY
PULLED binary with the same argv -- re-executing `update` from the new
on-disk code; (3) only then reaches `_install_clagentic_lite_plugin`, the
exact `claude plugin ...` call site GitHub issue #213 reported hanging.
That `exec` (see bin/clagentic-lite's own comment at the re-exec site,
"ALSO LOAD-BEARING FOR UPDATE SELF-HEALING") exists to refresh version
constants for the restamp comparison -- NOT because anyone designed it as
a self-heal mechanism. It happens to provide that property as a side
effect. This test makes that property an ENFORCED INVARIANT rather than an
accident: if a future edit ever gates that `exec` behind a condition
narrower than "the SHA moved", conditions it on a flag, or removes it, this
test fails LOUDLY with a hang (bounded by this test's own subprocess-level
guard) rather than the regression going unnoticed until the next GitHub
issue.

TEST SHAPE. Two throwaway git clones of THIS checkout's current on-disk
state (never the live checkout itself -- see scripts/test_support.py's own
TEST HAZARD note):
  1. "upstream" -- current on-disk state (the fix), used as the git remote
     the broken install pulls from.
  2. "broken install" -- checked out at the last commit BEFORE this task's
     SIGTTIN fix landed (still has the pre-lr-c65d8a bare DS_TIMEOUT_CMD,
     genuinely reproduces the hang), with its origin remote pointed at
     clone 1.

Then: a real pty (reusing scripts/test_timeout_foreground_pty_regression.py's
harness technique -- setsid + TIOCSCTTY, the only way to reproduce SIGTTIN
at all), a stub `claude` that touches /dev/tty (the same class of terminal
touch the real CLI performs, per issue #213's diagnosis) then exits, and a
plain `clagentic-lite update` invocation with NO flags and NO stdin
redirection -- run from the BROKEN install's own bin/clagentic-lite, exactly
as a real affected user would type it. Asserts the process completes
(reaches "update complete") within a bounded wall-clock window rather than
stopping under SIGTTIN and hanging forever.

Run with: python3 -m unittest scripts.test_update_self_heals_from_broken_version -v
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

from scripts.test_support import clone_tool_home_with_overlay

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Last commit before this task's SIGTTIN fix landed -- still carries the
# bare (no --foreground) DS_TIMEOUT_CMD that genuinely reproduces the
# GitHub issue #213 hang. Verified directly (this task): at this SHA,
# scripts/platform.sh's DS_TIMEOUT_CMD assembly has no --foreground
# capability detection at all.
_PRE_FIX_SHA = "c936db6e8b3ca1b699966b20893ab3d680a77e02"

_WAIT_BUDGET_SEC = 45
_NO_FIX_BUDGET_SEC = 10
_POLL_INTERVAL_SEC = 0.2
_STUB_TIMEOUT_SEC = "3"


def _write_tty_touching_claude_stub(bin_dir, invocation_log):
    """Stub `claude` matching the real CLI's issue-#213-diagnosed startup
    behavior: touches the controlling terminal, then answers normally and
    exits. Appends one line to `invocation_log` per call so the test can
    assert `update` actually reached (and got past) multiple `claude`
    invocations, not just the first.

    Unlike test_timeout_foreground_pty_regression.py's
    _write_tty_reading_stub (a blocking `read` used to prove the SIGTTIN
    STOP condition in isolation), this stub must actually PROCEED once not
    stopped, because `update`'s own completion depends on multiple `claude
    plugin ...` calls in sequence returning real (parseable) output --
    `plugin list` in particular is grepped by bin/clagentic-lite's own
    install/migrate logic, so it must print plausible output, not just
    exit 0."""
    path = os.path.join(bin_dir, "claude")
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            echo "$$ $*" >> '{invocation_log}'
            # Touch the controlling terminal (the issue #213 mechanism) --
            # a non-blocking read with a short read-timeout via `dd`'s
            # iflag=nonblock is not POSIX-portable; `read -r` against a pty
            # whose master side continuously supplies newlines (this test's
            # harness, see _feed_pty_newlines) returns quickly once this
            # process is not SIGTTIN-stopped, and never returns if it is --
            # which is exactly the property under test.
            read -r _line < /dev/tty
            case "$*" in
              *"plugin list"*)
                # Plausible, parseable `claude plugin list` output -- must
                # not be empty, or bin/clagentic-lite's own probes correctly
                # treat it as EMPTY/UNKNOWN rather than a real answer.
                printf 'clagentic-lite@clagentic-lite\\n'
                ;;
              *"--version"*)
                printf 'claude 1.2.3 (test stub)\\n'
                ;;
            esac
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


class _UpdateSelfHealPtyTestBase(unittest.TestCase):
    """Shared harness: a broken-pre-fix-SHA install, a real pty, and a
    tty-touching `claude` stub. Subclasses control whether the install's
    `origin` remote actually carries the fix (self-heal case) or is
    repointed at itself, still at the pre-fix SHA (harness self-check
    negative control, same discipline as
    scripts/test_timeout_foreground_pty_regression.py's
    TestBareTimeoutStopsUnderSigttinPreFix)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-update-self-heal-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.bin_dir = os.path.join(self.tmp, "stub-bin")
        os.makedirs(self.bin_dir)
        self.invocation_log = os.path.join(self.tmp, "claude-invocations.log")
        open(self.invocation_log, "w").close()
        _write_tty_touching_claude_stub(self.bin_dir, self.invocation_log)

    def _make_broken_install(self, upstream_has_fix):
        """Clones THIS repo's real history, checks out _PRE_FIX_SHA (the
        genuinely SIGTTIN-hanging commit), and points `origin` either at a
        throwaway overlay clone carrying the CURRENT on-disk fix
        (upstream_has_fix=True -- the self-heal case) or at itself, still
        pinned to _PRE_FIX_SHA (upstream_has_fix=False -- the harness
        self-check: proves this test's own reproduction technique detects
        the hang when no fix is actually available to pull, independent of
        whether bin/clagentic-lite's real re-exec logic landed).

        Sets self.broken_install.
        """
        if upstream_has_fix:
            upstream = os.path.join(self.tmp, "upstream")
            clone_tool_home_with_overlay(TOOL_HOME, upstream)
            subprocess.run(
                ["git", "-C", upstream, "add", "-A"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "-C", upstream, "commit", "-q", "-m", "overlay current on-disk state"],
                check=True, capture_output=True,
            )
            # The overlay clone's default branch is whatever branch is
            # checked out in THIS checkout (a feature branch mid-
            # development, not necessarily "main") -- read it back rather
            # than hardcoding a branch name, so this test does not depend
            # on which branch it happens to run from.
            upstream_branch = subprocess.run(
                ["git", "-C", upstream, "symbolic-ref", "--short", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
        else:
            # No-fix negative control: upstream is a bare clone pinned at
            # the SAME pre-fix SHA the broken install starts at, so there
            # is genuinely nothing new to fast-forward onto -- `git pull
            # --ff-only` is a real no-op, not a stubbed/skipped step.
            # Read the branch name BEFORE detaching (checkout of a bare SHA
            # leaves HEAD detached, so symbolic-ref would fail afterward),
            # then re-create it as a real branch AT the pre-fix SHA so the
            # broken install still has a named ref to track against.
            upstream = os.path.join(self.tmp, "upstream-no-fix")
            subprocess.run(
                ["git", "clone", "-q", TOOL_HOME, upstream],
                check=True, capture_output=True,
            )
            upstream_branch = subprocess.run(
                ["git", "-C", upstream, "symbolic-ref", "--short", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "-C", upstream, "checkout", "-q", "-B", upstream_branch, _PRE_FIX_SHA],
                check=True, capture_output=True,
            )

        broken_install = os.path.join(self.tmp, "broken-install")
        subprocess.run(
            ["git", "clone", "-q", TOOL_HOME, broken_install],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", broken_install, "checkout", "-q", _PRE_FIX_SHA],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", broken_install, "checkout", "-q", "-B", upstream_branch],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", broken_install, "remote", "set-url", "origin", upstream],
            check=True, capture_output=True,
        )
        # Refresh the remote-tracking ref against the REPOINTED origin --
        # without this, origin/<branch> still reflects TOOL_HOME's tip from
        # the initial clone (before the repoint), not the actual upstream
        # content, and `pull --ff-only` would not see what is really there.
        subprocess.run(
            ["git", "-C", broken_install, "fetch", "-q", "origin", upstream_branch],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", broken_install, "config", "user.email", "test@example.com"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", broken_install, "config", "user.name", "Test"],
            check=True, capture_output=True,
        )
        # `pull --ff-only` needs a configured upstream tracking branch.
        subprocess.run(
            ["git", "-C", broken_install, "branch", "-q",
             f"--set-upstream-to=origin/{upstream_branch}", upstream_branch],
            check=True, capture_output=True,
        )
        self.broken_install = broken_install

    def _env(self):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.broken_install
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env["CLAGENTIC_PLUGIN_TIMEOUT_SEC"] = _STUB_TIMEOUT_SEC
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        # Deliberately NOT set: CLAGENTIC_UPDATE_ALLOW_DISCARD. The whole
        # point is a user who knows NOTHING and passes NO flags -- if this
        # test needed that opt-in to pass, it would be testing the wrong
        # thing. The broken-install clone is clean (freshly cloned, no
        # working-tree edits), so cmd_update's dirty-tree discard guard
        # (lr-55a27a) is never even reached.
        return env

    def _run_bare_update_under_pty(self, budget_sec):
        """Runs `clagentic-lite update`, bare, no flags, no stdin
        redirection, under a real pty as the operator's exact scenario
        requires. Returns 'gone' if the process completed within
        `budget_sec`, or the last observed state otherwise (still running
        -- the hang this whole task exists to catch/reproduce, depending
        on which subclass is calling)."""
        cli = os.path.join(self.broken_install, "bin", "clagentic-lite")
        master_fd, slave_fd = pty.openpty()
        env = self._env()

        pid = os.fork()
        if pid == 0:
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if slave_fd > 2:
                os.close(slave_fd)
            try:
                os.execvpe(cli, [cli, "update"], env)
            except Exception:
                os._exit(127)
        os.close(slave_fd)

        try:
            # Continuously feed newlines into the pty master so the stub's
            # `read -r _line < /dev/tty` unblocks immediately whenever the
            # stub process is NOT SIGTTIN-stopped. If the stub IS stopped
            # (the defect reproducing), no amount of input on the master
            # side reaches a stopped process -- this feed does not mask
            # the defect, it only removes an unrelated reason a
            # correctly-running stub might block.
            deadline = time.time() + budget_sec
            state = "R"
            while time.time() < deadline:
                try:
                    os.write(master_fd, b"\n")
                except OSError:
                    pass
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
                if not os.path.exists(f"/proc/{pid}"):
                    state = "gone"
                    break
                time.sleep(_POLL_INTERVAL_SEC)
            return state
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass
            try:
                os.killpg(pid, signal.SIGCONT)
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass


class TestUpdateSelfHealsFromBrokenVersion(_UpdateSelfHealPtyTestBase):
    def setUp(self):
        super().setUp()
        self._make_broken_install(upstream_has_fix=True)

    def test_plain_update_no_flags_no_stdin_redirect_completes_under_real_pty(self):
        """The operator's exact test: `clagentic-lite update`, bare, no
        flags, no `</dev/null`, from a broken pre-fix install, under a real
        controlling terminal -- must complete, not hang."""
        state = self._run_bare_update_under_pty(_WAIT_BUDGET_SEC)
        self.assertEqual(
            state, "gone",
            f"`clagentic-lite update` (bare, no flags, no stdin "
            f"redirect) did not complete within {_WAIT_BUDGET_SEC}s "
            f"under a real pty -- this is the exact non-reachability "
            f"failure this test exists to catch: a user on the broken "
            f"version cannot receive the fix via the only delivery "
            f"path they have. If this fails, check whether "
            f"bin/clagentic-lite's re-exec at the post-`git pull` site "
            f"(see its own 'LOAD-BEARING FOR UPDATE SELF-HEALING' "
            f"comment) still fires unconditionally on any SHA change.",
        )

        # The broken install's on-disk code must actually have pulled the
        # fix -- otherwise "completed" could mean "completed using the
        # still-broken pre-fix code because the pty happened not to
        # trigger SIGTTIN this run", which would not prove what this test
        # claims to prove.
        post_sha = subprocess.run(
            ["git", "-C", self.broken_install, "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertNotEqual(
            post_sha, _PRE_FIX_SHA,
            "broken install's HEAD did not move -- `git pull --ff-only` "
            "did not land the fix, so this run does not actually prove "
            "self-healing happened",
        )

        # At least one `claude plugin ...` invocation must have reached the
        # stub -- proves `update` actually got as far as the hanging call
        # site (_install_clagentic_lite_plugin), not merely that it exited
        # early for an unrelated reason (e.g. a setup error) before ever
        # reaching the code under test.
        with open(self.invocation_log) as f:
            invocations = f.read()
        self.assertTrue(
            invocations.strip(),
            "no `claude` invocation was recorded -- update likely exited "
            "before reaching _install_clagentic_lite_plugin, so this test "
            "did not actually exercise the code path under test",
        )


class TestUpdateSelfHealHarnessSelfCheck(_UpdateSelfHealPtyTestBase):
    """HARNESS SELF-CHECK, same discipline as
    scripts/test_timeout_foreground_pty_regression.py's
    TestBareTimeoutStopsUnderSigttinPreFix: proves this module's own pty/
    SIGTTIN reproduction actually detects the hang when no fix is
    available to pull (origin repointed at itself, still pinned to
    _PRE_FIX_SHA) -- independent of whether bin/clagentic-lite's real
    re-exec/DS_TIMEOUT_FOREGROUND_CMD fix landed. A negative control that
    cannot fail is worthless; this one demonstrably can, and does when the
    fix genuinely is not reachable."""

    def setUp(self):
        super().setUp()
        self._make_broken_install(upstream_has_fix=False)

    def test_update_hangs_when_no_fix_is_available_to_pull(self):
        # Shorter budget than the self-heal test: this run is EXPECTED to
        # still be running (SIGTTIN-stopped) at the deadline, so there is
        # no reason to wait as long as the success-path test does.
        state = self._run_bare_update_under_pty(_NO_FIX_BUDGET_SEC)
        self.assertNotEqual(
            state, "gone",
            "expected `clagentic-lite update` to still be hanging "
            "(SIGTTIN-stopped) when no fix is available to pull -- if it "
            "completed anyway, this harness cannot distinguish a real "
            "self-heal from a false pass, and "
            "TestUpdateSelfHealsFromBrokenVersion's own passing result "
            "cannot be trusted until this negative control is fixed.",
        )
        # `git pull --ff-only` against an origin with nothing new is a
        # real no-op -- HEAD must NOT have moved, confirming this run
        # never had a fix to receive in the first place (as opposed to
        # having one and failing to land it for some other reason).
        post_sha = subprocess.run(
            ["git", "-C", self.broken_install, "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(
            post_sha, _PRE_FIX_SHA,
            "broken install's HEAD moved even though origin was pinned to "
            "the same pre-fix SHA -- this negative control's own setup is "
            "broken, not just the assertion above",
        )


if __name__ == "__main__":
    unittest.main()
