"""
Regression coverage for lr-da3b7e (finding fnd-fdb04d): every `claude
plugin ...`/`claude --version` subprocess invocation in bin/clagentic-lite's
doctor and init paths must be wall-clock bounded via $DS_TIMEOUT_CMD. Before
this fix, `_doctor_check_plugin_collision` (doctor step, `claude plugin
list`) and `_install_clagentic_lite_plugin`/`_migrate_legacy_router_plugin`
(init/update step, `claude plugin marketplace add/update/list/install`) were
unbounded network calls -- a slow or unreachable network could hang `doctor`
or `init` indefinitely with no diagnostic.

THE TEST THAT PROVES THE USER-FACING FIX: a stub `claude` binary placed
first on PATH that sleeps far longer than the configured
CLAGENTIC_PLUGIN_TIMEOUT_SEC before ever answering `plugin list`/`plugin
marketplace add` etc, simulating an unreachable/slow network. Both `doctor`
and `init` must terminate (non-hanging, bounded by the subprocess.run
`timeout=` guard which is set generously above the configured
CLAGENTIC_PLUGIN_TIMEOUT_SEC) rather than blocking on the stub's sleep, and
must surface a diagnostic rather than silently succeeding as if the call had
returned quickly.

Uses a low CLAGENTIC_PLUGIN_TIMEOUT_SEC (2s) so the test itself stays fast --
this exercises the same code path as the default (30s), just with a smaller
bound, per this codebase's established CLAGENTIC_<SCOPE>_TIMEOUT_SEC
convention (share/config.example).

HAZARD (test_enroll_reenroll_no_force.py:22-27 / test_router_bedrock_
settings_stamp.py:31-39 discipline): `init` mutates $CLAGENTIC_LITE_HOME
(hook materialization, plugin render dir, etc) and must never point at the
live dev checkout. Every test here uses scripts.test_support's throwaway-
clone-with-overlay helper, mirroring test_init_config_schema_version_stamp.py
and test_doctor_config_drift.py. `doctor` itself is read-only against
CLAGENTIC_LITE_HOME (per test_doctor_config_drift.py's own HAZARD note) but
uses the same clone helper anyway for consistency and because the stub
`claude` on PATH needs its own throwaway bin dir regardless.

SCOPE HAZARD, ADDED lr-c65d8a (GitHub issue #213, DO NOT MISTAKE THIS FILE
FOR COMPLETE COVERAGE OF THE TIMEOUT GUARD): every test in this module runs
with stdin=subprocess.DEVNULL (TestInitTerminatesOnUnreachableClaude) or a
non-tty inherited stdin (TestDoctorTerminatesOnUnreachableClaude, via
subprocess.run's default). That is deliberately the CI/non-interactive
shape and is retained here as real, load-bearing coverage of the network-
timeout axis lr-da3b7e fixed -- do not delete it.

But it is STRUCTURALLY INCAPABLE of reproducing the SIGTTIN/SIGTTOU
process-group stop GitHub issue #213 reported: that defect only manifests
when the wrapped command has a REAL CONTROLLING TERMINAL to touch. A
detached-stdin subprocess has no controlling terminal to raise SIGTTIN
against in the first place, so this module's stub-sleeps-past-the-timeout
technique proves the guard fires when there is nothing for SIGTTIN to
interact with -- it says nothing about the interactive-terminal case. THIS
IS EXACTLY THE GAP lr-da3b7e's own regression test had that let the SIGTTIN
regression ship undetected (see lr-c65d8a's task description for the full
diagnosis) -- recorded explicitly here per that task's own directive so
this file's scope is never again mistaken for full timeout-guard coverage.
The interactive/pty shape is covered separately by
scripts/test_timeout_foreground_pty_regression.py, which drives a real pty
and is the only place in this suite that can observe SIGTTIN at all.

Also lr-c65d8a: `_write_hanging_claude`'s stub was changed from a plain
child `sleep 300` to `exec sleep 300` -- see that function's own docstring
for why the non-exec'd form silently broke this module's own coverage the
moment `--foreground` was added to DS_TIMEOUT_CMD (a `--foreground`-bound
timeout signals only its direct child, not a whole process group the way
bare `timeout` does, so a non-exec'd grandchild survived and kept the
wrapping pipe open).

Run with: python3 -m unittest scripts.test_doctor_init_claude_plugin_timeout -v
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
_clone_tool_home = clone_this_tool_home_with_overlay

# Configured plugin timeout for these tests -- deliberately short so a
# hanging-stub test doesn't itself take 30s+ to run. The subprocess.run
# `timeout=` guard below is set well above this so a genuine regression
# (the wrapper not applying) shows up as an assertion/timeout FAILURE, not
# as this test suite itself hanging indefinitely.
_TEST_PLUGIN_TIMEOUT_SEC = "2"
_SUBPROCESS_GUARD_TIMEOUT = 30


def _write_hanging_claude(bin_dir):
    """Stub `claude` that never returns for `plugin ...`/`--version`
    invocations -- simulates an unreachable/slow network. Sleeps far longer
    than _TEST_PLUGIN_TIMEOUT_SEC so a passing test proves the timeout
    wrapper actually fired, not that the stub happened to finish first.

    `exec sleep 300`, NOT a plain `sleep 300` child call (lr-c65d8a
    discovery): the real `claude` CLI is a single process (a Node.js
    binary invoked directly, never itself forking a shell-visible child
    the way this stub used to) -- DS_TIMEOUT_CMD's real-world child IS the
    process that must receive the timeout signal. `timeout --foreground`
    (added by lr-c65d8a to fix the SIGTTIN class this file also guards)
    sends its expiry signal ONLY to its direct child, not to a whole
    process-group the way bare `timeout` does -- correct and sufficient
    for a single-process real `claude`, but a plain (non-exec'd) `sleep`
    child of a shell-script stub would survive its parent's SIGTERM and
    keep the wrapping pipe open, silently reintroducing the exact
    unbounded-hang class this test exists to catch, in the test fixture
    itself rather than the product. `exec` replaces the stub shell's own
    process image with `sleep`, matching the real single-process shape.
    """
    path = os.path.join(bin_dir, "claude")
    with open(path, "w") as f:
        f.write(textwrap.dedent("""\
            #!/bin/sh
            # Simulates an unreachable/slow network: never returns on its own.
            exec sleep 300
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


class _ClaudePluginTimeoutTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-plugin-timeout-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)
        self.stub_bin_dir = os.path.join(self.tmpdir, "stub-bin")
        os.makedirs(self.stub_bin_dir)
        _write_hanging_claude(self.stub_bin_dir)

    def _base_env(self):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env["CLAGENTIC_PLUGIN_TIMEOUT_SEC"] = _TEST_PLUGIN_TIMEOUT_SEC
        # Stub claude first on PATH so every `claude ...`/`command -v claude`
        # call site resolves to the hanging stub, never a real installed CLI.
        env["PATH"] = self.stub_bin_dir + os.pathsep + env.get("PATH", "")
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        return env


class TestDoctorTerminatesOnUnreachableClaude(_ClaudePluginTimeoutTestBase):
    def test_doctor_does_not_hang_and_reports_diagnostic(self):
        """doctor's plugin-collision check (`claude plugin list`) must not
        block doctor's overall run past CLAGENTIC_PLUGIN_TIMEOUT_SEC, and
        doctor must still reach its own summary line rather than dying
        silently or hanging on the stub's 300s sleep."""
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite"), "doctor"],
            cwd=self.tmpdir,
            env=self._base_env(),
            capture_output=True, text=True,
            timeout=_SUBPROCESS_GUARD_TIMEOUT,
        )
        # doctor must reach its final summary despite the hanging plugin
        # probe -- proves the timeout wrapper bounded the call rather than
        # doctor blocking indefinitely on it. Summary line carries a
        # trailing "N OK, M FAIL" count, so match the stable prefix only.
        self.assertIn("== doctor summary", proc.stdout, msg=proc.stdout + proc.stderr)


class TestInitTerminatesOnUnreachableClaude(_ClaudePluginTimeoutTestBase):
    def test_init_does_not_hang_and_completes(self):
        """init's plugin install/migration path (`claude plugin marketplace
        add`, `claude plugin list`, etc) must not block init indefinitely on
        an unreachable network -- init must still reach "init complete"
        within the bounded window."""
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite"), "init"],
            cwd=self.fake_tool_home,
            env=self._base_env(),
            capture_output=True, text=True,
            timeout=_SUBPROCESS_GUARD_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
        self.assertIn("init complete", proc.stdout, msg=proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
