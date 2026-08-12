"""
Regression coverage for run_bounded (scripts/gates.sh), the class-4 foundry
fix's single entry point for every previously-untimed external-process
invocation (gitleaks, osv-scanner, semgrep, git push, the host adapter's
open-change-request call).

Exercises the REAL run_bounded function (sourced via `sh -c`, truncated at
gates.sh's own subcommand dispatch the same way every other gates.sh-sourcing
test in this suite does) against a fake `timeout` binary that records its
own argv -- proving the duration argument is actually threaded through, not
merely that run_bounded "looks like" it should apply one.

Run with: python3 -m unittest scripts.test_run_bounded -v
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
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _functions_only_gates_source(dest_dir):
    """Copy gates.sh into dest_dir with its trailing subcommand dispatch
    (`case "${1:-}" in init) ... esac`) stripped off -- mirrors every
    llm-client.sh test's identical technique, applied to gates.sh instead.
    Also copies platform.sh and minimal review-merge.sh/host-adapter.sh
    stubs alongside (gates.sh sources all three unconditionally near the
    top)."""
    with open(GATES_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in gates.sh"
    dest = os.path.join(dest_dir, "gates.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    platform_dest = os.path.join(dest_dir, "platform.sh")
    with open(PLATFORM_SH) as src, open(platform_dest, "w") as dst:
        dst.write(src.read())
    # review-merge.sh / host-adapter.sh: gates.sh sources both unconditionally
    # (". $(dirname "$0")/review-merge.sh", ". $(dirname "$0")/host-adapter.sh")
    # but run_bounded/cmd_init do not need anything either one defines -- stub
    # files satisfy the source lines without pulling in unrelated machinery
    # this test does not exercise.
    review_merge_dest = os.path.join(dest_dir, "review-merge.sh")
    with open(review_merge_dest, "w") as f:
        f.write("#!/bin/sh\n# stub for run_bounded tests\n")
    host_adapter_dest = os.path.join(dest_dir, "host-adapter.sh")
    with open(host_adapter_dest, "w") as f:
        f.write("#!/bin/sh\n# stub for run_bounded tests\n")
    return dest


def _write_fake_timeout(bin_dir, argv_file, name="timeout"):
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_file}'
            _duration="$1"
            shift
            "$@"
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _init_repo(root):
    subprocess.run(["git", "init", "-q", root], check=True)
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "initial"],
                    check=True, cwd=root, env=env)


class TestRunBoundedAppliesTheConfiguredTimeout(unittest.TestCase):
    """run_bounded TIMEOUT_SEC -- CMD ARGS... must invoke $DS_TIMEOUT_CMD
    with TIMEOUT_SEC as its first argument, followed by the real command."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-run-bounded-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

        self._bin = os.path.join(self._tmp, "bin")
        self._argv_file = os.path.join(self._tmp, "timeout-argv.log")
        open(self._argv_file, "w").close()
        os.makedirs(self._bin)
        _write_fake_timeout(self._bin, self._argv_file)

        self._src_dir = os.path.join(self._tmp, "src")
        os.makedirs(self._src_dir)
        self._sourced_gates = _functions_only_gates_source(self._src_dir)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, script_body):
        env = os.environ.copy()
        env["PATH"] = self._bin + os.pathsep + env["PATH"]
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        script = textwrap.dedent(f"""\
            . '{self._sourced_gates}'
            {script_body}
        """)
        return subprocess.run(
            ["sh", "-c", script, self._sourced_gates],
            capture_output=True, text=True, env=env, cwd=self._repo,
        )

    def test_explicit_timeout_is_passed_to_ds_timeout_cmd(self):
        result = self._run("run_bounded 42 -- echo hello")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self._argv_file) as f:
            argv = f.read()
        self.assertIn(
            "42 echo hello", argv,
            f"expected the timeout binary to be called with duration 42 "
            f"followed by the real command; recorded argv={argv!r}",
        )

    def test_default_timeout_used_when_omitted(self):
        """No TIMEOUT_SEC given (starts directly with `--`) falls back to
        CLAGENTIC_EXTERNAL_TIMEOUT_SEC (default 120)."""
        result = self._run("run_bounded -- echo hello")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self._argv_file) as f:
            argv = f.read()
        self.assertIn(
            "120 echo hello", argv,
            f"expected the default 120s timeout; recorded argv={argv!r}",
        )

    def test_configured_default_timeout_is_honored(self):
        env = os.environ.copy()
        env["PATH"] = self._bin + os.pathsep + env["PATH"]
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        env["CLAGENTIC_EXTERNAL_TIMEOUT_SEC"] = "77"
        script = textwrap.dedent(f"""\
            . '{self._sourced_gates}'
            run_bounded -- echo hello
        """)
        result = subprocess.run(
            ["sh", "-c", script, self._sourced_gates],
            capture_output=True, text=True, env=env, cwd=self._repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self._argv_file) as f:
            argv = f.read()
        self.assertIn("77 echo hello", argv, f"recorded argv={argv!r}")

    def test_non_numeric_timeout_falls_back_to_default(self):
        """A non-numeric TIMEOUT_SEC (e.g. a corrupted config value) must
        not be passed through raw to the timeout binary -- it falls back
        to the same numeric-guard discipline every other timeout/interval
        var in this file uses."""
        result = self._run("run_bounded not-a-number -- echo hello")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self._argv_file) as f:
            argv = f.read()
        self.assertIn(
            "120 echo hello", argv,
            f"expected fallback to the default 120s on a non-numeric "
            f"timeout; recorded argv={argv!r}",
        )

    def test_command_exit_status_propagates(self):
        """run_bounded must propagate the wrapped command's own exit
        status, not swallow it -- every call site in gates.sh relies on
        this (`if run_bounded ... ; then ... else ...`)."""
        result = self._run("run_bounded 5 -- sh -c 'exit 7'")
        self.assertEqual(result.returncode, 7, result.stderr)


class TestRunBoundedFailsClosedWithNoTimeoutBinary(unittest.TestCase):
    """When neither timeout nor gtimeout is on PATH, run_bounded must
    refuse to run the wrapped command at all (INV-1a), not silently run it
    unbounded."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-run-bounded-noop-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)
        self._src_dir = os.path.join(self._tmp, "src")
        os.makedirs(self._src_dir)
        self._sourced_gates = _functions_only_gates_source(self._src_dir)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_run_bounded_refuses_to_run_the_command(self):
        marker = os.path.join(self._tmp, "should-not-be-created")
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        # PATH is stripped INSIDE the script (not via subprocess.run's env=
        # kwarg) so the subprocess LAUNCH itself can still resolve `/bin/sh`
        # via the outer, unmodified environment -- only platform.sh's own
        # `command -v timeout`/`command -v gtimeout` checks, which run
        # after the script starts, see the emptied PATH. `touch` is called
        # via its absolute path for the same reason (an emptied PATH cannot
        # resolve a bare `touch` either).
        script = textwrap.dedent(f"""\
            PATH="/nonexistent-empty-path-for-test"
            . '{self._sourced_gates}'
            run_bounded 5 -- /usr/bin/touch '{marker}'
        """)
        result = subprocess.run(
            ["/bin/sh", "-c", script, self._sourced_gates],
            capture_output=True, text=True, env=env, cwd=self._repo,
        )
        self.assertFalse(
            os.path.exists(marker),
            "run_bounded ran the wrapped command despite no timeout binary "
            "being present -- INV-1a requires it to refuse, not degrade "
            "silently",
        )
        self.assertNotEqual(
            result.returncode, 0,
            f"run_bounded must return non-zero when it refuses to run the "
            f"command. stdout={result.stdout!r} stderr={result.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
