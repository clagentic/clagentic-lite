"""
Regression coverage for ds_sqlite3 (scripts/platform.sh), the shared
busy-timeout wrapper every sqlite3 invocation against
.clagentic/lite/audit.db routes through (lr-c71845).

Mirrors test_run_bounded.py's technique for the sibling class-4-style
"unwritable bare form" mechanism: exercises the REAL ds_sqlite3 function
(sourced directly from platform.sh) against a fake `sqlite3` binary that
records its own argv, proving the busy-timeout `-cmd ".timeout N"` prefix is
actually threaded through -- not merely that the wrapper "looks like" it
should apply one. A second suite exercises the real sqlite3 binary (skipped
if not installed) to prove two concurrent writers to the same audit.db both
succeed, per the task's own acceptance criterion. A third suite sweeps
gates.sh and platform.sh for any bare `sqlite3 "$AUDIT_DB"`-shaped call that
bypassed the wrapper.

Run with: python3 -m unittest scripts.test_ds_sqlite3 -v
"""
import os
import re
import shutil
import sqlite3 as _pysqlite3
import stat
import subprocess
import tempfile
import textwrap
import threading
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

_HAS_SQLITE3_CLI = shutil.which("sqlite3") is not None


def _write_fake_sqlite3(bin_dir, argv_file):
    """A stand-in `sqlite3` that records its own argv (one line per call,
    space-joined) and exits 0 without touching a real database -- proves
    ds_sqlite3 threads the -cmd .timeout prefix through, without depending
    on a real sqlite3 binary being installed."""
    path = os.path.join(bin_dir, "sqlite3")
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_file}'
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


class TestDsSqlite3AppliesTheBusyTimeout(unittest.TestCase):
    """ds_sqlite3 must prepend `-cmd ".timeout N"` before forwarding its
    arguments verbatim to the real sqlite3 binary."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-ds-sqlite3-")
        self._bin = os.path.join(self._tmp, "bin")
        os.makedirs(self._bin)
        self._argv_file = os.path.join(self._tmp, "sqlite3-argv.log")
        open(self._argv_file, "w").close()
        _write_fake_sqlite3(self._bin, self._argv_file)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, script_body, extra_env=None):
        env = os.environ.copy()
        env["PATH"] = self._bin + os.pathsep + env["PATH"]
        if extra_env:
            env.update(extra_env)
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            {script_body}
        """)
        return subprocess.run(
            ["sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, env=env,
        )

    def _read_argv(self):
        with open(self._argv_file) as f:
            return f.read()

    def test_default_busy_timeout_is_applied(self):
        result = self._run("ds_sqlite3 /tmp/fake.db 'SELECT 1;'")
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = self._read_argv()
        self.assertIn(
            '-cmd .timeout 5000 /tmp/fake.db SELECT 1;', argv,
            f"expected the default 5000ms busy timeout prefixed before the "
            f"forwarded args; recorded argv={argv!r}",
        )

    def test_configured_busy_timeout_is_honored(self):
        result = self._run(
            "ds_sqlite3 /tmp/fake.db 'SELECT 1;'",
            extra_env={"CLAGENTIC_SQLITE_BUSY_TIMEOUT_MS": "9000"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = self._read_argv()
        self.assertIn("-cmd .timeout 9000", argv, f"recorded argv={argv!r}")

    def test_non_numeric_timeout_falls_back_to_default(self):
        result = self._run(
            "ds_sqlite3 /tmp/fake.db 'SELECT 1;'",
            extra_env={"CLAGENTIC_SQLITE_BUSY_TIMEOUT_MS": "not-a-number"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = self._read_argv()
        self.assertIn(
            "-cmd .timeout 5000", argv,
            f"expected fallback to the 5000ms default on a non-numeric "
            f"timeout; recorded argv={argv!r}",
        )

    def test_zero_timeout_falls_back_to_default(self):
        """A bare `case ''|*[!0-9]*` guard would admit "0" unchanged, and
        `.timeout 0` disables the busy wait entirely -- ds_positive_int_or_
        default must reject zero too, not just non-numeric/empty input."""
        result = self._run(
            "ds_sqlite3 /tmp/fake.db 'SELECT 1;'",
            extra_env={"CLAGENTIC_SQLITE_BUSY_TIMEOUT_MS": "0"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = self._read_argv()
        self.assertIn(
            "-cmd .timeout 5000", argv,
            f"expected fallback to the 5000ms default on a zero timeout "
            f"(the exact 'admits 0 unchanged' defect class INV-1a-adjacent "
            f"fixes in this codebase close); recorded argv={argv!r}",
        )

    def test_empty_timeout_falls_back_to_default(self):
        result = self._run(
            "ds_sqlite3 /tmp/fake.db 'SELECT 1;'",
            extra_env={"CLAGENTIC_SQLITE_BUSY_TIMEOUT_MS": ""},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = self._read_argv()
        self.assertIn("-cmd .timeout 5000", argv, f"recorded argv={argv!r}")

    def test_forwards_all_original_arguments(self):
        """Verifies ds_sqlite3 does not otherwise interpret its arguments --
        the DB path, flags (-separator, -header, -column), and SQL text must
        all reach the real sqlite3 binary unchanged, just prefixed."""
        result = self._run(
            "ds_sqlite3 -separator '|' /tmp/audit.db 'SELECT ts, gate FROM gate_runs;'"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = self._read_argv()
        self.assertIn("-separator | /tmp/audit.db SELECT ts, gate FROM gate_runs;", argv)


@unittest.skipUnless(_HAS_SQLITE3_CLI, "sqlite3 CLI not installed")
class TestDsSqlite3ConcurrentWritersBothSucceed(unittest.TestCase):
    """Acceptance criterion from lr-c71845: given two concurrent writers to
    the same audit.db, both succeed (the second waits up to the busy
    timeout rather than failing immediately with SQLITE_BUSY)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-ds-sqlite3-busy-")
        self._db = os.path.join(self._tmp, "audit.db")
        # Real schema, matching gates.sh's cmd_init.
        _pysqlite3.connect(self._db).execute(
            "CREATE TABLE gate_runs (id INTEGER PRIMARY KEY, ts TEXT, "
            "gate TEXT, outcome TEXT, details TEXT, session_id TEXT, branch TEXT)"
        ).connection.commit()

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_two_concurrent_writers_both_succeed(self):
        # A long-running transaction holding the write lock, to force any
        # concurrent writer to actually exercise the busy-retry path rather
        # than getting lucky with non-overlapping timing.
        blocker_conn = _pysqlite3.connect(self._db, timeout=0)
        blocker_conn.execute("BEGIN IMMEDIATE")
        blocker_conn.execute(
            "INSERT INTO gate_runs (ts, gate, outcome) VALUES ('t0','blocker','pass')"
        )

        results = {}

        def _writer(key, release_after_sec):
            env = os.environ.copy()
            env["CLAGENTIC_SQLITE_BUSY_TIMEOUT_MS"] = "5000"
            script = textwrap.dedent(f"""\
                . '{PLATFORM_SH}'
                ds_sqlite3 '{self._db}' \\
                  "INSERT INTO gate_runs (ts, gate, outcome) VALUES ('t1','writer-{key}','pass');"
            """)
            proc = subprocess.Popen(
                ["sh", "-c", script, PLATFORM_SH],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            results[key] = proc

        thread = threading.Thread(target=_writer, args=("A", 0))
        thread.start()
        # Give the writer time to attempt the write and hit the lock, then
        # release the blocking transaction well within the 5s busy timeout.
        import time
        time.sleep(0.5)
        blocker_conn.commit()
        blocker_conn.close()
        thread.join(timeout=10)

        proc = results["A"]
        stdout, stderr = proc.communicate(timeout=10)
        self.assertEqual(
            proc.returncode, 0,
            f"concurrent writer failed instead of waiting out the busy "
            f"timeout: stdout={stdout!r} stderr={stderr!r}",
        )

        check_conn = _pysqlite3.connect(self._db)
        rows = check_conn.execute("SELECT gate FROM gate_runs ORDER BY id").fetchall()
        gates = [r[0] for r in rows]
        self.assertIn("blocker", gates)
        self.assertIn("writer-A", gates)


class TestNoBareSqlite3CallAgainstAuditDb(unittest.TestCase):
    """Sweep gates.sh and platform.sh for any `sqlite3 "$AUDIT_DB"`/
    `sqlite3 "$DB"`-shaped call that bypasses ds_sqlite3 -- the
    unwritable-bare-form guarantee the wrapper exists to provide (lr-c71845,
    mirroring run_bounded's own sweep discipline). A future bare invocation
    at any of these two files must trip this test immediately."""

    # Matches a bare `sqlite3` INVOCATION (the binary being called), not a
    # `command -v sqlite3` capability probe -- `command -v` checks whether
    # the binary exists on PATH without running it, so it carries no
    # SQLITE_BUSY exposure and is not part of this sweep's scope.
    _BARE_SQLITE3_RE = re.compile(r'(?<!ds_)\bsqlite3\s')
    _CAPABILITY_PROBE_RE = re.compile(r'command\s+-v\s+sqlite3\b')

    def _bare_calls(self, path):
        with open(path) as f:
            lines = f.readlines()
        violations = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._CAPABILITY_PROBE_RE.search(line):
                continue
            for m in self._BARE_SQLITE3_RE.finditer(line):
                # Skip the wrapper's own definition line (`ds_sqlite3() { ...
                # sqlite3 -cmd ... "$@"; }`) and its doc comment references --
                # those are the ONE legitimate bare call, inside the wrapper
                # itself.
                if "ds_sqlite3() {" in line or "sqlite3 -cmd" in line:
                    continue
                violations.append((i + 1, line.rstrip("\n")))
        return violations

    def test_gates_sh_has_no_bare_sqlite3_call(self):
        violations = self._bare_calls(GATES_SH)
        self.assertEqual(
            violations, [],
            f"found bare sqlite3 call(s) in gates.sh bypassing ds_sqlite3:\n" +
            "\n".join(f"  gates.sh:{ln}: {txt}" for ln, txt in violations),
        )

    def test_platform_sh_has_no_bare_sqlite3_call(self):
        violations = self._bare_calls(PLATFORM_SH)
        self.assertEqual(
            violations, [],
            f"found bare sqlite3 call(s) in platform.sh bypassing "
            f"ds_sqlite3:\n" +
            "\n".join(f"  platform.sh:{ln}: {txt}" for ln, txt in violations),
        )

    def test_sweep_actually_finds_ds_sqlite3_call_sites(self):
        """Sanity check on the discovery mechanism: gates.sh must contain
        at least one ds_sqlite3 call, or this sweep is vacuously passing
        because its own regex is broken, not because gates.sh is clean."""
        with open(GATES_SH) as f:
            content = f.read()
        self.assertGreaterEqual(
            content.count("ds_sqlite3 "), 1,
            "sweep anchor failed: gates.sh has no ds_sqlite3 call at all "
            "-- either the sweep regex is broken or the wrapper was never "
            "actually wired in",
        )


if __name__ == "__main__":
    unittest.main()
