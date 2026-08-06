"""
Regression coverage for lr-829fcd: walk_chain (scripts/llm-client.sh) must
emit a one-line stderr notice on a step-failed outcome and on an overall
fallback (ATTEMPT > 1) outcome -- previously log_attempt (~line 1066) was
the ONLY destination for these outcomes (audit.db's gate_runs table via
ds_audit_log), so a same-vendor fallback (e.g. an auditor chain step timing
out and falling through to the next configured step) produced zero visible
signal on a normal `gates review`/`gates ship` run and was only
discoverable by manually querying audit.db.

Three properties this file proves, exercised through the real walk_chain
function end to end (mirroring the established fake-binary-on-PATH
technique test_walk_chain_unwrap_cause.py and
test_walk_chain_turns_exhausted.py already use):

  1. A step that fails (invocation error) and the chain advances emits a
     "step-failed" notice to stderr.
  2. An overall result that is a fallback (ATTEMPT > 1, not a clean primary
     pass) emits a "fallback" notice to stderr.
  3. A clean primary-pass run (ATTEMPT == 1, no failing step) stays silent
     on stderr -- the happy path must not gain new noise.

stdout is asserted clean of the notice text in every case: the notices are
stderr-only so machine-readable gate output is never polluted, and
audit.db logging (log_attempt, unaffected by this task) is not re-tested
here -- it already has its own coverage.

Run with: python3 -m unittest scripts.test_walk_chain_stderr_notice -v
"""
import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LLM_CLIENT_SH = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def _functions_only_source(dest_dir):
    """Identical helper to test_walk_chain_unwrap_cause.py -- reused, not
    reimplemented."""
    with open(LLM_CLIENT_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in llm-client.sh"
    dest = os.path.join(dest_dir, "llm-client.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    platform_dest = os.path.join(dest_dir, "platform.sh")
    with open(PLATFORM_SH) as src, open(platform_dest, "w") as dst:
        dst.write(src.read())
    return dest


def _write_always_failing_claude(bin_dir):
    """Identical to test_walk_chain_unwrap_cause.py's helper: exits 1
    unconditionally -- an invocation-level failure (step-failed)."""
    path = os.path.join(bin_dir, "claude")
    with open(path, "w") as f:
        f.write(textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            echo "simulated timeout" 1>&2
            exit 1
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_normal_success_claude(bin_dir, num_turns=6):
    """A `claude` stub that succeeds with subtype=="success" and a clean,
    parseable findings:[] result -- used both as the fallback CLI's
    behavior (second attempt succeeds) and as the negative-control primary
    (first attempt succeeds, ATTEMPT stays 1)."""
    path = os.path.join(bin_dir, "claude")
    inner = json.dumps({"summary": "clean diff", "checked": ["security"], "findings": []})
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "num_turns": num_turns,
        "duration_ms": 4000,
        "is_error": False,
        "result": inner,
    })
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            cat <<'ENVELOPE'
{envelope}
ENVELOPE
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_first_call_fails_then_succeeds_claude(bin_dir):
    """A single `claude` binary (same vendor on both chain steps, mirroring
    the task's own motivating example -- 'auditor codex times out -> falls
    back to claude') that fails its FIRST invocation and succeeds on every
    subsequent one, driven by a counter file so walk_chain's own two-step
    chain (primary + one CLAGENTIC_<ROLE>_CHAIN entry) produces a real
    step-failed followed by a real fallback pass."""
    path = os.path.join(bin_dir, "claude")
    counter_file = os.path.join(bin_dir, "call-count")
    inner = json.dumps({"summary": "clean diff", "checked": ["security"], "findings": []})
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "num_turns": 5,
        "duration_ms": 3000,
        "is_error": False,
        "result": inner,
    })
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            COUNT_FILE='{counter_file}'
            N=0
            [ -f "$COUNT_FILE" ] && N=$(cat "$COUNT_FILE")
            N=$((N+1))
            echo "$N" > "$COUNT_FILE"
            if [ "$N" -eq 1 ]; then
              echo "simulated timeout" 1>&2
              exit 1
            fi
            cat <<'ENVELOPE'
{envelope}
ENVELOPE
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _run_walk_chain(role_lower, mode, claude_writer, chain=""):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-notice-")
    try:
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        claude_writer(bin_dir)

        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced = _functions_only_source(src_dir)

        role_upper = role_lower.upper()
        chain_export = f"export CLAGENTIC_{role_upper}_CHAIN='{chain}'" if chain else ""
        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            export CLAGENTIC_{role_upper}_CMD=claude
            {chain_export}
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{sourced}'
            printf 'stdin diff content' | walk_chain '{role_lower}' '{mode}' _fixture_prompt
        """)
        r = subprocess.run(
            ["sh", "-c", script, sourced],
            capture_output=True,
            text=True,
            cwd=TOOL_HOME,
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestWalkChainStderrNotice(unittest.TestCase):
    """The core stderr-visibility contract this task adds."""

    def test_step_failed_emits_stderr_notice(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json", _write_always_failing_claude,
        )
        self.assertIn(
            "step-failed", stderr,
            f"a failing chain step must emit a one-line stderr notice "
            f"carrying the step-failed outcome. stderr={stderr!r}",
        )
        self.assertIn("role=auditor", stderr)
        self.assertIn("cli=claude", stderr)

    def test_step_failed_notice_not_on_stdout(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json", _write_always_failing_claude,
        )
        self.assertNotIn(
            "step-failed", stdout,
            f"the step-failed notice must go to stderr only -- stdout is "
            f"machine-readable gate output and must stay clean. "
            f"stdout={stdout!r}",
        )

    def test_fallback_emits_stderr_notice(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json", _write_first_call_fails_then_succeeds_claude,
            chain="claude:fallback",
        )
        self.assertEqual(rc, 0, f"expected the fallback step to pass. stdout={stdout!r} stderr={stderr!r}")
        self.assertIn(
            "fallback", stderr,
            f"an overall result reached via a fallback step (ATTEMPT > 1) "
            f"must emit a one-line stderr notice, carrying role/cli/tier -- "
            f"this is the exact gap lr-829fcd reports: a same-vendor "
            f"fallback (auditor codex times out, falls back to claude) was "
            f"previously invisible outside audit.db. stderr={stderr!r}",
        )
        self.assertIn("role=auditor", stderr)

    def test_fallback_notice_not_on_stdout(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json", _write_first_call_fails_then_succeeds_claude,
            chain="claude:fallback",
        )
        self.assertEqual(rc, 0, f"stdout={stdout!r} stderr={stderr!r}")
        self.assertNotIn(
            "[clagentic-lite/llm-client] fallback", stdout,
            f"the fallback notice must go to stderr only. stdout={stdout!r}",
        )
        self.assertIn('"findings": []', stdout, "the real payload must still reach stdout")

    def test_clean_primary_pass_is_silent_on_stderr(self):
        """The happy path: ATTEMPT stays 1, no step ever fails -- no new
        noise on stderr. This is the acceptance criterion that the notice
        must not fire on a clean primary pass."""
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json", _write_normal_success_claude,
        )
        self.assertEqual(rc, 0, f"stdout={stdout!r} stderr={stderr!r}")
        self.assertNotIn("step-failed", stderr)
        self.assertNotIn("[clagentic-lite/llm-client] fallback", stderr)
        self.assertNotIn("[clagentic-lite/llm-client] pass", stderr)


if __name__ == "__main__":
    unittest.main()
