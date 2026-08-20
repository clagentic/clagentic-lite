"""
Regression coverage for lr-c0c9f3: walk_chain's (scripts/llm-client.sh)
step-failure classification chain (:2761-2832 at the time of the fix) must
never report a nonzero-exit, empty-stderr CLI failure as SCHEMA-INVALID.

ROOT CAUSE: the two UNWRAP-FAILED branches are guarded by
[ "$EXIT_CODE" -eq 0 ], but before this fix SCHEMA-INVALID was guarded only
by [ -s "$TMP_OUT" ]. Any step where the CLI exits NON-ZERO, writes its
diagnostic to STDOUT, and leaves stderr EMPTY fell past the
[ -s "$TMP_ERR" ] branch into SCHEMA-INVALID and was reported as "output
schema mismatch" -- absorbing exactly the invocation-failure case its own
comment said it was distinct from. invoke_claude pipes the input file into
the CLI (`cat "$INPUT_FILE" | ...`), which suppresses the CLI's own
no-stdin warning -- the one thing that would otherwise have populated
TMP_ERR -- so this precondition is not intermittent. Claude Code's auth
failure has exactly this shape: exit 1, "Failed to authenticate. API Error:
401 Invalid bearer token" on stdout, stderr empty.

FIX: a new branch guarded by [ "$EXIT_CODE" -ne 0 ] && [ -s "$TMP_OUT" ],
inserted after the [ -s "$TMP_ERR" ] branch and before SCHEMA-INVALID, sets
ANY_INVOCATION_FAILED=1 and builds ERR_HINT as "cli exited $EXIT_CODE:
<first non-blank ANSI-stripped line of TMP_OUT>" (falling back to "no
diagnostic output" when TMP_OUT has bytes but no non-blank line). The
[ -s "$TMP_OUT" ] half of the guard means a nonzero exit with BOTH streams
empty still falls through to the pre-existing final else ("empty output
(exit=$EXIT_CODE)"), unchanged. SCHEMA-INVALID is now reachable only at
EXIT_CODE=0, matching its own documentation and its two UNWRAP-FAILED
siblings.

Six acceptance cases from the task report, all exercised through the real
walk_chain function end to end via a stubbed CLI binary on PATH --
mirroring the established fake-binary-on-PATH technique
test_walk_chain_unwrap_cause.py and test_walk_chain_codex_err_hint.py
already use. No real CLI, no network, no vendor-string pattern matching
asserted anywhere (the fix is structural, trust the exit code -- see the
task's own non-goals).

Run with: python3 -m unittest scripts.test_walk_chain_invocation_failed_empty_stderr -v
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_AUTH_FAILURE_TEXT = "Failed to authenticate. API Error: 401 Invalid bearer token"


def _write_stub(bin_dir, name, stdout_body, stderr_body, exit_code):
    """A CLI stub answering --version (codex_version_check's/generic version
    probe, matching test_invoke_exit_status_sweep.py's convention) with a
    fixed, never-asserted-on version string, then on the real invocation
    drains stdin, writes stdout_body/stderr_body to their respective
    streams, and exits with exit_code."""
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "{name} 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            printf '%s' '{stdout_body}'
            printf '%s' '{stderr_body}' 1>&2
            exit {exit_code}
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_reviewer_schema_invalid_stub(bin_dir, name):
    """A CLI stub that succeeds (exit 0) and emits a --output-format json
    envelope whose .result is a fenced JSON block with a top-level
    .findings array -- role-shaped enough for _llm_unwrap_json_envelope to
    accept it as the sole candidate (UNWRAP_CODE=0) -- but each finding is
    MISSING the reviewer-only required issue_class/class_fix fields
    (lr-3eb18c), which validate_output's own, stricter, later check
    rejects. This is the genuine SCHEMA-INVALID shape: unwrap succeeds,
    validate_output fails -- must remain reachable at EXIT_CODE=0."""
    path = os.path.join(bin_dir, name)
    inner_json = json.dumps({
        "summary": "clean",
        "checked": ["security"],
        "findings": [{"severity": "low", "file": "a.py", "line": 1,
                       "category": "style", "message": "x", "evidence": "y",
                       "suggestion": "z"}],
    })
    result_value = "```json\n" + inner_json + "\n```"
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "num_turns": 3,
        "duration_ms": 1000,
        "is_error": False,
        "result": result_value,
    })
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "{name} 99.0.0"
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


def _write_gate_schema_invalid_stub(bin_dir, name):
    """A CLI stub that succeeds (exit 0) and writes raw, non-envelope JSON
    directly to stdout (no --output-format json wrapper, no .result field)
    that is valid JSON but not role-shaped for gate -- e.g.
    {"error":"auth expired"} instead of {"decision":"approve"}.
    _llm_unwrap_json_envelope no-ops on this (no top-level "type":"result"
    -- "nothing to unwrap", UNWRAP_CODE=0, FILE untouched), and
    validate_output's own gate shape check then fails it -- the genuine
    SCHEMA-INVALID case, reachable at EXIT_CODE=0."""
    path = os.path.join(bin_dir, name)
    payload = json.dumps({"error": "not a role-shaped payload"})
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "{name} 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            printf '%s' '{payload}'
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _run_walk_chain(role_lower, mode, stub_writer, cli="claude"):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-invfailed-")
    try:
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        stub_writer(bin_dir, cli)

        sourced = LLM_CLIENT_SH

        role_upper = role_lower.upper()
        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            export CLAGENTIC_{role_upper}_CMD={cli}
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{sourced}'
            printf 'stdin diff content' | walk_chain '{role_lower}' '{mode}' _fixture_prompt
        """)
        env = os.environ.copy()
        env.update(source_env(llm_client=True))
        r = subprocess.run(
            ["sh", "-c", script, sourced],
            capture_output=True,
            text=True,
            cwd=TOOL_HOME,
            env=env,
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestWalkChainInvocationFailedEmptyStderr(unittest.TestCase):
    """Acceptance case 1: nonzero exit, diagnostic on stdout, empty stderr
    must classify as invocation-failed, never schema mismatch."""

    def test_nonzero_exit_stdout_only_is_invocation_failed_not_schema(self):
        stdout, stderr, rc = _run_walk_chain(
            "gate", "json",
            lambda bd, cli: _write_stub(bd, cli, _AUTH_FAILURE_TEXT, "", 1),
        )
        self.assertIn(
            "cli exited 1", stderr,
            f"a nonzero-exit CLI failure with output on stdout and empty "
            f"stderr must be classified as invocation-failed, carrying "
            f"'cli exited $EXIT_CODE'. stderr={stderr!r}",
        )
        self.assertIn(
            _AUTH_FAILURE_TEXT, stderr,
            f"ERR_HINT must surface the diagnostic text the CLI actually "
            f"wrote to stdout. stderr={stderr!r}",
        )
        self.assertNotIn(
            "schema mismatch", stderr,
            f"an invocation-level auth failure must never be reported as "
            f"an output schema mismatch. stderr={stderr!r}",
        )


class TestWalkChainSchemaInvalidStillReachableAtExitZero(unittest.TestCase):
    """Acceptance case 2: the existing SCHEMA-INVALID hint must still fire,
    unchanged, when EXIT_CODE is 0 -- for both the reviewer|auditor and
    gate role variants."""

    def test_reviewer_role_schema_invalid_at_exit_zero(self):
        stdout, stderr, rc = _run_walk_chain(
            "reviewer", "json", _write_reviewer_schema_invalid_stub,
        )
        self.assertIn(
            "output schema mismatch: expected JSON with top-level .findings array",
            stderr,
            f"reviewer/auditor SCHEMA-INVALID hint must be unchanged at "
            f"EXIT_CODE=0. stderr={stderr!r}",
        )

    def test_gate_role_schema_invalid_at_exit_zero(self):
        stdout, stderr, rc = _run_walk_chain(
            "gate", "json", _write_gate_schema_invalid_stub,
        )
        self.assertIn(
            "output schema mismatch: expected JSON with .decision=approve|refuse",
            stderr,
            f"gate SCHEMA-INVALID hint must be unchanged at EXIT_CODE=0. "
            f"stderr={stderr!r}",
        )


class TestWalkChainStderrBranchUnaffected(unittest.TestCase):
    """Acceptance case 3: a nonzero exit WITH output on stderr must still
    take the [ -s "$TMP_ERR" ] branch -- codex's ^ERROR: tail -1 selection
    is unaffected by the new branch."""

    def test_nonzero_exit_with_stderr_still_uses_stderr_branch(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json",
            lambda bd, cli: _write_stub(bd, cli, "", "ERROR: unexpected status 404 Not Found", 1),
        )
        self.assertIn(
            "ERROR: unexpected status 404 Not Found", stderr,
            f"a nonzero exit with real stderr output must still take the "
            f"existing stderr-based classification, unaffected by the new "
            f"branch. stderr={stderr!r}",
        )
        self.assertNotIn("cli exited 1:", stderr)


class TestWalkChainBothStreamsEmptyFallsThroughToElse(unittest.TestCase):
    """Acceptance case 4: nonzero exit, both stdout and stderr empty, falls
    through to the final else (empty output) -- not the new branch."""

    def test_nonzero_exit_both_streams_empty_falls_to_final_else(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json",
            lambda bd, cli: _write_stub(bd, cli, "", "", 1),
        )
        self.assertIn(
            "empty output (exit=1)", stderr,
            f"nonzero exit with nothing on either stream must fall through "
            f"to the pre-existing final else branch. stderr={stderr!r}",
        )
        self.assertNotIn("cli exited 1:", stderr)


class TestWalkChainDedicatedExitCodesUnaffected(unittest.TestCase):
    """Acceptance case 5: exit 124 (timeout) and 127 (not on PATH) keep
    their dedicated hints -- the new branch never captures them, since it is
    checked after both in the if/elif chain."""

    def test_exit_124_keeps_timeout_hint(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json",
            lambda bd, cli: _write_stub(bd, cli, "some stdout noise", "", 124),
        )
        self.assertIn("timeout after", stderr, f"stderr={stderr!r}")
        self.assertNotIn("cli exited 124:", stderr)

    def test_exit_127_keeps_not_on_path_hint(self):
        stdout, stderr, rc = _run_walk_chain(
            "auditor", "json",
            lambda bd, cli: _write_stub(bd, cli, "some stdout noise", "", 127),
        )
        self.assertIn("cli not on PATH", stderr, f"stderr={stderr!r}")
        self.assertNotIn("cli exited 127:", stderr)


class TestWalkChainNewBranchSetsInvocationFailedCause(unittest.TestCase):
    """Acceptance case 6: ANY_INVOCATION_FAILED is set on the new branch, so
    the overall chain cause classification still reports "infra", not
    "unwrap" -- proven via the emitted degraded envelope's own cause field,
    since a single-step chain with no fallback exhausts and degrades."""

    def test_overall_cause_is_infra_not_unwrap(self):
        stdout, stderr, rc = _run_walk_chain(
            "reviewer", "json",
            lambda bd, cli: _write_stub(bd, cli, _AUTH_FAILURE_TEXT, "", 1),
        )
        self.assertEqual(
            rc, 3,
            f"a nonzero-exit, empty-stderr failure must classify as cause "
            f"'infra' (status 3), never 'unwrap' (status 4) -- the new "
            f"branch is an invocation-level failure, not a model-quality "
            f"one. stdout={stdout!r} stderr={stderr!r}",
        )
        self.assertIn('"cause": "infra"', stdout)


if __name__ == "__main__":
    unittest.main()
