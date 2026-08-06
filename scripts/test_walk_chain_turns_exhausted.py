"""
Regression coverage for the class-4 foundry fix, mitigation (b): walk_chain
(scripts/llm-client.sh) must classify subtype=="error_max_turns" on the raw
--output-format json envelope as a THIRD, distinct degraded cause
("turns-exhausted", exit status 5) -- never folded into "infra" (status 3)
or "unwrap" (status 4), and never allowed to reach the ordinary pass branch
even when the truncated output happens to be well-formed, role-shaped JSON.

THE RISK THIS CLOSES (foundry's own framing, "the risk that matters most"):
a turn cap tight enough to bound the tool loop is, by construction, tight
enough to truncate the caller-tracing the reviewer prompt mandates. A
truncated reviewer can still emit perfectly well-formed JSON with
findings:[] -- which would otherwise sail through validate_output and the
existing degraded checks and ship as a clean pass. THE FAILURE SIGNATURE IS
THE GATE TURNING GREEN MORE OFTEN, with no alarm for it. This file proves
that even a WELL-FORMED, ROLE-SHAPED, ZERO-FINDINGS envelope is still
rejected as degraded when its subtype says the model was cut off.

These tests source the ACTUAL sh function via `sh -c`, mirroring the
established fake-binary-on-PATH technique test_walk_chain_unwrap_cause.py
and test_walk_chain_degraded_status.py already use (same helpers, reused
directly rather than reimplemented).

Run with: python3 -m unittest scripts.test_walk_chain_turns_exhausted -v
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


def _write_turns_exhausted_claude(bin_dir, num_turns=48, result_body=None):
    """A `claude` stub that succeeds (exit 0) and emits a --output-format
    json envelope carrying subtype=="error_max_turns" -- the exact signal
    Claude Code's own SDKResultError type uses to report the agentic loop
    was cut off before finishing (confirmed against the installed
    claude-agent-sdk's sdk.d.ts; see _llm_turn_diagnostics's own comment).
    result_body, when given, is well-formed role-shaped JSON (proving even
    a CLEAN-LOOKING partial result must still be rejected)."""
    path = os.path.join(bin_dir, "claude")
    envelope = {
        "type": "result",
        "subtype": "error_max_turns",
        "num_turns": num_turns,
        "duration_ms": 90000,
        "is_error": True,
    }
    if result_body is not None:
        envelope["result"] = result_body
    envelope_json = json.dumps(envelope)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            cat <<'ENVELOPE'
{envelope_json}
ENVELOPE
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_normal_success_claude(bin_dir, num_turns=6):
    """A `claude` stub that succeeds with subtype=="success" and a clean,
    parseable findings:[] result -- the ordinary passing case, unaffected
    by this task, used as a negative control."""
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


def _run_walk_chain(role_lower, mode, claude_writer):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-turns-")
    try:
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        claude_writer(bin_dir)

        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced = _functions_only_source(src_dir)

        role_upper = role_lower.upper()
        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            export CLAGENTIC_{role_upper}_CMD=claude
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


class TestWalkChainClassifiesTurnsExhaustedDistinctly(unittest.TestCase):
    """The core status-5 contract: subtype=="error_max_turns" must produce
    a distinct exit status and cause, never conflated with 3 (infra) or 4
    (unwrap), and the chain must exhaust every configured step (there is
    only one step here, so the overall chain fails) rather than treating a
    single turns-exhausted step as an ordinary retryable failure that could
    still emit a pass on a later attempt reading stale output."""

    def test_turns_exhausted_response_returns_5_not_3_or_4(self):
        stdout, stderr, rc = _run_walk_chain(
            "reviewer", "json",
            lambda bin_dir: _write_turns_exhausted_claude(bin_dir, num_turns=48),
        )
        self.assertEqual(
            rc, 5,
            f"a model that hit subtype=='error_max_turns' must return "
            f"status 5 (cause 'turns-exhausted'), distinct from 3 (infra) "
            f"and 4 (unwrap). stdout={stdout!r} stderr={stderr!r}",
        )

    def test_turns_exhausted_envelope_carries_cause_turns_exhausted(self):
        stdout, stderr, rc = _run_walk_chain(
            "reviewer", "json",
            lambda bin_dir: _write_turns_exhausted_claude(bin_dir, num_turns=48),
        )
        self.assertIn('"degraded": true', stdout)
        self.assertIn(
            '"cause": "turns-exhausted"', stdout,
            f"the emitted degraded envelope must carry cause:'turns-exhausted' "
            f"so a caller reading the file directly can also distinguish "
            f"this outcome. stdout={stdout!r}",
        )

    def test_turns_exhausted_reason_mentions_num_turns(self):
        stdout, stderr, rc = _run_walk_chain(
            "reviewer", "json",
            lambda bin_dir: _write_turns_exhausted_claude(bin_dir, num_turns=48),
        )
        self.assertIn(
            "num_turns=48", stdout,
            f"the degraded reason text must surface the measured num_turns "
            f"value so an operator can see how close to the ceiling the "
            f"run got, not just that it was truncated. stdout={stdout!r}",
        )

    def test_well_formed_partial_json_result_is_still_rejected(self):
        """THE CORE OF THE RISK THE FOUNDRY FLAGGED HARDEST: a
        subtype=='error_max_turns' envelope whose .result is ALREADY
        well-formed, role-shaped JSON (findings:[]) -- exactly the shape
        that would otherwise pass validate_output and every existing
        degraded check -- must still be classified as turns-exhausted, not
        silently accepted as a clean pass."""
        well_formed_result = json.dumps({
            "summary": "partial review, cut off",
            "checked": ["security"],
            "findings": [],
        })
        stdout, stderr, rc = _run_walk_chain(
            "reviewer", "json",
            lambda bin_dir: _write_turns_exhausted_claude(
                bin_dir, num_turns=48, result_body=well_formed_result),
        )
        self.assertEqual(
            rc, 5,
            f"a truncated run with well-formed partial JSON must still be "
            f"rejected as turns-exhausted (status 5) -- this is exactly "
            f"the invisible-truncation risk the foundry named. "
            f"stdout={stdout!r} stderr={stderr!r}",
        )
        self.assertNotIn(
            "partial review, cut off", stdout,
            f"the well-formed-but-truncated .result content must NOT be "
            f"passed through to stdout as if it were a real, complete "
            f"review -- the degraded envelope (not the model's own partial "
            f"summary/checked/findings) must be what's emitted. "
            f"stdout={stdout!r}",
        )
        self.assertIn(
            '"degraded": true', stdout,
            f"the degraded envelope itself must still be emitted. stdout={stdout!r}",
        )

    def test_ordinary_success_is_unaffected_returns_0(self):
        """Negative control: a normal subtype=='success' response with a
        clean findings:[] result must pass exactly as before -- this task
        narrows nothing about the ordinary path."""
        stdout, stderr, rc = _run_walk_chain(
            "reviewer", "json",
            lambda bin_dir: _write_normal_success_claude(bin_dir, num_turns=6),
        )
        self.assertEqual(rc, 0, f"stdout={stdout!r} stderr={stderr!r}")
        self.assertIn('"findings": []', stdout)


if __name__ == "__main__":
    unittest.main()
