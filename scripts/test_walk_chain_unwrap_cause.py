"""
Regression coverage for lr-33958f (PR-C): walk_chain (scripts/llm-client.sh)
must distinguish TWO degraded causes on its OWN return channel, not just the
single "3" status PR-B (lr-7047bf) introduced:

  status 3, cause "infra"   -- misconfigured/auth-broken/network-out chain
                                (no chain configured, or every invocation
                                itself failed).
  status 4, cause "unwrap"  -- every configured step's model INVOCATION
                                succeeded (auth worked, tokens were spent)
                                but its output could never be reduced to
                                exactly one role-shaped JSON candidate.

THIS IS THE MISCLASSIFICATION THE FOUNDRY INSISTED ON HARDEST: a model that
ran successfully and returned prose is NOT infrastructure failure, and
walk_chain must not collapse the two into the same exit status the way it
did before this task -- collapsing them is exactly what would still send an
operator to check CLI config/auth for a problem in neither.

These tests source the ACTUAL sh function via `sh -c`, mirroring the
established fake-binary-on-PATH technique test_walk_chain_degraded_status.py
already uses (same helpers, reused directly rather than reimplemented).

Run with: python3 -m unittest scripts.test_walk_chain_unwrap_cause -v
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
    """Identical helper to test_walk_chain_degraded_status.py -- reused, not
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


def _write_prose_only_claude(bin_dir):
    """A `claude` stub that succeeds (exit 0) and emits a --output-format
    json envelope whose .result is PROSE ONLY -- no fenced or bare JSON at
    all. Simulates a model that ran successfully (auth worked, tokens were
    spent) but never produced parseable output -- the exact shape that must
    classify as cause "unwrap", not cause "infra"."""
    path = os.path.join(bin_dir, "claude")
    envelope = json.dumps({
        "type": "result",
        "result": "I reviewed the diff and it looks fine, no issues to report.",
        "num_turns": 12,
        "duration_ms": 8000,
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


def _write_always_failing_claude(bin_dir):
    """Identical to test_walk_chain_degraded_status.py's helper: exits 1
    unconditionally -- an invocation-level failure, cause "infra"."""
    path = os.path.join(bin_dir, "claude")
    with open(path, "w") as f:
        f.write(textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            exit 1
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _run_walk_chain(role_lower, mode, claude_writer):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-unwrap-")
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


class TestWalkChainDistinguishesUnwrapCauseFromInfraCause(unittest.TestCase):
    """The core status-4-vs-3 contract, exercised through the real
    walk_chain function end to end (invoke_step -> _llm_unwrap_json_
    envelope -> the ANY_INVOCATION_FAILED/ANY_UNWRAP_FAILED classification
    -> emit_degraded's cause arg)."""

    def test_prose_only_model_response_returns_4_not_3(self):
        stdout, stderr, rc = _run_walk_chain("reviewer", "json", _write_prose_only_claude)
        self.assertEqual(
            rc, 4,
            f"a model that ran successfully but returned no parseable "
            f"role-shaped JSON must return status 4 (cause 'unwrap'), not "
            f"3 (cause 'infra') -- collapsing the two is the exact "
            f"misdirection the foundry named. stdout={stdout!r} stderr={stderr!r}",
        )

    def test_prose_only_envelope_carries_cause_unwrap(self):
        stdout, stderr, rc = _run_walk_chain("reviewer", "json", _write_prose_only_claude)
        self.assertIn('"degraded": true', stdout)
        self.assertIn(
            '"cause": "unwrap"', stdout,
            f"the emitted degraded envelope must carry cause:'unwrap' so a "
            f"caller reading the file directly (not just the exit status) "
            f"can also distinguish this outcome. stdout={stdout!r}",
        )

    def test_invocation_failure_still_returns_3_cause_infra(self):
        """Negative control / non-regression: the pre-existing all-steps-
        invocation-failed path (PR-B's own target) must still return 3,
        cause 'infra' -- this task narrows nothing about that path."""
        stdout, stderr, rc = _run_walk_chain("reviewer", "json", _write_always_failing_claude)
        self.assertEqual(
            rc, 3,
            f"an invocation-level failure (CLI exits nonzero) must still "
            f"return 3, unaffected by this task. stdout={stdout!r} stderr={stderr!r}",
        )
        self.assertIn('"cause": "infra"', stdout)

    def test_markdown_mode_unwrap_cause_is_a_no_op_returns_3(self):
        """_llm_unwrap_json_envelope is a no-op for non-json modes (markdown/
        line) -- there is no envelope shape to unwrap, so a fully prose-
        returning auditor in markdown mode still exhausts the chain via the
        ordinary schema-mismatch path (validate_output's markdown branch
        accepts any non-empty payload, so this specific stub would actually
        PASS as a real -- but a claude stub that fails outright still
        produces the pre-existing 'infra' cause in markdown mode, proving
        the unwrap cause is JSON-mode-specific by construction, not a
        blanket new degraded reason for every mode)."""
        stdout, stderr, rc = _run_walk_chain("auditor", "markdown", _write_always_failing_claude)
        self.assertEqual(rc, 3, f"stdout={stdout!r} stderr={stderr!r}")
        self.assertIn("(cause: infra)", stdout)


if __name__ == "__main__":
    unittest.main()
