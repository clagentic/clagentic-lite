"""
Regression coverage for lr-7047bf (PR-B, INV-1): walk_chain (llm-client.sh)
must return a distinct non-zero status (3) whenever it emits a degraded
envelope, on BOTH paths that call emit_degraded -- the full-chain-failure
path (every configured step failed) and the no-chain-configured path
(non-summarizer role with nothing configured).

Root cause: walk_chain used to `return 0` unconditionally after either
emit_degraded call. A degraded envelope and a real, successful response
were then indistinguishable on the one channel every caller actually
checks (the exit status) -- `if EXIT_CODE -eq 0` read a degraded chain
exactly like a clean pass. This is the single highest-leverage fix in the
class: it flips the default for every consumer at once, and after it a
consumer that wants the old permissive behavior must write `|| true`
explicitly.

These tests source the ACTUAL sh function (walk_chain) from llm-client.sh
via `sh -c`, mirroring test_llm_client_sh.py's and
test_invoke_exit_status_sweep.py's established fake-binary-on-PATH
technique -- a Python mirror of the logic would not catch a regression in
the real function body.

Run with: python3 -m unittest scripts.test_walk_chain_degraded_status -v
"""
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
    """Copy llm-client.sh into dest_dir with its trailing subcommand
    dispatch stripped off, so it is safe to `.` source without executing
    cmd_build/cmd_review/etc or calling `exit`. Mirrors test_llm_client_sh.py
    and test_invoke_exit_status_sweep.py's identical helper (same technique,
    reused rather than diverging)."""
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
    """A `claude` stub that drains stdin and exits 1 unconditionally --
    drives walk_chain's every-step-failed path deterministically."""
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


def _run_walk_chain(role_lower, mode, extra_env=None, configure_chain=True):
    """Source llm-client.sh (functions only) and call walk_chain directly.
    Returns (stdout, stderr, returncode)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-")
    try:
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        _write_always_failing_claude(bin_dir)

        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced = _functions_only_source(src_dir)

        role_upper = role_lower.upper()
        env_lines = []
        if configure_chain:
            env_lines.append(f"export CLAGENTIC_{role_upper}_CMD=claude")
        env_lines_text = "\n".join(env_lines)

        # A trivial prompt func -- walk_chain takes a function NAME (PFUNC)
        # and calls it, matching the real call shape in cmd_review/
        # cmd_adversarial/cmd_merge_gate (`walk_chain <role> <mode> ds_*_prompt`).
        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            {env_lines_text}
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


class TestWalkChainReturnsDistinctStatusOnFullChainFailure(unittest.TestCase):
    """The polarity flip's primary target: llm-client.sh:~1538-1554, every
    configured chain step fails."""

    def test_returns_3_not_0_when_every_step_fails(self):
        stdout, stderr, rc = _run_walk_chain("auditor", "markdown")
        self.assertEqual(
            rc, 3,
            f"walk_chain must return 3 (not 0) when every chain step failed "
            f"and a degraded envelope was emitted. stdout={stdout!r} stderr={stderr!r}",
        )

    def test_still_emits_the_degraded_envelope_despite_nonzero_return(self):
        """The status flip must not come at the cost of the payload -- a
        caller that still wants the degraded content (e.g. to cat it to the
        user) must still get it on stdout."""
        stdout, stderr, rc = _run_walk_chain("auditor", "markdown")
        self.assertIn(
            "# Degraded output", stdout,
            f"walk_chain must still emit the degraded envelope on stdout "
            f"even though it now also returns nonzero. stdout={stdout!r}",
        )

    def test_json_mode_degraded_envelope_also_returns_3(self):
        stdout, stderr, rc = _run_walk_chain("reviewer", "json")
        self.assertEqual(rc, 3, f"stdout={stdout!r} stderr={stderr!r}")
        self.assertIn('"degraded": true', stdout)

    def test_required_role_hard_failure_still_returns_1_not_3(self):
        """CLAGENTIC_<ROLE>_REQUIRED=1 is a distinct, pre-existing contract
        (a hard failure, no degraded envelope at all) that must not be
        conflated with the new degraded-envelope status 3 -- the two are
        different outcomes (no payload vs. a degraded payload) and must
        stay distinguishable on the exit status."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-required-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_always_failing_claude(bin_dir)
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            sourced = _functions_only_source(src_dir)
            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export CLAGENTIC_REVIEWER_CMD=claude
                export CLAGENTIC_REVIEWER_REQUIRED=1
                _fixture_prompt() {{ printf 'test prompt'; }}
                . '{sourced}'
                printf 'stdin diff content' | walk_chain reviewer json _fixture_prompt
            """)
            r = subprocess.run(
                ["sh", "-c", script, sourced],
                capture_output=True, text=True, cwd=TOOL_HOME,
            )
            self.assertEqual(
                r.returncode, 1,
                f"CLAGENTIC_REVIEWER_REQUIRED=1 hard failure must still "
                f"return 1, distinct from the degraded-envelope status 3. "
                f"stdout={r.stdout!r} stderr={r.stderr!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestWalkChainReturnsDistinctStatusOnNoChainConfigured(unittest.TestCase):
    """The second (fold-in) flip target: llm-client.sh:~1451-1464, no chain
    configured at all for a non-summarizer role. Same defect class, same
    function, same emit_degraded-then-return-0 shape -- the task's own
    'close the class, not the reported instance' directive applies within
    this single function, not just across gates.sh call sites."""

    def test_returns_3_when_no_chain_configured_for_non_summarizer_role(self):
        stdout, stderr, rc = _run_walk_chain("gate", "json", configure_chain=False)
        self.assertEqual(
            rc, 3,
            f"walk_chain must return 3 when no chain is configured for a "
            f"non-summarizer role (a degraded envelope is still emitted). "
            f"stdout={stdout!r} stderr={stderr!r}",
        )
        self.assertIn('"degraded": true', stdout)

    def test_summarizer_role_with_no_chain_still_returns_0(self):
        """The summarizer's no-chain path is a deliberate, documented
        silent no-op (memory.sh's cmd_summarize_turn already guards on an
        empty summary) -- NOT a degraded emission, and must not be swept
        into the same nonzero-return change. This is the control proving
        the flip only touches the two emit_degraded call sites, not every
        walk_chain return path."""
        stdout, stderr, rc = _run_walk_chain("summarizer", "line", configure_chain=False)
        self.assertEqual(
            rc, 0,
            f"the summarizer's benign no-chain skip must still return 0. "
            f"stdout={stdout!r} stderr={stderr!r}",
        )
        self.assertNotIn("degraded", stdout.lower())


if __name__ == "__main__":
    unittest.main()
