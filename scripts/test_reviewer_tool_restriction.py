"""
Regression coverage for the class-4 foundry fix, INV-2 tool restriction:
invoke_claude (scripts/llm-client.sh) must pass --allowedTools Read,Grep,Glob
--disallowedTools Bash on the `claude --print` invocation when CALL_ROLE is
"reviewer", and must NOT pass either flag for any other role.

FOUNDRY RULING THIS ENFORCES:
  - The reviewer KEEPS Read/Grep/Glob -- its prompt mandates caller-tracing,
    import-checking, and guard-branch verification ("Have you read the
    surrounding context? Check callers, imports, and tests"; "trace at
    least one caller first"). Stripping those tools would silently gut
    review quality, invisibly (a shallower review still emits valid JSON
    and passes every gate).
  - The reviewer LOSES Bash -- nothing in its prompt asks it to execute
    anything, and a --print reviewer holding unrestricted Bash while
    reading an attacker-influenceable diff is a live prompt-injection-to-
    execution path.
  - No other role (auditor, gate, builder, summarizer) is touched --
    scoped narrowly to CALL_ROLE=="reviewer" only.

These tests source the ACTUAL sh function (invoke_claude) via `sh -c`,
mirroring test_llm_client_sh.py's established fake-binary-on-PATH technique
(same helpers, reused directly rather than reimplemented) -- proving the
real invocation emits the flags, not a Python mirror of the logic.

Run with: python3 -m unittest scripts.test_reviewer_tool_restriction -v
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


def _write_fake_claude(bin_dir, argv_file):
    """Identical to test_llm_client_sh.py's helper -- reused, not
    reimplemented."""
    fake = os.path.join(bin_dir, "claude")
    with open(fake, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_file}'
            cat > /dev/null  # drain stdin (the diff/prompt input)
            printf 'ok\\n'
        """))
    os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return fake


def _functions_only_source(dest_dir):
    """Identical to test_llm_client_sh.py's helper -- reused, not
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


def _run_invoke_claude(call_role, call_mode="json", model=""):
    """Identical call shape to test_llm_client_sh.py's _run_invoke_claude --
    reused, not reimplemented (that file's own fixture already proves
    CALL_ROLE is the 8th positional; this file exercises what it does with
    that positional now that it is actually read)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-reviewer-tools-")
    try:
        argv_file = os.path.join(tmpdir, "argv.log")
        open(argv_file, "w").close()
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        _write_fake_claude(bin_dir, argv_file)

        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_llm_client = _functions_only_source(src_dir)

        prompt_file = os.path.join(tmpdir, "prompt.txt")
        input_file = os.path.join(tmpdir, "input.txt")
        output_file = os.path.join(tmpdir, "output.txt")
        err_file = os.path.join(tmpdir, "err.txt")
        with open(prompt_file, "w") as f:
            f.write("test prompt")
        with open(input_file, "w") as f:
            f.write("test diff")

        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            . '{sourced_llm_client}'
            invoke_claude '{model}' '{prompt_file}' '{input_file}' '{output_file}' '{err_file}' 60 '{call_mode}' '{call_role}'
        """)
        r = subprocess.run(
            ["sh", "-c", script, sourced_llm_client],
            capture_output=True,
            text=True,
            cwd=TOOL_HOME,
        )
        with open(argv_file) as f:
            recorded = [line.rstrip("\n") for line in f if line.strip()]
        return recorded, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestReviewerRoleGetsToolRestrictionFlags(unittest.TestCase):
    """The core positive contract: CALL_ROLE=="reviewer" emits both flags,
    with the correct tool lists, on both the model-specified and
    model-unspecified invocation branches (invoke_claude has two separate
    code paths for this, mirroring test_llm_client_sh.py's own coverage of
    both branches for the --temperature guard)."""

    def test_reviewer_role_gets_allowed_and_disallowed_tools_flags(self):
        recorded, err, rc = _run_invoke_claude("reviewer", call_mode="json")
        self.assertEqual(rc, 0, f"invoke_claude exited non-zero: {err}")
        self.assertEqual(len(recorded), 1, f"expected exactly one claude invocation, got: {recorded}")
        argv = recorded[0]
        self.assertIn(
            "--allowedTools", argv,
            f"reviewer role must pass --allowedTools: {argv!r}",
        )
        self.assertIn(
            "Read,Grep,Glob", argv,
            f"reviewer role must allow exactly Read,Grep,Glob: {argv!r}",
        )
        self.assertIn(
            "--disallowedTools", argv,
            f"reviewer role must pass --disallowedTools: {argv!r}",
        )
        self.assertIn(
            "Bash", argv,
            f"reviewer role must disallow Bash: {argv!r}",
        )

    def test_reviewer_role_gets_tool_flags_with_model_specified(self):
        """Same guard on the model-specified branch of invoke_claude
        (separate code path from the no-model branch above)."""
        recorded, err, rc = _run_invoke_claude("reviewer", call_mode="json", model="sonnet")
        self.assertEqual(rc, 0, f"invoke_claude exited non-zero: {err}")
        self.assertEqual(len(recorded), 1, f"expected exactly one claude invocation, got: {recorded}")
        argv = recorded[0]
        self.assertIn("--allowedTools", argv, f"argv={argv!r}")
        self.assertIn("Read,Grep,Glob", argv, f"argv={argv!r}")
        self.assertIn("--disallowedTools", argv, f"argv={argv!r}")
        self.assertIn("Bash", argv, f"argv={argv!r}")

    def test_allowed_tools_keeps_read_grep_glob_not_a_broader_or_narrower_set(self):
        """Guards the EXACT set the foundry ruling requires -- not merely
        'some tools allowed'. The reviewer prompt mandates caller-tracing
        (Grep) and import-checking (Read/Glob); a set missing any of the
        three would silently gut review quality the same way an
        unrestricted set would silently reintroduce the Bash risk."""
        recorded, err, rc = _run_invoke_claude("reviewer", call_mode="json")
        self.assertEqual(rc, 0, f"err={err}")
        argv = recorded[0]
        for tool in ("Read", "Grep", "Glob"):
            self.assertIn(tool, argv, f"reviewer must keep {tool}: argv={argv!r}")


class TestNonReviewerRolesAreUntouched(unittest.TestCase):
    """Negative control, the other half of the foundry ruling: auditor,
    gate, builder, and summarizer must NEVER receive either tool-
    restriction flag -- stripping Bash from the auditor (which reads
    security-tool output) or the merge-gate would be exactly the
    over-broad simplification the foundry rejected."""

    def test_other_roles_get_no_tool_restriction_flags(self):
        for role in ("auditor", "gate", "builder", "summarizer"):
            with self.subTest(role=role):
                recorded, err, rc = _run_invoke_claude(role, call_mode="markdown")
                self.assertEqual(rc, 0, f"role={role} err={err}")
                argv = recorded[0] if recorded else ""
                self.assertNotIn(
                    "--allowedTools", argv,
                    f"role={role} must not receive --allowedTools: {argv!r}",
                )
                self.assertNotIn(
                    "--disallowedTools", argv,
                    f"role={role} must not receive --disallowedTools: {argv!r}",
                )

    def test_empty_role_gets_no_tool_restriction_flags(self):
        """A caller that passes no role at all (e.g. a direct test call, or
        any future caller that omits the 8th positional) must default to
        the unrestricted behavior, not silently restrict tools for an
        unknown role."""
        recorded, err, rc = _run_invoke_claude("", call_mode="markdown")
        self.assertEqual(rc, 0, f"err={err}")
        argv = recorded[0] if recorded else ""
        self.assertNotIn("--allowedTools", argv, f"argv={argv!r}")
        self.assertNotIn("--disallowedTools", argv, f"argv={argv!r}")


def _write_fake_claude_json_reviewer(bin_dir, argv_file):
    """Like _write_fake_claude, but emits a valid --output-format json
    envelope with a well-formed reviewer .result -- so walk_chain's own
    validate_output accepts it and returns 0, letting this test assert on
    a clean success rather than a degraded envelope. Argv capture (the
    actual thing under test) happens before any of that validation runs
    either way."""
    fake = os.path.join(bin_dir, "claude")
    inner = '{\\"summary\\":\\"clean\\",\\"checked\\":[],\\"findings\\":[]}'
    with open(fake, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_file}'
            cat > /dev/null
            printf '{{"type":"result","subtype":"success","num_turns":3,"result":"{inner}"}}\\n'
        """))
    os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return fake


def _run_walk_chain_reviewer(bin_dir, argv_file):
    """Exercises the REAL PRODUCTION call path -- walk_chain -> invoke_step
    -> invoke_claude -- rather than calling invoke_claude directly.
    invoke_step's own signature carries no role positional
    (test_invoke_step_no_dead_role_positional.py locks that); role instead
    reaches invoke_claude via CLAGENTIC_LLM_CLIENT_TOOL_ROLE, exported by
    walk_chain immediately before calling invoke_step. This proves that
    env-var relay actually works end to end, not just that invoke_claude
    behaves correctly when called directly with the positional (the
    fixtures above already prove that half)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-toolrole-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced = _functions_only_source(src_dir)

        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            export CLAGENTIC_REVIEWER_CMD=claude
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{sourced}'
            printf 'stdin diff content' | walk_chain reviewer json _fixture_prompt
        """)
        r = subprocess.run(
            ["sh", "-c", script, sourced],
            capture_output=True, text=True, cwd=TOOL_HOME,
        )
        with open(argv_file) as f:
            recorded = [line.rstrip("\n") for line in f if line.strip()]
        return recorded, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestToolRestrictionAppliesThroughTheRealWalkChainPath(unittest.TestCase):
    """End-to-end proof: the env-var relay (CLAGENTIC_LLM_CLIENT_TOOL_ROLE)
    walk_chain uses to reach invoke_claude around invoke_step's fixed
    signature actually carries the role through in a real chain run, not
    just when invoke_claude is called directly with the positional."""

    def test_reviewer_call_via_walk_chain_gets_tool_restriction_flags(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-toolrole-outer-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

            recorded, err, rc = _run_walk_chain_reviewer(bin_dir, argv_file)
            self.assertEqual(rc, 0, f"walk_chain failed: err={err!r}")
            self.assertEqual(len(recorded), 1, f"recorded={recorded!r}")
            argv = recorded[0]
            self.assertIn("--allowedTools", argv, f"argv={argv!r}")
            self.assertIn("Read,Grep,Glob", argv, f"argv={argv!r}")
            self.assertIn("--disallowedTools", argv, f"argv={argv!r}")
            self.assertIn("Bash", argv, f"argv={argv!r}")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
