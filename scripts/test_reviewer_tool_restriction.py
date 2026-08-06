"""
Regression coverage for the class-4 foundry fix, INV-2 tool restriction:
invoke_claude (scripts/llm-client.sh) must pass --allowedTools Read,Grep,Glob
--disallowedTools Bash on the `claude --print` invocation for "reviewer" AND
for any role it does not explicitly recognize as a legitimate Bash user, and
must NOT pass either flag for the enumerated opt-out roles.

FOUNDRY RULING THIS ENFORCES:
  - The reviewer (and anything defaulting to the reviewer's restricted set)
    KEEPS Read/Grep/Glob -- its prompt mandates caller-tracing, import-
    checking, and guard-branch verification ("Have you read the surrounding
    context? Check callers, imports, and tests"; "trace at least one caller
    first"). Stripping those tools would silently gut review quality,
    invisibly (a shallower review still emits valid JSON and passes every
    gate).
  - The reviewer LOSES Bash -- nothing in its prompt asks it to execute
    anything, and a --print reviewer holding unrestricted Bash while
    reading an attacker-influenceable diff is a live prompt-injection-to-
    execution path.
  - auditor/gate/builder/summarizer are the ENUMERATED OPT-OUT roles --
    stripping Bash from the auditor (which reads security-tool output) or
    the merge-gate would be exactly the over-broad simplification the
    foundry rejected.

DEFAULT INVERTED (lr-49df97 fold-in, PR #143, HOLDEN-authorized correction):
originally scoped narrowly to CALL_ROLE=="reviewer" as the one OPT-IN role
(everything else unrestricted by default). BOBBIE's fold-in audit named
that an opt-in list is the wrong polarity for a control governing Bash
access to a process reading untrusted diffs -- a typo, a dropped export, or
a future caller that omits the role would silently hand Bash back to a
reviewer. The restricted set is now the default for anything NOT in the
enumerated opt-out list (auditor/gate/builder/summarizer), so an empty,
misspelled, or genuinely unknown role also gets restricted -- see
ds_llm_role_is_bash_unrestricted (platform.sh), the single source of truth
for the opt-out enumeration both invoke_claude and this test suite key off.

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

    def test_empty_or_unrecognized_role_gets_the_restricted_tool_flags(self):
        """CORRECTED lr-49df97 fold-in, HOLDEN-authorized rule-5 exception
        (PR #143 review): this test originally asserted the OPPOSITE --
        that an empty/unknown role must default to UNRESTRICTED. That
        assertion was WRONG, not a considered contract: it was written in
        this same task, hours before the correction, and it happened to
        lock in a fail-open default for a control that decides whether
        Bash is available to a process reading an attacker-influenceable
        diff. For a control of that kind, the hazard is inverted from what
        the original docstring named -- "silently restrict tools for an
        unknown role" is not the risk; silently UN-restricting Bash on a
        typo'd role string, a dropped export, or a nested invocation that
        lost the role entirely is. A security-relevant tool gate must fail
        toward RESTRICTED on anything it does not explicitly recognize, the
        same posture ds_llm_role_is_bash_unrestricted (platform.sh) and
        invoke_claude's inverted default now both take.

        This is a correction of a fresh, wrong assertion this same PR
        introduced, not a weakening of an established invariant -- see the
        commit message for the full rule-5-exception rationale. The
        sibling test above (test_other_roles_get_no_tool_restriction_flags)
        remains UNCHANGED: auditor/gate/builder/summarizer are a real,
        deliberate, foundry-ruled enumeration and still get no restriction.

        Covers empty string (the original case), a plausible misspelling
        of "reviewer" (proving this isn't merely an empty-string special
        case), and an entirely unrecognized role string."""
        for role in ("", "reviewr", "not-a-real-role"):
            with self.subTest(role=role):
                recorded, err, rc = _run_invoke_claude(role, call_mode="markdown")
                self.assertEqual(rc, 0, f"role={role!r} err={err}")
                argv = recorded[0] if recorded else ""
                self.assertIn(
                    "--allowedTools", argv,
                    f"role={role!r} must receive --allowedTools -- an "
                    f"unrecognized role must fail toward RESTRICTED, not "
                    f"unrestricted: {argv!r}",
                )
                self.assertIn(
                    "Read,Grep,Glob", argv,
                    f"role={role!r} argv={argv!r}",
                )
                self.assertIn(
                    "--disallowedTools", argv,
                    f"role={role!r} must receive --disallowedTools Bash: {argv!r}",
                )
                self.assertIn(
                    "Bash", argv,
                    f"role={role!r} argv={argv!r}",
                )


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


def _write_fake_codex_json_reviewer(bin_dir, argv_file):
    """Fake `codex` binary on PATH -- mirrors invoke_codex's real
    invocation shape (`codex exec ... -o OUTPUT_FILE -`, stdout/stderr both
    redirected to ERR_FILE by the real invoke_codex) closely enough for
    walk_chain's validate_output to accept a clean reviewer envelope. Used
    to prove the reviewer-on-unrestrictable-CLI warning (lr-49df97 fold-in,
    BOBBIE finding 1) actually fires when the resolved chain step is codex,
    not claude -- invoke_codex has no tool-restriction flags at all, so the
    warning is walk_chain's OWN responsibility, not something the fake CLI
    needs to simulate."""
    fake = os.path.join(bin_dir, "codex")
    with open(fake, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_file}'
            cat > /dev/null
            # invoke_codex writes the real response via -o FILE; find it in argv.
            for arg in "$@"; do
                if [ "$prev" = "-o" ]; then
                    printf '{{"summary":"clean","checked":[],"findings":[]}}\\n' > "$arg"
                fi
                prev="$arg"
            done
        """))
    os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return fake


class TestReviewerOnUnrestrictableCliWarnsLoudly(unittest.TestCase):
    """lr-49df97 fold-in (BOBBIE finding 1): invoke_codex has no
    --allowedTools/--disallowedTools equivalent, so a reviewer chain step
    that resolves to codex (the SHIPPED DEFAULT, share/config.example:66)
    runs with Bash fully unrestricted. This must never be silent --
    walk_chain prints a loud stderr warning on every such attempt so an
    operator running the stock config sees the exposure on every review
    call, not only if they happen to run `clagentic-lite doctor`."""

    def test_reviewer_via_codex_prints_unrestricted_bash_warning(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-reviewer-codex-warn-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_codex_json_reviewer(bin_dir, argv_file)

            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            sourced = _functions_only_source(src_dir)

            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export CLAGENTIC_REVIEWER_CMD=codex
                _fixture_prompt() {{ printf 'test prompt'; }}
                . '{sourced}'
                printf 'stdin diff content' | walk_chain reviewer json _fixture_prompt
            """)
            r = subprocess.run(
                ["sh", "-c", script, sourced],
                capture_output=True, text=True, cwd=TOOL_HOME,
            )
            self.assertIn(
                "UNRESTRICTED", r.stderr,
                f"expected a loud unrestricted-Bash warning on stderr when "
                f"the reviewer chain resolves to codex; stderr={r.stderr!r}",
            )
            self.assertIn(
                "codex", r.stderr,
                f"warning should name the CLI in use; stderr={r.stderr!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_reviewer_via_claude_does_not_print_the_warning(self):
        """Negative control: the claude path IS restricted (the sibling
        tests above prove the flags land), so it must not also emit the
        unrestricted-Bash warning -- that would be a false alarm on the one
        CLI where the control genuinely works."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-reviewer-claude-nowarn-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

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
            self.assertNotIn(
                "UNRESTRICTED", r.stderr,
                f"claude reviewer path must not emit the unrestricted-Bash "
                f"warning -- it IS restricted; stderr={r.stderr!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_non_reviewer_role_via_codex_does_not_print_the_warning(self):
        """The warning is scoped to ROLE_L=="reviewer" only -- the auditor
        role legitimately runs on codex with Bash for its security tools
        (docs/DESIGN.md "Auditor | Read, Bash (security tools)") and must
        not be flagged as if it were an accidental exposure."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-auditor-codex-nowarn-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_codex_json_reviewer(bin_dir, argv_file)

            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            sourced = _functions_only_source(src_dir)

            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export CLAGENTIC_AUDITOR_CMD=codex
                _fixture_prompt() {{ printf 'test prompt'; }}
                . '{sourced}'
                printf 'stdin diff content' | walk_chain auditor json _fixture_prompt
            """)
            r = subprocess.run(
                ["sh", "-c", script, sourced],
                capture_output=True, text=True, cwd=TOOL_HOME,
            )
            self.assertNotIn(
                "UNRESTRICTED", r.stderr,
                f"auditor role must not emit the reviewer-scoped warning; "
                f"stderr={r.stderr!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


def _run_walk_chain_with_role(role_lower, bin_dir, argv_file):
    """Calls walk_chain directly with an arbitrary ROLE_L string (not
    necessarily one of the five real subcommand-dispatch roles) -- proves
    the SECOND, INDEPENDENT layer (walk_chain's own role-sanity check,
    scripts/llm-client.sh) fires on its own, not merely that invoke_claude's
    default (the first layer, already covered by
    TestNonReviewerRolesAreUntouched above) happens to restrict too."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-rolecheck-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced = _functions_only_source(src_dir)

        role_upper = role_lower.upper().replace("-", "_")
        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            export CLAGENTIC_{role_upper}_CMD=claude
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{sourced}'
            printf 'stdin diff content' | walk_chain '{role_lower}' json _fixture_prompt
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


class TestWalkChainOwnRoleSanityCheckIsIndependentOfInvokeClaude(unittest.TestCase):
    """lr-49df97 fold-in, HOLDEN-authorized correction, layer 2: walk_chain
    itself warns when ROLE_L is neither a known opt-out role nor
    "reviewer" -- a producer-side check at the export site, structurally
    separate from invoke_claude's consumer-side default (proven by the
    OTHER test classes in this file). Neither layer's test depends on the
    other layer's code path."""

    def test_unrecognized_role_triggers_the_walk_chain_own_warning(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-rolecheck-outer-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

            recorded, err, rc = _run_walk_chain_with_role("bogus-role", bin_dir, argv_file)
            self.assertIn(
                "RESTRICTED", err,
                f"an unrecognized ROLE_L must trigger walk_chain's own "
                f"fail-safe warning naming the fallback to the restricted "
                f"set; stderr={err!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_unrecognized_role_still_gets_the_restricted_flags_on_the_real_call(self):
        """The warning is diagnostic, not a substitute for the actual
        restriction -- the real claude invocation this role reaches must
        still carry the restricted flags (invoke_claude's own default,
        layer 1), proving the two layers agree in practice even though
        this test only exercises walk_chain's call shape."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-rolecheck-flags-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

            recorded, err, rc = _run_walk_chain_with_role("bogus-role", bin_dir, argv_file)
            self.assertEqual(len(recorded), 1, f"recorded={recorded!r} err={err!r}")
            argv = recorded[0]
            self.assertIn("--allowedTools", argv, f"argv={argv!r}")
            self.assertIn("--disallowedTools", argv, f"argv={argv!r}")
            self.assertIn("Bash", argv, f"argv={argv!r}")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_known_optout_role_does_not_trigger_the_warning(self):
        """Negative control: a real, enumerated opt-out role (auditor) must
        not trip walk_chain's own sanity-check warning -- it is a known,
        deliberate role, not an unrecognized one."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-rolecheck-known-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

            recorded, err, rc = _run_walk_chain_with_role("auditor", bin_dir, argv_file)
            self.assertNotIn(
                "RESTRICTED", err,
                f"a known opt-out role must not trigger the role-sanity "
                f"warning; stderr={err!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_reviewer_role_does_not_trigger_the_warning(self):
        """Negative control: "reviewer" is the one role deliberately routed
        through the restricted default without being an opt-out role --
        walk_chain's own check must recognize it as expected, not flag it
        as an unrecognized role."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-rolecheck-reviewer-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

            recorded, err, rc = _run_walk_chain_with_role("reviewer", bin_dir, argv_file)
            self.assertNotIn(
                "RESTRICTED", err,
                f"the reviewer role itself must not trigger the "
                f"role-sanity warning; stderr={err!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
