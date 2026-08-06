"""
Regression coverage for the class-4 foundry fix, INV-2/INV-5 tool
restriction: invoke_claude (scripts/llm-client.sh) must pass --allowedTools
Read,Grep,Glob --disallowedTools Bash on the `claude --print` invocation for
"reviewer" AND for any role it does not explicitly recognize as a legitimate
Bash user, and must NOT pass either flag for the enumerated opt-out roles.
invoke_codex must carry the equivalent restriction (--disable shell_tool -s
read-only) on its own version-gated flag-surface path (lr-37282a).

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
  - gate/builder/summarizer are the ENUMERATED OPT-OUT roles -- stripping
    Bash from the merge-gate or the builder would be exactly the over-broad
    simplification the foundry rejected.

AUDITOR MOVED OFF THE OPT-OUT LIST (lr-8a28e0 adjudication, CORRECTING the
original class-4 fix's assumption, not merely extending it): the ORIGINAL
"auditor reads security-tool output" rationale for exempting auditor
describes plugins/clagentic-lite/agents/auditor.md, the interactive Claude
Code subagent a human/session invokes directly to run
gitleaks/semgrep/osv-scanner itself via its own scoped Bash allowlist -- a
STRUCTURALLY DIFFERENT mechanism (Claude Code's native subagent tools:
frontmatter) from the one this predicate and these tests govern
(--allowedTools/--disallowedTools on `claude --print` / --disable
shell_tool on `codex exec`). The invocation this predicate ACTUALLY governs
is the non-interactive TOOL_ROLE=auditor chain-step call
(gates.sh cmd_adversarial -> llm-client.sh adversarial -> invoke_claude/
invoke_codex): read scripts/llm-client.sh's ds_adversarial_prompt and
scripts/gates.sh's cmd_adversarial directly -- the ONLY input this call
receives is a diff on stdin, and cmd_adversarial never shells out to
gitleaks/semgrep/osv-scanner itself (those run as separate, deterministic
gates driven by gates.sh's own shell code, per AGENTS.md §4: "Do not add
LLM calls to the blocking path of any security check"). This invocation has
no genuine Bash need, so it is restricted identically to the reviewer.

DEFAULT INVERTED (lr-49df97 fold-in, PR #143, HOLDEN-authorized correction):
originally scoped narrowly to CALL_ROLE=="reviewer" as the one OPT-IN role
(everything else unrestricted by default). BOBBIE's fold-in audit named
that an opt-in list is the wrong polarity for a control governing Bash
access to a process reading untrusted diffs -- a typo, a dropped export, or
a future caller that omits the role would silently hand Bash back to a
reviewer. The restricted set is now the default for anything NOT in the
enumerated opt-out list (gate/builder/summarizer), so an empty, misspelled,
or genuinely unknown role also gets restricted -- see
ds_llm_role_is_bash_unrestricted (platform.sh), the single source of truth
for the opt-out enumeration invoke_claude, invoke_codex, and this test
suite all key off.

These tests source the ACTUAL sh functions (invoke_claude, invoke_codex)
via `sh -c`, mirroring test_llm_client_sh.py's established fake-binary-on-
PATH technique (same helpers, reused directly rather than reimplemented) --
proving the real invocation emits the flags, not a Python mirror of the
logic.

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
    """Negative control, the other half of the foundry ruling: gate,
    builder, and summarizer must NEVER receive either tool-restriction
    flag -- stripping Bash from the builder (needs it to do its job) or
    the merge-gate would be exactly the over-broad simplification the
    foundry rejected.

    AUDITOR IS DELIBERATELY ABSENT FROM THIS LIST (lr-8a28e0 adjudication,
    replacing the prior accident, not merely narrowing an existing
    contract). See TestAuditorRoleGetsToolRestrictionFlags below for the
    corrected, adjudicated contract and its full reasoning -- the
    TOOL_ROLE=auditor chain-step invocation this predicate governs has no
    genuine Bash need (it only ever reads a diff on stdin;
    gitleaks/semgrep/osv-scanner run as separate deterministic gates, never
    through this LLM call), so it is now restricted identically to the
    reviewer. The interactive Claude Code subagent that genuinely DOES need
    Bash (plugins/clagentic-lite/agents/auditor.md) is a structurally
    different mechanism this predicate does not and cannot reach."""

    def test_other_roles_get_no_tool_restriction_flags(self):
        for role in ("gate", "builder", "summarizer"):
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
        remains the current, adjudicated contract: gate/builder/summarizer
        are a real, deliberate, foundry-ruled enumeration and still get no
        restriction (auditor moved off this list under lr-8a28e0, see the
        class docstring above).

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


class TestAuditorRoleGetsToolRestrictionFlags(unittest.TestCase):
    """POSITIVE control, lr-8a28e0 adjudication: the TOOL_ROLE=auditor
    chain-step invocation now gets the SAME --allowedTools Read,Grep,Glob
    --disallowedTools Bash treatment as the reviewer, on the claude carrier.

    WHY THIS IS CORRECT, NOT MERELY CONSISTENT: read
    scripts/llm-client.sh's ds_adversarial_prompt (the actual prompt this
    invocation sends) and scripts/gates.sh's cmd_adversarial (the actual
    caller) directly -- the auditor's chain-step invocation receives ONLY a
    diff on stdin and is asked for prose exploitability commentary; nothing
    in that prompt asks it to execute anything, and cmd_adversarial never
    shells out to gitleaks/semgrep/osv-scanner itself (those are separate,
    deterministic gates -- cmd_secrets/cmd_deps/cmd_sast -- invoked directly
    by gates.sh's own shell code, per AGENTS.md §4). This mirrors the
    reviewer's own "nothing in its prompt asks it to execute anything"
    justification exactly.

    THIS IS NOT THE SAME "AUDITOR" the original class-4 fix's opt-out
    rationale meant: plugins/clagentic-lite/agents/auditor.md, the
    interactive Claude Code subagent a human/session invokes directly, DOES
    read gitleaks/semgrep/osv-scanner output and genuinely needs Bash for
    it -- but that subagent is governed by Claude Code's own subagent
    tools: frontmatter, a structurally different mechanism this predicate
    and these tests do not reach. Restricting the chain-step invocation
    here does not touch that subagent's Bash access at all."""

    def test_auditor_role_gets_allowed_and_disallowed_tools_flags(self):
        recorded, err, rc = _run_invoke_claude("auditor", call_mode="markdown")
        self.assertEqual(rc, 0, f"invoke_claude exited non-zero: {err}")
        self.assertEqual(len(recorded), 1, f"expected exactly one claude invocation, got: {recorded}")
        argv = recorded[0]
        self.assertIn("--allowedTools", argv, f"auditor role must pass --allowedTools: {argv!r}")
        self.assertIn("Read,Grep,Glob", argv, f"auditor role must allow exactly Read,Grep,Glob: {argv!r}")
        self.assertIn("--disallowedTools", argv, f"auditor role must pass --disallowedTools: {argv!r}")
        self.assertIn("Bash", argv, f"auditor role must disallow Bash: {argv!r}")

    def test_auditor_role_gets_tool_flags_with_model_specified(self):
        """Same guard on the model-specified branch of invoke_claude
        (separate code path from the no-model branch above)."""
        recorded, err, rc = _run_invoke_claude("auditor", call_mode="markdown", model="sonnet")
        self.assertEqual(rc, 0, f"invoke_claude exited non-zero: {err}")
        self.assertEqual(len(recorded), 1, f"expected exactly one claude invocation, got: {recorded}")
        argv = recorded[0]
        self.assertIn("--allowedTools", argv, f"argv={argv!r}")
        self.assertIn("--disallowedTools", argv, f"argv={argv!r}")
        self.assertIn("Bash", argv, f"argv={argv!r}")

    def test_ds_llm_role_is_bash_unrestricted_returns_false_for_auditor(self):
        """Direct probe of the single-source-of-truth predicate itself
        (platform.sh), independent of invoke_claude's own consumption of
        it -- proves the enumeration change landed at the source, not only
        that invoke_claude happens to behave correctly today."""
        script = (
            f'. "{PLATFORM_SH}"\n'
            'ds_llm_role_is_bash_unrestricted auditor\n'
            'echo "RC=$?"\n'
        )
        r = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
        self.assertIn(
            "RC=1", r.stdout,
            f"ds_llm_role_is_bash_unrestricted must return 1 (restricted) "
            f"for auditor; stdout={r.stdout!r}",
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
    walk_chain's validate_output to accept a clean reviewer envelope.
    DOES NOT respond meaningfully to `--version` (falls through to the
    generic argv-logging branch, no parseable version on stdout), so
    codex_version_check resolves this fake to "unknown" -- i.e. this
    fixture deliberately exercises invoke_codex's MINIMAL, version-gated
    fallback path (lr-37282a: the path that does NOT apply the
    tool-restriction flags, by the same conservative posture that also
    skips -m/-o/--color on that path). Used to prove the
    unrestricted-Bash warning (lr-49df97 fold-in, BOBBIE finding 1; text
    UPDATED lr-37282a to name the version-gate reason) fires correctly
    for that remaining case. See _write_fake_versioned_codex_json_reviewer
    below for the fixture proving restriction WHEN the version check
    passes."""
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


def _write_fake_versioned_codex_json_reviewer(bin_dir, argv_file, version="0.142.5"):
    """Like _write_fake_codex_json_reviewer, but responds to `--version`
    with a real, parseable version string above CODEX_MIN_VERSION -- so
    codex_version_check resolves this fake to the FULL, tool-restriction-
    carrying flag set (lr-37282a). Used to prove the restriction actually
    lands in the real invocation's argv, not merely that the mechanism is
    theoretically wired up."""
    fake = os.path.join(bin_dir, "codex")
    with open(fake, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            case "$1" in
              --version)
                printf 'codex-cli {version}\\n'
                exit 0
                ;;
            esac
            printf '%s\\n' "$*" >> '{argv_file}'
            cat > /dev/null
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
    """lr-49df97 fold-in (BOBBIE finding 1), UPDATED lr-37282a, THEN
    UPDATED AGAIN under lr-8a28e0 (PEACHES fold-in, PR #144 review,
    comment 5207862165): codex now HAS a tool-restriction mechanism
    (--disable shell_tool -s read-only, invoke_codex) on its version-gated
    flag-surface path -- but that path only activates when
    codex_version_check resolves the installed CLI to >= CODEX_MIN_VERSION.
    A codex whose --version cannot be parsed (or is genuinely too old)
    still runs with Bash fully unrestricted via invoke_codex's minimal
    fallback form, by the same conservative posture that also skips
    -m/-o/--color on that path -- an unconfirmed flag surface must not be
    assumed to also carry the restriction flags correctly. This must never
    be silent -- walk_chain prints a loud stderr warning on every such
    attempt.

    THE WARNING GATE IS NOW DRIVEN BY ds_llm_role_is_bash_unrestricted
    (the SAME predicate that decides the restriction itself), not a
    hardcoded ROLE_L=="reviewer" check. PEACHES caught the class defect
    this correction closes: the original condition was hardcoded to
    "reviewer" only, so when lr-8a28e0 (this same PR) moved auditor onto
    the restricted side, the WARNING did not move with it -- an auditor
    chain step on an old/unversioned codex silently ran with unrestricted
    Bash, exactly the defect lr-8a28e0's restriction existed to prevent.
    See test_auditor_via_unversioned_codex_prints_unrestricted_bash_warning
    below for the corrected coverage, and
    test_invariants.py's TestEveryBashRestrictedRoleWarningIsCoveredByTheSharedPredicate
    for the class-level sweep that would have caught this."""

    def test_reviewer_via_unversioned_codex_prints_unrestricted_bash_warning(self):
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

    def test_auditor_via_unversioned_codex_prints_unrestricted_bash_warning(self):
        """CORRECTED, PEACHES-caught fold-in (PR #144 review, comment
        5207862165): this test used to assert the warning was scoped to
        ROLE_L=="reviewer" ONLY and must NOT fire for auditor. That
        assertion was WRONG the moment lr-8a28e0 moved auditor onto the
        restricted side (this same PR) without updating this hardcoded
        gate to match -- a genuinely silent gap on auditor-via-old-codex:
        invoke_codex correctly skips the restriction flags on its
        unverified-flag-surface fallback path, but nothing said so,
        because the warning only ever checked for "reviewer". PR-D's
        whole defense of the residual reviewer-on-codex gap was "INERT
        means SILENT, and this is loud" -- that defense did not hold for
        auditor until this fix. The warning is now driven by
        ds_llm_role_is_bash_unrestricted (the SAME predicate that decides
        the restriction itself, not a second hardcoded role name), so
        auditor is covered automatically, as is any future role moved
        onto the restricted side."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-auditor-codex-warn-")
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
            self.assertIn(
                "UNRESTRICTED", r.stderr,
                f"expected a loud unrestricted-Bash warning on stderr when "
                f"an auditor chain step resolves to an unversioned/old "
                f"codex; stderr={r.stderr!r}",
            )
            self.assertIn(
                "auditor", r.stderr,
                f"warning should name the role in use; stderr={r.stderr!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_auditor_via_versioned_codex_does_not_print_the_warning(self):
        """Negative control, the corrected contract's other half: an
        auditor chain step resolving to a CURRENT codex (>= CODEX_MIN_
        VERSION) IS genuinely restricted (TestAuditorViaCodexGetsToolRestrictionFlags
        proves the flags land) -- the warning must not misfire there,
        the same "no false alarm on the CLI/version combination where
        the control genuinely works" property
        TestReviewerViaVersionedCodexGetsToolRestrictionFlags already
        proves for the reviewer role."""
        recorded, err, rc = _run_walk_chain_with_codex_fixture(
            "auditor", "CLAGENTIC_AUDITOR_CMD",
            _write_fake_versioned_codex_json_reviewer,
        )
        self.assertEqual(rc, 0, f"walk_chain failed: err={err!r}")
        self.assertNotIn(
            "UNRESTRICTED", err,
            f"auditor-via-current-codex must not emit the unrestricted-"
            f"Bash warning -- it IS restricted on this version; err={err!r}",
        )


def _run_walk_chain_with_codex_fixture(role_lower, cli_cmd_env_var, fixture_writer, mode="json", argv_file_name="argv.log"):
    """Shared harness: writes FIXTURE_WRITER's fake codex on PATH, runs
    walk_chain for ROLE_LOWER with CLI_CMD_ENV_VAR pointed at codex, and
    returns (recorded_argv_lines, stderr, rc). Generalizes
    _run_walk_chain_reviewer (claude-only) to the codex carrier so the
    same shape of end-to-end proof (env-var relay actually works, not just
    invoke_codex's own direct-call behavior) covers both CLIs. MODE must
    match the role's real validate_output schema (json for reviewer/
    auditor/gate roles whose fixture output satisfies .findings; markdown
    for roles with no closed schema) -- a mismatch makes walk_chain report
    a degraded envelope (exit 3/4) for reasons unrelated to the
    tool-restriction flags this harness exists to observe."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-codex-toolrole-")
    try:
        argv_file = os.path.join(tmpdir, argv_file_name)
        open(argv_file, "w").close()
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        fixture_writer(bin_dir, argv_file)

        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced = _functions_only_source(src_dir)

        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            export {cli_cmd_env_var}=codex
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{sourced}'
            printf 'stdin diff content' | walk_chain {role_lower} {mode} _fixture_prompt
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


class TestReviewerViaVersionedCodexGetsToolRestrictionFlags(unittest.TestCase):
    """POSITIVE control, lr-37282a: when the resolved codex CLI reports a
    version >= CODEX_MIN_VERSION, invoke_codex's real argv carries
    --disable shell_tool -s read-only, and walk_chain's unrestricted-Bash
    warning does NOT fire (it would be a false alarm on the CLI/version
    combination where the control genuinely works now, mirroring
    test_reviewer_via_claude_does_not_print_the_warning's own negative
    control for the claude path)."""

    def test_reviewer_via_codex_gets_disable_shell_tool_and_sandbox_flags(self):
        recorded, err, rc = _run_walk_chain_with_codex_fixture(
            "reviewer", "CLAGENTIC_REVIEWER_CMD",
            _write_fake_versioned_codex_json_reviewer,
        )
        self.assertEqual(rc, 0, f"walk_chain failed: err={err!r}")
        self.assertEqual(len(recorded), 1, f"recorded={recorded!r}")
        argv = recorded[0]
        self.assertIn("--disable", argv, f"argv={argv!r}")
        self.assertIn("shell_tool", argv, f"argv={argv!r}")
        self.assertIn("-s", argv, f"argv={argv!r}")
        self.assertIn("read-only", argv, f"argv={argv!r}")

    def test_reviewer_via_versioned_codex_does_not_print_the_warning(self):
        recorded, err, rc = _run_walk_chain_with_codex_fixture(
            "reviewer", "CLAGENTIC_REVIEWER_CMD",
            _write_fake_versioned_codex_json_reviewer,
        )
        self.assertEqual(rc, 0, f"walk_chain failed: err={err!r}")
        self.assertNotIn(
            "UNRESTRICTED", err,
            f"reviewer-via-current-codex must not emit the unrestricted-"
            f"Bash warning -- it IS restricted on this version; err={err!r}",
        )


class TestAuditorViaCodexGetsToolRestrictionFlags(unittest.TestCase):
    """POSITIVE control, lr-8a28e0 (codex side): the TOOL_ROLE=auditor
    chain-step invocation is restricted on the codex carrier exactly like
    it is on the claude carrier (TestAuditorRoleGetsToolRestrictionFlags,
    above) -- ds_llm_role_is_bash_unrestricted (platform.sh) is the SAME
    single source of truth both invoke_claude and invoke_codex consult, so
    this is not a second, independently-derived decision that could drift
    from the claude-side one."""

    def test_auditor_via_codex_gets_disable_shell_tool_and_sandbox_flags(self):
        recorded, err, rc = _run_walk_chain_with_codex_fixture(
            "auditor", "CLAGENTIC_AUDITOR_CMD",
            _write_fake_versioned_codex_json_reviewer,
        )
        self.assertEqual(rc, 0, f"walk_chain failed: err={err!r}")
        self.assertEqual(len(recorded), 1, f"recorded={recorded!r}")
        argv = recorded[0]
        self.assertIn("--disable", argv, f"argv={argv!r}")
        self.assertIn("shell_tool", argv, f"argv={argv!r}")
        self.assertIn("-s", argv, f"argv={argv!r}")
        self.assertIn("read-only", argv, f"argv={argv!r}")


class TestGateBuilderSummarizerViaCodexAreUntouched(unittest.TestCase):
    """Negative control, codex side: gate/builder/summarizer must NOT
    receive the codex tool-restriction flags either -- mirrors
    TestNonReviewerRolesAreUntouched's claude-side coverage, proving the
    two carriers agree on the SAME opt-out set via the SAME predicate
    rather than each hand-rolling its own enumeration."""

    def test_other_roles_via_codex_get_no_tool_restriction_flags(self):
        for role, env_var in (
            ("gate", "CLAGENTIC_GATE_CMD"),
            ("builder", "CLAGENTIC_BUILDER_CMD"),
            ("summarizer", "CLAGENTIC_SUMMARIZER_CMD"),
        ):
            with self.subTest(role=role):
                recorded, err, rc = _run_walk_chain_with_codex_fixture(
                    role, env_var, _write_fake_versioned_codex_json_reviewer,
                    mode="markdown",
                )
                self.assertEqual(rc, 0, f"role={role} walk_chain failed: err={err!r}")
                argv = recorded[0] if recorded else ""
                self.assertNotIn(
                    "--disable", argv,
                    f"role={role} must not receive --disable shell_tool: {argv!r}",
                )
                self.assertNotIn(
                    "shell_tool", argv,
                    f"role={role} argv={argv!r}",
                )


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
        """Negative control: a real, enumerated Bash-unrestricted opt-out
        role (gate) must not trip walk_chain's own sanity-check warning --
        it is a known, deliberate role, not an unrecognized one.

        Uses "gate", not "auditor" (the fixture this test used before
        lr-8a28e0): auditor moved OFF ds_llm_role_is_bash_unrestricted's
        opt-out enumeration under that adjudication -- it is now a
        deliberately-RESTRICTED role instead, exempted from THIS warning
        via the explicit reviewer|auditor case arm above (see
        TestAuditorRoleGetsToolRestrictionFlags for its own, separate
        positive-control coverage), not via the opt-out predicate this
        test is meant to probe. "gate" is a genuine, still-current member
        of the opt-out enumeration and keeps this test's original
        property intact."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-rolecheck-known-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

            recorded, err, rc = _run_walk_chain_with_role("gate", bin_dir, argv_file)
            self.assertNotIn(
                "RESTRICTED", err,
                f"a known opt-out role must not trigger the role-sanity "
                f"warning; stderr={err!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_auditor_role_does_not_trigger_the_warning(self):
        """Sibling negative control, lr-8a28e0: "auditor" is the SECOND
        role (alongside "reviewer") this codebase deliberately routes
        through the restricted default on purpose -- it must not trigger
        walk_chain's own role-sanity warning either, even though it is no
        longer in ds_llm_role_is_bash_unrestricted's opt-out enumeration."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-rolecheck-auditor-")
        try:
            argv_file = os.path.join(tmpdir, "argv.log")
            open(argv_file, "w").close()
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_fake_claude_json_reviewer(bin_dir, argv_file)

            recorded, err, rc = _run_walk_chain_with_role("auditor", bin_dir, argv_file)
            self.assertNotIn(
                "RESTRICTED", err,
                f"auditor is a deliberately-restricted role and must not "
                f"trigger the unrecognized-role warning; stderr={err!r}",
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
