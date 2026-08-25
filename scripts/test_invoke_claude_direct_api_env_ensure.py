"""
Regression coverage for lr-6276ea: CLAGENTIC_AUTH_MODE=enterprise/
anthropic-oauth previously fell through scripts/llm-client.sh's
CLAUDE_ROUTER_ENV_ENSURE `case` (:1603-onward) to the empty default -- a
silent no-op for both declared direct-API auth modes on the gate-path
`claude --print` spawn. Only bedrock-sso|bedrock-api-key had an arm
(lr-0ac353/lr-6d4a1f).

DEFECT THIS CLOSES: an operator who declares CLAGENTIC_AUTH_MODE=enterprise
(or anthropic-oauth) and also has a CLAGENTIC_ROUTER_URL settings.json
passthrough stamp (docs/ROUTER.md SS1 -- ANTHROPIC_BASE_URL/
ANTHROPIC_AUTH_TOKEN, or the Bedrock pair too if CLAGENTIC_ROUTER_BEDROCK_MODE
was also set) gets that env block inherited VERBATIM by this gate-path
`claude --print` subprocess, with nothing correcting it. The spawned process
sends the operator's real credential to the router endpoint the settings.json
env block names -- wrong endpoint for a direct-CLI call, 401s, and the chain
silently falls through to the next entry with no auth-specific error
surfaced.

THE FIX: a new `enterprise|anthropic-oauth` arm sets CLAUDE_ROUTER_ENV_ENSURE
to `env ANTHROPIC_BASE_URL= ANTHROPIC_AUTH_TOKEN= ANTHROPIC_BEDROCK_BASE_URL=
AWS_BEARER_TOKEN_BEDROCK= CLAUDE_CODE_USE_BEDROCK=`, blanking (not unsetting
-- the var name must still be present for tooling that probes presence,
matching the existing Bedrock arm's `env VAR=value` shape rather than
NON_CLAUDE_ENV_STRIP's `env -u VAR` shape) all five vars for this one spawn,
so the `claude` CLI falls back to its own native OAuth/Enterprise auth
resolution instead of whatever settings.json most recently stamped or
whatever Bedrock flag the operator's own ambient shell happened to carry.

FOLD-IN (PR #200 review round 2, PEACHES finding amos.path-choice.4):
CLAUDE_CODE_USE_BEDROCK was originally left ungoverned by this arm -- an
operator declaring enterprise/anthropic-oauth from a shell that ambiently
carried CLAUDE_CODE_USE_BEDROCK=1 got a gate-path child that STILL SPOKE
BEDROCK PROTOCOL, the exact ambient-session-dependence lr-0ac353 (PR #184)
existed to eliminate, now reappearing inverted inside its own successor.
Added as the fifth var in the same arm. A repo-wide sweep for every other
Claude-Code auth-mode-selecting env var (see scripts/llm-client.sh's arm
comment for the full enumeration) turned up exactly one further candidate,
ANTHROPIC_API_KEY, which is DELIBERATELY EXCLUDED -- it is the operator's
own legitimate direct-API credential, not an injection artifact, and
blanking it would break real --bare/API-key auth instead of fixing
anything. No Vertex-family var exists anywhere in this repo's
CLAGENTIC_AUTH_MODE surface, so there is nothing further to govern.

DESIGN CALL, stated here and in the PR body: anthropic-oauth is included in
the SAME arm as enterprise, not split into its own no-op arm. Both are
direct-API modes exposed to the identical settings.json-injection mechanism
-- nothing scopes the passthrough stamp to enterprise hosts only -- and
blanking an already-unset var is a no-op for any anthropic-oauth operator
with no router configured (see AC5 below, which proves this explicitly
rather than asserting it).

These tests reuse the REAL scripts/llm-client.sh (test_source_helpers.py's
guard-sentinel technique) with a stub `claude` on PATH that dumps its own
environ, exactly like test_invoke_claude_auth_mode_ensure.py's base class --
duplicated here rather than imported because that module's base class name
is private (leading underscore) and scoped to that file's own acceptance
numbering; the stub-writer helpers are small enough that reuse-via-import
would cost more coupling than the ~15 lines it saves (code-craft rule 2: this
is judged reuse, not a drive-by refactor of the existing file).

TEST-DISCIPLINE VERIFICATION (why each of these FAILS against the unfixed
implementation, i.e. the case block with only the bedrock-sso|bedrock-api-key
arm and no enterprise|anthropic-oauth arm):
  - AC1/AC2 (enterprise/anthropic-oauth blank the four vars): CODE PATH --
    with the unfixed case block, CLAGENTIC_AUTH_MODE=enterprise (or
    anthropic-oauth) matches no arm, so CLAUDE_ROUTER_ENV_ENSURE stays "" (the
    empty default at the top of the block) and invoke_claude's `$CLAUDE_ROUTER_ENV_ENSURE
    claude ...` expands to nothing -- no `env` prefix at all. The stub
    `claude` then inherits ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN/
    ANTHROPIC_BEDROCK_BASE_URL/AWS_BEARER_TOKEN_BEDROCK from the FIXTURE'S
    parent env UNCHANGED (still carrying the fixture's non-empty values) --
    the assertion that child_env[VAR] == "" fails because child_env[VAR]
    equals the fixture's non-empty value instead. This is not a doubly-passing
    test: the fixture sets each var to a distinguishing non-empty sentinel
    string specifically so an unfixed run reports that sentinel back, not an
    absence.
  - AC3 (unrecognized/typo value still no-op): CODE PATH -- both fixed and
    unfixed implementations reach the same `*)`-implicit fallthrough (no arm
    matches), so this case never distinguishes fixed from unfixed by
    construction. It is included as a boundary/non-regression check (mirrors
    AC9 in the sibling bedrock test file), not claimed as a fail-under-unfixed
    case -- see its class docstring, which states this explicitly rather than
    listing it under "verified to fail."
  - AC4 (UNDECLARED byte-identical, AC3 of lr-6276ea's own acceptance
    criteria): CODE PATH -- exercises the empty-default path, same as AC3
    above; included to prove the new arm does not widen what UNDECLARED
    matches, not as a fail-under-unfixed regression case.
  - AC5 (anthropic-oauth blanking is a no-op when the vars were already
    unset): CODE PATH -- with the unfixed implementation this test's
    assertion (all four vars absent from child_env) already PASSES, because
    an unset var stays unset either way; this is deliberately a
    doubly-passing case documenting the "blanking an absent var is a no-op"
    claim from the design-call comment, not a regression guard. Marked
    explicitly, not conflated with the fail-under-unfixed cases above.
  - AC6 (NON_CLAUDE_ENV_STRIP / invoke_generic unaffected): CODE PATH --
    invoke_generic never reads CLAUDE_ROUTER_ENV_ENSURE at all (it is
    invoke_claude-only, per the constant's own doc comment); this arm being
    added or not added cannot change invoke_generic's behavior. Included as a
    boundary check (mirrors AC6 in the sibling file), not a fail-under-unfixed
    case.
  - AC7 (bedrock arms unchanged): CODE PATH -- exercises the pre-existing
    bedrock-sso arm, untouched by this diff; included to prove the new arm's
    addition did not disturb the existing one (the "two predicates do not
    coexist" contract stays satisfied), not a fail-under-unfixed case.
  - AC8 (enterprise/anthropic-oauth blank CLAUDE_CODE_USE_BEDROCK too, the
    PEACHES fold-in): CODE PATH -- with the pre-fold-in arm (four router
    vars only, no CLAUDE_CODE_USE_BEDROCK= term), CLAGENTIC_AUTH_MODE=
    enterprise still matches the `enterprise|anthropic-oauth)` case, but
    CLAUDE_ROUTER_ENV_ENSURE's value carries no CLAUDE_CODE_USE_BEDROCK=
    term. The stub claude then inherits CLAUDE_CODE_USE_BEDROCK=1 from the
    fixture's parent env UNCHANGED. The assertion that child_env.get(
    "CLAUDE_CODE_USE_BEDROCK") == "" fails because it instead equals "1" --
    this was reproduced against this exact test harness (arm's
    CLAUDE_CODE_USE_BEDROCK= term temporarily removed, both vars set in the
    fixture, child confirmed to still carry CLAUDE_CODE_USE_BEDROCK=1)
    before the fifth term was restored and this test re-run green.

Run with:
  python3 -m unittest scripts.test_invoke_claude_direct_api_env_ensure -v
"""
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Distinguishing sentinel values -- non-empty, host-agnostic, obviously fake
# (AGENTS.md invariant 6: nothing host-specific hardcoded) -- so an unfixed
# run reports these values back verbatim instead of an accidental empty
# string that could be misread as the fix already working.
_FIXTURE_BASE_URL = "http://127.0.0.1:9999/router-passthrough-fixture"
_FIXTURE_AUTH_TOKEN = "fixture-anthropic-auth-token-not-real"
_FIXTURE_BEDROCK_BASE_URL = "http://127.0.0.1:9999/router-bedrock-fixture"
_FIXTURE_BEDROCK_BEARER = "fixture-bedrock-bearer-token-not-real"

_ROUTER_SCOPED_VARS = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "AWS_BEARER_TOKEN_BEDROCK",
)


def _write_environ_dump_stub_claude(bin_dir, out_path):
    """Stub `claude` that dumps its OWN environ to out_path -- same shape as
    test_invoke_claude_auth_mode_ensure.py's helper, duplicated per this
    file's docstring reuse-vs-coupling note."""
    path = os.path.join(bin_dir, "claude")
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            env > '{out_path}'
            printf '{{"type":"result","subtype":"success","num_turns":1,"duration_ms":1000,"is_error":false,"result":"{{}}"}}\\n'
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _read_environ_dump(out_path):
    names = {}
    with open(out_path) as f:
        for line in f:
            if "=" in line:
                name, _, value = line.rstrip("\n").partition("=")
                names[name] = value
    return names


class _DirectApiEnsureTestBase(unittest.TestCase):
    """Shared plumbing: sources the functions-only llm-client.sh with a stub
    `claude` on PATH, calls invoke_claude directly, and captures the stub's
    own environ for inspection."""

    def _run_invoke_claude_and_capture_child_env(self, extra_parent_env=None):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-direct-api-ensure-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_environ_dump_stub_claude(bin_dir, dump_path)

            prompt_file = os.path.join(tmpdir, "prompt.txt")
            input_file = os.path.join(tmpdir, "input.txt")
            output_file = os.path.join(tmpdir, "output.txt")
            err_file = os.path.join(tmpdir, "err.txt")
            with open(prompt_file, "w") as f:
                f.write("test prompt")
            with open(input_file, "w") as f:
                f.write("test diff")

            env = dict(os.environ)
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
            for var in _ROUTER_SCOPED_VARS:
                env.pop(var, None)
            env.pop("CLAGENTIC_AUTH_MODE", None)
            if extra_parent_env:
                env.update(extra_parent_env)
            env.update(source_env(llm_client=True))

            script = textwrap.dedent(f"""\
                export PROMPT_FILE='{prompt_file}'
                export INPUT_FILE='{input_file}'
                export OUTPUT_FILE='{output_file}'
                export ERR_FILE='{err_file}'
                . '{LLM_CLIENT_SH}'
                invoke_claude "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5 "markdown" "auditor"
            """)
            r = subprocess.run(
                ["sh", "-c", script, LLM_CLIENT_SH],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            self.assertTrue(
                os.path.exists(dump_path),
                f"stub claude never ran / never dumped its environ. "
                f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}",
            )
            return _read_environ_dump(dump_path), r
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _router_stamp_fixture(self):
        return {
            "ANTHROPIC_BASE_URL": _FIXTURE_BASE_URL,
            "ANTHROPIC_AUTH_TOKEN": _FIXTURE_AUTH_TOKEN,
            "ANTHROPIC_BEDROCK_BASE_URL": _FIXTURE_BEDROCK_BASE_URL,
            "AWS_BEARER_TOKEN_BEDROCK": _FIXTURE_BEDROCK_BEARER,
        }


class TestAcceptance1EnterpriseBlanksRouterVars(_DirectApiEnsureTestBase):
    """AC1: CLAGENTIC_AUTH_MODE=enterprise blanks all four router-scoped vars
    on the spawned claude child -- verified to FAIL against the unfixed
    implementation (see module docstring's TEST-DISCIPLINE section)."""

    def test_enterprise_blanks_all_four_router_scoped_vars(self):
        extra = {"CLAGENTIC_AUTH_MODE": "enterprise"}
        extra.update(self._router_stamp_fixture())
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env=extra,
        )
        for var in _ROUTER_SCOPED_VARS:
            self.assertIn(
                var, child_env,
                f"{var} must still be PRESENT (blanked, not unset) in the "
                f"spawned claude child's environ -- some tooling probes for "
                f"presence, not just value. child_env keys="
                f"{sorted(child_env)!r}",
            )
            self.assertEqual(
                child_env.get(var), "",
                f"CLAGENTIC_AUTH_MODE=enterprise must BLANK {var} on the "
                f"gate-path claude spawn so a settings.json router-passthrough "
                f"stamp cannot silently redirect this call's real credential. "
                f"Got {child_env.get(var)!r} (the fixture's un-blanked "
                f"sentinel value) -- this is exactly the pre-fix no-op this "
                f"task closes. stderr={r.stderr!r}",
            )


class TestAcceptance2AnthropicOauthBlanksRouterVars(_DirectApiEnsureTestBase):
    """AC2: CLAGENTIC_AUTH_MODE=anthropic-oauth blanks the same four vars --
    the lr-6276ea design call folding anthropic-oauth into the same arm as
    enterprise. Verified to FAIL against the unfixed implementation."""

    def test_anthropic_oauth_blanks_all_four_router_scoped_vars(self):
        extra = {"CLAGENTIC_AUTH_MODE": "anthropic-oauth"}
        extra.update(self._router_stamp_fixture())
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env=extra,
        )
        for var in _ROUTER_SCOPED_VARS:
            self.assertEqual(
                child_env.get(var), "",
                f"CLAGENTIC_AUTH_MODE=anthropic-oauth must BLANK {var} on "
                f"the gate-path claude spawn, same as enterprise (design "
                f"call: both are direct-API modes exposed to the identical "
                f"settings.json-injection mechanism). Got "
                f"{child_env.get(var)!r}. stderr={r.stderr!r}",
            )


class TestAcceptance3UnrecognizedValueStillNoOp(_DirectApiEnsureTestBase):
    """AC3: a typo'd/unrecognized CLAGENTIC_AUTH_MODE value never blanks or
    ensures anything -- boundary check, NOT a fail-under-unfixed case (both
    implementations reach the same implicit fallthrough; see module
    docstring)."""

    def test_unrecognized_value_leaves_router_vars_untouched(self):
        extra = {"CLAGENTIC_AUTH_MODE": "some-typo-value"}
        extra.update(self._router_stamp_fixture())
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env=extra,
        )
        self.assertEqual(child_env.get("ANTHROPIC_BASE_URL"), _FIXTURE_BASE_URL)
        self.assertEqual(child_env.get("ANTHROPIC_AUTH_TOKEN"), _FIXTURE_AUTH_TOKEN)
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", child_env)


class TestAcceptance4UndeclaredByteIdentical(_DirectApiEnsureTestBase):
    """AC4 (lr-6276ea's own non-negotiable, mirroring lr-0ac353's AC3): with
    CLAGENTIC_AUTH_MODE unset, the spawned command carries no env prefix at
    all -- byte-identical to today's, for every value including the new
    enterprise|anthropic-oauth arm's presence in the case block. Boundary
    check, NOT a fail-under-unfixed case."""

    def test_undeclared_leaves_router_vars_and_bedrock_var_untouched(self):
        extra = dict(self._router_stamp_fixture())
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env=extra,
        )
        self.assertEqual(child_env.get("ANTHROPIC_BASE_URL"), _FIXTURE_BASE_URL)
        self.assertEqual(child_env.get("ANTHROPIC_AUTH_TOKEN"), _FIXTURE_AUTH_TOKEN)
        self.assertEqual(child_env.get("ANTHROPIC_BEDROCK_BASE_URL"), _FIXTURE_BEDROCK_BASE_URL)
        self.assertEqual(child_env.get("AWS_BEARER_TOKEN_BEDROCK"), _FIXTURE_BEDROCK_BEARER)
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", child_env)


class TestAcceptance5BlankingAbsentVarIsNoOp(_DirectApiEnsureTestBase):
    """AC5: blanking an already-UNSET var is a no-op -- the design-call
    justification for folding anthropic-oauth into the same arm as
    enterprise, proven rather than merely asserted. Deliberately
    doubly-passing (see module docstring) -- documents the claim, is not a
    regression guard by itself."""

    def test_anthropic_oauth_with_no_router_configured_stays_unset(self):
        # No router-scoped vars in the fixture at all -- this operator never
        # configured CLAGENTIC_ROUTER_URL, so none of the four vars were ever
        # stamped into their environment in the first place.
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={"CLAGENTIC_AUTH_MODE": "anthropic-oauth"},
        )
        for var in _ROUTER_SCOPED_VARS:
            self.assertEqual(
                child_env.get(var, ""), "",
                f"blanking {var} when it was already absent must not "
                f"introduce any operator-visible behavior change -- "
                f"present-but-empty and absent are the same 'no usable "
                f"override' outcome for the claude CLI. child_env.get("
                f"{var!r})={child_env.get(var)!r}",
            )


class TestAcceptance6NonClaudeEnvStripUnaffected(unittest.TestCase):
    """AC6: invoke_generic (non-Claude CLIs) never reads
    CLAUDE_ROUTER_ENV_ENSURE at all -- the new arm cannot change its
    behavior. Boundary check, NOT a fail-under-unfixed case."""

    def test_invoke_generic_unaffected_by_enterprise_declaration(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-direct-api-generic-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            stub = os.path.join(bin_dir, "some-generic-cli")
            with open(stub, "w") as f:
                f.write(textwrap.dedent(f"""\
                    #!/bin/sh
                    cat > /dev/null 2>&1
                    env > '{dump_path}'
                    printf 'stub output\\n'
                    exit 0
                """))
            os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

            prompt_file = os.path.join(tmpdir, "prompt.txt")
            input_file = os.path.join(tmpdir, "input.txt")
            output_file = os.path.join(tmpdir, "output.txt")
            err_file = os.path.join(tmpdir, "err.txt")
            with open(prompt_file, "w") as f:
                f.write("test prompt")
            with open(input_file, "w") as f:
                f.write("test diff")

            script = textwrap.dedent(f"""\
                export PROMPT_FILE='{prompt_file}'
                export INPUT_FILE='{input_file}'
                export OUTPUT_FILE='{output_file}'
                export ERR_FILE='{err_file}'
                . '{LLM_CLIENT_SH}'
                invoke_generic "some-generic-cli" "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5
            """)
            env = dict(os.environ)
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
            env["CLAGENTIC_AUTH_MODE"] = "enterprise"
            env["ANTHROPIC_BASE_URL"] = _FIXTURE_BASE_URL
            env["ANTHROPIC_AUTH_TOKEN"] = _FIXTURE_AUTH_TOKEN
            env.update(source_env(llm_client=True))
            r = subprocess.run(
                ["sh", "-c", script, LLM_CLIENT_SH],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            self.assertTrue(os.path.exists(dump_path), f"stdout={r.stdout!r} stderr={r.stderr!r}")
            child_env = _read_environ_dump(dump_path)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

        # invoke_generic goes through NON_CLAUDE_ENV_STRIP, which UNSETS
        # (not blanks) these vars -- the enterprise arm's presence must not
        # change that pre-existing, unrelated behavior.
        for var in ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
            self.assertNotIn(
                var, child_env,
                f"invoke_generic must still strip {var} entirely (NON_CLAUDE_ENV_STRIP's "
                f"`env -u` form) regardless of the new enterprise|anthropic-oauth "
                f"arm -- the two constants must not interact. "
                f"child_env keys={sorted(child_env)!r}",
            )


class TestAcceptance8EnterpriseAndOauthBlankAmbientBedrockFlag(_DirectApiEnsureTestBase):
    """AC8 (PEACHES fold-in, PR #200 finding amos.path-choice.4): an ambient
    CLAUDE_CODE_USE_BEDROCK=1 in the operator's own shell must not survive
    into the gate-path claude spawn when CLAGENTIC_AUTH_MODE=enterprise or
    anthropic-oauth is declared -- verified to FAIL against the pre-fold-in
    implementation (see module docstring's TEST-DISCIPLINE section, AC8)."""

    def test_enterprise_blanks_ambient_claude_code_use_bedrock(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={
                "CLAGENTIC_AUTH_MODE": "enterprise",
                "CLAUDE_CODE_USE_BEDROCK": "1",
            },
        )
        self.assertIn(
            "CLAUDE_CODE_USE_BEDROCK", child_env,
            f"CLAUDE_CODE_USE_BEDROCK must still be PRESENT (blanked, not "
            f"unset) in the spawned claude child's environ, same shape as "
            f"the four router vars. child_env keys={sorted(child_env)!r}",
        )
        self.assertEqual(
            child_env.get("CLAUDE_CODE_USE_BEDROCK"), "",
            f"CLAGENTIC_AUTH_MODE=enterprise must BLANK an ambient "
            f"CLAUDE_CODE_USE_BEDROCK=1 on the gate-path claude spawn -- "
            f"otherwise the spawned child still speaks Bedrock protocol "
            f"despite a declared direct-API mode, the exact "
            f"ambient-session-dependence lr-0ac353 existed to eliminate, "
            f"now inverted. Got {child_env.get('CLAUDE_CODE_USE_BEDROCK')!r} "
            f"(the ambient value, un-blanked). stderr={r.stderr!r}",
        )

    def test_anthropic_oauth_blanks_ambient_claude_code_use_bedrock(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={
                "CLAGENTIC_AUTH_MODE": "anthropic-oauth",
                "CLAUDE_CODE_USE_BEDROCK": "1",
            },
        )
        self.assertEqual(
            child_env.get("CLAUDE_CODE_USE_BEDROCK"), "",
            f"CLAGENTIC_AUTH_MODE=anthropic-oauth must BLANK an ambient "
            f"CLAUDE_CODE_USE_BEDROCK=1 too, same arm as enterprise. Got "
            f"{child_env.get('CLAUDE_CODE_USE_BEDROCK')!r}. "
            f"stderr={r.stderr!r}",
        )


class TestAcceptance9AnthropicApiKeyDeliberatelyUngoverned(_DirectApiEnsureTestBase):
    """AC9 (the stated negative result from the sweep): ANTHROPIC_API_KEY is
    NOT blanked by the enterprise|anthropic-oauth arm -- it is the
    operator's own legitimate direct-API credential, not a router-injection
    artifact, and blanking it would break real --bare/API-key auth. This is
    a boundary check documenting the deliberate exclusion, NOT a
    fail-under-unfixed case -- both the pre-fold-in and current
    implementations leave this var untouched, by design."""

    def test_anthropic_api_key_survives_enterprise_arm_unblanked(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={
                "CLAGENTIC_AUTH_MODE": "enterprise",
                "ANTHROPIC_API_KEY": "fixture-real-operator-api-key-not-real",
            },
        )
        self.assertEqual(
            child_env.get("ANTHROPIC_API_KEY"),
            "fixture-real-operator-api-key-not-real",
            f"ANTHROPIC_API_KEY must survive the enterprise|anthropic-oauth "
            f"arm UNTOUCHED -- it is the operator's own legitimate "
            f"direct-API credential (see scripts/llm-client.sh's arm "
            f"comment and bin/clagentic-lite:585 for why), not a "
            f"router-injection artifact like the five governed vars. "
            f"child_env.get('ANTHROPIC_API_KEY')="
            f"{child_env.get('ANTHROPIC_API_KEY')!r}",
        )


class TestAcceptance7BedrockArmsUnchanged(_DirectApiEnsureTestBase):
    """AC7 (lr-6276ea's non-negotiable): the pre-existing bedrock-sso |
    bedrock-api-key arm is untouched by this diff -- boundary check, NOT a
    fail-under-unfixed case (this arm predates this task and was already
    covered by test_invoke_claude_auth_mode_ensure.py; re-asserted here as a
    same-file adjacency guard against the new arm disturbing it)."""

    def test_bedrock_sso_still_ensures_claude_code_use_bedrock(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={"CLAGENTIC_AUTH_MODE": "bedrock-sso"},
        )
        self.assertEqual(child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1")
        # The bedrock arm's own env-ensure form never touched the four
        # router-scoped vars -- confirms the two arms did not merge/overlap.
        self.assertNotIn("ANTHROPIC_BASE_URL", child_env)


if __name__ == "__main__":
    unittest.main()
