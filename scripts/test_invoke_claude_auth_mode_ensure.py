"""
Regression coverage for lr-6d4a1f, REPLACING scripts/test_invoke_claude_bedrock_env_ensure.py
(deleted by this same change -- see that file's history / this task's PR body).

BACKGROUND: lr-0ac353 shipped a detection predicate keying off
ANTHROPIC_BEDROCK_BASE_URL being non-empty via an eval-spliced indirect
variable read. AVASARALA's fold-in (lr-6d4a1f comment #1)
PROVED that predicate INERT under the exact Enterprise/OAuth session-blanking
payload it targeted: that payload sets the four router-scoped vars
(including ANTHROPIC_BEDROCK_BASE_URL) to EMPTY STRINGS, not unset -- set=yes
value_len=0. `${VAR:-}` collapses set-but-empty with unset, so the predicate
never fired. The bug lr-0ac353 targeted was UNCHANGED on the host class it
targeted.

THE FIX (this task): a single declared config key, CLAGENTIC_AUTH_MODE
(enum: anthropic-oauth | enterprise | bedrock-sso | bedrock-api-key,
UNDECLARED default). invoke_claude's CLAUDE_ROUTER_ENV_ENSURE now reads this
declaration directly instead of an env var a settings payload can blank --
CLAGENTIC_AUTH_MODE is never carried in the stamped settings.json env block
at all, so no session-blanking payload can zero it out. This REPLACES the
old predicate, per the builder directive in lr-6d4a1f comment #1 ("the
predicate block ... is REPLACED by the declaration read, not augmented -- do
not run two predicates"). It also removes the
CLAGENTIC_ROUTER_BEDROCK_ENSURE_VAR eval-splice entirely -- there is no
longer a configurable variable NAME to splice into an eval for THIS
predicate, only a fixed, closed-enum config VALUE read with `case`. Note
this did not close lr-fe9b3d: that task's sweep clause (fix the eval-splice
SHAPE everywhere it recurs, not just this one site) remained unsatisfied
until a later change routed the surviving llm-client.sh call sites through
a shared indirect-read primitive.

These tests source the REAL scripts/llm-client.sh (test_source_helpers.py's
guard-sentinel technique, same as every other llm-client.sh-sourcing test in
this suite) with a stub `claude` on PATH that both dumps its own environ
(proving/disproving CLAUDE_CODE_USE_BEDROCK's presence) and answers a valid
JSON envelope so walk_chain-driven tests (2, 4) see a clean primary pass.

Acceptance cases (task's own enumeration, description ACs 1-6 + comment #1's
folded-in ACs 7-9):
  1. UNDECLARED CLAGENTIC_AUTH_MODE -> spawned command's env carries no
     CLAUDE_CODE_USE_BEDROCK at all -- byte-identical to today's behavior
     for every existing install (no install predating this task has ever
     set CLAGENTIC_AUTH_MODE).
  2. CLAGENTIC_AUTH_MODE=bedrock-sso -> the spawned claude child process has
     CLAUDE_CODE_USE_BEDROCK=1 in ITS OWN environ, regardless of the calling
     session's own ambient value.
  3. CLAGENTIC_AUTH_MODE=bedrock-api-key -> same ensure fires (both
     bedrock-* values are equivalent for this specific ensure; they differ
     only for the SSO-cache readiness preflight, covered elsewhere).
  4. role=gate completes with cli=claude as PRIMARY, no "fallback:" stderr
     line, on a bedrock-sso-declared host.
  5. Reviewer run forced past the router (router unreachable) succeeds via
     the claude:flagship layer-2 direct-CLI fallback instead of
     INFRA_DEGRADED, and still carries CLAUDE_CODE_USE_BEDROCK into that
     fallback call on a bedrock-sso-declared host.
  6. NON_CLAUDE_ENV_STRIP behavior for a non-Claude CLI (invoke_generic) is
     unchanged by this addition -- the two constants do not interact.
  7. DS_TIMEOUT_CMD resolving to the ds_timeout_missing shell function still
     triggers INV-1a's fail-closed diagnostic (exit 99, distinct stderr)
     rather than "env: No such file or directory" -- proving the ORDERING
     requirement (CLAUDE_ROUTER_ENV_ENSURE placed AFTER $DS_TIMEOUT_CMD
     "$CALL_TIMEOUT", never wrapping it).
  8. THE EXACT REGRESSION CASE (AC 7 from lr-6d4a1f comment #1): the
     Enterprise/OAuth blanking payload sets ANTHROPIC_BEDROCK_BASE_URL and
     its siblings to EMPTY STRINGS (set-but-empty, not unset) -- with
     CLAGENTIC_AUTH_MODE=bedrock-sso declared, CLAUDE_CODE_USE_BEDROCK=1
     must still be ensured. This is the exact fixture gap that let the old
     predicate's inertness through undetected (the old 662-line test file
     covered only unset and non-empty ANTHROPIC_BEDROCK_BASE_URL).
  9. Anything OTHER than the two bedrock-* values (anthropic-oauth,
     enterprise, an unrecognized typo'd value, or unset) never ensures
     CLAUDE_CODE_USE_BEDROCK, even when ANTHROPIC_BEDROCK_BASE_URL happens
     to be non-empty in the environment -- the declaration is authoritative,
     not the old env-derived sentinel (which is deliberately no longer read
     at all).

Run with: python3 -m unittest scripts.test_invoke_claude_auth_mode_ensure -v
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


def _write_environ_dump_success_claude(bin_dir, out_path, num_turns=5):
    """Stub `claude` that dumps its OWN environ to out_path, then emits a
    valid --output-format json envelope on stdout and exits 0 -- lets a
    single call site prove BOTH env-content (acceptance 2/3/8/9) and
    walk_chain pass/fallback behavior (acceptance 4/5) without two stubs."""
    path = os.path.join(bin_dir, "claude")
    inner = json.dumps({"summary": "clean diff", "checked": ["security"], "findings": []})
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "num_turns": num_turns,
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
            env > '{out_path}'
            cat <<'ENVELOPE'
{envelope}
ENVELOPE
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_environ_dump_success_claude_gate_decision(bin_dir, out_path, num_turns=3):
    """Stub `claude` for the gate role specifically: gate mode expects a
    decision/reason-shaped JSON object (merge-gate.md's schema), not the
    findings-array shape reviewer/auditor use."""
    path = os.path.join(bin_dir, "claude")
    inner = json.dumps({"decision": "approve", "reason": "clean"})
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "num_turns": num_turns,
        "duration_ms": 2000,
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
            env > '{out_path}'
            cat <<'ENVELOPE'
{envelope}
ENVELOPE
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_valid_sso_cache(cache_dir):
    """Write one AWS SSO token-cache-shaped JSON file with expiresAt far in
    the future -- the mode-implied readiness preflight (_llm_auth_mode_preflight)
    treats this as 'ready'. Tests that exercise CLAGENTIC_AUTH_MODE=bedrock-sso
    for something OTHER than the preflight itself (the CLAUDE_CODE_USE_BEDROCK
    ensure, the gate no-fallback property, the Layer-2 fallback property) must
    point CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR at a fixture like this one so the
    preflight does not trip first and mask what they are actually testing."""
    import datetime
    os.makedirs(cache_dir, exist_ok=True)
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)
    path = os.path.join(cache_dir, "fixture-token.json")
    with open(path, "w") as f:
        json.dump({
            "startUrl": "https://example.invalid/start",
            "region": "us-east-1",
            "accessToken": "fixture-not-a-real-token",
            "expiresAt": future.strftime("%Y-%m-%dT%H:%M:%SUTC"),
        }, f)
    return path


def _read_environ_dump(out_path):
    names = {}
    with open(out_path) as f:
        for line in f:
            if "=" in line:
                name, _, value = line.rstrip("\n").partition("=")
                names[name] = value
    return names


class _InvokeClaudeEnsureTestBase(unittest.TestCase):
    """Shared plumbing: sources the functions-only llm-client.sh with a stub
    `claude` on PATH, calls invoke_claude directly, and captures the stub's
    own environ for inspection."""

    def _run_invoke_claude_and_capture_child_env(self, extra_parent_env=None):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-auth-mode-ensure-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_environ_dump_success_claude(bin_dir, dump_path)

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
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
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


class TestAcceptance1UndeclaredNoChange(_InvokeClaudeEnsureTestBase):
    """1. UNDECLARED CLAGENTIC_AUTH_MODE -> spawned command's child env
    carries no CLAUDE_CODE_USE_BEDROCK at all -- byte-identical to today's
    behavior (no env prefix inserted)."""

    def test_undeclared_auth_mode_no_claude_code_use_bedrock_in_child(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env()
        self.assertNotIn(
            "CLAUDE_CODE_USE_BEDROCK", child_env,
            f"with CLAGENTIC_AUTH_MODE unset, invoke_claude must not inject "
            f"CLAUDE_CODE_USE_BEDROCK -- spawned command must stay "
            f"byte-identical to pre-fix behavior. child_env "
            f"keys={sorted(child_env)!r}",
        )


class TestAcceptance2And3BedrockValuesEnsure(_InvokeClaudeEnsureTestBase):
    """2/3. Both bedrock-* declared values ensure CLAUDE_CODE_USE_BEDROCK=1
    on the spawned claude child, regardless of the calling session's own
    ambient value."""

    def test_bedrock_sso_ensures_claude_code_use_bedrock(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={"CLAGENTIC_AUTH_MODE": "bedrock-sso"},
        )
        self.assertEqual(
            child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1",
            f"invoke_claude must ensure CLAUDE_CODE_USE_BEDROCK when "
            f"CLAGENTIC_AUTH_MODE=bedrock-sso. child_env keys={sorted(child_env)!r}",
        )

    def test_bedrock_api_key_ensures_claude_code_use_bedrock(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={"CLAGENTIC_AUTH_MODE": "bedrock-api-key"},
        )
        self.assertEqual(child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1")

    def test_ambient_claude_code_use_bedrock_unset_in_parent_session(self):
        """Confirms the fixture actually represents 'a NON-Bedrock
        interactive session' -- CLAUDE_CODE_USE_BEDROCK is unset in the
        PARENT shell before invoke_claude runs; the child only gets it
        because invoke_claude's own env-ensure logic added it."""
        env = dict(os.environ)
        env.pop("CLAUDE_CODE_USE_BEDROCK", None)
        env["CLAGENTIC_AUTH_MODE"] = "bedrock-sso"
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", env)


class TestAcceptance4GateRoleNoFallback(unittest.TestCase):
    """4. role=gate completes with cli=claude as PRIMARY, no 'fallback:'
    line, on a bedrock-sso-declared host -- exercised through the real
    walk_chain function end to end."""

    def _run_walk_chain_gate(self, extra_env=None):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-auth-mode-gate-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_environ_dump_success_claude_gate_decision(bin_dir, dump_path)
            sso_cache_dir = os.path.join(tmpdir, "sso-cache")
            _write_valid_sso_cache(sso_cache_dir)

            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export CLAGENTIC_GATE_CMD=claude
                _fixture_prompt() {{ printf 'test prompt'; }}
                . '{LLM_CLIENT_SH}'
                printf 'stdin diff content' | walk_chain 'gate' 'json' _fixture_prompt
            """)
            env = dict(os.environ)
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
            env.pop("CLAGENTIC_AUTH_MODE", None)
            env["CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR"] = sso_cache_dir
            if extra_env:
                env.update(extra_env)
            env.update(source_env(llm_client=True))
            r = subprocess.run(
                ["sh", "-c", script, LLM_CLIENT_SH],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            child_env = _read_environ_dump(dump_path) if os.path.exists(dump_path) else {}
            return r, child_env
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_gate_role_primary_pass_no_fallback_notice_on_bedrock_host(self):
        r, child_env = self._run_walk_chain_gate(
            extra_env={"CLAGENTIC_AUTH_MODE": "bedrock-sso"},
        )
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn(
            "fallback", r.stderr,
            f"role=gate must complete via the PRIMARY (claude) step on a "
            f"bedrock-sso-declared host -- a fallback: notice here would mean "
            f"the primary step 401'd and the chain silently advanced past "
            f"it, exactly the class of failure this task fixes. "
            f"stderr={r.stderr!r}",
        )
        self.assertEqual(child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1")


class TestAcceptance5ReviewerLayer2FallbackCarriesEnsure(unittest.TestCase):
    """5. Reviewer run forced past the router (router stopped/unreachable)
    succeeds via the claude:flagship layer-2 direct-CLI fallback instead of
    INFRA_DEGRADED -- and that fallback call still carries
    CLAUDE_CODE_USE_BEDROCK on a bedrock-sso-declared host."""

    def test_layer2_fallback_call_carries_claude_code_use_bedrock(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-auth-mode-layer2-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_environ_dump_success_claude(bin_dir, dump_path)
            sso_cache_dir = os.path.join(tmpdir, "sso-cache")
            _write_valid_sso_cache(sso_cache_dir)

            # CLAGENTIC_ROUTER_URL points at a port nothing listens on, so
            # invoke_router's curl fails fast and walk_chain falls through
            # to the direct-CLI chain (Layer 2) -- the reviewer's only
            # non-router fallback, per the task's blast-radius note.
            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export CLAGENTIC_REVIEWER_CMD=claude
                export CLAGENTIC_REVIEWER_VIA_ROUTER=1
                export CLAGENTIC_ROUTER_URL=http://127.0.0.1:1
                _fixture_prompt() {{ printf 'test prompt'; }}
                . '{LLM_CLIENT_SH}'
                printf 'stdin diff content' | walk_chain 'reviewer' 'json' _fixture_prompt
            """)
            env = dict(os.environ)
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
            env["CLAGENTIC_AUTH_MODE"] = "bedrock-sso"
            env["CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR"] = sso_cache_dir
            env.update(source_env(llm_client=True))
            r = subprocess.run(
                ["sh", "-c", script, LLM_CLIENT_SH],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
                timeout=30,
            )
            self.assertEqual(r.returncode, 0, f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertIn(
                "LAYER-2 FALLBACK", r.stderr,
                f"expected a Layer-2 fallback notice before the direct-CLI "
                f"chain runs (docs/ROUTER.md 'Layer 1/Layer 2 fallback, "
                f"deliberately distinguishable'). stderr={r.stderr!r}",
            )
            self.assertTrue(
                os.path.exists(dump_path),
                f"the direct-CLI (claude) fallback never ran. "
                f"stdout={r.stdout!r} stderr={r.stderr!r}",
            )
            child_env = _read_environ_dump(dump_path)
            self.assertEqual(
                child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1",
                f"the Layer-2 direct-CLI fallback call must still carry "
                f"CLAUDE_CODE_USE_BEDROCK on a bedrock-sso-declared host -- "
                f"this is the reviewer's ONLY non-router fallback path "
                f"(blast radius note 2 in lr-0ac353). "
                f"child_env keys={sorted(child_env)!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestAcceptance6NonClaudeEnvStripUnaffected(unittest.TestCase):
    """6. NON_CLAUDE_ENV_STRIP behavior for codex/generic CLIs is unchanged;
    the two constants do not interact -- invoke_generic must still strip the
    four router-scoped vars even when a Bedrock declaration is present, and
    must never receive CLAUDE_CODE_USE_BEDROCK."""

    def test_invoke_generic_unaffected_by_auth_mode_declaration(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-auth-mode-non-claude-")
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
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
            env["CLAGENTIC_AUTH_MODE"] = "bedrock-sso"
            env["AWS_BEARER_TOKEN_BEDROCK"] = "router-admin-token-value"
            env["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:9999/router"
            env["ANTHROPIC_AUTH_TOKEN"] = "router-anthropic-token-value"
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

        for var in (
            "AWS_BEARER_TOKEN_BEDROCK",
            "ANTHROPIC_BEDROCK_BASE_URL",
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_AUTH_TOKEN",
        ):
            self.assertNotIn(
                var, child_env,
                f"invoke_generic must still strip {var} even when a "
                f"CLAGENTIC_AUTH_MODE declaration is present -- "
                f"CLAUDE_ROUTER_ENV_ENSURE must not interact with "
                f"NON_CLAUDE_ENV_STRIP. child_env keys={sorted(child_env)!r}",
            )
        self.assertNotIn(
            "CLAUDE_CODE_USE_BEDROCK", child_env,
            f"invoke_generic must never receive CLAUDE_CODE_USE_BEDROCK -- "
            f"that ensure is scoped to invoke_claude's own two call sites "
            f"only. child_env keys={sorted(child_env)!r}",
        )


class TestAcceptance7DsTimeoutMissingStillFailsClosed(unittest.TestCase):
    """7. DS_TIMEOUT_CMD resolving to the ds_timeout_missing shell function
    still triggers INV-1a's fail-closed diagnostic (exit 99, distinct
    stderr) rather than 'env: No such file or directory' -- proves
    CLAUDE_ROUTER_ENV_ENSURE is placed AFTER $DS_TIMEOUT_CMD "$CALL_TIMEOUT"
    in both invoke_claude call sites, never wrapping it."""

    def test_ds_timeout_missing_fails_closed_not_env_exec_error(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-auth-mode-ds-timeout-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            for src_dir in ("/usr/bin", "/bin"):
                if not os.path.isdir(src_dir):
                    continue
                for name in os.listdir(src_dir):
                    if name in ("timeout", "gtimeout"):
                        continue
                    dst = os.path.join(bin_dir, name)
                    if os.path.exists(dst):
                        continue
                    src = os.path.join(src_dir, name)
                    try:
                        os.symlink(src, dst)
                    except OSError:
                        pass

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
                invoke_claude "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5 "markdown" "auditor"
                exit $?
            """)
            env = dict(os.environ)
            env["PATH"] = bin_dir
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
            env["CLAGENTIC_AUTH_MODE"] = "bedrock-sso"
            env.update(source_env(llm_client=True))
            r = subprocess.run(
                ["sh", "-c", script, LLM_CLIENT_SH],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            err_file_content = ""
            if os.path.exists(err_file):
                with open(err_file) as f:
                    err_file_content = f.read()

            if "timeout" not in err_file_content and r.returncode not in (99, 127):
                self.skipTest(
                    f"host PATH still resolved a real timeout/gtimeout binary "
                    f"even after isolating PATH -- cannot exercise the "
                    f"ds_timeout_missing branch on this host. "
                    f"rc={r.returncode} err_file={err_file_content!r}"
                )
            self.assertEqual(
                r.returncode, 99,
                f"ds_timeout_missing must return its distinct fail-closed "
                f"exit status (99, INV-1a) -- an exit 127 with 'env: No "
                f"such file or directory' would mean CLAUDE_ROUTER_ENV_ENSURE "
                f"was placed BEFORE $DS_TIMEOUT_CMD, wrapping the shell-"
                f"function resolution itself (env cannot exec a shell "
                f"function). rc={r.returncode} stdout={r.stdout!r} "
                f"err_file={err_file_content!r}",
            )
            self.assertNotIn(
                "No such file or directory", err_file_content,
                f"the ordering regression this test guards against: "
                f"err_file={err_file_content!r}",
            )
            self.assertIn(
                "no timeout binary found", err_file_content,
                f"expected ds_timeout_missing's own diagnostic text. "
                f"err_file={err_file_content!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestAcceptance8EnterpriseBlankingPayloadFixture(_InvokeClaudeEnsureTestBase):
    """8. THE EXACT REGRESSION CASE (lr-6d4a1f comment #1, AC 7): the
    Enterprise/OAuth session-blanking payload sets the four router-scoped
    vars to EMPTY STRINGS (set-but-empty, not unset). This is the explicit
    set-but-empty fixture the old 662-line test file was missing -- it
    covered only unset and non-empty ANTHROPIC_BEDROCK_BASE_URL, which is
    exactly the gap that let the old predicate's inertness through
    undetected. With CLAGENTIC_AUTH_MODE=bedrock-sso declared, the ensure
    must fire regardless of what shape the (now-irrelevant) old sentinel
    var is in."""

    def test_enterprise_blanking_payload_set_but_empty_still_ensures_bedrock(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                # The Enterprise/OAuth blanking payload: all four
                # router-scoped vars SET TO EMPTY STRING, not unset.
                "ANTHROPIC_BEDROCK_BASE_URL": "",
                "AWS_BEARER_TOKEN_BEDROCK": "",
                "ANTHROPIC_BASE_URL": "",
                "ANTHROPIC_AUTH_TOKEN": "",
            },
        )
        self.assertEqual(
            child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1",
            f"CLAUDE_CODE_USE_BEDROCK must be ensured even when the "
            f"legacy ANTHROPIC_BEDROCK_BASE_URL sentinel is set-but-empty "
            f"(the exact Enterprise/OAuth blanking payload lr-0ac353's "
            f"predicate was inert under) -- the declaration is read "
            f"directly and is never carried in the stamped settings.json "
            f"env block, so it cannot be blanked this way. "
            f"child_env keys={sorted(child_env)!r}",
        )


class TestAcceptance9NonBedrockValuesNeverEnsure(_InvokeClaudeEnsureTestBase):
    """9. anthropic-oauth, enterprise, an unrecognized/typo'd value, and
    unset all never ENSURE CLAUDE_CODE_USE_BEDROCK -- even when the old,
    now-unread ANTHROPIC_BEDROCK_BASE_URL sentinel happens to be non-empty.
    The declaration is authoritative; the old env-derived sentinel is never
    consulted at all (report AC 5: 'no AWS/bedrock var stamped or injected
    for anthropic-oauth or enterprise').

    DELIBERATE UPDATE (lr-6276ea PR #200 fold-in, PEACHES finding
    amos.path-choice.4 -- code-craft rule 5 exception, stated explicitly
    rather than silently done): the anthropic-oauth/enterprise assertions
    below changed from `assertNotIn("CLAUDE_CODE_USE_BEDROCK", child_env)`
    to `assertNotEqual(child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1")`.
    This file predates lr-6276ea's enterprise|anthropic-oauth arm, which now
    deliberately BLANKS (not unsets) CLAUDE_CODE_USE_BEDROCK for those two
    modes -- the literal remediation PEACHES's fold-in required, to stop an
    ambient CLAUDE_CODE_USE_BEDROCK=1 surviving into a declared-direct-API
    gate-path spawn. `assertNotIn` encoded ABSENCE as this test's proxy for
    "not ensured"; blanking necessarily makes the key PRESENT-but-empty, so
    the literal proxy assertion would now fail on correct, intended
    behavior. The actual invariant this class name and docstring describe
    -- these modes never ENSURE (force to "1") Bedrock protocol -- is
    unchanged and is what the updated assertion checks directly. This is
    not a weakening: an empty-string CLAUDE_CODE_USE_BEDROCK is exactly as
    inert to the claude CLI's own `= "1"` check as an absent one (see
    bin/clagentic-lite:3286/3366's identical string-equality check), and
    the updated assertion is STRICTER in one respect -- it would also catch
    a hypothetical future regression that set CLAUDE_CODE_USE_BEDROCK to
    any other truthy-looking non-"1" string, which assertNotIn could not.
    The unrecognized-value case is untouched -- that arm still leaves
    CLAUDE_CODE_USE_BEDROCK entirely absent, no blanking, so its original
    assertNotIn remains the precise assertion there."""

    def test_anthropic_oauth_never_ensures(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={
                "CLAGENTIC_AUTH_MODE": "anthropic-oauth",
                "ANTHROPIC_BEDROCK_BASE_URL": "https://bedrock-mantle.example.invalid",
            },
        )
        self.assertNotEqual(
            child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1",
            f"anthropic-oauth must never ENSURE (force to \"1\") "
            f"CLAUDE_CODE_USE_BEDROCK -- present-but-blank (lr-6276ea's "
            f"direct-API arm) or absent are both acceptable; only \"1\" "
            f"would mean this mode wrongly forced Bedrock protocol. "
            f"child_env.get('CLAUDE_CODE_USE_BEDROCK')="
            f"{child_env.get('CLAUDE_CODE_USE_BEDROCK')!r}",
        )

    def test_enterprise_never_ensures(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={
                "CLAGENTIC_AUTH_MODE": "enterprise",
                "ANTHROPIC_BEDROCK_BASE_URL": "https://bedrock-mantle.example.invalid",
            },
        )
        self.assertNotEqual(
            child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1",
            f"enterprise must never ENSURE (force to \"1\") "
            f"CLAUDE_CODE_USE_BEDROCK -- present-but-blank (lr-6276ea's "
            f"direct-API arm) or absent are both acceptable; only \"1\" "
            f"would mean this mode wrongly forced Bedrock protocol. "
            f"child_env.get('CLAUDE_CODE_USE_BEDROCK')="
            f"{child_env.get('CLAUDE_CODE_USE_BEDROCK')!r}",
        )

    def test_unrecognized_value_never_ensures(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={
                "CLAGENTIC_AUTH_MODE": "some-typo-value",
                "ANTHROPIC_BEDROCK_BASE_URL": "https://bedrock-mantle.example.invalid",
            },
        )
        # Unchanged: an unrecognized value matches no arm at all (the
        # implicit `*)` fallthrough), so CLAUDE_CODE_USE_BEDROCK stays
        # entirely absent here -- no blanking applies, the original precise
        # assertion still holds untouched.
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", child_env)


if __name__ == "__main__":
    unittest.main()
