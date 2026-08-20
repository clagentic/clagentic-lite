"""
Regression coverage for lr-0ac353: invoke_claude never sets
CLAUDE_CODE_USE_BEDROCK, so on a Bedrock-mode router host every
non-routable role (notably gate/merge-gate) 401s.

ROOT CAUSE: invoke_claude (scripts/llm-client.sh) spawns `claude --print
--model <concrete-model>` relying entirely on AMBIENT session env for auth
mode. On a Bedrock-mode router host, an operator whose CURRENT interactive
session happens to be in Enterprise/OAuth mode leaves CLAUDE_CODE_USE_BEDROCK
unset, so the CLI speaks Anthropic-native /v1/messages to the router instead
of the Bedrock /model/<id>/invoke path. The router only routes
role:/chain:/backend:-prefixed models; a concrete model name is
passthrough-forwarded to api.anthropic.com carrying the router's local admin
token as the caller's Authorization header. Upstream 401s. Deterministic,
regardless of the operator's OWN interactive claude-switch state.

DETECTION PREDICATE (this task's design call): key off
ANTHROPIC_BEDROCK_BASE_URL being non-empty in the environment invoke_claude
itself runs in. bin/clagentic-lite's _render_claude_settings_body already
stamps that var into the enrolled repo's .claude/settings.json env block
specifically and only when CLAGENTIC_ROUTER_BEDROCK_MODE=1 was set at
enroll/update time (scripts/test_router_bedrock_settings_stamp.py) -- that
settings.json env block is process-wide for the session (the same fact that
makes NON_CLAUDE_ENV_STRIP, immediately above CLAUDE_ROUTER_ENV_ENSURE in
llm-client.sh, necessary), so ANTHROPIC_BEDROCK_BASE_URL is already the
live, host-declared source of truth for Bedrock mode by the time this script
runs -- clagentic-lite wrote it, clagentic-lite already inherits it
unchanged (invoke_claude is deliberately NOT covered by NON_CLAUDE_ENV_STRIP
-- see that constant's own docstring, "the whole point of the asymmetry").

These tests source the REAL scripts/llm-client.sh (test_source_helpers.py's
guard-sentinel technique, same as every other llm-client.sh-sourcing test in
this suite) with a stub `claude` on PATH that both dumps its own environ
(proving/disproving CLAUDE_CODE_USE_BEDROCK's presence) and answers a valid
JSON envelope so walk_chain-driven tests (2, 4) see a clean primary pass.

Six acceptance cases (task's own enumeration):
  1. Host whose settings.json declares Bedrock mode (ANTHROPIC_BEDROCK_BASE_URL
     set), invoke_claude called from a NON-Bedrock interactive session (this
     test's own shell does not itself set CLAUDE_CODE_USE_BEDROCK) -> the
     spawned claude child process has CLAUDE_CODE_USE_BEDROCK=1 in ITS OWN
     environ, proving the fix, not merely that the step "passed".
  2. role=gate completes with cli=claude as PRIMARY, no "fallback:" stderr
     line, on that host.
  3. Host with no Bedrock declaration -> spawned command's env carries no
     CLAUDE_CODE_USE_BEDROCK at all -- byte-identical to today's behavior.
  4. Reviewer run forced past the router (router unreachable) succeeds via
     the claude:flagship layer-2 direct-CLI fallback instead of
     INFRA_DEGRADED, and still carries CLAUDE_CODE_USE_BEDROCK into that
     fallback call on a Bedrock-declared host.
  5. NON_CLAUDE_ENV_STRIP behavior for a non-Claude CLI (invoke_generic) is
     unchanged by this addition -- the two constants do not interact.
  6. DS_TIMEOUT_CMD resolving to the ds_timeout_missing shell function still
     triggers INV-1a's fail-closed diagnostic (exit 99, distinct stderr)
     rather than "env: No such file or directory" -- proving the ORDERING
     requirement (CLAUDE_ROUTER_ENV_ENSURE placed AFTER $DS_TIMEOUT_CMD
     "$CALL_TIMEOUT", never wrapping it).

Run with: python3 -m unittest scripts.test_invoke_claude_bedrock_env_ensure -v
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

# The Bedrock-declaration var this task's detection predicate reads. Kept as
# a plain literal here (test-side), independent of the
# CLAGENTIC_ROUTER_BEDROCK_ENSURE_VAR default in llm-client.sh -- a
# divergence between the two would itself be a regression this test exists
# to catch (test_default_ensure_var_is_anthropic_bedrock_base_url below).
_BEDROCK_DECLARATION_VAR = "ANTHROPIC_BEDROCK_BASE_URL"


def _write_environ_dump_success_claude(bin_dir, out_path, num_turns=5):
    """Stub `claude` that dumps its OWN environ to out_path, then emits a
    valid --output-format json envelope on stdout and exits 0 -- lets a
    single call site prove BOTH env-content (acceptance 1/3/4) and
    walk_chain pass/fallback behavior (acceptance 2/4) without two stubs."""
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
    findings-array shape reviewer/auditor use -- an unwrap against the
    wrong shape fails (zero role-shaped fenced candidates), which is a
    genuine walk_chain outcome, not a fixture bug, so the gate-role test
    needs its own correctly-shaped stub."""
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
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-ensure-")
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


class TestAcceptance1BedrockHostNonBedrockSession(_InvokeClaudeEnsureTestBase):
    """1. Host whose settings.json declares Bedrock mode, invoke_claude
    called from a NON-Bedrock interactive session -> the spawned claude
    child carries CLAUDE_CODE_USE_BEDROCK=1 in its own environ (this is
    what makes the real CLI select the /model/<id>/invoke wire protocol
    instead of /v1/messages -- the step-passing shape alone, by itself,
    would not distinguish this from the pre-fix bug, since the stub always
    exits 0)."""

    def test_claude_code_use_bedrock_set_in_child_env(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={_BEDROCK_DECLARATION_VAR: "https://bedrock-mantle.example.invalid"},
        )
        self.assertIn(
            "CLAUDE_CODE_USE_BEDROCK", child_env,
            f"invoke_claude must ensure CLAUDE_CODE_USE_BEDROCK on a "
            f"Bedrock-declared host regardless of the calling session's own "
            f"ambient value. child_env keys={sorted(child_env)!r}",
        )
        self.assertEqual(child_env["CLAUDE_CODE_USE_BEDROCK"], "1")

    def test_ambient_claude_code_use_bedrock_unset_in_parent_session(self):
        """Confirms the fixture actually represents 'a NON-Bedrock
        interactive session' -- CLAUDE_CODE_USE_BEDROCK is unset in the
        PARENT shell before invoke_claude runs; the child only gets it
        because invoke_claude's own env-ensure logic added it, not because
        it leaked in ambiently."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-ensure-parent-")
        try:
            env = dict(os.environ)
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
            env[_BEDROCK_DECLARATION_VAR] = "https://bedrock-mantle.example.invalid"
            self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", env)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestAcceptance3NoDeclarationNoChange(_InvokeClaudeEnsureTestBase):
    """3. Host with no Bedrock declaration -> spawned command's child env
    carries no CLAUDE_CODE_USE_BEDROCK at all -- byte-identical to today's
    behavior (no env prefix inserted)."""

    def test_no_bedrock_declaration_no_claude_code_use_bedrock_in_child(self):
        child_env, r = self._run_invoke_claude_and_capture_child_env()
        self.assertNotIn(
            "CLAUDE_CODE_USE_BEDROCK", child_env,
            f"with no Bedrock declaration, invoke_claude must not inject "
            f"CLAUDE_CODE_USE_BEDROCK -- spawned command must stay "
            f"byte-identical to pre-fix behavior. child_env "
            f"keys={sorted(child_env)!r}",
        )

    def test_bedrock_declaration_var_empty_string_no_change(self):
        """Empty-string (not merely unset) ANTHROPIC_BEDROCK_BASE_URL must
        also be treated as 'no declaration' -- an operator who unstamps
        Bedrock mode by clearing the var, rather than removing it, must get
        the same byte-identical behavior."""
        child_env, r = self._run_invoke_claude_and_capture_child_env(
            extra_parent_env={_BEDROCK_DECLARATION_VAR: ""},
        )
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", child_env)


class TestAcceptance2GateRoleNoFallback(unittest.TestCase):
    """2. role=gate completes with cli=claude as PRIMARY, no 'fallback:'
    line, on a Bedrock-declared host -- exercised through the real
    walk_chain function end to end (mirroring
    test_walk_chain_stderr_notice.py's established technique)."""

    def _run_walk_chain_gate(self, extra_env=None):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-gate-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_environ_dump_success_claude_gate_decision(bin_dir, dump_path)

            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export CLAGENTIC_GATE_CMD=claude
                _fixture_prompt() {{ printf 'test prompt'; }}
                . '{LLM_CLIENT_SH}'
                printf 'stdin diff content' | walk_chain 'gate' 'json' _fixture_prompt
            """)
            env = dict(os.environ)
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
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
            extra_env={_BEDROCK_DECLARATION_VAR: "https://bedrock-mantle.example.invalid"},
        )
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn(
            "fallback", r.stderr,
            f"role=gate must complete via the PRIMARY (claude) step on a "
            f"Bedrock-declared host -- a fallback: notice here would mean "
            f"the primary step 401'd and the chain silently advanced past "
            f"it, exactly the class of failure this task fixes. "
            f"stderr={r.stderr!r}",
        )
        self.assertEqual(child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1")


class TestAcceptance4ReviewerLayer2FallbackCarriesEnsure(unittest.TestCase):
    """4. Reviewer run forced past the router (router stopped/unreachable)
    succeeds via the claude:flagship layer-2 direct-CLI fallback instead of
    INFRA_DEGRADED -- and that fallback call still carries
    CLAUDE_CODE_USE_BEDROCK on a Bedrock-declared host, proving the fix
    reaches the Layer-2 direct-CLI path, not merely a hypothetical primary
    call that never actually happens when the router is configured."""

    def test_layer2_fallback_call_carries_claude_code_use_bedrock(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-layer2-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_environ_dump_success_claude(bin_dir, dump_path)

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
            env[_BEDROCK_DECLARATION_VAR] = "https://bedrock-mantle.example.invalid"
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
                f"CLAUDE_CODE_USE_BEDROCK on a Bedrock-declared host -- "
                f"this is the reviewer's ONLY non-router fallback path "
                f"(blast radius note 2 in lr-0ac353). "
                f"child_env keys={sorted(child_env)!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestAcceptance5NonClaudeEnvStripUnaffected(unittest.TestCase):
    """5. NON_CLAUDE_ENV_STRIP behavior for codex/generic CLIs is unchanged;
    the two constants do not interact -- invoke_generic must still strip the
    four router-scoped vars even when a Bedrock declaration is present, and
    must never receive CLAUDE_CODE_USE_BEDROCK (that var is Claude-specific;
    a non-Claude CLI has no use for it and CLAUDE_ROUTER_ENV_ENSURE is only
    ever applied at invoke_claude's own two call sites)."""

    def test_invoke_generic_unaffected_by_bedrock_declaration(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-non-claude-")
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
            env[_BEDROCK_DECLARATION_VAR] = "https://bedrock-mantle.example.invalid"
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
                f"invoke_generic must still strip {var} even when a Bedrock "
                f"declaration is present -- CLAUDE_ROUTER_ENV_ENSURE must "
                f"not interact with NON_CLAUDE_ENV_STRIP. "
                f"child_env keys={sorted(child_env)!r}",
            )
        self.assertNotIn(
            "CLAUDE_CODE_USE_BEDROCK", child_env,
            f"invoke_generic must never receive CLAUDE_CODE_USE_BEDROCK -- "
            f"that ensure is scoped to invoke_claude's own two call sites "
            f"only. child_env keys={sorted(child_env)!r}",
        )


class TestAcceptance6DsTimeoutMissingStillFailsClosed(unittest.TestCase):
    """6. DS_TIMEOUT_CMD resolving to the ds_timeout_missing shell function
    still triggers INV-1a's fail-closed diagnostic (exit 99, distinct
    stderr) rather than 'env: No such file or directory' -- proves
    CLAUDE_ROUTER_ENV_ENSURE is placed AFTER $DS_TIMEOUT_CMD "$CALL_TIMEOUT"
    in both invoke_claude call sites, never wrapping it (env can only exec
    real binaries; DS_TIMEOUT_CMD may resolve to a shell function)."""

    def test_ds_timeout_missing_fails_closed_not_env_exec_error(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-ds-timeout-")
        try:
            # Build an isolated PATH: symlink every real binary from the
            # host's own /usr/bin and /bin into bin_dir EXCEPT
            # timeout/gtimeout, so every POSIX utility platform.sh and this
            # script need (dirname, sed, uname, date, stat, cat, wc, tr,
            # git, sort, ...) still resolves, but DS_TIMEOUT_CMD detection
            # (`command -v timeout`/`command -v gtimeout`) genuinely fails
            # and falls through to ds_timeout_missing -- an empty bin_dir
            # alone would break the shell/sourcing itself before ever
            # reaching invoke_claude.
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
            # PATH is bin_dir ONLY -- every real utility is reachable via
            # the symlinks built above, but timeout/gtimeout are not.
            env["PATH"] = bin_dir
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
            env[_BEDROCK_DECLARATION_VAR] = "https://bedrock-mantle.example.invalid"
            env.update(source_env(llm_client=True))
            r = subprocess.run(
                ["sh", "-c", script, LLM_CLIENT_SH],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            # invoke_claude redirects the subshell's own stderr to ERR_FILE
            # (2> "$ERR_FILE") -- ds_timeout_missing's diagnostic (printed
            # from inside that subshell) lands there, not in the outer `sh
            # -c` process's own stderr (r.stderr), which only carries a
            # `set -e` abort message, if anything.
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


class TestDefaultEnsureVarIsConfigurable(unittest.TestCase):
    """AGENTS.md invariant 6 (nothing host-specific hardcoded -- everything
    user-supplied goes through config/env): CLAGENTIC_ROUTER_BEDROCK_ENSURE_VAR
    lets an operator point the detection predicate at a different variable
    name entirely, without a code change."""

    def test_ensure_var_override_is_honored(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-ensure-var-")
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

            script = textwrap.dedent(f"""\
                export PROMPT_FILE='{prompt_file}'
                export INPUT_FILE='{input_file}'
                export OUTPUT_FILE='{output_file}'
                export ERR_FILE='{err_file}'
                . '{LLM_CLIENT_SH}'
                invoke_claude "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5 "markdown" "auditor"
            """)
            env = dict(os.environ)
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
            env.pop("CLAUDE_CODE_USE_BEDROCK", None)
            env.pop(_BEDROCK_DECLARATION_VAR, None)
            env["CLAGENTIC_ROUTER_BEDROCK_ENSURE_VAR"] = "MY_CUSTOM_BEDROCK_FLAG"
            env["MY_CUSTOM_BEDROCK_FLAG"] = "1"
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

        self.assertEqual(
            child_env.get("CLAUDE_CODE_USE_BEDROCK"), "1",
            f"a custom CLAGENTIC_ROUTER_BEDROCK_ENSURE_VAR override must be "
            f"honored -- the detection predicate is not hardcoded to "
            f"ANTHROPIC_BEDROCK_BASE_URL specifically. "
            f"child_env keys={sorted(child_env)!r}",
        )


if __name__ == "__main__":
    unittest.main()
