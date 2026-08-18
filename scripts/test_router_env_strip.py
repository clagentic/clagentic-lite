"""
Regression coverage for lr-b20c0a: invoke_codex (all three `codex exec` call
sites) and invoke_generic (scripts/llm-client.sh) must strip the four
router-scoped env vars -- AWS_BEARER_TOKEN_BEDROCK, ANTHROPIC_BEDROCK_BASE_URL,
ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN -- before shelling out, while
invoke_claude must keep carrying them unchanged. Extended by lr-d7c74e to
also cover codex_version_check's `codex --version` probe, the one spawn
lr-b20c0a left out of scope (no network call, so no live exposure, but the
same hazard class).

ROOT CAUSE: bin/clagentic-lite stamps those four vars into the enrolled
repo's .claude/settings.json env block under CLAGENTIC_ROUTER_BEDROCK_MODE=1
(lr-4af4c4). That block is process-wide for the session, not scoped to
Claude Code's own outbound calls -- every subprocess this session spawns
inherits it, including `codex exec`. codex's amazon-bedrock provider reads
AWS_BEARER_TOKEN_BEDROCK itself and prefers it over SSO-derived creds, so it
sends the router's local admin token to the real Bedrock endpoint, which
401s -- 100% failure for every codex-backed Reviewer/Auditor call on a
Bedrock-mode host.

THIS IS AN ENV-INSPECTION TEST, NOT AN EXIT-CODE TEST (the task's own
acceptance shape): the stub CLI dumps its own environ verbatim so the test
can assert on PRESENCE/ABSENCE of specific vars in the child process, not
merely on whether the call succeeded or failed. Follows
test_invoke_exit_status_sweep.py's stub-CLI-on-PATH convention (sources the
real llm-client.sh via test_source_helpers.py's guard-sentinel technique,
same as every other llm-client.sh-sourcing test in this suite).

THE NEGATIVE HALF IS REQUIRED: an over-broad strip that also stripped these
vars from invoke_claude's child would silently break router routing for the
Claude path (the whole point of Bedrock mode) while still looking "fixed"
from the codex side alone. Every test class below asserts BOTH directions --
absent from the non-Claude child, present in invoke_claude's child.

Run with: python3 -m unittest scripts.test_router_env_strip -v
"""
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

# The four router-scoped vars the fix must strip from every non-Claude
# subprocess. Kept as a plain tuple here (test-side), independent of the
# NON_CLAUDE_ENV_STRIP shell variable this test exercises -- a divergence
# between the two would be exactly the regression this test exists to catch.
ROUTER_SCOPED_VARS = (
    "AWS_BEARER_TOKEN_BEDROCK",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
)

# Fed into the parent shell before sourcing llm-client.sh, so every invoke_*
# call under test inherits all four vars exactly as a real Bedrock-mode
# session would via .claude/settings.json's env block.
_PARENT_ROUTER_ENV = {
    "AWS_BEARER_TOKEN_BEDROCK": "router-admin-token-value",
    "ANTHROPIC_BEDROCK_BASE_URL": "https://bedrock-mantle.example.invalid",
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:9999/router",
    "ANTHROPIC_AUTH_TOKEN": "router-anthropic-token-value",
}


def _write_environ_dump_stub(bin_dir, name, out_path):
    """Write a stub CLI binary that drains stdin and dumps its OWN environ
    (one NAME=VALUE per line, `env` output) to out_path, then exits 0.

    codex's carrier also probes `codex --version` before the real exec call
    (codex_version_check) -- the stub answers that with a fixed, modern
    version string so the full-flag-set path is used and the environ dump
    below captures the real exec invocation's env, not a version-probe
    fallback path (same reasoning as
    test_invoke_exit_status_sweep.py's _write_stub_binary)."""
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "{name} 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            env > '{out_path}'
            printf 'stub output\\n'
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _read_environ_dump(out_path):
    """Parse a NAME=VALUE-per-line `env` dump into a dict of names present."""
    names = set()
    with open(out_path) as f:
        for line in f:
            if "=" in line:
                names.add(line.split("=", 1)[0])
    return names


class _RouterEnvStripTestBase(unittest.TestCase):
    """Shared plumbing: sources the functions-only llm-client.sh with a stub
    CLI on PATH, all four router-scoped vars set in the parent, and captures
    the stub's own environ for inspection."""

    def _run_and_capture_child_env(self, stub_name, call_snippet):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-env-strip-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_environ_dump_stub(bin_dir, stub_name, dump_path)

            sourced = LLM_CLIENT_SH

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
            env.update(_PARENT_ROUTER_ENV)
            env.update(source_env(llm_client=True))

            script = textwrap.dedent(f"""\
                export PROMPT_FILE='{prompt_file}'
                export INPUT_FILE='{input_file}'
                export OUTPUT_FILE='{output_file}'
                export ERR_FILE='{err_file}'
                . '{sourced}'
                {call_snippet}
            """)
            r = subprocess.run(
                ["sh", "-c", script, sourced],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            self.assertTrue(
                os.path.exists(dump_path),
                f"stub CLI never ran / never dumped its environ. "
                f"stdout={r.stdout!r} stderr={r.stderr!r}",
            )
            return _read_environ_dump(dump_path)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestInvokeCodexStripsRouterEnv(_RouterEnvStripTestBase):
    """invoke_codex's full-flag-set call sites (:1515, :1519) -- MODEL set
    and MODEL empty, both of which select the full-flag-set branch since the
    stub answers --version as a known-compatible version."""

    def test_model_set_strips_all_four_router_vars(self):
        child_env = self._run_and_capture_child_env(
            "codex",
            'invoke_codex "gpt-5" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5',
        )
        for var in ROUTER_SCOPED_VARS:
            self.assertNotIn(
                var, child_env,
                f"invoke_codex (MODEL set) leaked {var} into the codex child env",
            )

    def test_model_empty_strips_all_four_router_vars(self):
        child_env = self._run_and_capture_child_env(
            "codex",
            'invoke_codex "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5',
        )
        for var in ROUTER_SCOPED_VARS:
            self.assertNotIn(
                var, child_env,
                f"invoke_codex (MODEL empty) leaked {var} into the codex child env",
            )


def _write_version_probe_environ_dump_stub(bin_dir, name, out_path):
    """Write a stub `codex` binary that dumps its OWN environ on the
    `--version` invocation specifically (unlike _write_environ_dump_stub
    above, whose `--version` branch answers with a fixed version string and
    does NOT dump env -- that shape exists so the exec-call environ dump
    captures the real invoke_codex exec, not the version probe. This
    variant is the version-probe-specific mirror of that: it exists to
    capture codex_version_check's OWN `codex --version` child env, so the
    other branch (the real exec call, never reached here) is irrelevant and
    left unimplemented."""
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              env > '{out_path}'
              echo "{name} 99.0.0"
              exit 0
            fi
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


class TestCodexVersionCheckStripsRouterEnv(unittest.TestCase):
    """codex_version_check's `codex --version` probe (:105, lr-d7c74e
    follow-up to lr-b20c0a) -- same hazard class as invoke_codex/
    invoke_generic even though this spawn makes no network call today."""

    def test_strips_all_four_router_vars(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-env-strip-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            dump_path = os.path.join(tmpdir, "child-environ.txt")
            _write_version_probe_environ_dump_stub(bin_dir, "codex", dump_path)

            sourced = LLM_CLIENT_SH

            env = dict(os.environ)
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
            env.update(_PARENT_ROUTER_ENV)
            env.update(source_env(llm_client=True))

            script = textwrap.dedent(f"""\
                . '{sourced}'
                codex_version_check
            """)
            r = subprocess.run(
                ["sh", "-c", script, sourced],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            self.assertTrue(
                os.path.exists(dump_path),
                f"codex_version_check never invoked the stub `codex --version`. "
                f"stdout={r.stdout!r} stderr={r.stderr!r}",
            )
            child_env = _read_environ_dump(dump_path)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

        for var in ROUTER_SCOPED_VARS:
            self.assertNotIn(
                var, child_env,
                f"codex_version_check leaked {var} into the `codex --version` child env",
            )


class TestInvokeGenericStripsRouterEnv(_RouterEnvStripTestBase):
    """invoke_generic (:1563) -- same hazard class, any non-Claude CLI."""

    def test_strips_all_four_router_vars(self):
        child_env = self._run_and_capture_child_env(
            "some-generic-cli",
            'invoke_generic "some-generic-cli" "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5',
        )
        for var in ROUTER_SCOPED_VARS:
            self.assertNotIn(
                var, child_env,
                f"invoke_generic leaked {var} into the child env",
            )


class TestInvokeClaudeStillCarriesRouterEnv(_RouterEnvStripTestBase):
    """THE NEGATIVE HALF: invoke_claude MUST NOT get the strip treatment --
    Claude Code's CLI is the intended consumer of the router env block. An
    over-broad strip that also caught this call site would silently break
    router routing while every codex-side assertion above still passed."""

    def test_all_four_router_vars_still_present(self):
        child_env = self._run_and_capture_child_env(
            "claude",
            'invoke_claude "claude-x" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5 "markdown" "auditor"',
        )
        for var in ROUTER_SCOPED_VARS:
            self.assertIn(
                var, child_env,
                f"invoke_claude no longer carries {var} into its child env -- "
                f"an over-broad strip would silently break router routing for "
                f"the Claude path, which is the whole point of the asymmetry",
            )


if __name__ == "__main__":
    unittest.main()
