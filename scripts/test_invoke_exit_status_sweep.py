"""
Sweeping regression coverage for lr-53dc6e (5.1: exit status propagation).

Root cause (invoke_claude, scripts/llm-client.sh): the function's return
status used to be whatever its LAST STATEMENT produced -- the json-mode
post-processing python3 block, which sys.exit(0)s on every path -- so
invoke_claude always returned 0 regardless of whether the underlying
`claude --print` invocation timed out (124), was killed, or otherwise
failed. invoke_codex already captured its real invocation status correctly
(_codex_exit, :1208-1244); invoke_claude did not.

THIS TEST IS DELIBERATELY NOT NAMED AFTER ONE SITE. The existing suite is
organized by incident (test_bleed_scope.py, test_merge_gate_recheck.py,
etc.) -- one test per reported bug, visiting only the site that was
reported. That shape is structurally incapable of catching a replicated
defect: invoke_codex was correct while invoke_claude, eleven lines away in
the same file, was not, and no existing test would have caught a THIRD
invoke_* carrier (e.g. a future invoke_gemini) shipping with the same
broken form invoke_claude had.

Instead: discover every invoke_* function in llm-client.sh by grep, and for
each one, stub its underlying CLI binary to exit with an INJECTED status,
then assert the function's own return status matches. A future invoke_*
carrier is covered automatically on the day it is added to llm-client.sh --
no test file needs to be touched.

Run with: python3 -m unittest scripts.test_invoke_exit_status_sweep -v
"""
import os
import re
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

# Exit codes to inject and assert propagate unchanged. 124 is the timeout
# sentinel this task's acceptance criteria calls out explicitly (the 124
# branch at the walk_chain call site becomes reachable only if invocation
# functions actually return their real status).
_INJECTED_CODES = (124, 1, 3)


def _discover_invoke_functions():
    """Grep llm-client.sh for every `invoke_NAME() {` definition.

    Returns a list of function names (e.g. ["invoke_claude", "invoke_codex",
    "invoke_generic"]). This is the sweep primitive: whatever this finds is
    exactly what the test class below iterates over, so a new invoke_*
    function added to llm-client.sh is automatically covered without any
    change to this test file.
    """
    pat = re.compile(r'^(invoke_[A-Za-z0-9_]+)\s*\(\)\s*\{')
    names = []
    with open(LLM_CLIENT_SH) as f:
        for line in f:
            m = pat.match(line)
            if m:
                names.append(m.group(1))
    assert names, "no invoke_* functions found in llm-client.sh -- grep pattern broken?"
    return names


def _write_stub_binary(bin_dir, name, exit_code):
    """Write a stub CLI binary that drains stdin, emits a harmless line on
    stdout (so downstream shape checks that peek at output do not choke),
    and exits with exit_code -- regardless of its arguments.

    codex's carrier also probes `codex --version` before the real exec
    call (codex_version_check); the stub answers that with a fixed, modern
    version string so the full-flag-set path is used and the injected exit
    code applies to the actual exec invocation, not a version-probe
    fallback path.
    """
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "{name} 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            printf 'stub output\\n'
            exit {exit_code}
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


# Maps each discovered invoke_* function name to how to call it: the stub
# CLI binary name to put on PATH, and the shell snippet to invoke it with
# arguments matching its real call signature (as seen in invoke_step,
# llm-client.sh). invoke_generic's first arg IS the CLI binary name (it is
# CLI-agnostic), so it uses a distinct stub name to prove the sweep isn't
# hardcoded to "claude"/"codex" specifically.
_INVOKE_CALL_SHAPES = {
    "invoke_claude": {
        "stub_name": "claude",
        "call": 'invoke_claude "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5 "markdown" "auditor"',
    },
    "invoke_codex": {
        "stub_name": "codex",
        "call": 'invoke_codex "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5',
    },
    "invoke_generic": {
        "stub_name": "some-generic-cli",
        "call": 'invoke_generic "some-generic-cli" "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5',
    },
    # invoke_step is the dispatcher every walk_chain call goes through (it
    # picks invoke_claude/invoke_codex/invoke_generic by CLI name and
    # returns whatever they return). It matches the invoke_* discovery
    # pattern too, so the sweep must cover it directly rather than only its
    # three carriers -- a bug in the dispatch/return plumbing itself (as
    # opposed to inside one carrier) would otherwise go uncaught.
    "invoke_step": {
        "stub_name": "some-generic-cli",
        "call": 'invoke_step "some-generic-cli" "" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5 "markdown" "auditor"',
    },
    # invoke_router (lr-02f048) speaks HTTP via curl, not a bare CLI exit
    # code -- but it propagates curl's OWN exit status verbatim on a
    # request-level failure (same contract as every other carrier here), so
    # stubbing `curl` to exit with the injected code exercises the same
    # property. python3 is also required (invoke_router builds/parses JSON
    # via python3 -c, same as this file's own real installs) -- present in
    # this test environment already (every other class in this file
    # depends on it transitively via _functions_only_source's platform.sh).
    "invoke_router": {
        "stub_name": "curl",
        "call": 'CLAGENTIC_ROUTER_URL="http://127.0.0.1:19999" CLAGENTIC_ROUTER_TOKEN="test-token" invoke_router "reviewer" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" 5',
    },
}


class TestEveryInvokeFunctionPropagatesExitStatus(unittest.TestCase):
    """For every invoke_* function discovered in llm-client.sh, stub its
    underlying CLI to exit with an injected status and assert the function
    returns that same status. Sweeps the whole invoke_* family, not one
    named site -- a future invoke_gemini (or any other new carrier) is
    covered automatically the day it is added, with no test-file edit."""

    def _run_invoke(self, func_name, injected_code):
        shape = _INVOKE_CALL_SHAPES.get(func_name)
        self.assertIsNotNone(
            shape,
            f"invoke_* function '{func_name}' was added to llm-client.sh but has no "
            f"entry in _INVOKE_CALL_SHAPES in this sweeping test -- add one so the "
            f"exit-status sweep covers it (this assertion is the trip-wire that keeps "
            f"the sweep honest: it fails loudly on a new, uncovered carrier instead of "
            f"silently skipping it).",
        )
        stub_name = shape["stub_name"]

        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-invoke-sweep-")
        try:
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            _write_stub_binary(bin_dir, stub_name, injected_code)

            sourced = LLM_CLIENT_SH

            prompt_file = os.path.join(tmpdir, "prompt.txt")
            input_file = os.path.join(tmpdir, "input.txt")
            output_file = os.path.join(tmpdir, "output.txt")
            err_file = os.path.join(tmpdir, "err.txt")
            with open(prompt_file, "w") as f:
                f.write("test prompt")
            with open(input_file, "w") as f:
                f.write("test diff")

            # Guard the call with `|| RC=$?` -- llm-client.sh runs under
            # `set -e`, and a bare failing simple command would abort the
            # sourcing shell before we can inspect its status. This mirrors
            # how walk_chain itself calls invoke_step (`|| EXIT_CODE=$?`,
            # gates.sh convention carried into llm-client.sh) rather than
            # inventing a different capture idiom for the test.
            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export PROMPT_FILE='{prompt_file}'
                export INPUT_FILE='{input_file}'
                export OUTPUT_FILE='{output_file}'
                export ERR_FILE='{err_file}'
                . '{sourced}'
                RC=0
                {shape['call']} || RC=$?
                exit "$RC"
            """)
            env = os.environ.copy()
            env.update(source_env(llm_client=True))
            r = subprocess.run(
                ["sh", "-c", script, sourced],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
            )
            return r
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_sweep_discovers_every_carrier_it_knows_how_to_call(self):
        """Sanity check on the discovery mechanism itself: every carrier this
        sweep knows how to call (_INVOKE_CALL_SHAPES, the sweep's own call-
        shape registry -- NOT a separately hardcoded name literal, so a
        rename can't silently desync the two) must actually be found by the
        grep-based discovery. This catches a change to the function
        signature convention (e.g. `invoke_claude() {` no longer matching
        the discovery pattern) rather than silently shrinking the sweep to
        zero coverage, without hardcoding names that go stale on rename."""
        found = set(_discover_invoke_functions())
        for expected in _INVOKE_CALL_SHAPES:
            self.assertIn(expected, found, f"sweep failed to discover {expected}")

    def test_every_invoke_function_propagates_injected_exit_status(self):
        for func_name in _discover_invoke_functions():
            for injected_code in _INJECTED_CODES:
                with self.subTest(func=func_name, injected_code=injected_code):
                    r = self._run_invoke(func_name, injected_code)
                    self.assertEqual(
                        r.returncode,
                        injected_code,
                        f"{func_name} did not propagate its underlying CLI's exit "
                        f"status: injected {injected_code}, function returned "
                        f"{r.returncode}. stderr={r.stderr!r}",
                    )

    def test_invoke_claude_timeout_status_specifically(self):
        """Named regression for the acceptance criterion: 'a forced timeout
        reports timeout, NOT output schema mismatch'. 124 is the shell
        convention for a `timeout`-killed child process; invoke_claude must
        surface it, not silently collapse to 0."""
        r = self._run_invoke("invoke_claude", 124)
        self.assertEqual(r.returncode, 124,
                          f"invoke_claude must propagate a forced-timeout (124) status, "
                          f"not silently succeed. stderr={r.stderr!r}")

    def test_a_renamed_carrier_fails_loudly_instead_of_silently_dropping_out(self):
        """Proves the rename-blindness the pre-fold-in hardcoded sanity
        check had: with a hardcoded literal tuple, renaming invoke_claude ->
        invoke_claude_v2 in llm-client.sh would silently DROP the renamed
        carrier from that check's coverage (the literal string
        "invoke_claude" simply stops matching a name that no longer exists;
        the assertion never fires because nothing asserts the NEW name is
        present). Here: a discovered function name absent from
        _INVOKE_CALL_SHAPES (simulating exactly that rename, since the
        registry would not yet have been updated) must trip _run_invoke's
        own assertIsNotNone trip-wire loudly, not pass silently."""
        renamed = "invoke_claude_renamed_for_test"
        self.assertNotIn(
            renamed, _INVOKE_CALL_SHAPES,
            "fixture name collides with a real registry entry -- pick another",
        )
        with self.assertRaises(AssertionError):
            self._run_invoke(renamed, 124)


if __name__ == "__main__":
    unittest.main()
