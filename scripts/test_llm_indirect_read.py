"""
Regression coverage for lr-fe9b3d (comment #1 retarget): the shared
POSIX-safe indirect-read primitive that replaces all four surviving
eval-with-name-splice call sites in scripts/llm-client.sh
(role_env, resolve_step's MODEL resolution, the router-opt-in
*_VIA_ROUTER key, and the *_REQUIRED key).

BACKGROUND: PR #185 (lr-6d4a1f) deleted the ONE call site lr-fe9b3d's
description originally reported (CLAGENTIC_ROUTER_BEDROCK_ENSURE_VAR) but
did not sweep for the same shape elsewhere. Four more instances of
`eval "printf '%s' \"\\${<computed-name>-}\""` survived in llm-client.sh.
This task routes all four through one shared primitive, _llm_indirect_read,
rather than point-patching each differently.

_llm_indirect_read validates its VAR_NAME argument against
^[A-Za-z_][A-Za-z0-9_]*$ (the POSIX portable-variable-name grammar) before
ever splicing it into an eval string -- a metacharacter-bearing name is
refused (returns the DEFAULT, never reaches eval) rather than executed,
fail-closed per AGENTS.md invariant 3.

These tests source the ACTUAL sh function from the real llm-client.sh (the
test_source_helpers.py guard-sentinel technique every other llm-client.sh
test in this suite uses) -- a Python mirror of the validation logic would
not catch a regression in the real function body.

Run with: python3 -m unittest scripts.test_llm_indirect_read -v
"""
import os
import subprocess
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run_indirect_read(call, extra_env=None):
    """Source the real llm-client.sh and invoke `call` (a shell fragment
    that calls _llm_indirect_read and prints its result), returning
    (stdout, stderr, returncode)."""
    script = textwrap.dedent(f"""\
        . '{LLM_CLIENT_SH}'
        {call}
    """)
    env = os.environ.copy()
    env.update(source_env(llm_client=True))
    if extra_env:
        env.update(extra_env)
    r = subprocess.run(
        ["sh", "-c", script, LLM_CLIENT_SH],
        capture_output=True,
        text=True,
        cwd=TOOL_HOME,
        env=env,
    )
    return r.stdout, r.stderr, r.returncode


class TestIndirectReadNormalCases(unittest.TestCase):
    """Existing behavior at all four call sites is unchanged for
    well-formed variable names (comment #1 acceptance criterion 3)."""

    def test_resolves_set_variable(self):
        stdout, stderr, rc = _run_indirect_read(
            '_llm_indirect_read "MY_TEST_VAR" "fallback"',
            extra_env={"MY_TEST_VAR": "resolved-value"},
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "resolved-value")

    def test_falls_back_to_default_when_unset(self):
        stdout, stderr, rc = _run_indirect_read(
            'unset SOME_UNSET_VAR 2>/dev/null; _llm_indirect_read "SOME_UNSET_VAR" "fallback-default"',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "fallback-default")

    def test_falls_back_to_default_when_set_but_empty(self):
        """Mirrors the pre-existing ${VAR:-} semantics every call site
        already had (unset and set-but-empty both fall back)."""
        stdout, stderr, rc = _run_indirect_read(
            'export EMPTY_VAR=""; _llm_indirect_read "EMPTY_VAR" "fallback-default"',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "fallback-default")

    def test_no_default_yields_empty_string(self):
        stdout, stderr, rc = _run_indirect_read(
            'unset SOME_UNSET_VAR 2>/dev/null; _llm_indirect_read "SOME_UNSET_VAR"',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "")

    def test_role_env_shaped_name_resolves(self):
        """role_env's own shape: CLAGENTIC_<ROLE>_<FIELD>."""
        stdout, stderr, rc = _run_indirect_read(
            'role_env REVIEWER CMD ""',
            extra_env={"CLAGENTIC_REVIEWER_CMD": "claude"},
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "claude")

    def test_model_table_shaped_name_resolves(self):
        """resolve_step's own shape: CLAGENTIC_MODEL_<CLI>_<TIER>."""
        stdout, stderr, rc = _run_indirect_read(
            'PAIR=$(resolve_step "claude:flagship"); printf "%s" "$PAIR" | cut -f2',
            extra_env={"CLAGENTIC_MODEL_CLAUDE_FLAGSHIP": "claude-opus-test"},
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout.rstrip("\n"), "claude-opus-test")

    def test_via_router_shaped_name_resolves(self):
        stdout, stderr, rc = _run_indirect_read(
            'ROLE_U=REVIEWER; ROUTER_VIA_KEY="CLAGENTIC_$(printf "%s" "$ROLE_U" | tr "[:lower:]-" "[:upper:]_")_VIA_ROUTER"; '
            '_llm_indirect_read "$ROUTER_VIA_KEY" "0"',
            extra_env={"CLAGENTIC_REVIEWER_VIA_ROUTER": "1"},
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "1")

    def test_via_router_shaped_name_defaults_to_zero(self):
        stdout, stderr, rc = _run_indirect_read(
            'ROLE_U=REVIEWER; ROUTER_VIA_KEY="CLAGENTIC_$(printf "%s" "$ROLE_U" | tr "[:lower:]-" "[:upper:]_")_VIA_ROUTER"; '
            '_llm_indirect_read "$ROUTER_VIA_KEY" "0"',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "0")

    def test_required_shaped_name_resolves(self):
        stdout, stderr, rc = _run_indirect_read(
            'ROLE_U=REVIEWER; REQUIRED_KEY="CLAGENTIC_$(printf "%s" "$ROLE_U" | tr "[:lower:]-" "[:upper:]_")_REQUIRED"; '
            '_llm_indirect_read "$REQUIRED_KEY" "0"',
            extra_env={"CLAGENTIC_REVIEWER_REQUIRED": "1"},
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "1")


class TestIndirectReadRefusesMetacharacterNames(unittest.TestCase):
    """A metacharacter-bearing value reaching the VAR_NAME position does
    not execute (comment #1 acceptance criterion 2) -- the injection shape
    BOBBIE originally flagged: a name like `X:-$(touch pwned)` spliced
    unescaped into an eval string."""

    def _assert_refused_no_execution(self, hostile_name):
        stdout, stderr, rc = _run_indirect_read(
            f'rm -f /tmp/clagentic-test-pwned-marker; '
            f'_llm_indirect_read \'{hostile_name}\' "safe-default"; '
            f'if [ -f /tmp/clagentic-test-pwned-marker ]; then echo EXECUTED; rm -f /tmp/clagentic-test-pwned-marker; fi',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertNotIn(
            "EXECUTED", stdout,
            f"hostile VAR_NAME {hostile_name!r} caused command execution -- "
            f"the eval was reached with an unvalidated name. stdout={stdout!r}",
        )

    def test_refuses_command_substitution_dollar_paren(self):
        self._assert_refused_no_execution(
            "X:-$(touch /tmp/clagentic-test-pwned-marker)"
        )

    def test_refuses_backtick_command_substitution(self):
        self._assert_refused_no_execution(
            "X:-`touch /tmp/clagentic-test-pwned-marker`"
        )

    def test_refuses_semicolon_command_chain(self):
        self._assert_refused_no_execution(
            "X; touch /tmp/clagentic-test-pwned-marker"
        )

    def test_refuses_embedded_double_quote(self):
        self._assert_refused_no_execution(
            'X"; touch /tmp/clagentic-test-pwned-marker; echo "'
        )

    def test_refuses_whitespace(self):
        stdout, stderr, rc = _run_indirect_read(
            '_llm_indirect_read "FOO BAR" "safe-default"',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "safe-default")

    def test_refuses_leading_digit(self):
        """Not itself a metacharacter, but not a valid POSIX variable name
        either (^[A-Za-z_] requires a leading letter or underscore) --
        must still fail closed to DEFAULT, never eval a malformed name."""
        stdout, stderr, rc = _run_indirect_read(
            '_llm_indirect_read "9FOO" "safe-default"',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "safe-default")

    def test_refuses_empty_name(self):
        stdout, stderr, rc = _run_indirect_read(
            '_llm_indirect_read "" "safe-default"',
        )
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout, "safe-default")


if __name__ == "__main__":
    unittest.main()
