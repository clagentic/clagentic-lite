"""
Regression coverage for lr-33958f (PR-C, INV-3): "every parameter accepted
by a function is referenced in that function's body."

ROOT CAUSE (Class 3, accepted-but-unread channel): CALL_ROLE was the 8th
positional argument to invoke_claude, faithfully passed by invoke_step, and
NEVER REFERENCED in invoke_claude's own body -- the unwrap logic that would
have needed it lived inline, one layer below where role is actually
meaningful. validate_output (llm-client.sh) is role-aware; invoke_claude
was role-blind despite accepting the parameter.

THE FIX IS STRUCTURAL, NOT PLUMBING: role is not threaded deeper into
invoke_claude. It is removed from invoke_claude's and invoke_step's own
signatures, and the unwrap that actually needs it now lives in walk_chain
(_llm_unwrap_json_envelope), the one place role is already in scope.

This file asserts the STRUCTURAL absence (grep-verified: llm-client.sh no
longer accepts an 8th/9th positional role arg in invoke_claude/invoke_step)
alongside the STRUCTURAL presence (walk_chain calls
_llm_unwrap_json_envelope with role, and that function's body actually
branches on it) -- proving the parameter was moved, not merely deleted and
silently dropped.

Run with: python3 -m unittest scripts.test_call_role_not_dead_parameter -v
"""
import os
import re
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LLM_CLIENT_SH = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")


def _read():
    with open(LLM_CLIENT_SH) as f:
        return f.read()


def _extract_function_body(src, func_name):
    """Return the body text of `func_name() { ... }` via brace counting
    from the `func_name() {` definition line. Mirrors the brace-counting
    technique test_llm_client_consumer_sweep.py's
    _find_enclosing_function_range already uses for the same reason (POSIX
    sh has no reliable single-regex function-body extraction)."""
    m = re.search(rf'^{re.escape(func_name)}\(\)\s*\{{', src, re.MULTILINE)
    assert m, f"could not find {func_name}() definition"
    start = m.end()
    depth = 1
    i = start
    while depth > 0 and i < len(src):
        if src[i] == '{':
            depth += 1
        elif src[i] == '}':
            depth -= 1
        i += 1
    return src[start:i]


class TestInvokeClaudeNoLongerAcceptsAnUnreadRoleParameter(unittest.TestCase):
    def test_invoke_claude_signature_has_no_call_role_binding(self):
        src = _read()
        sig_line = None
        for line in src.splitlines():
            if line.strip().startswith('MODEL="$1"; PROMPT_FILE="$2"'):
                sig_line = line
                break
        self.assertIsNotNone(sig_line, "could not locate invoke_claude's positional-arg binding line")
        self.assertNotIn(
            'CALL_ROLE', sig_line,
            f"invoke_claude must no longer bind an 8th positional to "
            f"CALL_ROLE -- the parameter was removed at this layer, not "
            f"left accepted-and-unread. line={sig_line!r}",
        )

    def test_invoke_claude_body_never_references_call_role_in_code(self):
        """Comments MAY mention CALL_ROLE as prose explaining the removal
        (exactly what the comment at the old unwrap site does) -- that is
        the expected, encouraged shape (comments explain why, not what).
        What must be genuinely absent is a CODE reference: an actual use
        of the token outside a `#`-prefixed line."""
        src = _read()
        body = _extract_function_body(src, "invoke_claude")
        code_lines = [
            line for line in body.splitlines()
            if "CALL_ROLE" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(
            code_lines, [],
            f"invoke_claude's body must not reference CALL_ROLE in actual "
            f"code (comments explaining the removal are fine and expected) "
            f"-- confirms the parameter is genuinely gone from the "
            f"function's logic, not merely renamed in the binding line "
            f"while still read somewhere in the body. code_lines={code_lines!r}",
        )

    def test_invoke_step_no_longer_forwards_a_role_argument_to_invoke_claude(self):
        src = _read()
        body = _extract_function_body(src, "invoke_step")
        # The claude dispatch line inside invoke_step's case statement.
        claude_dispatch = None
        for line in body.splitlines():
            if line.strip().startswith("claude)") or "invoke_claude " in line:
                if "invoke_claude" in line:
                    claude_dispatch = line
                    break
        self.assertIsNotNone(claude_dispatch, "could not find invoke_step's claude dispatch line")
        self.assertNotIn(
            "CALL_ROLE", claude_dispatch,
            f"invoke_step must not forward a role argument to invoke_claude "
            f"any more -- role now flows from walk_chain directly into "
            f"_llm_unwrap_json_envelope, not through this dispatcher. "
            f"line={claude_dispatch!r}",
        )


class TestRoleMovedNotDropped(unittest.TestCase):
    """The other half of the fix: role did not simply vanish -- it moved to
    walk_chain, the one place it is already in scope, and the unwrap
    helper's body actually branches on it (proven behaviorally by
    test_llm_unwrap_json_envelope.py's TestRoleShapeFiltering; this class
    only proves the STRUCTURAL wiring exists, not the behavior again)."""

    def test_walk_chain_calls_the_unwrap_helper_with_role_l(self):
        src = _read()
        body = _extract_function_body(src, "walk_chain")
        self.assertIn(
            "_llm_unwrap_json_envelope", body,
            "walk_chain must call the shared unwrap helper directly.",
        )
        # Must be called with $ROLE_L (walk_chain's own role variable), not
        # a hardcoded literal or an empty string -- role must actually flow
        # through, not just have the call site present cosmetically.
        unwrap_call_line = next(
            (l for l in body.splitlines() if "_llm_unwrap_json_envelope" in l and not l.strip().startswith("#")),
            None,
        )
        self.assertIsNotNone(unwrap_call_line)
        self.assertIn(
            "ROLE_L", unwrap_call_line,
            f"the unwrap call must pass walk_chain's own $ROLE_L, not a "
            f"hardcoded/empty value. line={unwrap_call_line!r}",
        )

    def test_unwrap_helper_body_actually_branches_on_role(self):
        src = _read()
        body = _extract_function_body(src, "_llm_unwrap_json_envelope")
        self.assertIn(
            "role", body,
            "_llm_unwrap_json_envelope's body must reference its role "
            "argument (passed to the embedded python3 heredoc as sys.argv[2]).",
        )
        self.assertIn(
            '_role_shaped', body,
            "the role-shape filter predicate must exist in the unwrap "
            "helper's body -- this is the actual behavioral use of role, "
            "not just a parameter name present for show.",
        )


if __name__ == "__main__":
    unittest.main()
