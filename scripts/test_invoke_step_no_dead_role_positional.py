"""
Regression coverage for lr-33958f (PR-C fold-in, BOBBIE PR #142 review 2,
nit 3): invoke_step (scripts/llm-client.sh) must not accept a 9th (role)
positional argument that nothing in its body reads.

ROOT CAUSE: a prior revision removed CALL_ROLE from invoke_step's BOUND
variables (see test_call_role_not_dead_parameter.py, which covers
invoke_claude's own CALL_ROLE removal) but left the doc comment claiming a
9th positional was still "accepted for backward-compatible call shape" --
an accepted-but-unread parameter is exactly the INV-3 defect class this
task names. The fix removes the 9th positional from invoke_step's
documented signature entirely; callers that still pass a trailing role
argument continue to work (POSIX sh silently ignores an extra positional no
`$N` reads), but the function no longer claims to accept something it does
not use.

This file asserts the STRUCTURAL absence: invoke_step's own positional-arg
binding line stops at $8 (CALL_MODE), and its Args: doc comment no longer
lists a ROLE/9th positional. Behavioral coverage that invoke_step still
returns the right thing regardless of a trailing role arg is
test_invoke_exit_status_sweep.py's job (unchanged, still passes a trailing
role arg on every call to prove the extra positional is harmless, not just
absent).

Run with: python3 -m unittest scripts.test_invoke_step_no_dead_role_positional -v
"""
import os
import re
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LLM_CLIENT_SH = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")


def _read():
    with open(LLM_CLIENT_SH) as f:
        return f.read()


class TestInvokeStepSignatureHasNoRolePositional(unittest.TestCase):
    def test_binding_line_stops_at_call_mode_no_9th_positional(self):
        src = _read()
        sig_line = None
        for line in src.splitlines():
            if line.strip().startswith('CLI="$1"; MODEL="$2"'):
                sig_line = line
                break
        self.assertIsNotNone(sig_line, "could not locate invoke_step's positional-arg binding line")
        # Exactly 8 positional bindings (CLI MODEL PROMPT_FILE INPUT_FILE
        # OUTPUT_FILE ERR_FILE CALL_TIMEOUT CALL_MODE), $9/${9:-} must not
        # appear anywhere on the binding line.
        self.assertNotIn(
            '"$9"', sig_line,
            f"invoke_step must not bind a 9th positional argument -- it is "
            f"never read anywhere in the function body. line={sig_line!r}",
        )
        self.assertNotRegex(
            sig_line, r'\$\{9[:\-]',
            f"invoke_step must not bind a 9th positional argument (even "
            f"with a default-value fallback form). line={sig_line!r}",
        )

    def test_doc_comment_args_line_lists_no_role_positional(self):
        src = _read()
        args_line = None
        for line in src.splitlines():
            if line.strip().startswith("# Args:") and "invoke_step" not in line and "CLI MODEL PROMPT_FILE" in line:
                args_line = line
                break
        self.assertIsNotNone(args_line, "could not locate invoke_step's '# Args:' doc comment line")
        self.assertNotIn(
            "ROLE", args_line,
            f"invoke_step's doc comment must not claim to accept a ROLE "
            f"positional it does not bind or use. line={args_line!r}",
        )


if __name__ == "__main__":
    unittest.main()
