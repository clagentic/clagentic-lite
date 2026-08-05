"""
Sweeping regression coverage for lr-53dc6e (5.6: numeric guard).

Root cause class: every timeout/count variable sourced from an env var in
gates.sh and llm-client.sh is validated with the case-based numeric guard
idiom (`case "$VAR" in ''|*[!0-9]*) VAR=<default> ;; esac`) before being
used in an arithmetic context or passed to a command that expects a
number -- except INTERVAL (gates.sh, cmd_tail), which reached `sleep
"$INTERVAL"` completely unguarded. "Missing-guard-where-every-sibling-has-
one is itself the class" (task description).

THIS TEST IS A SOURCE-LEVEL SWEEP, not a single assertion about INTERVAL.
It finds every `sleep "$VAR"` call in gates.sh and asserts a matching
case-based numeric guard for that same VAR appears earlier in the same
function body. A future `sleep "$SOMETHING_NEW"` call added without a
guard trips this test immediately, rather than waiting to be independently
reported as a new bug.

Run with: python3 -m unittest scripts.test_numeric_guard_sweep -v
"""
import os
import re
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

_SLEEP_CALL_RE = re.compile(r'sleep\s+"\$(\w+)"')
_NUMERIC_GUARD_RE = re.compile(r"case\s+\"\$(\w+)\"\s+in\s+''\|\*\[!0-9\]\*\)")


def _find_enclosing_function_start(lines, call_idx):
    """Walk backward from call_idx to find the nearest preceding
    `name() {` line -- the function this sleep call lives in. Falls back to
    0 (top of file) if no enclosing function is found (top-level script
    body), so top-level sleep calls are still checked against guards
    anywhere earlier in the file."""
    func_re = re.compile(r'^\w+\s*\(\)\s*\{')
    for i in range(call_idx, -1, -1):
        if func_re.match(lines[i]):
            return i
    return 0


class TestEverySleepIntervalIsNumericallyGuarded(unittest.TestCase):
    """Sweep gates.sh for every `sleep "$VAR"` call and assert VAR was
    validated by the same case-based numeric guard every sibling timeout/
    count variable in this file uses, somewhere between the enclosing
    function's start and the sleep call itself."""

    def setUp(self):
        with open(GATES_SH) as f:
            self.lines = f.readlines()

    def test_sweep_finds_at_least_one_sleep_call(self):
        """Sanity check on the discovery mechanism: if this finds zero sleep
        calls, the regex is broken, not the code -- gates.sh cmd_tail is
        known to poll via sleep."""
        found = [ln for ln in self.lines if _SLEEP_CALL_RE.search(ln)]
        self.assertGreaterEqual(len(found), 1,
                                 "sweep found no `sleep \"$VAR\"` calls -- regex broken?")

    def test_every_sleep_variable_has_a_preceding_numeric_guard(self):
        violations = []
        for i, line in enumerate(self.lines):
            if line.strip().startswith('#'):
                continue  # comment (may reference `sleep "$VAR"` as prose), not live code
            m = _SLEEP_CALL_RE.search(line)
            if not m:
                continue
            var_name = m.group(1)
            func_start = _find_enclosing_function_start(self.lines, i)
            guarded = False
            for j in range(func_start, i):
                gm = _NUMERIC_GUARD_RE.search(self.lines[j])
                if gm and gm.group(1) == var_name:
                    guarded = True
                    break
            if not guarded:
                violations.append((i + 1, var_name, line.rstrip('\n')))

        self.assertEqual(
            violations, [],
            f"found {len(violations)} unguarded sleep interval(s) -- every "
            f"other timeout/count variable in this file is validated with "
            f"`case \"$VAR\" in ''|*[!0-9]*) VAR=<default> ;; esac` before "
            f"use; missing that guard here reintroduces the class:\n" +
            "\n".join(f"  gates.sh:{ln}: var={var!r}: {txt}"
                       for ln, var, txt in violations),
        )


if __name__ == "__main__":
    unittest.main()
