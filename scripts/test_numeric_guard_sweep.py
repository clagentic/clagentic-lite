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
It finds every `sleep $VAR`-shaped call in gates.sh -- quoted or unquoted,
braced (${VAR}) or unbraced ($VAR) -- and asserts a matching case-based
numeric guard for that same VAR appears earlier in the same function body.
A future unguarded sleep call, in ANY of those styles, trips this test
immediately, rather than waiting to be independently reported as a new bug.
See TestSweepCatchesAlternateShellStyles for proof the discovery regex
actually covers the alternate styles, not just today's exact formatting.

Run with: python3 -m unittest scripts.test_numeric_guard_sweep -v
"""
import os
import re
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

# Matches `sleep "$VAR"`, `sleep $VAR`, `sleep "${VAR}"`, and `sleep ${VAR}`
# -- quoted or unquoted, braced or unbraced, with ordinary whitespace. A
# style-fragile version of this regex (quoted+brace-less only) is itself the
# failure mode this sweep exists to catch: a sibling `sleep $INTERVAL` or
# `sleep "${INTERVAL}"` written in an equally valid but different shell style
# would otherwise be invisible to the sweep (lr-53dc6e fold-in review).
_SLEEP_CALL_RE = re.compile(r'sleep\s+"?\$\{?(\w+)\}?"?')
_NUMERIC_GUARD_RE = re.compile(r"case\s+\"?\$\{?(\w+)\}?\"?\s+in\s+''\|\*\[!0-9\]\*\)")


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


def _find_unguarded_sleep_violations(lines):
    """Shared sweep primitive: for the given source lines, find every live
    `sleep $VAR`-shaped call whose VAR has no preceding case-based numeric
    guard in the enclosing function. Returns a list of (line_no, var,
    line_text) violations. Used both against the real gates.sh (the
    regression sweep) and against synthetic fixtures (the sweep's own
    self-test -- see TestSweepCatchesAlternateShellStyles below)."""
    violations = []
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            continue  # comment (may reference sleep "$VAR" as prose), not live code
        m = _SLEEP_CALL_RE.search(line)
        if not m:
            continue
        var_name = m.group(1)
        func_start = _find_enclosing_function_start(lines, i)
        guarded = False
        for j in range(func_start, i):
            gm = _NUMERIC_GUARD_RE.search(lines[j])
            if gm and gm.group(1) == var_name:
                guarded = True
                break
        if not guarded:
            violations.append((i + 1, var_name, line.rstrip('\n')))
    return violations


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
        violations = _find_unguarded_sleep_violations(self.lines)

        self.assertEqual(
            violations, [],
            f"found {len(violations)} unguarded sleep interval(s) -- every "
            f"other timeout/count variable in this file is validated with "
            f"`case \"$VAR\" in ''|*[!0-9]*) VAR=<default> ;; esac` before "
            f"use; missing that guard here reintroduces the class:\n" +
            "\n".join(f"  gates.sh:{ln}: var={var!r}: {txt}"
                       for ln, var, txt in violations),
        )


# The pre-fold-in discovery regex (lr-53dc6e review, PEACHES/HOLDEN
# fold-in): required the sleep argument to be double-quoted and
# brace-less (`sleep "$VAR"` only). Kept here, inert, ONLY so the negative
# fixtures below can prove the CURRENT regex (_SLEEP_CALL_RE above) actually
# covers strictly more shell styles than the old one -- not as a second
# discovery mechanism used anywhere in the live sweep.
_PRE_FOLDIN_SLEEP_CALL_RE = re.compile(r'sleep\s+"\$(\w+)"')


class TestSweepCatchesAlternateShellStyles(unittest.TestCase):
    """Proves the discovery regex is robust to ordinary shell style
    variation (quoted/unquoted, braced/unbraced), not just today's exact
    formatting in gates.sh. Each fixture below is a synthetic sibling
    function, written in a valid-but-different style than cmd_tail's
    `sleep "$INTERVAL"`, with an UNGUARDED sleep variable. The pre-fold-in
    regex misses the call entirely (so the sweep would silently pass); the
    current regex must both discover the call and report it as a
    violation."""

    _FIXTURES = {
        "unquoted_unbraced": 'cmd_fixture() {\n  sleep $FOO\n}\n',
        "quoted_braced": 'cmd_fixture() {\n  sleep "${FOO}"\n}\n',
        "unquoted_braced": 'cmd_fixture() {\n  sleep ${FOO}\n}\n',
    }

    def test_pre_foldin_regex_missed_these_styles(self):
        """Guards the premise: these fixtures must be exactly the shapes the
        old regex could not see, or this test proves nothing."""
        for style, src in self._FIXTURES.items():
            with self.subTest(style=style):
                lines = src.splitlines(keepends=True)
                found = [ln for ln in lines if _PRE_FOLDIN_SLEEP_CALL_RE.search(ln)]
                self.assertEqual(
                    found, [],
                    f"fixture {style!r} was already matched by the old "
                    f"quoted+brace-less regex -- not a valid negative fixture",
                )

    def test_current_regex_discovers_and_flags_each_alternate_style(self):
        for style, src in self._FIXTURES.items():
            with self.subTest(style=style):
                lines = src.splitlines(keepends=True)
                violations = _find_unguarded_sleep_violations(lines)
                var_names = [v[1] for v in violations]
                self.assertIn(
                    "FOO", var_names,
                    f"hardened sweep failed to discover/flag the unguarded "
                    f"sleep in the {style!r} fixture -- discovery regex "
                    f"still style-fragile",
                )


if __name__ == "__main__":
    unittest.main()
