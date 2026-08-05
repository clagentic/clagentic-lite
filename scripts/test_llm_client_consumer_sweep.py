"""
Sweeping regression coverage for lr-7047bf (PR-B, INV-1b): every direct
llm-client.sh invocation in gates.sh must be BOTH status-checked (the real
exit status of the call is captured, not discarded) AND degraded-checked
(the mode-appropriate degraded marker is inspected before the output is
trusted).

Root cause (walk_chain, scripts/llm-client.sh): invoke_claude/invoke_codex
communicate outcomes through the FILESYSTEM (a written payload) instead of
through RETURN VALUES alone. Before this task, walk_chain returned 0 even
when it emitted a degraded envelope (every chain step failed) -- so a
caller's `if EXIT_CODE -eq 0` was a fail-open by construction, and the
worst offender (cmd_adversarial) had no check of any kind: a fully-dead
auditor produced a degraded markdown envelope, and the merge gate was told
the audit was clean.

THIS TEST IS DELIBERATELY NOT NAMED AFTER ONE SITE, following the pattern
PR #140 established (test_invoke_exit_status_sweep.py,
test_freshness_helper_sweep.py, test_numeric_guard_sweep.py): discover
every live `llm-client.sh <role>` invocation in gates.sh by grep, and for
each one, assert (a) the exit status is captured on the same line (not
discarded via a bare `|| true` or left unguarded to abort the `set -e`
script), and (b) the enclosing function body contains a degraded check
downstream of the call. A future fifth consumer -- a new gate that shells
out to llm-client.sh -- is covered automatically the day it is added, with
no test-file edit required.

Run with: python3 -m unittest scripts.test_llm_client_consumer_sweep -v
"""
import os
import re
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

# Matches a live (non-comment) invocation of llm-client.sh with one of the
# five llm-client.sh subcommands, exactly as gates.sh always calls it:
# "$TOOL_HOME/scripts/llm-client.sh" <role> ... -- captures the role name so
# a violation message can say which gate is affected.
_LLM_CLIENT_CALL_RE = re.compile(
    r'llm-client\.sh"\s+(review|adversarial|merge-gate|summarize)\b'
)

# A captured exit status on the SAME line: `|| VAR=$?` (the idiom this
# codebase already uses everywhere else -- see invoke_step's own call in
# llm-client.sh walk_chain, and PR #140's test_invoke_exit_status_sweep.py
# fixture comment for the same convention). Deliberately narrow: a bare
# `|| true` does NOT match this (it discards the status, which is exactly
# the defect class site 1.5 was), and an unguarded call (no `||` at all)
# does not match it either (which would abort the whole gates.sh script
# under `set -e` on a degraded emission -- also a bug, just a louder one).
_STATUS_CAPTURE_RE = re.compile(r'\|\|\s*\w+=\$\?')

# Degraded-check call forms this codebase uses downstream of a captured
# status: the mode-complete detector (_llm_output_is_degraded), its
# json-mode back-compat wrapper (review_is_degraded), or a direct
# comparison of the captured status against walk_chain's degraded sentinel
# (3, e.g. `[ "$_adv_status" -eq 3 ]` or `[ "$_mg_status" -eq 3 ]`) --
# INV-1b requires BOTH the status channel and the mode-appropriate file
# check, and this repo's convention is to combine them with `||`, so either
# form appearing downstream counts.
_DEGRADED_CHECK_RE = re.compile(
    r'_llm_output_is_degraded\b|review_is_degraded\b|-eq 3\b'
)

_FUNC_DEF_RE = re.compile(r'^\w+\s*\(\)\s*\{')


def _discover_llm_client_call_sites(lines):
    """Grep primitive: every live (non-comment) line in gates.sh that
    directly invokes llm-client.sh with one of its five subcommands.
    Returns a list of (line_no, role, line_text)."""
    sites = []
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            continue
        m = _LLM_CLIENT_CALL_RE.search(line)
        if not m:
            continue
        sites.append((i, m.group(1), line.rstrip('\n')))
    return sites


def _find_enclosing_function_range(lines, call_idx):
    """Return (start_idx, end_idx) 0-based inclusive for the function body
    containing call_idx, via brace counting from the nearest preceding
    `name() {` line. Falls back to (0, len(lines)-1) if none is found."""
    start = None
    for i in range(call_idx, -1, -1):
        if _FUNC_DEF_RE.match(lines[i]):
            start = i
            break
    if start is None:
        return 0, len(lines) - 1
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth == 0 and i > start:
            return start, i
    return start, len(lines) - 1


def _find_unchecked_consumers(lines):
    """Sweep primitive: for every discovered llm-client.sh call site,
    check (a) the same line captures its exit status, and (b) the
    enclosing function body contains a degraded check anywhere at or after
    the call line. Returns a list of (line_no, role, reason) violations."""
    violations = []
    for i, role, text in _discover_llm_client_call_sites(lines):
        if not _STATUS_CAPTURE_RE.search(text):
            violations.append((
                i + 1, role,
                f"exit status not captured on the call line (no `|| VAR=$?`): {text!r}",
            ))
            continue  # can't meaningfully check "downstream" without a captured status
        func_start, func_end = _find_enclosing_function_range(lines, i)
        downstream = lines[i:func_end + 1]
        if not any(_DEGRADED_CHECK_RE.search(dl) for dl in downstream):
            violations.append((
                i + 1, role,
                "exit status captured but no degraded check "
                "(_llm_output_is_degraded / review_is_degraded / -eq 3) "
                "found anywhere in the enclosing function from the call site onward",
            ))
    return violations


class TestEveryLlmClientConsumerIsStatusAndDegradedChecked(unittest.TestCase):
    """INV-1b: every gates.sh line that directly invokes llm-client.sh with
    a role subcommand must capture its exit status AND be followed by a
    mode-appropriate degraded check in the same function. A future gate
    that shells out to llm-client.sh without both is covered automatically
    -- no edit to this test file is required."""

    def setUp(self):
        with open(GATES_SH) as f:
            self.lines = f.readlines()

    def test_sweep_discovers_at_least_the_known_consumer_roles(self):
        """Sanity check on the discovery mechanism itself: today's four
        call sites span three distinct roles (review, adversarial,
        merge-gate). If this ever finds zero sites, the grep pattern
        itself is broken (e.g. gates.sh stopped quoting the binary path)
        and the sweep below would vacuously pass with zero coverage --
        this catches that silently-empty-sweep failure mode."""
        sites = _discover_llm_client_call_sites(self.lines)
        self.assertGreaterEqual(
            len(sites), 4,
            f"expected at least 4 llm-client.sh call sites in gates.sh "
            f"(review x2 [chunked + single-pass], adversarial, merge-gate); "
            f"found {len(sites)}: {sites!r}",
        )
        roles_found = {role for _, role, _ in sites}
        for expected_role in ("review", "adversarial", "merge-gate"):
            self.assertIn(
                expected_role, roles_found,
                f"sweep failed to discover a '{expected_role}' consumer",
            )

    def test_every_consumer_is_status_and_degraded_checked(self):
        violations = _find_unchecked_consumers(self.lines)
        self.assertEqual(
            violations, [],
            f"found {len(violations)} llm-client.sh consumer site(s) in "
            f"gates.sh that are not both status-checked and degraded-checked "
            f"(INV-1b):\n" + "\n".join(
                f"  gates.sh:{ln} (role={role}): {reason}"
                for ln, role, reason in violations
            ),
        )


class TestSweepCatchesUncheckedAndAlternateStyleSiblings(unittest.TestCase):
    """Proves the sweep actually catches what it claims to, using synthetic
    fixtures written in the exact shapes the historical defect class took:
    the fully-unchecked site (cmd_adversarial, pre-fix) and a discarded-
    status site (the old `2>/dev/null || true` chunked-review form, site
    1.5). Each fixture is a valid-but-broken sibling that the pre-fix
    codebase actually contained; the sweep must flag both."""

    _UNCHECKED_FIXTURE = (
        'cmd_fixture() {\n'
        '  OUT="$REPO_ROOT/.clagentic/lite/last-fixture.md"\n'
        '  "$TOOL_HOME/scripts/llm-client.sh" adversarial < "$_fx_diff" > "$OUT"\n'
        '  cat "$OUT"\n'
        '}\n'
    )

    _DISCARDED_STATUS_FIXTURE = (
        'cmd_fixture() {\n'
        '  "$TOOL_HOME/scripts/llm-client.sh" review < "$_fx_chunk" > "$_fx_env" 2>/dev/null || true\n'
        '  if review_is_degraded "$_fx_env" 2>/dev/null; then\n'
        '    echo degraded\n'
        '  fi\n'
        '}\n'
    )

    _STATUS_CHECKED_BUT_NO_DEGRADED_CHECK_FIXTURE = (
        'cmd_fixture() {\n'
        '  _fx_status=0\n'
        '  "$TOOL_HOME/scripts/llm-client.sh" merge-gate < "$_fx_in" > "$_fx_out" || _fx_status=$?\n'
        '  cat "$_fx_out"\n'
        '}\n'
    )

    _FULLY_WIRED_FIXTURE = (
        'cmd_fixture() {\n'
        '  _fx_status=0\n'
        '  "$TOOL_HOME/scripts/llm-client.sh" adversarial < "$_fx_diff" > "$_fx_out" || _fx_status=$?\n'
        '  if [ "$_fx_status" -eq 3 ] || _llm_output_is_degraded markdown "$_fx_out"; then\n'
        '    echo degraded\n'
        '  fi\n'
        '}\n'
    )

    def test_flags_the_fully_unchecked_site(self):
        """Mirrors the pre-fix cmd_adversarial exactly: no `||` at all on
        the call line."""
        lines = self._UNCHECKED_FIXTURE.splitlines(keepends=True)
        violations = _find_unchecked_consumers(lines)
        self.assertTrue(
            any(role == "adversarial" and "not captured" in reason for _, role, reason in violations),
            f"sweep failed to flag the fully-unchecked fixture. violations={violations!r}",
        )

    def test_flags_the_discarded_status_site_even_though_a_degraded_check_exists(self):
        """Mirrors the pre-fix chunked-review site 1.5 exactly: a bare
        `|| true` on the call line discards the real exit status, even
        though a review_is_degraded file check runs afterward. The sweep
        must flag the missing status capture regardless of the downstream
        degraded check being present -- INV-1b requires BOTH channels, and
        `|| true` is not a status capture."""
        lines = self._DISCARDED_STATUS_FIXTURE.splitlines(keepends=True)
        violations = _find_unchecked_consumers(lines)
        self.assertTrue(
            any(role == "review" and "not captured" in reason for _, role, reason in violations),
            f"sweep failed to flag the discarded-status fixture despite its "
            f"downstream review_is_degraded call. violations={violations!r}",
        )

    def test_flags_status_checked_but_no_degraded_check(self):
        """A site that captures the exit status but never inspects it (or
        any mode-appropriate file marker) is still a violation -- capturing
        a status nobody reads is equivalent to not capturing it."""
        lines = self._STATUS_CHECKED_BUT_NO_DEGRADED_CHECK_FIXTURE.splitlines(keepends=True)
        violations = _find_unchecked_consumers(lines)
        self.assertTrue(
            any(role == "merge-gate" and "no degraded check" in reason for _, role, reason in violations),
            f"sweep failed to flag the status-captured-but-unchecked fixture. "
            f"violations={violations!r}",
        )

    def test_does_not_flag_a_fully_wired_consumer(self):
        """Negative control: a site that captures status AND checks it
        (either via the sentinel comparison or the mode-complete detector)
        must NOT be flagged -- proves the sweep does not simply reject
        every call site indiscriminately."""
        lines = self._FULLY_WIRED_FIXTURE.splitlines(keepends=True)
        violations = _find_unchecked_consumers(lines)
        self.assertEqual(
            violations, [],
            f"sweep flagged a fully-wired consumer as a violation -- false "
            f"positive. violations={violations!r}",
        )


if __name__ == "__main__":
    unittest.main()
