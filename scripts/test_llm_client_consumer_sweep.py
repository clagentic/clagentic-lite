"""
Sweeping regression coverage for lr-7047bf (PR-B/fold-in, INV-1b): every
direct llm-client.sh invocation ANYWHERE in this repo's scripts/ and bin/
trees must be BOTH status-checked (the real exit status of the call is
captured, not discarded) AND degraded-checked (the mode-appropriate
degraded marker is inspected before the output is trusted) -- or carry an
explicit, discoverable exemption with a stated reason.

Root cause (walk_chain, scripts/llm-client.sh): invoke_claude/invoke_codex
communicate outcomes through the FILESYSTEM (a written payload) instead of
through RETURN VALUES alone. Before this task, walk_chain returned 0 even
when it emitted a degraded envelope (every chain step failed) -- so a
caller's `if EXIT_CODE -eq 0` was a fail-open by construction, and the
worst offender (cmd_adversarial) had no check of any kind: a fully-dead
auditor produced a degraded markdown envelope, and the merge gate was told
the audit was clean.

WIDENING (BOBBIE, PR #141 review, fold-in): the original version of this
sweep scanned gates.sh ONLY. That scope was exactly why memory.sh's
cmd_summarize_turn (scripts/memory.sh:225) was invisible to it -- a fifth,
unwired consumer of the same walk_chain outcome channel, discovered only
by BOBBIE's manual review after this task's own enforcement mechanism
shipped. The enforcement mechanism replicated the defect class it was
built to prevent. This version discovers every live `llm-client.sh <role>`
invocation across every *.sh file under scripts/ and every file under
bin/ -- not a hardcoded file list -- so a future sixth consumer anywhere
in the repo is covered automatically, not just a future gates.sh site.

THIS TEST IS DELIBERATELY NOT NAMED AFTER ONE SITE, following the pattern
PR #140 established (test_invoke_exit_status_sweep.py,
test_freshness_helper_sweep.py, test_numeric_guard_sweep.py).

Run with: python3 -m unittest scripts.test_llm_client_consumer_sweep -v
"""
import glob
import os
import re
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(TOOL_HOME, "scripts")
BIN_DIR = os.path.join(TOOL_HOME, "bin")

# Matches a live (non-comment) invocation of llm-client.sh with one of the
# five llm-client.sh subcommands, exactly as every consumer in this repo
# calls it: "$TOOL_HOME/scripts/llm-client.sh" <role> ... -- captures the
# role name so a violation message can say which consumer is affected.
_LLM_CLIENT_CALL_RE = re.compile(
    r'llm-client\.sh"\s+(review|adversarial|merge-gate|summarize)\b'
)

# A captured exit status on the SAME line: `|| VAR=$?` (the idiom this
# codebase already uses everywhere else -- see invoke_step's own call in
# llm-client.sh walk_chain, and PR #140's test_invoke_exit_status_sweep.py
# fixture comment for the same convention). Deliberately narrow: a bare
# `|| true` does NOT match this (it discards the status, which is exactly
# the defect class site 1.5 was), and an unguarded call (no `||` at all)
# does not match it either (which would abort the whole enclosing script
# under `set -e` on a degraded emission -- also a bug, just a louder one).
#
# EXEMPTION escape hatch: a call line (or the line immediately before it)
# carrying the literal marker `llm-client-sweep-exempt:` is skipped
# entirely, PROVIDED a reason follows the colon (see _EXEMPT_RE below) --
# an unreasoned exemption is not accepted; this is what "explicit,
# discoverable exemption" means operationally, not a silent grep-dodge.
_STATUS_CAPTURE_RE = re.compile(r'\|\|\s*\w+=\$\?')

# Degraded-check call forms this codebase uses downstream of a captured
# status: the mode-complete detector (_llm_output_is_degraded, gates.sh),
# its json-mode back-compat wrapper (review_is_degraded, gates.sh), a
# direct comparison of the captured status against walk_chain's degraded
# sentinel (3, e.g. `[ "$_adv_status" -eq 3 ]` or `[ "$_mg_status" -eq 3 ]`
# or `[ "$_szt_status" -eq 3 ]`), or a direct text-marker grep for the
# "[clagentic-lite degraded]" line-mode banner (the form memory.sh uses,
# since it lives outside gates.sh and has no access to gates.sh's private
# detector helpers) -- INV-1b requires BOTH the status channel and the
# mode-appropriate check, and this repo's convention is to combine them
# with `||`, so any of these forms appearing downstream counts.
_DEGRADED_CHECK_RE = re.compile(
    r'_llm_output_is_degraded\b'
    r'|review_is_degraded\b'
    r'|-eq 3\b'
    r'|clagentic-lite degraded\b'
)

_FUNC_DEF_RE = re.compile(r'^\w+\s*\(\)\s*\{')

# Explicit exemption marker: `# llm-client-sweep-exempt: <reason>` on the
# call line itself or the line immediately preceding it. A reason is
# REQUIRED (non-empty text after the colon) -- `llm-client-sweep-exempt:`
# with nothing after it does not count, so an exemption cannot be used to
# silently blank out a violation without explaining why.
_EXEMPT_RE = re.compile(r'llm-client-sweep-exempt:\s*(\S.*)$')

# Files the sweep does not scan at all: this test's own fixture strings
# (which deliberately contain the call pattern as literal Python string
# data, not shell source) and llm-client.sh itself (the five subcommand
# dispatch lines in its own `case` statement and the cmd_* one-liners are
# the DEFINITION of the call, not a caller of it).
_SELF_EXCLUDE_BASENAMES = {"llm-client.sh", "test_llm_client_consumer_sweep.py"}


def _iter_candidate_files():
    """Every *.sh file under scripts/, plus every file under bin/ -- the
    two trees AMoS's own tool allowlist and this repo's own layout treat
    as 'things that can invoke llm-client.sh', per BOBBIE's fold-in
    finding 2. Not a hardcoded list: a new script dropped into either
    directory is picked up the next run with no test-file edit."""
    paths = sorted(glob.glob(os.path.join(SCRIPTS_DIR, "*.sh")))
    if os.path.isdir(BIN_DIR):
        paths += sorted(
            p for p in glob.glob(os.path.join(BIN_DIR, "*")) if os.path.isfile(p)
        )
    return [p for p in paths if os.path.basename(p) not in _SELF_EXCLUDE_BASENAMES]


def _discover_llm_client_call_sites(lines):
    """Grep primitive: every live (non-comment) line that directly invokes
    llm-client.sh with one of its five subcommands. Returns a list of
    (line_no, role, line_text, exempt_reason_or_None)."""
    sites = []
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            continue
        m = _LLM_CLIENT_CALL_RE.search(line)
        if not m:
            continue
        exempt_reason = None
        for candidate in (line, lines[i - 1] if i > 0 else ""):
            em = _EXEMPT_RE.search(candidate)
            if em:
                exempt_reason = em.group(1).strip()
                break
        sites.append((i, m.group(1), line.rstrip('\n'), exempt_reason))
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
    """Sweep primitive: for every discovered, non-exempt llm-client.sh call
    site, check (a) the same line captures its exit status, and (b) the
    enclosing function body contains a degraded check anywhere at or after
    the call line. Returns a list of (line_no, role, reason) violations.
    An explicitly exempted site (see _EXEMPT_RE) is skipped entirely and
    does not appear in the returned violations."""
    violations = []
    for i, role, text, exempt_reason in _discover_llm_client_call_sites(lines):
        if exempt_reason is not None:
            continue
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
                "(_llm_output_is_degraded / review_is_degraded / -eq 3 / "
                "'[clagentic-lite degraded]' text marker) "
                "found anywhere in the enclosing function from the call site onward",
            ))
    return violations


def _sweep_file(path):
    """Read one candidate file and return its (lines, violations)."""
    with open(path) as f:
        lines = f.readlines()
    return lines, _find_unchecked_consumers(lines)


class TestEveryLlmClientConsumerRepoWideIsStatusAndDegradedChecked(unittest.TestCase):
    """INV-1b, widened (BOBBIE fold-in): every *.sh file under scripts/ and
    every file under bin/ that directly invokes llm-client.sh with a role
    subcommand must capture its exit status AND be followed by a
    mode-appropriate degraded check in the same function, OR carry an
    explicit `llm-client-sweep-exempt: <reason>` marker. A future consumer
    in ANY file under either tree is covered automatically -- no edit to
    this test file is required."""

    def test_sweep_discovers_at_least_the_known_consumer_roles(self):
        """Sanity check on the discovery mechanism itself: today's known
        call sites span gates.sh (review x2, adversarial, merge-gate) and
        memory.sh (summarize). If this ever finds zero sites, the grep
        pattern itself is broken (e.g. a caller stopped quoting the binary
        path) and the sweep below would vacuously pass with zero coverage
        -- this catches that silently-empty-sweep failure mode."""
        total_sites = 0
        roles_found = set()
        for path in _iter_candidate_files():
            lines, _ = _sweep_file(path)
            for _, role, _, _ in _discover_llm_client_call_sites(lines):
                total_sites += 1
                roles_found.add(role)
        self.assertGreaterEqual(
            total_sites, 5,
            f"expected at least 5 llm-client.sh call sites across scripts/ "
            f"and bin/ (gates.sh: review x2, adversarial, merge-gate; "
            f"memory.sh: summarize); found {total_sites}",
        )
        for expected_role in ("review", "adversarial", "merge-gate", "summarize"):
            self.assertIn(
                expected_role, roles_found,
                f"sweep failed to discover a '{expected_role}' consumer anywhere "
                f"under scripts/ or bin/",
            )

    def test_every_consumer_repo_wide_is_status_and_degraded_checked(self):
        all_violations = []
        for path in _iter_candidate_files():
            lines, violations = _sweep_file(path)
            rel = os.path.relpath(path, TOOL_HOME)
            all_violations.extend((rel, ln, role, reason) for ln, role, reason in violations)
        self.assertEqual(
            all_violations, [],
            f"found {len(all_violations)} llm-client.sh consumer site(s) across "
            f"scripts/ and bin/ that are not both status-checked and "
            f"degraded-checked, and are not explicitly exempted (INV-1b):\n" +
            "\n".join(
                f"  {rel}:{ln} (role={role}): {reason}"
                for rel, ln, role, reason in all_violations
            ),
        )

    def test_memory_sh_summarize_consumer_is_covered_by_the_widened_sweep(self):
        """Names the specific finding (BOBBIE, PR #141): scripts/memory.sh's
        cmd_summarize_turn was the unwired fifth consumer that the
        gates.sh-only sweep could not see. This test proves the widened
        sweep actually discovers and clears it, not just that the general
        assertion above happens to pass."""
        memory_sh = os.path.join(SCRIPTS_DIR, "memory.sh")
        lines, violations = _sweep_file(memory_sh)
        sites = _discover_llm_client_call_sites(lines)
        self.assertTrue(
            any(role == "summarize" for _, role, _, _ in sites),
            f"widened sweep failed to discover memory.sh's summarize call site "
            f"at all -- sites found: {sites!r}",
        )
        self.assertEqual(
            violations, [],
            f"memory.sh's summarize consumer is not fully wired: {violations!r}",
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

    # NEGATIVE FIXTURE (required by BOBBIE's fold-in review, "prove the
    # widened sweep catches a consumer in a file OTHER than gates.sh"):
    # the exact shape memory.sh's cmd_summarize_turn had BEFORE this task's
    # fix -- a non-empty-output guard only, no status capture, no degraded
    # check at all. Written to a real temp file under scripts/ (not just a
    # Python string handed to the sweep primitive directly) so this test
    # exercises the SAME file-discovery path (_iter_candidate_files /
    # glob) the real sweep uses, not only the line-level primitive --
    # proving the widening (new files are discovered) is proven, not just
    # the per-line logic (which the fixtures above already cover).
    _MEMORY_SH_PRE_FIX_SHAPE = (
        '#!/bin/sh\n'
        'cmd_summarize_turn() {\n'
        '  SUMMARY=$("$TOOL_HOME/scripts/llm-client.sh" summarize | head -c 200)\n'
        '  [ -z "$SUMMARY" ] && { echo "empty summary, skipping" 1>&2; exit 0; }\n'
        '  cmd_log_turn "$SUMMARY"\n'
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

    def test_widened_sweep_catches_a_consumer_in_a_file_other_than_gates_sh(self):
        """Proves the widening itself, not just the per-line logic: writes
        the pre-fix memory.sh shape to a real *.sh file under scripts/,
        runs it through the SAME file-discovery primitive the real sweep
        uses (_iter_candidate_files), and asserts it is flagged. Without
        this fixture, "the sweep now scans scripts/ and bin/" is an
        assertion about the code, not a proven behavior -- this is what
        BOBBIE's review explicitly asked for."""
        fixture_path = os.path.join(SCRIPTS_DIR, "_test_fixture_other_file_consumer.sh")
        with open(fixture_path, "w") as f:
            f.write(self._MEMORY_SH_PRE_FIX_SHAPE)
        try:
            self.assertIn(
                fixture_path, _iter_candidate_files(),
                "widened file-discovery did not pick up a *.sh file under scripts/",
            )
            lines, violations = _sweep_file(fixture_path)
            self.assertTrue(
                any(role == "summarize" and "not captured" in reason for _, role, reason in violations),
                f"widened sweep failed to flag the pre-fix memory.sh shape "
                f"written to a file OTHER than gates.sh. violations={violations!r}",
            )
        finally:
            os.remove(fixture_path)

    def test_explicit_exemption_marker_suppresses_a_violation_with_a_reason(self):
        """The benign no-chain-configured summarizer skip is a real,
        deliberate exemption (see test_walk_chain_degraded_status.py
        ::test_summarizer_role_with_no_chain_still_returns_0) -- but an
        exemption must be an explicit, discoverable, REASONED marker, not
        a silent omission a future reader could mistake for an oversight.
        This proves the marker mechanism works and that a bare marker with
        no reason text does NOT suppress the violation."""
        reasoned = (
            'cmd_fixture() {\n'
            '  # llm-client-sweep-exempt: no-chain summarizer skip is a documented '
            'benign no-op, see test_walk_chain_degraded_status.py\n'
            '  "$TOOL_HOME/scripts/llm-client.sh" summarize\n'
            '}\n'
        )
        violations = _find_unchecked_consumers(reasoned.splitlines(keepends=True))
        self.assertEqual(
            violations, [],
            f"a reasoned llm-client-sweep-exempt marker did not suppress the "
            f"violation. violations={violations!r}",
        )

        unreasoned = (
            'cmd_fixture() {\n'
            '  # llm-client-sweep-exempt:\n'
            '  "$TOOL_HOME/scripts/llm-client.sh" summarize\n'
            '}\n'
        )
        violations = _find_unchecked_consumers(unreasoned.splitlines(keepends=True))
        self.assertTrue(
            any(role == "summarize" for _, role, _ in violations),
            f"an exemption marker with NO reason text must not suppress the "
            f"violation -- an exemption without a stated reason is exactly the "
            f"silent-omission failure mode this marker exists to prevent. "
            f"violations={violations!r}",
        )


if __name__ == "__main__":
    unittest.main()
