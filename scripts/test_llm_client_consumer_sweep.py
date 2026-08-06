"""
Sweeping regression coverage for lr-7047bf (PR-B/fold-in, INV-1b): every
direct llm-client.sh invocation ANYWHERE in this repository must be BOTH
status-checked (the real exit status of the call is captured, not
discarded) AND degraded-checked (the mode-appropriate degraded marker is
inspected before the output is trusted) -- or carry an explicit,
discoverable exemption with a stated reason.

Root cause (walk_chain, scripts/llm-client.sh): invoke_claude/invoke_codex
communicate outcomes through the FILESYSTEM (a written payload) instead of
through RETURN VALUES alone. Before this task, walk_chain returned 0 even
when it emitted a degraded envelope (every chain step failed) -- so a
caller's `if EXIT_CODE -eq 0` was a fail-open by construction, and the
worst offender (cmd_adversarial) had no check of any kind: a fully-dead
auditor produced a degraded markdown envelope, and the merge gate was told
the audit was clean.

WIDENING, ROUND 1 (BOBBIE, PR #141 review #1, fold-in): the original
version of this sweep scanned gates.sh ONLY. That scope was exactly why
memory.sh's cmd_summarize_turn (scripts/memory.sh:225) was invisible to it
-- a fifth, unwired consumer of the same walk_chain outcome channel,
discovered only by BOBBIE's manual review after this task's own
enforcement mechanism shipped. The fix widened discovery to every *.sh
file under scripts/ plus every file under bin/, via glob -- an improvement,
but still a DIRECTORY LIST, and a directory list is exactly the shape of
mistake this round is closing.

WIDENING, ROUND 2 (BOBBIE + HOLDEN, PR #141 review #2, fold-in): the
scripts/-and-bin/ glob was STILL invisible to two more consumers --
.claude/hooks/stop-summarize.sh and .claude/hooks/post-tool-nudge.sh --
because .claude/ is a dotfile directory neither glob pattern walked, and
PEACHES's "no consumers exist outside these trees" assertion on the same
PR head was disproven by a single grep. Enumerating trees has now failed
THREE times running (gates.sh only -> +memory.sh -> +.claude/hooks/) with
the same shape of failure each time: the enforcement mechanism's own
discovery scope was narrower than the repository. Discovery is now driven
by `git ls-files` -- every file Git tracks in this repository, full stop --
not a hardcoded directory or extension list, so a future consumer in ANY
tracked location (a new dotfile directory, a new top-level tool, anything)
is covered automatically the day it lands, with no edit to this test file.

THIS TEST IS DELIBERATELY NOT NAMED AFTER ONE SITE, following the pattern
PR #140 established (test_invoke_exit_status_sweep.py,
test_freshness_helper_sweep.py, test_numeric_guard_sweep.py).

Run with: python3 -m unittest scripts.test_llm_client_consumer_sweep -v
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(TOOL_HOME, "scripts")
BIN_DIR = os.path.join(TOOL_HOME, "bin")

# Matches a live (non-comment) invocation of llm-client.sh with one of the
# five llm-client.sh subcommands, exactly as most consumers in this repo
# call it: "$TOOL_HOME/scripts/llm-client.sh" <role> ... -- captures the
# role name so a violation message can say which consumer is affected.
_LLM_CLIENT_CALL_RE = re.compile(
    r'llm-client\.sh"\s+(review|adversarial|merge-gate|summarize)\b'
)

# INDIRECTION (BOBBIE + HOLDEN, PR #141 review #2, fold-in): a caller may
# assign the llm-client.sh path to a variable first, then call it via that
# variable -- .claude/hooks/post-tool-nudge.sh does exactly this
# (`_summarize_cmd="$REPO_ROOT/scripts/llm-client.sh"`, then `"$_summarize_
# cmd" summarize`), the same indirection shape
# test_freshness_helper_sweep.py's TestNoRawOriginRefResolutionOutsideHelper
# already had to handle for a different sweep. _LLM_CLIENT_CALL_RE alone
# cannot see this: the literal text `llm-client.sh"` never appears on the
# call line itself. Two-pass fix: first find every `VAR=".../llm-client.sh"`
# assignment (capturing VAR), then treat `"$VAR" <role>` anywhere later in
# the same file as an additional call site using that assignment's captured
# variable name.
_LLM_CLIENT_VAR_ASSIGN_RE = re.compile(
    r'^\s*(\w+)=["\']?\S*llm-client\.sh["\']?\s*$'
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

# .py FILES ARE NEVER SCANNED FOR LIVE CALL SITES (BOBBIE + HOLDEN, PR #141
# review #2, fold-in -- discovered by the repo-wide widening itself). Every
# *.py file this repo tracks is either a unittest module or an unrelated
# example (examples/python/auth.py) -- confirmed by direct inspection of
# every `git ls-files -- '*.py'` hit at the time of this widening. A Python
# unittest module never invokes llm-client.sh as literal Python source; it
# either (a) shells out to a REAL *.sh consumer via subprocess, which this
# sweep already scans directly, or (b) embeds a shell FIXTURE as a string
# constant for a synthetic test (the existing _UNCHECKED_FIXTURE-style
# constants below), which this sweep's own dedicated fixture tests already
# exercise by calling _find_unchecked_consumers directly on that string --
# NOT by relying on file-discovery to stumble onto it. What .py files DO
# contain, routinely, is PROSE quoting the exact call shape in a docstring
# for documentation (test_merge_gate_recheck.py's `_make_fake_llm_client`
# docstring, test_memory_summarize_turn_degraded.py's module docstring) --
# indistinguishable from a live call site to a line-level regex, and a
# false positive the repo-wide widening surfaced immediately. Excluding the
# extension is more honest than trying to out-clever docstring detection:
# the repo's own convention already guarantees no .py file is a real
# consumer, so there is nothing this exclusion could hide.
#
# CLOSED, NOT MERELY ASSERTED (lr-33958f, PR-C, carried from PR-B review):
# BOBBIE's follow-up correctly named this exclusion as accurate-today but
# STRUCTURALLY INCIDENTAL -- nothing previously enforced it, so a future
# .py script shelling out to llm-client.sh with the literal path would be
# invisible. TestPyFilesShellingOutToLlmClientAreDetected (below, same
# file) is the structural enforcement: an AST-based detector that finds a
# real subprocess argv list/tuple literal (not prose/docstring text, which
# a line-level regex cannot distinguish) shelling out to llm-client.sh.
# The line-level .sh sweep above still excludes .py (that half of the
# problem -- docstring false positives on a text-level regex -- is real
# and unrelated to argv detection); the AST detector is a SEPARATE,
# narrower check that closes the actual gap without reintroducing the
# false-positive class the .sh sweep's exclusion exists to avoid.
_EXCLUDE_EXTENSIONS = {".py"}


def _iter_candidate_files():
    """Every file `git ls-files` tracks in this repository (ROUND 2
    widening, BOBBIE + HOLDEN fold-in) -- NOT a directory list. A directory
    list (first gates.sh only, then +scripts/*.sh and bin/) is the exact
    shape of mistake that hid memory.sh and then .claude/hooks/*.sh from
    two prior versions of this sweep in a row. `git ls-files` walks the
    whole tracked tree, dotfile directories (.claude/, .codex/, .crew/,
    .github/) included, so a future consumer anywhere Git tracks it is
    discovered automatically with no edit to this test file.

    Binary/non-UTF-8 tracked files (media/, *.png, etc.) are skipped by
    the caller on decode failure (see `_read_lines`), not filtered here --
    keeping the discovery step itself a single, unconditional `git
    ls-files` call is what makes "did we scan everything" a fact about one
    subprocess call, not about a maintained include/exclude list.
    """
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=TOOL_HOME,
        capture_output=True,
        text=True,
        check=True,
    )
    paths = [
        os.path.join(TOOL_HOME, rel)
        for rel in out.stdout.splitlines()
        if rel.strip()
    ]
    return [
        p for p in paths
        if os.path.basename(p) not in _SELF_EXCLUDE_BASENAMES
        and os.path.splitext(p)[1] not in _EXCLUDE_EXTENSIONS
        and os.path.isfile(p)
    ]


def _read_lines(path):
    """Read a tracked file as text, returning [] for anything that isn't
    (binary assets like media/*.png can't contain a shell invocation, and
    must not crash the sweep)."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.readlines()
    except (UnicodeDecodeError, OSError):
        return []


def _find_llm_client_indirection_vars(lines):
    """Pre-pass: every variable assigned a path ending in llm-client.sh,
    e.g. `_summarize_cmd="$REPO_ROOT/scripts/llm-client.sh"`. Returns a set
    of variable names. See _LLM_CLIENT_VAR_ASSIGN_RE's comment for why this
    exists -- a caller can invoke llm-client.sh through a variable, and
    that call line carries no literal `llm-client.sh"` text for
    _LLM_CLIENT_CALL_RE to match."""
    names = set()
    for line in lines:
        if line.strip().startswith('#'):
            continue
        m = _LLM_CLIENT_VAR_ASSIGN_RE.match(line)
        if m:
            names.add(m.group(1))
    return names


def _discover_llm_client_call_sites(lines):
    """Grep primitive: every live (non-comment) line that directly invokes
    llm-client.sh with one of its five subcommands, either literally
    (`"$TOOL_HOME/scripts/llm-client.sh" <role>`) or via a variable
    assigned that path earlier in the file (`"$VAR" <role>` where VAR was
    assigned a .../llm-client.sh path -- see _find_llm_client_indirection_
    vars). Returns a list of (line_no, role, line_text, exempt_reason_or_None).
    """
    indirection_vars = _find_llm_client_indirection_vars(lines)
    indirect_call_re = None
    if indirection_vars:
        var_alt = "|".join(re.escape(v) for v in sorted(indirection_vars))
        indirect_call_re = re.compile(
            r'\$(?:\{)?(?:' + var_alt + r')(?:\})?"?\s+(review|adversarial|merge-gate|summarize)\b'
        )
    sites = []
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            continue
        m = _LLM_CLIENT_CALL_RE.search(line)
        if not m and indirect_call_re is not None:
            m = indirect_call_re.search(line)
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
    `name() {` line. Falls back to (0, len(lines)-1) if none is found OR if
    the nearest preceding function def's body closes BEFORE reaching
    call_idx (BOBBIE + HOLDEN, PR #141 review #2, fold-in widening: a
    top-level dotfile hook script -- .claude/hooks/post-tool-nudge.sh --
    has helper functions defined near the top (_json_escape) followed by
    plain top-level statements with no enclosing function at all; the
    'nearest preceding name() {' search found _json_escape, whose body
    closes long before call_idx, silently handing back a range that does
    not even CONTAIN the call site. A range that excludes its own call
    site can never find a downstream degraded check, no matter how real
    one is -- this guard is what makes call_idx-not-in-range detectable
    instead of silently wrong)."""
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
            if call_idx <= i:
                return start, i
            break  # call_idx is past this function's own closing brace
    return 0, len(lines) - 1


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
    lines = _read_lines(path)
    return lines, _find_unchecked_consumers(lines)


class TestEveryLlmClientConsumerRepoWideIsStatusAndDegradedChecked(unittest.TestCase):
    """INV-1b, widened (BOBBIE + HOLDEN fold-in, round 2): every file this
    repository's `git ls-files` tracks -- not a directory list -- that
    directly invokes llm-client.sh with a role subcommand must capture its
    exit status AND be followed by a mode-appropriate degraded check in
    the same function, OR carry an explicit `llm-client-sweep-exempt:
    <reason>` marker. A future consumer anywhere in the tracked tree
    (including a new dotfile directory) is covered automatically -- no
    edit to this test file is required."""

    def test_sweep_discovers_at_least_the_known_consumer_roles(self):
        """Sanity check on the discovery mechanism itself: today's known
        call sites span gates.sh (review x2, adversarial, merge-gate),
        memory.sh (summarize), and .claude/hooks/stop-summarize.sh +
        .claude/hooks/post-tool-nudge.sh (both summarize). If this ever
        finds zero sites, the grep pattern itself is broken (e.g. a caller
        stopped quoting the binary path) and the sweep below would
        vacuously pass with zero coverage -- this catches that
        silently-empty-sweep failure mode."""
        total_sites = 0
        roles_found = set()
        for path in _iter_candidate_files():
            lines, _ = _sweep_file(path)
            for _, role, _, _ in _discover_llm_client_call_sites(lines):
                total_sites += 1
                roles_found.add(role)
        self.assertGreaterEqual(
            total_sites, 7,
            f"expected at least 7 llm-client.sh call sites repo-wide "
            f"(gates.sh: review x2, adversarial, merge-gate; memory.sh: "
            f"summarize; .claude/hooks/stop-summarize.sh: summarize; "
            f".claude/hooks/post-tool-nudge.sh: summarize); found {total_sites}",
        )
        for expected_role in ("review", "adversarial", "merge-gate", "summarize"):
            self.assertIn(
                expected_role, roles_found,
                f"sweep failed to discover a '{expected_role}' consumer "
                f"anywhere in the tracked tree",
            )

    def test_every_consumer_repo_wide_is_status_and_degraded_checked(self):
        all_violations = []
        for path in _iter_candidate_files():
            lines, violations = _sweep_file(path)
            rel = os.path.relpath(path, TOOL_HOME)
            all_violations.extend((rel, ln, role, reason) for ln, role, reason in violations)
        self.assertEqual(
            all_violations, [],
            f"found {len(all_violations)} llm-client.sh consumer site(s) "
            f"repo-wide that are not both status-checked and "
            f"degraded-checked, and are not explicitly exempted (INV-1b):\n" +
            "\n".join(
                f"  {rel}:{ln} (role={role}): {reason}"
                for rel, ln, role, reason in all_violations
            ),
        )

    def test_memory_sh_summarize_consumer_is_covered_by_the_widened_sweep(self):
        """Names the specific finding (BOBBIE, PR #141 review #1): scripts/
        memory.sh's cmd_summarize_turn was the unwired fifth consumer that
        the gates.sh-only sweep could not see. This test proves the
        widened sweep actually discovers and clears it, not just that the
        general assertion above happens to pass."""
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

    def test_dotfile_hook_summarize_consumers_are_covered_by_the_repo_wide_sweep(self):
        """Names the specific finding (BOBBIE + HOLDEN, PR #141 review #2):
        .claude/hooks/stop-summarize.sh and .claude/hooks/post-tool-nudge.sh
        were the sixth and seventh unwired consumers, invisible to the
        scripts/-and-bin/-only sweep specifically BECAUSE .claude/ is a
        dotfile directory neither glob pattern walked. This test proves the
        `git ls-files`-driven sweep actually discovers and clears both real
        files at their real repo paths -- not a synthetic fixture standing
        in for them -- so the round-2 widening is proven the same way the
        round-1 widening was proven for memory.sh."""
        hooks_dir = os.path.join(TOOL_HOME, ".claude", "hooks")
        for hook_name in ("stop-summarize.sh", "post-tool-nudge.sh"):
            hook_path = os.path.join(hooks_dir, hook_name)
            self.assertIn(
                hook_path, _iter_candidate_files(),
                f"repo-wide file-discovery did not pick up {hook_name!r} "
                f"under .claude/hooks/ -- the dotfile-directory gap this "
                f"round exists to close",
            )
            lines, violations = _sweep_file(hook_path)
            sites = _discover_llm_client_call_sites(lines)
            self.assertTrue(
                any(role == "summarize" for _, role, _, _ in sites),
                f"widened sweep failed to discover {hook_name}'s summarize "
                f"call site at all -- sites found: {sites!r}",
            )
            self.assertEqual(
                violations, [],
                f"{hook_name}'s summarize consumer is not fully wired: "
                f"{violations!r}",
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
        """Proves the round-1 widening itself, not just the per-line logic:
        writes the pre-fix memory.sh shape to a real *.sh file, runs it
        through the SAME file-discovery primitive the real sweep uses
        (_iter_candidate_files), and asserts it is flagged. Without this
        fixture, "the sweep now scans every tracked file" is an assertion
        about the code, not a proven behavior -- this is what BOBBIE's
        review explicitly asked for.

        Discovery is now `git ls-files`-driven (ROUND 2, BOBBIE + HOLDEN
        fold-in), which reads the real repo's tracked-file list -- an
        UNTRACKED scratch file dropped into scripts/ is invisible to it by
        design (the whole point of moving off a directory glob is that
        "on disk" is no longer sufficient; "tracked" is what's scanned).
        Writing a real untracked file and asserting `git ls-files` finds it
        would therefore be testing git's behavior, not this sweep's -- so,
        like test_repo_wide_discovery_catches_a_consumer_in_a_dotfile_
        directory below, this stubs `subprocess.run` to make
        _iter_candidate_files believe `git ls-files` reported this fixture
        path, exercising the exact same production code path
        (_iter_candidate_files -> _sweep_file) with a real file on disk."""
        with tempfile.TemporaryDirectory() as tmp_repo:
            fixture_path = os.path.join(tmp_repo, "_test_fixture_other_file_consumer.sh")
            with open(fixture_path, "w") as f:
                f.write(self._MEMORY_SH_PRE_FIX_SHAPE)
            fake_ls_files = subprocess.CompletedProcess(
                args=["git", "ls-files"], returncode=0,
                stdout=os.path.relpath(fixture_path, tmp_repo) + "\n", stderr="",
            )
            # MODULE RESOLUTION (matches test_freshness_helper_sweep.py's
            # and test_review_merge_py.py's identical fix, same PR,
            # order-dependency class): a hardcoded dotted patch target
            # ("scripts.test_llm_client_consumer_sweep.TOOL_HOME") can
            # resolve to a DIFFERENT module object than the one this
            # TestCase and _iter_candidate_files actually run in, under
            # `unittest discover` (no scripts/__init__.py in this repo, so
            # discovery imports this file as a bare top-level module while
            # the dotted patch target creates/addresses a second,
            # independent module object). Patching the wrong object's
            # TOOL_HOME is a silent no-op -- _iter_candidate_files still
            # reads the REAL module's unpatched TOOL_HOME, so this fixture
            # would fail only under discover, not under a direct `-m
            # unittest scripts.test_llm_client_consumer_sweep` run.
            # Resolving via sys.modules[self.__class__.__module__] always
            # targets the module this test is actually executing in.
            _self_mod_name = sys.modules[self.__class__.__module__].__name__
            with patch(f"{_self_mod_name}.TOOL_HOME", tmp_repo), \
                 patch("subprocess.run", return_value=fake_ls_files):
                self.assertIn(
                    fixture_path, _iter_candidate_files(),
                    "widened file-discovery did not pick up a tracked *.sh "
                    "file outside gates.sh",
                )
                lines, violations = _sweep_file(fixture_path)
                self.assertTrue(
                    any(role == "summarize" and "not captured" in reason for _, role, reason in violations),
                    f"widened sweep failed to flag the pre-fix memory.sh shape "
                    f"written to a file OTHER than gates.sh. violations={violations!r}",
                )

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

    def test_repo_wide_discovery_catches_a_consumer_in_a_dotfile_directory(self):
        """Proves the ROUND 2 widening itself (BOBBIE + HOLDEN fold-in),
        the same way test_widened_sweep_catches_a_consumer_in_a_file_other_
        than_gates_sh above proved round 1: without this fixture, "the
        sweep now scans every git-tracked file, dotfile directories
        included" is an assertion about the code, not a proven behavior --
        exactly the same trap the scripts/-and-bin/ widening fell into for
        real files at .claude/hooks/.

        Rather than mutating this repo's real git index (which `git
        ls-files` reads live and which a build step must not touch), this
        writes the pre-fix hook shape to a real file inside a SYNTHETIC
        dotfile directory (a temp tree's own `.dotdir/`) and stubs
        `subprocess.run` so `_iter_candidate_files` believes `git
        ls-files` reported that path -- exercising the exact same
        production code path (`_iter_candidate_files` -> `_sweep_file` ->
        `_discover_llm_client_call_sites` / `_find_unchecked_consumers`)
        the real sweep runs, with a dotfile directory as the discriminating
        variable, not scripts/ vs. some other ordinary directory."""
        with tempfile.TemporaryDirectory() as tmp_repo:
            dotdir = os.path.join(tmp_repo, ".dotdir", "hooks")
            os.makedirs(dotdir)
            fixture_path = os.path.join(dotdir, "consumer.sh")
            with open(fixture_path, "w") as f:
                f.write(
                    '#!/bin/sh\n'
                    'run_hook() {\n'
                    '  SUMMARY=$("$TOOL_HOME/scripts/llm-client.sh" summarize | head -c 200)\n'
                    '  [ -z "$SUMMARY" ] && exit 0\n'
                    '  echo "$SUMMARY"\n'
                    '}\n'
                )
            fake_ls_files = subprocess.CompletedProcess(
                args=["git", "ls-files"], returncode=0,
                stdout=os.path.relpath(fixture_path, tmp_repo) + "\n", stderr="",
            )
            # MODULE RESOLUTION (matches test_freshness_helper_sweep.py's
            # and test_review_merge_py.py's identical fix, same PR,
            # order-dependency class): a hardcoded dotted patch target
            # ("scripts.test_llm_client_consumer_sweep.TOOL_HOME") can
            # resolve to a DIFFERENT module object than the one this
            # TestCase and _iter_candidate_files actually run in, under
            # `unittest discover` (no scripts/__init__.py in this repo, so
            # discovery imports this file as a bare top-level module while
            # the dotted patch target creates/addresses a second,
            # independent module object). Patching the wrong object's
            # TOOL_HOME is a silent no-op -- _iter_candidate_files still
            # reads the REAL module's unpatched TOOL_HOME, so this fixture
            # would fail only under discover, not under a direct `-m
            # unittest scripts.test_llm_client_consumer_sweep` run.
            # Resolving via sys.modules[self.__class__.__module__] always
            # targets the module this test is actually executing in.
            _self_mod_name = sys.modules[self.__class__.__module__].__name__
            with patch(f"{_self_mod_name}.TOOL_HOME", tmp_repo), \
                 patch("subprocess.run", return_value=fake_ls_files):
                discovered = _iter_candidate_files()
                self.assertIn(
                    fixture_path, discovered,
                    "repo-wide file-discovery did not pick up a consumer in a "
                    "synthetic dotfile directory -- the exact gap that hid "
                    ".claude/hooks/stop-summarize.sh and "
                    ".claude/hooks/post-tool-nudge.sh from the scripts/-and-bin/ "
                    "glob this round replaces",
                )
                lines, violations = _sweep_file(fixture_path)
                self.assertTrue(
                    any(role == "summarize" and "not captured" in reason for _, role, reason in violations),
                    f"repo-wide sweep failed to flag the pre-fix hook shape "
                    f"written to a dotfile directory. violations={violations!r}",
                )



# ---------------------------------------------------------------------- #
# .py SHELL-OUT DETECTOR (lr-33958f, PR-C, carried from PR-B review):
# BOBBIE assessed the blanket .py exclusion above as ACCURATE for the
# current tree but STRUCTURALLY INCIDENTAL, not enforced -- a future
# Python script shelling out to llm-client.sh with the literal path would
# be invisible to the line-level sweep (which excludes .py entirely to
# avoid docstring false positives, see _EXCLUDE_EXTENSIONS's own comment).
#
# This closes that gap WITHOUT reopening the docstring-false-positive
# problem: instead of a line-level regex over .py source text (which
# cannot distinguish "a docstring quoting the call shape for
# documentation" from "a real subprocess argv"), this scans for the
# call as a PYTHON LIST/TUPLE LITERAL ELEMENT -- the actual argv shape a
# real subprocess.run/Popen call would use
# (["...llm-client.sh", "review", ...]) -- which a docstring's prose
# quoting the same shape does not produce (docstrings quote it as
# free-form text or as a shell command STRING, e.g. the fixture shell
# scripts embedded as triple-quoted strings elsewhere in this test suite,
# never as a bare list-literal element).
import ast


def _iter_tracked_py_files():
    """Same `git ls-files`-driven discovery as _iter_candidate_files, but
    for .py files specifically (the class that function excludes)."""
    out = subprocess.run(
        ["git", "ls-files", "--", "*.py"],
        cwd=TOOL_HOME,
        capture_output=True,
        text=True,
        check=True,
    )
    return [
        os.path.join(TOOL_HOME, rel)
        for rel in out.stdout.splitlines()
        if rel.strip()
    ]


def _find_py_argv_shellouts_to_llm_client(path):
    """Parse PATH as a Python AST and find every list/tuple literal
    containing a string element ending in 'llm-client.sh' followed
    (anywhere later in the same literal) by one of the five role
    subcommands as its own string element -- the actual argv shape
    subprocess.run(["path/to/llm-client.sh", "review", ...]) produces.
    Returns a list of (lineno, role) tuples. A syntax error or unreadable
    file yields an empty list (fail toward "nothing found" rather than
    crashing the sweep on an unrelated file the repo happens to track)."""
    try:
        with open(path, encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=path)
    except (SyntaxError, UnicodeDecodeError, OSError):
        return []

    roles = ("review", "adversarial", "merge-gate", "summarize")
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        str_elems = [
            (elt.value, elt.lineno)
            for elt in node.elts
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        ]
        has_llm_client = any(v.endswith("llm-client.sh") for v, _ in str_elems)
        if not has_llm_client:
            continue
        for value, lineno in str_elems:
            if value in roles:
                hits.append((lineno, value))
    return hits


class TestPyFilesShellingOutToLlmClientAreDetected(unittest.TestCase):
    """Closes the carried-forward PR-B review gap: a real .py subprocess
    argv shell-out to llm-client.sh IS discoverable, structurally, not
    merely assumed absent by the line-level sweep's blanket exclusion."""

    def test_no_tracked_py_file_shells_out_to_llm_client_today(self):
        """Sanity check on the CURRENT state BOBBIE's assessment described:
        confirms no tracked .py file actually does this today, so the
        blanket line-level exclusion is not silently hiding a REAL
        consumer right now. If this ever fails, the newly-discovered file
        needs the SAME status+degraded-check discipline every .sh consumer
        already has, via a Python-side check (subprocess returncode +
        stdout inspection for a 'degraded'/'cause' marker) -- not just a
        note that .py needs to be added to the .sh line-level sweep, which
        cannot express Python's own call/return idiom anyway."""
        offenders = []
        for path in _iter_tracked_py_files():
            hits = _find_py_argv_shellouts_to_llm_client(path)
            if hits:
                rel = os.path.relpath(path, TOOL_HOME)
                offenders.extend(f"{rel}:{ln} (role={role})" for ln, role in hits)
        self.assertEqual(
            offenders, [],
            f"found {len(offenders)} .py subprocess argv shell-out(s) to "
            f"llm-client.sh -- the blanket .py exclusion in the line-level "
            f"sweep above is only safe while this list is empty. Each "
            f"offender needs explicit status+degraded-check discipline "
            f"(python subprocess returncode check + stdout inspection for "
            f"the degraded marker/cause field) added at its call site:\n" +
            "\n".join(f"  {o}" for o in offenders),
        )

    def test_detector_actually_finds_a_synthetic_argv_shellout(self):
        """Proves the detector is not vacuously passing -- a REAL .py file
        on disk, containing an actual subprocess argv literal shaped
        exactly like a live consumer, must be found. Written to a real
        temp .py file (not just a string handed to the AST parser
        in-process) so this exercises the full file-read-then-parse path."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-py-shellout-")
        try:
            fixture_path = os.path.join(tmpdir, "hypothetical_consumer.py")
            with open(fixture_path, "w") as f:
                f.write(
                    "import subprocess\n"
                    "def run_it():\n"
                    "    r = subprocess.run(\n"
                    "        ['/some/path/scripts/llm-client.sh', 'review'],\n"
                    "        capture_output=True,\n"
                    "    )\n"
                    "    return r.stdout\n"
                )
            hits = _find_py_argv_shellouts_to_llm_client(fixture_path)
            self.assertTrue(
                any(role == "review" for _, role in hits),
                f"detector failed to find a synthetic argv shell-out to "
                f"llm-client.sh written to a real .py file. hits={hits!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_detector_does_not_flag_a_docstring_quoting_the_same_shape(self):
        """Negative control: a docstring quoting the exact call shape as
        PROSE (not a list literal) must not be flagged -- this is the
        false-positive class the blanket .sh-side exclusion exists to
        avoid, and the .py-specific AST detector must not reintroduce it."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-py-shellout-docstring-")
        try:
            fixture_path = os.path.join(tmpdir, "docs_only.py")
            with open(fixture_path, "w") as f:
                f.write(
                    '"""\n'
                    'This module documents the call shape:\n'
                    '  "$TOOL_HOME/scripts/llm-client.sh" review\n'
                    '"""\n'
                    "import unittest\n"
                )
            hits = _find_py_argv_shellouts_to_llm_client(fixture_path)
            self.assertEqual(
                hits, [],
                f"a docstring quoting the call shape as prose must not be "
                f"flagged -- only an actual argv list/tuple literal "
                f"element counts. hits={hits!r}",
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_detector_does_not_flag_a_shell_fixture_string_constant(self):
        """Negative control: the existing _UNCHECKED_FIXTURE-style shell
        script embedded as a triple-quoted STRING constant (this test
        file's own established pattern) must not be flagged -- it is a
        single string, not a list/tuple literal with 'llm-client.sh' and a
        role as separate elements."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-py-shellout-fixture-")
        try:
            fixture_path = os.path.join(tmpdir, "fixture_only.py")
            with open(fixture_path, "w") as f:
                f.write(
                    "FIXTURE = (\n"
                    "    'cmd_fixture() {\\n'\n"
                    "    '  \"$TOOL_HOME/scripts/llm-client.sh\" adversarial < \"$_fx_diff\" > \"$OUT\"\\n'\n"
                    "    '}\\n'\n"
                    ")\n"
                )
            hits = _find_py_argv_shellouts_to_llm_client(fixture_path)
            self.assertEqual(hits, [], f"hits={hits!r}")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
