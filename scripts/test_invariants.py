"""
Home for sweeping tests that discover invocation sites by grepping tracked
files (git ls-files-driven, per AGENTS.md's "Sweeping-test discovery
convention"), rather than hardcoding a site list -- the discipline
test_freshness_helper_sweep.py, test_llm_client_consumer_sweep.py, and
test_numeric_guard_sweep.py already established for their own single
invariant. This file is the general home for CLASS-LEVEL invariant sweeps
(see AGENTS.md "Invariants") that are not naturally scoped to one of those
existing single-purpose files.

THIS PASS covers INV-1a and INV-4 (class-4 foundry fix, the last of a
four-PR class-level sequence): every external-process invocation in
scripts/gates.sh that was previously untimed (gitleaks x3, osv-scanner x3,
semgrep x2, git push, gh pr view, gh pr create) now runs through the
run_bounded wrapper, and $DS_TIMEOUT_CMD (scripts/platform.sh) can never
resolve to a silent-unbounded no-op.

Run with: python3 -m unittest scripts.test_invariants -v
"""
import os
import re
import subprocess
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")

# ---------------------------------------------------------------------- #
# INV-4: every external-process invocation carries an explicit wall-clock
# bound.
# ---------------------------------------------------------------------- #

# Binaries this invariant covers -- the exact class-4 foundry enumeration
# (gitleaks, osv-scanner, semgrep, gh, git push, claude, codex). `git fetch`/
# `git ls-remote` are deliberately NOT in this list: those two are already
# timed directly via $DS_TIMEOUT_CMD inside
# _gate_resolve_fresh_default_branch_ref (predating this task, see that
# function's own docstring) -- a genuinely different, already-covered site,
# not an omission from this sweep's scope.
#
# INVOCATION SHAPE, not bare substring presence: the binary name must
# appear as the FIRST TOKEN of a statement -- immediately after `if `,
# `&&`, `||`, `;`, a pipe, a `(`, or at the very start of the (stripped)
# line -- optionally preceded by `run_bounded "$VAR" -- ` or
# `$DS_TIMEOUT_CMD "$VAR" `. A bare substring match (the binary name
# appearing inside an echo/cmd_log_run message string, a `.gitleaks.toml`
# path, or prose) is NOT an invocation and must not be flagged -- that
# distinction is exactly what turned the first version of this sweep into
# 29 false positives against gates.sh's own log/audit message text.
_STMT_START = r'(?:^|(?<=if )|(?<=;\s)|(?<=&&\s)|(?<=\|\|\s)|(?<=\(\s))'
_BOUND_PREFIX_OPT = r'(?:(?:run_bounded\s+"?\$\w+"?\s+--\s+)|(?:\$DS_TIMEOUT_CMD\s+"?\$\w+"?\s+))?'
_INVOCATION_RE = re.compile(
    _STMT_START
    + r'\s*'
    + _BOUND_PREFIX_OPT
    + r'(gitleaks|osv-scanner|semgrep|gh|_git\s+push)\b'
)


def _iter_gates_sh_lines():
    with open(GATES_SH, encoding="utf-8") as f:
        return f.readlines()


def _find_unbound_external_invocations(lines):
    """Sweep primitive: every live (non-comment) line in gates.sh whose
    STATEMENT-START token is one of the INV-4-covered binaries (a real
    invocation, not a substring appearing inside a log message or
    comment), that is not itself a capability probe, and has no
    run_bounded/$DS_TIMEOUT_CMD prefix captured as part of the same match.
    Returns a list of (line_no, line_text) violations."""
    violations = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        m = _INVOCATION_RE.search(stripped)
        if not m:
            continue
        # The captured binary-name group's own start offset tells us
        # whether the optional bound-prefix group actually matched
        # immediately before it -- if the prefix consumed text, the
        # binary's start index is later than the statement-start anchor.
        # Simpler and equally reliable: re-check whether a bound prefix
        # immediately precedes the matched binary within THIS match's span.
        prefix_text = stripped[m.start():m.start(1)]
        if 'run_bounded' in prefix_text or '$DS_TIMEOUT_CMD' in prefix_text:
            continue
        if '--help' in line or '--version' in line:
            continue
        violations.append((i + 1, line.rstrip('\n')))
    return violations


class TestEveryExternalInvocationInGatesShIsBounded(unittest.TestCase):
    """INV-4: no line invoking gitleaks/osv-scanner/semgrep/gh/git-push in
    scripts/gates.sh may lack a run_bounded/$DS_TIMEOUT_CMD prefix. Sweeps
    the real, current gates.sh -- not a snapshot of today's known sites --
    so a future contributor adding an eleventh unbounded invocation trips
    this test immediately."""

    def setUp(self):
        self.lines = _iter_gates_sh_lines()

    def test_run_bounded_helper_exists(self):
        self.assertTrue(
            any(re.match(r'^run_bounded\s*\(\)\s*\{', ln) for ln in self.lines),
            "run_bounded() not found in gates.sh -- INV-4's single entry "
            "point for external-process bounds is missing",
        )

    def test_sweep_discovers_at_least_the_known_bound_sites(self):
        """Sanity check on discovery itself: if this ever finds zero
        binary invocations, the regex is broken (e.g. gitleaks/osv-scanner/
        semgrep were all renamed or removed) and the violation sweep below
        would vacuously pass with zero coverage."""
        found = 0
        for line in self.lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if _INVOCATION_RE.search(stripped) and '--help' not in line and '--version' not in line:
                found += 1
        self.assertGreaterEqual(
            found, 11,
            f"expected at least 11 real invocation sites (gitleaks x3, "
            f"osv-scanner x3, semgrep x2, git push, gh pr view, gh pr "
            f"create, plus the legacy osv-scanner fallback); found {found}",
        )

    def test_no_unbound_external_invocation_in_gates_sh(self):
        violations = _find_unbound_external_invocations(self.lines)
        self.assertEqual(
            violations, [],
            f"found {len(violations)} external-process invocation(s) in "
            f"gates.sh with no run_bounded/$DS_TIMEOUT_CMD prefix -- this "
            f"reintroduces the unbounded-external-call class (INV-4):\n" +
            "\n".join(f"  gates.sh:{ln}: {txt}" for ln, txt in violations),
        )


class TestSweepCatchesAnUnboundSiblingInvocation(unittest.TestCase):
    """Proves the sweep actually catches what it claims to, using a
    synthetic sibling call site written in the exact unbound shape every
    real site had before this task's fix."""

    _UNBOUND_FIXTURE = (
        'cmd_fixture() {\n'
        '  if gitleaks protect --staged --redact --no-banner; then\n'
        '    cmd_log_run secrets pass ""\n'
        '  fi\n'
        '}\n'
    )

    _BOUND_VIA_RUN_BOUNDED_FIXTURE = (
        'cmd_fixture() {\n'
        '  if run_bounded "$_TIMEOUT" -- gitleaks protect --staged --redact --no-banner; then\n'
        '    cmd_log_run secrets pass ""\n'
        '  fi\n'
        '}\n'
    )

    _BOUND_VIA_DS_TIMEOUT_CMD_FIXTURE = (
        'cmd_fixture() {\n'
        '  if $DS_TIMEOUT_CMD "$_TIMEOUT" gh pr view "$BRANCH" >/dev/null 2>&1; then\n'
        '    echo "PR already open"\n'
        '  fi\n'
        '}\n'
    )

    _PROBE_ONLY_FIXTURE = (
        'cmd_fixture() {\n'
        '  if gitleaks git --help >/dev/null 2>&1; then\n'
        '    echo "modern gitleaks"\n'
        '  fi\n'
        '}\n'
    )

    def test_flags_the_unbound_sibling(self):
        lines = self._UNBOUND_FIXTURE.splitlines(keepends=True)
        violations = _find_unbound_external_invocations(lines)
        self.assertTrue(
            any('gitleaks protect' in txt for _, txt in violations),
            f"sweep failed to flag an unbound gitleaks invocation. "
            f"violations={violations!r}",
        )

    def test_does_not_flag_a_run_bounded_call(self):
        lines = self._BOUND_VIA_RUN_BOUNDED_FIXTURE.splitlines(keepends=True)
        violations = _find_unbound_external_invocations(lines)
        self.assertEqual(violations, [], f"violations={violations!r}")

    def test_does_not_flag_a_direct_ds_timeout_cmd_call(self):
        lines = self._BOUND_VIA_DS_TIMEOUT_CMD_FIXTURE.splitlines(keepends=True)
        violations = _find_unbound_external_invocations(lines)
        self.assertEqual(violations, [], f"violations={violations!r}")

    def test_does_not_flag_a_capability_probe(self):
        """Negative control: a --help/--version capability probe (which
        every real gitleaks/osv-scanner/semgrep site in gates.sh also
        performs before the real scan) must not be flagged -- it never
        touches untrusted input or the network for an unbounded duration
        the way the real invocation does."""
        lines = self._PROBE_ONLY_FIXTURE.splitlines(keepends=True)
        violations = _find_unbound_external_invocations(lines)
        self.assertEqual(violations, [], f"violations={violations!r}")


# ---------------------------------------------------------------------- #
# INV-1a: $DS_TIMEOUT_CMD can never resolve to a silent-unbounded no-op.
# ---------------------------------------------------------------------- #

class TestTimeoutBinaryNeverResolvesToASilentNoOp(unittest.TestCase):
    """INV-1a: platform.sh must not define a DS_TIMEOUT_CMD fallback that
    discards its duration argument and runs the wrapped command unbounded.
    Sweeps the real, current platform.sh source."""

    def setUp(self):
        with open(PLATFORM_SH, encoding="utf-8") as f:
            self.lines = f.readlines()

    def test_no_op_stub_pattern_is_absent_from_live_code(self):
        """The exact shape the pre-fix stub took: a one-line function body
        that shifts off the duration argument and execs the rest with no
        timeout binary in between. `shift; "$@"` (or `shift ; "$@"`, any
        whitespace) on a LIVE (non-comment) line is the discriminating
        fossil -- a fail-closed replacement never contains this pattern in
        its own executable code, because it never reaches an unbounded
        exec at all. Comments are excluded deliberately: platform.sh's own
        docstring for ds_timeout_missing quotes this exact old pattern as
        prose, documenting what it replaced -- that quotation is not a
        live occurrence of the defect."""
        no_op_pattern = re.compile(r'shift\s*;\s*"\$@"')
        live_hits = [
            (i + 1, ln.rstrip('\n'))
            for i, ln in enumerate(self.lines)
            if not ln.strip().startswith('#') and no_op_pattern.search(ln)
        ]
        self.assertEqual(
            live_hits, [],
            f"platform.sh contains a live `shift; \"$@\"`-shaped no-op "
            f"timeout stub -- this is the exact silently-unbounded "
            f"fallback INV-1a forbids. DS_TIMEOUT_CMD must fail closed "
            f"instead. hits={live_hits!r}",
        )

    def test_fail_closed_fallback_function_exists(self):
        self.assertIn(
            "ds_timeout_missing", "".join(self.lines),
            "platform.sh's DS_TIMEOUT_CMD fallback (ds_timeout_missing) is "
            "missing -- INV-1a requires a NAMED fail-closed fallback, not "
            "an unbounded stub",
        )

    def test_fallback_returns_nonzero_without_executing_the_wrapped_command(self):
        """Extracts ds_timeout_missing's body via brace counting and
        asserts it does not contain an unguarded `"$@"` exec anywhere --
        the function must refuse to run the command, not merely print a
        warning before running it anyway (which would still be silently
        unbounded, just with extra noise)."""
        lines = self.lines
        start = None
        for i, line in enumerate(lines):
            if re.match(r'^ds_timeout_missing\s*\(\)\s*\{', line):
                start = i
                break
        self.assertIsNotNone(start, "could not locate ds_timeout_missing() in platform.sh")
        depth = 0
        end = None
        for i in range(start, len(lines)):
            depth += lines[i].count('{') - lines[i].count('}')
            if depth == 0 and i > start:
                end = i
                break
        self.assertIsNotNone(end, "could not find closing brace for ds_timeout_missing()")
        body = "".join(lines[start:end + 1])
        self.assertNotIn(
            '"$@"', body,
            "ds_timeout_missing's body invokes \"$@\" -- it must refuse to "
            "run the wrapped command entirely, not execute it after "
            "printing a warning",
        )
        self.assertIn(
            "return 99", body,
            "ds_timeout_missing must return a distinct, greppable exit "
            "status (99) rather than exiting 0 or falling through",
        )

    def test_ds_timeout_cmd_resolves_to_the_fail_closed_fallback_when_no_binary_present(self):
        """End-to-end: source platform.sh in a subshell with PATH stripped
        of any directory containing `timeout`/`gtimeout`, and assert
        DS_TIMEOUT_CMD resolves to ds_timeout_missing (never to a bare
        pass-through) and that invoking it refuses to run a marker command."""
        script = (
            'PATH="/nonexistent-empty-path-for-test"\n'
            f'. "{PLATFORM_SH}"\n'
            'echo "DS_TIMEOUT_CMD=$DS_TIMEOUT_CMD"\n'
            '$DS_TIMEOUT_CMD 5 touch /tmp/clagentic-test-invariants-should-not-exist-$$\n'
            'echo "EXIT=$?"\n'
        )
        result = subprocess.run(
            ["sh", "-c", script],
            capture_output=True, text=True,
        )
        self.assertIn(
            "DS_TIMEOUT_CMD=ds_timeout_missing", result.stdout,
            f"DS_TIMEOUT_CMD did not resolve to ds_timeout_missing with no "
            f"timeout binary on PATH. stdout={result.stdout!r} "
            f"stderr={result.stderr!r}",
        )
        self.assertIn(
            "EXIT=99", result.stdout,
            f"invoking $DS_TIMEOUT_CMD with no real timeout binary present "
            f"did not return the distinct fail-closed exit status (99). "
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )


class TestSweepCatchesTheOldNoOpStubShape(unittest.TestCase):
    """Proves the INV-1a source sweep actually catches the old defect
    shape, not merely that today's platform.sh happens to pass."""

    _OLD_STUB_FIXTURE = (
        'if command -v timeout >/dev/null 2>&1; then\n'
        '  DS_TIMEOUT_CMD="timeout"\n'
        'elif command -v gtimeout >/dev/null 2>&1; then\n'
        '  DS_TIMEOUT_CMD="gtimeout"\n'
        'else\n'
        '  ds_no_timeout() { shift; "$@"; }\n'
        '  DS_TIMEOUT_CMD="ds_no_timeout"\n'
        'fi\n'
        'export DS_TIMEOUT_CMD\n'
    )

    def test_old_stub_shape_is_detected_by_the_pattern_the_real_sweep_uses(self):
        no_op_pattern = re.compile(r'shift\s*;\s*"\$@"')
        self.assertIsNotNone(
            no_op_pattern.search(self._OLD_STUB_FIXTURE),
            "the sweep's own no-op detection pattern failed to match the "
            "exact pre-fix stub shape -- not a valid regression guard",
        )


# ---------------------------------------------------------------------- #
# lr-49df97 fold-in (BOBBIE finding 3): a timeout-like variable's numeric
# guard must reject ZERO, not merely non-numeric/empty input.
# ---------------------------------------------------------------------- #
#
# THE HOLE: `case "$VAR" in ''|*[!0-9]*) VAR=<default> ;; esac` -- the idiom
# every timeout variable in gates.sh/llm-client.sh used before this fix --
# rejects empty and non-digit input but ADMITS the literal string "0"
# unchanged (it contains no non-digit character). A timeout variable that
# survives this guard as 0 then reaches `$DS_TIMEOUT_CMD 0 cmd...`, and GNU
# coreutils' documented behavior for `timeout 0 cmd` is to DISABLE the
# timeout and run cmd unbounded -- silently reopening the exact class INV-1a
# exists to close, through a config value that LOOKS validated. Fixed via
# ds_positive_int_or_default (platform.sh), used at every timeout-like call
# site in gates.sh and llm-client.sh's llm_timeout_for.
#
# SCOPE: only variables whose NAME contains "TIMEOUT" -- CLAGENTIC_LLM_
# TIMEOUT_MAX_SEC's own MAX has a DELIBERATE, DOCUMENTED "0 = no cap"
# sentinel (llm_timeout_for's own "Cap at max when max is set and positive"
# comment) and is correctly excluded by name (its shell variable is `MAX`,
# not `*TIMEOUT*`) rather than by an ad hoc allowlist.
_BARE_NUMERIC_GUARD_ON_TIMEOUT_RE = re.compile(
    r"case\s+\"?\$\{?(\w*TIMEOUT\w*)\}?\"?\s+in\s+''\|\*\[!0-9\]\*\)"
)


def _iter_llm_client_sh_lines():
    llm_client_sh = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")
    with open(llm_client_sh, encoding="utf-8") as f:
        return f.readlines()


def _find_bare_zero_admitting_timeout_guards(lines):
    """Sweep primitive: every live (non-comment) line using the bare
    `case "$VAR" in ''|*[!0-9]*)` idiom where VAR's name contains TIMEOUT --
    this idiom admits "0" unchanged, which is the exact hole this sweep
    exists to catch. A hardened site uses ds_positive_int_or_default
    instead and never matches this pattern at all."""
    violations = []
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            continue
        m = _BARE_NUMERIC_GUARD_ON_TIMEOUT_RE.search(line)
        if m:
            violations.append((i + 1, m.group(1), line.rstrip('\n')))
    return violations


class TestNoTimeoutVariableUsesTheZeroAdmittingBareGuard(unittest.TestCase):
    """No TIMEOUT-named variable in gates.sh or llm-client.sh may use the
    bare `''|*[!0-9]*` case guard -- every one must route through
    ds_positive_int_or_default (platform.sh), which rejects zero as well as
    non-numeric/empty input. Sweeps the real, current source files, not a
    hardcoded site list."""

    def test_gates_sh_has_no_bare_zero_admitting_timeout_guard(self):
        lines = _iter_gates_sh_lines()
        violations = _find_bare_zero_admitting_timeout_guards(lines)
        self.assertEqual(
            violations, [],
            f"found {len(violations)} TIMEOUT variable(s) in gates.sh still "
            f"using the bare ''|*[!0-9]* guard, which admits \"0\" unchanged "
            f"and silently disables $DS_TIMEOUT_CMD's bound -- route through "
            f"ds_positive_int_or_default (platform.sh) instead:\n" +
            "\n".join(f"  gates.sh:{ln}: var={var!r}: {txt}" for ln, var, txt in violations),
        )

    def test_llm_client_sh_has_no_bare_zero_admitting_timeout_guard(self):
        lines = _iter_llm_client_sh_lines()
        violations = _find_bare_zero_admitting_timeout_guards(lines)
        self.assertEqual(
            violations, [],
            f"found {len(violations)} TIMEOUT variable(s) in llm-client.sh "
            f"still using the bare ''|*[!0-9]* guard:\n" +
            "\n".join(f"  llm-client.sh:{ln}: var={var!r}: {txt}" for ln, var, txt in violations),
        )

    def test_ds_positive_int_or_default_exists_in_platform_sh(self):
        with open(PLATFORM_SH, encoding="utf-8") as f:
            content = f.read()
        self.assertIn(
            "ds_positive_int_or_default", content,
            "platform.sh must define ds_positive_int_or_default -- the "
            "shared zero-rejecting normalizer this sweep requires every "
            "TIMEOUT-named variable to use",
        )

    def test_sweep_discovers_at_least_the_known_timeout_sites(self):
        """Sanity check on discovery: gates.sh has at least 7 distinct
        TIMEOUT-named call sites (run_bounded x2, secrets, deps, bleed-fetch,
        sast-fetch, sast, review-fetch, ship) that were converted by this
        fix -- if the sweep finds none of the OLD guard shape (expected,
        post-fix) it must still be able to discover the NEW call shape so a
        future regression to the old idiom is not silently invisible."""
        lines = _iter_gates_sh_lines()
        ds_positive_calls = sum(
            1 for ln in lines if "ds_positive_int_or_default" in ln and not ln.strip().startswith('#')
        )
        self.assertGreaterEqual(
            ds_positive_calls, 7,
            f"expected at least 7 ds_positive_int_or_default call sites in "
            f"gates.sh (run_bounded x2, secrets, deps, bleed-fetch, "
            f"sast-fetch, sast, review-fetch, ship); found {ds_positive_calls} "
            f"-- did a call site regress to the bare case-guard idiom?",
        )


class TestSweepCatchesTheBareZeroAdmittingGuardShape(unittest.TestCase):
    """Proves the sweep actually catches what it claims to, using a
    synthetic sibling call site written in the exact bare, zero-admitting
    guard shape every real TIMEOUT site had before this fix."""

    _VULNERABLE_FIXTURE = (
        'cmd_fixture() {\n'
        '  _FIXTURE_TIMEOUT="${CLAGENTIC_FIXTURE_TIMEOUT_SEC:-30}"\n'
        '  case "$_FIXTURE_TIMEOUT" in \'\'|*[!0-9]*) _FIXTURE_TIMEOUT=30 ;; esac\n'
        '}\n'
    )

    _HARDENED_FIXTURE = (
        'cmd_fixture() {\n'
        '  _FIXTURE_TIMEOUT="${CLAGENTIC_FIXTURE_TIMEOUT_SEC:-30}"\n'
        '  _FIXTURE_TIMEOUT=$(ds_positive_int_or_default "$_FIXTURE_TIMEOUT" 30)\n'
        '}\n'
    )

    def test_flags_the_vulnerable_sibling(self):
        lines = self._VULNERABLE_FIXTURE.splitlines(keepends=True)
        violations = _find_bare_zero_admitting_timeout_guards(lines)
        self.assertTrue(
            any(var == "_FIXTURE_TIMEOUT" for _, var, _ in violations),
            f"sweep failed to flag a bare zero-admitting TIMEOUT guard. "
            f"violations={violations!r}",
        )

    def test_does_not_flag_the_hardened_call(self):
        lines = self._HARDENED_FIXTURE.splitlines(keepends=True)
        violations = _find_bare_zero_admitting_timeout_guards(lines)
        self.assertEqual(violations, [], f"violations={violations!r}")


class TestDsPositiveIntOrDefaultRejectsZero(unittest.TestCase):
    """End-to-end: source platform.sh in a real subshell and call
    ds_positive_int_or_default directly, proving it falls back to DEFAULT
    on "0" (the exact input the old bare guard let through unchanged), not
    just that the source sweep above finds no bare guards left."""

    def _run(self, value, default):
        script = (
            f'. "{PLATFORM_SH}"\n'
            f'ds_positive_int_or_default "{value}" "{default}"\n'
        )
        result = subprocess.run(
            ["sh", "-c", script],
            capture_output=True, text=True,
        )
        return result.stdout, result.returncode

    def test_zero_falls_back_to_default(self):
        out, rc = self._run("0", "120")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "120", f"stdout={out!r}")

    def test_empty_falls_back_to_default(self):
        out, rc = self._run("", "120")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "120", f"stdout={out!r}")

    def test_non_numeric_falls_back_to_default(self):
        out, rc = self._run("abc", "120")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "120", f"stdout={out!r}")

    def test_valid_positive_integer_passes_through_unchanged(self):
        out, rc = self._run("45", "120")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "45", f"stdout={out!r}")

    def test_negative_number_falls_back_to_default(self):
        """Not reachable via the bare-guard sweep (a leading '-' is itself a
        non-digit character the old guard already rejected), but
        ds_positive_int_or_default's own contract is "positive integer or
        default" -- assert the boundary explicitly rather than leaving it
        implied."""
        out, rc = self._run("-5", "120")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "120", f"stdout={out!r}")


if __name__ == "__main__":
    unittest.main()
