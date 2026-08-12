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
semgrep x2, git push -- the former gh pr view/gh pr create sites moved to
scripts/host-adapter.sh under lr-2b07a8's host-adapter contract, swept
separately below, still via the same run_bounded wrapper) now runs through
the run_bounded wrapper, and $DS_TIMEOUT_CMD (scripts/platform.sh) can
never resolve to a silent-unbounded no-op.

ALSO COVERS INV-5 (lr-37282a/lr-8a28e0, extended same-PR by a PEACHES
fold-in, PR #144 review comment 5207862165): every reviewer-capable
`invoke_*` carrier in scripts/llm-client.sh either consults ds_llm_role_is_
bash_unrestricted (platform.sh) to decide its own tool-restriction flags,
or is a KNOWN-exempt carrier (invoke_generic: no CLI-specific flag surface
at all; invoke_step: the dispatcher, not a carrier) -- AND walk_chain's own
per-call unrestricted-CLI warning is driven by that SAME predicate, never a
hardcoded per-role literal comparison (the shape that let "auditor" fall
silently out of warning coverage the moment it moved onto the restricted
side, since the restriction propagated via the shared predicate but the
warning's own hardcoded `ROLE_L == "reviewer"` guard did not). Discovery is
by `git ls-files`-driven regex over the tracked llm-client.sh content, not
a hardcoded function-name/role-name list -- a third `invoke_*` carrier, or
a future role moved onto the restricted side, trips this sweep the day it
happens, the same "per-CLI fix without the sweep is the instance-fixing
pattern" property INV-1b/INV-4 already establish for their own classes.

Run with: python3 -m unittest scripts.test_invariants -v
"""
import os
import re
import subprocess
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")
LLM_CLIENT_SH = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")
HOST_ADAPTER_SH = os.path.join(TOOL_HOME, "scripts", "host-adapter.sh")

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
# not an omission from this sweep's scope. `gh` invocations now live in
# scripts/host-adapter.sh (lr-2b07a8), not gates.sh -- this same regex is
# reused by the host-adapter-scoped sweep below.
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


def _iter_host_adapter_sh_lines():
    with open(HOST_ADAPTER_SH, encoding="utf-8") as f:
        return f.readlines()


# A `case` arm label of the exact shape `gh) ...` (scripts/host-adapter.sh's
# adapter-id dispatch, e.g. `gh) _host_adapter_gh_open_change_request ...`)
# matches _INVOCATION_RE's statement-start + word-boundary shape but is not
# an invocation at all -- `gh` here is a case PATTERN, not a command. This
# shape does not occur in gates.sh (no per-host case dispatch there), which
# is why the original sweep never needed this exclusion.
_CASE_ARM_LABEL_RE = re.compile(r'^\s*(?:gitleaks|osv-scanner|semgrep|gh)\)\s')


def _find_unbound_external_invocations(lines):
    """Sweep primitive: every live (non-comment) line in gates.sh whose
    STATEMENT-START token is one of the INV-4-covered binaries (a real
    invocation, not a substring appearing inside a log message, comment, or
    case-arm label), that is not itself a capability probe, and has no
    run_bounded/$DS_TIMEOUT_CMD prefix captured as part of the same match.
    Returns a list of (line_no, line_text) violations."""
    violations = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        if _CASE_ARM_LABEL_RE.match(stripped):
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
    this test immediately. (`gh pr view`/`gh pr create` moved to
    scripts/host-adapter.sh under lr-2b07a8 -- swept separately by
    TestEveryExternalInvocationInHostAdapterShIsBounded below, since that
    file, not gates.sh, is where those two sites now live.)"""

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
            found, 9,
            f"expected at least 9 real invocation sites in gates.sh "
            f"(gitleaks x3, osv-scanner x3, semgrep x2, git push, plus the "
            f"legacy osv-scanner fallback); found {found}",
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


class TestEveryExternalInvocationInHostAdapterShIsBounded(unittest.TestCase):
    """INV-4, extended to scripts/host-adapter.sh (lr-2b07a8): the `gh pr
    view`/`gh pr create`/`gh pr comment` sites that used to live in
    gates.sh now live here, still behind run_bounded -- this sweep proves
    the move didn't quietly drop the bound."""

    def setUp(self):
        self.lines = _iter_host_adapter_sh_lines()

    def test_sweep_discovers_at_least_the_known_bound_sites(self):
        found = 0
        for line in self.lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if _CASE_ARM_LABEL_RE.match(stripped):
                continue
            if _INVOCATION_RE.search(stripped) and '--help' not in line and '--version' not in line:
                found += 1
        self.assertGreaterEqual(
            found, 2,
            f"expected at least 2 real gh invocation sites in "
            f"host-adapter.sh (pr view, pr create/comment); found {found}",
        )

    def test_no_unbound_external_invocation_in_host_adapter_sh(self):
        violations = _find_unbound_external_invocations(self.lines)
        self.assertEqual(
            violations, [],
            f"found {len(violations)} external-process invocation(s) in "
            f"host-adapter.sh with no run_bounded/$DS_TIMEOUT_CMD prefix -- "
            f"this reintroduces the unbounded-external-call class (INV-4):\n" +
            "\n".join(f"  host-adapter.sh:{ln}: {txt}" for ln, txt in violations),
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


# ---------------------------------------------------------------------- #
# INV-5: every reviewer-capable invoke_* carrier consults the SAME
# Bash-restriction predicate; no carrier silently omits the check.
# ---------------------------------------------------------------------- #

# Discovers `invoke_<name>() {` function definitions at statement start in
# the tracked llm-client.sh source -- not a hardcoded list of "invoke_claude,
# invoke_codex", so a fourth carrier (e.g. invoke_gemini) is picked up the
# day someone adds it, per the class-level bar this task sets.
_INVOKE_FUNC_DEF_RE = re.compile(r'^invoke_(\w+)\(\)\s*\{')

# A carrier is considered to "apply the restriction mechanism" if its own
# function body (from its def line to the matching top-level closing brace)
# calls ds_llm_role_is_bash_unrestricted -- the single source of truth both
# invoke_claude and invoke_codex consult (platform.sh). Two KNOWN
# exemptions, each asserted explicitly below rather than silently excluded
# from the sweep:
#   generic -- invoke_generic (the invoke_<CLI> naming pattern) has no
#     CLI-specific flag surface to restrict at all: a bare `<cli> -p -`
#     pipe for an arbitrary third-party binary. Covered instead by
#     walk_chain's own per-call warning when a reviewer chain step
#     resolves to a CLI outside claude/codex.
#   step -- invoke_step (scripts/llm-client.sh) matches the same
#     `invoke_(\w+)()` discovery regex but is NOT a per-CLI carrier at
#     all -- it is the DISPATCHER that routes to invoke_claude/
#     invoke_codex/invoke_generic by CLI name (see its own case statement).
#     It has no role/tool-restriction decision of its own to make; its
#     callees are what this sweep actually verifies, one function down.
_KNOWN_UNRESTRICTABLE_CARRIERS = {"generic", "step"}


def _iter_llm_client_sh_lines_raw():
    with open(LLM_CLIENT_SH, encoding="utf-8") as f:
        return f.readlines()


def _discover_invoke_carriers(lines):
    """Returns {carrier_name: function_body_text} for every invoke_* def
    found via git-ls-files-tracked source, brace-counted to its own closing
    line (mirrors test_invariants.py's own ds_timeout_missing brace-count
    technique above, reused rather than reimplemented)."""
    carriers = {}
    i = 0
    while i < len(lines):
        m = _INVOKE_FUNC_DEF_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        start = i
        depth = 0
        end = None
        for j in range(start, len(lines)):
            depth += lines[j].count('{') - lines[j].count('}')
            if depth == 0 and j > start:
                end = j
                break
        if end is None:
            i += 1
            continue
        carriers[name] = "".join(lines[start:end + 1])
        i = end + 1
    return carriers


class TestEveryInvokeCarrierConsultsTheSharedBashRestrictionPredicate(unittest.TestCase):
    """INV-5: every invoke_* carrier in scripts/llm-client.sh must either
    call ds_llm_role_is_bash_unrestricted (the single source of truth,
    platform.sh) to decide its own tool-restriction flags, or be in the
    explicitly-enumerated KNOWN-unrestrictable set (currently just
    invoke_generic) -- a fourth carrier added later that omits BOTH is a
    silent regression to the exact "per-CLI fix without the sweep" pattern
    this task's class-level bar forbids."""

    def setUp(self):
        self.lines = _iter_llm_client_sh_lines_raw()
        self.carriers = _discover_invoke_carriers(self.lines)

    def test_sweep_discovers_at_least_the_known_carriers(self):
        """Sanity check on discovery itself: if this ever finds fewer than
        the three known carriers, the regex is broken (e.g. invoke_claude
        was renamed) and the assertion below would vacuously pass with
        incomplete coverage."""
        self.assertGreaterEqual(
            len(self.carriers), 3,
            f"expected at least invoke_claude, invoke_codex, invoke_generic; "
            f"found carriers={sorted(self.carriers)!r}",
        )
        for expected in ("claude", "codex", "generic"):
            self.assertIn(
                expected, self.carriers,
                f"expected an invoke_{expected} carrier; found "
                f"carriers={sorted(self.carriers)!r}",
            )

    def test_every_carrier_either_restricts_or_is_a_known_exemption(self):
        violations = []
        for name, body in self.carriers.items():
            if name in _KNOWN_UNRESTRICTABLE_CARRIERS:
                continue
            if "ds_llm_role_is_bash_unrestricted" not in body:
                violations.append(name)
        self.assertEqual(
            violations, [],
            f"invoke_{{{','.join(violations)}}} defines a reviewer-capable "
            f"carrier that never consults ds_llm_role_is_bash_unrestricted "
            f"(platform.sh) -- this carrier can silently ship a Bash-"
            f"unrestricted reviewer/auditor call with no restriction "
            f"mechanism and no known-exemption entry. Either wire the "
            f"predicate in (mirroring invoke_claude/invoke_codex) or add "
            f"the carrier name to _KNOWN_UNRESTRICTABLE_CARRIERS above "
            f"with a comment explaining why it is genuinely exempt.",
        )

    def test_known_unrestrictable_carriers_are_actually_unrestrictable(self):
        """The flip side of the assertion above: a carrier listed as a
        KNOWN exemption must not have quietly grown a restriction call
        without this test's own allowlist being updated to match -- proves
        the exemption list is current, not stale."""
        for name in _KNOWN_UNRESTRICTABLE_CARRIERS:
            if name not in self.carriers:
                continue
            self.assertNotIn(
                "ds_llm_role_is_bash_unrestricted", self.carriers[name],
                f"invoke_{name} is listed as a KNOWN-unrestrictable "
                f"exemption but its body now calls "
                f"ds_llm_role_is_bash_unrestricted -- update "
                f"_KNOWN_UNRESTRICTABLE_CARRIERS (remove {name!r}) so this "
                f"sweep's positive-control assertion above actually covers "
                f"it going forward.",
            )


class TestSweepCatchesASiblingCarrierMissingTheRestrictionCall(unittest.TestCase):
    """Proves the sweep actually catches what it claims to, using a
    synthetic sibling invoke_* function written in the exact
    forgot-the-predicate shape a future third-CLI carrier could ship."""

    _MISSING_PREDICATE_FIXTURE = (
        'invoke_gemini() {\n'
        '  MODEL="$1"; PROMPT_FILE="$2"\n'
        '  gemini exec "$MODEL" < "$PROMPT_FILE"\n'
        '}\n'
    )

    _WIRED_PREDICATE_FIXTURE = (
        'invoke_gemini() {\n'
        '  MODEL="$1"; PROMPT_FILE="$2"; TOOL_ROLE="${3:-}"\n'
        '  FLAGS=""\n'
        '  if ! ds_llm_role_is_bash_unrestricted "$TOOL_ROLE"; then\n'
        '    FLAGS="--no-shell"\n'
        '  fi\n'
        '  gemini exec $FLAGS "$MODEL" < "$PROMPT_FILE"\n'
        '}\n'
    )

    def test_flags_a_carrier_missing_the_predicate_call(self):
        lines = self._MISSING_PREDICATE_FIXTURE.splitlines(keepends=True)
        carriers = _discover_invoke_carriers(lines)
        self.assertIn("gemini", carriers, f"carriers={carriers!r}")
        self.assertNotIn("ds_llm_role_is_bash_unrestricted", carriers["gemini"])

    def test_does_not_flag_a_carrier_with_the_predicate_wired_in(self):
        lines = self._WIRED_PREDICATE_FIXTURE.splitlines(keepends=True)
        carriers = _discover_invoke_carriers(lines)
        self.assertIn("gemini", carriers, f"carriers={carriers!r}")
        self.assertIn("ds_llm_role_is_bash_unrestricted", carriers["gemini"])


# ---------------------------------------------------------------------- #
# INV-5 (extended), PEACHES fold-in (PR #144 review, comment 5207862165):
# the unrestricted-Bash WARNING must be driven by the SAME predicate that
# decides the RESTRICTION, so a role moved onto the restricted side is
# covered by construction, not by remembering to also touch the warning's
# own gate condition.
# ---------------------------------------------------------------------- #
#
# THE DEFECT THIS CLOSES: walk_chain's tool-restriction predicate
# (ds_llm_role_is_bash_unrestricted) decided WHICH roles get restricted
# flags, but the loud stderr warning covering the case where a chain step
# resolves to a CLI/version the restriction cannot actually reach (a
# non-claude/non-current-codex CLI) was hardcoded to `ROLE_L == "reviewer"`
# only. When lr-8a28e0 moved "auditor" onto the restricted side, the
# restriction propagated (invoke_claude/invoke_codex both consult the
# predicate) but the WARNING did not -- an auditor chain step resolving to
# an old/unversioned codex ran with genuinely unrestricted Bash and NO
# diagnostic, the exact silent-unrestricted shape lr-8a28e0 exists to
# prevent. This is a control/disclosure PAIR (PEACHES's framing): a fix
# that updates one half without the other reopens the hole for any role
# not present when the pair was first wired.
#
# THE MECHANICAL CHECK: extract walk_chain's warning-condition block from
# the tracked llm-client.sh source (anchored on the distinguishing
# "UNRESTRICTABLE-CLI" marker comment this block carries) and assert its
# GUARDING condition invokes ds_llm_role_is_bash_unrestricted -- not a
# bare `[ "$ROLE_L" = "<literal-role-name>" ]` comparison, which is
# exactly the shape that silently stopped covering auditor. A per-role
# literal comparison anywhere in the guarding condition is the instance-
# fixing pattern this sweep exists to forbid recurring.
_WALK_CHAIN_WARNING_BLOCK_START_RE = re.compile(r'UNRESTRICTABLE-CLI, FAIL-SAFE-NOT-SILENT')
# A bare positional-parameter string-equality test against a role literal,
# e.g. `[ "$ROLE_L" = "reviewer" ]` or `[ "$ROLE_L" = "auditor" ]` -- the
# exact shape of the pre-fix hardcoded gate. Deliberately does NOT flag
# `[ "$CLI" != "claude" ]` (a CLI-name comparison, not a role-name one --
# unrelated to which roles the warning covers) or a `case "$ROLE_L" in
# reviewer|auditor)` construct (walk_chain's SEPARATE role-sanity-check
# block, a few lines below the warning block this sweep targets, which
# has its own distinct purpose -- flagging an unrecognized role literal --
# and is not part of this invariant).
_ROLE_LITERAL_EQUALITY_RE = re.compile(r'\$ROLE_L"?\s*=\s*"(?:reviewer|auditor|gate|builder|summarizer)"')


def _extract_walk_chain_warning_block(lines):
    """Returns the warning-condition block's text (from its distinguishing
    anchor comment through the closing `fi` of the outer `if` it opens),
    or None if the anchor is not found -- callers must treat None as a
    sweep-discovery failure, not a vacuous pass."""
    start = None
    for i, line in enumerate(lines):
        if _WALK_CHAIN_WARNING_BLOCK_START_RE.search(line):
            start = i
            break
    if start is None:
        return None
    # Find the first `if` after the anchor comment (the guarding
    # condition itself), then brace/fi-count to its matching close. This
    # block uses `if`/`fi`, not `{`/`}` -- POSIX sh conditional, not a
    # function body -- so the counting primitive differs from
    # _discover_invoke_carriers' brace count above.
    if_start = None
    for i in range(start, len(lines)):
        if re.match(r'^\s*if\s', lines[i]):
            if_start = i
            break
    if if_start is None:
        return None
    depth = 0
    end = None
    for i in range(if_start, len(lines)):
        # Count opens/closes of if/fi pairs (nested ifs inside this block
        # are expected -- the codex-vs-other-CLI branches are themselves
        # nested `if`s).
        depth += len(re.findall(r'(?:^|\s)if\s', lines[i]))
        depth -= len(re.findall(r'(?:^|\s)fi(?:\s|$)', lines[i]))
        if depth == 0 and i > if_start:
            end = i
            break
    if end is None:
        return None
    return "".join(lines[if_start:end + 1])


class TestUnrestrictedCliWarningIsDrivenByTheSharedPredicate(unittest.TestCase):
    """PEACHES fold-in (PR #144 review): walk_chain's unrestricted-Bash
    warning must consult ds_llm_role_is_bash_unrestricted, the SAME
    predicate that gates the restriction itself -- never a hardcoded
    per-role string literal, which is exactly the shape that silently
    stopped covering auditor when lr-8a28e0 moved it onto the restricted
    side without this file's warning gate being updated to match."""

    def setUp(self):
        self.lines = _iter_llm_client_sh_lines_raw()
        self.block = _extract_walk_chain_warning_block(self.lines)

    def test_sweep_finds_the_warning_block(self):
        """Sanity check on discovery itself: if the anchor comment is
        ever removed or reworded, this test fails loudly instead of the
        assertion below vacuously passing on an empty/None block."""
        self.assertIsNotNone(
            self.block,
            "could not locate walk_chain's unrestricted-CLI warning block "
            "via its UNRESTRICTABLE-CLI anchor comment in llm-client.sh -- "
            "either the anchor was renamed (update "
            "_WALK_CHAIN_WARNING_BLOCK_START_RE to match) or the warning "
            "block itself was removed (which would silently reopen this "
            "invariant)",
        )

    def test_warning_block_consults_the_shared_predicate(self):
        self.assertIn(
            "ds_llm_role_is_bash_unrestricted", self.block or "",
            "walk_chain's unrestricted-CLI warning block does not consult "
            "ds_llm_role_is_bash_unrestricted -- if it instead hardcodes "
            "which role(s) get this warning, a future role moved onto the "
            "restricted side (the way auditor was under lr-8a28e0) will "
            "silently lose warning coverage the same way auditor did "
            "before this fix (PEACHES, PR #144 review, comment 5207862165)",
        )

    def test_warning_block_has_no_hardcoded_role_literal_guard(self):
        hits = _ROLE_LITERAL_EQUALITY_RE.findall(self.block or "")
        self.assertEqual(
            hits, [],
            f"walk_chain's unrestricted-CLI warning block contains a "
            f"hardcoded role-literal equality guard ({hits!r}) -- this is "
            f"the exact shape (`[ \"$ROLE_L\" = \"reviewer\" ]`) that let "
            f"auditor silently fall out of warning coverage when it moved "
            f"onto the restricted side; the guard must be the shared "
            f"predicate, not a per-role literal comparison",
        )


class TestSweepCatchesAHardcodedRoleLiteralWarningGuard(unittest.TestCase):
    """Proves the sweep actually catches what it claims to, using a
    synthetic sibling warning block written in the exact hardcoded-
    single-role shape the real code had before this fold-in."""

    _HARDCODED_FIXTURE = (
        '  while IFS= read -r STEP; do\n'
        '    # UNRESTRICTABLE-CLI, FAIL-SAFE-NOT-SILENT (test fixture)\n'
        '    if [ "$ROLE_L" = "reviewer" ] && [ "$CLI" != "claude" ]; then\n'
        '      printf \'WARN\\n\' 1>&2\n'
        '    fi\n'
        '  done\n'
    )

    _PREDICATE_DRIVEN_FIXTURE = (
        '  while IFS= read -r STEP; do\n'
        '    # UNRESTRICTABLE-CLI, FAIL-SAFE-NOT-SILENT (test fixture)\n'
        '    if ! ds_llm_role_is_bash_unrestricted "$ROLE_L"; then\n'
        '      if [ "$CLI" != "claude" ]; then\n'
        '        printf \'WARN\\n\' 1>&2\n'
        '      fi\n'
        '    fi\n'
        '  done\n'
    )

    def test_flags_the_hardcoded_role_literal_guard(self):
        lines = self._HARDCODED_FIXTURE.splitlines(keepends=True)
        block = _extract_walk_chain_warning_block(lines)
        self.assertIsNotNone(block, "sweep failed to locate the fixture's warning block at all")
        hits = _ROLE_LITERAL_EQUALITY_RE.findall(block)
        self.assertNotEqual(hits, [], f"sweep failed to flag the hardcoded guard; block={block!r}")
        self.assertNotIn("ds_llm_role_is_bash_unrestricted", block)

    def test_does_not_flag_the_predicate_driven_guard(self):
        lines = self._PREDICATE_DRIVEN_FIXTURE.splitlines(keepends=True)
        block = _extract_walk_chain_warning_block(lines)
        self.assertIsNotNone(block, "sweep failed to locate the fixture's warning block at all")
        hits = _ROLE_LITERAL_EQUALITY_RE.findall(block)
        self.assertEqual(hits, [], f"violations={hits!r}")
        self.assertIn("ds_llm_role_is_bash_unrestricted", block)


# ---------------------------------------------------------------------- #
# INV-6 (lr-da1f28 sweep): no `git` invocation that reads REPO-STATE (a
# staged diff, a branch name, a commit SHA, a merge-base, a ls-files/
# ls-remote/fetch result) may resolve as a BARE `git ...` call, or as a
# `git -C "$REPO_ROOT"`/`git -C "$SOME_HOME_VAR"` call NOT gated by a
# toplevel-equality scoping check first -- in scripts/gates.sh specifically.
# ---------------------------------------------------------------------- #
#
# THE DEFECT CLASS: `git -C <dir> <cmd>` only changes cwd BEFORE git's own
# repo discovery runs -- it still walks UP the filesystem from <dir> looking
# for a `.git` directory. When <dir> is not itself a git repo (the
# wrapper/.clagentic-project layout this codebase supports permits exactly
# this) but an ancestor of it is, EVERY repo-state read silently resolves
# against that unrelated ancestor repo instead -- a wrong-repo RESULT, not a
# git error, so nothing about the call itself signals the mistake. lr-4a3f88
# fixed one instance (a --recheck SHA-staleness guard); this sweep is the
# class-level closure: every site in gates.sh that reads repo state for a
# security- or correctness-relevant decision must first prove REPO_ROOT is
# the repo being consulted, via _git_repo_root_is_scoped (or the shared
# _git_repo_scoped_head_sha wrapper for the common HEAD-SHA case).
#
# WHAT THIS SWEEP DOES NOT COVER (deliberately, not an oversight): `git
# init <dir>` (creates a repo AT <dir> directly -- no discovery/walk-up
# involved, so the defect class does not apply); `_git_repo_root_is_scoped`
# and `_git_repo_scoped_head_sha`'s OWN internal `_git rev-parse
# --show-toplevel`/`_git rev-parse HEAD` calls (they ARE the scoping check
# --requiring them to be preceded by themselves is circular); the two
# `$DS_TIMEOUT_CMD`-bound `git -C "$REPO_ROOT" fetch`/`ls-remote` calls
# inside `_gate_resolve_fresh_default_branch_ref`, which cannot route through
# the `_git` shell function at all ($DS_TIMEOUT_CMD execs a literal command,
# not a function) -- that function instead gates its ENTIRE body on
# `_git_repo_root_is_scoped` up front, which this sweep verifies separately.
_GIT_REPO_STATE_SUBCOMMANDS = (
    "rev-parse", "diff", "log", "status", "merge-base",
    "ls-files", "ls-remote", "fetch", "remote", "push",
)
# Bare `git <subcommand>` (no `-C`, not `_git`) at statement start -- the
# original lr-4a3f88 defect shape. Excludes `git init` (see docstring above)
# and excludes any line already using `_git` (a shell function name that
# happens to start with `git` would NOT match this pattern since it requires
# a word-boundary `git` token followed by whitespace, not `_git`).
_BARE_GIT_REPO_STATE_RE = re.compile(
    r'(?:^|[;&|(]|\bif\s|\bthen\s)\s*git\s+(' + "|".join(_GIT_REPO_STATE_SUBCOMMANDS) + r')\b'
)
# `git -C "$SOMEVAR" <subcommand>` -- the -C-scoped-but-still-vulnerable
# shape (lr-4a3f88's OWN original site, and this sweep's highest-stakes
# find, _gate_resolve_fresh_default_branch_ref). Any occurrence outside the
# two documented, already-function-level-guarded fetch/ls-remote sites is a
# violation.
_DASH_C_GIT_REPO_STATE_RE = re.compile(
    r'git\s+-C\s+"\$\w+"\s+(' + "|".join(_GIT_REPO_STATE_SUBCOMMANDS) + r')\b'
)


def _find_gates_sh_scoping_violations(lines):
    """Sweep primitive: every live (non-comment) line in gates.sh containing
    a bare `git <repo-state-subcommand>` invocation (never using `_git` or
    an explicit `-C`), OR a `git -C "$VAR" <repo-state-subcommand>` call
    that is not one of the two documented $DS_TIMEOUT_CMD-bound sites inside
    _gate_resolve_fresh_default_branch_ref (that function gates its entire
    body on _git_repo_root_is_scoped up front -- verified by a separate
    test below, not by this line-level sweep). Returns a list of
    (line_no, line_text) violations."""
    violations = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        # `git init <dir>` is exempt -- see module-level docstring.
        if re.search(r'\bgit\s+init\b', stripped):
            continue
        if _BARE_GIT_REPO_STATE_RE.search(stripped):
            violations.append((i + 1, line.rstrip('\n')))
            continue
        m = _DASH_C_GIT_REPO_STATE_RE.search(stripped)
        if m:
            # The two documented exemptions: $DS_TIMEOUT_CMD-bound fetch/
            # ls-remote inside _gate_resolve_fresh_default_branch_ref. Both
            # carry a `$DS_TIMEOUT_CMD "$_gfdbr_timeout"` prefix on the same
            # line -- a real, mechanically-checkable marker, not a
            # line-number allowlist.
            if '$DS_TIMEOUT_CMD' in stripped and '_gfdbr_timeout' in stripped:
                continue
            violations.append((i + 1, line.rstrip('\n')))
    return violations


class TestNoBareOrUnscopedGitRepoStateCallInGatesSh(unittest.TestCase):
    """INV-6: every git invocation in scripts/gates.sh that reads repo state
    must go through `_git` (or the two documented, function-guarded
    $DS_TIMEOUT_CMD exemptions) -- never a bare `git <cmd>` or an
    unguarded `git -C "$VAR" <cmd>`. Sweeps the real, current gates.sh via
    git-ls-files-tracked content, not a hardcoded site list."""

    def setUp(self):
        self.lines = _iter_gates_sh_lines()

    def test_git_repo_root_is_scoped_helper_exists(self):
        self.assertTrue(
            any(re.match(r'^_git_repo_root_is_scoped\s*\(\)\s*\{', ln) for ln in self.lines),
            "_git_repo_root_is_scoped() not found in gates.sh -- INV-6's "
            "scoping predicate is missing",
        )

    def test_sweep_discovers_at_least_the_known_git_call_sites(self):
        """Sanity check on discovery itself: if this ever finds fewer real
        `_git`/`git -C` repo-state calls than expected, the regex is broken
        (e.g. a subcommand list drifted) and the violation sweep below
        would vacuously pass with incomplete coverage."""
        found = 0
        for line in self.lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if re.search(r'_git\s+(' + "|".join(_GIT_REPO_STATE_SUBCOMMANDS) + r')\b', stripped):
                found += 1
        self.assertGreaterEqual(
            found, 20,
            f"expected at least 20 `_git <repo-state-subcommand>` call "
            f"sites in gates.sh; found {found} -- did the subcommand list "
            f"or discovery regex regress?",
        )

    def test_no_bare_or_unscoped_git_call_in_gates_sh(self):
        violations = _find_gates_sh_scoping_violations(self.lines)
        self.assertEqual(
            violations, [],
            f"found {len(violations)} bare or unscoped git repo-state "
            f"call(s) in gates.sh -- this reintroduces the ancestor-repo "
            f"walk-up class (INV-6, lr-da1f28 sweep): a bare `git <cmd>` or "
            f"an ungated `git -C \"$VAR\" <cmd>` can silently resolve "
            f"against an unrelated ancestor repo instead of REPO_ROOT. "
            f"Route through `_git` (function-guarded call sites) or gate "
            f"explicitly on _git_repo_root_is_scoped first:\n" +
            "\n".join(f"  gates.sh:{ln}: {txt}" for ln, txt in violations),
        )

    def test_gate_resolve_fresh_default_branch_ref_gates_on_scoping_predicate(self):
        """The two documented $DS_TIMEOUT_CMD-bound exemptions are only
        safe because _gate_resolve_fresh_default_branch_ref gates its ENTIRE
        body on _git_repo_root_is_scoped before either runs -- assert that
        guard is actually present in the function, not just documented in
        a comment a future edit could silently drop."""
        content = "".join(self.lines)
        m = re.search(
            r'_gate_resolve_fresh_default_branch_ref\(\)\s*\{(.*?)\n\}',
            content, re.DOTALL,
        )
        self.assertIsNotNone(
            m, "could not locate _gate_resolve_fresh_default_branch_ref() body in gates.sh",
        )
        self.assertIn(
            "_git_repo_root_is_scoped", m.group(1),
            "_gate_resolve_fresh_default_branch_ref no longer gates on "
            "_git_repo_root_is_scoped -- this is the highest-stakes site "
            "in the lr-da1f28 sweep (feeds cmd_sast's semgrep "
            "--baseline-commit and cmd_bleed's branch-diff scope); losing "
            "this guard silently narrows a blocking security gate's scan "
            "window against a wrong-repo baseline instead of erroring",
        )


class TestSweepCatchesABareGitSiblingCallInGatesSh(unittest.TestCase):
    """Proves the sweep actually catches what it claims to, using
    synthetic sibling fixtures in the exact bare-git and unscoped-`-C`
    shapes the real pre-fix sites had (lr-da1f28 sweep, and the earlier
    lr-4a3f88 site this generalizes)."""

    _BARE_GIT_FIXTURE = (
        'cmd_fixture() {\n'
        '  FIXTURE_SHA=$(git rev-parse HEAD 2>/dev/null || echo "")\n'
        '}\n'
    )

    _UNGATED_DASH_C_FIXTURE = (
        'cmd_fixture() {\n'
        '  FIXTURE_TIP=$(git -C "$REPO_ROOT" ls-remote origin refs/heads/main 2>/dev/null)\n'
        '}\n'
    )

    _PROPERLY_SCOPED_VIA_GIT_FUNC_FIXTURE = (
        'cmd_fixture() {\n'
        '  FIXTURE_SHA=$(_git rev-parse HEAD 2>/dev/null || echo "")\n'
        '}\n'
    )

    _GIT_INIT_FIXTURE = (
        'cmd_fixture() {\n'
        '  git init "$_ep" || return 1\n'
        '}\n'
    )

    def test_flags_a_bare_git_repo_state_call(self):
        lines = self._BARE_GIT_FIXTURE.splitlines(keepends=True)
        violations = _find_gates_sh_scoping_violations(lines)
        self.assertTrue(
            any('git rev-parse HEAD' in txt for _, txt in violations),
            f"sweep failed to flag a bare `git rev-parse` call. "
            f"violations={violations!r}",
        )

    def test_flags_an_ungated_dash_c_call(self):
        lines = self._UNGATED_DASH_C_FIXTURE.splitlines(keepends=True)
        violations = _find_gates_sh_scoping_violations(lines)
        self.assertTrue(
            any('ls-remote' in txt for _, txt in violations),
            f"sweep failed to flag an ungated `git -C` ls-remote call. "
            f"violations={violations!r}",
        )

    def test_does_not_flag_a_call_through_the_git_function(self):
        lines = self._PROPERLY_SCOPED_VIA_GIT_FUNC_FIXTURE.splitlines(keepends=True)
        violations = _find_gates_sh_scoping_violations(lines)
        self.assertEqual(violations, [], f"violations={violations!r}")

    def test_does_not_flag_git_init(self):
        lines = self._GIT_INIT_FIXTURE.splitlines(keepends=True)
        violations = _find_gates_sh_scoping_violations(lines)
        self.assertEqual(violations, [], f"violations={violations!r}")


# ---------------------------------------------------------------------- #
# INV-7: no tracked, live Claude Code hook script under .claude/ (lr-57db23)
# ---------------------------------------------------------------------- #

# The exact six hook script basenames this repo ships. Kept in one place so
# a future addition to CLAGENTIC_HOOK_SCRIPTS (bin/clagentic-lite) needs a
# matching update here -- the mechanical failure mode this sweep exists to
# avoid is a NEW hook script landing back under a tracked .claude/hooks/
# without this check ever running against it.
_TRACKED_HOOK_SCRIPT_BASENAMES = (
    "session-start.sh",
    "prompt-inject.sh",
    "pre-bash-guard.sh",
    "pre-write-guard.sh",
    "post-tool-nudge.sh",
    "stop-summarize.sh",
)


def _git_ls_files_claude_dir():
    """git ls-files under .claude/ -- the tracked-file source of truth this
    sweep discovers violations from, never a hand-maintained path list."""
    proc = subprocess.run(
        ["git", "-C", TOOL_HOME, "ls-files", ".claude/"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


class TestNoTrackedLiveHookScriptUnderClaudeDir(unittest.TestCase):
    """INV-7: this repo's own .claude/ must never carry a tracked, live
    (i.e. installer-independent, directly Claude-Code-executed) copy of a
    lifecycle hook script or settings.json again -- their source of truth
    is share/hook-shims/*.sh.template + claude-settings.template,
    installer-materialized into $CLAGENTIC_LITE_HOME/.claude/ at
    init/update time (lr-57db23). Discovery is git-ls-files-driven over
    the ACTUAL tracked tree, not a hardcoded snapshot of today's file
    list -- a hook script re-added under .claude/hooks/ by a future PR
    (even under a new name this list doesn't yet know) trips this sweep
    the same way a bare-git call trips INV-6's sweep.
    """

    def setUp(self):
        self.tracked = _git_ls_files_claude_dir()

    def test_sweep_anchor_still_finds_the_known_tracked_claude_file(self):
        """Fail LOUDLY, not silently-vacuous, if git ls-files' scope
        under .claude/ is ever renamed/moved out from under this sweep
        (e.g. .claude/commands/recall.md relocates or the tracked file
        set under .claude/ becomes empty for an unrelated reason) --
        this is the sweep's own anchor, proving the discovery mechanism
        itself is still live before trusting an empty violation list
        below as meaningful rather than as "found nothing to look at."
        """
        self.assertIn(
            ".claude/commands/recall.md", self.tracked,
            f"expected .claude/commands/recall.md in `git ls-files "
            f".claude/` output -- if this file genuinely moved, update "
            f"this anchor; do not delete the assertion, since an empty "
            f"self.tracked list would otherwise let the violation check "
            f"below pass vacuously with zero files actually swept. "
            f"tracked={self.tracked!r}",
        )

    def test_no_tracked_hook_script_under_claude_hooks(self):
        violations = [
            path for path in self.tracked
            if path.startswith(".claude/hooks/")
            or os.path.basename(path) in _TRACKED_HOOK_SCRIPT_BASENAMES
        ]
        self.assertEqual(
            violations, [],
            f"found tracked Claude Code lifecycle hook script(s) under "
            f".claude/ in this repo: {violations!r} -- this repo's own "
            f".claude/ must not carry a live, tracked hook script again "
            f"(lr-57db23: source of truth moved to "
            f"share/hook-shims/*.sh.template, installer-materialized into "
            f"$CLAGENTIC_LITE_HOME/.claude/hooks/ at init/update time). "
            f"Move any new hook script's source to share/hook-shims/ and "
            f"wire it through _stamp_claude_hooks instead.",
        )

    def test_no_tracked_settings_json_under_claude(self):
        violations = [
            path for path in self.tracked
            if os.path.basename(path) == "settings.json"
        ]
        self.assertEqual(
            violations, [],
            f"found a tracked .claude/settings.json in this repo: "
            f"{violations!r} -- this repo's own .claude/ must not carry a "
            f"live, tracked settings.json again (lr-57db23). Enrolled "
            f"repos still receive one via _stamp_claude_settings "
            f"(share/hook-shims/claude-settings.template); this checkout's "
            f"own copy, if a maintainer opts into self-dogfooding via "
            f"`clagentic-lite init` (AGENTS.md \"Developing clagentic-lite "
            f"itself\"), is materialized under $CLAGENTIC_LITE_HOME/.claude/ "
            f"-- gitignored, never committed.",
        )


if __name__ == "__main__":
    unittest.main()
