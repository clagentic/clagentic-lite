"""
Sweeping regression coverage for lr-53dc6e (5.3 verified-SHA-discarded,
5.4 freshness -- the most serious site in that task).

Root cause class: several call sites in gates.sh resolve `origin/<branch>`
BY NAME (raw string interpolation: `origin/${VAR}`) for a diff or
merge-base, instead of using the already-fetched, already-verified SHA
that _gate_resolve_fresh_default_branch_ref (gates.sh) proves is current.
A name resolution can succeed against a STALE local tracking ref (present
but wrong) even when the freshness check that ran moments earlier failed
or was skipped -- a "successful-looking wrong resolution" that silently
narrows a diff-scoped security scan while producing a normal-looking
verdict. cmd_bleed was already hardened against this class; cmd_sast
(5.3), get_review_diff (5.4), and build_gate_summary (5.4) were not.

THIS TEST IS DELIBERATELY A SOURCE-LEVEL SWEEP, not three separate
incident-named tests. It greps gates.sh for every live (non-comment)
`origin/${VAR}`-shaped interpolation -- braced or unbraced, quoted or
unquoted -- and asserts each one is EITHER inside
_gate_resolve_fresh_default_branch_ref's own body (where that pattern is
correct and expected) OR is not used to scope a diff/merge-base directly
(e.g. a log message built from an already-verified tip variable). Any
future call site that reintroduces a raw `origin/${...}` diff/merge-base
resolution outside the helper trips this test immediately -- it does not
need to be independently reported and separately fixed, which is exactly
the failure mode (replication without class-level defense) this task
exists to close.

A per-line regex sweep cannot, by construction, see a STORED-VARIABLE
INDIRECTION (`VAR="origin/${X}"` assigned on one line, then `$VAR` fed to a
git operation on another). Rather than silently missing that shape, a
separate check below fails loudly the moment it detects the shape outside
the helper -- see TestNoRawOriginRefResolutionOutsideHelper's
test_no_stored_variable_indirection_hides_a_raw_origin_ref_git_op and
TestFreshnessSweepCatchesAlternateShellStylesAndIndirection for proof both
the hardened regex and the indirection trip-wire actually catch what the
pre-fold-in version missed.

Run with: python3 -m unittest scripts.test_freshness_helper_sweep -v
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Variables that are legitimately used in `origin/${VAR}` form outside the
# helper's own body: only as a HUMAN-READABLE LOG STRING built from a
# variable that was itself assigned from the helper's verified output
# (e.g. cmd_bleed's _BLEED_SCOPE_REASON message, which describes the diff
# that was already computed against _BLEED_FRESH_TIP two lines above, not a
# second independent resolution). Any bare git operation (diff, merge-base,
# rev-parse) using a raw `origin/${VAR}` name is what this sweep forbids.
_ALLOWED_LOG_STRING_VARS = {"_BLEED_DEFAULT_BRANCH"}

_HELPER_NAME = "_gate_resolve_fresh_default_branch_ref"

# Matches `origin/${VAR}`, `origin/$VAR`, quoted or unquoted, with the
# variable name captured -- covers the ordinary shell style variation a
# contributor would actually write (braced/unbraced, single/double-quoted/
# unquoted), not just today's exact `origin/${VAR}` and `origin/"$VAR`
# formatting (lr-53dc6e fold-in review: the pre-fold-in version's ad hoc
# plain-string prefilter, `'origin/${' not in line`, missed the unbraced
# form entirely).
_ORIGIN_REF_RE = re.compile(r'origin/["\']?\$\{?(\w+)\}?')

# Matches an actual `_git`/`git` invocation (the repo's wrapper function,
# gates.sh:50) whose subcommand is diff/merge-base/rev-parse/ls-remote/
# fetch -- i.e. a live git OPERATION, not just the English word "diff"
# appearing inside a log/reason string like cmd_bleed's
# `_BLEED_SCOPE_REASON="branch diff vs origin/${...}"`.
_GIT_OP_RE = re.compile(r'\b_?git\b[^=]*\b(diff|merge-base|rev-parse|ls-remote|fetch)\b')

# A shell variable assignment: `VAR=...` or `VAR="..."` at the start of a
# (stripped) line, not inside a `case`/comparison. Deliberately simple --
# this only needs to catch the common `NAME=value` / `NAME="value"` form a
# contributor would write, to feed the stored-variable indirection check.
_ASSIGNMENT_RE = re.compile(r'^(\w+)=')


def _find_raw_origin_ref_git_op_violations(lines, helper_start, helper_end):
    """Sweep primitive: every live (non-comment) line outside the helper's
    body where an `origin/${VAR}`-shaped ref appears directly in a live git
    operation (diff/merge-base/rev-parse/ls-remote/fetch), rather than as a
    log/reason string built from an already-verified variable."""
    violations = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue  # comment, not live code
        if helper_start <= i <= helper_end:
            continue  # inside the helper itself -- correct by definition
        m = _ORIGIN_REF_RE.search(line)
        if not m:
            continue
        var_name = m.group(1)
        if var_name in _ALLOWED_LOG_STRING_VARS and not _GIT_OP_RE.search(line):
            continue  # a log/reason string, not a git operation
        if _GIT_OP_RE.search(line):
            violations.append((i + 1, line.rstrip('\n')))
    return violations


def _find_stored_origin_ref_indirection(lines, helper_start, helper_end):
    """Detect (and thereby fail-loudly on, rather than silently miss) the
    one shape the line-scoped sweep above cannot verify: a raw origin/${...}
    string assigned to a variable on one line, where that same variable name
    is later used as an argument to a live git operation elsewhere in the
    file, outside the helper. This does not need to prove the two sites are
    causally connected (that would require real shell dataflow analysis,
    out of scope for a regex sweep) -- the mere presence of the shape is
    itself the trip-wire: a reviewer or future contributor must not be able
    to introduce this indirection and have the sweep quietly pass."""
    assigned_from_origin_ref = {}  # var_name -> (line_no, line_text)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#') or (helper_start <= i <= helper_end):
            continue
        am = _ASSIGNMENT_RE.match(stripped)
        if not am:
            continue
        assigned_var = am.group(1)
        om = _ORIGIN_REF_RE.search(line)
        if not om:
            continue
        # BUG FIX (lr-7047bf, carried from PR #140/lr-53dc6e review): the
        # exemption must key on the CAPTURED origin-ref variable (the name
        # inside `origin/${...}`, e.g. _BLEED_DEFAULT_BRANCH) -- the thing
        # _ALLOWED_LOG_STRING_VARS actually documents as safe -- not on the
        # ASSIGNED variable (the log-string variable being built, e.g.
        # _BLEED_SCOPE_REASON). The prior form checked assigned_var, which is
        # never itself an "origin/${VAR}"-referencing name and so was almost
        # never in the allowlist -- gates.sh:547
        # (_BLEED_SCOPE_REASON="branch diff vs origin/${_BLEED_DEFAULT_BRANCH}")
        # avoided tripping this check only by accident, because none of its
        # five consumers (:573,:582,:597,:608,:626) happen to also match
        # _GIT_OP_RE, not because the exemption logic correctly recognized it
        # as a safe log string. A future consumer of $_BLEED_SCOPE_REASON
        # containing a git-subcommand word (e.g. a log line reading "git diff
        # summary: ...") would have false-positived the entire suite.
        captured_var = om.group(1)
        if captured_var not in _ALLOWED_LOG_STRING_VARS:
            assigned_from_origin_ref[assigned_var] = (i + 1, line.rstrip('\n'))

    if not assigned_from_origin_ref:
        return []

    hits = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#') or (helper_start <= i <= helper_end):
            continue
        if not _GIT_OP_RE.search(line):
            continue
        for var_name, (assign_ln, assign_txt) in assigned_from_origin_ref.items():
            if re.search(r'\$\{?' + re.escape(var_name) + r'\}?\b', line):
                hits.append((
                    i + 1,
                    f"{line.rstrip(chr(10))!r} uses ${{{var_name}}}, assigned "
                    f"from a raw origin/${{...}} string at gates.sh:{assign_ln}: "
                    f"{assign_txt!r}",
                ))
    return hits


def _find_function_body_range(lines, func_name):
    """Return (start_line_idx, end_line_idx) 0-based, inclusive, for a
    `func_name() {` ... matching `}` block. Uses simple brace counting,
    which is sufficient here because gates.sh has no braces inside string
    literals in this function body."""
    start = None
    for i, line in enumerate(lines):
        if re.match(r'^' + re.escape(func_name) + r'\s*\(\)\s*\{', line):
            start = i
            break
    assert start is not None, f"could not find {func_name}() in gates.sh"
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth == 0 and i > start:
            return start, i
    raise AssertionError(f"could not find closing brace for {func_name}()")


class TestNoRawOriginRefResolutionOutsideHelper(unittest.TestCase):
    """Static sweep: every live `origin/${VAR}` git-operation site in
    gates.sh must be inside _gate_resolve_fresh_default_branch_ref itself.
    A call site outside the helper that resolves origin/<branch> by name
    for an actual git command (diff, merge-base, rev-parse) reintroduces
    the exact staleness class cmd_bleed, cmd_sast, and get_review_diff were
    hardened against."""

    def setUp(self):
        with open(GATES_SH) as f:
            self.lines = f.readlines()
        self.helper_start, self.helper_end = _find_function_body_range(
            self.lines, _HELPER_NAME)

    def test_helper_exists_and_has_a_body(self):
        self.assertGreater(self.helper_end, self.helper_start)

    def test_no_git_operation_uses_raw_origin_ref_outside_helper(self):
        violations = _find_raw_origin_ref_git_op_violations(
            self.lines, self.helper_start, self.helper_end)

        self.assertEqual(
            violations, [],
            f"found {len(violations)} live git-operation site(s) outside "
            f"{_HELPER_NAME}() resolving origin/<branch> by raw name instead "
            f"of the verified-fresh SHA -- this reintroduces the staleness "
            f"class:\n" + "\n".join(f"  gates.sh:{ln}: {txt}" for ln, txt in violations),
        )

    def test_no_stored_variable_indirection_hides_a_raw_origin_ref_git_op(self):
        """The line-scoped regex sweep above genuinely cannot see a
        stored-variable indirection: `VAR="origin/${X}"` on one line, then a
        live git operation using `$VAR` on another. Rather than silently
        passing on a shape it cannot cover, this check fails LOUDLY the
        moment it detects that shape outside the helper -- an
        undetectable-by-design construct must name itself as a failure, not
        pass quietly (fail-closed, same principle the production fix
        applies)."""
        hits = _find_stored_origin_ref_indirection(
            self.lines, self.helper_start, self.helper_end)
        self.assertEqual(
            hits, [],
            f"found {len(hits)} stored-variable indirection site(s) outside "
            f"{_HELPER_NAME}() where a variable is assigned a raw "
            f"origin/${{...}} string and then used elsewhere -- this shape "
            f"cannot be verified safe by the per-line sweep above (it may "
            f"feed a git operation on a later line) and is exactly the class "
            f"this task hardens against; resolve via the verified-fresh SHA "
            f"instead:\n" + "\n".join(f"  gates.sh:{ln}: {txt}" for ln, txt in hits),
        )


# The pre-fold-in discovery prefilter (lr-53dc6e review, PEACHES/HOLDEN
# fold-in): a plain-string membership check (`'origin/${' not in line and
# 'origin/"$' not in line`) that only matched today's exact `origin/${VAR}`
# and `origin/"$VAR` formatting. Kept here, inert, ONLY so the negative
# fixture below can prove the CURRENT regex (_ORIGIN_REF_RE above) covers
# strictly more shell styles than the old prefilter -- not as a second
# discovery mechanism used anywhere in the live sweep.
def _pre_foldin_origin_ref_prefilter_matches(line):
    return 'origin/${' in line or 'origin/"$' in line


class TestFreshnessSweepCatchesAlternateShellStylesAndIndirection(unittest.TestCase):
    """Proves the hardened discovery regex and the stored-variable
    indirection check actually sweep, rather than asserting they do.  Each
    fixture is a synthetic sibling call site, written in a valid-but-
    different style than the sites the pre-fold-in sweep already covered,
    that reintroduces the raw-name-resolution staleness class. The old
    sweep missed it (so it would silently pass); the hardened sweep must
    both discover it and report a violation/failure."""

    _UNBRACED_FIXTURE = (
        'cmd_fixture() {\n'
        '  _FIX_TIP=$(_git diff origin/$_FIX_BRANCH --name-only)\n'
        '}\n'
    )

    _INDIRECTION_FIXTURE = (
        'cmd_fixture() {\n'
        '  _FIX_REF="origin/${_FIX_BRANCH}"\n'
        '  _FIX_TIP=$(_git diff "$_FIX_REF" --name-only)\n'
        '}\n'
    )

    def test_pre_foldin_prefilter_missed_the_unbraced_fixture(self):
        """Guards the premise for the unbraced case: if the old prefilter
        already caught this line, it is not a valid negative fixture."""
        lines = self._UNBRACED_FIXTURE.splitlines(keepends=True)
        target_line = lines[1]
        self.assertFalse(
            _pre_foldin_origin_ref_prefilter_matches(target_line),
            "fixture line was already matched by the old plain-string "
            "prefilter -- not a valid negative fixture",
        )

    def test_hardened_regex_discovers_and_flags_the_unbraced_fixture(self):
        lines = self._UNBRACED_FIXTURE.splitlines(keepends=True)
        # No helper body in this fixture -- pass an empty (never-entered)
        # helper range so every line is "outside the helper".
        violations = _find_raw_origin_ref_git_op_violations(lines, -1, -1)
        self.assertTrue(
            any('_git diff origin/$_FIX_BRANCH' in txt for _, txt in violations),
            f"hardened sweep failed to discover/flag the unbraced "
            f"origin/$VAR git operation. violations={violations!r}",
        )

    def test_indirection_fixture_is_invisible_to_the_direct_regex_sweep(self):
        """Guards the premise for the indirection case: the direct
        per-line sweep (test_no_git_operation_uses_raw_origin_ref_outside_helper's
        primitive) must NOT see this as a violation on its own -- the git
        operation line only references `$_FIX_REF`, not `origin/${...}`
        directly. This is what makes it a genuinely undetectable-by-regex
        shape, requiring the separate fail-loud indirection check."""
        lines = self._INDIRECTION_FIXTURE.splitlines(keepends=True)
        violations = _find_raw_origin_ref_git_op_violations(lines, -1, -1)
        self.assertEqual(
            violations, [],
            "fixture was already caught by the direct per-line sweep -- not "
            "a valid indirection fixture (it should only be catchable by "
            "the separate fail-loud indirection check)",
        )

    def test_indirection_check_fails_loudly_on_the_indirection_fixture(self):
        lines = self._INDIRECTION_FIXTURE.splitlines(keepends=True)
        hits = _find_stored_origin_ref_indirection(lines, -1, -1)
        self.assertTrue(
            any('_FIX_REF' in txt for _, txt in hits),
            f"indirection check failed to fail loudly on the stored-"
            f"variable indirection fixture -- an undetectable-by-regex "
            f"shape must trip a named failure, not pass silently. "
            f"hits={hits!r}",
        )


class TestIndirectionExemptionKeysOnCapturedVarNotAssignedVar(unittest.TestCase):
    """Regression for the PR #140 review fold-in (BOBBIE, carried into
    lr-7047bf): _find_stored_origin_ref_indirection used to check
    `assigned_var not in _ALLOWED_LOG_STRING_VARS` -- the LHS variable being
    built (e.g. _BLEED_SCOPE_REASON) -- when the allowlist actually documents
    which CAPTURED origin-ref variable (the name inside `origin/${...}`,
    e.g. _BLEED_DEFAULT_BRANCH) is safe to reference in a log string. Those
    are never the same name, so the exemption almost never matched by
    design, and gates.sh:547's real
    `_BLEED_SCOPE_REASON="branch diff vs origin/${_BLEED_DEFAULT_BRANCH}"`
    avoided tripping this check only because none of its five consumers
    happen to also contain a git-subcommand word -- not because the
    exemption logic recognized it as safe. A future consumer that DOES
    contain one (e.g. a log line reading "git diff summary: <reason>")
    would have false-positived the entire suite, and a future contributor
    would have "fixed" that by disabling this trip-wire -- silently
    reopening the freshness hole PR #140 closed."""

    # Mirrors the real gates.sh:485-547 shape exactly: a log-string variable
    # built from a captured, allowlisted origin-ref variable, then used by a
    # LATER consumer that (unlike gates.sh's real five consumers) DOES
    # contain a git-subcommand word. This is the genuinely dangerous case:
    # the log string itself is fine (built from an allowlisted capture), but
    # if a future edit's consumer line happens to look like a git operation,
    # the exemption must still recognize the origin string as safe and not
    # flag it -- correctly recognizing the ALLOWLISTED case is exactly what
    # the keying bug broke.
    _ALLOWLISTED_CAPTURE_FIXTURE = (
        'cmd_fixture() {\n'
        '  _FIX_DEFAULT_BRANCH="main"\n'
        '  _FIX_SCOPE_REASON="branch diff vs origin/${_FIX_DEFAULT_BRANCH}"\n'
        '  echo "git diff summary: $_FIX_SCOPE_REASON" 1>&2\n'
        '}\n'
    )

    def setUp(self):
        # Patch the module-level allowlist for the duration of this test so
        # the fixture can use its own, self-contained variable names rather
        # than colliding with the real _BLEED_DEFAULT_BRANCH -- keeps this
        # test from silently depending on gates.sh's current variable names.
        #
        # ORDER-DEPENDENCY FIX (lr-7047bf fold-in): `import scripts.test_
        # freshness_helper_sweep as mod` used to hardcode the dotted path.
        # Under `python3 -m unittest scripts.test_freshness_helper_sweep`
        # that happens to be the same module object this TestCase runs in,
        # so the patch reached _find_stored_origin_ref_indirection's globals
        # and every test passed. Under `python3 -m unittest discover -s
        # scripts -t scripts` (this repo has no scripts/__init__.py),
        # unittest's discovery loader imports this file as a BARE top-level
        # module (test_freshness_helper_sweep) while the hardcoded import
        # statement -- resolved against a repo-root sys.path entry that a
        # `-m` invocation also seeds -- created a SECOND, independent module
        # object under the `scripts.`-qualified name. setUp patched that
        # second object's allowlist; the sweep functions the test actually
        # exercises are bound to the FIRST (bare) object's unpatched globals,
        # so the patch silently never took effect and the test failed only
        # under discover -- a real order/dispatch-mode dependency, not a
        # flake. Resolving the module via the TestCase's own __module__
        # (looked up in sys.modules) always identifies the module object
        # this test is actually running in, regardless of which import path
        # produced it, so there is only ever one identity to patch.
        self._mod = sys.modules[self.__class__.__module__]
        self._orig_allowlist = self._mod._ALLOWED_LOG_STRING_VARS
        self._mod._ALLOWED_LOG_STRING_VARS = {"_FIX_DEFAULT_BRANCH"}

    def tearDown(self):
        self._mod._ALLOWED_LOG_STRING_VARS = self._orig_allowlist

    def test_old_assigned_var_keying_would_have_flagged_a_safe_allowlisted_capture(self):
        """Guards the premise: with the OLD (buggy) keying -- checking the
        ASSIGNED var (_FIX_SCOPE_REASON) against the allowlist instead of
        the CAPTURED var (_FIX_DEFAULT_BRANCH) -- this fixture would be
        flagged as a violation even though the captured variable IS
        allowlisted. That would make the sweep noisy on legitimate code,
        which is exactly the pressure that gets a trip-wire disabled by a
        later contributor."""
        lines = self._ALLOWLISTED_CAPTURE_FIXTURE.splitlines(keepends=True)
        old_assigned_from_origin_ref = {}
        for i, line in enumerate(lines):
            stripped = line.strip()
            am = _ASSIGNMENT_RE.match(stripped)
            if not am:
                continue
            assigned_var = am.group(1)
            if _ORIGIN_REF_RE.search(line) and assigned_var not in self._mod._ALLOWED_LOG_STRING_VARS:
                old_assigned_from_origin_ref[assigned_var] = (i + 1, line.rstrip('\n'))
        self.assertIn(
            "_FIX_SCOPE_REASON", old_assigned_from_origin_ref,
            "premise check failed: the old assigned-var-keyed logic was "
            "expected to (wrongly) flag this fixture -- if it doesn't, this "
            "is not a valid fixture for proving the fix matters",
        )

    def test_fixed_captured_var_keying_recognizes_the_allowlisted_capture(self):
        """The actual fix: keying on the captured var means this fixture --
        a log string built from an allowlisted capture, consumed by a line
        that happens to contain a git-subcommand word -- produces NO
        indirection hit, because _FIX_DEFAULT_BRANCH (the captured var) is
        allowlisted, exactly as _BLEED_DEFAULT_BRANCH is for the real
        gates.sh shape this fixture mirrors."""
        lines = self._ALLOWLISTED_CAPTURE_FIXTURE.splitlines(keepends=True)
        hits = _find_stored_origin_ref_indirection(lines, -1, -1)
        self.assertEqual(
            hits, [],
            f"fixed exemption keying still flagged an allowlisted capture "
            f"as a violation -- the fix should recognize _FIX_DEFAULT_BRANCH "
            f"(the captured origin-ref var) as safe, matching real "
            f"gates.sh:547's _BLEED_DEFAULT_BRANCH shape. hits={hits!r}",
        )

    def test_a_non_allowlisted_capture_with_the_same_shape_still_trips(self):
        """Sanity check on the other direction: change the captured var to
        one NOT in the allowlist (same fixture shape otherwise) and confirm
        the indirection check still fires -- proves the fix narrows the
        exemption to the captured var specifically, rather than accidentally
        exempting everything."""
        fixture = self._ALLOWLISTED_CAPTURE_FIXTURE.replace(
            "_FIX_DEFAULT_BRANCH", "_FIX_UNLISTED_BRANCH")
        lines = fixture.splitlines(keepends=True)
        hits = _find_stored_origin_ref_indirection(lines, -1, -1)
        self.assertTrue(
            any("_FIX_SCOPE_REASON" in txt for _, txt in hits),
            f"expected a hit once the captured var is no longer "
            f"allowlisted. hits={hits!r}",
        )


def _init_bare_and_clone(tmp):
    origin = os.path.join(tmp, "origin.git")
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    work = os.path.join(tmp, "work")
    subprocess.run(["git", "clone", "-q", origin, work], check=True)
    env = {**os.environ, **_GIT_ENV}
    readme = os.path.join(work, "README")
    with open(readme, "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=work, env=env)
    subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=env)
    subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=env)
    with open(readme, "a") as f:
        f.write("feature change\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "feature commit"], check=True, cwd=work, env=env)
    return origin, work


class TestGetReviewDiffFailsClosedOnUnfetchableOrigin(unittest.TestCase):
    """get_review_diff (5.4, the most serious site): when origin cannot be
    fetched/verified, it must fail toward MORE coverage or a hard error --
    never silently produce a narrower diff off a raw name resolution.

    This test breaks the freshness precondition by pointing `origin` at a
    path that no longer exists (fetch fails outright) and asserts cmd_review
    does NOT exit 0 with a silently-narrowed (possibly empty, possibly
    stale-local-state) diff -- it must fail loudly instead.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-freshness-review-")
        self._origin, self._work = _init_bare_and_clone(self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_review_gate_fails_closed_when_origin_unreachable(self):
        # Break the remote after the initial clone/fetch so a local
        # tracking ref for origin/main already exists (simulating "fetched
        # once, never refreshed") but any FRESH fetch this run will fail.
        broken_origin = os.path.join(self._tmp, "origin-does-not-exist.git")
        subprocess.run(
            ["git", "remote", "set-url", "origin", broken_origin],
            check=True, cwd=self._work,
        )

        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = self._work
        env["CLAGENTIC_DEFAULT_BRANCH"] = "main"
        env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
        result = subprocess.run(
            ["sh", GATES_SH, "review"],
            capture_output=True, text=True, env=env, cwd=self._work,
        )
        # Must NOT succeed quietly. The gate should either hard-error (set -e
        # aborting on get_review_diff's non-zero return) or otherwise report
        # the unverifiable baseline -- never exit 0 having silently produced
        # a diff off a stale/local-only resolution.
        combined = result.stdout + result.stderr
        self.assertIn(
            "not provably current", combined,
            f"expected the freshness failure to be surfaced, not silently "
            f"swallowed. returncode={result.returncode} output={combined!r}",
        )


if __name__ == "__main__":
    unittest.main()
