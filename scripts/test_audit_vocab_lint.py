"""
Regression coverage for lr-7047bf (PR-B, task item 4): cmd_audit_vocab_lint,
the warn-only audit-vocabulary lint (scripts/gates.sh). Widened by lr-2e8444
for the runtime-checked-helper fix -- see that task's own class writeup for
the three visibility classes (fully opaque / partially visible / fully
literal) this file now covers.

Root cause class (foundry sub-class 1.6-1.11): several gates log
`cmd_log_run <gate> pass "<details>"` where the details string itself names
a reason the underlying tool never actually scanned anything -- git
ls-files failed, no package sources found, an empty pattern file, an older
gitleaks unable to scan history. "pass" is a promise the audit trail is
telling the truth about coverage; a details string that contradicts its own
outcome label is definitionally a lie against that promise.

Per the task's own directive, this lint is deliberately WARN-ONLY and does
NOT rewrite the six gates' underlying behavior -- it blocks NEW violations
while making the existing backlog explicit (the _KNOWN_VIOLATIONS
allowlist in cmd_audit_vocab_lint) rather than invisible. These tests
cover: (1) the real gates.sh backlog is exactly the known set, no more, no
less; (2) a synthetic new violation is correctly flagged; (3) a "warn"
outcome (already honestly labeled, e.g. cross-round dedup's "splice
failed" warning) is correctly NOT flagged -- the lint targets "pass" only.

lr-2e8444 WIDENING: the static lint above can only see a LITERAL
double-quoted details string -- a variable-assembled details string (bare,
as cmd_sast's pre-fix `"$_SAST_PASS_DETAILS"`, or mixed literal+variable, as
cmd_bleed's `"...($_BLEED_SCOPE_REASON)"` sites and cmd_merge_gate's
class/state-suffix sites) is invisible to it in whole or in part. This is
closed from the runtime side: `_cmd_log_run_checked_pass` (scripts/gates.sh)
checks the fully-assembled, post-interpolation details string at the moment
it actually exists, downgrading pass->warn on a vocabulary hit rather than
silently reporting a false-clean pass. A second static check inside
cmd_audit_vocab_lint (`_UNCHECKED_DIRECT_CALL_RE`) is the regression guard:
it flags any direct `cmd_log_run <gate> pass ...` call whose details
argument contains a `$` and therefore bypasses the checked helper. New test
classes below cover: (4) the checked helper's own runtime vocabulary check
(pass/warn downgrade, exact non-substitution of an all-literal or all-clean
string); (5) the second static check's detection of an unchecked
variable-assembled call site and non-flagging of the sanctioned choke point
and of a checked call; (6) the real gates.sh has zero unchecked
variable-assembled pass sites (the sast/bleed/merge-gate sweep is complete);
(7) the shell and Python failure-word vocabularies stay in sync.

Sources the REAL sh function from gates.sh (not a Python mirror), mirroring
test_deferrals_sanitize.py's established functions-only-source technique.

Run with: python3 -m unittest scripts.test_audit_vocab_lint -v
"""
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")


def _functions_only_source(dest_dir):
    """Same truncation/symlink pattern as test_build_gate_summary_change_class.py."""
    with open(GATES_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in gates.sh"
    dest = os.path.join(dest_dir, "gates.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
    for fname in ("platform.sh", "review-merge.sh", "host-adapter.sh"):
        os.symlink(os.path.join(real_scripts_dir, fname), os.path.join(dest_dir, fname))
    return dest


def _run_lint(target_file, project_root=None):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-vocab-lint-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)
        script = textwrap.dedent(f"""\
            . '{sourced_gates}'
            cmd_audit_vocab_lint '{target_file}'
        """)
        env = os.environ.copy()
        if project_root:
            env["CLAGENTIC_PROJECT_ROOT"] = project_root
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestRealGatesShKnownBacklog(unittest.TestCase):
    """The real gates.sh's existing violations must be exactly the
    allowlisted known set -- no unexpected new ones (a real, un-reviewed
    violation would mean either a fix landed without updating the
    allowlist, or a genuine new instance of the lie-class slipped in), and
    none of the known ones may have silently disappeared (which would mean
    the allowlist is stale and should be trimmed, not a test failure to
    hide)."""

    def test_no_new_violations_in_real_gates_sh(self):
        out, err, rc = _run_lint(GATES_SH)
        self.assertEqual(rc, 0, f"warn-only lint must never exit nonzero. stderr={err!r}")
        self.assertNotIn(
            "NEW violation", out,
            f"cmd_audit_vocab_lint found an unreviewed 'pass' outcome with "
            f"a failure-word details string in real gates.sh -- either add "
            f"it to _KNOWN_VIOLATIONS (reviewed exception) or fix the gate "
            f"to log block/warn instead of pass. output={out!r}",
        )

    def test_real_gates_sh_has_exactly_the_documented_known_violations(self):
        """Sanity check on the allowlist itself: four known VIOLATION SITES
        from three distinct _KNOWN_VIOLATIONS entries (deps/no-package-
        sources, bleed/empty-pattern-file, bleed/git-ls-files-failed --
        matched at TWO call sites, identical text) must still be present and
        still counted as known -- if any disappeared, the allowlist should
        be trimmed rather than silently going stale (a stale allowlist
        entry provides no coverage but looks like it does).

        The former sast/"unavailable" exception (and its lr-321e18
        exclude-ladder-suffixed sibling) is GONE, not merely uncounted:
        lr-321e18's BOBBIE fold-in changed cmd_sast's two
        `cmd_log_run sast pass ...` call sites to build their details string
        into a variable ($_SAST_PASS_DETAILS, so the new config-pin
        visibility fix can conditionally append to it) and pass that
        variable rather than a literal string -- this lint's regex only
        matches a literal double-quoted details string, so those two call
        sites are no longer statically flagged at all, and the entries that
        used to allowlist them were removed from _KNOWN_VIOLATIONS as dead
        (see that dict's own comment)."""
        out, err, rc = _run_lint(GATES_SH)
        self.assertIn("4 known", out, f"output={out!r}")
        self.assertIn("no package sources found", out)
        self.assertIn("empty pattern file", out)
        self.assertIn("git ls-files failed", out)
        self.assertNotIn("baseline unavailable", out)


class TestSyntheticFixtures(unittest.TestCase):
    """Proves the lint actually discovers and flags what it claims to,
    using synthetic fixture files (not the real gates.sh, so the allowlist
    interaction is fully controlled)."""

    def _write_fixture(self, content):
        fd, path = tempfile.mkstemp(prefix="clagentic-test-vocab-fixture-", suffix=".sh")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    def test_flags_a_new_pass_outcome_with_a_failure_word(self):
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run fixture-gate pass "scanner not found, skipped entirely"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertEqual(rc, 0, "warn-only: must not exit nonzero")
            self.assertIn("1 NEW violation", out, f"output={out!r}")
            self.assertIn("fixture-gate", out)
        finally:
            os.unlink(path)

    def test_does_not_flag_warn_outcome_with_a_failure_word(self):
        """A 'warn' outcome describing a real, conservative fallback
        (already honestly labeled as not-fully-clean) must NOT be flagged
        -- the lint targets the specific "pass" + failure-word
        contradiction, not every mention of a failure word."""
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run fixture-gate warn "splice failed; original findings retained"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertIn("no new violations", out, f"output={out!r}")
        finally:
            os.unlink(path)

    def test_does_not_flag_a_clean_pass_with_no_failure_word(self):
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run fixture-gate pass "0 findings"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertIn("no new violations", out, f"output={out!r}")
        finally:
            os.unlink(path)

    def test_a_known_violation_shape_reported_as_known_not_new(self):
        """Exact match to a _KNOWN_VIOLATIONS entry (same gate, same
        details string) must be reported as known/allowlisted, not as a
        new violation -- proves the allowlist actually suppresses what it
        claims to."""
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run deps pass "no package sources found"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertIn("1 known", out, f"output={out!r}")
            self.assertNotIn("NEW violation", out)
        finally:
            os.unlink(path)

    def test_same_gate_different_wording_is_a_new_violation_not_absorbed_by_allowlist(self):
        """The allowlist keys on the EXACT (gate, details) pair -- a
        near-miss (same gate, reworded details still containing a failure
        word) must not be silently absorbed just because the gate name
        matches a known entry. This is what keeps the allowlist from
        becoming a blanket exemption for the whole gate."""
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run deps pass "dependency scan skipped, nothing checked"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertIn("1 NEW violation", out, f"output={out!r}")
        finally:
            os.unlink(path)

    def test_quoted_variable_gate_name_form_is_discovered(self):
        """cmd_merge_gate uses `cmd_log_run "$_mg_gate_name" pass ...` (a
        quoted variable, not a bare literal) -- the discovery regex must
        cover this call shape too, not just the bare-literal form the other
        five gates use."""
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run "$_fx_gate_name" pass "resolution failed, falling back"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertIn("1 NEW violation", out, f"output={out!r}")
            self.assertIn("_fx_gate_name", out)
        finally:
            os.unlink(path)

    def test_a_comment_line_is_not_flagged(self):
        fixture = (
            'cmd_fixture() {\n'
            '  # cmd_log_run fixture-gate pass "not found, skipped"\n'
            '  true\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertIn("no new violations", out, f"output={out!r}")
        finally:
            os.unlink(path)


def _run_checked_pass(gate, details, extra_env=None):
    """Sources the real _cmd_log_run_checked_pass (and its cmd_log_run/
    cmd_init dependencies) from gates.sh via the same functions-only-source
    technique as _run_lint, then calls it with GATE and DETAILS. Runs with
    cwd inside this repo's own scripts/ dir (a real git checkout) so
    REPO_ROOT resolution at the top of gates.sh succeeds; CLAGENTIC_PROJECT_ROOT
    is pinned to a throwaway tmpdir git repo so the audit DB write (cmd_init/
    cmd_log_run) never touches this checkout's own .clagentic/lite/audit.db.

    Returns (stdout, stderr, returncode, tmpdir, project_dir). The caller
    owns tmpdir cleanup (via a `finally: shutil.rmtree(tmpdir, ...)` of its
    own) -- deleting it here, before the caller reads project_dir's audit
    DB, would remove the very file the caller needs to assert against."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-checked-pass-")
    src_dir = os.path.join(tmpdir, "src")
    os.makedirs(src_dir)
    sourced_gates = _functions_only_source(src_dir)
    project_dir = os.path.join(tmpdir, "project")
    os.makedirs(project_dir)
    subprocess.run(["git", "init", "-q", project_dir], check=True)
    script = textwrap.dedent(f"""\
        . '{sourced_gates}'
        _cmd_log_run_checked_pass '{gate}' '{details}'
    """)
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_dir
    if extra_env:
        env.update(extra_env)
    r = subprocess.run(
        ["sh", "-c", script, sourced_gates],
        capture_output=True, text=True, env=env,
        cwd=os.path.join(TOOL_HOME, "scripts"),
    )
    return r.stdout, r.stderr, r.returncode, tmpdir, project_dir


def _audit_db_last_row(project_dir):
    """Reads the single most recent gate_runs row (outcome, details) written
    by cmd_log_run under CLAGENTIC_PROJECT_ROOT=project_dir."""
    import sqlite3
    db_path = os.path.join(project_dir, ".clagentic", "lite", "audit.db")
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT outcome, details FROM gate_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row
    finally:
        conn.close()


class TestCheckedPassHelperRuntimeVocabularyCheck(unittest.TestCase):
    """_cmd_log_run_checked_pass GATE DETAILS -- proves the runtime check
    examines the FULLY ASSEMBLED details string (not source text), and
    downgrades pass->warn on a hit rather than silently reporting a
    false-clean pass. This is the direct regression test for BOBBIE's PR 159
    false-clean finding: cmd_sast's variable-assembled details string now
    goes through this exact function."""

    def test_clean_details_logs_as_pass(self):
        out, err, rc, tmpdir, project_dir = _run_checked_pass(
            "fixture-gate", "0 findings, config=auto"
        )
        try:
            self.assertEqual(rc, 0, err)
            row = _audit_db_last_row(project_dir)
            self.assertIsNotNone(row, "expected a gate_runs row to be written")
            outcome, details = row
            self.assertEqual(outcome, "pass")
            self.assertEqual(details, "0 findings, config=auto")
            self.assertNotIn("logging as 'warn' instead", err)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_failure_word_in_assembled_details_downgrades_to_warn(self):
        """The exact false-clean shape this task closes: a details string
        whose failure-word content only exists after variable interpolation
        (never literally in gates.sh's own source text) must still be
        caught -- because this check runs on the ASSEMBLED string at
        runtime, not on source text."""
        assembled = "full-tree (baseline unavailable: no origin remote)"
        out, err, rc, tmpdir, project_dir = _run_checked_pass("sast", assembled)
        try:
            self.assertEqual(rc, 0, err)
            row = _audit_db_last_row(project_dir)
            outcome, details = row
            self.assertEqual(
                outcome, "warn",
                f"a failure-word details string must be logged as warn, not pass; row={row!r}",
            )
            self.assertEqual(details, assembled, "the real details text must still be recorded, not suppressed")
            self.assertIn("logging as 'warn' instead", err)
            self.assertIn("unavailable", err)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_mixed_literal_and_variable_failure_word_downgrades_to_warn(self):
        """The partially-visible class (cmd_bleed's $_BLEED_SCOPE_REASON,
        cmd_merge_gate's suffix sites): the failure word lives in the
        interpolated half, not the literal half -- must still be caught."""
        assembled = "no files to scan (git ls-files failed, non-blocking)"
        out, err, rc, tmpdir, project_dir = _run_checked_pass("bleed", assembled)
        try:
            self.assertEqual(rc, 0, err)
            outcome, details = _audit_db_last_row(project_dir)
            self.assertEqual(outcome, "warn")
            self.assertEqual(details, assembled)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_details_with_no_failure_word_is_unaffected(self):
        assembled = "branch diff vs origin/main; excluded 2 rule(s): a.b.c,d.e.f"
        out, err, rc, tmpdir, project_dir = _run_checked_pass("sast", assembled)
        try:
            self.assertEqual(rc, 0, err)
            outcome, details = _audit_db_last_row(project_dir)
            self.assertEqual(outcome, "pass")
            self.assertEqual(details, assembled)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestUnifiedFailureWordVocabulary(unittest.TestCase):
    """The shell _AUDIT_FAILURE_WORDS list (scripts/gates.sh, consulted by
    _cmd_log_run_checked_pass at runtime) and the Python _FAILURE_WORDS
    tuple (inside cmd_audit_vocab_lint's embedded lint, consulted
    statically) must name the exact same vocabulary -- a runtime check that
    is more lenient than the static one would silently let a failure word
    through the ONE path (the checked helper) built specifically to examine
    content the static lint cannot see."""

    def test_shell_and_python_failure_word_lists_match(self):
        with open(GATES_SH) as f:
            content = f.read()

        shell_start = content.index('_AUDIT_FAILURE_WORDS="')
        shell_end = content.index('"\n\n_cmd_log_run_checked_pass', shell_start)
        shell_block = content[shell_start + len('_AUDIT_FAILURE_WORDS="'):shell_end]
        shell_words = set(w for w in shell_block.splitlines() if w)

        py_start = content.index("_FAILURE_WORDS = (")
        py_end = content.index(")", py_start)
        py_block = content[py_start + len("_FAILURE_WORDS = ("):py_end]
        py_words = set(
            w.strip().strip('"').strip("'")
            for w in py_block.replace("\n", " ").split(",")
            if w.strip()
        )

        self.assertEqual(
            shell_words, py_words,
            f"shell _AUDIT_FAILURE_WORDS and Python _FAILURE_WORDS have diverged: "
            f"shell-only={shell_words - py_words!r} python-only={py_words - shell_words!r}",
        )
        # Sanity: both extractions must have actually found something, or a
        # parse-anchor drift would silently pass this test with two empty sets.
        self.assertTrue(shell_words, "shell vocabulary extraction found nothing -- anchor drifted")
        self.assertTrue(py_words, "python vocabulary extraction found nothing -- anchor drifted")


class TestUncheckedDirectCallSweep(unittest.TestCase):
    """Second static check inside cmd_audit_vocab_lint: any direct
    `cmd_log_run <gate> pass ...` call site whose details argument contains
    a `$` bypasses `_cmd_log_run_checked_pass` and is flagged as a
    regression -- its runtime content can never be vocabulary-checked by
    either mechanism."""

    def _write_fixture(self, content):
        fd, path = tempfile.mkstemp(prefix="clagentic-test-unchecked-fixture-", suffix=".sh")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    def test_bare_variable_pass_call_is_flagged_unchecked(self):
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run fixture-gate pass "$_FX_DETAILS"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertEqual(rc, 0)
            self.assertIn("1 UNCHECKED variable-assembled", out, f"output={out!r}")
        finally:
            os.unlink(path)

    def test_mixed_literal_variable_pass_call_is_flagged_unchecked(self):
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run fixture-gate pass "scope reduced ($_FX_REASON)"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertEqual(rc, 0)
            self.assertIn("1 UNCHECKED variable-assembled", out, f"output={out!r}")
        finally:
            os.unlink(path)

    def test_all_literal_pass_call_is_not_flagged_unchecked(self):
        """A fully-literal details string (no `$` at all) is already
        completely covered by the vocabulary check itself -- routing it
        through the checked helper too would be pure churn, so it must not
        be flagged by this second check."""
        fixture = (
            'cmd_fixture() {\n'
            '  cmd_log_run fixture-gate pass "0 findings"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertEqual(rc, 0)
            self.assertIn("no unchecked variable-assembled pass call sites", out, f"output={out!r}")
        finally:
            os.unlink(path)

    def test_checked_helper_call_site_itself_is_not_flagged(self):
        """A call routed through the checked helper (`_cmd_log_run_checked_pass
        GATE "$VAR"`) is the FIX, not a violation -- must never be flagged."""
        fixture = (
            'cmd_fixture() {\n'
            '  _cmd_log_run_checked_pass fixture-gate "$_FX_DETAILS"\n'
            '}\n'
        )
        path = self._write_fixture(fixture)
        try:
            out, err, rc = _run_lint(path)
            self.assertEqual(rc, 0)
            self.assertIn("no unchecked variable-assembled pass call sites", out, f"output={out!r}")
        finally:
            os.unlink(path)

    def test_real_gates_sh_has_zero_unchecked_variable_assembled_call_sites(self):
        """The actual regression guard: after lr-2e8444's sast/bleed/
        merge-gate rewiring, gates.sh itself must have zero direct
        cmd_log_run pass calls with a variable-assembled details string --
        every one goes through _cmd_log_run_checked_pass. The ONE sanctioned
        exception (_cmd_log_run_checked_pass's own final line, which IS the
        checked helper's implementation) is excluded by the lint itself via
        exact call-site text match, not a blanket allowance."""
        out, err, rc = _run_lint(GATES_SH)
        self.assertEqual(rc, 0, err)
        self.assertIn(
            "no unchecked variable-assembled pass call sites", out,
            f"gates.sh has an unchecked variable-assembled pass call site "
            f"(the lr-2e8444 sast/bleed/merge-gate sweep is incomplete or a "
            f"new one was introduced): output={out!r}",
        )


if __name__ == "__main__":
    unittest.main()
