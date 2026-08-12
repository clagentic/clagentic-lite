"""
Regression coverage for lr-7047bf (PR-B, task item 4): cmd_audit_vocab_lint,
the warn-only audit-vocabulary lint (scripts/gates.sh).

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


if __name__ == "__main__":
    unittest.main()
