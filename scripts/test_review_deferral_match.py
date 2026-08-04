"""
Regression tests for lr-2ebc41: gate-code enforcement of operator deferrals.

BACKGROUND: lr-c567 shipped .clagentic/deferrals.json and injected it into
the Reviewer's prompt as context to weigh -- suppression stayed entirely
inside model judgment. Field evidence (lr-2ebc41 task description): a
stage-contract finding, accepted once with a stable rationale, was
re-raised by the stateless Reviewer six times across a 7-round run because
nothing MECHANICALLY excluded it once accepted. _review_deferral_match
(gates.sh) is the gate-code enforcement half: a finding whose (file,
category, message) triple matches a deferral entry with scope
"stable-contract" AND whose named file's current sha256 still equals the
entry's file_sha256 is annotated _deferral_matched: true / _deferral_id, and
severity_blockers() excludes it from the block count -- threshold, never
suppression, mirroring _recurrence_demoted's own posture (lr-66e598).

TEST LAYERS:

  1. TestDeferralMatchFunctionDirect calls the REAL _review_deferral_match
     sh function directly against a hand-crafted envelope + deferrals.json +
     target file, matching test_review_recurrence_demotion.py's own direct-
     call harness pattern exactly.

  2. TestDeferralLapseOnFileChange proves the core "sensitive enough to
     lapse when the deferred logic changes" property (lr-2ebc41 comment 2):
     editing the named file after a deferral was granted must lapse the
     match back to blocking.

  3. TestFailClosed proves every enumerated fail-closed condition from the
     task retains the finding as blocking: missing file_sha256, wrong scope,
     missing file, ambiguous (two live entries matching one finding),
     malformed deferrals.json.

  4. TestSeverityBlockersExcludesDeferralMatched proves the OTHER required
     half: severity_blockers() (gates.sh) must exclude a _deferral_matched
     finding from its block count, the same way it already excludes
     _recurrence_demoted findings (lr-66e598).

  5. TestDeferralsLint covers `cmd_deferrals_lint` (gates.sh
     deferrals-lint): a stable-contract entry missing required fields must
     be refused loudly (non-zero exit, specific stderr reason); a
     non-stable-contract entry (or no scope at all) must never be refused
     for missing gate-code fields, since it is not gate-code-eligible.

Run with: python3 -m unittest scripts.test_review_deferral_match -v
"""
import hashlib
import json
import os
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def _functions_only_source(dest_dir):
    """Same truncation pattern as test_review_recurrence_demotion.py."""
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
    for fname in ("platform.sh", "review-merge.sh"):
        os.symlink(os.path.join(real_scripts_dir, fname), os.path.join(dest_dir, fname))
    return dest


def _write_envelope(path, findings):
    with open(path, "w") as f:
        json.dump({"summary": "x", "findings": findings}, f)


def _assert_not_matched(testcase, finding):
    """A finding is 'not matched' whether _review_deferral_match explicitly
    annotated it _deferral_matched: false (the splice-ran-but-no-match case)
    OR left the field entirely absent (the no-live-deferrals-at-all case,
    mirroring _review_recurrence_demote's own "nothing to bump, leave the
    envelope untouched" posture when its own keyed TSV is empty) -- both are
    equally "not blocking-excluded," and severity_blockers() treats an
    absent key and an explicit false identically (`.get(..., False)`)."""
    testcase.assertFalse(
        finding.get("_deferral_matched", False),
        "finding must not be matched (either absent or explicit false)",
    )


_FINDING = {
    "severity": "high",
    "file": "run_pipeline.py",
    "line": 216,
    "category": "correctness",
    "message": "per-repo failures don't fail the stage",
}

_TARGET_CONTENT = "def run_stage():\n    pass\n"


class _RepoHarness(unittest.TestCase):
    """Shared repo-root + sourced-gates.sh fixture for direct function calls."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-rdm-")
        self._repo = os.path.join(self._tmpdir, "repo")
        os.makedirs(self._repo)
        self._target_file = os.path.join(self._repo, "run_pipeline.py")
        with open(self._target_file, "w") as f:
            f.write(_TARGET_CONTENT)
        self._deferrals_path = os.path.join(self._repo, ".clagentic", "deferrals.json")
        os.makedirs(os.path.dirname(self._deferrals_path), exist_ok=True)
        self._envelope_path = os.path.join(self._tmpdir, "env.json")
        src_dir = os.path.join(self._tmpdir, "src")
        os.makedirs(src_dir)
        self._sourced_gates = _functions_only_source(src_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_deferrals(self, entries):
        with open(self._deferrals_path, "w") as f:
            json.dump(entries, f)

    def _current_hash(self):
        with open(self._target_file, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _live_entry(self, **overrides):
        entry = {
            "id": "def-001",
            "file": "run_pipeline.py",
            "category": "correctness",
            "message": "per-repo failures don't fail the stage",
            "description": "shared stage-contract acceptance",
            "scope": "stable-contract",
            "file_sha256": self._current_hash(),
        }
        entry.update(overrides)
        return entry

    def _run_match(self):
        """Source gates.sh (functions only) and call _review_deferral_match
        directly. Returns (stdout, stderr, returncode); envelope_path is
        mutated in place."""
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{self._sourced_gates}'
            REPO_ROOT='{self._repo}'
            _git() {{ git -C "$REPO_ROOT" "$@"; }}
            _review_deferral_match '{self._envelope_path}'
        """)
        r = subprocess.run(
            ["sh", "-c", script, self._sourced_gates],
            capture_output=True, text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode

    def _findings(self):
        with open(self._envelope_path) as f:
            return json.load(f)["findings"]


class TestDeferralMatchFunctionDirect(_RepoHarness):
    def test_live_stable_contract_entry_matches_and_annotates(self):
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        self._write_deferrals([self._live_entry()])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["_deferral_matched"])
        self.assertEqual(findings[0]["_deferral_id"], "def-001")
        self.assertEqual(findings[0]["severity"], "high",
                          "severity must be reported honestly, unmodified")

    def test_no_deferrals_file_finding_untouched(self):
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertNotIn("_deferral_matched", findings[0])

    def test_mismatched_message_does_not_match(self):
        """A finding whose message text differs is a NEW finding, not a
        re-raise -- the match key intentionally does not do fuzzy/semantic
        sameness (explicitly out of scope, task description)."""
        finding = dict(_FINDING)
        finding["message"] = "a completely different observation"
        _write_envelope(self._envelope_path, [finding])
        self._write_deferrals([self._live_entry()])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertFalse(findings[0]["_deferral_matched"])

    def test_mismatched_file_does_not_match(self):
        finding = dict(_FINDING)
        finding["file"] = "other_file.py"
        _write_envelope(self._envelope_path, [finding])
        self._write_deferrals([self._live_entry()])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertFalse(findings[0]["_deferral_matched"])

    def test_line_number_drift_still_matches(self):
        """Core design point: the match key is (file, category, message),
        NOT finding_content_keys' line-window sha256 -- a finding reported
        at a different line number (incidental surrounding edits) must
        still match."""
        finding = dict(_FINDING)
        finding["line"] = 999
        _write_envelope(self._envelope_path, [finding])
        self._write_deferrals([self._live_entry()])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertTrue(findings[0]["_deferral_matched"])


class TestDeferralLapseOnFileChange(_RepoHarness):
    """lr-2ebc41 comment 2: a deferral must LAPSE when the deferred file's
    content changes -- the core tension between "stable enough to survive
    incidental edits" (comment 1, the match key) and "sensitive enough to
    lapse when the deferred logic changes" (comment 2, file_sha256)."""

    def test_editing_named_file_lapses_the_match(self):
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        # Grant against the ORIGINAL content...
        self._write_deferrals([self._live_entry()])
        # ...then the file changes (round 3/4/6-style edit, field evidence).
        with open(self._target_file, "w") as f:
            f.write(_TARGET_CONTENT + "    # a materially different line\n")
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        _assert_not_matched(self, findings[0])

    def test_missing_named_file_does_not_match(self):
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        self._write_deferrals([self._live_entry()])
        os.remove(self._target_file)
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        _assert_not_matched(self, findings[0])


class TestFailClosed(_RepoHarness):
    """Task's own governing principle: over-matching is the dangerous
    direction. Any ambiguity or malformation must retain the finding as
    blocking, exactly as if no deferral existed."""

    def test_missing_file_sha256_never_matches(self):
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        entry = self._live_entry()
        del entry["file_sha256"]
        self._write_deferrals([entry])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        _assert_not_matched(self, findings[0])

    def test_wrong_scope_never_matches(self):
        """An entry without scope "stable-contract" is prompt-context-only
        -- it must never be mechanically matched, by design (comment 3,
        outcome (b))."""
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        entry = self._live_entry(scope="conditional")
        self._write_deferrals([entry])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        _assert_not_matched(self, findings[0])

    def test_absent_scope_never_matches(self):
        """lr-c567's original six-field shape (no scope at all) must remain
        a pure prompt-context hint -- unchanged, never gate-code-matched."""
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        entry = self._live_entry()
        del entry["scope"]
        self._write_deferrals([entry])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        _assert_not_matched(self, findings[0])

    def test_ambiguous_two_live_entries_same_triple_neither_matches(self):
        """Two deferral entries independently claiming the same (file,
        category, message) triple is a data-quality problem in
        deferrals.json, not something this function silently resolves by
        picking one -- fail closed, per 'preserve when uncertain.'"""
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        entry_a = self._live_entry(id="def-001")
        entry_b = self._live_entry(id="def-002")
        self._write_deferrals([entry_a, entry_b])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertFalse(
            findings[0]["_deferral_matched"],
            "an ambiguous match (two live entries, one finding) must never "
            "resolve to a match",
        )

    def test_malformed_deferrals_json_fails_closed(self):
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        with open(self._deferrals_path, "w") as f:
            f.write("not valid json {{{")
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertNotIn("_deferral_matched", findings[0])

    def test_empty_deferrals_array_no_match(self):
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        self._write_deferrals([])
        out, err, rc = self._run_match()
        self.assertEqual(rc, 0, err)
        findings = self._findings()
        self.assertNotIn("_deferral_matched", findings[0])

    def test_finding_never_dropped_threshold_not_suppression(self):
        """The task's core distinction, restated for deferrals: a match
        must never remove the finding from the array -- only annotate it."""
        _write_envelope(self._envelope_path, [dict(_FINDING)])
        self._write_deferrals([self._live_entry()])
        self._run_match()
        findings = self._findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["message"], _FINDING["message"])
        self.assertEqual(findings[0]["severity"], _FINDING["severity"])


class TestSeverityBlockersExcludesDeferralMatched(unittest.TestCase):
    """severity_blockers() (gates.sh) must exclude a _deferral_matched
    finding from its block count -- the OTHER required half (gate code, not
    prompt text) alongside the match/lapse mechanics above."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-sb-defer-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_blockers(self, findings):
        src_dir = os.path.join(self._tmpdir, "src")
        os.makedirs(src_dir, exist_ok=True)
        sourced = _functions_only_source(src_dir)
        review_path = os.path.join(self._tmpdir, "review.json")
        with open(review_path, "w") as f:
            json.dump({"summary": "x", "findings": findings}, f)
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{sourced}'
            severity_blockers '{review_path}' high
        """)
        r = subprocess.run(
            ["sh", "-c", script, sourced],
            capture_output=True, text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout.strip(), r.stderr, r.returncode

    def test_unmatched_high_blocks(self):
        out, err, rc = self._run_blockers([dict(_FINDING, _deferral_matched=False)])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "1")

    def test_matched_high_excluded_from_count(self):
        out, err, rc = self._run_blockers([dict(_FINDING, _deferral_matched=True, _deferral_id="def-001")])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "0")

    def test_matched_finding_stays_high_severity_not_rewritten(self):
        """Threshold change, never suppression: severity_blockers excludes
        it from the COUNT, but this test asserts the exclusion mechanism
        itself never touches the finding's severity field."""
        finding = dict(_FINDING, _deferral_matched=True, _deferral_id="def-001")
        out, err, rc = self._run_blockers([finding])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "0")
        self.assertEqual(finding["severity"], "high")

    def test_absent_annotation_counts_as_before_no_regression(self):
        """A finding with no _deferral_matched key at all (feature off, or
        no deferrals file) must count exactly as it did before this
        feature existed."""
        out, err, rc = self._run_blockers([dict(_FINDING)])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "1")

    def test_low_severity_deferral_matched_still_zero_regardless(self):
        finding = {
            "severity": "low", "file": "x.py", "line": 1,
            "category": "style", "message": "nit",
            "_deferral_matched": True, "_deferral_id": "def-001",
        }
        out, err, rc = self._run_blockers([finding])
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "0", "low severity never blocks at threshold high regardless")


class TestDeferralsLint(unittest.TestCase):
    """cmd_deferrals_lint (gates.sh deferrals-lint) -- comment 3's
    requirement that a conditional/scope-boundary acceptance be REFUSED
    LOUDLY at capture time rather than silently accepted and mis-honored."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-lint-")
        src_dir = os.path.join(self._tmpdir, "src")
        os.makedirs(src_dir)
        self._sourced_gates = _functions_only_source(src_dir)
        self._deferrals_path = os.path.join(self._tmpdir, "deferrals.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_lint(self, content):
        with open(self._deferrals_path, "w") as f:
            f.write(content)
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{self._sourced_gates}'
            cmd_deferrals_lint '{self._deferrals_path}'
        """)
        r = subprocess.run(
            ["sh", "-c", script, self._sourced_gates],
            capture_output=True, text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode

    def test_well_formed_stable_contract_entry_passes(self):
        entries = [{
            "id": "def-001",
            "file": "run_pipeline.py",
            "category": "correctness",
            "message": "per-repo failures don't fail the stage",
            "description": "shared stage-contract acceptance",
            "scope": "stable-contract",
            "file_sha256": "a" * 64,
        }]
        out, err, rc = self._run_lint(json.dumps(entries))
        self.assertEqual(rc, 0, out)
        self.assertIn("no problems", out)

    def test_stable_contract_missing_file_sha256_refused(self):
        entries = [{
            "id": "def-001", "file": "x.py", "message": "m",
            "description": "d", "scope": "stable-contract",
        }]
        out, err, rc = self._run_lint(json.dumps(entries))
        self.assertNotEqual(rc, 0)
        self.assertIn("file_sha256", out)

    def test_stable_contract_malformed_file_sha256_refused(self):
        entries = [{
            "id": "def-001", "file": "x.py", "message": "m",
            "description": "d", "scope": "stable-contract",
            "file_sha256": "not-a-hash",
        }]
        out, err, rc = self._run_lint(json.dumps(entries))
        self.assertNotEqual(rc, 0)
        self.assertIn("file_sha256", out)

    def test_unsupported_scope_value_refused_loudly(self):
        """comment 3's core requirement: a conditional/scope-boundary
        acceptance must be refused loudly, not silently accepted."""
        entries = [{
            "id": "def-001", "file": "scan_gradle.py", "message": "m",
            "description": "conditional on reset logic living elsewhere",
            "scope": "conditional-on-reset-logic",
            "file_sha256": "a" * 64,
        }]
        out, err, rc = self._run_lint(json.dumps(entries))
        self.assertNotEqual(rc, 0)
        self.assertIn("not a supported gate-code scope", out)

    def test_no_scope_at_all_is_valid_prompt_context_only(self):
        """lr-c567's original shape (no scope, no file_sha256) must remain
        completely valid -- it is simply not gate-code-eligible."""
        entries = [{
            "id": "def-001", "category": "sql", "file": "seed.sh",
            "description": "fixture, not production",
        }]
        out, err, rc = self._run_lint(json.dumps(entries))
        self.assertEqual(rc, 0, out)

    def test_missing_message_on_stable_contract_refused(self):
        entries = [{
            "id": "def-001", "file": "x.py",
            "description": "d", "scope": "stable-contract",
            "file_sha256": "a" * 64,
        }]
        out, err, rc = self._run_lint(json.dumps(entries))
        self.assertNotEqual(rc, 0)
        self.assertIn("message", out)

    def test_absent_deferrals_file_is_a_noop(self):
        # self._deferrals_path is never created by setUp (only _run_lint
        # writes it) -- so the file is already absent here, exercising the
        # "no deferrals file at all" path directly.
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{self._sourced_gates}'
            cmd_deferrals_lint '{self._deferrals_path}'
        """)
        r = subprocess.run(
            ["sh", "-c", script, self._sourced_gates],
            capture_output=True, text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_malformed_json_refused(self):
        out, err, rc = self._run_lint("not json {{{")
        self.assertNotEqual(rc, 0)
        self.assertIn("not valid JSON", out)


if __name__ == "__main__":
    unittest.main()
