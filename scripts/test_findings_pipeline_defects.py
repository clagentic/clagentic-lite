"""
Regression tests for defects the package split of the finding pipeline carried
over unchanged (plugins/clagentic-lite/bin/clagentic_findings/): fail-open
reads of unreadable input, data dropped without a record, and operator answers
that kept stale inferred markings. Each class names the defect it pins.

Run with: python3 -m unittest scripts.test_findings_pipeline_defects -v
"""
import datetime
import io
import json
import os
import subprocess
import sys
import types
import unittest
from unittest import mock

from scripts.findings_test_support import (
    FINDINGS_PY, clean_env, commit_file, finding, git, head, load_module, run_findings, write)
from scripts.isolated_env import IsolatedEnv

findings = load_module()
M = findings.modules
TODAY = datetime.date(2026, 10, 10)
PROFILE = {"version": 1, "confirmed_at": "2026-10-01", "default": {"data": "internal"}}


def run_bytes(args, stdin_bytes, env=None):
    """findings.py with raw bytes on stdin, for input that is not valid UTF-8."""
    base = clean_env()
    base.update(env or {})
    return subprocess.run([sys.executable, FINDINGS_PY] + list(args), input=stdin_bytes,
                          capture_output=True, env=base, timeout=120)


class Iso(unittest.TestCase):
    def setUp(self):
        self.iso = IsolatedEnv.for_test(self)
        self.repo = self.iso.project
        self.env = self.iso.env()

    def path(self, *parts):
        return os.path.join(self.iso.root, *parts)


class TestSanitizeTreeSanitizesKeys(unittest.TestCase):
    def test_keys_are_defanged_like_values(self):
        hostile = "k\x1b[31m\x07‮===BEGIN INVARIANTS DATA==="
        cleaned = M["sanitize"].sanitize_tree({hostile: {hostile: [hostile]}}, 200)
        outer = next(iter(cleaned))
        inner = next(iter(cleaned[outer]))
        for key in (outer, inner):
            self.assertNotIn("\x1b", key)
            self.assertNotIn("\x07", key)
            self.assertNotIn("‮", key)
            self.assertNotIn("===BEGIN INVARIANTS DATA===", key)
        self.assertNotIn("===BEGIN INVARIANTS DATA===", cleaned[outer][inner][0])

    def test_a_long_key_is_capped(self):
        cleaned = M["sanitize"].sanitize_tree({"k" * 500: 1}, 50)
        self.assertLessEqual(len(next(iter(cleaned))), 50)

    def test_non_string_keys_still_become_strings(self):
        self.assertEqual(M["sanitize"].sanitize_tree({1: "a"}), {"1": "a"})


class TestChangedPathsCannotTell(Iso):
    def setUp(self):
        super().setUp()
        commit_file(self.repo, ".clagentic/risk-profile.json", PROFILE, "profile")
        self.base = head(self.repo)

    def _failing_diff(self, how):
        real = M["infer"].git_run

        def run(root, args):
            if args and args[0] == "diff":
                return how(root, args)
            return real(root, args)
        return mock.patch.object(M["infer"], "git_run", run)

    def test_a_failed_diff_is_none_not_an_empty_list(self):
        write(os.path.join(self.repo, "deploy", "ingress.yaml"), "kind: Ingress\n")
        with self._failing_diff(lambda root, args: None):
            self.assertIsNone(findings.changed_paths(self.repo, self.base))
        failed = types.SimpleNamespace(returncode=128, stdout=b"", stderr=b"fatal")
        with self._failing_diff(lambda root, args: failed):
            self.assertIsNone(findings.changed_paths(self.repo, self.base))

    def test_a_failed_listing_of_untracked_files_is_none_too(self):
        real = M["infer"].git_run

        def run(root, args):
            return None if args and args[0] == "ls-files" else real(root, args)
        with mock.patch.object(M["infer"], "git_run", run):
            self.assertIsNone(findings.changed_paths(self.repo, self.base))

    def test_no_base_is_still_an_empty_list(self):
        self.assertEqual(findings.changed_paths(self.repo, None), [])

    def test_the_stakes_resolve_a_failed_diff_to_the_worst_case_warning(self):
        with self._failing_diff(lambda root, args: None):
            stakes = findings.load_stakes(self.repo, self.base, TODAY)
        self.assertTrue(any("could not be listed" in w and "treated as touching" in w
                            for w in stakes.warnings), stakes.warnings)

    def test_a_working_diff_does_not_warn_about_listing(self):
        stakes = findings.load_stakes(self.repo, self.base, TODAY)
        self.assertFalse(any("could not be listed" in w for w in stakes.warnings))


class TestInferenceFiltersBeforeItsCap(Iso):
    def test_candidate_files_survive_a_tree_full_of_other_files(self):
        for index in range(10):
            write(os.path.join(self.repo, "a%d.txt" % index), "x\n")
        write(os.path.join(self.repo, "svc.py"), "app = Flask(__name__)\n")
        with mock.patch.object(M["infer"], "INFER_MAX_FILES", 3):
            names = M["infer"].list_repo_files(self.repo)
            markers, _ = M["infer"].infer_markers(self.repo)
        self.assertIn("svc.py", names)
        self.assertFalse(any(name.endswith(".txt") for name in names))
        self.assertEqual([m["file"] for m in markers if m["dimension"] == "exposure"], ["svc.py"])

    def test_the_cap_still_applies_to_candidates(self):
        for index in range(5):
            write(os.path.join(self.repo, "m%d.py" % index), "x = 1\n")
        with mock.patch.object(M["infer"], "INFER_MAX_FILES", 3):
            self.assertEqual(len(M["infer"].list_repo_files(self.repo)), 3)
            _, notes = M["infer"].infer_markers(self.repo)
        self.assertTrue(any("more than" in note for note in notes), notes)


def summary_opts(**over):
    base = dict(
        review_fenced_file="", review_unavailable='"review unavailable"', review_degraded="false",
        adversarial_fenced_file="", adversarial_unavailable='"adversarial unavailable"',
        adversarial_report_degraded="false", det_gates="", det_gates_fenced="",
        adf="", adf_meta="", adf_degraded="false", adf_unavailable='"findings unavailable"',
        adversarial_missing="false", adversarial_degraded="false", review_sha="abc",
        threshold="high")
    base.update(over)
    return types.SimpleNamespace(**base)


class TestGateSummary(Iso):
    def build(self, **over):
        return json.loads(M["summary"].build_gate_summary(summary_opts(**over)))

    def test_a_staged_json_null_is_degraded_not_a_missing_review_that_is_fine(self):
        staged = write(self.path("review.json"), "null")
        result = self.build(review_fenced_file=staged)
        self.assertTrue(result["review_degraded"])
        self.assertEqual(result["review_fenced"], "review unavailable")

    def test_an_object_or_empty_string_is_degraded_and_a_string_is_not(self):
        for text, degraded in (('{"a": 1}', True), ('""', True), ('"fenced text"', False)):
            with self.subTest(text=text):
                staged = write(self.path("review.json"), text)
                self.assertEqual(self.build(review_fenced_file=staged)["review_degraded"], degraded)

    def test_no_staged_file_stays_not_degraded(self):
        self.assertFalse(self.build()["review_degraded"])

    def test_det_gates_without_the_fenced_form_takes_the_fallback(self):
        for fenced in ("", None):
            with self.subTest(fenced=fenced):
                result = self.build(det_gates='{"secrets": []}', det_gates_fenced=fenced)
                self.assertTrue(result["deterministic_gates"]["audit_db_unavailable"])

    def test_counts_agree_with_the_findings_a_degraded_source_empties(self):
        sidecar = write(self.path("adf.json"), [
            {"tier": "blocking", "class": "ephemeral", "severity": "high", "reachable": "yes"},
            {"tier": "advisory", "class": "durable"}])
        degraded = self.build(adf=sidecar, adf_degraded="true")
        self.assertEqual(degraded["adversarial_findings"], [])
        self.assertEqual(degraded["adversarial_findings_fenced"], "findings unavailable")
        self.assertEqual((degraded["adversarial_blocking_count"],
                          degraded["adversarial_advisory_count"]), (0, 0))
        self.assertIsNone(degraded["resolved_change_class"])
        healthy = self.build(adf=sidecar)
        self.assertEqual((healthy["adversarial_blocking_count"],
                          healthy["adversarial_advisory_count"]), (1, 1))
        self.assertEqual(healthy["resolved_change_class"], "ephemeral")


class TestCodeownersFollowsHostPrecedence(Iso):
    def test_the_first_location_found_is_the_only_one_read(self):
        commit_file(self.repo, ".github/CODEOWNERS", "docs/ @team\n", "github")
        commit_file(self.repo, "CODEOWNERS", "* @team\n", "root")
        for base in (None, head(self.repo)):
            with self.subTest(base=base):
                texts = M["stakes"]._codeowners_texts(self.repo, base)
                self.assertEqual(texts, ["docs/ @team\n"])
                self.assertFalse(M["stakes"].Codeowners(texts).covers("src/app.py"))

    def test_a_lower_precedence_file_is_read_when_it_is_the_only_one(self):
        commit_file(self.repo, "docs/CODEOWNERS", "* @team\n", "docs")
        texts = M["stakes"]._codeowners_texts(self.repo, None)
        self.assertTrue(M["stakes"].Codeowners(texts).covers("src/app.py"))

    def test_no_file_is_none(self):
        self.assertIsNone(M["stakes"]._codeowners_texts(self.repo, None))

    def test_an_unreadable_higher_location_does_not_fall_through(self):
        commit_file(self.repo, "CODEOWNERS", "* @team\n", "root")

        def reader(rel):
            if rel == ".github/CODEOWNERS":
                raise OSError("cannot read")
            return "* @team\n" if rel == "CODEOWNERS" else None
        with mock.patch.object(M["stakes"], "worktree_reader", lambda root: reader):
            self.assertIsNone(M["stakes"]._codeowners_texts(self.repo, None))


class TestMigrationOverflowIsRecorded(Iso):
    def acks(self, count):
        return [{"cwe": "CWE-%d" % n, "path_glob": "src/**", "rationale": "r",
                 "acknowledged_by": "me", "acknowledged_at": "2026-01-01"} for n in range(count)]

    def test_entries_past_the_limit_are_an_invalid_record_and_block_the_migration(self):
        limit = M["dispositions"].MAX_ENTRIES
        write(os.path.join(self.repo, ".clagentic", "adversarial-acks.json"), self.acks(limit + 1))
        code, _, report = M["dispositions"].migrate_dispositions(self.repo, True)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(os.path.join(self.repo, ".clagentic", "dispositions.json")))
        joined = "\n".join(report)
        self.assertIn("not migrated", joined)
        self.assertIn("legacy files must be kept", joined)

    def test_the_cli_exits_nonzero(self):
        limit = M["dispositions"].MAX_ENTRIES
        write(os.path.join(self.repo, ".clagentic", "adversarial-acks.json"), self.acks(limit + 1))
        result = run_findings(["dispositions", "migrate", "--root", self.repo, "--write"], env=self.env)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_exactly_the_limit_still_migrates(self):
        limit = M["dispositions"].MAX_ENTRIES
        write(os.path.join(self.repo, ".clagentic", "adversarial-acks.json"), self.acks(limit))
        code, _, _ = M["dispositions"].migrate_dispositions(self.repo, False)
        self.assertEqual(code, 0)


class TestOperatorAnswerReplacesInference(Iso):
    def setUp(self):
        super().setUp()
        commit_file(self.repo, "deploy/ingress.yaml", "kind: Ingress\n", "ingress")

    def draft(self, *answers):
        return M["profile"].build_profile(self.repo, list(answers), False, TODAY)

    def test_an_answer_for_an_inferred_glob_is_stated_and_loses_the_evidence(self):
        inferred, _ = self.draft()
        entry = inferred["paths"][0]
        self.assertTrue(entry["inferred"])
        document, lines = self.draft("%s:exposure=internal_authenticated" % entry["glob"])
        stated = [p for p in document["paths"] if p["glob"] == entry["glob"]]
        self.assertEqual(len(stated), 1)
        self.assertEqual(stated[0]["exposure"], "internal_authenticated")
        self.assertNotIn("inferred", stated[0])
        self.assertNotIn("evidence", stated[0])
        self.assertTrue(any(line.startswith("WARN:") and "contradicted by the tree" in line
                            for line in lines), lines)

    def test_an_answer_for_another_dimension_does_not_unmark_the_inferred_one(self):
        inferred, _ = self.draft()
        entry = inferred["paths"][0]
        document, _ = self.draft("%s:data=internal" % entry["glob"])
        by_dimension = {d: p for p in document["paths"] if p["glob"] == entry["glob"]
                        for d in ("exposure", "data") if d in p}
        self.assertTrue(by_dimension["exposure"]["inferred"])
        self.assertIn("evidence", by_dimension["exposure"])
        self.assertNotIn("inferred", by_dimension["data"])


class TestProfileWriteChecksContainmentFirst(Iso):
    def test_a_symlinked_state_directory_is_refused_and_nothing_outside_is_touched(self):
        outside = self.path("outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.repo, ".clagentic"))
        with self.assertRaises(ValueError):
            M["profile"].write_profile(self.repo, {"version": 1, "paths": []})
        self.assertEqual(os.listdir(outside), [])

    def test_the_check_precedes_makedirs(self):
        order = []
        real_makedirs, real_realpath = os.makedirs, os.path.realpath
        with mock.patch("os.makedirs", lambda *a, **k: (order.append("makedirs"), real_makedirs(*a, **k))), \
                mock.patch("os.path.realpath", lambda p: (order.append("realpath"), real_realpath(p))[1]):
            M["profile"].write_profile(self.repo, {"version": 1, "paths": []})
        self.assertLess(order.index("realpath"), order.index("makedirs"))


class TestCliUnreadableInput(Iso):
    def test_blocking_json_exits_2_on_undecodable_and_unparsable_stdin(self):
        result = run_bytes(["verdict", "blocking-json", "high"], b"\xff\xfe\x00")
        self.assertEqual(result.returncode, 2)
        result = run_findings(["verdict", "blocking-json", "high"], stdin="{not json", env=self.env)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "null")

    def test_blocking_json_still_lists_for_good_input(self):
        document = json.dumps({"findings": [finding()]})
        result = run_findings(["verdict", "blocking-json", "high"], stdin=document, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 1)

    def test_fingerprint_keys_exits_2_on_unreadable_stdin_and_0_on_an_empty_array(self):
        self.assertEqual(run_bytes(["fingerprint", "keys"], b"\xff\xfe").returncode, 2)
        for text in ("not json", '{"a": 1}'):
            with self.subTest(text=text):
                self.assertEqual(run_findings(["fingerprint", "keys"], stdin=text).returncode, 2)
        self.assertEqual(run_findings(["fingerprint", "keys"], stdin="[]").returncode, 0)

    def test_stdin_readers_report_undecodable_input_instead_of_crashing(self):
        ledger = self.path("ledger.jsonl")
        cases = (
            ["fingerprint", "bump", self.path("counts.json")],
            ["dispositions", "ledger-recurrence", "--ledger", ledger, "--branch", "b"],
            ["verdict", "ledger-append", ledger, "10"],
            ["verdict", "ledger-entry", "--ts", "t", "--branch", "b", "--gate", "review",
             "--base", "x", "--head", "y", "--verdict", "PASS", "--config", "c"],
            ["render", "fence-findings"],
        )
        for args in cases:
            with self.subTest(args=args[:2]):
                result = run_bytes(args, b"\xff\xfe")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(b"Traceback", result.stderr)

    def test_cap_rejects_a_negative_max_and_accepts_zero(self):
        result = run_findings(["ingest", "cap", "--max", "-1"], stdin="[1,2,3]")
        self.assertEqual(result.returncode, 2)
        self.assertIn("negative", result.stderr)
        result = run_findings(["ingest", "cap", "--max", "0"], stdin="[1,2,3]")
        self.assertEqual((result.returncode, result.stdout), (0, "[]"))
        result = run_findings(["ingest", "cap", "--max", "2"], stdin="[1,2,3]")
        self.assertEqual(result.stdout, "[1,2]")


class TestCliWarningsAreTerminalSafe(Iso):
    HOSTILE = "a\x1b[31mb‮c"

    def args(self, **over):
        base = dict(root=self.repo, answer=[], confirm=False, today="", write=False,
                    file=self.path("f.json"))
        base.update(over)
        return types.SimpleNamespace(**base)

    def stderr_of(self, func, patched, exc, args):
        err = io.StringIO()
        with mock.patch.object(M["cli"], patched, side_effect=exc), \
                mock.patch.object(sys, "stderr", err), mock.patch.object(sys, "stdout", io.StringIO()):
            func(args)
        return err.getvalue()

    def assertSafe(self, text):
        self.assertTrue(text)
        for char in ("\x1b", "‮"):
            self.assertNotIn(char, text)

    def test_profile_refusal(self):
        self.assertSafe(self.stderr_of(M["cli"].cmd_profile, "build_profile",
                                       ValueError(self.HOSTILE), self.args()))

    def test_migrate_failure(self):
        self.assertSafe(self.stderr_of(M["cli"].cmd_dispositions_migrate, "migrate_dispositions",
                                       OSError(self.HOSTILE), self.args()))

    def test_render_review_failure(self):
        self.assertSafe(self.stderr_of(M["cli"].cmd_render_review, "render_review",
                                       ValueError(self.HOSTILE), self.args(file="p" + self.HOSTILE)))


class TestIngestRobustness(Iso):
    def test_the_degraded_stub_goes_through_the_atomic_writer(self):
        target = write(self.path("env.json"), {"findings": {"severity": "critical"}})
        with mock.patch.object(M["ingest"], "write_file_atomic",
                               wraps=M["ingest"].write_file_atomic) as atomic:
            self.assertTrue(M["ingest"].mark_review_sanitize_failed(target))
        atomic.assert_called_once_with(target, M["ingest"].SANITIZE_FAILED_ENVELOPE)
        with open(target) as handle:
            self.assertTrue(json.load(handle)["sanitize_failed"])
        self.assertFalse([n for n in os.listdir(self.iso.root) if n.startswith(".findings-")])

    def test_a_failed_atomic_write_leaves_the_original_for_the_unlink_path(self):
        target = write(self.path("env.json"), {"findings": {"severity": "critical"}})
        with mock.patch.object(M["ingest"], "write_file_atomic", side_effect=OSError("full")), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertFalse(M["ingest"].mark_review_sanitize_failed(target))
        self.assertFalse(os.path.exists(target), "the raw envelope was left in place")

    def test_an_unhashable_severity_ranks_as_unrankable_and_sorts_with_the_blockers(self):
        items = [{"severity": "low"}, {"severity": ["high"]}, {"severity": {"a": 1}},
                 {"severity": "medium"}, {"tier": "blocking", "severity": "low"}]
        ordered = M["ingest"].sort_blocking_first(items)
        self.assertEqual(ordered[0], {"tier": "blocking", "severity": "low"})
        self.assertEqual(ordered[1:3], [{"severity": ["high"]}, {"severity": {"a": 1}}])
        self.assertEqual(ordered[3:], [{"severity": "medium"}, {"severity": "low"}])

    def test_the_sort_cli_does_not_crash_on_an_unhashable_severity(self):
        result = run_findings(["ingest", "adversarial-sort"],
                              stdin=json.dumps([{"severity": "low"}, {"severity": [1]}]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[0], {"severity": [1]})


class TestFloorOnAHeaderThatStatesFacts(unittest.TestCase):
    """A header without facts keeps the parser's clamp; a header with facts is
    decided by the rubric, whose own floor must hold: open to anyone with a
    high impact is at least high and blocking, whatever severity was claimed."""

    HEADER = ("[FINDING] CWE-78 | app.py:2 | severity: %s | reachable: yes | precondition: %s"
              " | impact: %s | tier: advisory | class: durable | title: t")

    def parse(self, severity, precondition, impact):
        return M["ingest"].parse_adversarial_text(self.HEADER % (severity, precondition, impact))[0]

    def test_a_low_claim_with_floor_facts_is_raised_and_blocking(self):
        record = self.parse("low", "network", "code_exec")
        self.assertIn(record["severity"], ("high", "critical"))
        self.assertEqual(record["tier"], "blocking")

    def test_a_high_claim_stays_blocking_when_its_facts_are_on_the_floor(self):
        record = self.parse("high", "none", "data_write")
        self.assertIn(record["severity"], ("high", "critical"))
        self.assertEqual(record["tier"], "blocking")

    def test_a_high_claim_with_weak_facts_is_the_rubrics_reading_not_the_claim(self):
        record = self.parse("critical", "authenticated_user", "availability")
        self.assertEqual((record["severity"], record["tier"]), ("medium", "advisory"))
        self.assertEqual(record["severity_claimed"], "critical")

    def test_a_header_without_facts_keeps_the_clamp(self):
        text = "[FINDING] CWE-78 | app.py:2 | severity: high | tier: advisory | title: t"
        record = M["ingest"].parse_adversarial_text(text)[0]
        self.assertEqual((record["severity"], record["tier"]), ("high", "blocking"))


if __name__ == "__main__":
    unittest.main()
