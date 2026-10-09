"""
`gates.sh review` and the code verdict, end to end (real git repo, stub
llm-client.sh, real findings.py):

  - the block decision is the accumulated, disposition-aware verdict, not the
    count in the latest envelope: a re-run whose reviewer misses the finding
    still blocks
  - a valid merged disposition clears a finding and says so; one added in the
    gated change does not
  - the ledger records the pipeline's verdict, with each finding annotated by
    its fingerprint and disposition
  - an envelope that cannot be sanitized is never read as findings

Run with: python3 -m unittest scripts.test_review_code_verdict -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.findings_test_support import git  # noqa: E402
from test_source_helpers import (  # noqa: E402
    RECURRING_FINDING,
    init_git_repo,
    setup_fake_tool_home,
    setup_project,
    stage_identical_recreation,
    stub_review_llm,
)

FINDING_ENVELOPE = {"summary": "one", "checked": ["security"], "findings": [dict(RECURRING_FINDING)]}
CLEAN_ENVELOPE = {"summary": "clean", "checked": ["security"], "findings": []}
ENTRY = {
    "id": "fixture", "gates": ["review"],
    "match": {"path_glob": "app.py", "category": "security"},
    "kind": "by_design", "rationale": "intentional fixture", "by": "maintainer", "at": "2026-01-01",
}


def run_review(tool_home, project, extra_env=None):
    setup_fake_tool_home(tool_home)
    env = os.environ.copy()
    env.update({
        "CLAGENTIC_PROJECT_ROOT": project,
        "CLAGENTIC_ALLOW_MISSING_GITLEAKS": "1",
        "CLAGENTIC_ALLOW_MISSING_SEMGREP": "1",
        "CLAGENTIC_ALLOW_MISSING_OSV": "1",
        # The throwaway repo's own branch is the default branch, so the base
        # the dispositions are measured against is HEAD itself.
        "CLAGENTIC_DEFAULT_BRANCH": "master",
    })
    env.update(extra_env or {})
    return subprocess.run(["sh", os.path.join(tool_home, "scripts", "gates.sh"), "review"],
                          capture_output=True, text=True, env=env, cwd=project, timeout=180)


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-rcv-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = setup_project(self.tmp)
        init_git_repo(self.project)
        git(self.project, "branch", "-M", "master")
        self.lite = os.path.join(self.project, ".clagentic", "lite")

    def last_review(self):
        with open(os.path.join(self.lite, "last-review.json")) as handle:
            return json.load(handle)

    def ledger(self):
        with open(os.path.join(self.lite, "review-ledger.jsonl")) as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def commit_dispositions(self, entries):
        path = os.path.join(self.project, ".clagentic", "dispositions.json")
        with open(path, "w") as handle:
            json.dump({"entries": entries}, handle)
        git(self.project, "add", "-f", ".clagentic/dispositions.json")
        git(self.project, "commit", "-q", "-m", "dispositions")


class TestBlockIsTheAccumulatedVerdict(Case):
    def test_a_rerun_that_misses_the_finding_still_blocks(self):
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        first = run_review(self.tmp, self.project)
        self.assertEqual(first.returncode, 1, first.stderr)
        self.assertIn("VERDICT: BLOCKED", first.stderr)
        self.assertIn("REVIEW_BLOCKED", first.stderr)
        stub_review_llm(self.tmp, CLEAN_ENVELOPE)
        second = run_review(self.tmp, self.project)
        self.assertEqual(second.returncode, 1,
                         "a nondeterministic reviewer that missed the finding must not clear it: "
                         + second.stderr)
        self.assertEqual(self.last_review()["findings"], [], "this run's envelope really was clean")

    def test_a_new_head_starts_fresh(self):
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        self.assertEqual(run_review(self.tmp, self.project).returncode, 1)
        git(self.project, "commit", "-q", "-m", "fix")
        git(self.project, "commit", "-q", "--allow-empty", "-m", "next")
        stub_review_llm(self.tmp, CLEAN_ENVELOPE)
        stage_identical_recreation(self.project, 2)
        self.assertEqual(run_review(self.tmp, self.project).returncode, 0)

    def test_the_ledger_records_the_pipeline_verdict_with_annotated_findings(self):
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        run_review(self.tmp, self.project)
        entry = self.ledger()[-1]
        self.assertEqual((entry["gate"], entry["verdict"]), ("review", "block"))
        finding = entry["findings"][0]
        self.assertEqual(finding["disposition"]["status"], "open")
        self.assertEqual(len(finding["fingerprint"]), 32)

    def test_a_clean_review_passes_and_is_on_record(self):
        stub_review_llm(self.tmp, CLEAN_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        result = run_review(self.tmp, self.project)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ledger()[-1]["verdict"], "pass")
        with open(os.path.join(self.lite, "findings-state.json")) as handle:
            self.assertEqual(json.load(handle)["runs"][0]["caller"], "gates")

    def test_demotion_by_repetition_is_gone(self):
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        for _ in range(4):
            self.assertEqual(run_review(self.tmp, self.project).returncode, 1)
        self.assertNotIn("_recurrence_demoted", json.dumps(self.last_review()))


class TestDispositionsAtTheReviewGate(Case):
    def test_a_merged_disposition_clears_and_says_so(self):
        self.commit_dispositions([ENTRY])
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        result = run_review(self.tmp, self.project)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cleared by dispositions", result.stderr)
        self.assertIn("fixture", result.stderr)
        finding = self.last_review()["findings"][0]
        self.assertEqual(finding["disposition"], {"status": "cleared", "id": "fixture",
                                                  "kind": "by_design"})
        self.assertEqual(self.ledger()[-1]["verdict"], "pass")

    def test_the_cleared_finding_is_still_in_the_envelope_and_the_rendering(self):
        self.commit_dispositions([ENTRY])
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        result = run_review(self.tmp, self.project)
        self.assertIn("unsanitized input reaches a sink", result.stdout)
        self.assertIn("cleared by disposition fixture", result.stdout)

    def test_a_disposition_added_in_the_gated_change_does_not_clear(self):
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        with open(os.path.join(self.project, ".clagentic", "dispositions.json"), "w") as handle:
            json.dump({"entries": [ENTRY]}, handle)
        result = run_review(self.tmp, self.project)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("1 finding would be cleared by entries added in this PR", result.stderr)

    def test_a_blocked_review_prints_the_stanza_that_would_clear_it(self):
        stub_review_llm(self.tmp, FINDING_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        result = run_review(self.tmp, self.project)
        self.assertIn('"fingerprint_hint"', result.stderr)
        self.assertIn("To clear a finding", result.stderr)


class TestNoVerdictBlocks(Case):
    def test_an_unreadable_state_blocks_the_review(self):
        stub_review_llm(self.tmp, CLEAN_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        with open(os.path.join(self.lite, "findings-state.json"), "w") as handle:
            handle.write("{corrupt")
        result = run_review(self.tmp, self.project)
        self.assertEqual(result.returncode, 1, "a verdict that could not be computed must block")
        self.assertIn("could not be computed", result.stderr)

    def test_an_envelope_that_cannot_be_reduced_is_degraded_not_read_as_findings(self):
        stub_review_llm(self.tmp, {"summary": "x", "checked": [], "findings": {"severity": "low"}})
        stage_identical_recreation(self.project, 1)
        result = run_review(self.tmp, self.project)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("INFRA_DEGRADED", result.stderr)


if __name__ == "__main__":
    unittest.main()
