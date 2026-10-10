"""
The gate path for the optional review samples, the profile command and the
Auditor sidecar, end to end: a real git repo, a stub llm-client.sh that hands
out a scripted sequence of answers, the real gates.sh and findings.py.

  - CLAGENTIC_REVIEW_SAMPLES is optional: unset or invalid is one call, exactly
    as before; N calls are unioned by rubric severity, each sample is an audit
    row, a degraded sample adds nothing, and the cap is 10
  - `gates profile` reaches the profile command and rejects unknown options
  - the Auditor sidecar carries the tier and severity the rubric computed, not
    the ones the model wrote

Run with: python3 -m unittest scripts.test_review_samples_gate -v
"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.findings_test_support import FINDINGS_PY, git  # noqa: E402
from scripts.isolated_env import IsolatedEnv  # noqa: E402
from test_source_helpers import (  # noqa: E402
    init_git_repo, setup_fake_tool_home, setup_project, stage_identical_recreation)

STRONG = {"severity_claimed": "low", "file": "app.py", "line": 2, "category": "security",
          "message": "unsanitized input reaches a sink", "reachable": "yes",
          "attacker_precondition": "network", "impact": "code_exec", "class": "durable",
          "issue_class": "none — isolated", "class_fix": "n/a — isolated"}
WEAK = dict(STRONG, severity_claimed="critical", attacker_precondition="local_ci_only",
            impact="quality_only")
DEGRADED = {"degraded": True, "summary": "[clagentic-lite degraded] every step failed", "checked": [],
            "findings": []}


def envelope(*items):
    return {"summary": "s", "checked": ["security"], "findings": list(items)}


AUDIT = (
    "[FINDING] CWE-78 | app.py:2 | severity: low | reachable: yes | precondition: network | "
    "impact: code_exec | tier: advisory | class: durable | title: shell injection\n\nBody.\n\n"
    "[FINDING] CWE-1 | app.py:2 | severity: critical | reachable: yes | precondition: local_ci_only | "
    "impact: quality_only | tier: blocking | class: durable | title: naming\n\nBody.\n")


def stub_llm(tmp, samples, audit_text=AUDIT):
    """llm-client.sh that answers `review` with the Nth scripted envelope (the
    last repeats) and `adversarial` with AUDIT_TEXT, counting calls."""
    scripts_dir = os.path.join(tmp, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    calls = os.path.join(tmp, "calls.txt")
    scripted = os.path.join(tmp, "samples.json")
    with open(scripted, "w") as handle:
        json.dump(samples, handle)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    with open(stub, "w") as handle:
        handle.write(textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import json, sys
            role = sys.argv[1] if len(sys.argv) > 1 else ""
            sys.stdin.read()
            with open({calls!r}, "a") as log:
                log.write(role + "\\n")
            if role == "adversarial":
                sys.stdout.write({audit_text!r})
                sys.exit(0)
            with open({calls!r}) as log:
                count = sum(1 for _ in log)
            answers = json.load(open({scripted!r}))
            sys.stdout.write(json.dumps(answers[min(count, len(answers)) - 1]))
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return calls


class Case(unittest.TestCase):
    def setUp(self):
        self.iso = IsolatedEnv.for_test(self, git_project=False)
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-samples-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = setup_project(self.tmp)
        init_git_repo(self.project)
        git(self.project, "branch", "-M", "master")
        self.lite = os.path.join(self.project, ".clagentic", "lite")
        stage_identical_recreation(self.project, 1)

    def gate(self, subcommand, args=(), **extra_env):
        """Run `gates.sh SUBCOMMAND` from a fake tool home (this temp dir, holding
        the stub llm-client.sh) with HOME, CLAGENTIC_LITE_HOME and the project all
        under temp dirs."""
        setup_fake_tool_home(self.tmp)
        env = self.iso.env(
            project=self.project, CLAGENTIC_ALLOW_MISSING_GITLEAKS="1",
            CLAGENTIC_ALLOW_MISSING_SEMGREP="1", CLAGENTIC_ALLOW_MISSING_OSV="1",
            CLAGENTIC_DEFAULT_BRANCH="master", **extra_env)
        return subprocess.run(
            ["sh", os.path.join(self.tmp, "scripts", "gates.sh"), subcommand] + list(args),
            capture_output=True, text=True, env=env, cwd=self.project, timeout=180)

    def call_count(self, calls):
        with open(calls) as handle:
            return len([line for line in handle if line.strip()])

    def audit_rows(self, gate):
        conn = sqlite3.connect(os.path.join(self.lite, "audit.db"))
        try:
            return conn.execute("SELECT outcome, details FROM gate_runs WHERE gate = ? ORDER BY id",
                                (gate,)).fetchall()
        finally:
            conn.close()

    def last_review(self):
        with open(os.path.join(self.lite, "last-review.json")) as handle:
            return json.load(handle)


class TestReviewSamples(Case):
    def test_unset_is_one_call_and_no_sample_rows(self):
        calls = stub_llm(self.tmp, [envelope(STRONG)])
        result = self.gate("review")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.call_count(calls), 1)
        self.assertEqual(self.audit_rows("review-sample"), [])

    def test_an_invalid_value_warns_and_is_one_call(self):
        calls = stub_llm(self.tmp, [envelope(STRONG)])
        result = self.gate("review", CLAGENTIC_REVIEW_SAMPLES="lots")
        self.assertEqual(self.call_count(calls), 1)
        self.assertIn("CLAGENTIC_REVIEW_SAMPLES", result.stderr)

    def test_n_samples_are_unioned_by_rubric_severity_and_each_is_logged(self):
        calls = stub_llm(self.tmp, [envelope(WEAK), envelope(STRONG), DEGRADED])
        result = self.gate("review", CLAGENTIC_REVIEW_SAMPLES="3")
        self.assertEqual(self.call_count(calls), 3)
        self.assertEqual(result.returncode, 1, result.stderr)
        [kept] = self.last_review()["findings"]
        self.assertEqual(kept["attacker_precondition"], "network",
                         "the rubric-strongest reading wins, not the highest claimed severity")
        self.assertEqual((kept["severity"], kept["severity_claimed"]), ("critical", "low"))
        rows = self.audit_rows("review-sample")
        self.assertEqual([outcome for outcome, _ in rows], ["pass", "pass", "degraded", "pass"])
        self.assertIn("sample=3/3", rows[2][1])
        self.assertIn("union of 2/3", rows[3][1])

    def test_the_union_can_only_add_a_finding_a_single_sample_missed(self):
        other = dict(STRONG, line=9, message="a second, unrelated problem", category="correctness",
                     impact="quality_only", attacker_precondition="local_ci_only")
        calls = stub_llm(self.tmp, [envelope(), envelope(other), envelope()])
        self.gate("review", CLAGENTIC_REVIEW_SAMPLES="3")
        self.assertEqual(self.call_count(calls), 3)
        self.assertEqual(len(self.last_review()["findings"]), 1)

    def test_all_samples_degraded_is_the_degraded_path_not_a_clean_pass(self):
        stub_llm(self.tmp, [DEGRADED])
        result = self.gate("review", CLAGENTIC_REVIEW_SAMPLES="2")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("INFRA_DEGRADED", result.stderr)

    def test_the_count_is_capped(self):
        calls = stub_llm(self.tmp, [envelope()])
        result = self.gate("review", CLAGENTIC_REVIEW_SAMPLES="50")
        self.assertEqual(self.call_count(calls), 10, result.stderr)
        self.assertIn("above the cap", result.stderr)


class TestProfileSubcommand(Case):
    def test_it_prints_a_draft_and_writes_nothing_without_write(self):
        stub_llm(self.tmp, [envelope()])
        result = self.gate("profile", ["--answer", "data=internal"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["default"], {"data": "internal"})
        self.assertFalse(os.path.exists(os.path.join(self.project, ".clagentic", "risk-profile.json")))

    def test_write_saves_the_file_for_review(self):
        stub_llm(self.tmp, [envelope()])
        result = self.gate("profile", ["--answer", "deploy/**:exposure=internal_authenticated", "--write"])
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(os.path.join(self.project, ".clagentic", "risk-profile.json")) as handle:
            self.assertEqual(json.load(handle)["paths"][0]["glob"], "deploy/**")

    def test_an_unknown_option_is_refused(self):
        stub_llm(self.tmp, [envelope()])
        result = self.gate("profile", ["--bogus"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown option", result.stderr)

    def test_a_bad_answer_is_refused(self):
        stub_llm(self.tmp, [envelope()])
        result = self.gate("profile", ["--answer", "exposure=moon"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("profile refused", result.stderr)


class TestAuditorSidecar(Case):
    def test_the_sidecar_carries_the_rubric_tier_not_the_claimed_one(self):
        stub_llm(self.tmp, [envelope()])
        result = self.gate("adversarial")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(os.path.join(self.lite, "last-adversarial-findings.json")) as handle:
            by_cwe = {item["category"]: item for item in json.load(handle)}
        shell = by_cwe["CWE-78"]
        self.assertEqual((shell["tier"], shell["severity"], shell["severity_claimed"]),
                         ("blocking", "critical", "low"))
        naming = by_cwe["CWE-1"]
        self.assertEqual((naming["tier"], naming["severity"], naming["severity_claimed"]),
                         ("advisory", "low", "critical"))

    def test_the_merge_gate_view_blocks_on_the_rubric_finding(self):
        stub_llm(self.tmp, [envelope()])
        self.gate("adversarial")
        evaluated = subprocess.run(
            [sys.executable, FINDINGS_PY, "evaluate", "--gate", "merge-gate", "--no-input", "--json",
             "--root", self.project],
            capture_output=True, text=True, timeout=60, env=self.iso.env(project=self.project),
            cwd=self.project)
        verdict = json.loads(evaluated.stdout)
        self.assertEqual(evaluated.returncode, 1, evaluated.stdout)
        self.assertEqual([item["category"] for item in verdict["open"]], ["CWE-78"])


if __name__ == "__main__":
    unittest.main()
