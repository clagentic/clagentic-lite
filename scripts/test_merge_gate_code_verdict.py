"""
`gates.sh merge-gate` and the code verdict.

The block decision on findings is made in code, before the model is called:
the open blocking findings accumulated at HEAD (every review and adversarial
run), minus those a valid, already-merged disposition clears. These tests run
the real gates.sh against a throwaway git repository with a stub llm-client.sh
that records every call and its stdin, and prove:

  - a BLOCKED code verdict refuses without calling the model at all, so the
    model cannot flip it, whatever it would have said
  - on PASS the model is called with the verdict in its payload, and it can
    still add a refusal
  - a verdict that cannot be computed refuses; the gate does not run without one
  - cleared findings are named in the audit trail from the verdict, and a
    BLOCKED refusal lists the stanza that would clear each open finding
  - the model prompt and the merge-gate subagent carry the one-way rule

Run with: python3 -m unittest scripts.test_merge_gate_code_verdict -v
"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

from scripts.findings_test_support import (
    TOOL_HOME, adversarial_finding, commit_file, entry, finding, head, make_repo,
    run_findings, write)


def _stub_llm(tmpdir, decision):
    scripts_dir = os.path.join(tmpdir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    calls = os.path.join(tmpdir, "llm_calls.txt")
    payload = os.path.join(tmpdir, "llm_payload.json")
    body = json.dumps({"decision": decision, "reason": "stub"})
    with open(stub, "w") as handle:
        handle.write(textwrap.dedent("""\
            #!/bin/sh
            echo called >> %s
            cat > %s
            printf '%%s\\n' '%s'
        """ % (calls, payload, body)))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return calls, payload


def _fake_tool_home(tmpdir):
    scripts_dir = os.path.join(tmpdir, "scripts")
    for name in os.listdir(os.path.join(TOOL_HOME, "scripts")):
        if name.endswith(".sh") and name != "llm-client.sh":
            dst = os.path.join(scripts_dir, name)
            if not os.path.exists(dst):
                os.symlink(os.path.join(TOOL_HOME, "scripts", name), dst)
    share = os.path.join(tmpdir, "share")
    if not os.path.exists(share):
        os.symlink(os.path.join(TOOL_HOME, "share"), share)


def _audit_db(project):
    directory = os.path.join(project, ".clagentic", "lite")
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(os.path.join(directory, "audit.db"))
    conn.execute("CREATE TABLE IF NOT EXISTS gate_runs (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, "
                 "gate TEXT NOT NULL, outcome TEXT NOT NULL, details TEXT, session_id TEXT, branch TEXT)")
    conn.commit()
    conn.close()


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-mgcv-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = make_repo(os.path.join(self.tmp, "project"))
        _audit_db(self.project)

    def lite(self, name):
        return os.path.join(self.project, ".clagentic", "lite", name)

    def record(self, items, gate="review"):
        result = run_findings(["evaluate", "--gate", gate, "--root", self.project, "--caller", "gates"],
                              stdin=json.dumps({"findings": items}), cwd=self.project)
        self.assertIn(result.returncode, (0, 1), result.stderr)

    def merge_gate(self, decision="approve", extra_env=None):
        calls, payload = _stub_llm(self.tmp, decision)
        _fake_tool_home(self.tmp)
        env = dict(os.environ)
        env.update({"CLAGENTIC_PROJECT_ROOT": self.project, "CLAGENTIC_ALLOW_STALE_PAYLOAD": "1",
                    "CLAGENTIC_ALLOW_MISSING_GITLEAKS": "1", "CLAGENTIC_ALLOW_MISSING_SEMGREP": "1",
                    "CLAGENTIC_ALLOW_MISSING_OSV": "1", "CLAGENTIC_MERGE_GATE_BLOCKING": "1",
                    "CLAGENTIC_FINDINGS_TODAY": "2026-10-09"})
        env.update(extra_env or {})
        result = subprocess.run(["sh", os.path.join(self.tmp, "scripts", "gates.sh"), "merge-gate"],
                                capture_output=True, text=True, env=env, cwd=self.project, timeout=180)
        called = os.path.exists(calls) and open(calls).read().count("called") or 0
        return result, called, payload

    def last_decision(self):
        with open(self.lite("last-merge-gate.json")) as handle:
            return json.load(handle)

    def audit_rows(self):
        conn = sqlite3.connect(self.lite("audit.db"))
        rows = conn.execute("SELECT gate, outcome, details FROM gate_runs ORDER BY id").fetchall()
        conn.close()
        return rows


class TestBlockedIsFinal(Case):
    def test_a_blocked_verdict_refuses_without_calling_the_model(self):
        self.record([finding()])
        result, called, _ = self.merge_gate("approve")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(called, 0, "the model must not be consulted once the code verdict is BLOCKED")
        self.assertEqual(self.last_decision()["decision"], "refuse")
        self.assertIn("VERDICT: BLOCKED", result.stderr)
        self.assertIn("1 open blocking finding(s)", result.stderr)

    def test_blocked_prints_the_stanza_that_would_clear_each_open_finding(self):
        self.record([finding(), finding(line=8, message="second")])
        result, _, _ = self.merge_gate("approve")
        self.assertEqual(result.stderr.count('"fingerprint_hint"'), 2)
        self.assertIn("To clear a finding", result.stderr)

    def test_an_adversarial_floor_finding_blocks_the_merge(self):
        self.record([adversarial_finding()], gate="adversarial")
        result, called, _ = self.merge_gate("approve")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(called, 0)
        self.assertIn("security floor", result.stderr)

    def test_a_review_that_missed_it_on_a_rerun_still_blocks(self):
        self.record([finding()])
        self.record([])
        result, called, _ = self.merge_gate("approve")
        self.assertEqual((result.returncode, called), (1, 0))

    def test_blocking_can_be_made_advisory_only_by_the_existing_switch(self):
        self.record([finding()])
        result, called, _ = self.merge_gate("approve", {"CLAGENTIC_MERGE_GATE_BLOCKING": "0"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(called, 0, "advisory mode still does not let the model overrule the verdict")
        self.assertEqual(self.last_decision()["decision"], "refuse")

    def test_the_audit_trail_records_the_block(self):
        self.record([finding()])
        self.merge_gate("approve")
        gate, outcome, details = self.audit_rows()[-1]
        self.assertEqual((gate, outcome), ("merge-gate", "block"))
        self.assertIn("code verdict BLOCKED", details)


class TestPassHandsTheModelTheVerdict(Case):
    def test_the_payload_carries_the_code_verdict_and_it_can_approve(self):
        self.record([finding(severity="low")])
        result, called, payload = self.merge_gate("approve")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(called, 1)
        with open(payload) as handle:
            summary = json.load(handle)
        self.assertEqual(summary["code_verdict"]["verdict"], "PASS")
        self.assertEqual(summary["code_verdict"]["head"], head(self.project))
        self.assertTrue(summary["code_verdict_fenced"].startswith("===BEGIN CODE VERDICT DATA==="))
        for gone in ("adversarial_acks", "accepted_risks", "introduces_ack_file"):
            self.assertNotIn(gone, summary, "the model no longer judges ack coverage")

    def test_the_model_can_still_add_a_refusal(self):
        self.record([])
        result, called, _ = self.merge_gate("refuse")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(called, 1)

    def test_cleared_findings_are_named_in_the_audit_trail_from_the_verdict(self):
        commit_file(self.project, ".clagentic/dispositions.json",
                    json.dumps({"entries": [entry(id="accepted-fixture")]}), "dispositions")
        self.record([finding()])
        result, called, payload = self.merge_gate("approve")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(called, 1)
        with open(payload) as handle:
            cleared = json.load(handle)["code_verdict"]["cleared"]
        self.assertEqual(cleared[0]["entry"]["id"], "accepted-fixture")
        details = self.audit_rows()[-1][2]
        self.assertIn("cleared by disposition: accepted-fixture", details)
        self.assertIn("Cleared by dispositions", result.stderr)


class TestNoVerdictNoMerge(Case):
    def test_a_state_that_cannot_be_read_refuses_without_the_model(self):
        write(self.lite("findings-state.json"), "{corrupt")
        result, called, _ = self.merge_gate("approve")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(called, 0)
        self.assertIn("could not be computed", self.last_decision()["reason"])

    def test_an_adversarial_run_that_could_not_be_recorded_refuses(self):
        self.record([])
        write(self.lite("adversarial-unrecorded"), head(self.project) + "\n")
        result, called, _ = self.merge_gate("approve")
        self.assertEqual((result.returncode, called), (1, 0))
        self.assertIn("could not be recorded", self.last_decision()["reason"])

    def test_a_marker_for_another_commit_is_ignored(self):
        self.record([])
        write(self.lite("adversarial-unrecorded"), "0" * 40 + "\n")
        result, called, _ = self.merge_gate("approve")
        self.assertEqual((result.returncode, called), (0, 1))


class TestRecheckRecomputesTheVerdict(Case):
    def test_recheck_applies_the_verdict_too(self):
        self.record([])
        first, called, _ = self.merge_gate("approve")
        self.assertEqual((first.returncode, called), (0, 1))
        self.record([finding()])
        calls, _ = _stub_llm(self.tmp, "approve")
        env = dict(os.environ)
        env.update({"CLAGENTIC_PROJECT_ROOT": self.project, "CLAGENTIC_ALLOW_STALE_PAYLOAD": "1",
                    "CLAGENTIC_MERGE_GATE_BLOCKING": "1"})
        # --recheck reads the saved summary and insists it carries the SHA of
        # the commit it describes; stamp it as a real review run would.
        with open(self.lite("gate-summary.json")) as handle:
            summary = json.load(handle)
        summary["review_sha"] = head(self.project)
        write(self.lite("gate-summary.json"), summary)
        # Dirty the tree so the state-identity cache does not short-circuit.
        write(os.path.join(self.project, "app.py"), "print('dirty')\n")
        result = subprocess.run(["sh", os.path.join(self.tmp, "scripts", "gates.sh"), "merge-gate",
                                 "--recheck"], capture_output=True, text=True, env=env,
                                cwd=self.project, timeout=180)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("VERDICT: BLOCKED", result.stderr)


class TestPromptAndSubagentCarryTheOneWayRule(unittest.TestCase):
    def _read(self, *parts):
        with open(os.path.join(TOOL_HOME, *parts)) as handle:
            return handle.read()

    def test_the_gate_prompt_no_longer_judges_acks_or_severity(self):
        prompt = self._read("scripts", "llm-client.sh")
        start = prompt.index("ds_merge_gate_prompt() {")
        body = prompt[start:prompt.index("# ----------------------------------------------------- env / tier resolution")]
        self.assertIn("code_verdict", body)
        self.assertIn("you can\nnever turn a refusal into an approval", body)
        for gone in ("adversarial_acks", "accepted_risks", "introduces_ack_file", "acknowledged",
                     "Read each finding's"):
            self.assertNotIn(gone, body)

    def test_the_subagent_refuses_without_a_code_computed_verdict(self):
        text = self._read("plugins", "clagentic-lite", "agents", "merge-gate.md")
        self.assertIn("never** approve against the code verdict", text)
        self.assertIn("no code-computed PASS verdict was supplied", text)
        self.assertIn("`code_verdict.verdict` is not `\"PASS\"`", text)
        self.assertIn("A `BLOCKED` verdict is final", text)
        for gone in ("adversarial_acks", "introduces_ack_file", "Bootstrap exemption",
                     "\"acknowledged\": ["):
            self.assertNotIn(gone, text)


if __name__ == "__main__":
    unittest.main()
