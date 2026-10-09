"""
The merge gate's stale-payload refusal must name its actual cause.

BACKGROUND: build_gate_summary set stale_payload for every stale cause, and
cmd_merge_gate answered all of them with one line ("stale gate payload --
re-run ...") and an audit row ending "(SHA mismatch)", including when the SHAs
matched and the real cause was a review that had BLOCKED at HEAD. Re-running
cannot fix that, so the message sent operators in a loop.

Each stale gate now carries a machine-readable reason in the summary
(`stale_reasons`, plus the headline `stale_reason`): sha_mismatch |
missing_stamp | review_blocked_at_head | empty_head. cmd_merge_gate renders a
distinct refusal and audit detail per reason, on the normal path and on
--recheck. The classification is the one python3 implementation in the
finding pipeline; without python3 the gate refuses.

Run with: python3 -m unittest scripts.test_merge_gate_stale_reasons -v
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

from test_source_helpers import (  # noqa: E402
    GATES_SH,
    PLATFORM_SH,
    RECURRING_FINDING as _RECURRING_FINDING,
    TOOL_HOME,
    init_git_repo as _init_git_repo,
    path_without,
    setup_fake_tool_home as _setup_fake_tool_home,
    setup_project as _setup_project,
    source_env,
    stage_identical_recreation as _stage_identical_recreation,
    stub_review_llm as _stub_llm,
)


def _approve_stub(tool_home):
    _setup_fake_tool_home(tool_home)
    stub = os.path.join(tool_home, "scripts", "llm-client.sh")
    with open(stub, "w") as f:
        f.write("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"decision\":\"approve\",\"reason\":\"ok\"}'\n")
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-stale-")
        self._project = _setup_project(self._tmp)
        _init_git_repo(self._project)
        self._lite = os.path.join(self._project, ".clagentic", "lite")
        self._review_home = os.path.join(self._tmp, "review-home")
        self._mg_home = os.path.join(self._tmp, "mg-home")
        _approve_stub(self._mg_home)
        self._shadows = []

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        for d in self._shadows:
            shutil.rmtree(d, ignore_errors=True)

    def _env(self, hide=None):
        env = os.environ.copy()
        env.update({
            "CLAGENTIC_PROJECT_ROOT": self._project,
            "CLAGENTIC_ALLOW_MISSING_GITLEAKS": "1",
            "CLAGENTIC_ALLOW_MISSING_SEMGREP": "1",
            "CLAGENTIC_ALLOW_MISSING_OSV": "1",
            "CLAGENTIC_MERGE_GATE_BLOCKING": "1",
        })
        env.pop("CLAGENTIC_ALLOW_STALE_PAYLOAD", None)
        if hide:
            shadow = path_without(hide)
            self._shadows.append(shadow)
            env["PATH"] = shadow
        return env

    def _gate(self, home, sub, args=(), hide=None):
        return subprocess.run(
            ["sh", os.path.join(home, "scripts", "gates.sh"), sub, *args],
            capture_output=True, text=True, env=self._env(hide), cwd=self._project,
        )

    def _merge_gate(self, *args, hide=None):
        return self._gate(self._mg_home, "merge-gate", args, hide)

    def _audit_details(self, gate="merge-gate"):
        conn = sqlite3.connect(os.path.join(self._lite, "audit.db"))
        rows = conn.execute(
            "SELECT details FROM gate_runs WHERE gate=? ORDER BY id DESC LIMIT 1", (gate,)
        ).fetchall()
        conn.close()
        return rows[0][0] if rows else ""

    def _refusal(self):
        with open(os.path.join(self._lite, "last-merge-gate.json")) as f:
            return json.load(f)

    def _head(self):
        return subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True, cwd=self._project).stdout.strip()

    def _block_review_at_head(self):
        _stub_llm(self._review_home, {
            "summary": "one", "checked": ["security"], "findings": [dict(_RECURRING_FINDING)],
        })
        _stage_identical_recreation(self._project, 1)
        _setup_fake_tool_home(self._review_home)
        r = self._gate(self._review_home, "review")
        self.assertEqual(r.returncode, 1, f"review must block to set up the case: {r.stderr}")


class TestShaMismatch(_Base):
    def _stale_artifacts(self):
        with open(os.path.join(self._lite, "last-review.json"), "w") as f:
            json.dump({"findings": [], "summary": "x", "_clagentic_diff_sha": "0" * 40}, f)

    def test_sha_mismatch_names_the_cause_and_says_rerun(self):
        self._stale_artifacts()
        r = self._merge_gate()
        self.assertEqual(r.returncode, 1, r.stderr)
        refusal = self._refusal()
        self.assertEqual(refusal["stale_reason"], "sha_mismatch")
        self.assertIn("SHA mismatch", refusal["reason"])
        self.assertIn("re-run", refusal["reason"])
        self.assertNotIn("unresolved blocking findings", refusal["reason"])
        detail = self._audit_details()
        self.assertIn("[sha_mismatch]", detail)
        self.assertIn("SHA mismatch", detail)

    def test_missing_stamp_is_distinct_from_sha_mismatch(self):
        with open(os.path.join(self._lite, "last-review.json"), "w") as f:
            json.dump({"findings": [], "summary": "x"}, f)
        r = self._merge_gate()
        self.assertEqual(r.returncode, 1, r.stderr)
        refusal = self._refusal()
        self.assertEqual(refusal["stale_reason"], "missing_stamp")
        self.assertNotIn("SHA mismatch", refusal["reason"])
        self.assertIn("[missing_stamp]", self._audit_details())

    def test_recheck_distinguishes_missing_stamp_from_mismatch(self):
        summary = os.path.join(self._lite, "gate-summary.json")
        with open(summary, "w") as f:
            json.dump({"review_sha": "0" * 40}, f)
        r = self._merge_gate("--recheck")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[sha_mismatch]", self._audit_details("merge-gate recheck"))
        with open(summary, "w") as f:
            json.dump({"threshold": "high"}, f)
        r = self._merge_gate("--recheck")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[missing_stamp]", self._audit_details("merge-gate recheck"))


class TestReviewBlockedAtHead(_Base):
    def _assert_blocked_refusal(self, r):
        self.assertEqual(r.returncode, 1, r.stderr)
        refusal = self._refusal()
        self.assertEqual(refusal["stale_reason"], "review_blocked_at_head")
        text = refusal["reason"]
        self.assertIn("unresolved blocking findings", text)
        self.assertIn("app.py:2", text, "lists file:line")
        self.assertIn("[high]", text, "lists severity")
        self.assertIn(_RECURRING_FINDING["message"], text, "lists the message")
        self.assertNotIn("re-run clagentic-lite gates review", text,
                         "must not send the operator back to re-run")
        self.assertNotIn("SHA mismatch", text)
        detail = self._audit_details()
        self.assertIn("[review_blocked_at_head]", detail)
        self.assertNotIn("SHA mismatch", detail, "the SHAs match; the audit row must not say otherwise")
        self.assertIn("app.py:2", detail)

    def test_blocked_review_at_head_lists_findings(self):
        self._block_review_at_head()
        self._assert_blocked_refusal(self._merge_gate())

    def test_listing_does_not_need_jq(self):
        self._block_review_at_head()
        self._assert_blocked_refusal(self._merge_gate(hide="jq"))

    def test_merge_gate_refuses_when_python3_is_unavailable(self):
        """The finding pipeline is required: with python3 hidden the gate
        cannot build or classify the summary and must refuse, not pass."""
        self._block_review_at_head()
        r = self._merge_gate(hide="python3")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn('"decision": "approve"', r.stdout)

    def test_missing_python3_is_the_reason_on_a_clean_review(self):
        """On a review that did not block, the refusal can only come from the
        missing pipeline, so it must say so."""
        _stub_llm(self._review_home, {"summary": "clean", "checked": ["security"], "findings": []})
        _stage_identical_recreation(self._project, 1)
        _setup_fake_tool_home(self._review_home)
        review = self._gate(self._review_home, "review")
        self.assertEqual(review.returncode, 0, f"review must pass to set up the case: {review.stderr}")
        # Hidden first: a passing run records its state and a repeat is a no-op.
        r = self._merge_gate(hide="python3")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("python3", r.stdout + r.stderr)
        self.assertNotIn("unresolved blocking findings", r.stdout + r.stderr)
        control = self._merge_gate()
        self.assertEqual(control.returncode, 0, control.stdout + control.stderr)

    def test_summary_carries_machine_readable_reason(self):
        self._block_review_at_head()
        self._merge_gate()
        with open(os.path.join(self._lite, "gate-summary.json")) as f:
            summary = json.load(f)
        self.assertIs(summary["stale_payload"], True)
        self.assertEqual(summary["stale_reason"], "review_blocked_at_head")
        self.assertEqual(summary["stale_reasons"]["review-ledger"], "review_blocked_at_head")
        self.assertEqual(summary["blocking_findings"][0]["file"], "app.py")
        self.assertEqual(summary["blocking_findings"][0]["severity"], "high")

    def test_recheck_on_a_stale_summary_reports_the_recorded_reason(self):
        self._block_review_at_head()
        self._merge_gate()
        r = self._merge_gate("--recheck")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(self._refusal()["stale_reason"], "review_blocked_at_head")
        self.assertIn("[review_blocked_at_head]", self._audit_details("merge-gate recheck"))

    def _annotate_ledger_finding(self, **fields):
        ledger = os.path.join(self._lite, "review-ledger.jsonl")
        with open(ledger) as f:
            entry = json.loads(f.read().strip().splitlines()[-1])
        entry["findings"][0].update(fields)
        with open(ledger, "w") as f:
            f.write(json.dumps(entry) + "\n")
        self._merge_gate()
        with open(os.path.join(self._lite, "gate-summary.json")) as f:
            return json.load(f)["blocking_findings"]

    def test_findings_cleared_by_a_disposition_are_not_listed(self):
        """The list is the set that blocked: a finding the review's verdict
        recorded as cleared by a disposition did not block."""
        self._block_review_at_head()
        listed = self._annotate_ledger_finding(disposition={"status": "cleared", "id": "d1"})
        self.assertEqual(listed, [])

    def test_the_old_exemption_annotation_no_longer_excludes_a_finding(self):
        self._block_review_at_head()
        listed = self._annotate_ledger_finding(_deferral_matched=True)
        self.assertEqual(len(listed), 1)


class TestMalformedFindingsStillNamed(_Base):
    """A malformed severity must not blank the list while the review blocks."""

    def _rewrite_ledger_entry(self, mutate):
        ledger = os.path.join(self._lite, "review-ledger.jsonl")
        with open(ledger) as f:
            entry = json.loads(f.read().strip().splitlines()[-1])
        mutate(entry)
        with open(ledger, "w") as f:
            f.write(json.dumps(entry) + "\n")

    def test_numeric_severity_is_listed(self):
        self._block_review_at_head()
        self._rewrite_ledger_entry(lambda e: e["findings"][0].update(severity=3))
        r = self._merge_gate()
        self.assertEqual(r.returncode, 1, r.stderr)
        refusal = self._refusal()
        self.assertEqual(refusal["stale_reason"], "review_blocked_at_head")
        self.assertIn("app.py:2", refusal["reason"], "the finding is still listed")
        self.assertIn(_RECURRING_FINDING["message"], refusal["reason"])
        self.assertNotIn("could not be listed", refusal["reason"])
        with open(os.path.join(self._lite, "gate-summary.json")) as f:
            listed = json.load(f)["blocking_findings"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["severity"], "3")

    def test_unlistable_findings_say_so(self):
        self._block_review_at_head()
        self._rewrite_ledger_entry(lambda e: e.update(findings=5))
        r = self._merge_gate()
        self.assertEqual(r.returncode, 1, r.stderr)
        refusal = self._refusal()
        self.assertEqual(refusal["stale_reason"], "review_blocked_at_head")
        self.assertIn("blocking findings could not be listed; see last-review.json", refusal["reason"])
        self.assertNotIn("(0)", refusal["reason"])
        self.assertIn("could not be listed", self._audit_details())


class TestEmptyHead(_Base):
    def test_unresolvable_head_in_a_git_repo_reports_empty_head(self):
        """HEAD cannot be forced to resolve to nothing in a healthy repo, so
        the helper is overridden after sourcing the real gates.sh; everything
        downstream of it (summary emitter, refusal renderer) is the real code."""
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{GATES_SH}'
            _git_repo_scoped_head_sha() {{ printf ''; }}
            build_gate_summary > "$SUMMARY_OUT"
            _mg_stale_report "$SUMMARY_OUT"
            printf '%s\\n%s\\n%s\\n' "$_MG_STALE_PRIMARY" "$_MG_STALE_TEXT" "$_MG_STALE_AUDIT"
        """)
        summary = os.path.join(self._tmp, "summary.json")
        env = self._env()
        env.update(source_env(gates=True))
        env["SUMMARY_OUT"] = summary
        r = subprocess.run(["sh", "-c", script, GATES_SH], capture_output=True, text=True,
                           env=env, cwd=os.path.join(TOOL_HOME, "scripts"))
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(summary) as f:
            body = json.load(f)
        self.assertEqual(body["stale_reason"], "empty_head")
        self.assertEqual(body["stale_reasons"], {"review": "empty_head", "adversarial": "empty_head"})
        primary, text, audit = r.stdout.splitlines()[:3]
        self.assertEqual(primary, "empty_head")
        self.assertIn("HEAD could not be resolved", text)
        self.assertIn("[empty_head]", audit)


class TestFreshStillPasses(_Base):
    def test_passing_review_at_head_is_not_refused(self):
        _stub_llm(self._review_home, {"summary": "clean", "checked": ["security"], "findings": []})
        _stage_identical_recreation(self._project, 1)
        _setup_fake_tool_home(self._review_home)
        self.assertEqual(self._gate(self._review_home, "review").returncode, 0)
        r = self._merge_gate()
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main()
