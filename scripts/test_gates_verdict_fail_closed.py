"""
Two fail-closed properties of the shell side of the code verdict:

  - the review gate treats an unset, empty, non-numeric or uncomputed blocker
    count as a block (the old `${BLOCKERS:-0}` read all of them as a pass), and
    never prints the 99 sentinel as a finding count
  - `gates evaluate` validates its arguments with the shared checker, including
    the --root=PATH form, so two roots can never reach findings.py

Run with: python3 -m unittest scripts.test_gates_verdict_fail_closed -v
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.findings_test_support import TOOL_HOME, commit_file, finding, head, make_repo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_review_code_verdict import (  # noqa: E402
    CLEAN_ENVELOPE, Case, run_review)
from test_source_helpers import (  # noqa: E402
    GATES_SH, source_env, stage_identical_recreation, stub_review_llm)


def source_gates(project, body):
    """Run BODY in a shell that has sourced the real gates.sh functions."""
    env = dict(os.environ)
    env.update(source_env(gates=True))
    env["CLAGENTIC_PROJECT_ROOT"] = project
    return subprocess.run(["sh", "-c", '. "%s"; %s' % (GATES_SH, body), GATES_SH],
                          capture_output=True, text=True, env=env,
                          cwd=os.path.join(TOOL_HOME, "scripts"), timeout=120)


class TestVerdictDecision(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-vfc-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = make_repo(os.path.join(self.tmp, "project"))

    def blocks(self, setup):
        # gates.sh runs under set -e, so the decision is read through a conditional.
        proc = source_gates(self.project, "%s; if _review_verdict_blocks; then echo BLOCK; "
                                          "else echo PASS; fi" % setup)
        self.assertIn(proc.stdout.strip(), ("BLOCK", "PASS"), proc.stderr)
        return proc.stdout.strip() == "BLOCK"

    def test_anything_but_a_computed_zero_blocks(self):
        for label, setup in (
                ("nothing set", "unset _RCV_BLOCKERS _RCV_COMPUTED"),
                ("count unset", "_RCV_COMPUTED=1; unset _RCV_BLOCKERS"),
                ("count empty", "_RCV_COMPUTED=1; _RCV_BLOCKERS="),
                ("count not a number", "_RCV_COMPUTED=1; _RCV_BLOCKERS=abc"),
                ("not computed, zero", "_RCV_COMPUTED=0; _RCV_BLOCKERS=0"),
                ("computed flag unset", "unset _RCV_COMPUTED; _RCV_BLOCKERS=0"),
                ("computed, positive", "_RCV_COMPUTED=1; _RCV_BLOCKERS=3")):
            with self.subTest(label):
                self.assertTrue(self.blocks(setup))

    def test_a_computed_zero_passes(self):
        self.assertFalse(self.blocks("_RCV_COMPUTED=1; _RCV_BLOCKERS=0"))

    def test_the_sentinel_is_never_worded_as_a_finding_count(self):
        for mode in ("log", "say"):
            with self.subTest(mode=mode):
                proc = source_gates(self.project,
                                    '_RCV_COMPUTED=0; _RCV_BLOCKERS=99; '
                                    '_review_blocked_reason high %s' % mode)
                self.assertNotIn("99", proc.stdout)
                self.assertIn("could not be computed", proc.stdout)

    def test_a_real_count_is_worded_as_one(self):
        proc = source_gates(self.project,
                            '_RCV_COMPUTED=1; _RCV_BLOCKERS=2; _review_blocked_reason high log')
        self.assertEqual(proc.stdout, "2 finding(s) at >= high")

    def test_no_default_to_zero_is_left_on_a_verdict_count(self):
        with open(GATES_SH) as handle:
            text = handle.read()
        code = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        offenders = [line for line in code
                     if re.search(r"\$\{(BLOCKERS|_RCV_BLOCKERS|_OSV_BLOCKERS)[^}]*:-0\}", line)]
        self.assertEqual(offenders, [])


class TestReviewGateEndToEnd(Case):
    def test_an_uncomputed_verdict_blocks_without_calling_it_a_finding_count(self):
        stub_review_llm(self.tmp, CLEAN_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        with open(os.path.join(self.lite, "findings-state.json"), "w") as handle:
            handle.write("{corrupt")
        result = run_review(self.tmp, self.project)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("REVIEW_BLOCKED: the verdict could not be computed", result.stderr)
        self.assertNotIn("99 finding", result.stderr)

    def test_the_audit_row_does_not_carry_the_sentinel_either(self):
        import sqlite3
        stub_review_llm(self.tmp, CLEAN_ENVELOPE)
        stage_identical_recreation(self.project, 1)
        with open(os.path.join(self.lite, "findings-state.json"), "w") as handle:
            handle.write("{corrupt")
        run_review(self.tmp, self.project)
        conn = sqlite3.connect(os.path.join(self.lite, "audit.db"))
        rows = conn.execute("SELECT details FROM gate_runs WHERE gate='review' AND outcome='block'"
                            ).fetchall()
        conn.close()
        details = " | ".join(row[0] or "" for row in rows)
        self.assertIn("review-blocked: the verdict could not be computed", details)
        self.assertNotIn("99", details)


class TestEvaluateArguments(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-evargs-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = make_repo(os.path.join(self.tmp, "home"))
        self.other = make_repo(os.path.join(self.tmp, "other"))
        # Two fresh repositories can share a commit SHA (same tree, author and
        # second); a second commit makes the two heads tell the roots apart.
        commit_file(self.other, "extra.txt", "x\n", "second")

    def evaluate(self, *args, stdin=None):
        env = dict(os.environ)
        env.update({"CLAGENTIC_PROJECT_ROOT": self.home, "CLAGENTIC_FINDINGS_TODAY": "2026-10-09"})
        return subprocess.run(["sh", GATES_SH, "evaluate"] + list(args), input=stdin,
                              capture_output=True, text=True, env=env, cwd=self.home, timeout=120)

    def test_the_root_equals_form_selects_that_root_and_no_second_root_is_added(self):
        result = self.evaluate("--root=%s" % self.other, "--json", stdin=json.dumps([finding()]))
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertEqual(json.loads(result.stdout)["head"], head(self.other))
        self.assertNotEqual(head(self.other), head(self.home))

    def test_the_root_space_form_selects_that_root(self):
        result = self.evaluate("--root", self.other, "--json", stdin=json.dumps([finding()]))
        self.assertEqual(json.loads(result.stdout)["head"], head(self.other))

    def test_the_default_root_is_this_repository(self):
        result = self.evaluate("--json", stdin=json.dumps([finding()]))
        self.assertEqual(json.loads(result.stdout)["head"], head(self.home))

    def test_an_unknown_option_is_refused_with_usage(self):
        result = self.evaluate("--bogus", stdin="[]")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown option '--bogus'", result.stderr)
        self.assertIn("usage: gates.sh evaluate", result.stderr)

    def test_a_stray_positional_is_refused(self):
        result = self.evaluate("whatever", stdin="[]")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unexpected argument", result.stderr)

    def test_an_option_that_needs_a_value_and_has_none_is_refused(self):
        result = self.evaluate("--root", stdin="[]")
        self.assertEqual(result.returncode, 2)
        self.assertIn("needs a value", result.stderr)

    def test_a_glob_in_an_option_name_is_not_a_known_option(self):
        result = self.evaluate("--r*", stdin="[]")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown option", result.stderr)

    def test_no_input_reads_nothing(self):
        result = self.evaluate("--no-input", "--gate", "merge-gate", "--json")
        self.assertIn(result.returncode, (0, 1, 2), result.stderr)
        self.assertNotIn("unknown option", result.stderr)


if __name__ == "__main__":
    unittest.main()
