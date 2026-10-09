"""
When the adversarial audit's findings cannot be added to the code verdict, the
merge gate must refuse, and nothing on the way may swallow the failure:

  - the marker the audit leaves and the comparison the merge gate makes use the
    one stamp function, so the refusal fires
  - a marker that cannot be written is a hard error (exit status 4), not a
    silent `|| :`
  - the audit's empty-input path records or marks exactly like the main path
  - a cached merge-gate pass does not outlive an unrecorded audit at that state
  - a successful record clears the marker

Run with: python3 -m unittest scripts.test_adversarial_unrecorded_marker -v
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

from scripts.findings_test_support import TOOL_HOME, head, make_repo, write
from scripts.test_merge_gate_code_verdict import Case, _fake_tool_home
from scripts.test_source_helpers import GATES_SH, source_env

ADVERSARIAL_STATUS_UNRECORDED = 4


def _clean_auditor(tmpdir):
    scripts_dir = os.path.join(tmpdir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    with open(stub, "w") as handle:
        handle.write(textwrap.dedent("""\
            #!/bin/sh
            cat > /dev/null
            printf '# Adversarial findings\\n\\nNo exploitable issues found.\\n'
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


class AdversarialCase(Case):
    def marker(self):
        return self.lite("adversarial-unrecorded")

    def run_adversarial(self):
        _clean_auditor(self.tmp)
        _fake_tool_home(self.tmp)
        # A staged change keeps get_review_diff on its network-free path.
        write(os.path.join(self.project, "app.py"), "print('changed')\n")
        subprocess.run(["git", "-C", self.project, "add", "app.py"], check=True)
        env = dict(os.environ)
        env.update({"CLAGENTIC_PROJECT_ROOT": self.project, "CLAGENTIC_ALLOW_MISSING_GITLEAKS": "1",
                    "CLAGENTIC_ALLOW_MISSING_SEMGREP": "1", "CLAGENTIC_ALLOW_MISSING_OSV": "1",
                    "CLAGENTIC_FINDINGS_TODAY": "2026-10-09", "CLAGENTIC_DEFAULT_BRANCH": "main"})
        return subprocess.run(["sh", os.path.join(self.tmp, "scripts", "gates.sh"), "adversarial"],
                              capture_output=True, text=True, env=env, cwd=self.project, timeout=180)

    def break_the_state(self):
        write(self.lite("findings-state.json"), "{corrupt")

    def fix_the_state(self):
        os.unlink(self.lite("findings-state.json"))


class TestUnrecordedFindingsMakeTheMergeGateRefuse(AdversarialCase):
    def test_an_audit_that_blocks_but_cannot_record_makes_merge_gate_refuse(self):
        self.break_the_state()
        result = self.run_adversarial()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("could not be recorded", result.stderr)
        self.assertTrue(os.path.exists(self.marker()), "no marker was left")
        self.fix_the_state()
        gate, called, _ = self.merge_gate("approve")
        self.assertEqual((gate.returncode, called), (1, 0), gate.stdout + gate.stderr)
        self.assertIn("could not be recorded", self.last_decision()["reason"])

    def test_the_marker_holds_the_stamp_the_merge_gate_compares_it_to(self):
        self.break_the_state()
        self.run_adversarial()
        with open(self.marker()) as handle:
            self.assertEqual(handle.read().strip(), head(self.project))

    def test_the_stamp_has_one_definition_used_on_both_sides(self):
        with open(os.path.join(TOOL_HOME, "scripts", "gates.sh")) as handle:
            text = handle.read()
        self.assertEqual(len(re.findall(r"^_adv_unrecorded_stamp\(\)", text, re.M)), 1)
        mark = text[text.index("_adv_unrecorded_mark() {"):]
        mark = mark[:mark.index("\n}\n")]
        pending = text[text.index("_adv_unrecorded_pending() {"):]
        pending = pending[:pending.index("\n}\n")]
        self.assertIn("_adv_unrecorded_stamp", mark)
        self.assertIn("_adv_unrecorded_stamp", pending)

    def test_a_successful_record_removes_a_stale_marker(self):
        write(self.marker(), head(self.project) + "\n")
        result = self.run_adversarial()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.exists(self.marker()))


class TestAMarkerThatCannotBeWrittenIsAHardError(AdversarialCase):
    def test_exit_status_and_message(self):
        self.break_the_state()
        os.makedirs(self.marker())
        result = self.run_adversarial()
        self.assertEqual(result.returncode, ADVERSARIAL_STATUS_UNRECORDED, result.stderr)
        self.assertIn("could not be written", result.stderr)
        self.assertIn("ERROR", result.stderr)

    def test_the_audit_trail_names_it(self):
        self.break_the_state()
        os.makedirs(self.marker())
        self.run_adversarial()
        rows = [row for row in self.audit_rows() if row[0] == "adversarial"]
        self.assertTrue(any(outcome == "block" and "marker could not be written" in (details or "")
                            for _, outcome, details in rows), rows)

    def test_no_silent_discard_is_left_on_the_marker_write(self):
        with open(os.path.join(TOOL_HOME, "scripts", "gates.sh")) as handle:
            text = handle.read()
        self.assertNotRegex(text, r"adversarial-unrecorded[^\n]*2>/dev/null \|\| :")
        self.assertNotRegex(text, r"_gate_evaluate adversarial[^\n]*\|\| :")


class TestBothRecordSitesShareTheHelper(unittest.TestCase):
    def test_cmd_adversarial_records_only_through_the_helper(self):
        with open(os.path.join(TOOL_HOME, "scripts", "gates.sh")) as handle:
            text = handle.read()
        start = text.index("\ncmd_adversarial() {")
        body = text[start:text.index("\n}\n", start)]
        self.assertEqual(body.count("_adv_record_findings "), 2, "empty-input path and main path")
        self.assertNotIn("_gate_evaluate", body)

    def test_the_helper_marks_when_the_verdict_cannot_be_computed(self):
        # Driven directly, as both sites call it: a state that cannot be read.
        tmp = tempfile.mkdtemp(prefix="clagentic-test-advhelper-")
        self.addCleanup(shutil.rmtree, tmp, True)
        project = make_repo(os.path.join(tmp, "project"))
        lite = os.path.join(project, ".clagentic", "lite")
        write(os.path.join(lite, "findings-state.json"), "{corrupt")
        write(os.path.join(lite, "f.json"), "[]")
        # gates.sh runs under set -e, so the status is read the way the call
        # sites read it: through a conditional.
        script = ('. "%s"; if _adv_record_findings "%s" "" quiet; then echo "rc=0"; '
                  'else echo "rc=$?"; fi') % (GATES_SH, os.path.join(lite, "f.json"))
        env = dict(os.environ)
        env.update(source_env(gates=True))
        env["CLAGENTIC_PROJECT_ROOT"] = project

        def call():
            return subprocess.run(["sh", "-c", script, GATES_SH], capture_output=True, text=True,
                                  env=env, cwd=os.path.join(TOOL_HOME, "scripts"), timeout=120)

        proc = call()
        self.assertIn("rc=0", proc.stdout, proc.stderr)
        self.assertTrue(os.path.isfile(os.path.join(lite, "adversarial-unrecorded")))
        os.unlink(os.path.join(lite, "adversarial-unrecorded"))
        os.makedirs(os.path.join(lite, "adversarial-unrecorded"))
        proc = call()
        self.assertIn("rc=4", proc.stdout, proc.stderr)


class TestACachedPassDoesNotOutliveAnUnrecordedAudit(AdversarialCase):
    def test_the_marker_beats_the_state_cache(self):
        self.record([])
        first, called, _ = self.merge_gate("approve")
        self.assertEqual((first.returncode, called), (0, 1), first.stdout + first.stderr)
        again, called_again, _ = self.merge_gate("approve")
        self.assertEqual(again.returncode, 0)
        self.assertIn("already passed", again.stderr, "precondition: the state cache short-circuits")
        write(self.marker(), head(self.project) + "\n")
        refused, called_after, _ = self.merge_gate("approve")
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        # The call log is cumulative: the refusal added no model call.
        self.assertEqual(called_after, called_again)
        self.assertIn("could not be recorded", self.last_decision()["reason"])


if __name__ == "__main__":
    unittest.main()
