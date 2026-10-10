"""
Policy is read only from the trusted base revision.

The dispositions file, the legacy deferral and ack files and the stakes
profile decide what blocks. The gate and `evaluate` read them through git at
the merge base with the default branch (HEAD on the default branch itself),
never from the working tree or the branch, so a change to a policy file applies
only after it is merged, whatever wrote it: a Write tool, a shell redirect, a
glob, an in-place editor, rsync, another process. The Builder write blocks
(W-007, R-021) are a best-effort deterrent on top of that, and these tests do
not rely on them.

Run with: python3 -m unittest scripts.test_policy_from_base -v
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from scripts.findings_test_support import (
    commit_file, entry, git, make_repo, run_findings, write)
from scripts.isolated_env import IsolatedEnv

TODAY = "2026-10-09"
PROFILE = {"version": 1, "confirmed_at": "2026-10-01",
           "paths": [{"glob": "app.py", "exposure": "local_or_ci_only"}]}
# authenticated_user + code_exec is high (blocks) and off the security floor,
# so a by_design entry may clear it.
ITEM = {"severity_claimed": "low", "file": "app.py", "line": 2, "category": "security",
        "message": "unsanitized input reaches a sink", "reachable": "yes",
        "attacker_precondition": "authenticated_user", "impact": "code_exec", "class": "durable"}
# Clears ITEM if it applied.
CLEARING = entry(id="clear-app")
UNRELATED = entry(id="other", match={"path_glob": "other.py", "category": "security"})
ACK = [{"cwe": "CWE-79", "path_glob": "app.py", "rationale": "reviewed by the maintainers",
        "acknowledged_by": "maintainer", "acknowledged_at": "2026-01-01"}]
AUDIT_ITEM = dict(ITEM, category="CWE-79")


class Base(unittest.TestCase):
    def setUp(self):
        self.iso = IsolatedEnv.for_test(self, git_project=False)
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-policy-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = make_repo(os.path.join(self.tmp, "repo"))

    def put(self, rel, document, message="policy"):
        return commit_file(self.repo, rel, document, message)

    def dispositions(self, *entries):
        return {"version": 1, "entries": list(entries)}

    def branch(self, name="feat/x"):
        git(self.repo, "checkout", "-q", "-b", name)

    def merge_into_main(self, name="feat/x"):
        git(self.repo, "checkout", "-q", "main")
        git(self.repo, "merge", "-q", "--ff-only", name)

    def evaluate(self, items=None, gate="review", extra=()):
        args = ["evaluate", "--gate", gate, "--today", TODAY, "--json"] + list(extra)
        result = run_findings(args, stdin=json.dumps({"findings": [ITEM] if items is None else items}),
                              cwd=self.repo, env=self.iso.env(project=self.repo))
        return result, json.loads(result.stdout)

    def shell(self, script, **env):
        merged = dict(self.iso.env(project=self.repo), **env)
        return subprocess.run(["sh", "-c", script], cwd=self.repo, env=merged, check=True,
                              capture_output=True, text=True, timeout=60)


class TestDispositionsComeFromTheBase(Base):
    def test_a_merged_entry_applies(self):
        self.put(".clagentic/dispositions.json", self.dispositions(CLEARING))
        result, verdict = self.evaluate()
        self.assertEqual((result.returncode, len(verdict["cleared"])), (0, 1), verdict)

    def test_an_uncommitted_working_tree_entry_clears_nothing_and_is_reported(self):
        write(os.path.join(self.repo, ".clagentic", "dispositions.json"), self.dispositions(CLEARING))
        result, verdict = self.evaluate()
        self.assertEqual(result.returncode, 1)
        self.assertEqual([p["entry_id"] for p in verdict["pending_in_change"]], ["clear-app"])

    def test_an_entry_committed_on_the_branch_clears_nothing_and_is_reported(self):
        self.branch()
        self.put(".clagentic/dispositions.json", self.dispositions(CLEARING), "add entry")
        result, verdict = self.evaluate(extra=["--base", "main"])
        self.assertEqual(result.returncode, 1)
        self.assertEqual([p["entry_id"] for p in verdict["pending_in_change"]], ["clear-app"])
        text = run_findings(["evaluate", "--gate", "review", "--today", TODAY],
                            stdin=json.dumps({"findings": [ITEM]}), cwd=self.repo,
                            env=self.iso.env(project=self.repo)).stdout
        self.assertIn("1 finding would be cleared by entries added in this PR", text)

    def test_a_branch_that_merges_the_entry_applies_it_afterwards(self):
        self.branch()
        self.put(".clagentic/dispositions.json", self.dispositions(CLEARING), "add entry")
        self.assertEqual(self.evaluate(extra=["--base", "main"])[0].returncode, 1)
        self.merge_into_main()
        result, verdict = self.evaluate(extra=["--base", "main"])
        self.assertEqual((result.returncode, len(verdict["cleared"])), (0, 1), verdict)

    def test_deleting_or_loosening_a_base_entry_in_the_change_changes_nothing_yet(self):
        self.put(".clagentic/dispositions.json", self.dispositions(CLEARING))
        self.branch()
        loosened = dict(CLEARING, match={"path_glob": "nothing.py", "category": "security"})
        self.put(".clagentic/dispositions.json", self.dispositions(loosened), "loosen")
        self.assertEqual(self.evaluate(extra=["--base", "main"])[0].returncode, 0)
        os.unlink(os.path.join(self.repo, ".clagentic", "dispositions.json"))
        self.assertEqual(self.evaluate(extra=["--base", "main"])[0].returncode, 0)

    def test_a_shell_glob_write_does_not_change_the_verdict(self):
        self.put(".clagentic/dispositions.json", self.dispositions(UNRELATED))
        payload = os.path.join(self.tmp, "payload.json")
        write(payload, self.dispositions(CLEARING))
        self.shell('cd .c*ntic && cp "$PAYLOAD" d*', PAYLOAD=payload)
        with open(os.path.join(self.repo, ".clagentic", "dispositions.json")) as handle:
            self.assertIn("clear-app", handle.read(), "the write really landed in the working tree")
        result, verdict = self.evaluate()
        self.assertEqual(result.returncode, 1, "it changes nothing until it is merged")
        self.assertEqual(verdict["cleared"], [])

    def test_an_rsync_write_does_not_change_the_verdict(self):
        if shutil.which("rsync") is None:
            self.skipTest("rsync is not installed")
        self.put(".clagentic/dispositions.json", self.dispositions(UNRELATED))
        payload = os.path.join(self.tmp, "payload.json")
        write(payload, self.dispositions(CLEARING))
        self.shell('rsync "$PAYLOAD" .clagentic/dispositions.json', PAYLOAD=payload)
        self.assertEqual(self.evaluate()[0].returncode, 1)

    def test_an_in_place_rewrite_by_another_process_does_not_change_the_verdict(self):
        self.put(".clagentic/dispositions.json", self.dispositions(UNRELATED))
        self.shell("python3 -c \"import json, os, sys; p = '.clagentic/dispositions.json'; "
                   "d = json.load(open(p)); d['entries'] = [json.loads(sys.argv[1])]; "
                   "json.dump(d, open(p, 'w'))\" \"$ENTRY\"", ENTRY=json.dumps(CLEARING))
        self.assertEqual(self.evaluate()[0].returncode, 1)

    def test_with_no_resolvable_base_no_entry_applies_and_the_output_says_so(self):
        self.put(".clagentic/dispositions.json", self.dispositions(CLEARING))
        result, verdict = self.evaluate(extra=["--base", "no-such-ref"])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(verdict["cleared"], [])
        self.assertTrue(any("base commit could not be resolved" in w and "no disposition entry applies" in w
                            for w in verdict["warnings"]), verdict["warnings"])

    def test_no_policy_files_and_no_base_is_silent(self):
        _, verdict = self.evaluate(extra=["--base", "no-such-ref"])
        self.assertFalse(any("disposition" in w for w in verdict["warnings"]), verdict["warnings"])


class TestLegacyFilesComeFromTheBase(Base):
    def test_a_merged_ack_applies(self):
        self.put(".clagentic/adversarial-acks.json", ACK)
        result, verdict = self.evaluate([AUDIT_ITEM], gate="adversarial")
        self.assertEqual((result.returncode, len(verdict["cleared"])), (0, 1), verdict)

    def test_a_working_tree_ack_does_not_apply(self):
        write(os.path.join(self.repo, ".clagentic", "adversarial-acks.json"), ACK)
        result, verdict = self.evaluate([AUDIT_ITEM], gate="adversarial")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(verdict["cleared"], [])

    def test_a_branch_commit_adding_an_ack_does_not_apply(self):
        self.branch()
        self.put(".clagentic/adversarial-acks.json", ACK, "ack")
        result, _ = self.evaluate([AUDIT_ITEM], gate="adversarial", extra=["--base", "main"])
        self.assertEqual(result.returncode, 1)


class TestProfileComesFromTheBase(Base):
    DATA = dict(ITEM, attacker_precondition="network")

    def test_a_shell_glob_write_of_the_profile_changes_nothing_until_merged(self):
        self.put(".clagentic/risk-profile.json", {"version": 1, "confirmed_at": "2026-10-01"})
        payload = os.path.join(self.tmp, "payload.json")
        write(payload, PROFILE)
        self.shell('cd .c*ntic && cp "$PAYLOAD" r*', PAYLOAD=payload)
        result, _ = self.evaluate([self.DATA])
        self.assertEqual(result.returncode, 1)

    def test_an_uncommitted_profile_is_ignored_loudly_without_a_base(self):
        write(os.path.join(self.repo, ".clagentic", "risk-profile.json"), PROFILE)
        result, verdict = self.evaluate([self.DATA], extra=["--base", "no-such-ref"])
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("base commit could not be resolved" in w for w in verdict["warnings"]))

    def test_a_merged_profile_applies(self):
        self.put(".clagentic/risk-profile.json", PROFILE)
        self.assertEqual(self.evaluate([self.DATA])[0].returncode, 0)


if __name__ == "__main__":
    unittest.main()
