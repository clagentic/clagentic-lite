"""
The disposition store (.clagentic/dispositions.json) and the guardrails around
it, exercised through the real `findings.py evaluate` and `dispositions` CLI in
throwaway git repositories:

  - matching is done in code (path glob, category, message, fingerprint hint)
  - an entry added or changed in the gated change does not clear that change's
    findings, and the output counts how many it would have cleared
  - a security-floor finding is cleared by a fix or a mitigation naming its
    control, never by by_design / false_positive / accepted_risk
  - rationale, by and at are required; an invalid entry is ignored loudly
  - an expired entry stops applying and is reported
  - deferrals.json / adversarial-acks.json / accepted-risks.md are still read,
    converted, and warned about

Run with: python3 -m unittest scripts.test_dispositions_store -v
"""
import hashlib
import json
import os
import shutil
import tempfile
import unittest

from scripts.findings_test_support import (
    TOOL_HOME, adversarial_finding, commit_file, entry, finding, git, load_module, make_repo,
    run_findings, write)

findings = load_module()
TODAY = "2026-10-09"


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-disp-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = make_repo(os.path.join(self.tmp, "repo"))

    def put_dispositions(self, entries, message="record dispositions"):
        return commit_file(self.repo, ".clagentic/dispositions.json",
                           json.dumps({"version": 1, "entries": entries}), message)

    def start_branch(self):
        git(self.repo, "checkout", "-q", "-b", "feat")
        return commit_file(self.repo, "app.py", "print('changed')\n", "work")

    def evaluate(self, items, gate="review", extra=(), fmt=None, env=None):
        args = ["evaluate", "--gate", gate, "--root", self.repo, "--base", "main",
                "--today", TODAY] + list(extra)
        if fmt:
            args += ["--format", fmt]
        stdin = items if isinstance(items, str) else json.dumps({"findings": items})
        return run_findings(args, stdin=stdin, cwd=self.repo, env=env)

    def verdict_json(self, items, gate="review", extra=()):
        result = self.evaluate(items, gate, ["--json"] + list(extra))
        return result, (json.loads(result.stdout) if result.stdout.strip().startswith("{") else None)


class TestMechanicalMatching(RepoCase):
    def test_a_merged_entry_clears_a_matching_finding(self):
        self.put_dispositions([entry()])
        self.start_branch()
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(verdict["verdict"], "PASS")
        self.assertEqual(verdict["cleared"][0]["entry"]["id"], "d1")

    def test_cleared_findings_are_always_printed(self):
        self.put_dispositions([entry(rationale="intentional fixture, reviewed")])
        self.start_branch()
        result = self.evaluate([finding()])
        self.assertEqual(result.returncode, 0)
        self.assertIn("Cleared by dispositions", result.stdout)
        self.assertIn("d1", result.stdout)
        self.assertIn("intentional fixture, reviewed", result.stdout)
        self.assertIn("maintainer", result.stdout)

    def test_each_match_field_must_agree(self):
        self.put_dispositions([entry(match={"path_glob": "app.py", "category": "security"})])
        self.start_branch()
        for label, item in (("other file", finding(file="other.py")),
                            ("other category", finding(category="correctness"))):
            with self.subTest(label=label):
                result = self.evaluate([item])
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("VERDICT: BLOCKED", result.stdout)

    def test_gates_scope_the_entry_to_its_source(self):
        self.put_dispositions([entry(gates=["adversarial"])])
        self.start_branch()
        self.assertEqual(self.evaluate([finding()]).returncode, 1)

    def test_message_and_fingerprint_hint_narrow_the_match(self):
        probe = findings.unify_finding(finding(), "review")
        hint = probe["fingerprint"][:12]
        self.put_dispositions([
            entry(id="by-message", match={"path_glob": "app.py", "category": "security",
                                          "message": "A DIFFERENT MESSAGE"}),
            entry(id="by-hint", match={"path_glob": "app.py", "category": "security",
                                       "fingerprint_hint": hint}),
        ])
        self.start_branch()
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "PASS", result.stdout)
        self.assertEqual([c["entry"]["id"] for c in verdict["cleared"]], ["by-hint"])

    def test_a_wrong_fingerprint_hint_does_not_match(self):
        self.put_dispositions([entry(match={"path_glob": "app.py", "category": "security",
                                            "fingerprint_hint": "deadbeefdeadbeef"})])
        self.start_branch()
        self.assertEqual(self.evaluate([finding()]).returncode, 1)

    def test_path_globs_stay_within_their_segments_unless_double_star(self):
        match = findings.glob_matches
        self.assertTrue(match("src/**", "src/a/b.py"))
        self.assertTrue(match("**/gen/*.py", "a/b/gen/x.py"))
        self.assertTrue(match("**/gen/*.py", "gen/x.py"))
        self.assertTrue(match("**", "anything/at/all.py"))
        self.assertTrue(match("*.py", "app.py"))
        self.assertFalse(match("*.py", "src/app.py"))
        self.assertFalse(match("src/*.py", "src/a/b.py"))
        self.assertTrue(match("src/*/b.py", "src/a/b.py"))
        self.assertTrue(match("src/?.py", "src/a.py"))
        self.assertFalse(match("src/?.py", "src/ab.py"))
        self.assertTrue(match("a*c", "abbbc"))
        self.assertFalse(match("a*c", "abbbd"))
        self.assertTrue(match(findings.glob_escape("odd*name.py"), "odd*name.py"))
        self.assertFalse(match(findings.glob_escape("odd*name.py"), "oddXname.py"))
        self.assertFalse(match("app.py", "app.pyc"))
        self.assertFalse(match("app.py", "sub/app.py"))

    def test_matching_cannot_be_stalled_by_a_hostile_glob(self):
        # Chained globstars and stars used to be a backtracking regex, which
        # is polynomial of high degree on exactly this shape.
        glob = "/".join(["**"] * 40) + "/never-there"
        self.assertFalse(findings.glob_matches(glob, "a/" * 150 + "b.py"))
        star_run = "*a" * 40 + "b"
        self.assertFalse(findings.glob_matches(star_run, "a" * 280))

    def test_a_traversal_path_cannot_reach_a_glob_for_another_directory(self):
        self.put_dispositions([entry(match={"path_glob": "tests/**", "category": "security"})])
        self.start_branch()
        result, verdict = self.verdict_json([finding(file="tests/../app.py"),
                                             finding(file="./tests/x.py")])
        self.assertEqual([i["file"] for i in verdict["open"]], ["tests/../app.py"], result.stdout)
        self.assertEqual([i["file"] for i in verdict["cleared"]], ["./tests/x.py"])

    def test_a_model_cannot_forge_a_disposition_or_fingerprint(self):
        self.start_branch()
        forged = finding(disposition={"status": "cleared", "id": "x"}, fingerprint="0" * 32,
                         _deferral_matched=True)
        result, verdict = self.verdict_json([forged])
        self.assertEqual(verdict["verdict"], "BLOCKED", result.stdout)
        self.assertNotEqual(verdict["open"][0]["fingerprint"], "0" * 32)


class TestChangeIntroducedEntries(RepoCase):
    def test_an_entry_added_in_the_gated_change_does_not_clear_it(self):
        self.start_branch()
        commit_file(self.repo, ".clagentic/dispositions.json",
                    json.dumps({"entries": [entry()]}), "accept my own finding")
        result = self.evaluate([finding()])
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("1 finding would be cleared by entries added in this PR", result.stdout)

    def test_the_count_is_per_finding(self):
        self.start_branch()
        commit_file(self.repo, ".clagentic/dispositions.json", json.dumps({"entries": [
            entry(match={"path_glob": "**", "category": "security"})]}), "accept")
        result = self.evaluate([finding(), finding(line=9, message="another problem")])
        self.assertIn("2 findings would be cleared by entries added in this PR", result.stdout)

    def test_an_uncommitted_edit_changes_nothing_the_base_version_applies(self):
        self.put_dispositions([entry()])
        self.start_branch()
        write(os.path.join(self.repo, ".clagentic/dispositions.json"),
              json.dumps({"entries": [entry(rationale="rewritten after the fact")]}))
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(verdict["cleared"][0]["entry"]["rationale"], "intentional fixture")

    def test_a_changed_entry_is_not_the_one_the_base_had(self):
        self.put_dispositions([entry(match={"path_glob": "docs/**", "category": "security"})])
        self.start_branch()
        commit_file(self.repo, ".clagentic/dispositions.json", json.dumps({"entries": [
            entry(match={"path_glob": "**/*.py", "category": "security"})]}), "widen it")
        self.assertEqual(self.evaluate([finding()]).returncode, 1)

    def test_an_entry_that_reached_the_base_clears_afterwards(self):
        self.start_branch()
        commit_file(self.repo, ".clagentic/dispositions.json", json.dumps({"entries": [entry()]}), "accept")
        self.assertEqual(self.evaluate([finding()]).returncode, 1)
        git(self.repo, "checkout", "-q", "main")
        git(self.repo, "merge", "-q", "--ff-only", "feat")
        git(self.repo, "checkout", "-q", "-b", "next")
        commit_file(self.repo, "app.py", "print('next')\n", "next work")
        fresh = self.evaluate([finding()])
        self.assertEqual(fresh.returncode, 0, fresh.stdout)

    def test_an_unresolvable_base_treats_every_entry_as_added(self):
        self.put_dispositions([entry()])
        result = run_findings(["evaluate", "--gate", "review", "--root", self.repo, "--today", TODAY,
                               "--default-branch", "no-such-branch"],
                              stdin=json.dumps({"findings": [finding()]}), cwd=self.repo)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("could not be resolved", result.stdout)
        self.assertIn("would be cleared by entries added in this PR", result.stdout)


class TestSecurityFloor(RepoCase):
    FLOOR = adversarial_finding()

    def _verdict(self, kind, **extra):
        self.put_dispositions([entry(gates=["adversarial"],
                                     match={"path_glob": "app.py", "category": "CWE-78"},
                                     kind=kind, **extra)])
        self.start_branch()
        return self.verdict_json([self.FLOOR], gate="adversarial")

    def test_by_design_cannot_clear_a_reachable_high_finding(self):
        for kind in ("by_design", "false_positive", "accepted_risk"):
            with self.subTest(kind=kind):
                self.setUp()
                result, verdict = self._verdict(kind)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(verdict["refused"][0]["kind"], kind)

    def test_the_refusal_is_explained_in_the_text(self):
        self._verdict("by_design")
        text = self.evaluate([self.FLOOR], gate="adversarial").stdout
        self.assertIn("cannot be cleared by entry d1", text)
        self.assertIn("kind mitigated", text)

    def test_mitigated_with_a_named_control_clears_it(self):
        result, verdict = self._verdict("mitigated", control="gateway policy admin-only")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(verdict["cleared"][0]["entry"]["control"], "gateway policy admin-only")

    def test_mitigated_without_a_control_is_invalid(self):
        result, verdict = self._verdict("mitigated")
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("control" in " ".join(r["errors"]) for r in verdict["invalid"]))

    def test_an_unreachable_or_medium_finding_is_not_on_the_floor(self):
        self.put_dispositions([entry(gates=["adversarial"],
                                     match={"path_glob": "app.py", "category": "CWE-78"})])
        self.start_branch()
        medium = adversarial_finding(severity="medium", tier="blocking")
        self.assertEqual(self.evaluate([medium], gate="adversarial").returncode, 0)

    def test_a_blocking_finding_off_the_floor_is_cleared_by_by_design(self):
        self.put_dispositions([entry(gates=["adversarial"],
                                     match={"path_glob": "app.py", "category": "CWE-78"})])
        self.start_branch()
        off_floor = adversarial_finding(attacker_precondition="authenticated_user", impact="code_exec")
        result, verdict = self.verdict_json([off_floor], gate="adversarial")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(len(verdict["cleared"]), 1, "blocking by tier, and by_design may clear it")

    def test_the_floor_is_reachable_and_at_least_high(self):
        self.assertTrue(findings.is_floor(findings.unify_finding(self.FLOOR, "adversarial")))
        for over in ({"reachable": "no"}, {"reachable": "unknown"}, {"severity": "medium"},
                     {"severity": "low"}):
            with self.subTest(over=over):
                record = findings.unify_finding(adversarial_finding(**over), "adversarial")
                self.assertFalse(findings.is_floor(record))

    def test_a_reachable_unrankable_severity_is_on_the_floor(self):
        record = findings.unify_finding(adversarial_finding(severity="blocker"), "adversarial")
        self.assertTrue(findings.is_floor(record))
        self.assertEqual(record["tier"], "blocking")


class TestRequiredFieldsAndFailClosed(RepoCase):
    def _blocked_with(self, bad_entry):
        self.put_dispositions([bad_entry])
        self.start_branch()
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(result.returncode, 1, result.stdout)
        return verdict

    def test_rationale_by_and_at_are_each_required(self):
        for missing in ("rationale", "by", "at"):
            with self.subTest(missing=missing):
                self.setUp()
                bad = entry()
                del bad[missing]
                verdict = self._blocked_with(bad)
                self.assertEqual(len(verdict["invalid"]), 1)
                self.assertIn(missing, " ".join(verdict["invalid"][0]["errors"]))

    def test_blank_and_wrongly_typed_values_are_invalid(self):
        for label, bad in (("blank rationale", entry(rationale="   ")),
                           ("numeric by", entry(by=7)),
                           ("bad date", entry(at="yesterday")),
                           ("unknown kind", entry(kind="whatever")),
                           ("empty gates", entry(gates=[])),
                           ("unknown gate", entry(gates=["merge-gate"])),
                           ("no match", entry(match=None)),
                           ("catch-all", entry(match={"path_glob": "**", "category": "*"})),
                           ("bad hint", entry(match={"path_glob": "a", "category": "c",
                                                     "fingerprint_hint": "zz"})),
                           ("bad expiry", entry(expires="someday"))):
            with self.subTest(label=label):
                self.setUp()
                verdict = self._blocked_with(bad)
                self.assertEqual(len(verdict["invalid"]), 1, verdict)

    def test_an_invalid_entry_is_reported_loudly_in_the_text(self):
        bad = entry()
        del bad["by"]
        self.put_dispositions([bad])
        self.start_branch()
        text = self.evaluate([finding()]).stdout
        self.assertIn("Invalid disposition ignored", text)

    def test_one_invalid_entry_does_not_disable_the_valid_ones(self):
        bad = entry(id="bad")
        del bad["rationale"]
        self.put_dispositions([bad, entry(id="good")])
        self.start_branch()
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "PASS", result.stdout)
        self.assertEqual(len(verdict["invalid"]), 1)

    def test_duplicate_ids_keep_only_the_first(self):
        self.put_dispositions([entry(), entry(match={"path_glob": "other.py", "category": "x"})])
        self.start_branch()
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "PASS")
        self.assertEqual(len(verdict["invalid"]), 1)

    def test_unusable_files_apply_nothing(self):
        self.start_branch()
        for label, content in (("not json", "{nope"), ("string", '"x"'), ("object no entries", '{"a": 1}')):
            with self.subTest(label=label):
                commit_file(self.repo, ".clagentic/dispositions.json", content, label)
                result, verdict = self.verdict_json([finding()])
                self.assertEqual(verdict["verdict"], "BLOCKED")
                self.assertEqual(len(verdict["invalid"]), 1)

    def test_a_symlink_out_of_the_repository_is_refused(self):
        self.start_branch()
        outside = write(os.path.join(self.tmp, "elsewhere.json"), json.dumps({"entries": [entry()]}))
        os.makedirs(os.path.join(self.repo, ".clagentic"), exist_ok=True)
        os.symlink(outside, os.path.join(self.repo, ".clagentic", "dispositions.json"))
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "BLOCKED", result.stdout)
        self.assertTrue(any("outside the repository" in " ".join(r["errors"]) for r in verdict["invalid"]))


class TestExpiry(RepoCase):
    def test_an_expired_entry_stops_applying_and_is_reported(self):
        self.put_dispositions([entry(expires="2026-10-08")])
        self.start_branch()
        result = self.evaluate([finding()])
        self.assertEqual(result.returncode, 1)
        self.assertIn("Expired: entry d1", result.stdout)
        self.assertIn("would have cleared 1 finding", result.stdout)

    def test_the_expiry_date_itself_is_still_valid(self):
        self.put_dispositions([entry(expires=TODAY)])
        self.start_branch()
        self.assertEqual(self.evaluate([finding()]).returncode, 0)

    def test_a_future_expiry_applies(self):
        self.put_dispositions([entry(expires="2027-01-01")])
        self.start_branch()
        self.assertEqual(self.evaluate([finding()]).returncode, 0)

    def test_the_date_override_must_be_a_date(self):
        result = run_findings(["evaluate", "--root", self.repo, "--today", "soon"],
                              stdin='{"findings": []}', cwd=self.repo)
        self.assertEqual(result.returncode, 2)


class TestStanza(RepoCase):
    def _open(self, items, gate="review"):
        self.start_branch()
        result, verdict = self.verdict_json(items, gate=gate)
        return result, verdict

    def test_blocked_prints_the_stanza_for_each_open_finding(self):
        self.start_branch()
        result = self.evaluate([finding(), finding(line=7, message="a second problem")])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count('"fingerprint_hint"'), 2)
        self.assertIn("To clear a finding", result.stdout)

    def test_an_unedited_stanza_clears_nothing(self):
        result, verdict = self._open([finding()])
        stanza = verdict["open"][0]["stanza"]
        _, errors = findings.validate_entry(stanza)
        self.assertTrue(errors and any("placeholder" in e for e in errors), errors)

    def test_a_completed_stanza_clears_the_finding_once_merged(self):
        result, verdict = self._open([finding()])
        stanza = dict(verdict["open"][0]["stanza"], rationale="reviewed and accepted",
                      by="maintainer")
        self.assertEqual(stanza["kind"], "by_design")
        git(self.repo, "checkout", "-q", "main")
        commit_file(self.repo, ".clagentic/dispositions.json", json.dumps({"entries": [stanza]}), "accept")
        git(self.repo, "checkout", "-q", "-b", "later")
        commit_file(self.repo, "app.py", "print('later')\n", "later work")
        again = self.evaluate([finding()])
        self.assertEqual(again.returncode, 0, again.stdout)

    def test_a_floor_stanza_asks_for_a_mitigation_and_its_control(self):
        result, verdict = self._open([adversarial_finding()], gate="adversarial")
        stanza = verdict["open"][0]["stanza"]
        self.assertEqual(stanza["kind"], "mitigated")
        self.assertIn("control", stanza)
        self.assertTrue(verdict["open"][0]["floor"])


class TestLegacyFiles(RepoCase):
    def _deferral(self, **over):
        content = "print('hi')\n"
        base = {"id": "def-1", "category": "security", "file": "app.py",
                "message": "unsanitized input reaches a sink", "description": "stable fixture",
                "acknowledged_by": "maintainer", "scope": "stable-contract",
                "file_sha256": hashlib.sha256(content.encode()).hexdigest()}
        base.update(over)
        return base

    def test_a_stable_contract_deferral_still_clears_and_warns(self):
        commit_file(self.repo, ".clagentic/deferrals.json", json.dumps([self._deferral()]), "defer")
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "PASS", result.stdout)
        self.assertEqual(verdict["cleared"][0]["entry"]["id"], "deferral-def-1")
        self.assertTrue(any("DEPRECATED" in w and "deferrals.json" in w for w in verdict["warnings"]))

    def test_a_deferral_lapses_when_its_file_changes(self):
        commit_file(self.repo, ".clagentic/deferrals.json", json.dumps([self._deferral()]), "defer")
        write(os.path.join(self.repo, "app.py"), "print('edited')\n")
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "BLOCKED")
        self.assertTrue(any("lapsed" in w for w in verdict["warnings"]))

    def test_a_deferral_added_in_the_gated_change_does_not_clear_it(self):
        self.start_branch()
        write(os.path.join(self.repo, "app.py"), "print('hi')\n")
        content = open(os.path.join(self.repo, "app.py"), "rb").read()
        deferral = self._deferral(file_sha256=hashlib.sha256(content).hexdigest())
        commit_file(self.repo, ".clagentic/deferrals.json", json.dumps([deferral]), "defer")
        result = self.evaluate([finding()])
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("would be cleared by entries added in this PR", result.stdout)

    def test_a_prompt_context_only_deferral_is_never_applied_in_code(self):
        commit_file(self.repo, ".clagentic/deferrals.json",
                    json.dumps([{"id": "soft", "file": "app.py", "description": "just a hint"}]), "defer")
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "BLOCKED")
        self.assertTrue(any("prompt-context" in w for w in verdict["warnings"]))

    def test_an_adversarial_ack_clears_a_non_floor_finding(self):
        commit_file(self.repo, ".clagentic/adversarial-acks.json", json.dumps([{
            "cwe": "CWE-78", "path_glob": "app.py", "rationale": "internal tool only",
            "acknowledged_by": "maintainer", "acknowledged_at": "2026-05-01"}]), "ack")
        result = self.evaluate([adversarial_finding(attacker_precondition="authenticated_user",
                                                    impact="code_exec")], gate="adversarial")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("ack-", result.stdout)

    def test_an_ack_no_longer_clears_a_reachable_high_finding(self):
        commit_file(self.repo, ".clagentic/adversarial-acks.json", json.dumps([{
            "cwe": "CWE-78", "rationale": "internal tool only",
            "acknowledged_by": "maintainer", "acknowledged_at": "2026-05-01"}]), "ack")
        result, verdict = self.verdict_json([adversarial_finding()], gate="adversarial")
        self.assertEqual(verdict["verdict"], "BLOCKED", result.stdout)
        self.assertEqual(verdict["refused"][0]["kind"], "accepted_risk")

    def test_accepted_risks_markdown_clears_nothing_and_says_so(self):
        commit_file(self.repo, ".clagentic/accepted-risks.md", "# Accepted\nEverything is fine.\n", "risks")
        result, verdict = self.verdict_json([finding()])
        self.assertEqual(verdict["verdict"], "BLOCKED")
        self.assertTrue(any("accepted-risks.md" in w and "clears nothing" in w for w in verdict["warnings"]))

    def test_migrate_folds_the_legacy_entries_into_a_valid_file(self):
        commit_file(self.repo, ".clagentic/deferrals.json", json.dumps([self._deferral()]), "defer")
        commit_file(self.repo, ".clagentic/adversarial-acks.json", json.dumps([{
            "cwe": "CWE-79", "rationale": "docs only", "acknowledged_by": "me",
            "acknowledged_at": "2026-02-02"}]), "ack")
        result = run_findings(["dispositions", "migrate", "--root", self.repo], cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        ids = sorted(e["id"] for e in document["entries"])
        self.assertEqual(len(ids), 2)
        self.assertIn("deferral-def-1", ids)
        for item in document["entries"]:
            self.assertEqual(findings.validate_entry(item)[1], [], item)
        written = run_findings(["dispositions", "migrate", "--root", self.repo, "--write"], cwd=self.repo)
        self.assertEqual(written.returncode, 0, written.stderr)
        with open(os.path.join(self.repo, ".clagentic", "dispositions.json")) as handle:
            self.assertEqual(sorted(e["id"] for e in json.load(handle)["entries"]), ids)

    def test_migrate_refuses_to_write_over_an_invalid_file(self):
        write(os.path.join(self.repo, ".clagentic/dispositions.json"), "{broken")
        result = run_findings(["dispositions", "migrate", "--root", self.repo, "--write"], cwd=self.repo)
        self.assertEqual(result.returncode, 1)
        with open(os.path.join(self.repo, ".clagentic", "dispositions.json")) as handle:
            self.assertEqual(handle.read(), "{broken")


class TestLint(RepoCase):
    def test_the_shipped_example_is_valid(self):
        example = os.path.join(TOOL_HOME, "share", "dispositions.example.json")
        result = run_findings(["dispositions", "lint", example, "--root", self.repo], cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("3 entries, no problems", result.stdout)

    def test_every_problem_is_listed_and_the_status_is_nonzero(self):
        bad = entry(id="needs-more")
        del bad["rationale"]
        del bad["by"]
        write(os.path.join(self.repo, ".clagentic/dispositions.json"),
              json.dumps({"entries": [bad, entry(id="fine")]}))
        result = run_findings(["dispositions", "lint", "--root", self.repo], cwd=self.repo)
        self.assertEqual(result.returncode, 1)
        self.assertIn("needs-more", result.stdout)
        self.assertIn("rationale", result.stdout)
        self.assertIn("'by'", result.stdout)

    def test_an_expired_entry_is_reported_but_is_not_a_problem(self):
        write(os.path.join(self.repo, ".clagentic/dispositions.json"),
              json.dumps({"entries": [entry(expires="2000-01-01")]}))
        result = run_findings(["dispositions", "lint", "--root", self.repo], cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("expired on 2000-01-01", result.stdout)


if __name__ == "__main__":
    unittest.main()
