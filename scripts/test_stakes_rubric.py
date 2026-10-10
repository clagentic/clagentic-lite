"""
Structured facts, the deterministic rubric and the optional stakes profile.

A finding that states facts (attacker_precondition, impact, reachable, class)
has its severity decided by one table in findings.py, scaled by a committed,
agent-maintained profile that is read as of the merge base. These tests cover
the rubric as a pure function, the profile's dimensions and sources, the floor,
fail-closed behavior, and the same answer from the gate path and a standalone
agent in a repository that was never enrolled. Everything runs the real CLI
against throwaway git repositories under a temp dir.

Run with: python3 -m unittest scripts.test_stakes_rubric -v
"""
import datetime
import json
import os
import re
import shutil
import tempfile
import unittest

from scripts.findings_test_support import (
    TOOL_HOME, commit_file, git, load_module, make_repo, run_findings, write)

findings = load_module()

TODAY = "2026-10-09"
PROMPTS = os.path.join(TOOL_HOME, "plugins", "clagentic-lite", "prompts")


def dims(**over):
    """A dimension map in the shape the rubric reads, worst case unless named."""
    base = findings.worst_dims()
    for key, value in over.items():
        base[key] = (value, "test glob")
    return base


def rubric(precondition, impact, reachable="yes", change_class="durable", **over):
    return findings.evaluate_rubric(precondition, impact, reachable, change_class, dims(**over))


def fact_finding(**over):
    base = {"severity_claimed": "low", "file": "deploy/app.py", "line": 3, "category": "security",
            "message": "command built from request input", "reachable": "yes",
            "attacker_precondition": "network", "impact": "code_exec", "class": "durable"}
    base.update(over)
    return base


class TestRubricTable(unittest.TestCase):
    def test_the_same_facts_and_profile_always_give_the_same_answer(self):
        for pre in findings.PRECONDITIONS:
            for impact in findings.IMPACTS:
                for reachable in ("yes", "no", "unknown"):
                    with self.subTest(pre=pre, impact=impact, reachable=reachable):
                        self.assertEqual(rubric(pre, impact, reachable), rubric(pre, impact, reachable))

    def test_the_open_column_and_the_far_columns(self):
        expected = {
            ("network", "code_exec"): ("critical", True),
            ("none", "code_exec"): ("critical", True),
            ("authenticated_user", "code_exec"): ("high", False),
            ("repo_write_can_merge", "code_exec"): ("high", False),
            ("maintainer_admin", "code_exec"): ("medium", False),
            ("local_ci_only", "code_exec"): ("medium", False),
            ("network", "quality_only"): ("medium", False),
            ("local_ci_only", "quality_only"): ("low", False),
            ("network", "availability"): ("medium", False),
        }
        for (pre, impact), (severity, floor) in expected.items():
            with self.subTest(pre=pre, impact=impact):
                got = rubric(pre, impact)
                self.assertEqual((got["severity"], got["floor"]), (severity, floor))

    def test_values_outside_the_vocabulary_resolve_to_the_worst_case(self):
        worst = rubric("none", "code_exec")
        for pre, impact, reachable in (("bogus", "bogus", "maybe"), (None, None, None),
                                       (5, ["x"], {}), ("", "", "")):
            with self.subTest(pre=pre, impact=impact):
                got = findings.evaluate_rubric(pre, impact, reachable, "durable", dims())
                self.assertEqual(got["severity"], worst["severity"])
                self.assertTrue(got["floor"])

    def test_unreachable_is_capped_below_the_default_threshold_but_still_reported(self):
        got = rubric("network", "code_exec", "no")
        self.assertEqual(got["severity"], "medium")
        self.assertFalse(got["floor"])

    def test_ephemeral_excuses_only_what_longevity_matters_for(self):
        self.assertEqual(rubric("authenticated_user", "availability")["severity"], "medium")
        self.assertEqual(rubric("authenticated_user", "availability",
                                change_class="ephemeral")["severity"], "low")
        self.assertEqual(rubric("network", "code_exec", change_class="ephemeral")["severity"],
                         "critical")
        self.assertTrue(rubric("network", "integrity", change_class="ephemeral")["floor"])


class TestProfileDimensions(unittest.TestCase):
    def test_internal_authenticated_turns_network_into_authenticated_user(self):
        got = rubric("network", "code_exec", exposure="internal_authenticated")
        self.assertEqual(got["effective_precondition"], "authenticated_user")
        self.assertEqual(got["severity"], "high")
        self.assertFalse(got["floor"])
        self.assertEqual(got["moves"], [
            "precondition network -> authenticated_user via exposure=internal_authenticated for test glob"])

    def test_internal_authenticated_leaves_a_precondition_of_none_alone(self):
        got = rubric("none", "code_exec", exposure="internal_authenticated")
        self.assertEqual((got["severity"], got["floor"]), ("critical", True))

    def test_local_or_ci_only_turns_network_and_authenticated_into_local_ci_only(self):
        for pre in ("network", "authenticated_user"):
            with self.subTest(pre=pre):
                got = rubric(pre, "code_exec", exposure="local_or_ci_only")
                self.assertEqual(got["effective_precondition"], "local_ci_only")
                self.assertEqual(got["severity"], "medium")

    def test_code_owner_review_makes_merging_a_trusted_reviewer_precondition(self):
        held = rubric("repo_write_can_merge", "code_exec", merge_control="code_owner_review_required")
        self.assertEqual(held["effective_precondition"], "maintainer_admin")
        self.assertEqual(held["severity"], "medium")
        for merge in ("review_required", "unrestricted"):
            with self.subTest(merge=merge):
                self.assertEqual(rubric("repo_write_can_merge", "code_exec",
                                        merge_control=merge)["severity"], "high")

    def test_a_private_repo_removes_the_anonymous_reader_off_the_internet_only(self):
        off = rubric("none", "code_exec", visibility="private", exposure="internal_authenticated")
        self.assertEqual(off["effective_precondition"], "authenticated_user")
        on = rubric("none", "code_exec", visibility="private", exposure="internet")
        self.assertEqual((on["severity"], on["floor"]), ("critical", True))

    def test_data_raises_and_lowers_the_weight_of_a_data_impact(self):
        read = {d: rubric("authenticated_user", "data_read", data=d)["severity"]
                for d in findings.DATA_LEVELS}
        self.assertEqual(read, {"regulated_or_customer": "high", "internal": "medium",
                                "public_or_none": "medium"})
        write_ = {d: rubric("authenticated_user", "data_write", data=d)["severity"]
                  for d in findings.DATA_LEVELS}
        self.assertEqual(write_["regulated_or_customer"], "high")
        self.assertEqual(write_["public_or_none"], "medium")
        for data in findings.DATA_LEVELS:
            with self.subTest(data=data):
                self.assertEqual(rubric("authenticated_user", "code_exec", data=data)["severity"], "high")

    def test_exposure_internet_never_lowers_a_high_impact_finding_below_the_floor(self):
        lowest = {"exposure": "internet", "data": "public_or_none", "visibility": "private",
                  "merge_control": "code_owner_review_required"}
        for pre in ("none", "network"):
            for impact in ("code_exec", "data_write", "integrity"):
                with self.subTest(pre=pre, impact=impact):
                    got = rubric(pre, impact, **lowest)
                    self.assertTrue(got["floor"])
                    self.assertGreaterEqual(findings.severity_rank(got["severity"]), findings.FLOOR_RANK)

    def test_an_unprofiled_run_is_the_worst_case_everywhere(self):
        facts = ("network", "data_read", "yes", "durable")
        self.assertEqual(findings.evaluate_rubric(*facts, dims=findings.worst_dims())["severity"],
                         "critical")


class TestUnifiedRecord(unittest.TestCase):
    def test_the_schema_version_is_bumped_and_stamped_on_every_record(self):
        self.assertEqual(findings.FINDING_SCHEMA, 2)
        legacy = findings.unify_finding({"severity": "low", "file": "a.py", "message": "m"}, "review")
        self.assertEqual(legacy["schema"], 2)

    def test_a_finding_without_facts_is_the_worst_case_and_never_keeps_the_claim(self):
        for source in ("review", "adversarial"):
            for claimed in ("low", "critical", None):
                with self.subTest(source=source, claimed=claimed):
                    raw = {"file": "a.py", "message": "m"}
                    if claimed:
                        raw["severity"] = claimed
                    record = findings.unify_finding(raw, source)
                    self.assertEqual(record["severity"], "critical")
                    self.assertTrue(record["rubric_applied"] and record["floor"])
                    self.assertEqual((record["attacker_precondition"], record["impact"]),
                                     ("unknown", "unknown"))
                    if source == "adversarial":
                        self.assertEqual(record["tier"], "blocking")
        low = findings.unify_finding({"severity": "low", "file": "a.py", "message": "m"}, "review")
        self.assertEqual(low["severity_claimed"], "low", "the claim is still shown")

    def test_a_finding_with_facts_takes_the_rubric_severity_and_keeps_the_claim(self):
        record = findings.unify_finding(fact_finding(severity_claimed="low"), "review")
        self.assertEqual((record["severity"], record["severity_claimed"]), ("critical", "low"))
        self.assertTrue(record["rubric_applied"] and record["floor"])

    def test_missing_and_invalid_facts_are_the_worst_case(self):
        for over in ({"impact": "nonsense"}, {"attacker_precondition": 7}, {"reachable": "perhaps"},
                     {"impact": None}):
            with self.subTest(over=over):
                record = findings.unify_finding(fact_finding(**over), "review")
                self.assertEqual(record["severity"], "critical")
        only_one = findings.unify_finding({"file": "a.py", "message": "m", "impact": "quality_only"},
                                          "review")
        self.assertEqual(only_one["attacker_precondition"], "unknown")
        self.assertEqual(only_one["severity"], "medium",
                         "the unstated precondition is the worst case, the stated impact still counts")

    def test_an_auditor_tier_comes_from_the_rubric_not_from_the_claim(self):
        record = findings.unify_finding(
            fact_finding(tier="advisory", attacker_precondition="local_ci_only", impact="quality_only"),
            "adversarial")
        self.assertEqual(record["tier"], "advisory")
        claimed_blocking = findings.unify_finding(
            fact_finding(tier="blocking", attacker_precondition="maintainer_admin",
                         impact="availability"), "adversarial")
        self.assertEqual(claimed_blocking["tier"], "advisory")
        open_ = findings.unify_finding(fact_finding(tier="advisory"), "adversarial")
        self.assertEqual(open_["tier"], "blocking")

    def test_the_auditor_header_carries_the_facts(self):
        text = ("[FINDING] CWE-78 | app.py:2 | severity: low | reachable: yes | "
                "precondition: network | impact: code_exec | tier: advisory | class: durable | "
                "title: shell injection\n")
        [parsed] = findings.parse_adversarial_text(text)
        self.assertEqual((parsed["attacker_precondition"], parsed["impact"]), ("network", "code_exec"))
        self.assertEqual(parsed["severity_claimed"], "low")
        self.assertEqual(parsed["tier"], "blocking")

    def test_a_header_with_garbled_facts_is_the_worst_case_and_unreachable_is_not_assumed(self):
        text = ("[FINDING] CWE-78 | app.py:2 | severity: low | precondition: ask nicely | "
                "impact: <script> | title: odd\n")
        [parsed] = findings.parse_adversarial_text(text)
        self.assertEqual((parsed["attacker_precondition"], parsed["impact"]), ("unknown", "unknown"))
        self.assertEqual(parsed["reachable"], "unknown")
        self.assertEqual(parsed["tier"], "blocking")

    def test_a_header_without_facts_is_read_as_before(self):
        text = "[FINDING] CWE-78 | app.py:2 | severity: medium | reachable: no | title: odd\n"
        [parsed] = findings.parse_adversarial_text(text)
        self.assertNotIn("impact", parsed)
        self.assertEqual((parsed["reachable"], parsed["tier"]), ("no", "advisory"))


class Repo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-stakes-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = make_repo(os.path.join(self.tmp, "repo"))

    def put_profile(self, document, message="profile"):
        return commit_file(self.repo, ".clagentic/risk-profile.json", document, message)

    def evaluate(self, items, gate="review", extra=(), env=None, repo=None):
        args = ["evaluate", "--gate", gate, "--today", TODAY] + list(extra)
        return run_findings(args, stdin=json.dumps({"findings": items}), cwd=repo or self.repo,
                            env=env)

    def verdict(self, items, extra=(), **kwargs):
        result = self.evaluate(items, extra=["--json"] + list(extra), **kwargs)
        return result, json.loads(result.stdout)


INTERNAL_DEPLOY = {"version": 1, "confirmed_at": "2026-10-01",
                   "paths": [{"glob": "deploy/**", "exposure": "internal_authenticated",
                              "data": "internal"}]}


class TestProfileEndToEnd(Repo):
    def test_without_a_profile_the_finding_blocks_and_nothing_is_reported_about_one(self):
        result, verdict = self.verdict([fact_finding(impact="data_read")])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(verdict["open"][0]["severity"], "critical")
        self.assertEqual((verdict["adjusted"], verdict["warnings"]), ([], []))

    def test_internal_authenticated_downgrades_and_the_downgrade_is_printed(self):
        self.put_profile(INTERNAL_DEPLOY)
        result = self.evaluate([fact_finding(impact="data_read")])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("advisory: precondition network -> authenticated_user via "
                      "exposure=internal_authenticated for deploy/**", result.stdout)
        self.assertIn("severity critical -> medium", result.stdout)

    def test_a_path_the_profile_does_not_cover_stays_at_the_worst_case(self):
        self.put_profile(INTERNAL_DEPLOY)
        result = self.evaluate([fact_finding(impact="data_read", file="src/api.py")])
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_overlapping_globs_resolve_to_the_worse_value(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01", "paths": [
            {"glob": "deploy/**", "exposure": "internal_authenticated"},
            {"glob": "deploy/public/**", "exposure": "internet"}]})
        _, verdict = self.verdict([fact_finding(file="deploy/public/x.py")])
        self.assertEqual(verdict["open"][0]["severity"], "critical")

    def test_exposure_internet_in_the_profile_never_lowers_the_floor(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01",
                          "default": {"exposure": "internet", "data": "public_or_none",
                                      "visibility": "private",
                                      "merge_control": "code_owner_review_required"}})
        result, verdict = self.verdict([fact_finding(impact="integrity")])
        self.assertEqual(result.returncode, 1)
        self.assertTrue(verdict["open"][0]["floor"])

    def test_internal_authenticated_does_not_lower_a_precondition_of_none(self):
        self.put_profile(INTERNAL_DEPLOY)
        _, verdict = self.verdict([fact_finding(attacker_precondition="none", impact="code_exec")])
        self.assertTrue(verdict["open"][0]["floor"])

    def test_the_floor_in_the_disposition_guardrail_uses_the_effective_precondition(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01",
                          "default": {"exposure": "internal_authenticated"}})
        write(os.path.join(self.repo, ".clagentic", "dispositions.json"), {"entries": [{
            "id": "d1", "gates": ["review"], "match": {"path_glob": "**/*.py", "category": "security"},
            "kind": "by_design", "rationale": "intentional", "by": "maintainer", "at": "2026-01-01"}]})
        git(self.repo, "add", ".clagentic/dispositions.json")
        git(self.repo, "commit", "-q", "-m", "dispositions")
        high = fact_finding(impact="code_exec")
        _, verdict = self.verdict([high])
        self.assertFalse(verdict["open"] and verdict["open"][0]["floor"])
        self.assertEqual(len(verdict["cleared"]), 1, "off the floor, by_design can clear it")
        _, floor = self.verdict([fact_finding(attacker_precondition="none", message="other", line=50)])
        self.assertTrue(floor["open"][0]["floor"])
        self.assertEqual(floor["refused"][0]["kind"], "by_design")

    def test_a_standalone_evaluate_in_an_unenrolled_repo_matches_the_gate_path(self):
        other = make_repo(os.path.join(self.tmp, "other"))
        for repo in (self.repo, other):
            commit_file(repo, ".clagentic/risk-profile.json", INTERNAL_DEPLOY, "profile")
        items = [fact_finding(impact="data_read"), fact_finding(file="src/a.py", line=9, message="b")]
        _, standalone = self.verdict(items, extra=["--caller", "standalone"])
        _, gates = self.verdict(items, extra=["--caller", "gates"], repo=other)
        def shape(v):
            return ([(i["file"], i["severity"], i["floor"]) for i in v["open"]],
                    [(a["moved"], a["outcome"]) for a in v["adjusted"]], v["verdict"])
        self.assertEqual(shape(standalone), shape(gates))
        self.assertNotIn("review-ledger.jsonl",
                         os.listdir(os.path.join(self.repo, ".clagentic", "lite")))

    def test_the_markdown_report_and_the_json_form_agree(self):
        self.put_profile(INTERNAL_DEPLOY)
        report = ("[FINDING] CWE-78 | deploy/app.py:3 | severity: critical | reachable: yes | "
                  "precondition: network | impact: data_read | tier: blocking | class: durable | "
                  "title: command built from request input\n")
        result = run_findings(["evaluate", "--gate", "adversarial", "--format", "markdown",
                               "--today", TODAY, "--json"], stdin=report, cwd=self.repo)
        verdict = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(verdict["advisory"], 1)
        self.assertEqual(verdict["adjusted"][0]["outcome"], "advisory")

    def test_a_profile_in_the_gated_diff_does_not_apply_to_that_diff(self):
        git(self.repo, "checkout", "-q", "-b", "feat/x")
        self.put_profile(INTERNAL_DEPLOY, "add the profile")
        result = self.evaluate([fact_finding(impact="data_read")], extra=["--base", "main"])
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("is not in the base commit", result.stdout)
        git(self.repo, "checkout", "-q", "main")
        git(self.repo, "merge", "-q", "--ff-only", "feat/x")
        merged = self.evaluate([fact_finding(impact="data_read")], extra=["--base", "main"])
        self.assertEqual(merged.returncode, 0, merged.stdout)

    def test_an_edit_to_the_profile_in_the_diff_leaves_the_base_version_in_force(self):
        self.put_profile(INTERNAL_DEPLOY)
        git(self.repo, "checkout", "-q", "-b", "feat/x")
        loosened = json.loads(json.dumps(INTERNAL_DEPLOY))
        loosened["paths"][0]["exposure"] = "local_or_ci_only"
        self.put_profile(loosened, "loosen")
        _, verdict = self.verdict([fact_finding(impact="code_exec")], extra=["--base", "main"])
        self.assertEqual(verdict["open"][0]["severity"], "high", "the base version (internal) applies")
        self.assertTrue(any("differs from its base version" in w for w in verdict["warnings"]))

    def test_an_unresolvable_base_ignores_the_profile_loudly(self):
        self.put_profile(INTERNAL_DEPLOY)
        result, verdict = self.verdict([fact_finding(impact="data_read")],
                                       extra=["--base", "no-such-ref"])
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("base commit could not be resolved" in w for w in verdict["warnings"]))

    def test_an_unreadable_or_invalid_profile_is_the_worst_case_with_a_reason(self):
        self.put_profile("{not json")
        result, verdict = self.verdict([fact_finding(impact="data_read")])
        self.assertEqual(result.returncode, 1)
        self.assertTrue(any("not valid JSON" in w for w in verdict["warnings"]))

    def test_an_invalid_value_in_the_profile_is_its_dimension_worst_case(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01",
                          "default": {"exposure": "internal-ish", "data": "internal"}})
        _, verdict = self.verdict([fact_finding(impact="code_exec")])
        self.assertEqual(verdict["open"][0]["severity"], "critical")
        self.assertTrue(any("internal-ish" in w for w in verdict["warnings"]))

    def test_facts_make_a_model_claim_of_low_irrelevant_and_a_claim_of_critical_too(self):
        _, quiet = self.verdict([fact_finding(severity_claimed="critical",
                                              attacker_precondition="local_ci_only",
                                              impact="quality_only", message="style")])
        self.assertEqual((quiet["open"], quiet["advisory"]), ([], 1))


class TestTreeInference(Repo):
    INGRESS = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\n"

    def setUp(self):
        super().setUp()
        commit_file(self.repo, "deploy/ingress.yaml", self.INGRESS, "ingress")

    def test_a_public_ingress_overrides_a_profile_claim_of_internal(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01",
                          "default": {"exposure": "internal_authenticated"}})
        result, verdict = self.verdict([fact_finding(impact="code_exec"),
                                        fact_finding(file="src/x.py", message="other")])
        by_file = {i["file"]: i["severity"] for i in verdict["open"]}
        self.assertEqual(by_file["deploy/app.py"], "critical", "the ingress path stays exposed")
        self.assertEqual(by_file["src/x.py"], "high", "the claim holds where nothing contradicts it")
        self.assertTrue(any("contradicts it" in w and "deploy/ingress.yaml" in w
                            for w in verdict["warnings"]), verdict["warnings"])

    def test_an_ingress_marked_internal_is_not_a_contradiction(self):
        commit_file(self.repo, "deploy/ingress.yaml",
                    self.INGRESS + "spec:\n  ingressClassName: nginx-internal\n", "internal ingress")
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01",
                          "default": {"exposure": "internal_authenticated"}})
        _, verdict = self.verdict([fact_finding(impact="code_exec")])
        self.assertEqual(verdict["open"][0]["severity"], "high")
        self.assertFalse(any("contradicts" in w for w in verdict["warnings"]))

    def test_other_exposure_markers(self):
        markers = {
            "svc/Dockerfile": "FROM x\nEXPOSE 8080\n",
            "svc2/service.yaml": "kind: Service\nspec:\n  type: LoadBalancer\n",
            "app/server.py": "app = Flask(__name__)\n",
            ".github/workflows/ci.yml": "on:\n  pull_request_target:\n",
        }
        for rel, content in markers.items():
            with self.subTest(rel=rel):
                commit_file(self.repo, rel, content, "marker " + rel)
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01",
                          "default": {"exposure": "local_or_ci_only"}})
        _, verdict = self.verdict([fact_finding(file=rel, line=i + 1, message="m%d" % i)
                                   for i, rel in enumerate(list(markers) + ["plain/x.py"])])
        severity = {i["file"]: i["severity"] for i in verdict["open"]}
        for rel in markers:
            self.assertEqual(severity[rel], "critical", rel)
        self.assertNotIn("plain/x.py", severity, "an unmarked path keeps the profile's claim")

    def test_pii_shaped_schema_fields_contradict_a_claim_of_public_data(self):
        commit_file(self.repo, "db/schema.sql", "create table u (id int, email text);\n", "schema")
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01",
                          "default": {"data": "public_or_none"}})
        _, verdict = self.verdict([fact_finding(file="db/migrate.py", attacker_precondition="authenticated_user",
                                                impact="data_read")])
        self.assertEqual(verdict["open"][0]["severity"], "high")
        self.assertTrue(any("data=public_or_none" in w and "contradicts" in w
                            for w in verdict["warnings"]))

    def test_test_paths_are_not_served_but_only_under_a_profile_and_only_when_unstated(self):
        item = fact_finding(file="tests/test_x.py", impact="code_exec")
        _, bare = self.verdict([item])
        self.assertEqual(bare["open"][0]["severity"], "critical")
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01", "default": {"data": "internal"}})
        _, with_profile = self.verdict([item])
        self.assertEqual(with_profile["adjusted"][0]["severity"], "medium")
        self.assertIn("exposure=local_or_ci_only", with_profile["adjusted"][0]["moved"])
        self.assertIn("a test path", with_profile["adjusted"][0]["moved"])

    def test_no_inference_runs_and_nothing_is_said_without_a_profile(self):
        _, verdict = self.verdict([fact_finding(impact="code_exec")])
        self.assertEqual(verdict["warnings"], [])


class TestAnEnclosingRepositoryIsNotTheTree(Repo):
    """git -C answers with the ancestor's refs and files for a directory that
    is only inside another repository; a profile read there would be the
    ancestor's, deciding this tree's severity."""

    def setUp(self):
        super().setUp()
        self.put_profile(INTERNAL_DEPLOY)
        self.inner = os.path.join(self.repo, "pkg")
        os.makedirs(self.inner)

    def test_no_base_is_resolved_for_such_a_directory(self):
        self.assertIsNotNone(findings.resolve_base(self.repo, "", "main"))
        for explicit in ("", "main"):
            with self.subTest(explicit=explicit):
                self.assertIsNone(findings.resolve_base(self.inner, explicit, "main"))

    def test_the_ancestors_profile_never_applies_even_given_the_ancestors_base(self):
        base = findings.resolve_base(self.repo, "", "main")
        stakes = findings.load_stakes(self.inner, base, datetime.date(2026, 10, 9))
        self.assertFalse(stakes.present)
        self.assertEqual(stakes.dims_for("deploy/app.py")["exposure"][0], "internet")

    def test_a_profile_file_in_such_a_directory_is_ignored_loudly(self):
        write(os.path.join(self.inner, ".clagentic", "risk-profile.json"), INTERNAL_DEPLOY)
        base = findings.resolve_base(self.repo, "", "main")
        stakes = findings.load_stakes(self.inner, base, datetime.date(2026, 10, 9))
        self.assertFalse(stakes.present)
        self.assertTrue(any("could not be resolved" in w for w in stakes.warnings), stakes.warnings)

    def test_the_profile_command_refuses_to_run_there(self):
        result = run_findings(["profile", "--root", self.inner, "--today", TODAY])
        self.assertEqual(result.returncode, 2)
        self.assertIn("not the top level of a git repository", result.stderr)


class TestCodeowners(Repo):
    PROFILE = {"version": 1, "confirmed_at": "2026-10-01",
               "default": {"merge_control": "code_owner_review_required"}}
    ITEM = dict(attacker_precondition="repo_write_can_merge", file="src/app.py")

    def test_coverage_in_every_conventional_location_supports_the_claim(self):
        for rel in (".github/CODEOWNERS", ".gitea/CODEOWNERS", ".forgejo/CODEOWNERS",
                    ".gitlab/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            with self.subTest(rel=rel):
                repo = make_repo(os.path.join(self.tmp, "r-" + re.sub(r"\W", "_", rel)))
                commit_file(repo, rel, "# owners\n*  @team/maintainers\n", "owners")
                commit_file(repo, ".clagentic/risk-profile.json", self.PROFILE, "profile")
                _, verdict = self.verdict([fact_finding(**self.ITEM)], repo=repo)
                self.assertEqual(verdict["open"], [], verdict)
                self.assertEqual(verdict["advisory"], 1)
                self.assertIn("merge_control=code_owner_review_required",
                              verdict["adjusted"][0]["moved"])

    def test_the_claim_without_a_codeowners_file_is_ignored_loudly(self):
        self.put_profile(self.PROFILE)
        _, verdict = self.verdict([fact_finding(**self.ITEM)])
        self.assertEqual(verdict["open"][0]["severity"], "high")
        self.assertTrue(any("no CODEOWNERS file exists" in w for w in verdict["warnings"]))

    def test_a_rule_without_an_owner_or_for_other_paths_does_not_cover(self):
        for rules in ("*\n", "docs/ @team\n", "/other/ @team\n"):
            with self.subTest(rules=rules):
                repo = make_repo(os.path.join(self.tmp, "r%d" % abs(hash(rules))))
                commit_file(repo, "CODEOWNERS", rules, "owners")
                commit_file(repo, ".clagentic/risk-profile.json", self.PROFILE, "profile")
                _, verdict = self.verdict([fact_finding(**self.ITEM)], repo=repo)
                self.assertEqual(verdict["open"][0]["severity"], "high")
                self.assertTrue(any("CODEOWNERS" in w for w in verdict["warnings"]))

    def test_a_codeowners_file_added_in_the_same_change_does_not_support_it(self):
        self.put_profile(self.PROFILE)
        git(self.repo, "checkout", "-q", "-b", "feat/x")
        commit_file(self.repo, "CODEOWNERS", "* @team\n", "add owners")
        _, verdict = self.verdict([fact_finding(**self.ITEM)], extra=["--base", "main"])
        self.assertEqual(verdict["open"][0]["severity"], "high")

    def test_codeowners_globs(self):
        cases = {"/docs/": ["docs/**"], "*.js": ["**/*.js"], "src/app": ["src/app", "src/app/**"],
                 "/a.txt": ["a.txt", "a.txt/**"]}
        for pattern, globs in cases.items():
            with self.subTest(pattern=pattern):
                self.assertEqual(findings.codeowners_globs(pattern), globs)


class TestReconfirmation(Repo):
    def test_an_old_profile_is_prompted_for_confirmation_not_blocked(self):
        self.put_profile({"version": 1, "confirmed_at": "2025-01-01", "default": {"data": "internal"}})
        result, verdict = self.verdict([])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(any("last confirmed on 2025-01-01" in w for w in verdict["warnings"]))
        _, relaxed = self.verdict([], env={"CLAGENTIC_RISK_PROFILE_MAX_AGE_DAYS": "100000"})
        self.assertFalse(any("last confirmed" in w for w in relaxed["warnings"]))

    def test_a_profile_never_confirmed_is_prompted_too(self):
        self.put_profile({"version": 1, "default": {"data": "internal"}})
        _, verdict = self.verdict([])
        self.assertTrue(any("no valid confirmed_at" in w for w in verdict["warnings"]))

    def test_a_diff_touching_the_exposure_surface_prompts_for_reconfirmation(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01", "default": {"data": "internal"}})
        git(self.repo, "checkout", "-q", "-b", "feat/x")
        commit_file(self.repo, "deploy/ingress.yaml", "kind: Ingress\n", "add an ingress")
        result, verdict = self.verdict([], extra=["--base", "main"])
        self.assertEqual(result.returncode, 0, "a prompt, not a block")
        self.assertTrue(any("touches the exposure surface" in w and "deploy/ingress.yaml" in w
                            for w in verdict["warnings"]), verdict["warnings"])

    def test_the_exposure_filter_runs_before_the_path_cap(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01", "default": {"data": "internal"}})
        git(self.repo, "checkout", "-q", "-b", "feat/x")
        for index in range(5):
            write(os.path.join(self.repo, "a%d.txt" % index), "x\n")
        commit_file(self.repo, "deploy/ingress.yaml", "kind: Ingress\n", "an ingress sorted past the cap")
        base = findings.resolve_base(self.repo, "main", "main")
        infer = findings.modules["infer"]
        saved = infer.CHANGED_PATHS_MAX
        infer.CHANGED_PATHS_MAX = 3
        self.addCleanup(setattr, infer, "CHANGED_PATHS_MAX", saved)
        touched = findings.changed_paths(self.repo, base, lambda p: p.endswith("ingress.yaml"))
        self.assertEqual(touched, ["deploy/ingress.yaml"])

    def test_an_unrelated_diff_does_not(self):
        self.put_profile({"version": 1, "confirmed_at": "2026-10-01", "default": {"data": "internal"}})
        git(self.repo, "checkout", "-q", "-b", "feat/x")
        commit_file(self.repo, "lib/util.py", "x = 1\n", "unrelated")
        _, verdict = self.verdict([], extra=["--base", "main"])
        self.assertFalse(any("exposure surface" in w for w in verdict["warnings"]))


class TestProfileCommand(Repo):
    def run_profile(self, *args):
        return run_findings(["profile", "--root", self.repo, "--today", TODAY] + list(args))

    def test_a_draft_is_printed_not_written_and_carries_inferred_evidence(self):
        commit_file(self.repo, "deploy/ingress.yaml", "kind: Ingress\n", "ingress")
        result = self.run_profile()
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["paths"][0]["exposure"], "internet")
        self.assertTrue(document["paths"][0]["inferred"])
        self.assertIn("deploy/ingress.yaml", document["paths"][0]["evidence"])
        self.assertNotIn("confirmed_at", document, "inference alone confirms nothing")
        self.assertFalse(os.path.exists(os.path.join(self.repo, ".clagentic", "risk-profile.json")))
        self.assertIn("unstated", result.stderr)

    def test_answers_are_written_with_a_confirmation_date_and_survive_an_update(self):
        first = self.run_profile("--answer", "deploy/**:exposure=internal_authenticated",
                                 "--answer", "data=internal", "--write")
        self.assertEqual(first.returncode, 0, first.stderr)
        path = os.path.join(self.repo, ".clagentic", "risk-profile.json")
        with open(path) as handle:
            written = json.load(handle)
        self.assertEqual(written["confirmed_at"], TODAY)
        self.assertEqual(written["default"], {"data": "internal"})
        self.assertEqual(written["paths"], [{"glob": "deploy/**", "exposure": "internal_authenticated"}])
        commit_file(self.repo, "deploy/ingress.yaml", "kind: Ingress\n", "ingress")
        second = self.run_profile("--answer", "visibility=private", "--write")
        self.assertEqual(second.returncode, 0, second.stderr)
        with open(path) as handle:
            updated = json.load(handle)
        self.assertEqual(updated["default"], {"data": "internal", "visibility": "private"})
        operator = [p for p in updated["paths"] if not p.get("inferred")]
        self.assertEqual(operator, [{"glob": "deploy/**", "exposure": "internal_authenticated"}])
        self.assertIn("WARN", second.stderr)
        self.assertIn("contradicted by the tree", second.stderr)

    def test_a_written_profile_is_what_evaluate_reads_once_committed(self):
        self.run_profile("--answer", "deploy/**:exposure=internal_authenticated",
                         "--answer", "deploy/**:data=internal", "--write")
        git(self.repo, "add", ".clagentic/risk-profile.json")
        git(self.repo, "commit", "-q", "-m", "profile")
        result = self.evaluate([fact_finding(impact="data_read")])
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_a_malformed_answer_is_refused(self):
        for answer in ("exposure=moon", "colour=red", "exposure", "a:b:c"):
            with self.subTest(answer=answer):
                result = self.run_profile("--answer", answer)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("profile refused", result.stderr)

    def test_an_existing_file_that_is_not_a_profile_is_not_overwritten(self):
        write(os.path.join(self.repo, ".clagentic", "risk-profile.json"), "[1, 2]")
        result = self.run_profile("--answer", "data=internal", "--write")
        self.assertEqual(result.returncode, 2)
        with open(os.path.join(self.repo, ".clagentic", "risk-profile.json")) as handle:
            self.assertEqual(handle.read(), "[1, 2]")


class TestSampleUnion(Repo):
    def samples(self, *documents):
        paths = []
        for index, document in enumerate(documents, 1):
            paths.append(write(os.path.join(self.tmp, "sample-%d.json" % index), document))
        return paths

    def union(self, *documents):
        paths = self.samples(*documents)
        result = run_findings(["ingest", "union-samples"] + paths + ["--root", self.repo])
        return result, (json.loads(result.stdout) if result.stdout else None)

    def test_the_rubric_severity_decides_not_the_claimed_one(self):
        weak = fact_finding(severity_claimed="critical", attacker_precondition="local_ci_only",
                            impact="quality_only", message="the same observation")
        strong = fact_finding(severity_claimed="low", message="the same observation")
        result, merged = self.union({"summary": "a", "findings": [weak]},
                                    {"summary": "b", "findings": [strong]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(merged["findings"]), 1)
        self.assertEqual(merged["findings"][0]["impact"], "code_exec")
        self.assertIn("sample 1/2: 1 finding(s)", result.stderr)
        self.assertIn("sample 2/2: 1 finding(s)", result.stderr)

    def test_findings_link_by_fingerprint_hint_or_by_location(self):
        a = fact_finding(line=3, message="reworded here")
        b = fact_finding(line=3, message="and reworded there")
        c = fact_finding(line=40, message="reworded here")
        d = fact_finding(line=60, message="a different problem entirely", category="correctness")
        result, merged = self.union({"findings": [a]}, {"findings": [b, c]}, {"findings": [d]})
        self.assertEqual(sorted(f["line"] for f in merged["findings"]), [3, 60],
                         "b links to a by location, c to a by fingerprint hint")

    def test_a_degraded_or_unreadable_sample_contributes_nothing_and_is_logged(self):
        good = fact_finding()
        result, merged = self.union({"degraded": True, "findings": [fact_finding(message="x")]},
                                    {"findings": [good]}, "not json at all")
        self.assertEqual(len(merged["findings"]), 1)
        self.assertIn("degraded", result.stderr)
        self.assertIn("unreadable", result.stderr)

    def test_no_usable_sample_is_a_failure_not_an_empty_union(self):
        result, merged = self.union({"degraded": True, "findings": []})
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(merged)

    def test_a_sample_that_is_not_an_envelope_object_is_excluded_not_a_crash(self):
        good = fact_finding()
        for odd in ([fact_finding(message="bare array")], "a string", 7, None):
            with self.subTest(odd=odd):
                result, merged = self.union(odd, {"findings": [good]})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("sample 1/2: unreadable or unusable, excluded", result.stderr)
                self.assertEqual([f["message"] for f in merged["findings"]], [good["message"]])

    def test_a_finding_that_is_not_an_object_is_kept_as_a_blank_worst_case_one(self):
        good = fact_finding()
        result, merged = self.union({"findings": ["not a finding"]}, {"findings": [good]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(len(merged["findings"]), 2, "a finding is never dropped for being malformed")
        self.assertIn({}, merged["findings"])

    def test_only_unusable_samples_fail_closed(self):
        result, merged = self.union([fact_finding()], "scalar", {"degraded": True})
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(merged)
        self.assertNotIn("Traceback", result.stderr)

    def test_the_union_applies_the_profile_of_the_repo(self):
        self.put_profile(INTERNAL_DEPLOY)
        strong_by_claim = fact_finding(severity_claimed="critical", impact="data_read",
                                       attacker_precondition="local_ci_only", message="m")
        strong_by_facts = fact_finding(severity_claimed="low", impact="data_read",
                                       attacker_precondition="none", message="m")
        _, merged = self.union({"findings": [strong_by_claim]}, {"findings": [strong_by_facts]})
        self.assertEqual(merged["findings"][0]["attacker_precondition"], "none")


class TestPromptsAskForFacts(unittest.TestCase):
    def block(self, role, name):
        with open(os.path.join(PROMPTS, role + ".shared.txt")) as handle:
            text = handle.read()
        match = re.search(r"^@@@ %s\n(.*?)(?=^@@@ |\Z)" % re.escape(name), text, re.S | re.M)
        self.assertIsNotNone(match, "%s has no %s block" % (role, name))
        return match.group(1)

    def test_both_roles_name_every_value_of_every_closed_vocabulary(self):
        for role in ("reviewer", "auditor"):
            facts = self.block(role, "facts")
            for vocabulary in (findings.PRECONDITIONS, findings.IMPACTS):
                for value in vocabulary:
                    with self.subTest(role=role, value=value):
                        self.assertIn(value, facts)

    def test_the_reviewer_schema_asks_for_facts_and_keeps_the_claim_for_display(self):
        schema = self.block("reviewer", "schema")
        for key in ("severity_claimed", "reachable", "attacker_precondition", "impact", '"class"'):
            self.assertIn(key, schema)

    def test_removal_aware_review_is_in_both_roles(self):
        for role in ("reviewer", "auditor"):
            text = self.block(role, "removal-aware")
            self.assertIn("does the invariant still hold", text)
            self.assertIn("declined layers", text)
            self.assertIn("never authority", text)

    def test_the_auditor_header_format_carries_the_facts(self):
        header = self.block("auditor", "finding-format")
        self.assertIn("precondition: <", header)
        self.assertIn("impact: <", header)


class TestIngestKeepsTheFacts(unittest.TestCase):
    def test_the_review_envelope_keeps_facts_and_strips_forgeries(self):
        with tempfile.TemporaryDirectory(prefix="clagentic-test-ingest-") as tmp:
            path = write(os.path.join(tmp, "env.json"), {"summary": "s", "findings": [
                dict(fact_finding(), disposition={"status": "cleared"}, floor=False, rubric_applied=True,
                     moves=["forged"], severity_moved="forged")]})
            result = run_findings(["ingest", "review-envelope", path])
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(path) as handle:
                [kept] = json.load(handle)["findings"]
        for key in ("attacker_precondition", "impact", "reachable", "class", "severity_claimed"):
            self.assertIn(key, kept)
        for key in ("disposition", "floor", "rubric_applied", "moves", "severity_moved"):
            self.assertNotIn(key, kept)


if __name__ == "__main__":
    unittest.main()
