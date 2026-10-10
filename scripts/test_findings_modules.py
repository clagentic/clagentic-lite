"""
Unit tests, one class per module of the finding pipeline package
(plugins/clagentic-lite/bin/clagentic_findings/), calling each module's own
exported functions on real inputs. The CLI-level behaviour is covered by the
stage tests (test_findings_pipeline.py and its siblings); these pin each
module's contract on its own so a change to one module cannot hide behind
another.

Run with: python3 -m unittest scripts/test_findings_modules.py -v
"""
import datetime
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

from scripts.findings_test_support import (
    commit_file, entry, finding, git, head, load_module, make_repo, write)

findings = load_module()
M = findings.modules
TODAY = datetime.date(2026, 10, 10)
HEAD_SHA = "a" * 40


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-findings-modules-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def repo(self, name="repo"):
        return make_repo(self.path(name))


def unified(**over):
    base = {"severity": "high", "file": "app.py", "line": 2, "category": "security",
            "message": "m", "attacker_precondition": "authenticated_user",
            "impact": "code_exec", "reachable": "yes", "class": "durable"}
    base.update(over)
    return M["unify"].unify_finding(base, "review")


class TestFileio(Tmp):
    def test_dumps_is_compact_and_keeps_non_ascii(self):
        self.assertEqual(M["fileio"].dumps({"a": "é", "b": [1, 2]}), '{"a":"é","b":[1,2]}')
        self.assertEqual(M["fileio"].dumps({"a": 1}, indent=2), '{\n  "a": 1\n}')

    def test_write_file_atomic_replaces_the_content_and_keeps_the_mode(self):
        target = self.path("out.json")
        write(target, "old")
        os.chmod(target, 0o640)
        M["fileio"].write_file_atomic(target, "new")
        with open(target) as handle:
            self.assertEqual(handle.read(), "new")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o640)
        self.assertEqual(os.listdir(self.tmp), ["out.json"])

    def test_positive_int_env_falls_back_loudly_on_a_rejected_value(self):
        for raw, expected in (("7", 7), ("", 5), ("0", 5), ("-3", 5), ("x", 5)):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"CLAGENTIC_T": raw}), \
                    mock.patch.object(sys, "stderr", io.StringIO()) as err:
                self.assertEqual(M["fileio"].positive_int_env("CLAGENTIC_T", 5), expected)
                self.assertEqual("WARN" in err.getvalue(), raw not in ("7", ""))

    def test_max_field_chars_is_resolved_once_per_process(self):
        fileio = load_module().modules["fileio"]
        with mock.patch.dict(os.environ, {"CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS": "250"}):
            self.assertEqual(fileio.max_field_chars(), 250)
        with mock.patch.dict(os.environ, {"CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS": "999"}):
            self.assertEqual(fileio.max_field_chars(), 250)


class TestDigest(unittest.TestCase):
    ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    def test_text_and_stream_digests_agree(self):
        self.assertEqual(M["digest"].sha256_hex("abc"), self.ABC)
        self.assertEqual(M["digest"].sha256_stream(io.BytesIO(b"abc"), chunk=2), self.ABC)


class TestSeverity(unittest.TestCase):
    def test_canonical_severity_normalizes_and_guesses_nothing(self):
        s = M["severity"]
        self.assertEqual(s.canonical_severity(" HIGH "), "high")
        self.assertIsNone(s.canonical_severity("crit"))
        self.assertIsNone(s.canonical_severity(5))

    def test_an_unrankable_severity_ranks_as_blocking(self):
        s = M["severity"]
        self.assertEqual((s.severity_rank(None), s.severity_rank("Low"), s.severity_rank("blocker")),
                         (0, 1, 4))
        self.assertTrue(s.counts_toward_verdict({"severity": "???"}, 3))
        self.assertFalse(s.counts_toward_verdict({"severity": "medium"}, 3))

    def test_an_unknown_threshold_means_high(self):
        self.assertEqual((M["severity"].threshold_rank("nope"), M["severity"].threshold_rank("critical")),
                         (3, 4))

    def test_triple_is_the_cross_round_match_key(self):
        self.assertEqual(M["severity"].triple({"file": "a", "category": 1}), ("a", "1", ""))


class TestErrors(unittest.TestCase):
    def test_a_stage_failure_carries_its_exit_status(self):
        self.assertEqual(M["errors"].StageFailure(11).code, 11)
        self.assertTrue(issubclass(M["errors"].InputRefused, Exception))


class TestSanitize(unittest.TestCase):
    def test_terminal_text_turns_control_bytes_into_spaces(self):
        self.assertEqual(M["sanitize"].terminal_text("a\x1b[31mb\nc‮"), "a [31mb c ")
        self.assertEqual(M["sanitize"].terminal_text(None), "")
        self.assertEqual(M["sanitize"].terminal_text("abcdef", 3), "abc")

    def test_sanitize_text_strips_escapes_and_defangs_fence_labels(self):
        s = M["sanitize"]
        self.assertEqual(s.sanitize_text("x\x1b[31my\x00z", 100), "xyz")
        label = "===BEGIN CODE VERDICT DATA==="
        defanged = s.sanitize_text(label, 1000)
        self.assertNotIn("===BEGIN", defanged)
        self.assertEqual(defanged.replace(" ", ""), label.replace(" ", ""))

    def test_sanitize_text_truncates_to_the_limit(self):
        out = M["sanitize"].sanitize_text("a" * 100, 20)
        self.assertEqual((len(out), out.endswith("...[truncated]")), (20, True))

    def test_allowlist_keeps_only_declared_fields_of_the_declared_type(self):
        s = M["sanitize"]
        self.assertEqual(s.allowlist_fields([{"a": "x", "b": 1, "c": True, "d": "y"}],
                                            ["a", "b:number", "c:number"]), [{"a": "x", "b": 1}])
        with self.assertRaises(ValueError):
            s.allowlist_fields([], [])

    def test_sanitize_fields_strict_fails_closed(self):
        s = M["sanitize"]
        self.assertEqual(s.sanitize_fields_strict([{"m": "a\x00b", "other": "\x00"}], ["m"]),
                         [{"m": "ab", "other": "\x00"}])
        for bad in ([1], "x"):
            with self.assertRaises(ValueError):
                s.sanitize_fields_strict(bad, ["m"])

    def test_shell_value_drops_trailing_newlines_only(self):
        self.assertEqual(M["sanitize"].shell_value("x\ny\n\n"), "x\ny")


class TestPaths(Tmp):
    def test_norm_path_collapses_what_could_reach_another_glob(self):
        p = M["paths"]
        self.assertEqual([p.norm_path(x) for x in ("src/../auth.py", "./a", "", ".")],
                         ["auth.py", "a", "", ""])

    def test_plain_relative_path_refuses_anything_that_escapes(self):
        p = M["paths"]
        self.assertEqual(p.plain_relative_path("a/b"), "a/b")
        for bad in ("a/../b", "/etc/passwd", "C:x", "", "a\x00b"):
            self.assertIsNone(p.plain_relative_path(bad), bad)

    def test_open_contained_regular_reads_only_regular_files_inside_the_root(self):
        root = self.path("root")
        write(os.path.join(root, "ok.txt"), "data")
        os.makedirs(os.path.join(root, "dir"))
        outside = self.path("outside.txt")
        write(outside, "secret")
        os.symlink(outside, os.path.join(root, "link.txt"))
        handle = M["paths"].open_contained_regular(root, "ok.txt")
        self.assertEqual(handle.read(), b"data")
        handle.close()
        for rel in ("link.txt", "dir", "missing.txt", "../outside.txt"):
            self.assertIsNone(M["paths"].open_contained_regular(root, rel), rel)

    def test_norm_text_folds_case_and_space(self):
        self.assertEqual(M["paths"].norm_text("  A   B\tc "), "a b c")


class TestGlobs(unittest.TestCase):
    def test_star_stays_in_a_segment_and_globstar_crosses_them(self):
        g = M["globs"]
        self.assertTrue(g.glob_matches("src/**/*.py", "src/a/b.py"))
        self.assertFalse(g.glob_matches("src/*.py", "src/a/b.py"))
        self.assertTrue(g.glob_matches("**", "a/b/c"))
        self.assertTrue(g.glob_matches("a?c", "abc"))

    def test_a_backslash_escapes_the_next_character(self):
        g = M["globs"]
        self.assertTrue(g.glob_matches("a\\*c", "a*c"))
        self.assertFalse(g.glob_matches("a\\*c", "abc"))
        self.assertEqual(g.glob_escape("a*b?c\\d"), "a\\*b\\?c\\\\d")

    def test_a_catch_all_is_decided_by_matching_not_by_spelling(self):
        g = M["globs"]
        for glob in ("*", "**", "**/*", "***", "**/**"):
            self.assertTrue(g.matches_every_probe(glob), glob)
        for glob in ("src/*.py", ".env", "a"):
            self.assertFalse(g.matches_every_probe(glob), glob)

    def test_a_pathological_glob_matches_in_linear_time(self):
        self.assertFalse(M["globs"].glob_matches("*a" * 40 + "b", "a" * 200))


class TestDates(unittest.TestCase):
    def test_parse_date_takes_a_leading_date_only(self):
        d = M["dates"]
        self.assertEqual(d.parse_date("2026-10-09"), datetime.date(2026, 10, 9))
        self.assertEqual(d.parse_date("2026-10-09T12:00:00Z"), datetime.date(2026, 10, 9))
        for bad in ("2026-13-01", "10/09/2026", 5, None):
            self.assertIsNone(d.parse_date(bad), bad)

    def test_today_override_is_refused_when_it_is_not_a_date(self):
        d = M["dates"]
        self.assertEqual(d.today_date("2026-01-02"), datetime.date(2026, 1, 2))
        with self.assertRaises(M["errors"].InputRefused):
            d.today_date("garbage")
        with mock.patch.dict(os.environ, {"CLAGENTIC_FINDINGS_TODAY": "2026-02-03"}):
            self.assertEqual(d.today_date(), datetime.date(2026, 2, 3))


class TestGitstate(Tmp):
    def test_the_top_level_is_proven_not_assumed(self):
        g = M["gitstate"]
        repo = self.repo()
        sub = os.path.join(repo, "sub")
        os.makedirs(sub)
        self.assertTrue(g.is_repo_toplevel(repo))
        self.assertFalse(g.is_repo_toplevel(sub))
        self.assertEqual(g.repo_head(repo), head(repo))
        self.assertIsNone(g.repo_head(sub))
        self.assertIsNone(g.resolve_base(sub, "", "main"))

    def test_resolve_base_takes_an_explicit_ref_or_the_default_branch(self):
        g = M["gitstate"]
        repo = self.repo()
        first = head(repo)
        git(repo, "checkout", "-q", "-b", "feat/x")
        commit_file(repo, "b.txt", "b\n")
        self.assertEqual(g.resolve_base(repo, "", "main"), first)
        self.assertEqual(g.resolve_base(repo, "main", ""), first)
        self.assertIsNone(g.resolve_base(repo, "-bad", ""))
        self.assertIsNone(g.resolve_base(repo, "no-such-ref", ""))

    def test_the_base_reader_returns_the_committed_text_not_the_working_tree(self):
        g = M["gitstate"]
        repo = self.repo()
        base = head(repo)
        write(os.path.join(repo, "app.py"), "changed\n")
        self.assertEqual(g.git_reader(repo, base)("app.py"), "print('hi')\n")
        self.assertIsNone(g.git_reader(repo, base)("absent.txt"))
        self.assertEqual(g.worktree_reader(repo)("app.py"), "changed\n")

    def test_the_worktree_reader_refuses_a_symlink_out_of_the_repository(self):
        repo = self.repo()
        outside = self.path("outside.txt")
        write(outside, "secret")
        os.symlink(outside, os.path.join(repo, "link"))
        with self.assertRaises(OSError):
            M["gitstate"].worktree_reader(repo)("link")

    def test_read_text_bounded_refuses_an_oversized_file(self):
        big = write(self.path("big"), "x" * (M["gitstate"].MAX_FILE_BYTES + 1))
        with self.assertRaises(OSError):
            M["gitstate"].read_text_bounded(big)


class TestRubric(unittest.TestCase):
    def test_a_garbled_fact_is_the_worst_case(self):
        r = M["rubric"]
        result = r.evaluate_rubric("bogus", "bogus", "maybe", "durable", r.worst_dims())
        self.assertEqual((result["severity"], result["floor"], result["effective_precondition"]),
                         ("critical", True, "none"))

    def test_unreachable_is_capped_and_off_the_floor(self):
        r = M["rubric"]
        result = r.evaluate_rubric("none", "code_exec", "no", "durable", r.worst_dims())
        self.assertEqual((result["severity"], result["floor"]), ("medium", False))

    def test_an_ephemeral_change_lowers_durability_impacts_only(self):
        r = M["rubric"]
        dims = r.worst_dims()
        self.assertEqual(r.evaluate_rubric("authenticated_user", "availability", "yes", "durable",
                                           dims)["severity"], "medium")
        self.assertEqual(r.evaluate_rubric("authenticated_user", "availability", "yes", "ephemeral",
                                           dims)["severity"], "low")
        self.assertEqual(r.evaluate_rubric("authenticated_user", "code_exec", "yes", "ephemeral",
                                           dims)["severity"], "high")

    def test_the_profile_can_move_a_precondition_and_says_so(self):
        r = M["rubric"]
        dims = r.worst_dims()
        dims["exposure"] = ("internal_authenticated", "deploy/**")
        result = r.evaluate_rubric("network", "code_exec", "yes", "durable", dims)
        self.assertEqual(result["effective_precondition"], "authenticated_user")
        self.assertEqual(len(result["moves"]), 1)
        self.assertIn("deploy/**", result["moves"][0])

    def test_worse_value_orders_each_dimension_worst_first(self):
        r = M["rubric"]
        self.assertEqual(r.worse_value("exposure", "internet", "local_or_ci_only"), "internet")
        self.assertEqual(r.worse_value("merge_control", "review_required", "unrestricted"),
                         "unrestricted")

    def test_merged_facts_can_only_rise(self):
        r = M["rubric"]
        known = {"attacker_precondition": "authenticated_user", "impact": "availability"}
        r.merge_facts(known, {"attacker_precondition": "network", "impact": "data_read"})
        self.assertEqual(known, {"attacker_precondition": "network", "impact": "data_read"})
        r.merge_facts(known, {"attacker_precondition": "maintainer_admin", "impact": "quality_only"})
        self.assertEqual(known, {"attacker_precondition": "network", "impact": "data_read"})
        r.merge_facts(known, {"attacker_precondition": "garbage", "impact": "data_read"})
        self.assertEqual(known["attacker_precondition"], "unknown")

    def test_apply_rubric_replaces_severity_and_keeps_the_claim_elsewhere(self):
        r = M["rubric"]
        record = {"source": "adversarial", "reachable": "yes", "class": "durable",
                  "attacker_precondition": "none", "impact": "code_exec", "severity": "low"}
        r.apply_rubric(record, None)
        self.assertEqual((record["severity"], record["tier"], record["floor"]),
                         ("critical", "blocking", True))
        self.assertEqual(r.rubric_moved_text(record), "")


class TestFingerprint(Tmp):
    DIFF = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -0,0 +1,3 @@\n+a\n+b\n+c\n")

    def test_the_diff_index_numbers_added_lines_by_new_file_line(self):
        f = M["fingerprint"]
        index = f.DiffIndex(write(self.path("d.diff"), self.DIFF))
        self.assertEqual(index.by_file["a.py"], [(1, "+a"), (2, "+b"), (3, "+c")])
        self.assertEqual(index.window("a.py", 3), ["+a", "+b", "+c"])
        self.assertEqual(index.window("other.py", 1), [])

    def test_the_window_key_survives_a_changed_message_but_not_changed_lines(self):
        f = M["fingerprint"]
        diff = write(self.path("d.diff"), self.DIFF)
        one = f.window_key({"file": "a.py", "line": 2, "message": "x"}, diff)
        two = f.window_key({"file": "a.py", "line": 2, "message": "y"}, diff)
        self.assertEqual(one, two)
        self.assertIsNone(f.window_key({"file": "a.py", "line": 50}, diff))

    def test_dedup_keeps_the_higher_severity_of_one_location(self):
        f = M["fingerprint"]
        low = {"severity": "low", "file": "a", "line": 1, "category": "c", "message": "m"}
        high = dict(low, severity="high")
        kept, new_keys = f.dedup_findings([low, high], "location", set(), "", False)
        self.assertEqual(([k["severity"] for k in kept], len(new_keys)), (["high"], 1))

    def test_a_seen_key_drops_in_drop_mode_and_annotates_in_annotate_mode(self):
        f = M["fingerprint"]
        item = {"severity": "high", "file": "a", "line": 1, "category": "c", "message": "m"}
        key = f.finding_key(item, "location", "")
        self.assertEqual(f.dedup_findings([item], "location", {key}, "", False)[0], [])
        kept, new_keys = f.dedup_findings([item], "location", {key}, "", True)
        self.assertEqual((kept[0]["_seen_before"], kept[0]["_seen_key"], new_keys), (True, key, []))

    def test_a_finding_whose_key_cannot_be_computed_is_retained(self):
        kept, new_keys = M["fingerprint"].dedup_findings([5, 5], "location", set(), "", False)
        self.assertEqual((kept, new_keys), ([5, 5], []))

    def test_round_counts_persist_and_a_non_integer_reads_as_zero(self):
        f = M["fingerprint"]
        counts_path = self.path("counts.json")
        self.assertEqual(f.bump_counts(counts_path, ["k"]), [1])
        self.assertEqual(f.bump_counts(counts_path, ["k", "z"]), [2, 1])
        self.assertEqual(f.next_counts({"k": True}, ["k"]), [1])
        self.assertEqual(f.read_counts(self.path("absent.json")), {})

    def test_seen_key_files_round_trip(self):
        f = M["fingerprint"]
        keys = self.path("seen")
        self.assertEqual(f.read_key_file(keys), set())
        f.append_key_file(keys, ["a", "b"])
        self.assertEqual(f.read_key_file(keys), {"a", "b"})

    def test_key_rows_are_single_tsv_lines(self):
        f = M["fingerprint"]
        diff = write(self.path("d.diff"), self.DIFF)
        rows = f.content_key_rows([{"file": "a.py", "line": 2, "category": "c\td", "message": "m\nn"}],
                                  diff)
        self.assertEqual([row[1:] for row in rows], [("a.py", "c d", "m n")])


class TestIngest(Tmp):
    def test_a_header_without_facts_defaults_to_reachable_and_the_floor_blocks(self):
        parsed = M["ingest"].parse_adversarial_text(
            "[FINDING] CWE-78 | a.sh:3 | severity: high | title: shell injection\nprose\n")
        self.assertEqual(len(parsed), 1)
        self.assertEqual((parsed[0]["file"], parsed[0]["line"], parsed[0]["reachable"],
                          parsed[0]["tier"], parsed[0]["class"]),
                         ("a.sh", 3, "yes", "blocking", "durable"))

    def test_a_header_with_garbled_facts_is_the_worst_case_not_the_claim(self):
        parsed = M["ingest"].parse_adversarial_text(
            "[FINDING] CWE-78 | a.sh:3 | severity: low | precondition: bogus | impact: code_exec "
            "| title: t\n")[0]
        self.assertEqual((parsed["reachable"], parsed["attacker_precondition"], parsed["severity_claimed"],
                          parsed["severity"], parsed["tier"]),
                         ("unknown", "unknown", "low", "critical", "blocking"))

    def test_unreachable_is_never_blocking_by_the_header_tier(self):
        parsed = M["ingest"].parse_adversarial_text(
            "[FINDING] CWE-1 | x:1 | severity: high | reachable: no | tier: blocking | title: t\n")[0]
        self.assertEqual((parsed["reachable"], parsed["tier"]), ("no", "advisory"))

    def test_the_count_cap_only_ever_drops_the_least_severe_tail(self):
        ordered = M["ingest"].sort_blocking_first([
            {"tier": "advisory", "severity": "critical"}, {"tier": "blocking", "severity": "low"},
            {"tier": "blocking", "severity": "high"}, "junk"])
        self.assertEqual([(i.get("tier"), i.get("severity")) if isinstance(i, dict) else i
                          for i in ordered],
                         [("blocking", "high"), ("blocking", "low"), ("advisory", "critical"), "junk"])

    def test_strict_extraction_refuses_a_present_non_array(self):
        i = M["ingest"]
        env = write(self.path("env.json"), {"findings": None})
        with self.assertRaises(ValueError):
            i.extract_findings_strict(env)
        with mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(i.extract_findings(env), [])
        self.assertEqual(i.extract_findings_strict(write(self.path("e2.json"), {})), [])

    def test_an_envelope_that_cannot_be_reduced_is_replaced_by_the_degraded_stub(self):
        i = M["ingest"]
        env = write(self.path("env.json"), {"findings": None})
        with mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(i.ingest_review_envelope(env), 0)
        with open(env) as handle:
            self.assertTrue(json.load(handle)["sanitize_failed"])
        self.assertEqual(i.ingest_review_envelope(self.path("absent.json")), 0)

    def test_merging_no_envelopes_is_a_degraded_failure(self):
        code, merged = M["ingest"].merge_envelopes(self.tmp, "location")
        self.assertEqual((code, merged["degraded"], merged["_no_envelopes"]), (1, True, True))

    def test_merging_marks_an_unreadable_chunk_degraded(self):
        write(self.path("envelope-001.json"), {"summary": "s", "checked": ["c"],
                                                "findings": [finding()]})
        write(self.path("envelope-002.json"), "not json")
        code, merged = M["ingest"].merge_envelopes(self.tmp, "location")
        self.assertEqual((code, merged["degraded"], merged["chunks"], merged["chunks_degraded"],
                          len(merged["findings"])), (0, True, 2, 1, 1))


class TestUnify(unittest.TestCase):
    def test_a_finding_that_states_no_facts_is_the_worst_case_whatever_it_claimed(self):
        record = M["unify"].unify_finding(
            {"severity": "low", "file": "a", "line": 1, "category": "c", "message": "m"}, "review")
        self.assertEqual((record["severity_claimed"], record["severity"], record["floor"]),
                         ("low", "critical", True))
        self.assertEqual(len(record["fingerprint"]), 32)

    def test_a_forged_key_is_not_carried_over(self):
        record = M["unify"].unify_finding(
            {"file": "a", "line": 1, "category": "c", "message": "m", "disposition": {"status": "cleared"},
             "fingerprint": "forged"}, "review")
        self.assertNotIn("disposition", record)
        self.assertNotEqual(record["fingerprint"], "forged")

    def test_input_that_is_not_an_object_or_is_too_large_is_refused(self):
        u = M["unify"]
        with self.assertRaises(ValueError):
            u.unify_finding("not a dict", "review")
        with self.assertRaises(ValueError):
            u.unify_findings([{}] * (u.EVALUATE_MAX_FINDINGS + 1), "review")
        with self.assertRaises(ValueError):
            u.unify_findings("x", "review")

    def test_identity_ignores_line_case_and_path_spelling_but_not_the_source(self):
        u = M["unify"]
        one = u.finding_identity("review", "a.py", "CWE-1", "Msg  X")
        self.assertEqual(one, u.finding_identity("review", "./a.py", "cwe-1", "msg x"))
        self.assertNotEqual(one, u.finding_identity("adversarial", "a.py", "CWE-1", "Msg X"))

    def test_blocking_is_by_tier_for_the_auditor_and_by_severity_for_the_reviewer(self):
        u = M["unify"]
        self.assertTrue(u.is_blocking({"source": "adversarial", "tier": "blocking"}, 4))
        self.assertFalse(u.is_blocking({"source": "adversarial", "tier": "advisory",
                                        "severity": "critical"}, 1))
        self.assertTrue(u.is_blocking({"source": "review", "severity": "high"}, 3))
        self.assertFalse(u.is_blocking({"source": "review", "severity": "medium"}, 3))


class TestDispositions(Tmp):
    def test_a_valid_entry_is_normalized_and_a_bad_one_names_every_reason(self):
        d = M["dispositions"]
        normalized, errors = d.validate_entry(entry())
        self.assertEqual((errors, normalized["id"], normalized["gates"]), ([], "d1", ["review"]))
        bad, errors = d.validate_entry(entry(rationale="<why>", kind="mitigated"))
        self.assertIsNone(bad)
        self.assertTrue(any("placeholder" in e for e in errors), errors)
        self.assertTrue(any("control" in e for e in errors), errors)

    def test_a_catch_all_match_is_refused(self):
        _, errors = M["dispositions"].validate_entry(
            entry(match={"path_glob": "**", "category": "*"}))
        self.assertTrue(any("catch-all" in e for e in errors), errors)

    def test_matching_is_by_source_glob_category_and_hint(self):
        d = M["dispositions"]
        valid = d.validate_entry(entry(match={"path_glob": "app.py", "category": "security",
                                              "fingerprint_hint": "abcd1234"}))[0]
        hit = {"source": "review", "file": "./app.py", "category": "Security", "fingerprint": "abcd1234ff"}
        self.assertTrue(d.entry_matches(valid, hit))
        self.assertFalse(d.entry_matches(valid, dict(hit, source="adversarial")))
        self.assertFalse(d.entry_matches(valid, dict(hit, fingerprint="ffff0000")))
        self.assertFalse(d.entry_matches(valid, dict(hit, file="other.py")))

    def test_only_a_mitigation_clears_a_floor_finding(self):
        d = M["dispositions"]
        by_design = d.validate_entry(entry())[0]
        mitigated = d.validate_entry(entry(id="m1", kind="mitigated", control="a WAF"))[0]
        self.assertFalse(d.entry_can_clear(by_design, {"floor": True}))
        self.assertTrue(d.entry_can_clear(mitigated, {"floor": True}))
        self.assertTrue(d.entry_can_clear(by_design, {"floor": False}))

    def test_the_store_reports_a_duplicate_id_and_applies_the_first(self):
        d = M["dispositions"]
        text = json.dumps({"entries": [entry(), entry(rationale="second")]})
        store = d.load_store(self.tmp, lambda rel: text if rel == d.DISPOSITIONS_REL else None)
        self.assertEqual(([e["rationale"] for e in store["entries"]], len(store["invalid"])),
                         (["intentional fixture"], 1))

    def test_an_unreadable_file_contributes_nothing_and_one_invalid_record(self):
        d = M["dispositions"]
        store = d.load_store(self.tmp, lambda rel: "{not json" if rel == d.DISPOSITIONS_REL else None)
        self.assertEqual((store["entries"], len(store["invalid"])), ([], 1))

    def test_a_legacy_ack_converts_to_an_accepted_risk_with_a_deprecation_note(self):
        d = M["dispositions"]
        acks = json.dumps([{"cwe": "CWE-79", "path_glob": "web/**", "rationale": "r",
                            "acknowledged_by": "me", "acknowledged_at": "2026-01-01"}])
        store = d.load_store(self.tmp, lambda rel: acks if rel == d.LEGACY_ACKS_REL else None)
        self.assertEqual([(e["kind"], e["gates"]) for e in store["entries"]],
                         [("accepted_risk", ["adversarial"])])
        self.assertTrue(any(w.startswith("DEPRECATED") for w in store["warnings"]))

    def test_migrate_without_write_reports_and_writes_nothing(self):
        d = M["dispositions"]
        code, text, report = d.migrate_dispositions(self.tmp, False)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text), {"version": 1, "entries": []})
        self.assertIn("0 entries", report[0])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, d.DISPOSITIONS_REL)))

    def test_lint_flags_an_invalid_entry_with_a_nonzero_code(self):
        d = M["dispositions"]
        path = write(self.path("d.json"), {"entries": [entry(rationale="<why>")]})
        code, lines = d.lint_dispositions(self.tmp, path)
        self.assertEqual(code, 1)
        self.assertIn("placeholder", " ".join(lines))


class TestPolicy(Tmp):
    def test_without_a_base_nothing_applies_and_the_working_tree_only_proposes(self):
        write(self.path(".clagentic", "dispositions.json"), {"entries": [entry()]})
        store, proposed, notes = M["policy"].load_policy(self.tmp, None)
        self.assertEqual(store["entries"], [])
        self.assertEqual([e["id"] for e in proposed], ["d1"])
        self.assertEqual(len(notes), 1)

    def test_the_base_revision_decides_and_a_branch_edit_only_proposes(self):
        repo = self.repo()
        commit_file(repo, ".clagentic/dispositions.json", json.dumps({"entries": [entry(id="d1")]}),
                    "add d1")
        base = head(repo)
        write(os.path.join(repo, ".clagentic", "dispositions.json"),
              {"entries": [entry(id="d1"), entry(id="d2", rationale="added on the branch")]})
        store, proposed, notes = M["policy"].load_policy(repo, base)
        self.assertEqual(([e["id"] for e in store["entries"]], [e["id"] for e in proposed], notes),
                         (["d1"], ["d2"], []))

    def test_a_policy_file_is_read_at_the_base_and_nothing_else_is_a_policy_file(self):
        p = M["policy"]
        repo = self.repo()
        commit_file(repo, ".clagentic/deferrals.json", "[]", "add")
        base = head(repo)
        write(os.path.join(repo, ".clagentic", "deferrals.json"), "[1]")
        self.assertEqual(p.read_policy_file_at_base(repo, base, ".clagentic/deferrals.json"), "[]")
        self.assertEqual(p.read_policy_file_at_base(repo, None, ".clagentic/deferrals.json"), "")
        with self.assertRaises(ValueError):
            p.read_policy_file_at_base(repo, base, "README.md")


class TestState(Tmp):
    def test_a_run_accumulates_and_a_rerun_only_adds(self):
        s = M["state"]
        state = s.fresh_state(HEAD_SHA)
        record = unified()
        self.assertEqual(s.accumulate(state, [record], "review", "standalone"), 1)
        self.assertEqual(s.accumulate(state, [unified()], "review", "gates"), 0)
        self.assertEqual((len(state["findings"]), len(state["runs"])), (1, 2))
        self.assertEqual(s.accumulate(state, [unified(file="other.py")], "review", "gates"), 1)

    def test_a_merged_finding_can_only_get_stronger(self):
        s = M["state"]
        state = s.fresh_state(HEAD_SHA)
        s.accumulate(state, [unified(attacker_precondition="maintainer_admin", impact="availability",
                                     reachable="no")], "review", "gates")
        s.accumulate(state, [unified(attacker_precondition="network", impact="code_exec",
                                     reachable="yes")], "review", "gates")
        stored = state["findings"][0]
        self.assertEqual((stored["attacker_precondition"], stored["impact"], stored["reachable"]),
                         ("network", "code_exec", "yes"))

    def test_the_state_is_per_head_and_a_corrupt_file_is_an_error_not_empty(self):
        s = M["state"]
        root = self.tmp
        state = s.fresh_state(HEAD_SHA)
        s.accumulate(state, [unified()], "review", "gates")
        s.save_state(root, state)
        self.assertEqual(len(s.load_state(root, HEAD_SHA)["findings"]), 1)
        self.assertEqual(s.load_state(root, "b" * 40)["findings"], [])
        write(s.state_file(root), "{garbage")
        with self.assertRaises(M["errors"].StateError):
            s.load_state(root, HEAD_SHA)

    def test_a_state_written_before_facts_existed_is_read_as_the_worst_case(self):
        s = M["state"]
        old = {"schema": 1, "head": HEAD_SHA, "runs": [],
               "findings": [{"source": "review", "fingerprint": "f", "severity": "low"}]}
        write(s.state_file(self.tmp), old)
        loaded = s.load_state(self.tmp, HEAD_SHA)["findings"][0]
        self.assertEqual((loaded["attacker_precondition"], loaded["impact"], loaded["rubric_applied"]),
                         ("unknown", "unknown", True))

    def test_the_lock_is_taken_and_released(self):
        with M["state"].StateLock(self.tmp) as lock:
            self.assertIsNotNone(lock.handle)
        self.assertTrue(lock.handle.closed)


class TestVerdict(unittest.TestCase):
    def state_with(self, *records):
        state = M["state"].fresh_state(HEAD_SHA)
        M["state"].accumulate(state, list(records), "review", "gates")
        return state

    def store(self, *raw):
        return {"entries": [M["dispositions"].validate_entry(r)[0] for r in raw], "invalid": [],
                "warnings": [], "legacy": []}

    def verdict(self, state, store, proposed=()):
        return M["verdict"].build_verdict(state, store, list(proposed), "high", TODAY, None,
                                          HEAD_SHA, None)

    def test_an_open_blocking_finding_blocks_and_prints_its_clearing_stanza(self):
        result = self.verdict(self.state_with(unified()), self.store())
        self.assertEqual((result["verdict"], len(result["open"])), ("BLOCKED", 1))
        stanza = result["open"][0]["stanza"]
        self.assertEqual((stanza["kind"], stanza["rationale"].startswith("<")), ("by_design", True))

    def test_a_base_entry_clears_it_and_is_always_listed(self):
        result = self.verdict(self.state_with(unified()), self.store(entry()))
        self.assertEqual((result["verdict"], result["cleared"][0]["entry"]["id"]), ("PASS", "d1"))

    def test_an_entry_added_in_the_change_clears_nothing_and_is_reported(self):
        proposed = self.store(entry())["entries"]
        result = self.verdict(self.state_with(unified()), self.store(), proposed)
        self.assertEqual((result["verdict"], len(result["pending_in_change"])), ("BLOCKED", 1))

    def test_a_floor_finding_refuses_an_entry_that_is_not_a_mitigation(self):
        floor = unified(attacker_precondition="none")
        result = self.verdict(self.state_with(floor), self.store(entry()))
        self.assertEqual((result["verdict"], result["refused"][0]["entry_id"], result["open"][0]["floor"]),
                         ("BLOCKED", "d1", True))
        stanza = result["open"][0]["stanza"]
        self.assertEqual((stanza["kind"], "control" in stanza), ("mitigated", True))

    def test_an_expired_entry_no_longer_clears_and_says_how_many_it_would_have(self):
        result = self.verdict(self.state_with(unified()), self.store(entry(expires="2026-01-01")))
        self.assertEqual((result["verdict"], result["expired"][0]["would_have_cleared"]), ("BLOCKED", 1))

    def test_blockers_count_and_fail_closed(self):
        v = M["verdict"]
        with tempfile.TemporaryDirectory() as tmp:
            review = write(os.path.join(tmp, "r.json"), {"findings": [{"severity": "high"},
                                                                       {"severity": "low"}]})
            self.assertEqual(v.count_blockers(review, "high"), 1)
            self.assertEqual(v.count_blockers(os.path.join(tmp, "absent.json"), "high"), 99)
            bad = write(os.path.join(tmp, "b.json"), {"findings": "x"})
            self.assertEqual(v.count_blockers(bad, "high"), 99)

    def test_the_blocking_listing_is_none_when_unreadable_and_skips_cleared(self):
        v = M["verdict"]
        self.assertIsNone(v.blocking_findings_listing("not json", "high"))
        text = json.dumps({"findings": [
            {"severity": "high", "file": "a", "line": 1, "message": "m"},
            {"severity": "high", "file": "b", "disposition": {"status": "cleared"}}]})
        self.assertEqual([i["file"] for i in v.blocking_findings_listing(text, "high")], ["a"])
        self.assertTrue(v.is_cleared({"disposition": {"status": "cleared"}}))
        self.assertFalse(v.is_cleared({"disposition": "cleared"}))


class TestRender(Tmp):
    def test_the_verdict_lines_say_none_only_for_a_list_that_was_read(self):
        r = M["render"]
        self.assertEqual(r.render_verdict_lines("abc", "[]"), (0, "head_sha: `abc`\n\nFindings: none\n"))
        self.assertEqual(r.render_verdict_lines("abc", "garbage"), (2, ""))
        self.assertEqual(r.render_verdict_lines("abc", "{}"), (2, ""))

    def test_the_verdict_text_names_the_head_threshold_and_standalone_status(self):
        verdict = M["verdict"].build_verdict(M["state"].fresh_state(HEAD_SHA),
                                             {"entries": [], "invalid": [], "warnings": []},
                                             [], "high", TODAY, None, HEAD_SHA, None)
        text = M["render"].render_verdict_text(verdict, "standalone")
        lines = text.splitlines()
        self.assertEqual(lines[0], "VERDICT: PASS (no open blocking findings at HEAD %s)" % ("a" * 12))
        self.assertIn("threshold: high", lines[1])
        self.assertIn("does not count toward 'gates ship'", lines[-1])

    def test_a_fence_block_is_a_json_string_literal(self):
        out = M["render"].fence_data_block("X", "text", "hi")
        self.assertEqual(json.loads(out), "===BEGIN X DATA===\nhi\n===END X DATA===\n")
        pretty = json.loads(M["render"].fence_data_block("X", "json", '{"b":1,"a":2}'))
        self.assertIn('"a": 2,\n  "b": 1', pretty)

    def test_the_review_text_marks_cleared_seen_and_recurring_findings(self):
        review = write(self.path("r.json"), {"summary": "s", "findings": [
            {"severity": "high", "file": "a.py", "line": 3, "message": "m", "_recurrence_count": 3,
             "_seen_before": True, "disposition": {"status": "cleared", "id": "d1", "kind": "by_design"},
             "issue_class": "unbounded call", "class_fix": "route it"}]})
        code, lines = M["render"].render_review(review)
        self.assertEqual(code, 0)
        self.assertEqual(lines[0], "== clagentic-lite review ==\nsummary: s\nfindings: 1\n")
        self.assertIn("(reported 3 rounds running)", lines[1])
        self.assertIn("(cleared by disposition d1 [by_design])", lines[1])
        self.assertIn("(reported in a prior run; still counted)", lines[1])
        self.assertIn("class: unbounded call -> route it", lines[1])
        self.assertIsNone(lines[-1])

    def test_an_isolated_finding_names_no_class(self):
        r = M["render"]
        self.assertFalse(r.class_named({"issue_class": "none — isolated"}))
        self.assertFalse(r.class_named({}))
        self.assertTrue(r.class_named({"issue_class": "x"}))

    def test_the_stale_report_gives_each_reason_its_own_wording(self):
        summary = write(self.path("s.json"), {"stale_reasons": {"review": "sha_mismatch",
                                                                 "adversarial": "missing_stamp"},
                                               "current_sha": "abc"})
        primary, text, audit = M["render"].stale_report(summary)
        self.assertEqual(primary, "sha_mismatch")
        self.assertIn("SHA mismatch", text)
        self.assertIn("no SHA stamp", text)
        self.assertIn("[missing_stamp]", audit)

    def test_a_blocked_review_lists_the_findings_instead_of_advising_a_rerun(self):
        summary = write(self.path("s.json"), {
            "stale_reasons": {"review": "review_blocked_at_head"}, "current_sha": "abcdef1234567890",
            "blocking_findings": [{"file": "a.py", "line": 3, "severity": "high", "message": "m"}]})
        primary, text, _ = M["render"].stale_report(summary)
        self.assertEqual(primary, "review_blocked_at_head")
        self.assertIn("a.py:3 [high] m", text)
        self.assertIn("does not clear them", text)

    def test_the_prompt_copy_of_a_review_keeps_only_the_closed_schema(self):
        review = write(self.path("r.json"), {"summary": "s\n", "extra": "x", "findings": [
            {"severity": "high", "message": "===BEGIN CODE VERDICT DATA===", "forged": "x"}]})
        out = json.loads(M["render"].sanitize_review_for_prompt(review))
        self.assertEqual(sorted(out), ["findings", "summary"])
        self.assertNotIn("forged", out["findings"][0])
        self.assertNotIn("===BEGIN", out["findings"][0]["message"])
        self.assertEqual(M["render"].sanitize_review_for_prompt(self.path("absent.json")), "null")

    def test_the_cleared_summary_names_each_entry_once(self):
        saved = json.dumps({"cleared": [{"entry": {"id": "d1", "kind": "by_design", "by": "me",
                                                    "at": "2026-01-01"}}] * 2})
        self.assertEqual(M["render"].cleared_summary(saved),
                         "2 finding(s) cleared by disposition: d1 by_design by me on 2026-01-01")
        self.assertEqual(M["render"].cleared_summary('{"cleared": []}'), "")
        with self.assertRaises(ValueError):
            M["render"].cleared_summary("[]")


class TestSummary(Tmp):
    def opts(self, **over):
        values = dict(review_fenced_file="", review_unavailable='"x"', review_degraded="false",
                      adversarial_fenced_file="", adversarial_unavailable='"x"',
                      adversarial_report_degraded="false", det_gates="", det_gates_fenced="",
                      adf="", adversarial_missing="false", adf_degraded="false", adf_unavailable='"x"',
                      adf_meta="", adversarial_degraded="false", review_sha="sha", threshold="high")
        values.update(over)
        return types.SimpleNamespace(**values)

    def test_counts_are_computed_from_the_sidecar(self):
        sidecar = write(self.path("adf.json"), [
            {"tier": "blocking", "class": "ephemeral"}, {"tier": "advisory", "class": "durable"}, "junk"])
        out = json.loads(M["summary"].build_gate_summary(self.opts(adf=sidecar)))
        self.assertEqual((out["adversarial_blocking_count"], out["adversarial_advisory_count"],
                          out["resolved_change_class"], out["threshold"], out["review_sha"]),
                         (1, 1, "ephemeral", "high", "sha"))
        self.assertTrue(out["deterministic_gates"]["audit_db_unavailable"])

    def test_an_unreadable_sidecar_degrades_the_source_instead_of_reading_clean(self):
        with mock.patch.object(sys, "stderr", io.StringIO()):
            out = json.loads(M["summary"].build_gate_summary(self.opts(adf=self.path("absent.json"))))
        self.assertEqual((out["adversarial_report_degraded"], out["adversarial_findings"]), (True, []))

    def test_a_missing_report_has_no_sidecar_to_distrust(self):
        with mock.patch.object(sys, "stderr", io.StringIO()):
            out = json.loads(M["summary"].build_gate_summary(
                self.opts(adf=self.path("absent.json"), adversarial_missing="true")))
        self.assertFalse(out["adversarial_report_degraded"])

    def test_a_source_marked_degraded_becomes_the_unavailable_marker(self):
        out = json.loads(M["summary"].build_gate_summary(self.opts(review_degraded="true")))
        self.assertEqual((out["review_fenced"], out["review_degraded"]), ("x", True))


class TestEvaluate(unittest.TestCase):
    def test_input_that_is_not_a_review_is_refused(self):
        e, refused = M["evaluate"], M["errors"].InputRefused
        for text, fmt in (("", "markdown"), ("not json", "json"), ('{"degraded": true, "findings": []}', "json"),
                          ('{"summary": "s"}', "json"), ('{"findings": "x"}', "json"), ("5", "json")):
            with self.subTest(text=text), self.assertRaises(refused):
                e.findings_from_text(text, fmt)

    def test_an_array_or_an_envelope_or_a_report_is_accepted(self):
        e = M["evaluate"]
        self.assertEqual(e.findings_from_text('[{"a": 1}]', "json"), [{"a": 1}])
        self.assertEqual(e.findings_from_text('{"findings": []}', "json"), [])
        self.assertEqual(len(e.findings_from_text("[FINDING] CWE-1 | a:1 | severity: low | title: t",
                                                  "markdown")), 1)

    def test_oversized_stdin_is_refused(self):
        e = M["evaluate"]
        fake = types.SimpleNamespace(buffer=io.BytesIO(b"x" * (e.MAX_INPUT_BYTES + 1)))
        with mock.patch.object(sys, "stdin", fake), self.assertRaises(M["errors"].InputRefused):
            e.read_stdin_bounded()

    def test_annotation_writes_the_rubric_reading_back_index_aligned(self):
        e = M["evaluate"]
        with tempfile.TemporaryDirectory() as tmp:
            path = write(os.path.join(tmp, "f.json"), {"findings": [{"severity": "low", "file": "app.py"}]})
            record = unified(severity="low")
            e.annotate_rubric_file(path, [record])
            with open(path) as handle:
                item = json.load(handle)["findings"][0]
            self.assertEqual((item["severity"], item["severity_claimed"]), (record["severity"], "low"))
            with self.assertRaises(ValueError):
                e.annotate_rubric_file(path, [record, record])


class TestSamples(Tmp):
    def envelope(self, name, *items, **extra):
        return write(self.path(name), dict({"summary": name, "checked": ["c"], "findings": list(items)},
                                           **extra))

    def test_the_union_keeps_the_highest_rubric_severity_of_a_linked_group(self):
        low = self.envelope("a.json", finding(severity="low"))
        high = self.envelope("b.json", finding(severity="high"))
        union, lines = M["samples"].union_review_samples([low, high], None)
        self.assertEqual([f["severity"] for f in union["findings"]], ["high"])
        self.assertEqual(union["samples"], 2)
        self.assertIn("union of 2 usable sample(s): 1 distinct finding(s)", lines)

    def test_an_unusable_sample_is_excluded_and_reported(self):
        good = self.envelope("a.json", finding())
        degraded = self.envelope("d.json", degraded=True)
        union, lines = M["samples"].union_review_samples(
            [good, degraded, self.path("absent.json"), write(self.path("arr.json"), [])], None)
        self.assertEqual(len(union["findings"]), 1)
        self.assertEqual(sum("excluded" in line for line in lines), 2)
        self.assertTrue(any("degraded" in line for line in lines))

    def test_with_no_usable_sample_the_union_fails_closed(self):
        union, _ = M["samples"].union_review_samples([self.path("absent.json")], None)
        self.assertIsNone(union)


class TestLedger(Tmp):
    def entry(self, **over):
        base = {"branch": "b", "gate": "review", "head_sha": "h1", "verdict": "pass"}
        base.update(over)
        return json.dumps(base)

    def test_a_pass_is_anchored_to_the_head_it_was_recorded_at(self):
        led, ledger = M["ledger"], self.path("sub", "ledger.jsonl")
        led.ledger_append(ledger, self.entry(), 0)
        self.assertTrue(led.anchored_pass(ledger, "b", "h1", "review"))
        self.assertFalse(led.anchored_pass(ledger, "b", "h2", "review"))
        self.assertFalse(led.anchored_pass(ledger, "b", "", "review"))
        self.assertFalse(led.anchored_pass(ledger, "b", "h1", "adversarial"))
        self.assertEqual(led.head_verdict_state(ledger, "b", "h2", "review"), "sha_mismatch")
        self.assertEqual(led.head_verdict_state(ledger, "other", "h1", "review"), "missing_stamp")
        self.assertEqual(led.latest_passing_head(ledger, "b", "review"), "h1")

    def test_a_block_at_the_head_says_a_rerun_cannot_help(self):
        led, ledger = M["ledger"], self.path("ledger.jsonl")
        led.ledger_append(ledger, self.entry(head_sha="h3", verdict="block"), 0)
        self.assertEqual(led.head_verdict_state(ledger, "b", "h3", "review"), "review_blocked_at_head")

    def test_the_trim_drops_the_oldest_entries_of_the_same_branch_only(self):
        led, ledger = M["ledger"], self.path("ledger.jsonl")
        for index in range(4):
            led.ledger_append(ledger, self.entry(head_sha="h%d" % index), 2)
        led.ledger_append(ledger, self.entry(branch="other"), 2)
        self.assertEqual([e["head_sha"] for e in led.ledger_entries(ledger, "b")], ["h2", "h3"])
        self.assertEqual(len(led.ledger_entries(ledger, "other")), 1)

    def test_a_line_that_is_not_an_object_is_skipped_and_branch_names_match_whole(self):
        led, ledger = M["ledger"], write(self.path("ledger.jsonl"), "garbage\n[1]\n" + self.entry() + "\n")
        self.assertEqual(len(led.ledger_entries(ledger, "b")), 1)
        self.assertEqual(led.ledger_entries(ledger, "bb"), [])
        self.assertEqual(led.ledger_entries(self.path("absent"), "b"), [])

    def test_field_text_and_the_entry_builder_tolerate_bad_inputs(self):
        led = M["ledger"]
        self.assertEqual((led.field_text({"a": None}, "a"), led.field_text({"a": {"x": 1}}, "a")),
                         ("", '{"x":1}'))
        built = json.loads(led.build_ledger_entry("t", "b", "review", "base", "head", "pass", "garbage", "{bad"))
        self.assertEqual((built["findings"], built["config"], built["head_sha"]), ([], {}, "head"))


class TestRounds(Tmp):
    def test_the_ledger_marks_a_finding_it_has_seen_on_the_branch(self):
        ledger = write(self.path("l.jsonl"), json.dumps(
            {"branch": "b", "findings": [{"file": "a", "category": "c", "message": "m"}]}) + "\n")
        marked = M["rounds"].mark_ledger_recurrence(
            [{"file": "a", "category": "c", "message": "m"}, {"file": "z", "category": "c", "message": "m"}],
            ledger, "b")
        self.assertEqual([f["_ledger_recurring"] for f in marked], [True, False])

    def test_cross_round_fails_with_its_own_status_when_the_envelope_is_unreadable(self):
        with self.assertRaises(M["errors"].StageFailure) as caught:
            M["rounds"].cross_round(self.path("absent.json"), "", self.path("seen"))
        self.assertEqual(caught.exception.code, M["errors"].KEYS_FAILED)

    def test_the_recurrence_count_is_information_and_grows_per_round(self):
        diff = write(self.path("d.diff"), TestFingerprint.DIFF)
        env, counts = self.path("env.json"), self.path("counts.json")
        for expected in (1, 2):
            write(env, {"findings": [finding(file="a.py", line=2)]})
            self.assertEqual(M["rounds"].recurrence_count(env, diff, counts), 1)
            with open(env) as handle:
                self.assertEqual(json.load(handle)["findings"][0]["_recurrence_count"], expected)

    def test_an_envelope_with_non_array_findings_is_never_touched(self):
        env = write(self.path("env.json"), {"findings": None})
        with open(env) as handle:
            before = handle.read()
        self.assertIsNone(M["rounds"].recurrence_count(env, "", self.path("counts.json")))
        with open(env) as handle:
            self.assertEqual(handle.read(), before)


class TestInfer(Tmp):
    def test_an_exposed_port_in_a_container_file_is_an_internet_marker(self):
        repo = self.repo()
        commit_file(repo, "svc/Dockerfile", "FROM x\nEXPOSE 8080\n")
        markers, notes = M["infer"].infer_markers(repo)
        self.assertEqual(notes, [])
        hits = [m for m in markers if m["dimension"] == "exposure"]
        self.assertEqual([(m["value"], m["glob"], m["file"]) for m in hits],
                         [("internet", "svc/**", "svc/Dockerfile")])

    def test_an_internal_ingress_is_not_read_as_public(self):
        repo = self.repo()
        commit_file(repo, "k/ing.yaml",
                    "kind: Ingress\nmetadata:\n  annotations:\n    nginx.ingress.kubernetes.io/auth-url: x\n")
        self.assertEqual([m for m in M["infer"].infer_markers(repo)[0] if m["dimension"] == "exposure"], [])

    def test_pii_shaped_fields_in_a_schema_raise_the_data_dimension(self):
        repo = self.repo()
        commit_file(repo, "db/schema.sql", "create table t (email text);\n")
        self.assertEqual([(m["dimension"], m["value"]) for m in M["infer"].infer_markers(repo)[0]],
                         [("data", "regulated_or_customer")])

    def test_a_tree_that_cannot_be_listed_infers_nothing_and_says_so(self):
        with mock.patch.object(M["infer"], "git_run", return_value=None):
            markers, notes = M["infer"].infer_markers(self.tmp)
        self.assertEqual((markers, len(notes)), ([], 1))

    def test_the_exposure_surface_is_recognized_by_name(self):
        t = M["infer"].touches_exposure_surface
        self.assertTrue(t("deploy/ingress.yaml", set()))
        self.assertTrue(t("auth/login.py", set()))
        self.assertTrue(t(".github/workflows/ci.yml", set()))
        self.assertTrue(t("anything.py", {"anything.py"}))
        self.assertFalse(t("lib/util.py", set()))

    def test_no_base_means_no_changed_paths(self):
        self.assertEqual(M["infer"].changed_paths(self.repo(), None), [])


class TestStakes(Tmp):
    def test_a_value_outside_its_vocabulary_is_the_worst_case_and_reported(self):
        profile, problems = M["stakes"].parse_profile(json.dumps({
            "default": {"exposure": "bogus"}, "paths": [{"glob": "a/**", "data": "internal"}, {"x": 1}]}))
        self.assertEqual(profile["default"], {"exposure": "internet"})
        self.assertEqual(profile["entries"], [("a/**", {"data": "internal"})])
        self.assertEqual(len(problems), 2, problems)

    def test_text_that_is_not_a_profile_is_unusable(self):
        s = M["stakes"]
        self.assertIsNone(s.parse_profile("not json")[0])
        self.assertIsNone(s.parse_profile("[]")[0])

    def test_an_inert_stakes_is_the_worst_case_everywhere(self):
        dims = M["stakes"].Stakes().dims_for("any/path.py")
        self.assertEqual({k: v[0] for k, v in dims.items()}, M["rubric"].WORST_DIMS)

    def test_a_test_path_is_not_served_unless_the_profile_says_otherwise(self):
        s = M["stakes"].Stakes()
        s.present = True
        s.default = {"data": "internal"}
        dims = s.dims_for("tests/test_a.py")
        self.assertEqual(dims["exposure"][0], "local_or_ci_only")
        self.assertEqual(dims["data"], ("internal", "the repo-wide default"))
        s.default = {"exposure": "internet"}
        self.assertEqual(s.dims_for("tests/test_a.py")["exposure"][0], "internet")

    def test_the_most_specific_worst_statement_wins_among_matching_globs(self):
        s = M["stakes"].Stakes()
        s.present = True
        s.entries = [("a/**", M["globs"].compile_glob("a/**"), {"exposure": "local_or_ci_only"}),
                     ("a/b/*", M["globs"].compile_glob("a/b/*"), {"exposure": "internet"})]
        self.assertEqual(s.dims_for("a/b/c")["exposure"], ("internet", "a/b/*"))

    def test_codeowners_last_matching_rule_decides_and_needs_an_owner(self):
        c = M["stakes"].Codeowners(["* @team\n/docs/\n"])
        self.assertTrue(c.covers("a.py"))
        self.assertFalse(c.covers("docs/x.md"))

    def test_a_claim_of_code_owner_review_without_codeowners_is_ignored_loudly(self):
        s = M["stakes"].Stakes()
        s.present = True
        s.default = {"merge_control": "code_owner_review_required"}
        self.assertEqual(s.dims_for("a.py")["merge_control"][0], "unrestricted")
        self.assertEqual(len(s.warnings), 1)

    def test_a_profile_in_the_working_tree_only_never_applies(self):
        repo = self.repo()
        write(os.path.join(repo, ".clagentic", "risk-profile.json"),
              {"version": 1, "confirmed_at": "2026-10-01", "default": {"exposure": "local_or_ci_only"}})
        stakes = M["stakes"].load_stakes(repo, head(repo), TODAY)
        self.assertFalse(stakes.present)
        self.assertTrue(any("not in the base commit" in n for n in stakes.notes), stakes.notes)
        no_base = M["stakes"].load_stakes(repo, None, TODAY)
        self.assertFalse(no_base.present)
        self.assertTrue(any("base commit could not be resolved" in w for w in no_base.warnings))

    def test_a_profile_at_the_base_applies(self):
        repo = self.repo()
        commit_file(repo, ".clagentic/risk-profile.json",
                    json.dumps({"version": 1, "confirmed_at": "2026-10-01",
                                "default": {"exposure": "local_or_ci_only"}}))
        stakes = M["stakes"].load_stakes(repo, head(repo), TODAY)
        self.assertTrue(stakes.present)
        self.assertEqual(stakes.dims_for("src/a.py")["exposure"][0], "local_or_ci_only")

    def test_is_test_path(self):
        t = M["stakes"].is_test_path
        self.assertTrue(all(t(p) for p in ("tests/a.py", "pkg/test_a.py", "a_test.go", "x/b.spec.ts")))
        self.assertFalse(any(t(p) for p in ("src/a.py", "contest/a.py")))


class TestProfile(Tmp):
    def test_an_answer_names_an_optional_glob_a_dimension_and_a_listed_value(self):
        p = M["profile"].parse_answer
        self.assertEqual(p("exposure=internet"), (None, "exposure", "internet"))
        self.assertEqual(p("deploy/**:exposure=internal_authenticated"),
                         ("deploy/**", "exposure", "internal_authenticated"))
        for bad in ("nonsense", "color=red", "exposure=nowhere", ":exposure=internet"):
            with self.assertRaises(ValueError, msg=bad):
                p(bad)

    def test_a_draft_carries_the_answers_and_confirmation_date(self):
        repo = self.repo()
        document, lines = M["profile"].build_profile(repo, ["exposure=internet"], False, TODAY)
        self.assertEqual((document["version"], document["default"], document["confirmed_at"]),
                         (1, {"exposure": "internet"}, "2026-10-10"))
        self.assertTrue(any(line.startswith("unstated") for line in lines))

    def test_a_draft_without_answers_or_confirmation_is_not_dated(self):
        document, _ = M["profile"].build_profile(self.repo(), [], False, TODAY)
        self.assertNotIn("confirmed_at", document)

    def test_inference_adds_marked_entries_and_flags_a_contradicted_claim(self):
        repo = self.repo()
        commit_file(repo, "svc/Dockerfile", "FROM x\nEXPOSE 8080\n")
        document, lines = M["profile"].build_profile(
            repo, ["**:exposure=local_or_ci_only"], False, TODAY)
        self.assertTrue(any(entry_.get("inferred") for entry_ in document["paths"]))
        self.assertTrue(any(line.startswith("WARN:") and "contradicted" in line for line in lines), lines)

    def test_a_profile_is_never_written_through_a_symlinked_directory(self):
        repo = self.repo()
        elsewhere = self.path("elsewhere")
        os.makedirs(elsewhere)
        os.symlink(elsewhere, os.path.join(repo, ".clagentic"))
        with self.assertRaises(ValueError):
            M["profile"].write_profile(repo, {"version": 1})
        self.assertEqual(os.listdir(elsewhere), [])

    def test_a_profile_is_written_atomically_inside_the_repository(self):
        repo = self.repo()
        target = M["profile"].write_profile(repo, {"version": 1, "paths": []})
        with open(target) as handle:
            self.assertEqual(json.load(handle), {"version": 1, "paths": []})


class TestCli(unittest.TestCase):
    def test_the_parser_routes_each_stage_to_its_command(self):
        cli = M["cli"]
        for argv, name in ((["verdict", "rank", "high"], "cmd_verdict_rank"),
                           (["evaluate"], "cmd_evaluate"), (["profile"], "cmd_profile"),
                           (["render", "gate-summary"], "cmd_render_gate_summary"),
                           (["ingest", "union-samples", "a", "b"], "cmd_ingest_union_samples")):
            self.assertIs(cli.build_parser().parse_args(argv).func, getattr(cli, name), argv)

    def test_a_command_writes_its_answer_to_stdout(self):
        with mock.patch.object(sys, "stdout", io.StringIO()) as out:
            self.assertEqual(M["cli"].cmd_verdict_rank(types.SimpleNamespace(name="high")), 0)
        self.assertEqual(out.getvalue(), "3\n")

    def test_a_crash_is_status_70_and_not_python_s_own_status_1(self):
        cli = M["cli"]
        with mock.patch.object(cli, "main", side_effect=RuntimeError("boom")), \
                mock.patch.object(sys, "stderr", io.StringIO()) as err:
            self.assertEqual(cli.run([]), cli.CRASH_STATUS)
        self.assertEqual(cli.CRASH_STATUS, 70)
        self.assertIn("RuntimeError: boom", err.getvalue())

    def test_a_refusal_of_the_arguments_keeps_argparse_status_2(self):
        with mock.patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit) as caught:
            M["cli"].build_parser().parse_args(["no-such-stage"])
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
