"""
Hardening of the finding pipeline (plugins/clagentic-lite/bin/findings.py)
found in review of the unified-dispositions change:

  - a non-array 'findings' is never counted, rewritten or silently read as empty
  - the legacy deferral hash covers the whole file, whatever its size
  - a path read from a legacy file cannot escape the repository or hang a read
  - a catch-all disposition is recognised by what it matches, not how it is spelled
  - an untakeable state lock refuses the run
  - migrate does not advise deleting a legacy file whose entries were not moved

Run with: python3 -m unittest scripts.test_findings_hardening -v
"""
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from scripts.findings_test_support import (
    entry, finding, load_module, make_repo, run_findings, write)

findings = load_module()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-hardening-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def put(self, name, content):
        return write(self.path(name), content)


class TestNonListFindingsAreNeverCounted(Tmp):
    VALUES = ({"severity": "critical"}, "text", 5, True, False, None, 1.5)

    def test_recurrence_returns_none_and_leaves_the_envelope_byte_identical(self):
        diff = self.put("d.diff", "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
                                  "@@ -0,0 +1,3 @@\n+a\n+b\n+c\n")
        for value in self.VALUES:
            with self.subTest(value=value):
                env = self.put("env.json", json.dumps({"findings": value}))
                with open(env, "rb") as handle:
                    before = handle.read()
                counts = self.path("counts.json")
                self.assertIsNone(findings.recurrence_count(env, diff, counts))
                with open(env, "rb") as handle:
                    self.assertEqual(handle.read(), before)
                self.assertFalse(os.path.exists(counts))

    def test_the_cli_path_does_not_crash_either(self):
        diff = self.put("d.diff", "")
        for value in self.VALUES:
            with self.subTest(value=value):
                env = self.put("env.json", json.dumps({"findings": value}))
                result = run_findings(["dispositions", "recurrence", env, "--diff", diff,
                                       "--counts", self.path("c.json")])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "none")

    def test_lenient_read_warns_instead_of_going_silent(self):
        for value in self.VALUES:
            with self.subTest(value=value):
                env = self.put("env.json", json.dumps({"findings": value}))
                result = run_findings(["ingest", "findings", env])
                self.assertEqual(result.stdout.strip(), "[]")
                self.assertIn("not an array", result.stderr)

    def test_an_absent_key_is_a_genuine_empty_list_without_a_warning(self):
        env = self.put("env.json", json.dumps({"summary": "s"}))
        result = run_findings(["ingest", "findings", env])
        self.assertEqual(result.stdout.strip(), "[]")
        self.assertEqual(result.stderr, "")


class TestEveryFindingsConsumerSurvivesANonList(Tmp):
    """Class sweep for B1: every reader of an envelope's findings, fed every
    non-list value, either refuses or reads it as empty; none raises."""

    def test_no_reader_crashes(self):
        diff = self.put("d.diff", "")
        for value in TestNonListFindingsAreNeverCounted.VALUES:
            env = self.put("env.json", json.dumps({"findings": value}))
            for label, args in (
                    ("render review", ["render", "review", env]),
                    ("class footer", ["render", "class-footer", env]),
                    ("sanitize review", ["render", "sanitize-review", env]),
                    ("blockers", ["verdict", "blockers", env, "high"]),
                    ("cross-round", ["dispositions", "cross-round", env, "--diff", diff,
                                     "--seen", self.path("seen")]),
                    ("recurrence", ["dispositions", "recurrence", env, "--diff", diff,
                                    "--counts", self.path("c.json")])):
                with self.subTest(value=value, reader=label):
                    result = run_findings(args)
                    self.assertNotEqual(result.returncode, findings.CRASH_STATUS, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)


class TestDeferralHashCoversTheWholeFile(Tmp):
    def _store_with_deferral(self, size):
        repo = make_repo(self.path("repo"))
        content = b"x" * size
        with open(os.path.join(repo, "big.bin"), "wb") as handle:
            handle.write(content)
        deferral = {"id": "big", "category": "security", "file": "big.bin", "message": "m",
                    "description": "d", "acknowledged_by": "me", "scope": "stable-contract",
                    "file_sha256": hashlib.sha256(content).hexdigest()}
        write(os.path.join(repo, ".clagentic", "deferrals.json"), json.dumps([deferral]))
        return repo

    def test_a_two_mebibyte_file_still_matches_its_recorded_sha256(self):
        repo = self._store_with_deferral(2 * 1024 * 1024)
        store = findings.load_store(repo, findings.worktree_reader(repo))
        self.assertEqual([e["id"] for e in store["entries"]], ["deferral-big"], store)

    def test_a_change_past_the_first_mebibyte_still_lapses_it(self):
        repo = self._store_with_deferral(2 * 1024 * 1024)
        with open(os.path.join(repo, "big.bin"), "ab") as handle:
            handle.write(b"tail")
        store = findings.load_store(repo, findings.worktree_reader(repo))
        self.assertEqual(store["entries"], [])
        self.assertTrue(any("lapsed" in w for w in store["warnings"]), store["warnings"])


class TestLegacyPathsStayInsideTheRepository(Tmp):
    def _deferral(self, file):
        return {"id": "p", "category": "security", "file": file, "message": "m",
                "description": "d", "acknowledged_by": "me", "scope": "stable-contract",
                "file_sha256": "0" * 64}

    def _load(self, repo, file):
        write(os.path.join(repo, ".clagentic", "deferrals.json"), json.dumps([self._deferral(file)]))
        return findings.load_store(repo, findings.worktree_reader(repo))

    def test_unsafe_names_are_ignored_with_a_note_and_never_opened(self):
        repo = make_repo(self.path("repo"))
        for name in ("../../etc/passwd", "/etc/passwd", "a/../../b", "/dev/stdin", "..",
                     "src/../../x", "a\x00b"):
            with self.subTest(name=name), mock.patch("builtins.open", wraps=open) as spy:
                store = self._load(repo, name)
                opened = [c.args[0] for c in spy.call_args_list if c.args]
                self.assertFalse([p for p in opened if "passwd" in str(p) or "stdin" in str(p)])
                self.assertEqual(store["entries"], [])
                self.assertTrue(any("not a plain relative path" in w for w in store["warnings"]),
                                store["warnings"])

    def test_a_symlink_out_of_the_repository_is_not_followed(self):
        repo = make_repo(self.path("repo"))
        outside = self.put("outside.txt", "secret")
        os.symlink(outside, os.path.join(repo, "link.txt"))
        store = self._load(repo, "link.txt")
        self.assertEqual(store["entries"], [])
        self.assertTrue(any("lapsed" in w or "not a plain" in w for w in store["warnings"]))

    def test_a_fifo_is_refused_rather_than_read(self):
        repo = make_repo(self.path("repo"))
        os.mkfifo(os.path.join(repo, "pipe"))
        store = self._load(repo, "pipe")
        self.assertEqual(store["entries"], [])

    def test_a_normal_nested_file_still_works(self):
        repo = make_repo(self.path("repo"))
        content = "print('x')\n"
        write(os.path.join(repo, "src", "mod.py"), content)
        raw = self._deferral("src/mod.py")
        raw["file_sha256"] = hashlib.sha256(content.encode()).hexdigest()
        write(os.path.join(repo, ".clagentic", "deferrals.json"), json.dumps([raw]))
        store = findings.load_store(repo, findings.worktree_reader(repo))
        self.assertEqual([e["id"] for e in store["entries"]], ["deferral-p"])


class TestCatchAllGuardUsesTheMatcher(Tmp):
    def _verdict(self, glob, **match):
        raw = entry(match=dict({"path_glob": glob, "category": "*"}, **match))
        return findings.validate_entry(raw)

    def test_every_spelling_of_match_everything_is_rejected(self):
        for glob in ("*", "**", "**/*", "***", "**/**", "*/**", "**/**/*", "**/*/**", "?*",
                     "**/?*", "*/*/**", "**/***"):
            with self.subTest(glob=glob):
                parsed, errors = self._verdict(glob)
                self.assertIsNone(parsed)
                self.assertTrue(any("catch-all" in e for e in errors), errors)

    def test_narrow_globs_and_narrowing_fields_are_accepted(self):
        for glob in ("src/**", "**/*.py", "app.py", "**/gen/*", "*.py"):
            with self.subTest(glob=glob):
                self.assertIsNotNone(self._verdict(glob)[0])
        self.assertIsNotNone(self._verdict("**", message="a specific message")[0])
        self.assertIsNotNone(self._verdict("**", fingerprint_hint="deadbeef")[0])

    def test_a_specific_category_makes_a_wide_glob_acceptable(self):
        raw = entry(match={"path_glob": "**", "category": "CWE-79"})
        self.assertIsNotNone(findings.validate_entry(raw)[0])


class TestStateLockRefuses(Tmp):
    def test_an_untakeable_lock_refuses_the_run_and_writes_nothing(self):
        repo = make_repo(self.path("repo"))
        with mock.patch("fcntl.flock", side_effect=OSError("no locks here")):
            with self.assertRaises(findings.StateError):
                with findings.StateLock(repo):
                    self.fail("the body ran without the lock")

    def test_evaluate_exits_2_and_does_not_accumulate(self):
        repo = make_repo(self.path("repo"))
        args = mock.Mock(root=repo, gate="review", no_input=False, head="", base="", threshold="",
                         today="2026-10-09", default_branch="", scope="head", caller="standalone",
                         annotate="", attach_to="", json_out="", json=False, format="json")
        with mock.patch("fcntl.flock", side_effect=OSError("no locks here")), \
                mock.patch.object(findings.modules["evaluate"], "read_stdin_bounded",
                                  return_value=json.dumps([finding()])):
            code, text = findings.run_evaluate(args)
        self.assertEqual(code, 2, text)
        self.assertIn("lock", text)
        self.assertFalse(os.path.exists(os.path.join(repo, findings.STATE_REL)))


class TestMigrateNeverAdvisesLosingEntries(Tmp):
    def _repo_with_a_bad_ack(self):
        repo = make_repo(self.path("repo"))
        write(os.path.join(repo, ".clagentic", "adversarial-acks.json"), json.dumps([
            {"cwe": "CWE-1", "rationale": "ok", "acknowledged_by": "me", "acknowledged_at": "2026-01-01"},
            {"cwe": "CWE-2", "acknowledged_by": "me", "acknowledged_at": "2026-01-01"}]))
        return repo

    def test_write_exits_nonzero_writes_nothing_and_does_not_say_delete(self):
        repo = self._repo_with_a_bad_ack()
        result = run_findings(["dispositions", "migrate", "--root", repo, "--write"], cwd=repo)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(os.path.exists(os.path.join(repo, findings.DISPOSITIONS_REL)))
        self.assertNotIn("then delete the legacy files", result.stderr)
        self.assertIn("not migrated", result.stderr)

    def test_a_clean_migration_still_advises_and_exits_zero(self):
        repo = make_repo(self.path("repo"))
        write(os.path.join(repo, ".clagentic", "adversarial-acks.json"), json.dumps([
            {"cwe": "CWE-1", "rationale": "ok", "acknowledged_by": "me", "acknowledged_at": "2026-01-01"}]))
        result = run_findings(["dispositions", "migrate", "--root", repo, "--write"], cwd=repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("then delete the legacy files", result.stderr)


class TestUnreadableRisksFile(Tmp):
    def test_a_risks_file_that_resolves_outside_the_repo_is_reported(self):
        repo = make_repo(self.path("repo"))
        outside = self.put("outside.md", "# risks\n")
        os.makedirs(os.path.join(repo, ".clagentic"), exist_ok=True)
        os.symlink(outside, os.path.join(repo, findings.LEGACY_RISKS_REL))
        store = findings.load_store(repo, findings.worktree_reader(repo))
        self.assertTrue([r for r in store["invalid"] if r["source"] == findings.LEGACY_RISKS_REL],
                        store["invalid"])


class TestLintRejectsExactlyWhatTheVerdictIgnores(Tmp):
    """Parity for the dispositions format: an entry the lint calls invalid is
    one the verdict ignores, and a clean entry passes the lint and clears. Both
    read the file through load_store, and this keeps it so."""

    FIELDS = ("id", "rationale", "by", "match.category", "match.message")
    HOSTILE = ("\x01", "\r", "\x1b", "\x85", chr(0x202E))

    def _entry_with(self, field, char):
        item = entry(match={"path_glob": "app.py", "category": "security",
                            "message": "unsanitized input reaches a sink"})
        if field.startswith("match."):
            item["match"][field.split(".", 1)[1]] += char
        else:
            item[field] += char
        return item

    def _both(self, item):
        document = json.dumps({"entries": [item]})
        path = self.put("dispositions.json", document)
        code, lines = findings.lint_dispositions(self.tmp, path)
        store = findings.load_store(
            self.tmp, lambda rel: document if rel == findings.DISPOSITIONS_REL else None)
        unified = findings.unify_finding(finding(), "review")
        clears = any(findings.entry_matches(e, unified) for e in store["entries"])
        return code, "\n".join(lines), store, clears

    def test_each_hostile_character_in_each_field(self):
        for field in self.FIELDS:
            for char in self.HOSTILE:
                with self.subTest(field=field, char=repr(char)):
                    code, text, store, clears = self._both(self._entry_with(field, char))
                    self.assertEqual(code, 1, text)
                    self.assertIn("control characters", text)
                    self.assertEqual(store["entries"], [])
                    self.assertFalse(clears)

    def test_the_clean_entry_passes_the_lint_and_clears(self):
        # Positive control: without it "does not clear" could come from any
        # cause, including a matcher that never matches.
        code, text, store, clears = self._both(self._entry_with("id", ""))
        self.assertEqual(code, 0, text)
        self.assertEqual(len(store["entries"]), 1)
        self.assertTrue(clears)

    def test_the_cli_agrees_with_the_library(self):
        path = self.put("dispositions.json", json.dumps({"entries": [self._entry_with("by", "\x01")]}))
        result = run_findings(["dispositions", "lint", path, "--root", self.tmp])
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("control characters", result.stdout)


class TestSharedClearedHelper(unittest.TestCase):
    def test_the_two_renderers_agree_on_what_cleared_means(self):
        for disposition, expected in (({"status": "cleared"}, True), ({"status": "open"}, False),
                                      ("cleared", False), (None, False), ({}, False)):
            with self.subTest(disposition=disposition):
                self.assertEqual(findings.is_cleared({"disposition": disposition}), expected)


if __name__ == "__main__":
    unittest.main()
