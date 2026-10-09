"""
Regression tests for the verdict defects the extraction of the finding pipeline
ported faithfully (plugins/clagentic-lite/bin/findings.py): each of them lets a
finding that should block, or an unsanitized byte, through.

  (a) a failed degraded-stub rewrite must not leave raw findings as the answer
  (b) a severity that is not a known rank name blocks (it is never ranked low)
  (c) recurrence counts belong to one finding each, not to a shared triple
  (d) the shared control-byte helper strips C1 controls and bidi overrides
  (e) a non-list findings value is [], stale annotations are cleared, and a
      failed splice persists nothing

Run with: python3 -m unittest scripts.test_findings_verdict_defects -v
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from scripts.findings_test_support import finding, load_module, run_findings

findings = load_module()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-defects-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def write(self, name, content):
        with open(self.path(name), "w") as handle:
            handle.write(content if isinstance(content, str) else json.dumps(content))
        return self.path(name)

    def read_json(self, name):
        with open(self.path(name)) as handle:
            return json.load(handle)


class TestIngestNeverEmitsRawFindings(Tmp):
    """(a) The envelope is rewritten in place; when the stub cannot be written
    the raw findings must not be what a later reader sees as a review."""

    def _unusable_envelope(self):
        # findings is present but not an array, so ingest takes the stub path.
        return self.write("env.json", {"summary": "s", "findings": {"severity": "critical"}})

    def test_stub_write_failure_exits_nonzero(self):
        target = self._unusable_envelope()
        real_open = open

        def failing_open(path, mode="r", *args, **kwargs):
            if os.fspath(path) == target and "w" in mode:
                raise OSError("disk full")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", failing_open):
            status = findings.ingest_review_envelope(target)
        self.assertEqual(status, 1)

    def test_unremovable_raw_file_is_reported_not_hidden(self):
        target = self._unusable_envelope()
        real_open = open

        def failing_open(path, mode="r", *args, **kwargs):
            if os.fspath(path) == target and "w" in mode:
                raise OSError("read-only")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", failing_open), \
                mock.patch("os.unlink", side_effect=OSError("busy")):
            self.assertFalse(findings.mark_review_sanitize_failed(target))
            self.assertEqual(findings.ingest_review_envelope(target), 1)

    def test_a_removed_raw_file_does_not_survive_as_a_review(self):
        target = self._unusable_envelope()
        real_open = open

        def failing_open(path, mode="r", *args, **kwargs):
            if os.fspath(path) == target and "w" in mode:
                raise OSError("read-only")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", failing_open):
            status = findings.ingest_review_envelope(target)
        self.assertEqual(status, 1)
        self.assertFalse(os.path.exists(target), "the raw envelope was left in place")

    def test_successful_stub_still_exits_zero(self):
        target = self._unusable_envelope()
        result = run_findings(["ingest", "review-envelope", target])
        self.assertEqual(result.returncode, 0, result.stderr)
        stub = self.read_json("env.json")
        self.assertTrue(stub["degraded"] and stub["sanitize_failed"])


class TestSeverityRanking(Tmp):
    """(b) Anything that is not a known rank name once stripped and lowercased
    ranks as unrankable, which blocks."""

    def test_unknown_strings_are_unrankable(self):
        for value in ("blocker", "crit", "severe", "", "highest", "hi gh", "high;"):
            with self.subTest(value=value):
                self.assertEqual(findings.severity_rank(value), findings.UNRANKABLE_RANK)

    def test_known_names_are_stripped_and_case_folded(self):
        for value, rank in (("high ", 3), ("HIGH", 3), ("\tCritical\n", 4), (" low", 1),
                            ("Medium", 2)):
            with self.subTest(value=value):
                self.assertEqual(findings.severity_rank(value), rank)

    def test_absent_is_rank_zero_and_non_strings_are_unrankable(self):
        self.assertEqual(findings.severity_rank(None), 0)
        for value in (3, True, 1.5, ["high"], {"a": 1}):
            with self.subTest(value=value):
                self.assertEqual(findings.severity_rank(value), findings.UNRANKABLE_RANK)

    def test_blockers_counts_them_at_every_threshold(self):
        review = self.write("review.json", {"findings": [
            finding(severity="blocker"), finding(severity="crit"), finding(severity="high "),
            finding(severity="HIGH"), finding(severity="low")]})
        for threshold, expected in (("low", 5), ("high", 4), ("critical", 2)):
            with self.subTest(threshold=threshold):
                result = run_findings(["verdict", "blockers", review, threshold])
                self.assertEqual(result.stdout.strip(), str(expected), result.stderr)


class TestRecurrenceCountsPerFinding(Tmp):
    """(c) Two findings can share a (file, category, message) triple; each
    keeps its own count."""

    def _diff(self):
        lines = ["+x%d" % i for i in range(1, 21)]
        return self.write("d.diff", "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
                          "@@ -0,0 +1,20 @@\n" + "\n".join(lines) + "\n")

    def _envelope(self, lines_reported):
        return self.write("env.json", {"findings": [
            finding(line=n, category="c", message="same message") for n in lines_reported]})

    def test_each_finding_gets_its_own_count(self):
        diff, counts = self._diff(), self.path("counts.json")
        env = self._envelope([3])
        self.assertEqual(run_findings(["dispositions", "recurrence", env, "--diff", diff,
                                       "--counts", counts]).stdout.strip(), "counted=1")
        env = self._envelope([3, 15])
        result = run_findings(["dispositions", "recurrence", env, "--diff", diff, "--counts", counts])
        self.assertEqual(result.stdout.strip(), "counted=2", result.stderr)
        got = [f["_recurrence_count"] for f in self.read_json("env.json")["findings"]]
        self.assertEqual(got, [2, 1], "the new finding must not inherit the old one's count "
                                      "(or the reverse) through a shared triple")

    def test_count_never_changes_a_verdict(self):
        diff, counts = self._diff(), self.path("counts.json")
        env = self._envelope([3])
        for _ in range(5):
            run_findings(["dispositions", "recurrence", env, "--diff", diff, "--counts", counts])
        result = run_findings(["verdict", "blockers", env, "high"])
        self.assertEqual(result.stdout.strip(), "1")
        self.assertNotIn("_recurrence_demoted", json.dumps(self.read_json("env.json")))


class TestControlBytes(Tmp):
    """(d) The shared helper strips C0, DEL, C1 and bidi overrides/isolates."""

    HOSTILE = {
        "C0 escape": "\x1b",
        "DEL": "\x7f",
        "C1 CSI": "\u009b",
        "C1 NEL": "\u0085",
        "bidi override": chr(0x202E),
        "bidi embedding": chr(0x202A),
        "bidi isolate": chr(0x2066),
        "bidi pop isolate": chr(0x2069),
    }

    def test_terminal_text_replaces_every_one(self):
        for label, char in self.HOSTILE.items():
            with self.subTest(label=label):
                shown = findings.terminal_text("a%sb" % char)
                self.assertEqual(shown, "a b")

    def test_sanitize_text_removes_every_one_but_keeps_tab_and_newline(self):
        # A bare ESC is consumed together with the byte after it (a two-byte
        # escape), so it is covered by the terminal-escape tests, not here.
        for label, char in self.HOSTILE.items():
            if label == "C0 escape":
                continue
            with self.subTest(label=label):
                self.assertEqual(findings.sanitize_text("a%sb" % char, 100), "ab")
        self.assertNotIn("\x1b", findings.sanitize_text("a\x1bb", 100))
        self.assertEqual(findings.sanitize_text("a\tb\nc", 100), "a\tb\nc")

    def test_a_rendered_listing_carries_none_of_them(self):
        text = "".join(self.HOSTILE.values())
        document = json.dumps({"findings": [finding(message="m" + text, file="f" + text)]})
        listing = findings.blocking_findings_listing(document, "high")
        self.assertEqual(len(listing), 1)
        for char in self.HOSTILE.values():
            self.assertNotIn(char, json.dumps(listing, ensure_ascii=False))


class TestEnvelopeAccess(Tmp):
    """(e) extract_findings is [] for any non-list; stale annotations are
    cleared on an early return; a failed splice persists nothing."""

    def test_non_list_findings_are_an_empty_list(self):
        for value in ({"a": 1}, "text", 5, True, False, None, 1.5):
            with self.subTest(value=value):
                path = self.write("env.json", {"findings": value})
                self.assertEqual(findings.extract_findings(path), [])
                result = run_findings(["ingest", "findings", path])
                self.assertEqual(result.stdout.strip(), "[]")

    def test_a_list_is_returned_as_is(self):
        path = self.write("env.json", {"findings": [finding()]})
        self.assertEqual(findings.extract_findings(path), [finding()])

    def test_stale_count_is_cleared_when_nothing_can_be_counted(self):
        env = self.write("env.json", {"findings": [finding(_recurrence_count=7)]})
        result = run_findings(["dispositions", "recurrence", env, "--diff",
                               self.path("absent.diff"), "--counts", self.path("c.json")])
        self.assertEqual(result.stdout.strip(), "none", result.stderr)
        self.assertNotIn("_recurrence_count", self.read_json("env.json")["findings"][0])
        self.assertFalse(os.path.exists(self.path("c.json")))

    def test_failed_splice_persists_neither_counts_nor_seen_keys(self):
        diff = self.write("d.diff", "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
                                    "@@ -0,0 +1,3 @@\n+a\n+b\n+c\n")
        env = self.write("env.json", {"findings": [finding(line=2)]})
        counts, seen = self.path("counts.json"), self.path("seen")
        with mock.patch.object(findings, "splice_findings", side_effect=OSError("full")):
            self.assertIsNone(findings.recurrence_count(env, diff, counts))
            with self.assertRaises(findings.StageFailure):
                findings.cross_round(env, diff, seen)
        self.assertFalse(os.path.exists(counts), "counts persisted although the envelope was not rewritten")
        self.assertFalse(os.path.exists(seen), "seen keys persisted although the envelope was not rewritten")

    def test_a_good_splice_does_persist_them(self):
        diff = self.write("d.diff", "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
                                    "@@ -0,0 +1,3 @@\n+a\n+b\n+c\n")
        env = self.write("env.json", {"findings": [finding(line=2)]})
        counts, seen = self.path("counts.json"), self.path("seen")
        self.assertEqual(findings.recurrence_count(env, diff, counts), 1)
        findings.cross_round(env, diff, seen)
        self.assertEqual(len(self.read_json("counts.json")), 1)
        with open(seen) as handle:
            self.assertEqual(len(handle.read().split()), 1)


if __name__ == "__main__":
    unittest.main()
