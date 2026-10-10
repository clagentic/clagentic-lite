"""
Python-level tests for the dedup and key logic behind review-merge.sh.

These used to exercise verbatim copies of the python heredocs embedded in
review-merge.sh. That logic now lives once, in the finding pipeline
(plugins/clagentic-lite/bin/findings.py), so the tests load the real module and
call it directly: what they prove is the shipped behaviour, not a copy of it.

Run with: python3 -m unittest scripts/test_review_merge_py.py -v
"""
import os
import tempfile
import unittest

from scripts.findings_test_support import load_module

pipeline = load_module()


def compute_key(f, strategy, diff_file=""):
    return pipeline.finding_key(f, strategy, diff_file)


def dedup_findings_py(findings, strategy="location", seen=None, diff_file=""):
    """The pipeline's drop-mode dedup, in the (result, seen) shape these
    tests have always asserted against."""
    seen = dict(seen or {})
    kept, new_keys = pipeline.dedup_findings(findings, strategy, set(seen), diff_file, False)
    seen.update({key: True for key in new_keys})
    return kept, seen


# ── Tests ──────────────────────────────────────────────────────────────────

class TestDedupFindingsPy(unittest.TestCase):

    def test_location_severity_wins_high_over_medium(self):
        """BLOCKER 1 proof: dedup returns findings (not []), high wins."""
        findings = [
            {"severity": "medium", "file": "a.py", "line": 5, "category": "sec", "message": "sql injection"},
            {"severity": "high",   "file": "a.py", "line": 5, "category": "sec", "message": "sql injection"},
        ]
        result, _ = dedup_findings_py(findings, strategy="location")
        self.assertEqual(len(result), 1, "Two same-location findings must dedup to 1 (not [])")
        self.assertEqual(result[0]["severity"], "high", "Higher severity must win")

    def test_location_distinct_findings_retained(self):
        """Two distinct (file, line, category, message) findings are both kept."""
        findings = [
            {"severity": "high", "file": "a.py", "line": 1, "category": "sec", "message": "xss"},
            {"severity": "low",  "file": "b.py", "line": 2, "category": "style", "message": "long line"},
        ]
        result, _ = dedup_findings_py(findings, strategy="location")
        self.assertEqual(len(result), 2)

    def test_issue_class_and_class_fix_survive_dedup_untouched(self):
        """dedup is pure object pass-through keyed on file/line/category/
        message -- it must never inspect, require, or drop issue_class/
        class_fix. Two distinct findings, each carrying the fields, must both
        survive dedup with those fields byte-identical -- proving the per-chunk
        merge path carries the mandatory field through without any code of its
        own (the fields flow because dedup never allowlists, unlike the review
        ingest step upstream of it)."""
        findings = [
            {"severity": "high", "file": "a.py", "line": 1, "category": "sec",
             "message": "xss", "issue_class": "unbounded external call",
             "class_fix": "route through run_bounded"},
            {"severity": "low", "file": "b.py", "line": 2, "category": "style",
             "message": "long line", "issue_class": "none — isolated",
             "class_fix": "n/a — isolated"},
        ]
        result, _ = dedup_findings_py(findings, strategy="location")
        self.assertEqual(len(result), 2)
        by_file = {f["file"]: f for f in result}
        self.assertEqual(by_file["a.py"]["issue_class"], "unbounded external call")
        self.assertEqual(by_file["a.py"]["class_fix"], "route through run_bounded")
        self.assertEqual(by_file["b.py"]["issue_class"], "none — isolated")
        self.assertEqual(by_file["b.py"]["class_fix"], "n/a — isolated")

    def test_conservative_retain_on_none_key(self):
        """A finding whose key cannot be computed is retained, never dropped."""
        findings = [
            {"severity": "high", "file": "x.py", "line": 1, "category": "c", "message": "m"},
            "not a finding object",
            {"severity": "high", "file": "x.py", "line": "not-a-number", "category": "c", "message": "m"},
        ]
        self.assertIsNone(compute_key(findings[1], "location"))
        result, _ = dedup_findings_py(findings, strategy="content-hash",
                                      diff_file=__file__)
        self.assertEqual(len(result), 3, "findings with an uncomputable key must be conservatively retained")

    def test_cross_run_dedup_via_seen(self):
        """Finding already in seen dict is excluded on second pass."""
        finding = {"severity": "high", "file": "d.py", "line": 7, "category": "correctness", "message": "null deref"}
        # First pass: populates seen.
        r1, seen_after = dedup_findings_py([finding], strategy="location")
        self.assertEqual(len(r1), 1)
        # Second pass with same seen: finding excluded.
        r2, _ = dedup_findings_py([finding], strategy="location", seen=dict(seen_after))
        self.assertEqual(len(r2), 0, "Second pass with same seen must produce 0 findings")

    def test_content_hash_with_diff_file(self):
        """content-hash strategy deduplicates findings with identical context windows."""
        diff_text = (
            "diff --git a/e.py b/e.py\n"
            "--- a/e.py\n"
            "+++ b/e.py\n"
            "@@ -1,5 +1,6 @@\n"
            " def bar():\n"
            '+    eval("x")   # suspicious\n'
            "     x = 1\n"
            "     y = 2\n"
            "     z = 3\n"
            "     return x + y + z\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as tf:
            tf.write(diff_text)
            diff_path = tf.name
        try:
            findings = [
                {"severity": "medium", "file": "e.py", "line": 2, "category": "sec", "message": "eval usage"},
                {"severity": "high",   "file": "e.py", "line": 2, "category": "sec", "message": "eval usage"},
            ]
            result, _ = dedup_findings_py(findings, strategy="content-hash", diff_file=diff_path)
            self.assertEqual(len(result), 1, "content-hash dedup with real diff must yield 1 finding")
            self.assertEqual(result[0]["severity"], "high", "high must win over medium")
        finally:
            os.unlink(diff_path)

    def test_content_hash_no_diff_falls_back_to_location(self):
        """content-hash without diff file falls back to location key; still deduplicates."""
        findings = [
            {"severity": "high", "file": "c.py", "line": 3, "category": "sec", "message": "eval"},
            {"severity": "high", "file": "c.py", "line": 3, "category": "sec", "message": "eval"},
        ]
        result, _ = dedup_findings_py(findings, strategy="content-hash", diff_file="")
        self.assertEqual(len(result), 1)

    def test_invalid_json_passthrough(self):
        """The key handles missing fields gracefully (no exception propagation)."""
        # Empty-dict findings: no file/line/category/message -> location key is still computed.
        findings = [{}]
        result, _ = dedup_findings_py(findings, strategy="location")
        self.assertEqual(len(result), 1)  # retained (key computed from empty strings)

    def test_null_line_matches_absent_line_key(self):
        """Regression: null line and absent line must produce the same key.

        The location key collapses both null and absent to the integer 0 and
        stringifies it to "0". A prior bug used `f.get("line", "")`, which
        yielded "" instead and broke cross-round dedup.
        """
        key_null   = compute_key({"file": "f.py", "line": None,   "category": "c", "message": "m"}, "location")
        key_absent = compute_key({"file": "f.py",                  "category": "c", "message": "m"}, "location")
        key_zero   = compute_key({"file": "f.py", "line": 0,      "category": "c", "message": "m"}, "location")
        self.assertEqual(key_null, key_absent, "null line and absent line must hash identically")
        self.assertEqual(key_null, key_zero,   "null line and 0 line must hash identically")


class TestSplitDiffLogic(unittest.TestCase):
    """Test the awk parsing logic by verifying buf/idx initialization assumptions
    hold — specifically that empty-string comparison works without initialization
    in the awk that is now fixed with BEGIN { buf = ""; idx = 0 }."""

    def test_begin_block_initialization_correctness(self):
        """Verify awk BEGIN { buf = ""; idx = 0 } produces correct chunk count.

        We verify this indirectly: if the BEGIN block was missing, GNU/mawk
        would still work (implicit init), but we confirm the fix is present
        by reading the file and asserting the BEGIN line is there.
        """
        rm_path = os.path.join(
            os.path.dirname(__file__), "review-merge.sh"
        )
        with open(rm_path) as f:
            content = f.read()

        # BLOCKER 2 fix: both awk blocks must have BEGIN { buf = ""; idx = 0 }
        # (or BEGIN { buf = ""; idx = 0 } — spacing may vary).
        # Check for the split-on-diff-git awk.
        self.assertIn(
            'BEGIN { buf = ""; idx = 0 }',
            content,
            "split_diff file-splitting awk must initialize buf and idx in BEGIN block"
        )
        # Check for the hunk-splitting awk.
        self.assertIn(
            'BEGIN { hbuf = ""; hidx = 0 }',
            content,
            "split_diff hunk-splitting awk must initialize hbuf and hidx in BEGIN block"
        )

    def test_placeholder_block_removed(self):
        """BLOCKER 1 fix: dead placeholder awk block must be absent."""
        rm_path = os.path.join(
            os.path.dirname(__file__), "review-merge.sh"
        )
        with open(rm_path) as f:
            content = f.read()

        self.assertNotIn(
            "above awk skeleton is a placeholder",
            content,
            "Dead placeholder awk block must be removed (BLOCKER 1)"
        )
        self.assertNotIn(
            "' /dev/null)\n  # The above",
            content,
            "Placeholder awk reading /dev/null must be removed (BLOCKER 1)"
        )

    def test_dfj_select_variable_not_used_in_dead_block(self):
        """_dfj_select (empty dead variable) must not appear in the sh code."""
        rm_path = os.path.join(
            os.path.dirname(__file__), "review-merge.sh"
        )
        with open(rm_path) as f:
            content = f.read()

        self.assertNotIn(
            "_dfj_select",
            content,
            "_dfj_select (dead placeholder variable) must be removed"
        )


class TestReviewMergeHoldsNoFindingLogic(unittest.TestCase):
    """review-merge.sh is wrappers only: merge, dedup, key derivation and the
    ledger all delegate to the finding pipeline."""

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "review-merge.sh")) as f:
            self.content = f.read()

    def test_merge_and_dedup_delegate_to_the_pipeline(self):
        for call in ("ingest merge", "fingerprint dedup", "fingerprint keys", "fingerprint bump",
                     "verdict ledger-append", "verdict ledger-entries"):
            self.assertRegex(self.content, r"ds_findings_call [^\n]*" + call)

    def test_no_inline_severity_table_or_json_tooling(self):
        self.assertNotIn('"low": 1, "medium": 2, "high": 3, "critical": 4', self.content)
        self.assertNotIn("srank[", self.content)
        for tool in ("jq ", "json.load", "hashlib"):
            self.assertNotIn(tool, self.content)


if __name__ == "__main__":
    unittest.main()
