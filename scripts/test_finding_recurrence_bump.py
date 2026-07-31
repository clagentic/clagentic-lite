"""
Unit tests for finding_recurrence_bump (scripts/review-merge.sh), lr-66e598.

finding_recurrence_bump is the pure counting primitive the recurrence-
demotion feature is built on: given a TSV of finding_content_keys-shaped
rows (key<TAB>file<TAB>category<TAB>message) and a persisted JSON counts
file, it increments each row's count and appends it as a 5th TSV column,
persisting the updated count back to the counts file.

These tests source the ACTUAL sh function (not a Python reimplementation),
matching the convention test_review_merge_sh.py already uses for
dedup_findings/split_diff in the same file.

Run with: python3 -m unittest scripts.test_finding_recurrence_bump -v
"""
import json
import os
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.join(os.path.dirname(__file__), "..")
RM_SH = os.path.join(TOOL_HOME, "scripts", "review-merge.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def sh(script, stdin=None):
    r = subprocess.run(
        ["sh", "-c", script],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=TOOL_HOME,
    )
    return r.stdout, r.stderr, r.returncode


def source_and_run(fn_call, stdin=None):
    script = textwrap.dedent(f"""\
        . '{PLATFORM_SH}'
        ds_load_env 2>/dev/null || true
        . '{RM_SH}'
        {fn_call}
    """)
    return sh(script, stdin=stdin)


def _tsv_row(key, fname="a.py", category="security", message="sql injection"):
    return "\t".join([key, fname, category, message])


class TestFindingRecurrenceBump(unittest.TestCase):
    def setUp(self):
        fd, self.counts_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.counts_path)  # start absent — bump must create it fresh

    def tearDown(self):
        if os.path.exists(self.counts_path):
            os.unlink(self.counts_path)

    def _bump(self, tsv_input):
        fn_call = f"finding_recurrence_bump '{self.counts_path}'"
        out, err, rc = source_and_run(fn_call, stdin=tsv_input)
        return out, err, rc

    def test_first_occurrence_gets_count_1(self):
        """A key never seen before starts at count 1, not 0 — this call
        itself is the first occurrence."""
        row = _tsv_row("abc123")
        out, err, rc = self._bump(row + "\n")
        self.assertEqual(rc, 0, err)
        lines = [l for l in out.strip("\n").split("\n") if l]
        self.assertEqual(len(lines), 1)
        fields = lines[0].split("\t")
        self.assertEqual(len(fields), 5)
        self.assertEqual(fields[4], "1")

    def test_second_call_same_key_increments_to_2(self):
        """The core recurrence-counting property: calling twice with the same
        key persists and increments across calls, mirroring what happens
        across two review rounds."""
        row = _tsv_row("abc123")
        out1, err1, rc1 = self._bump(row + "\n")
        self.assertEqual(rc1, 0, err1)
        self.assertEqual(out1.strip().split("\t")[4], "1")

        out2, err2, rc2 = self._bump(row + "\n")
        self.assertEqual(rc2, 0, err2)
        self.assertEqual(out2.strip().split("\t")[4], "2",
                          f"second call must report count 2, got: {out2!r}")

    def test_third_call_increments_to_3(self):
        """Threshold-adjacent case: three rounds of the same finding must
        report count 3, not saturate at 2."""
        row = _tsv_row("abc123")
        for expected in (1, 2, 3):
            out, err, rc = self._bump(row + "\n")
            self.assertEqual(rc, 0, err)
            self.assertEqual(int(out.strip().split("\t")[4]), expected)

    def test_distinct_keys_counted_independently(self):
        """Two distinct keys must not share or pollute each other's count."""
        row_a = _tsv_row("keyA", fname="a.py")
        row_b = _tsv_row("keyB", fname="b.py")
        self._bump(row_a + "\n")
        out, err, rc = self._bump(row_a + "\n" + row_b + "\n")
        self.assertEqual(rc, 0, err)
        lines = [l for l in out.strip("\n").split("\n") if l]
        counts = {l.split("\t")[0]: l.split("\t")[4] for l in lines}
        self.assertEqual(counts["keyA"], "2", "keyA is on its second bump")
        self.assertEqual(counts["keyB"], "1", "keyB is on its first bump")

    def test_empty_key_row_gets_count_1_and_is_not_persisted(self):
        """An empty key (first TSV field) has no stable identity to count
        occurrences of — conservative posture: always treated as count 1
        (never demotable), and never written to the counts file (so it can
        never accidentally collide with a real key later)."""
        row = "\t" + "\t".join(["a.py", "security", "some message"])
        out, err, rc = self._bump(row + "\n")
        self.assertEqual(rc, 0, err)
        # strip() would eat the leading tab (empty first field) — strip only
        # the trailing newline so the empty key field survives the split.
        fields = out.rstrip("\n").split("\t")
        self.assertEqual(len(fields), 5, f"expected 5 tab-separated fields, got: {fields!r}")
        self.assertEqual(fields[0], "", "first field (key) must remain empty")
        self.assertEqual(fields[4], "1")
        # Counts file must not contain an entry for the empty key.
        if os.path.exists(self.counts_path):
            with open(self.counts_path) as f:
                content = f.read().strip()
            if content:
                counts = json.loads(content)
                self.assertNotIn("", counts, "empty key must never be persisted")

    def test_counts_file_persisted_as_valid_json_object(self):
        row = _tsv_row("persisted-key")
        self._bump(row + "\n")
        self.assertTrue(os.path.exists(self.counts_path))
        with open(self.counts_path) as f:
            counts = json.load(f)
        self.assertIsInstance(counts, dict)
        self.assertEqual(counts.get("persisted-key"), 1)

    def test_corrupt_counts_file_treated_as_empty_not_fatal(self):
        """A malformed/corrupt counts file (e.g. truncated write, foreign
        content) must not crash the bump — fail-open to 'no prior count',
        matching the rest of this codebase's on-disk-state handling."""
        with open(self.counts_path, "w") as f:
            f.write("{not valid json at all")
        row = _tsv_row("keyX")
        out, err, rc = self._bump(row + "\n")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip().split("\t")[4], "1",
                          "corrupt counts file must be treated as if the key had never been seen")

    def test_non_object_counts_file_treated_as_empty(self):
        """A counts file that is valid JSON but not an object (e.g. a bare
        array or number) must not be trusted as a key->count map."""
        with open(self.counts_path, "w") as f:
            f.write("[1, 2, 3]")
        row = _tsv_row("keyY")
        out, err, rc = self._bump(row + "\n")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip().split("\t")[4], "1")

    def test_multiple_rows_in_one_call_all_annotated(self):
        rows = "\n".join([
            _tsv_row("k1", fname="a.py"),
            _tsv_row("k2", fname="b.py"),
            _tsv_row("k3", fname="c.py"),
        ])
        out, err, rc = self._bump(rows + "\n")
        self.assertEqual(rc, 0, err)
        lines = [l for l in out.strip("\n").split("\n") if l]
        self.assertEqual(len(lines), 3)
        for line in lines:
            self.assertEqual(line.split("\t")[4], "1")

    def test_original_columns_preserved_verbatim(self):
        """The 5th column is appended; the original 4 columns must survive
        unchanged (file/category/message are used downstream by gates.sh's
        splice-back-by-value matching)."""
        row = _tsv_row("keyZ", fname="path/to/file.py", category="correctness",
                        message="null pointer dereference")
        out, err, rc = self._bump(row + "\n")
        self.assertEqual(rc, 0, err)
        fields = out.strip().split("\t")
        self.assertEqual(fields[0], "keyZ")
        self.assertEqual(fields[1], "path/to/file.py")
        self.assertEqual(fields[2], "correctness")
        self.assertEqual(fields[3], "null pointer dereference")


if __name__ == "__main__":
    unittest.main()
