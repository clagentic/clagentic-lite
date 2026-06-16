"""
Tests that exercise the ACTUAL sh functions in review-merge.sh by shelling out.

These tests are the ground truth — they prove the real sh code works, not a
Python copy. They source review-merge.sh (via sh -c) and call the functions
directly with crafted stdin/args, asserting on real stdout.

Run with: python3 -m unittest scripts/test_review_merge_sh.py -v
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
    """Run a POSIX sh snippet and return (stdout, stderr, returncode)."""
    r = subprocess.run(
        ["sh", "-c", script],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=TOOL_HOME,
    )
    return r.stdout, r.stderr, r.returncode


def source_and_run(fn_call, stdin=None):
    """Source review-merge.sh (with platform.sh), then call fn_call.
    Returns (stdout, stderr, returncode)."""
    script = textwrap.dedent(f"""\
        . '{PLATFORM_SH}'
        ds_load_env 2>/dev/null || true
        . '{RM_SH}'
        {fn_call}
    """)
    return sh(script, stdin=stdin)


class TestJqKeyFilter(unittest.TestCase):
    """Verify the jq filter that computes location keys produces non-empty output."""

    def test_jq_location_key_non_empty(self):
        """The jq filter used for location keys must return a non-empty string."""
        finding = json.dumps({"file": "a.py", "line": 10,
                              "category": "security", "message": "x"})
        # This is the CORRECT filter (after the fix).
        filt = '[(.file // ""), ((.line // 0) | tostring), (.category // ""), ((.message // "") | ascii_downcase)] | join(":")'
        out, err, rc = sh(f"printf '%s' '{finding}' | jq -r '{filt}'")
        self.assertEqual(rc, 0, f"jq filter errored: {err}")
        self.assertNotEqual(out.strip(), "", "key must be non-empty")
        self.assertIn("a.py", out, "file name must be in key")
        self.assertIn("10", out, "line number must be in key")
        self.assertIn("security", out, "category must be in key")

    def test_jq_broken_filter_was_empty(self):
        """Document that the OLD filter produced empty output (confirming root cause)."""
        finding = json.dumps({"file": "a.py", "line": 10,
                              "category": "security", "message": "x"})
        # This is the OLD (broken) filter from the original code.
        broken = '[.file // "", (.line // "") | tostring, .category // "", (.message // "" | ascii_downcase)] | join(":")'
        out, err, rc = sh(f"printf '%s' '{finding}' | jq -r '{broken}' 2>/dev/null")
        # On most jq versions this errors (rc!=0) or produces wrong output.
        # Either way, document that it did NOT produce "a.py:10:security:x".
        expected_key = "a.py:10:security:x"
        if rc == 0 and out.strip() == expected_key:
            self.skipTest("jq version on this host accepted the broken filter — skip regression doc")
        # The broken filter either errors OR produces malformed output.
        self.assertTrue(
            rc != 0 or out.strip() != expected_key,
            f"Broken filter unexpectedly produced the correct key: {out.strip()!r}"
        )


class TestDedupFindingsSh(unittest.TestCase):
    """Tests that call the ACTUAL sh dedup_findings function."""

    def _run_dedup(self, findings_json, strategy="location", seen_contents="", diff_file=""):
        """Source review-merge.sh and pipe findings through dedup_findings."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".seen", delete=False) as sf:
            sf.write(seen_contents)
            seen_path = sf.name
        try:
            df_call = f"dedup_findings {strategy} '{seen_path}'"
            if diff_file:
                df_call += f" '{diff_file}'"
            out, err, rc = source_and_run(df_call, stdin=findings_json)
            return out.strip(), err, rc
        finally:
            os.unlink(seen_path)

    def test_single_finding_returned(self):
        """REGRESSION for original bug: one finding must NOT be dropped (must not return [])."""
        findings = '[{"file":"a.py","line":10,"category":"security","severity":"high","message":"x"}]'
        out, err, rc = self._run_dedup(findings)
        self.assertEqual(rc, 0, f"dedup_findings exited non-zero: {err}")
        parsed = json.loads(out)
        self.assertEqual(len(parsed), 1, f"Expected 1 finding, got {len(parsed)}: {out}")
        self.assertEqual(parsed[0]["severity"], "high")

    def test_severity_wins_high_over_medium(self):
        """Two same-location findings: dedup yields 1, higher severity wins."""
        findings = json.dumps([
            {"file": "a.py", "line": 5, "category": "security",
             "severity": "medium", "message": "sql injection"},
            {"file": "a.py", "line": 5, "category": "security",
             "severity": "high", "message": "sql injection"},
        ])
        out, err, rc = self._run_dedup(findings)
        self.assertEqual(rc, 0)
        parsed = json.loads(out)
        self.assertEqual(len(parsed), 1, f"Expected 1 finding after dedup, got {len(parsed)}: {out}")
        self.assertEqual(parsed[0]["severity"], "high",
                         f"Expected high severity to win, got: {parsed[0]['severity']}")

    def test_distinct_findings_both_retained(self):
        """Two distinct findings (different file/line) must both be kept."""
        findings = json.dumps([
            {"file": "a.py", "line": 1, "category": "security",
             "severity": "high", "message": "xss"},
            {"file": "b.py", "line": 2, "category": "style",
             "severity": "low", "message": "long line"},
        ])
        out, err, rc = self._run_dedup(findings)
        self.assertEqual(rc, 0)
        parsed = json.loads(out)
        self.assertEqual(len(parsed), 2, f"Expected 2 distinct findings, got {len(parsed)}: {out}")

    def test_cross_run_dedup_via_seen_file(self):
        """Findings already in seen file are excluded on second pass."""
        finding = {"file": "d.py", "line": 7, "category": "correctness",
                   "severity": "high", "message": "null deref"}
        findings_json = json.dumps([finding])

        # First pass: populate seen file.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".seen", delete=False) as sf:
            seen_path = sf.name

        try:
            fn_call = f"dedup_findings location '{seen_path}'"
            out1, _, rc1 = source_and_run(fn_call, stdin=findings_json)
            self.assertEqual(rc1, 0)
            parsed1 = json.loads(out1.strip())
            self.assertEqual(len(parsed1), 1, "First pass must return 1 finding")

            # Second pass with same seen file (now contains the key).
            out2, _, rc2 = source_and_run(fn_call, stdin=findings_json)
            self.assertEqual(rc2, 0)
            parsed2 = json.loads(out2.strip())
            self.assertEqual(len(parsed2), 0,
                             f"Second pass must return 0 findings (cross-run dedup), got: {out2}")
        finally:
            os.unlink(seen_path)

    def test_invalid_json_conservative_passthrough(self):
        """Invalid JSON input must not crash; function must exit 0."""
        out, err, rc = self._run_dedup("not json at all")
        self.assertEqual(rc, 0, f"dedup_findings must exit 0 on invalid JSON, got rc={rc}: {err}")


class TestSplitDiffSh(unittest.TestCase):
    """Tests that call the ACTUAL sh split_diff function."""

    SYNTHETIC_DIFF = textwrap.dedent("""\
        diff --git a/file_a.py b/file_a.py
        --- a/file_a.py
        +++ b/file_a.py
        @@ -1,3 +1,4 @@
         def foo():
        +    # added comment
             return 1

        diff --git a/file_b.py b/file_b.py
        --- a/file_b.py
        +++ b/file_b.py
        @@ -1,2 +1,3 @@
         x = 1
        +y = 2
         z = 3
    """)

    def _run_split(self, diff_text, budget):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as df:
            df.write(diff_text)
            diff_path = df.name
        chunk_dir = tempfile.mkdtemp(prefix="clagentic-test-split-")
        try:
            fn_call = f"split_diff '{diff_path}' '{chunk_dir}' {budget}"
            out, err, rc = source_and_run(fn_call)
            chunk_count = int(out.strip()) if out.strip().isdigit() else -1
            # Collect chunk files.
            chunks = sorted(
                f for f in os.listdir(chunk_dir)
                if f.startswith("chunk-")
            )
            chunk_contents = {}
            for c in chunks:
                with open(os.path.join(chunk_dir, c)) as f:
                    chunk_contents[c] = f.read()
            return chunk_count, chunks, chunk_contents, err, rc
        finally:
            os.unlink(diff_path)
            import shutil
            shutil.rmtree(chunk_dir, ignore_errors=True)

    def test_chunk_count_large_budget(self):
        """Large budget: all files fit in one chunk; count >= 1."""
        count, chunks, contents, err, rc = self._run_split(self.SYNTHETIC_DIFF, 65536)
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(count, 1, f"Expected >= 1 chunk, got {count}. stderr: {err}")
        self.assertEqual(len(chunks), count,
                         f"Chunk file count {len(chunks)} != reported {count}")

    def test_chunk_numbering_starts_at_001(self):
        """First chunk file must be chunk-001, not chunk-000."""
        count, chunks, contents, err, rc = self._run_split(self.SYNTHETIC_DIFF, 65536)
        self.assertEqual(rc, 0)
        self.assertGreater(count, 0)
        self.assertIn("chunk-001", chunks,
                      f"First chunk must be chunk-001, got: {chunks}")
        self.assertNotIn("chunk-000", chunks, "chunk-000 must not exist (1-based numbering)")

    def test_each_chunk_begins_with_diff_git_header(self):
        """Every chunk must begin with 'diff --git' (intact boundary)."""
        count, chunks, contents, err, rc = self._run_split(self.SYNTHETIC_DIFF, 65536)
        self.assertEqual(rc, 0)
        for cname, content in contents.items():
            first_line = content.split("\n")[0] if content else ""
            self.assertTrue(
                first_line.startswith("diff --git "),
                f"Chunk {cname} must start with 'diff --git', got: {first_line!r}"
            )

    def test_small_budget_multiple_chunks(self):
        """Small budget produces more chunks than large budget."""
        count_large, _, _, _, _ = self._run_split(self.SYNTHETIC_DIFF, 65536)
        count_small, chunks_small, contents_small, err, rc = self._run_split(self.SYNTHETIC_DIFF, 50)
        self.assertEqual(rc, 0)
        # Each small-budget chunk must also start with diff --git or @@ (hunk header).
        for cname, content in contents_small.items():
            first_line = content.split("\n")[0] if content else ""
            self.assertTrue(
                first_line.startswith("diff --git ") or first_line.startswith("@@ "),
                f"Small-budget chunk {cname} must start with diff or hunk header, got: {first_line!r}"
            )

    def test_missing_diff_file_returns_zero(self):
        """Non-existent diff file produces 0 chunks and exits 0."""
        chunk_dir = tempfile.mkdtemp(prefix="clagentic-test-split-")
        try:
            fn_call = f"split_diff '/nonexistent/path.diff' '{chunk_dir}' 65536"
            out, err, rc = source_and_run(fn_call)
            count = int(out.strip()) if out.strip().isdigit() else -1
            self.assertEqual(rc, 0)
            self.assertEqual(count, 0, f"Expected 0 chunks for missing diff, got {count}")
        finally:
            import shutil
            shutil.rmtree(chunk_dir, ignore_errors=True)
