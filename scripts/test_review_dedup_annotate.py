"""
Cross-round dedup must annotate, never drop, and every review run must leave
enough provenance to be diagnosed afterwards.

BACKGROUND: with CLAGENTIC_CROSS_ROUND_DEDUP=1 (the default) a finding whose
content key was in .clagentic/lite/review-seen-keys used to be REMOVED from the
envelope before severity_blockers counted it. Re-running `gates review` at an
unchanged HEAD after REVIEW_BLOCKED therefore passed: the second run forgot the
first run's blocking finding. Dedup now keeps such a finding, marked
`_seen_before: true`, and the verdict is computed over it like any other.

Layers:
  1. dedup_findings (review-merge.sh) in annotate and drop mode.
  2. cmd_review end to end (real git repo, stub llm-client.sh), single-pass
     and chunked: block, then an identical re-run still blocks.
  3. The per-run provenance fields (model, prompt hash, diff hash, chunk
     count/sizes) in the ledger config and the audit trail, and the
     llm-client.sh side that records them.

Run with: python3 -m unittest scripts.test_review_dedup_annotate -v
"""
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from isolated_env import shared_env  # noqa: E402
from test_source_helpers import (  # noqa: E402
    LLM_CLIENT_SH,
    PLATFORM_SH,
    RECURRING_FINDING as _RECURRING_FINDING,
    REVIEW_MERGE_SH,
    init_git_repo as _init_git_repo,
    setup_fake_tool_home as _setup_fake_tool_home,
    setup_project as _setup_project,
    source_env,
    stage_identical_recreation as _stage_identical_recreation,
    stub_review_llm as _stub_llm,
)

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_DIFF = textwrap.dedent("""\
    diff --git a/app.py b/app.py
    --- a/app.py
    +++ b/app.py
    @@ -1,2 +1,2 @@
    -old
    +def handle(x):
    +    return x
    """)


def _dedup(findings, seen_path, mode):
    """Call the real sh dedup_findings (a wrapper over the finding pipeline)."""
    work = tempfile.mkdtemp(prefix="clagentic-test-dedup-")
    try:
        diff_path = os.path.join(work, "d.diff")
        with open(diff_path, "w") as f:
            f.write(_DIFF)
        env = shared_env(project=work)
        # The finding pipeline is found only under the tool home.
        env["TOOL_HOME"] = TOOL_HOME
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            . '{REVIEW_MERGE_SH}'
            dedup_findings content-hash '{seen_path}' '{diff_path}' {mode}
        """)
        r = subprocess.run(["sh", "-c", script], input=json.dumps(findings),
                           capture_output=True, text=True, env=env,
                           cwd=work)
        return json.loads(r.stdout), r
    finally:
        shutil.rmtree(work, ignore_errors=True)


class TestDedupFindingsAnnotateMode(unittest.TestCase):
    """Layer 1: dedup_findings in annotate and drop mode."""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="clagentic-test-dedup-seen-")
        self._seen = os.path.join(self._dir, "seen")

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    def test_seen_finding_is_kept_and_marked_in_annotate_mode(self):
        open(self._seen, "w").close()
        first, _ = _dedup([dict(_RECURRING_FINDING)], self._seen, "annotate")
        self.assertEqual(len(first), 1)
        self.assertNotIn("_seen_before", first[0], "first sighting is not seen")
        second, r = _dedup([dict(_RECURRING_FINDING)], self._seen, "annotate")
        self.assertEqual(len(second), 1, f"seen finding must be kept: {r.stderr}")
        self.assertIs(second[0]["_seen_before"], True)
        self.assertTrue(second[0]["_seen_key"], "prior key must be carried")
        self.assertEqual(second[0]["severity"], "high", "severity untouched")

    def test_drop_mode_still_drops_for_non_verdict_callers(self):
        open(self._seen, "w").close()
        _dedup([dict(_RECURRING_FINDING)], self._seen, "drop")
        again, _ = _dedup([dict(_RECURRING_FINDING)], self._seen, "drop")
        self.assertEqual(again, [])

    def test_annotate_keeps_within_run_collapse_and_new_findings_unmarked(self):
        new = dict(_RECURRING_FINDING, file="other.py", line=5, message="different")
        open(self._seen, "w").close()
        _dedup([dict(_RECURRING_FINDING)], self._seen, "annotate")
        out, _ = _dedup([dict(_RECURRING_FINDING), dict(_RECURRING_FINDING), new],
                        self._seen, "annotate")
        by_msg = {f["message"]: f for f in out}
        self.assertEqual(len(out), 2, "duplicate pair collapses to one")
        self.assertIs(by_msg[_RECURRING_FINDING["message"]]["_seen_before"], True)
        self.assertNotIn("_seen_before", by_msg["different"])


def _run_review(tool_home, project, extra_env=None):
    _setup_fake_tool_home(tool_home)
    env = shared_env(project=project)
    env.update({
        "CLAGENTIC_ALLOW_MISSING_GITLEAKS": "1",
        "CLAGENTIC_ALLOW_MISSING_SEMGREP": "1",
        "CLAGENTIC_ALLOW_MISSING_OSV": "1",
    })
    env.update(extra_env or {})
    return subprocess.run(
        ["sh", os.path.join(tool_home, "scripts", "gates.sh"), "review"],
        capture_output=True, text=True, env=env, cwd=project,
    )


_FINDING_ENVELOPE = {"summary": "one", "checked": ["security"], "findings": [dict(_RECURRING_FINDING)]}


class TestReviewRerunStillBlocks(unittest.TestCase):
    """Layer 2: the fail-open. Block at HEAD, identical re-run, still blocked."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-annotate-e2e-")
        self._project = _setup_project(self._tmp)
        _init_git_repo(self._project)
        _stub_llm(self._tmp, _FINDING_ENVELOPE)
        self._lite = os.path.join(self._project, ".clagentic", "lite")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _last_review(self):
        with open(os.path.join(self._lite, "last-review.json")) as f:
            return json.load(f)

    def _assert_rerun_blocks(self, extra_env=None):
        _stage_identical_recreation(self._project, 1)
        r1 = _run_review(self._tmp, self._project, extra_env)
        self.assertEqual(r1.returncode, 1, f"run 1 must block: {r1.stderr}")
        # Same staged state, same HEAD, no edits: the second run must agree.
        r2 = _run_review(self._tmp, self._project, extra_env)
        self.assertEqual(r2.returncode, 1, f"identical re-run must still block: {r2.stderr}")
        self.assertIn("REVIEW_BLOCKED", r2.stderr)
        findings = self._last_review()["findings"]
        self.assertEqual(len(findings), 1, "the seen finding stays in the envelope")
        self.assertIs(findings[0]["_seen_before"], True)
        self.assertIn("prior run", r2.stderr)
        # A third run is no different: the verdict never depends on the count.
        r3 = _run_review(self._tmp, self._project, extra_env)
        self.assertEqual(r3.returncode, 1, f"third identical run must block: {r3.stderr}")
        return r2

    def test_single_pass_rerun_at_same_head_still_blocks(self):
        self._assert_rerun_blocks()

    def test_chunked_rerun_at_same_head_still_blocks(self):
        # Two files and a tiny chunk budget force the chunked path.
        with open(os.path.join(self._project, "other.py"), "w") as f:
            f.write("def other(y):\n    return y\n")
        subprocess.run(["git", "add", "other.py"], check=True, cwd=self._project)
        self._assert_rerun_blocks({
            "CLAGENTIC_REVIEW_CHUNKING": "1",
            "CLAGENTIC_REVIEW_CHUNK_BYTES": "150",
        })

    def test_dedup_audit_row_reports_seen_count_and_mode(self):
        _stage_identical_recreation(self._project, 1)
        _run_review(self._tmp, self._project)
        _run_review(self._tmp, self._project)
        conn = sqlite3.connect(os.path.join(self._lite, "audit.db"))
        rows = conn.execute(
            "SELECT details FROM gate_runs WHERE gate='review-dedup' ORDER BY id DESC LIMIT 1"
        ).fetchall()
        conn.close()
        self.assertTrue(rows)
        self.assertIn("seen_before:1", rows[0][0])
        self.assertIn("mode:annotate", rows[0][0])

    def test_repeated_runs_do_not_demote_via_recurrence(self):
        """Repetition is information, never an exemption: the finding keeps
        blocking however many times it is reported, and a seen finding is not
        counted as another round."""
        _stage_identical_recreation(self._project, 1)
        for _ in range(4):
            r = _run_review(self._tmp, self._project)
            self.assertEqual(r.returncode, 1, r.stderr)
        findings = self._last_review()["findings"]
        self.assertNotIn(True, [f.get("_recurrence_demoted") for f in findings])
        self.assertEqual(findings[0].get("_recurrence_count", 0), 0,
                         "a seen-before finding is not counted again")

    def test_changed_context_is_a_new_finding_and_still_blocks(self):
        _stage_identical_recreation(self._project, 1)
        self.assertEqual(_run_review(self._tmp, self._project).returncode, 1)
        # Edit the flagged lines: new content key, so not "seen".
        with open(os.path.join(self._project, "app.py"), "w") as f:
            f.write("def handle(x):\n    return x + 1\n")
        subprocess.run(["git", "add", "app.py"], check=True, cwd=self._project)
        r = _run_review(self._tmp, self._project)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("_seen_before", self._last_review()["findings"][0])


class TestRunProvenance(unittest.TestCase):
    """Layer 3: model, prompt hash, true diff hash, chunk count/sizes."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-prov-")
        self._project = _setup_project(self._tmp)
        _init_git_repo(self._project)
        self._lite = os.path.join(self._project, ".clagentic", "lite")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _ledger_config(self):
        with open(os.path.join(self._lite, "review-ledger.jsonl")) as f:
            return json.loads(f.read().strip().splitlines()[-1])["config"]

    def _audit(self, gate):
        conn = sqlite3.connect(os.path.join(self._lite, "audit.db"))
        rows = conn.execute(
            "SELECT details FROM gate_runs WHERE gate=? ORDER BY id DESC LIMIT 1", (gate,)
        ).fetchall()
        conn.close()
        return rows[0][0] if rows else ""

    def _staged_diff_sha(self):
        out = subprocess.run(["git", "diff", "--cached", "--unified=3"], check=True,
                             capture_output=True, cwd=self._project).stdout
        return hashlib.sha256(out).hexdigest(), len(out)

    def test_single_pass_fields_present_in_ledger_and_audit(self):
        _stub_llm(self._tmp, {"summary": "clean", "checked": ["security"], "findings": []})
        _stage_identical_recreation(self._project, 1)
        sha, size = self._staged_diff_sha()
        head = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True, cwd=self._project).stdout.strip()
        r = _run_review(self._tmp, self._project)
        self.assertEqual(r.returncode, 0, r.stderr)

        cfg = self._ledger_config()
        self.assertEqual(cfg["model"], "stub-model-1")
        self.assertEqual(cfg["prompt_sha256"], "ab" * 32)
        self.assertEqual(cfg["diff_sha256"], sha)
        self.assertNotEqual(cfg["diff_sha256"], head, "diff hash is not the HEAD stamp")
        self.assertEqual(cfg["chunk_count"], 1)
        self.assertEqual(cfg["chunk_sizes"], [size])
        # Existing config members are untouched.
        self.assertEqual(cfg["block_severity"], "high")

        detail = self._audit("review-run")
        for token in ("stub-model-1", "ab" * 32, sha, "chunk_count:1", f"chunk_sizes:[{size}]"):
            self.assertIn(token, detail)
        with open(os.path.join(self._lite, "last-review.json")) as f:
            self.assertEqual(json.load(f)["_clagentic_diff_sha"], head,
                             "_clagentic_diff_sha keeps meaning HEAD for its consumers")

    def test_chunked_run_records_every_chunk_size(self):
        _stub_llm(self._tmp, {"summary": "clean", "checked": ["security"], "findings": []})
        _stage_identical_recreation(self._project, 1)
        with open(os.path.join(self._project, "other.py"), "w") as f:
            f.write("def other(y):\n    return y\n")
        subprocess.run(["git", "add", "other.py"], check=True, cwd=self._project)
        r = _run_review(self._tmp, self._project, {
            "CLAGENTIC_REVIEW_CHUNKING": "1", "CLAGENTIC_REVIEW_CHUNK_BYTES": "150",
        })
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = self._ledger_config()
        self.assertGreaterEqual(cfg["chunk_count"], 2)
        self.assertEqual(len(cfg["chunk_sizes"]), cfg["chunk_count"])
        self.assertTrue(all(isinstance(n, int) and n > 0 for n in cfg["chunk_sizes"]))
        self.assertEqual(cfg["diff_sha256"], self._staged_diff_sha()[0],
                         "the diff hash covers the whole reviewed diff, not a chunk")

    def test_missing_provenance_reads_none_not_absent(self):
        _stub_llm(self._tmp, {"summary": "clean", "checked": ["security"], "findings": []},
                  record_meta=False)
        _stage_identical_recreation(self._project, 1)
        self.assertEqual(_run_review(self._tmp, self._project).returncode, 0)
        cfg = self._ledger_config()
        self.assertEqual(cfg["model"], "none")
        self.assertEqual(cfg["prompt_sha256"], "none")
        self.assertNotEqual(cfg["diff_sha256"], "none")


class TestLlmClientRecordsRunMeta(unittest.TestCase):
    """The llm-client.sh half: one TSV line per accepted call, opt-in only."""

    def _call(self, meta_path, prompt, inp, set_env=True):
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            . '{LLM_CLIENT_SH}'
            _llm_record_run_meta claude high claude-test-9 '{prompt}' '{inp}'
        """)
        # Sourcing llm-client.sh resolves REPO_ROOT and its audit.db from the
        # cwd otherwise, i.e. the live checkout.
        project = os.path.dirname(meta_path)
        env = shared_env(project=project)
        env.update(source_env(llm_client=True))
        if set_env:
            env["CLAGENTIC_LLM_RUN_META_FILE"] = meta_path
        return subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env,
                              cwd=project)

    def test_line_carries_model_prompt_hash_and_sizes(self):
        with tempfile.TemporaryDirectory() as d:
            prompt, inp, meta = (os.path.join(d, n) for n in ("p", "i", "m"))
            with open(prompt, "w") as f:
                f.write("system prompt + injected block")
            with open(inp, "w") as f:
                f.write("diff text")
            r = self._call(meta, prompt, inp)
            self.assertEqual(r.returncode, 0, r.stderr)
            fields = open(meta).read().rstrip("\n").split("\t")
            self.assertEqual(fields[0], "claude-test-9")
            self.assertEqual(fields[3], hashlib.sha256(b"system prompt + injected block").hexdigest())
            self.assertEqual(fields[4:], [str(len(b"system prompt + injected block")), "9"])

    def test_no_env_var_means_no_file_and_no_failure(self):
        with tempfile.TemporaryDirectory() as d:
            prompt, inp, meta = (os.path.join(d, n) for n in ("p", "i", "m"))
            open(prompt, "w").close()
            open(inp, "w").close()
            r = self._call(meta, prompt, inp, set_env=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(os.path.exists(meta))


if __name__ == "__main__":
    unittest.main()
