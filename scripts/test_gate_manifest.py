"""
Acceptance tests for lr-37a9c8: the gate attestation manifest --
.clagentic/lite/last-gate-manifest.json, one machine-readable per-run record
of what ran, via which path/brand/model, with any fallback events, for every
gate `gates.sh ship` declares.

SCOPE:
  1. _manifest_init writes a fresh, unconditional manifest before any gate
     runs (absence-as-failure precondition -- acceptance criterion 4).
  2. _manifest_set_gate / _manifest_finalize merge per-gate records and
     compute the top-level "complete"/"degraded" flags.
  3. _manifest_llm_provenance reads back log_attempt's own gate_runs rows
     (gate='llm-call') to derive path/brand/model/fallback_events for an
     LLM-backed gate, scoped to a watermark so a prior run's rows for the
     same role are never misattributed.
  4. _manifest_is_complete is the fail-closed consumer predicate for a
     missing/incomplete manifest (never inferred as success).
  5. _render_gate_manifest_lines renders the same "explicit sentence per
     state" discipline lr-429b32 established, reused (not re-derived) by
     _build_ship_pr_body's new "Gate attestation" section.

VERIFICATION: direct-source tests against the real scripts/gates.sh via the
CLAGENTIC_GATES_SOURCE_ONLY / CLAGENTIC_GATES_DELIBERATE_SOURCE guard
(test_source_helpers.source_env), mirroring test_ship_pr_body.py's pattern --
a real, remoteless temp git repo, no network, no host.

Run with: python3 -m unittest scripts.test_gate_manifest -v
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _init_repo(root):
    subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
    env = {**os.environ, **_GIT_ENV}
    with open(os.path.join(root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    subprocess.run(["git", "add", "app.py"], check=True, cwd=root, env=env, timeout=30)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], check=True, cwd=root, env=env, timeout=30)
    subprocess.run(["git", "checkout", "-q", "-b", "feat/example"], check=True, cwd=root, env=env, timeout=30)


def _manifest_path(repo):
    return os.path.join(repo, ".clagentic", "lite", "last-gate-manifest.json")


def _run_gates_sh(repo, script_body):
    env = os.environ.copy()
    env.update(source_env(gates=True))
    env["CLAGENTIC_PROJECT_ROOT"] = repo
    script = textwrap.dedent(f"""\
        . '{GATES_SH}'
        {script_body}
    """)
    return subprocess.run(
        ["sh", "-c", script, GATES_SH],
        capture_output=True, text=True, env=env, cwd=repo, timeout=30,
    )


def _init_audit_db(repo):
    """Create the gate_runs table directly (mirrors cmd_init's own schema)
    so tests can seed rows without depending on a real LLM call."""
    db_dir = os.path.join(repo, ".clagentic", "lite")
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "audit.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS gate_runs (
          id         INTEGER PRIMARY KEY,
          ts         TEXT NOT NULL,
          gate       TEXT NOT NULL,
          outcome    TEXT NOT NULL,
          details    TEXT,
          session_id TEXT,
          branch     TEXT
        );
    """)
    conn.commit()
    conn.close()
    return db_path


def _insert_call_row(db_path, gate, outcome, details):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO gate_runs (ts, gate, outcome, details) VALUES (datetime('now'), ?, ?, ?)",
        (gate, outcome, details),
    )
    conn.commit()
    conn.close()


class TestManifestInit(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-manifest-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_init_writes_unconditional_manifest_before_any_gate_runs(self):
        r = _run_gates_sh(self._repo, "_manifest_init")
        self.assertEqual(r.returncode, 0, r.stderr)
        path = _manifest_path(self._repo)
        self.assertTrue(os.path.isfile(path))
        with open(path) as f:
            m = json.load(f)
        self.assertEqual(m["branch"], "feat/example")
        self.assertEqual(m["gates"], {})
        self.assertFalse(m["complete"])

    def test_is_complete_false_when_manifest_absent(self):
        """Acceptance criterion 4: a missing manifest is reported as
        failure, never inferred as success."""
        r = _run_gates_sh(self._repo, "_manifest_is_complete")
        self.assertNotEqual(r.returncode, 0)

    def test_render_manifest_refuses_loudly_when_absent(self):
        r = _run_gates_sh(self._repo, "cmd_render_manifest")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no gate attestation manifest", r.stderr)


class TestManifestSetGateAndFinalize(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-manifest-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)
        _run_gates_sh(self._repo, "_manifest_init")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_set_gate_records_deterministic_gate_with_no_path_or_brand(self):
        r = _run_gates_sh(self._repo, '_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""')
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_manifest_path(self._repo)) as f:
            m = json.load(f)
        self.assertEqual(m["gates"]["secrets"]["outcome"], "ran")
        self.assertEqual(m["gates"]["secrets"]["path"], "n/a")
        self.assertEqual(m["gates"]["secrets"]["brand"], "")

    def test_set_gate_records_llm_gate_with_brand_and_model(self):
        r = _run_gates_sh(
            self._repo,
            '_manifest_set_gate review ran direct codex gpt-5.1-codex "[]" "" ""',
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_manifest_path(self._repo)) as f:
            m = json.load(f)
        self.assertEqual(m["gates"]["review"]["path"], "direct")
        self.assertEqual(m["gates"]["review"]["brand"], "codex")
        self.assertEqual(m["gates"]["review"]["model"], "gpt-5.1-codex")

    def test_finalize_marks_complete_true_when_every_declared_gate_recorded(self):
        script = """\
_manifest_set_gate bleed ran "n/a" "" "" "[]" "" ""
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_set_gate deps ran "n/a" "" "" "[]" "" ""
_manifest_set_gate sast ran "n/a" "" "" "[]" "" ""
_manifest_set_gate review ran direct codex "" "[]" "" ""
_manifest_set_gate adversarial ran direct codex "" "[]" "" ""
_manifest_set_gate merge-gate ran direct claude "" "[]" "" ""
_manifest_finalize "bleed secrets deps sast review adversarial merge-gate"
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_manifest_path(self._repo)) as f:
            m = json.load(f)
        self.assertTrue(m["complete"])
        self.assertEqual(m["missing_gates"], [])
        self.assertFalse(m["degraded"])

    def test_finalize_marks_incomplete_when_a_declared_gate_never_recorded(self):
        """A crashed/killed-mid-run ship: merge-gate never reached, never
        recorded -- the manifest must say so explicitly, not silently omit
        the field or claim completeness."""
        script = """\
_manifest_set_gate bleed ran "n/a" "" "" "[]" "" ""
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_finalize "bleed secrets deps sast review adversarial merge-gate"
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_manifest_path(self._repo)) as f:
            m = json.load(f)
        self.assertFalse(m["complete"])
        self.assertIn("merge-gate", m["missing_gates"])
        self.assertIn("deps", m["missing_gates"])

    def test_finalize_marks_degraded_true_when_any_gate_outcome_degraded(self):
        """Acceptance criterion 1: a run where a chain step fell back /
        degraded is marked degraded-with-reason, distinct from
        passed-as-configured."""
        script = """\
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_set_gate review degraded direct codex "" "[]" degraded "infra-degraded at review"
_manifest_finalize "secrets review"
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_manifest_path(self._repo)) as f:
            m = json.load(f)
        self.assertTrue(m["degraded"])
        self.assertEqual(m["gates"]["review"]["outcome"], "degraded")

    def test_degraded_but_passed_is_distinct_from_ordinary_ran(self):
        """A fallback that still produces a passing verdict is NOT the same
        manifest shape as a clean primary-CLI pass -- fallback_events must
        be non-empty and distinguishable via jq/grep on the manifest file."""
        script = """\
_manifest_set_gate review ran direct claude "" '[{"from":"codex","to":"claude","reason":"step-failed"}]' "" ""
_manifest_finalize "review"
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_manifest_path(self._repo)) as f:
            m = json.load(f)
        self.assertEqual(len(m["gates"]["review"]["fallback_events"]), 1)
        self.assertEqual(m["gates"]["review"]["fallback_events"][0]["from"], "codex")
        self.assertEqual(m["gates"]["review"]["fallback_events"][0]["to"], "claude")


class TestManifestIsComplete(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-manifest-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_is_complete_true_after_finalize_with_no_missing_gates(self):
        script = """\
_manifest_init
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_finalize "secrets"
_manifest_is_complete
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_is_complete_false_when_finalize_never_ran(self):
        """_manifest_init alone (mid-run crash before finalize) must never
        read as complete."""
        script = """\
_manifest_init
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_is_complete
"""
        r = _run_gates_sh(self._repo, script)
        self.assertNotEqual(r.returncode, 0)


class TestManifestLlmProvenance(unittest.TestCase):
    """_manifest_llm_provenance reads back log_attempt's own gate_runs rows
    (gate='llm-call') -- these tests seed that table directly rather than
    running a real LLM call, mirroring _read_deterministic_gates' own test
    posture for reading pre-existing audit rows."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-manifest-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)
        self._db = _init_audit_db(self._repo)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_primary_pass_reports_direct_path_no_fallback(self):
        _insert_call_row(self._db, "llm-call", "pass", "reviewer:codex:default model=gpt-5.1-codex")
        r = _run_gates_sh(self._repo, "_manifest_llm_provenance reviewer 0")
        self.assertEqual(r.returncode, 0, r.stderr)
        path, brand, model, fallback, exit_class = r.stdout.split("\t")
        self.assertEqual(path, "direct")
        self.assertEqual(brand, "codex")
        self.assertEqual(model, "gpt-5.1-codex")
        self.assertEqual(json.loads(fallback), [])
        self.assertEqual(exit_class, "")

    def test_step_failed_then_fallback_pass_reports_fallback_event(self):
        _insert_call_row(self._db, "llm-call", "step-failed", "reviewer:codex:default — timeout after 180s")
        _insert_call_row(self._db, "llm-call", "fallback", "reviewer:claude:default model=claude-sonnet-5")
        r = _run_gates_sh(self._repo, "_manifest_llm_provenance reviewer 0")
        self.assertEqual(r.returncode, 0, r.stderr)
        path, brand, model, fallback, exit_class = r.stdout.split("\t")
        self.assertEqual(path, "direct")
        self.assertEqual(brand, "claude")
        events = json.loads(fallback)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["from"], "codex")
        self.assertEqual(events[0]["to"], "claude")

    def test_router_pass_reports_router_path(self):
        _insert_call_row(self._db, "llm-call", "pass", "reviewer:router:role:reviewer-chain — via clagentic-router")
        r = _run_gates_sh(self._repo, "_manifest_llm_provenance reviewer 0")
        self.assertEqual(r.returncode, 0, r.stderr)
        path, brand, model, fallback, exit_class = r.stdout.split("\t")
        self.assertEqual(path, "router")
        self.assertEqual(brand, "router")

    def test_degraded_only_reports_exit_class_degraded_no_brand(self):
        _insert_call_row(self._db, "llm-call", "degraded", "reviewer::  — cause=infra")
        r = _run_gates_sh(self._repo, "_manifest_llm_provenance reviewer 0")
        self.assertEqual(r.returncode, 0, r.stderr)
        path, brand, model, fallback, exit_class = r.stdout.split("\t")
        self.assertEqual(exit_class, "degraded")
        self.assertEqual(brand, "")

    def test_watermark_excludes_rows_from_a_prior_run(self):
        """A prior run's leftover rows for the same role must never be
        misattributed to this run's manifest entry."""
        _insert_call_row(self._db, "llm-call", "pass", "reviewer:codex:default model=old-model")
        # Capture watermark as the current max id.
        conn = sqlite3.connect(self._db)
        watermark = conn.execute("SELECT MAX(id) FROM gate_runs").fetchone()[0]
        conn.close()
        _insert_call_row(self._db, "llm-call", "pass", "reviewer:claude:default model=new-model")
        r = _run_gates_sh(self._repo, f"_manifest_llm_provenance reviewer {watermark}")
        self.assertEqual(r.returncode, 0, r.stderr)
        path, brand, model, fallback, exit_class = r.stdout.split("\t")
        self.assertEqual(brand, "claude")
        self.assertEqual(model, "new-model")

    def test_no_rows_for_role_reports_empty_provenance(self):
        r = _run_gates_sh(self._repo, "_manifest_llm_provenance reviewer 0")
        self.assertEqual(r.returncode, 0, r.stderr)
        path, brand, model, fallback, exit_class = r.stdout.split("\t")
        self.assertEqual(path, "")
        self.assertEqual(brand, "")
        self.assertEqual(json.loads(fallback), [])


class TestRenderGateManifestLines(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-manifest-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_renders_brand_and_model_per_gate(self):
        script = """\
_manifest_init
_manifest_set_gate review ran direct codex gpt-5.1-codex "[]" "" ""
_manifest_finalize "review"
_render_gate_manifest_lines
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("review: ran", r.stdout)
        self.assertIn("brand=codex", r.stdout)
        self.assertIn("model=gpt-5.1-codex", r.stdout)

    def test_renders_degraded_but_passed_as_distinct_loud_state(self):
        script = """\
_manifest_init
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_set_gate review degraded direct codex "" "[]" degraded "infra-degraded at review"
_manifest_finalize "secrets review"
_render_gate_manifest_lines
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DEGRADED-BUT-PASSED", r.stdout)
        self.assertIn("review: degraded", r.stdout)

    def test_renders_incomplete_manifest_notice(self):
        script = """\
_manifest_init
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_finalize "secrets review merge-gate"
_render_gate_manifest_lines
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("INCOMPLETE manifest", r.stdout)
        self.assertIn("review", r.stdout)
        self.assertIn("merge-gate", r.stdout)


class TestShipPrBodyIncludesGateAttestation(unittest.TestCase):
    """_build_ship_pr_body's new fifth section reuses _render_gate_manifest_lines
    -- covered end-to-end here rather than duplicating test_ship_pr_body.py's
    own review-provenance-focused suite."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-manifest-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _head_sha(self):
        r = subprocess.run(["git", "rev-parse", "HEAD"], check=True, cwd=self._repo,
                            capture_output=True, text=True, timeout=30)
        return r.stdout.strip()

    def test_no_manifest_renders_honest_absence_sentence(self):
        r = _run_gates_sh(self._repo, f"_build_ship_pr_body 'feat/example' '{self._head_sha()}'")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## Gate attestation", r.stdout)
        self.assertIn("no gate attestation manifest recorded", r.stdout)
        self.assertIn("never inferred as a clean run", r.stdout)

    def test_manifest_present_renders_per_gate_attestation(self):
        script = f"""\
_manifest_init
_manifest_set_gate secrets ran "n/a" "" "" "[]" "" ""
_manifest_set_gate review ran direct codex gpt-5.1-codex "[]" "" ""
_manifest_finalize "secrets review"
_build_ship_pr_body 'feat/example' '{self._head_sha()}'
"""
        r = _run_gates_sh(self._repo, script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## Gate attestation", r.stdout)
        self.assertIn("review: ran", r.stdout)
        self.assertIn("brand=codex", r.stdout)


if __name__ == "__main__":
    unittest.main()
