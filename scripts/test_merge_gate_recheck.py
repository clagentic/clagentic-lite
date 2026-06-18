"""
Regression tests for the --recheck flag in cmd_merge_gate (gates.sh).

Tests added in lr-291d: PEACHES found no coverage for the --recheck path.
Test 4-5 added in lr-23c2: SHA-mismatch staleness guard for --recheck.

Scenarios:
  1. --recheck exits 1 with a clear error message when gate-summary.json is absent.
  2. --recheck succeeds (exit 0) when gate-summary.json exists and the LLM stub
     returns {"decision":"approve","reason":"test"}.
  3. The audit trail records "merge-gate recheck" (not "merge-gate") when
     --recheck is passed and gate-summary.json exists.
  4. --recheck exits 1 when gate-summary.json exists but its embedded SHA does
     not match HEAD (staleness guard added in lr-23c2).
  5. --recheck succeeds when gate-summary.json SHA matches HEAD exactly.

Run with:
  python3 -m unittest scripts/test_merge_gate_recheck.py -v
"""
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def _make_fake_llm_client(tmpdir, decision="approve", reason="test"):
    """Write a stub llm-client.sh that echoes a fixed JSON response.

    The real gates.sh invokes llm-client.sh via:
        "$TOOL_HOME/scripts/llm-client.sh" merge-gate < "$IN" > "$OUT"

    We override TOOL_HOME inside the gates.sh invocation so it picks up our
    stub instead.  The stub ignores its arguments and stdin, and writes a
    valid merge-gate JSON envelope to stdout.
    """
    scripts_dir = os.path.join(tmpdir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    payload = json.dumps({"decision": decision, "reason": reason})
    with open(stub, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            # stub llm-client.sh — returns a fixed merge-gate decision
            printf '%s\\n' '{payload}'
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return tmpdir   # caller uses this as the fake TOOL_HOME


def _setup_fake_tool_home(fake_tool_home):
    """Symlink all real scripts/*.sh into the fake tool home's scripts/ dir,
    except llm-client.sh which is already a stub written by _make_fake_llm_client.

    gates.sh resolves TOOL_HOME as dirname(dirname($0)).  Calling it from
    fake_tool_home/scripts/ makes TOOL_HOME == fake_tool_home, so the stub
    llm-client.sh is invoked instead of the real one.  All other sourced
    helpers (platform.sh, review-merge.sh) are symlinked from the real scripts/
    dir so they work identically.
    """
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")

    for fname in os.listdir(real_scripts_dir):
        if not fname.endswith(".sh"):
            continue
        if fname == "llm-client.sh":
            # Already a stub written by _make_fake_llm_client — don't overwrite.
            continue
        src = os.path.join(real_scripts_dir, fname)
        dst = os.path.join(scripts_dir, fname)
        if not os.path.exists(dst):
            os.symlink(src, dst)

    # gates.sh also needs share/config.example to not crash on ds_load_env.
    # Symlink the entire share/ dir tree at the fake tool home level.
    real_share = os.path.join(TOOL_HOME, "share")
    fake_share = os.path.join(fake_tool_home, "share")
    if not os.path.exists(fake_share) and os.path.isdir(real_share):
        os.symlink(real_share, fake_share)


def _run_merge_gate(extra_args, fake_tool_home, project_root):
    """Invoke gates.sh merge-gate from the fake_tool_home's scripts/ dir.

    gates.sh computes TOOL_HOME from dirname(dirname($0)).  By calling it as
    fake_tool_home/scripts/gates.sh, TOOL_HOME resolves to fake_tool_home, so
    the stub llm-client.sh is used.  All other helpers are symlinked from the
    real scripts/ dir.

    CLAGENTIC_PROJECT_ROOT points to our temp project_root so audit.db and
    gate artifacts land there instead of the real repo.
    """
    _setup_fake_tool_home(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")

    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    # Suppress external tool requirements — not testing secrets/sast/deps.
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    # merge-gate blocking stays on (default=1); a 'refuse' from the LLM would
    # exit 1.  Tests that expect exit 0 use the approve stub.
    env["CLAGENTIC_MERGE_GATE_BLOCKING"] = "1"
    # Skip staleness check — our test gate-summary.json has no real SHA stamp.
    env["CLAGENTIC_ALLOW_STALE_PAYLOAD"] = "1"

    cmd = ["sh", fake_gates, "merge-gate"] + extra_args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        cwd=project_root,
    )
    return result


def _setup_project(tmpdir):
    """Create the minimal directory structure a fresh project root needs."""
    clagentic_dir = os.path.join(tmpdir, ".clagentic", "lite")
    os.makedirs(clagentic_dir, exist_ok=True)
    # Initialize audit.db with the schema.
    db_path = os.path.join(clagentic_dir, "audit.db")
    conn = sqlite3.connect(db_path)
    conn.execute(textwrap.dedent("""\
        CREATE TABLE IF NOT EXISTS gate_runs (
          id         INTEGER PRIMARY KEY,
          ts         TEXT NOT NULL,
          gate       TEXT NOT NULL,
          outcome    TEXT NOT NULL,
          details    TEXT,
          session_id TEXT,
          branch     TEXT
        )
    """))
    conn.commit()
    conn.close()
    return tmpdir


def _init_git_repo(project_root):
    """Initialize a minimal git repo in project_root and return the HEAD SHA.

    Creates one commit so git rev-parse HEAD succeeds.  The SHA is used by
    tests that exercise the SHA-staleness guard in --recheck.
    """
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"

    subprocess.run(["git", "init", "-q", project_root], check=True, env=env)
    subprocess.run(
        ["git", "commit", "--allow-empty", "-q", "-m", "initial"],
        check=True,
        env=env,
        cwd=project_root,
    )
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        cwd=project_root,
    )
    return result.stdout.strip()


class TestMergeGateRecheck(unittest.TestCase):
    """Regression tests for gates.sh merge-gate --recheck."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-mg-")
        self._project = _setup_project(self._tmpdir)
        self._fake_tool_home = _make_fake_llm_client(self._tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------ test 1
    def test_recheck_fails_when_gate_summary_missing(self):
        """--recheck exits 1 with a clear error when gate-summary.json does not exist."""
        summary_path = os.path.join(self._project, ".clagentic", "lite", "gate-summary.json")
        self.assertFalse(os.path.exists(summary_path),
                         "gate-summary.json must not exist for this test")

        result = _run_merge_gate(["--recheck"], self._fake_tool_home, self._project)

        self.assertEqual(result.returncode, 1,
                         f"Expected exit 1; got {result.returncode}\n"
                         f"stdout: {result.stdout}\nstderr: {result.stderr}")
        self.assertIn("gate-summary.json", result.stderr,
                      f"Error message must mention 'gate-summary.json'; stderr: {result.stderr}")
        # The message must be clear: no opaque error, no traceback.
        self.assertIn("--recheck", result.stderr,
                      f"Error message must mention '--recheck'; stderr: {result.stderr}")

    # ------------------------------------------------------------------ test 2
    def test_recheck_succeeds_when_gate_summary_exists(self):
        """--recheck exits 0 when gate-summary.json exists and stub LLM returns approve."""
        summary_path = os.path.join(self._project, ".clagentic", "lite", "gate-summary.json")
        summary = {
            "review": {"findings": [], "summary": "clean"},
            "adversarial": None,
            "adversarial_missing": True,
            "adversarial_acks": [],
            "accepted_risks": "",
            "introduces_ack_file": False,
            "threshold": "high",
        }
        with open(summary_path, "w") as f:
            json.dump(summary, f)

        result = _run_merge_gate(["--recheck"], self._fake_tool_home, self._project)

        self.assertEqual(result.returncode, 0,
                         f"Expected exit 0 (approve); got {result.returncode}\n"
                         f"stdout: {result.stdout}\nstderr: {result.stderr}")

        # last-merge-gate.json must contain the stub's decision.
        output_path = os.path.join(self._project, ".clagentic", "lite", "last-merge-gate.json")
        self.assertTrue(os.path.exists(output_path),
                        "last-merge-gate.json must be written by --recheck")
        with open(output_path) as f:
            out_json = json.load(f)
        self.assertEqual(out_json.get("decision"), "approve",
                         f"Expected decision=approve; got: {out_json}")

    # ------------------------------------------------------------------ test 3
    def test_recheck_audit_gate_name_is_merge_gate_recheck(self):
        """Audit trail records 'merge-gate recheck' (not 'merge-gate') when --recheck is used."""
        summary_path = os.path.join(self._project, ".clagentic", "lite", "gate-summary.json")
        summary = {
            "review": {"findings": [], "summary": "clean"},
            "adversarial": None,
            "adversarial_missing": True,
            "adversarial_acks": [],
            "accepted_risks": "",
            "introduces_ack_file": False,
            "threshold": "high",
        }
        with open(summary_path, "w") as f:
            json.dump(summary, f)

        result = _run_merge_gate(["--recheck"], self._fake_tool_home, self._project)
        self.assertEqual(result.returncode, 0,
                         f"--recheck must succeed for audit test; "
                         f"stdout: {result.stdout}\nstderr: {result.stderr}")

        db_path = os.path.join(self._project, ".clagentic", "lite", "audit.db")
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT gate, outcome FROM gate_runs ORDER BY id DESC LIMIT 5"
        ).fetchall()
        conn.close()

        gate_names = [r[0] for r in rows]
        self.assertIn("merge-gate recheck", gate_names,
                      f"Expected 'merge-gate recheck' in audit rows; got: {gate_names}\n"
                      f"stdout: {result.stdout}\nstderr: {result.stderr}")
        self.assertNotIn("merge-gate", [g for g in gate_names if g != "merge-gate recheck"],
                         f"Unexpected bare 'merge-gate' row logged during --recheck; "
                         f"rows: {rows}")

    # ------------------------------------------------------------------ test 4
    def test_recheck_refuses_on_sha_mismatch(self):
        """--recheck exits 1 when gate-summary.json SHA does not match HEAD (lr-23c2)."""
        head_sha = _init_git_repo(self._project)

        # Write a gate-summary.json whose review._clagentic_diff_sha is a
        # deliberately wrong SHA (all zeros — not a real commit object).
        stale_sha = "0" * 40
        self.assertNotEqual(stale_sha, head_sha,
                            "stale_sha must differ from HEAD for this test to be meaningful")

        summary_path = os.path.join(self._project, ".clagentic", "lite", "gate-summary.json")
        summary = {
            "review": {
                "findings": [],
                "summary": "clean",
                "_clagentic_diff_sha": stale_sha,
            },
            "adversarial": None,
            "adversarial_missing": True,
            "adversarial_acks": [],
            "accepted_risks": "",
            "introduces_ack_file": False,
            "threshold": "high",
        }
        with open(summary_path, "w") as f:
            json.dump(summary, f)

        result = _run_merge_gate(["--recheck"], self._fake_tool_home, self._project)

        self.assertEqual(result.returncode, 1,
                         f"Expected exit 1 on SHA mismatch; got {result.returncode}\n"
                         f"stdout: {result.stdout}\nstderr: {result.stderr}")
        self.assertIn(stale_sha, result.stderr,
                      f"Error must include the stale SHA; stderr: {result.stderr}")
        self.assertIn(head_sha, result.stderr,
                      f"Error must include HEAD SHA; stderr: {result.stderr}")

    # ------------------------------------------------------------------ test 5
    def test_recheck_succeeds_on_sha_match(self):
        """--recheck exits 0 when gate-summary.json SHA matches HEAD (lr-23c2)."""
        head_sha = _init_git_repo(self._project)

        summary_path = os.path.join(self._project, ".clagentic", "lite", "gate-summary.json")
        summary = {
            "review": {
                "findings": [],
                "summary": "clean",
                "_clagentic_diff_sha": head_sha,
            },
            "adversarial": None,
            "adversarial_missing": True,
            "adversarial_acks": [],
            "accepted_risks": "",
            "introduces_ack_file": False,
            "threshold": "high",
        }
        with open(summary_path, "w") as f:
            json.dump(summary, f)

        result = _run_merge_gate(["--recheck"], self._fake_tool_home, self._project)

        self.assertEqual(result.returncode, 0,
                         f"Expected exit 0 when SHA matches HEAD; got {result.returncode}\n"
                         f"stdout: {result.stdout}\nstderr: {result.stderr}")
        output_path = os.path.join(self._project, ".clagentic", "lite", "last-merge-gate.json")
        self.assertTrue(os.path.exists(output_path),
                        "last-merge-gate.json must be written on SHA-matching recheck")
        with open(output_path) as f:
            out_json = json.load(f)
        self.assertEqual(out_json.get("decision"), "approve",
                         f"Expected decision=approve; got: {out_json}")


if __name__ == "__main__":
    unittest.main()
