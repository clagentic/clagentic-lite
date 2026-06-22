"""
Regression tests for the wrapper/repo staleness check in gates.sh merge-gate.

Root cause fixed: every git operation in gates.sh now runs via _git(), which
uses git -C "$REPO_ROOT". Previously, bare `git rev-parse HEAD` used $PWD's
git context; in a wrapper layout $PWD has no git context (or a foreign one),
so the staleness check was silently skipped (fail-open) and stale artifacts
passed the merge-gate.

Fixture layout:
    <tmp>/
        wrapper/             # non-git directory (the wrapper)
            .clagentic-project  -> points to wrapper/repo
            repo/            # the enrolled git repo
                .clagentic/lite/
                    last-review.json     (stamped with old HEAD)
                    last-adversarial.md  (stamped with old HEAD)

Scenarios:
    1. cwd = wrapper dir (non-git): stale artifacts blocked (not fail-opened).
    2. cwd = unrelated outer git repo: foreign HEAD does not satisfy staleness
       check — stale artifacts still blocked.
    3. When artifacts carry the real current HEAD SHA, merge-gate proceeds to
       the LLM call (exits 0 with approve stub).
    4. CLAGENTIC_ALLOW_STALE_PAYLOAD=1 bypasses the check even in wrapper layout.

Run with:
    python3 -m unittest scripts/test_wrapper_staleness.py -v
"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _make_fake_llm_client(fake_tool_home, decision="approve", reason="test"):
    """Stub llm-client.sh that echoes a fixed JSON merge-gate decision."""
    scripts_dir = os.path.join(fake_tool_home, "scripts")
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
    return fake_tool_home


def _setup_fake_tool_home(fake_tool_home):
    """Symlink all real .sh scripts except llm-client.sh into the fake tool home."""
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")

    for fname in os.listdir(real_scripts_dir):
        if not fname.endswith(".sh"):
            continue
        if fname == "llm-client.sh":
            continue
        src = os.path.join(real_scripts_dir, fname)
        dst = os.path.join(scripts_dir, fname)
        if not os.path.exists(dst):
            os.symlink(src, dst)

    real_share = os.path.join(TOOL_HOME, "share")
    fake_share = os.path.join(fake_tool_home, "share")
    if not os.path.exists(fake_share) and os.path.isdir(real_share):
        os.symlink(real_share, fake_share)


def _init_git_repo(path):
    """Initialize a git repo at path and return the first commit SHA."""
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", path], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@example.com"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Test"],
                   check=True, capture_output=True)
    init_file = os.path.join(path, "init.txt")
    with open(init_file, "w") as f:
        f.write("initial\n")
    subprocess.run(["git", "-C", path, "add", "init.txt"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", path, "commit", "-m", "initial commit"],
                   check=True, capture_output=True)
    sha = subprocess.check_output(
        ["git", "-C", path, "rev-parse", "HEAD"],
        text=True
    ).strip()
    return sha


def _advance_repo(repo_path):
    """Add a new commit to advance HEAD; return the new SHA."""
    bump_file = os.path.join(repo_path, "bump.txt")
    with open(bump_file, "w") as f:
        f.write("bump\n")
    subprocess.run(["git", "-C", repo_path, "add", "bump.txt"], check=True,
                   capture_output=True)
    subprocess.run(["git", "-C", repo_path, "commit", "-m", "bump commit"],
                   check=True, capture_output=True)
    sha = subprocess.check_output(
        ["git", "-C", repo_path, "rev-parse", "HEAD"],
        text=True
    ).strip()
    return sha


def _stamp_artifacts(clagentic_lite_dir, sha):
    """Write last-review.json and last-adversarial.md stamped with sha."""
    review = {
        "findings": [],
        "summary": "clean",
        "_clagentic_diff_sha": sha,
    }
    with open(os.path.join(clagentic_lite_dir, "last-review.json"), "w") as f:
        json.dump(review, f)

    with open(os.path.join(clagentic_lite_dir, "last-adversarial.md"), "w") as f:
        f.write(f"<!-- clagentic-diff-sha: {sha} -->\n")
        f.write("No adversarial findings.\n")


def _setup_project_db(clagentic_lite_dir):
    """Initialize audit.db schema."""
    db_path = os.path.join(clagentic_lite_dir, "audit.db")
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
    return db_path


def _run_merge_gate(fake_tool_home, project_root, cwd, extra_env=None):
    """Run gates.sh merge-gate with cwd set to the given directory."""
    _setup_fake_tool_home(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")

    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    env["CLAGENTIC_MERGE_GATE_BLOCKING"] = "1"
    # Do NOT set CLAGENTIC_ALLOW_STALE_PAYLOAD — we want the check to run.
    env.pop("CLAGENTIC_ALLOW_STALE_PAYLOAD", None)
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        ["sh", fake_gates, "merge-gate"],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
    )
    return result


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestWrapperStaleness(unittest.TestCase):
    """Regression: stale gate artifacts caught even in wrapper/repo layouts."""

    def setUp(self):
        self._base = tempfile.mkdtemp(prefix="clagentic-wrap-test-")
        self._wrapper = os.path.join(self._base, "wrapper")
        self._repo = os.path.join(self._wrapper, "repo")
        os.makedirs(self._repo)

        # Initialize the enrolled git repo and get the first SHA.
        self._old_sha = _init_git_repo(self._repo)

        # Write .clagentic-project pointer in the wrapper directory.
        with open(os.path.join(self._wrapper, ".clagentic-project"), "w") as f:
            f.write(self._repo + "\n")

        # Set up .clagentic/lite/ inside the repo.
        self._lite_dir = os.path.join(self._repo, ".clagentic", "lite")
        os.makedirs(self._lite_dir, exist_ok=True)
        _setup_project_db(self._lite_dir)

        # Stamp artifacts with the OLD sha, then advance HEAD.
        _stamp_artifacts(self._lite_dir, self._old_sha)
        self._new_sha = _advance_repo(self._repo)

        # Confirm old_sha != new_sha (test would be vacuous otherwise).
        assert self._old_sha != self._new_sha, "SHA did not advance"

        # Build the fake tool home with the approve stub.
        self._fake_tool_home = os.path.join(self._base, "toolhome")
        _make_fake_llm_client(self._fake_tool_home)

    def tearDown(self):
        shutil.rmtree(self._base, ignore_errors=True)

    # ------------------------------------------------------------------ test 1
    def test_stale_blocked_from_wrapper_dir(self):
        """Stale artifacts are refused when cwd is the (non-git) wrapper directory.

        Before the fix, git rev-parse HEAD from the non-git wrapper dir returned
        empty, causing the entire staleness block to be skipped (fail-open).
        After the fix, _git uses REPO_ROOT, finds the new HEAD, and catches
        the mismatch.
        """
        result = _run_merge_gate(
            self._fake_tool_home,
            project_root=self._repo,
            cwd=self._wrapper,
        )

        # Must exit 1 (stale payload detected, merge-gate blocking=1).
        self.assertEqual(
            result.returncode, 1,
            f"Expected exit 1 (stale payload); got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )
        # The refusal output must mention stale.
        combined = result.stdout + result.stderr
        self.assertIn(
            "stale",
            combined.lower(),
            f"Expected 'stale' in output; got:\nstdout: {result.stdout}\nstderr: {result.stderr}",
        )

    # ------------------------------------------------------------------ test 2
    def test_stale_blocked_from_unrelated_outer_repo(self):
        """Stale artifacts are refused when cwd is an unrelated git repo.

        A foreign HEAD satisfies the old `if [ -n "$CURRENT_SHA" ]` guard
        (non-empty string), but the SHA itself belongs to a different repo and
        would never match the artifact stamp — so stale_payload must still fire.
        After the fix, _git targets REPO_ROOT, ignoring the outer repo entirely.
        """
        outer_repo = os.path.join(self._base, "outer")
        _init_git_repo(outer_repo)
        # Advance outer repo too, so its HEAD is fresh and distinct.
        _advance_repo(outer_repo)

        result = _run_merge_gate(
            self._fake_tool_home,
            project_root=self._repo,
            cwd=outer_repo,
        )

        self.assertEqual(
            result.returncode, 1,
            f"Expected exit 1 (stale payload from outer repo cwd); got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )
        combined = result.stdout + result.stderr
        self.assertIn(
            "stale",
            combined.lower(),
            f"Expected 'stale' in output; got:\nstdout: {result.stdout}\nstderr: {result.stderr}",
        )

    # ------------------------------------------------------------------ test 3
    def test_fresh_artifacts_pass(self):
        """Artifacts stamped with the current HEAD SHA pass the staleness check."""
        # Re-stamp artifacts with the new (current) SHA.
        _stamp_artifacts(self._lite_dir, self._new_sha)

        result = _run_merge_gate(
            self._fake_tool_home,
            project_root=self._repo,
            cwd=self._wrapper,
        )

        self.assertEqual(
            result.returncode, 0,
            f"Expected exit 0 (fresh artifacts, approve stub); got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )

    # ------------------------------------------------------------------ test 4
    def test_allow_stale_payload_bypass(self):
        """CLAGENTIC_ALLOW_STALE_PAYLOAD=1 bypasses staleness even in wrapper layout."""
        result = _run_merge_gate(
            self._fake_tool_home,
            project_root=self._repo,
            cwd=self._wrapper,
            extra_env={"CLAGENTIC_ALLOW_STALE_PAYLOAD": "1"},
        )

        self.assertEqual(
            result.returncode, 0,
            f"Expected exit 0 (bypass via CLAGENTIC_ALLOW_STALE_PAYLOAD=1); got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
