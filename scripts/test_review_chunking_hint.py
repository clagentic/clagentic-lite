"""
Regression tests for lr-e33f73 item 5: cmd_review's oversized-diff hint
(scripts/gates.sh, ~line 3363-3377) must name CLAGENTIC_REVIEW_CHUNKING
explicitly, in both the not-yet-enabled and already-enabled cases -- the
exact variable the field incident behind this task needed and never saw.

PEACHES PR #193 review, finding 2: this conditional was previously
untested. This file drives the REAL cmd_review (via `sh gates.sh review`)
against a throwaway, remoteless git repo with a staged diff sized to cross
CLAGENTIC_REVIEW_CHUNK_BYTES, and a stub llm-client.sh so no real LLM/
network call ever happens -- reusing test_review_ledger.py's own harness
functions (_init_git_repo_no_remote, _stage_file, _setup_fake_tool_home,
_make_stub_llm_client) rather than inventing a parallel one.

The hint block itself (gates.sh get_review_diff -> cmd_review's diff-size
check) executes purely from git + arithmetic, before any LLM call -- see
get_review_diff's own doc comment and cmd_review's call order. Only the
staged-diff path is needed here (get_review_diff's highest-priority path),
so no remote, ledger state, or branch-diff fallback is required.

Run with: python3 -m unittest scripts.test_review_chunking_hint -v
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

_GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Small threshold so the staged diff (well under a real 256KB default) can
# cross it deterministically and quickly, without writing an enormous fixture
# file. cmd_review reads this from CLAGENTIC_REVIEW_CHUNK_BYTES (bytes alias),
# so this is exercising the real threshold-comparison code, not a fake one.
_CHUNK_BYTES_THRESHOLD = 2048


def _git(args, cwd):
    e = os.environ.copy()
    e.update(_GIT_IDENTITY_ENV)
    return subprocess.run(["git"] + args, cwd=cwd, env=e, check=True,
                           capture_output=True, text=True)


def _init_git_repo_no_remote(project_root):
    _git(["init", "-q", "-b", "main", project_root], cwd=None)
    with open(os.path.join(project_root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    _git(["add", "app.py"], cwd=project_root)
    _git(["commit", "-q", "-m", "seed"], cwd=project_root)
    _git(["checkout", "-q", "-b", "feat/example"], cwd=project_root)


def _stage_large_diff(project_root, name, approx_bytes):
    """Stage a file large enough that its diff crosses _CHUNK_BYTES_THRESHOLD.
    get_review_diff's highest-priority path (git diff --cached) fires on a
    staged change with zero prior ledger state and no remote."""
    path = os.path.join(project_root, name)
    with open(path, "w") as f:
        # Each line ~20 bytes; comfortably exceeds approx_bytes once diffed
        # (unified diff adds a '+' + context per line, so actual diff bytes
        # are larger than the raw file, not smaller).
        line_count = (approx_bytes // 20) + 50
        for i in range(line_count):
            f.write("x = %d  # padding line\n" % i)
    _git(["add", name], cwd=project_root)


def _setup_project(tmpdir):
    clagentic_dir = os.path.join(tmpdir, ".clagentic", "lite")
    os.makedirs(clagentic_dir, exist_ok=True)
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


def _setup_fake_tool_home(fake_tool_home):
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
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


def _make_stub_llm_client(fake_tool_home):
    """Fast, deterministic stub -- always returns one clean envelope. cmd_review
    reaches this only AFTER the hint block prints, so the hint's own text is
    already on stderr regardless of what this stub returns."""
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    payload = json.dumps({"summary": "clean", "checked": [], "findings": []})
    with open(stub, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            cat >/dev/null
            printf '%s\\n' '{payload}'
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def _run_review(fake_tool_home, project_root, env_overrides=None):
    _setup_fake_tool_home(fake_tool_home)
    _make_stub_llm_client(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    env["CLAGENTIC_REVIEW_CHUNK_BYTES"] = str(_CHUNK_BYTES_THRESHOLD)
    if env_overrides:
        env.update(env_overrides)
    cmd = ["sh", fake_gates, "review"]
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                           cwd=project_root, timeout=60)


class _ChunkingHintTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-review-chunk-hint-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.project = os.path.join(self.tmpdir, "project")
        os.makedirs(self.project)
        _init_git_repo_no_remote(self.project)
        _setup_project(self.project)
        _stage_large_diff(self.project, "big.py", _CHUNK_BYTES_THRESHOLD * 2)
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")


class TestChunkingOffNamesTheOptIn(_ChunkingHintTestBase):
    def test_hint_names_variable_and_how_to_enable_it(self):
        """The not-yet-enabled case -- the exact shape of the field incident:
        an oversized diff, CLAGENTIC_REVIEW_CHUNKING unset, and the operator
        needs to be told the variable name and that setting it helps."""
        r = _run_review(self.fake_tool_home, self.project,
                         env_overrides={"CLAGENTIC_REVIEW_CHUNKING": "0"})
        self.assertIn("CLAGENTIC_REVIEW_CHUNKING=1", r.stderr, msg=r.stderr)
        self.assertIn("diff is", r.stderr, msg=r.stderr)
        self.assertNotIn("chunked review will be used", r.stderr, msg=r.stderr)

    def test_hint_fires_when_var_unset_entirely(self):
        """Same as above but CLAGENTIC_REVIEW_CHUNKING is absent from the
        environment altogether (the realistic case for an install whose
        config predates this key), not just explicitly set to 0."""
        env = os.environ.copy()
        r = _run_review(self.fake_tool_home, self.project)
        self.assertIn("CLAGENTIC_REVIEW_CHUNKING=1", r.stderr, msg=r.stderr)


class TestChunkingOnConfirmsItWillBeUsed(_ChunkingHintTestBase):
    def test_hint_confirms_chunking_will_be_used(self):
        """The already-enabled case -- must not repeat the "set this" advice
        (the operator already has), and must confirm chunking will actually
        be used for this oversized diff."""
        r = _run_review(self.fake_tool_home, self.project,
                         env_overrides={"CLAGENTIC_REVIEW_CHUNKING": "1"})
        self.assertIn("chunked review will be used (CLAGENTIC_REVIEW_CHUNKING=1)",
                       r.stderr, msg=r.stderr)
        self.assertNotIn("set CLAGENTIC_REVIEW_CHUNKING=1 in your global config",
                          r.stderr, msg=r.stderr)


class TestNoHintUnderThreshold(unittest.TestCase):
    """Negative control: a small diff, well under the threshold, must not
    print the hint at all -- proves the hint is genuinely conditional on
    diff size, not unconditional noise on every review run."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-review-chunk-hint-neg-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.project = os.path.join(self.tmpdir, "project")
        os.makedirs(self.project)
        _init_git_repo_no_remote(self.project)
        _setup_project(self.project)
        # Small, well under _CHUNK_BYTES_THRESHOLD.
        path = os.path.join(self.project, "small.py")
        with open(path, "w") as f:
            f.write("x = 1\n")
        _git(["add", "small.py"], cwd=self.project)
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")

    def test_small_diff_prints_no_chunking_hint(self):
        r = _run_review(self.fake_tool_home, self.project,
                         env_overrides={"CLAGENTIC_REVIEW_CHUNKING": "0"})
        self.assertNotIn("CLAGENTIC_REVIEW_CHUNKING", r.stderr, msg=r.stderr)


if __name__ == "__main__":
    unittest.main()
