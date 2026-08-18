"""
Regression coverage for the class-4 foundry fix, mitigation (a): num_turns
(already present in the --output-format json envelope, previously discarded
during unwrap) must be logged into the llm-call audit row for EVERY
successful claude json-mode call, not just a failing one -- a reviewer
riding close to its turn ceiling on every PASSING run must be visible in
`gates.sh digest`/`gates.sh status` before it ever tips over into a
turns-exhausted failure (test_walk_chain_turns_exhausted.py covers that
failure path separately).

These tests source the ACTUAL sh functions via `sh -c`, with a real
.clagentic/lite/audit.db so ds_audit_log (platform.sh) actually writes a
row, then query that row back with sqlite3 -- proving the real production
call path, not a mock of log_attempt.

Run with: python3 -m unittest scripts.test_num_turns_audit_logging -v
"""
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

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _write_success_claude(bin_dir, num_turns):
    path = os.path.join(bin_dir, "claude")
    inner = json.dumps({"summary": "clean diff", "checked": ["security"], "findings": []})
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "num_turns": num_turns,
        "duration_ms": 3000,
        "is_error": False,
        "result": inner,
    })
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            cat <<'ENVELOPE'
{envelope}
ENVELOPE
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _init_bare_repo(tmp):
    """A minimal real git repo so ds_repo_root/CLAGENTIC_PROJECT_ROOT
    resolution and ds_audit_log's own repo-root lookup both succeed."""
    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    with open(os.path.join(repo, "README"), "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "README"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True, env=env)
    return repo


def _make_audit_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE gate_runs "
        "(ts TEXT, gate TEXT, outcome TEXT, details TEXT, session_id TEXT);"
    )
    conn.commit()
    conn.close()


class TestNumTurnsLoggedOnSuccessfulReviewerCall(unittest.TestCase):
    """The core contract: a successful (subtype=='success') reviewer call
    writes num_turns into its llm-call audit row's details field."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-numturns-")
        self._repo = _init_bare_repo(self._tmpdir)
        clagentic_dir = os.path.join(self._repo, ".clagentic", "lite")
        os.makedirs(clagentic_dir)
        self._audit_db = os.path.join(clagentic_dir, "audit.db")
        _make_audit_db(self._audit_db)

        self._bin_dir = os.path.join(self._tmpdir, "bin")
        os.makedirs(self._bin_dir)
        _write_success_claude(self._bin_dir, num_turns=9)

        self._sourced = LLM_CLIENT_SH

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_walk_chain(self):
        script = textwrap.dedent(f"""\
            export PATH='{self._bin_dir}':"$PATH"
            export CLAGENTIC_PROJECT_ROOT='{self._repo}'
            export CLAGENTIC_REVIEWER_CMD=claude
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{self._sourced}'
            printf 'stdin diff content' | walk_chain reviewer json _fixture_prompt
        """)
        # cwd MUST be self._repo, not TOOL_HOME: ds_audit_log (platform.sh)
        # resolves its target DB via ds_repo_root, which prefers
        # `git rev-parse --show-toplevel` of the CURRENT WORKING DIRECTORY
        # over CLAGENTIC_PROJECT_ROOT entirely (that env var is a
        # gates.sh/llm-client.sh-level convention for THEIR OWN repo-root
        # resolution, not one platform.sh's ds_repo_root reads) -- running
        # from TOOL_HOME would silently write (or fail to write, if
        # TOOL_HOME is not a git repo boundary matching self._repo) to the
        # wrong audit.db.
        env = os.environ.copy()
        env.update(source_env(llm_client=True))
        return subprocess.run(
            ["sh", "-c", script, self._sourced],
            capture_output=True, text=True, cwd=self._repo, env=env,
        )

    def test_num_turns_appears_in_the_llm_call_audit_row(self):
        result = self._run_walk_chain()
        self.assertEqual(
            result.returncode, 0,
            f"walk_chain failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        conn = sqlite3.connect(self._audit_db)
        rows = conn.execute(
            "SELECT outcome, details FROM gate_runs WHERE gate='llm-call' ORDER BY rowid;"
        ).fetchall()
        conn.close()
        self.assertTrue(rows, "no llm-call audit rows were written at all")
        pass_rows = [r for r in rows if r[0] == "pass"]
        self.assertTrue(
            pass_rows,
            f"no 'pass' outcome row found -- rows={rows!r}",
        )
        self.assertTrue(
            any("num_turns=9" in details for _, details in pass_rows),
            f"expected 'num_turns=9' in the pass row's details -- rows={rows!r}",
        )


if __name__ == "__main__":
    unittest.main()
