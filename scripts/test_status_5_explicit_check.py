"""
Regression coverage for lr-49df97 (fold-in, HOLDEN "also verify" item):
memory.sh's cmd_summarize_turn and both former .claude/hooks/ summarize
consumers (stop-summarize.sh, post-tool-nudge.sh; source of truth now
share/hook-shims/*.sh.template, lr-57db23 -- see AGENTS.md INV-7) only
ever tested `-eq 3` for walk_chain's degraded exit status, relying on the
cause-agnostic "[clagentic-lite degraded]" text-marker grep to also catch
status 4 ("unwrap") and 5 ("turns-exhausted") by ACCIDENT -- emit_degraded's
line-mode banner text happens to be the same regardless of cause, but
nothing in the status check itself recognized 4 or 5 as degraded outcomes.

THE PROOF THIS FILE ADDS: a fake `llm-client.sh` that exits 5 (or 4) but
emits a payload carrying NO "[clagentic-lite degraded]" substring at all --
isolating whether each consumer's STATUS CHECK alone (not the text-marker
grep as a fallback) recognizes the outcome as degraded. Before the fix
these tests target, a status-5 exit with non-marker-text output would have
been silently treated as a real summary and written to memory -- exactly
the "next new exit code will not be so lucky" risk HOLDEN named.

Run with: python3 -m unittest scripts.test_status_5_explicit_check -v
"""
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MEMORY_SH = os.path.join(TOOL_HOME, "scripts", "memory.sh")
STOP_SUMMARIZE_HOOK = os.path.join(
    TOOL_HOME, "share", "hook-shims", "stop-summarize.sh.template"
)


def _init_scratch_repo(repo_dir):
    subprocess.run(["git", "init", "-q", repo_dir], check=True)
    subprocess.run(
        ["git", "-C", repo_dir, "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(["git", "-C", repo_dir, "config", "user.name", "test"], check=True)


def _write_fake_llm_client_no_marker_text(path, exit_status):
    """A fake llm-client.sh that exits with the given status but writes a
    payload containing NO "[clagentic-lite degraded]" substring at all --
    the discriminating fixture: if a consumer's explicit status check is
    what catches this (not the text-marker grep, which would find nothing
    here), row_count stays 0. If the consumer only ever worked by accident
    via the text marker, this fixture proves it by making the marker
    absent."""
    with open(path, "w") as f:
        f.write(
            "#!/bin/sh\n"
            "cat > /dev/null\n"
            "printf 'partial output with no marker text at all'\n"
            f"exit {exit_status}\n"
        )
    os.chmod(path, 0o755)


class TestMemoryShExplicitlyChecksStatus5(unittest.TestCase):
    """memory.sh cmd_summarize_turn must reject a status-5 payload even
    when the payload text does not contain the degraded banner string."""

    def _run(self, exit_status):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-status5-memsh-")
        try:
            repo_dir = os.path.join(tmpdir, "repo")
            os.makedirs(repo_dir)
            _init_scratch_repo(repo_dir)

            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            # memory.sh invokes "$TOOL_HOME/scripts/llm-client.sh" by
            # absolute path (TOOL_HOME resolved from memory.sh's own
            # location) -- point CLAGENTIC_LITE_HOME-independent TOOL_HOME
            # resolution at a scratch scripts/ dir carrying our fake.
            fake_home = os.path.join(tmpdir, "fake-tool-home")
            fake_scripts = os.path.join(fake_home, "scripts")
            os.makedirs(fake_scripts)
            shutil.copy(MEMORY_SH, fake_scripts)
            shutil.copy(os.path.join(TOOL_HOME, "scripts", "platform.sh"), fake_scripts)
            os.chmod(os.path.join(fake_scripts, "memory.sh"), 0o755)
            fake_llm_client = os.path.join(fake_scripts, "llm-client.sh")
            _write_fake_llm_client_no_marker_text(fake_llm_client, exit_status)

            env = dict(os.environ)
            env["CLAGENTIC_PROJECT_ROOT"] = repo_dir
            env["CLAGENTIC_LITE_HOME"] = fake_home

            r = subprocess.run(
                ["sh", os.path.join(fake_scripts, "memory.sh"), "summarize-turn"],
                input="assistant turn text",
                capture_output=True,
                text=True,
                cwd=repo_dir,
                env=env,
            )

            db_path = os.path.join(repo_dir, ".clagentic", "lite", "memory.db")
            summaries = []
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                try:
                    summaries = [row[0] for row in conn.execute("SELECT summary FROM turns").fetchall()]
                except sqlite3.OperationalError:
                    pass
                finally:
                    conn.close()
            return r.returncode, r.stdout, r.stderr, summaries
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_status_5_with_no_marker_text_writes_no_row(self):
        rc, out, err, summaries = self._run(5)
        self.assertEqual(
            summaries, [],
            f"status 5 (turns-exhausted) with NO degraded-marker text in "
            f"the payload must still be rejected by the explicit -eq 5 "
            f"check -- if this fails, memory.sh only ever caught status 5 "
            f"by accident via the text-marker grep. summaries={summaries!r} "
            f"stdout={out!r} stderr={err!r}",
        )

    def test_status_4_with_no_marker_text_writes_no_row(self):
        rc, out, err, summaries = self._run(4)
        self.assertEqual(
            summaries, [],
            f"status 4 (unwrap) with NO degraded-marker text in the "
            f"payload must still be rejected by the explicit -eq 4 check. "
            f"summaries={summaries!r} stdout={out!r} stderr={err!r}",
        )

    def test_status_5_surfaces_on_stderr(self):
        rc, out, err, summaries = self._run(5)
        self.assertIn(
            "degraded", err.lower(),
            f"a status-5 rejection must be visible on stderr. stderr={err!r}",
        )


class TestStopSummarizeHookExplicitlyChecksStatus5(unittest.TestCase):
    """Same proof against the real stop-summarize.sh (source of truth
    share/hook-shims/stop-summarize.sh.template, lr-57db23), which invokes
    llm-client.sh via a relative REPO_ROOT-scoped path rather than
    memory.sh's TOOL_HOME resolution."""

    def _run(self, exit_status):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-status5-hook-")
        try:
            repo_dir = os.path.join(tmpdir, "repo")
            os.makedirs(repo_dir)
            _init_scratch_repo(repo_dir)

            scripts_dir = os.path.join(repo_dir, "scripts")
            os.makedirs(scripts_dir)
            for fname in ("memory.sh", "platform.sh"):
                shutil.copy(os.path.join(TOOL_HOME, "scripts", fname), scripts_dir)
                os.chmod(os.path.join(scripts_dir, fname), 0o755)
            fake_llm_client = os.path.join(scripts_dir, "llm-client.sh")
            _write_fake_llm_client_no_marker_text(fake_llm_client, exit_status)

            clagentic_dir = os.path.join(repo_dir, ".clagentic", "lite")
            os.makedirs(clagentic_dir, exist_ok=True)
            audit_db = os.path.join(clagentic_dir, "audit.db")
            conn = sqlite3.connect(audit_db)
            conn.execute(
                "CREATE TABLE gate_runs (ts TEXT, gate TEXT, outcome TEXT, details TEXT, session_id TEXT);"
            )
            conn.commit()
            conn.close()

            transcript = os.path.join(tmpdir, "transcript.jsonl")
            with open(transcript, "w") as f:
                f.write(json.dumps({"role": "assistant", "content": "the assistant's last turn"}) + "\n")

            session_id = f"sess-status{exit_status}"
            payload = {
                "session_id": session_id,
                "transcript_path": transcript,
                "stop_hook_active": False,
            }
            env = dict(os.environ)
            env["CLAGENTIC_ENV_LOADED"] = "1"
            env["CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC"] = "0"
            env["CLAGENTIC_DISABLE_HANDOFF"] = "1"
            # This fixture's own scripts/platform.sh (copied above) is what
            # the hook should source -- points CLAGENTIC_LITE_HOME at the
            # fake repo, not the real checkout.
            env["CLAGENTIC_LITE_HOME"] = repo_dir
            env.pop("GIT_DIR", None)
            env.pop("GIT_WORK_TREE", None)

            hook_proc = subprocess.run(
                ["sh", STOP_SUMMARIZE_HOOK],
                input=json.dumps(payload).encode(),
                capture_output=True,
                env=env,
                cwd=repo_dir,
            )
            # A "cannot open <hook path>: No such file" here would otherwise
            # be silently indistinguishable from a real, clean skip -- both
            # produce zero audit rows and zero summaries. Fail loudly on a
            # missing/broken hook script rather than letting the assertions
            # below pass vacuously for the wrong reason.
            assert not hook_proc.stderr or b"No such file" not in hook_proc.stderr, (
                f"stop-summarize.sh.template failed to run: {hook_proc.stderr!r}"
            )

            def _audit_rows():
                conn = sqlite3.connect(audit_db)
                rows = conn.execute(
                    "SELECT gate, outcome, details FROM gate_runs WHERE session_id=?;",
                    (session_id,),
                ).fetchall()
                conn.close()
                return rows

            deadline = time.time() + 5
            rows = _audit_rows()
            while not rows and time.time() < deadline:
                time.sleep(0.05)
                rows = _audit_rows()

            memory_db = os.path.join(clagentic_dir, "memory.db")
            summaries = []
            if os.path.exists(memory_db):
                conn = sqlite3.connect(memory_db)
                try:
                    summaries = [r[0] for r in conn.execute("SELECT summary FROM turns").fetchall()]
                except sqlite3.OperationalError:
                    pass
                finally:
                    conn.close()
            return rows, summaries
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_status_5_with_no_marker_text_writes_no_row(self):
        rows, summaries = self._run(5)
        self.assertEqual(
            summaries, [],
            f"stop-summarize.sh must reject a status-5 payload with no "
            f"marker text via its explicit -eq 5 check. summaries={summaries!r} "
            f"audit rows={rows!r}",
        )

    def test_status_5_does_not_log_audit_pass(self):
        rows, summaries = self._run(5)
        outcomes = [r[1] for r in rows if r[0] == "summarize"]
        self.assertNotIn("pass", outcomes, f"rows={rows!r}")


if __name__ == "__main__":
    unittest.main()
