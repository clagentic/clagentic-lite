"""Regression test (lr-b56a03): memory.sh's cmd_init self-heals a desynced
external-content FTS5 index instead of leaving it to raise SQLITE_CORRUPT on
a later write.

Background: memory.sh creates turns_fts as an external-content FTS5 table
(content=turns, content_rowid=id) kept in sync only via AFTER INSERT/DELETE/
UPDATE triggers on `turns`. Any out-of-band write to the FTS5 shadow tables
(or an interrupted trigger) desyncs the index without changing its row
count, so the old empty-only backfill in cmd_init could never detect or
repair it. Once desynced, a later external-content write raises
SQLITE_CORRUPT (result code 11), and that raw SQLite result code was
observed propagating verbatim as smoke.sh's own exit code under `set -e`
(scripts/smoke.sh step 11), with no message identifying the real cause.

This test deliberately desyncs a real memory.db by deleting one FTS5 leaf
segment block (scripts/memory.sh's turns_fts_data shadow table) directly,
confirms the desync is real via FTS5's own 'integrity-check' command, then
confirms a subsequent memory.sh call self-heals it (cmd_init's
integrity-check + rebuild) and that integrity-check passes cleanly
afterward.

Uses a throwaway CLAGENTIC_PROJECT_ROOT tempdir per the ENVIRONMENT HAZARD
note in lr-25ce17 -- never the live checkout.
"""
import os
import shutil
import sqlite3
import subprocess
import tempfile

TOOL_HOME = "/workspace/clagentic-lite"


def test_fts5_desync_self_heals_on_next_write():
    tmpdir = tempfile.mkdtemp(prefix="amos-lr56a03-fts5-")
    try:
        subprocess.run(["git", "init", tmpdir], check=True, capture_output=True)
        env = dict(os.environ)
        env["CLAGENTIC_PROJECT_ROOT"] = tmpdir

        # Seed a few real turns through memory.sh so the FTS5 index and
        # triggers are genuinely populated (not just schema-created).
        for i in range(3):
            subprocess.run(
                [f"{TOOL_HOME}/scripts/memory.sh", "log-turn", f"demo row {i}", "demo", "seed"],
                env=env, check=True, capture_output=True,
            )

        db_path = os.path.join(tmpdir, ".clagentic", "lite", "memory.db")
        assert os.path.isfile(db_path)

        # Deliberately desync the FTS5 shadow index from `turns`: delete a
        # b-tree LEAF segment block from the FTS5 module's own internal
        # shadow table (turns_fts_data) directly, bypassing the trigger
        # entirely. turns_fts_data holds both small internal bookkeeping
        # rows (id=1: structure; id=10: per-column-average record) and the
        # actual leaf segment blocks (large ids, one per ~4KB segment of
        # indexed token data) -- deleting a LEAF block (id > 10) removes
        # real indexed content without breaking vtable construction (unlike
        # deleting id=1 or id=10, which breaks vtable construction itself
        # and is unrecoverable in-place -- that path produces the exact
        # SQLITE_CORRUPT result code 11 this bug surfaced, and is now
        # reported loudly by cmd_log_turn instead of propagating raw).
        con = sqlite3.connect(db_path)
        con.execute("DELETE FROM turns_fts_data WHERE id > 10;")
        con.commit()
        con.close()

        # Confirm the desync is real: integrity-check must now report a problem.
        con = sqlite3.connect(db_path)
        desynced = False
        try:
            con.execute("INSERT INTO turns_fts(turns_fts) VALUES('integrity-check');")
            con.commit()
        except sqlite3.DatabaseError:
            desynced = True
        con.close()
        assert desynced, "expected the manual shadow-table delete to desync the FTS5 index"

        # The next memory.sh call runs cmd_init first, which now runs an
        # integrity-check + rebuild -- this is the self-healing path under test.
        result = subprocess.run(
            [f"{TOOL_HOME}/scripts/memory.sh", "log-turn", "post-repair row", "demo", "seed"],
            env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, f"log-turn failed after repair attempt: {result.stderr}"

        # Integrity-check must now pass cleanly -- the index was rebuilt.
        con = sqlite3.connect(db_path)
        con.execute("INSERT INTO turns_fts(turns_fts) VALUES('integrity-check');")
        con.commit()
        con.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
