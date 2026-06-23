"""Tests for FTS5 recall path in scripts/memory.sh.

Exercises the FTS5 schema creation, trigger-driven index updates, backfill,
CLAGENTIC_DISABLE_FTS opt-out, and the LIKE fallback path by invoking
memory.sh via subprocess against a temporary DB.

Does NOT test BM25 rank ordering — the implementation intentionally orders
by (source='manual') DESC, ts DESC only, never by rank. (AGENTS.md bright-line,
hc-2026-06-01-litemem, tome #552.)
"""
import os
import subprocess
import sqlite3
import tempfile
import unittest


MEMORY_SH = os.path.join(os.path.dirname(__file__), "memory.sh")


def _run(args, env=None, capture=True):
    """Run memory.sh with given arg list, return (returncode, stdout, stderr)."""
    base_env = os.environ.copy()
    base_env.pop("CLAGENTIC_PROJECT_ROOT", None)
    if env:
        base_env.update(env)
    result = subprocess.run(
        ["sh", MEMORY_SH] + args,
        capture_output=capture,
        text=True,
        env=base_env,
    )
    return result.returncode, result.stdout, result.stderr


class TestFTS5Schema(unittest.TestCase):
    """FTS5 virtual table, triggers, and backfill created by cmd_init."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-")
        self._db = os.path.join(self._tmpdir, "memory.db")
        # Create the .clagentic/lite path structure memory.sh expects
        os.makedirs(os.path.join(self._tmpdir, ".clagentic", "lite"), exist_ok=True)
        # Point memory.sh at our temp dir
        self._env = {
            "CLAGENTIC_PROJECT_ROOT": self._tmpdir,
            "CLAGENTIC_DISABLE_FTS": "0",
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _db_path(self):
        return os.path.join(self._tmpdir, ".clagentic", "lite", "memory.db")

    def _tables(self):
        conn = sqlite3.connect(self._db_path())
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','trigger') ORDER BY name"
        )
        names = {row[0] for row in cur.fetchall()}
        conn.close()
        return names

    def test_init_creates_fts5_table(self):
        rc, out, err = _run(["init"], env=self._env)
        self.assertEqual(rc, 0, err)
        tables = self._tables()
        # turns_fts should exist on any SQLite with FTS5 (practically all)
        self.assertIn("turns_fts", tables, "turns_fts virtual table missing")
        self.assertIn("turns_fts_insert", tables, "insert trigger missing")
        self.assertIn("turns_fts_delete", tables, "delete trigger missing")
        self.assertIn("turns_fts_update", tables, "update trigger missing")

    def test_disable_fts_skips_virtual_table(self):
        env = dict(self._env)
        env["CLAGENTIC_DISABLE_FTS"] = "1"
        rc, out, err = _run(["init"], env=env)
        self.assertEqual(rc, 0, err)
        tables = self._tables()
        self.assertNotIn("turns_fts", tables, "turns_fts should not exist when DISABLE_FTS=1")

    def test_backfill_on_first_init(self):
        """Pre-existing turns are backfilled into turns_fts on first init."""
        # Manually create turns table with a row, then init with FTS
        db_path = self._db_path()
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE turns (id INTEGER PRIMARY KEY, ts TEXT NOT NULL,"
            " session_id TEXT NOT NULL DEFAULT 'unknown', branch TEXT,"
            " summary TEXT NOT NULL, tags TEXT, source TEXT)"
        )
        conn.execute(
            "INSERT INTO turns (ts, summary, tags, source) "
            "VALUES ('2026-01-01T00:00:00Z', 'auth refactor split login', 'auth', 'seed')"
        )
        conn.commit()
        conn.close()

        rc, out, err = _run(["init"], env=self._env)
        self.assertEqual(rc, 0, err)

        conn = sqlite3.connect(db_path)
        fts_count = conn.execute("SELECT COUNT(*) FROM turns_fts").fetchone()[0]
        conn.close()
        self.assertEqual(fts_count, 1, "backfill should have inserted 1 row into turns_fts")


class TestFTS5Recall(unittest.TestCase):
    """cmd_recall uses FTS5 MATCH when available and falls back to LIKE."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-")
        os.makedirs(os.path.join(self._tmpdir, ".clagentic", "lite"), exist_ok=True)
        self._env = {
            "CLAGENTIC_PROJECT_ROOT": self._tmpdir,
            "CLAGENTIC_DISABLE_FTS": "0",
        }
        # Seed with two rows via log-turn
        _run(["log-turn", "auth refactor split login module", "auth refactor", "seed"],
             env=self._env)
        _run(["log-turn", "database migration schema update", "db migration", "seed"],
             env=self._env)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_fts5_recall_finds_match(self):
        rc, out, err = _run(["recall", "auth"], env=self._env)
        self.assertEqual(rc, 0, err)
        self.assertIn("auth", out, "FTS5 recall should return auth row")

    def test_fts5_recall_no_match(self):
        rc, out, err = _run(["recall", "zxqjklmno"], env=self._env)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "", "No match should return empty output")

    def test_like_fallback_recall(self):
        env = dict(self._env)
        env["CLAGENTIC_DISABLE_FTS"] = "1"
        rc, out, err = _run(["recall", "database"], env=env)
        self.assertEqual(rc, 0, err)
        self.assertIn("database", out, "LIKE fallback should find database row")

    def test_fts5_multi_keyword_or(self):
        """Multiple keywords use OR semantics — each independently matches."""
        rc, out, err = _run(["recall", "auth", "migration"], env=self._env)
        self.assertEqual(rc, 0, err)
        # Both rows should appear since keywords match independently
        self.assertIn("auth", out)
        self.assertIn("migration", out)

    def test_order_is_recency_not_rank(self):
        """ORDER BY is ts DESC only — not BM25 rank. Verify results contain
        all auth-matching rows and no rank column influences output.
        (Bright-line compliance: AGENTS.md hc-2026-06-01-litemem, tome #552.)"""
        # Insert a third row that clearly matches "auth" too
        _run(["log-turn", "auth session handling review", "auth", "seed"],
             env=self._env)
        rc, out, err = _run(["recall", "auth"], env=self._env)
        self.assertEqual(rc, 0, err)
        lines = [l for l in out.splitlines() if l.strip()]
        # Both auth rows should appear
        self.assertTrue(len(lines) >= 2, "Expected at least two auth results")
        combined = "\n".join(lines)
        self.assertIn("auth refactor", combined)
        self.assertIn("session", combined)
        # Confirm no BM25 rank column leaked into output (no numeric score prefix)
        for line in lines:
            # Lines are: "ts | display-text"; no rank number should appear before ts
            self.assertRegex(line, r"^\d{4}-\d{2}-\d{2}", "line should start with ISO ts")

    def test_no_keywords_returns_all_recent(self):
        """Empty keyword recall returns most recent rows without FTS filtering."""
        rc, out, err = _run(["recall"], env=self._env)
        self.assertEqual(rc, 0, err)
        self.assertIn("auth", out)
        self.assertIn("database", out)

    def test_trigger_keeps_fts_in_sync(self):
        """After log-turn, new row is immediately findable via FTS MATCH."""
        _run(["log-turn", "xyzzy unique term added now", "xyzzy", "seed"],
             env=self._env)
        rc, out, err = _run(["recall", "xyzzy"], env=self._env)
        self.assertEqual(rc, 0, err)
        self.assertIn("xyzzy", out, "Insert trigger should have synced new row to FTS")


if __name__ == "__main__":
    unittest.main()
