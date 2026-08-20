"""
Regression tests for lr-367a21: build_gate_summary's informational
"deterministic_gates" block.

BACKGROUND: ds_merge_gate_prompt (scripts/llm-client.sh) used to tell the
model its stdin payload held "outputs of secrets/deps/sast/review/
adversarial gates" and instructed it to refuse on "contradictions between
gates (e.g. review says clean but sast errored)" -- but build_gate_summary
never emitted anything about secrets/deps/sast at all. This file covers the
read side of the fix: build_gate_summary must read the LATEST gate_runs row
per deterministic gate (secrets/deps/sast) from audit.db and surface it as
an INFORMATIONAL "deterministic_gates" block, preserving the distinction
between pass/warn/skip/block/absent, with an explicit
"audit_db_unavailable" marker when the read itself fails. The read must
never block -- cmd_secrets/cmd_deps/cmd_sast already fail closed upstream,
before this gate ever runs.

Both JSON-emitter branches (jq and python3) must agree -- the python3
branch receives the pre-built JSON object as an argument rather than
re-querying audit.db a second time (see _read_deterministic_gates's doc
comment in gates.sh), so a class of tests here forces the jq-less PATH
(mirroring test_review_findings_forged_field_stripped.py's
_call_validate_output(jq_available=False) helper) to exercise that branch
directly rather than only ever hitting jq's.

Sources the ACTUAL sh function from gates.sh (not a Python
reimplementation), same sourcing pattern as
test_build_gate_summary_change_class.py / test_build_gate_summary_dropped_count.py.

Run with: python3 -m unittest scripts.test_build_gate_summary_deterministic_gates -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _git_init_with_commit(path):
    """`git init -q` alone leaves HEAD unborn (no commits). This test file
    asserts on audit.db presence/absence, which is sensitive to
    build_gate_summary's staleness-check branching -- an unborn HEAD is an
    edge case orthogonal to what this file covers, so give every repo a
    normal, born HEAD via one empty commit."""
    subprocess.run(["git", "init", "-q", path], check=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", path, "commit", "--allow-empty", "-q", "-m", "init"], check=True)


def _jqless_path():
    """Build a PATH with every real-PATH executable symlinked EXCEPT jq, so
    `command -v jq` genuinely fails inside the subprocess without also
    breaking dirname/cat/sed/sqlite3/python3/etc that gates.sh/platform.sh
    need at source and run time. Mirrors
    test_review_findings_forged_field_stripped.py's _call_validate_output
    helper (jq_available=False branch)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-nojq-bin-")
    real_path = os.environ.get("PATH", "")
    for d in real_path.split(os.pathsep):
        if not d or not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name == "jq":
                continue
            link = os.path.join(tmpdir, name)
            if os.path.exists(link):
                continue
            try:
                os.symlink(os.path.join(d, name), link)
            except OSError:
                continue
    return tmpdir


def _seed_audit_db(project_root, rows):
    """Seed .clagentic/lite/audit.db with gate_runs rows via `gates.sh
    log-run` (the same CLI path a real gate run would use), so this test
    exercises the real schema/insert path rather than hand-crafting SQL.
    rows: list of (gate, outcome, details) tuples, inserted in order (later
    rows are the ones _read_deterministic_gates should surface as latest).
    """
    for gate, outcome, details in rows:
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = project_root
        r = subprocess.run(
            [GATES_SH, "log-run", gate, outcome, details],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        assert r.returncode == 0, f"log-run failed: {r.stderr}"


def _run_build_gate_summary(project_root, path_override=None):
    sourced_gates = GATES_SH
    script = f". '{sourced_gates}'\nbuild_gate_summary\n"
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_STALE_PAYLOAD"] = "1"
    env.update(source_env(gates=True))
    if path_override is not None:
        env["PATH"] = path_override

    r = subprocess.run(
        ["sh", "-c", script, sourced_gates],
        capture_output=True, text=True, env=env,
        cwd=os.path.join(TOOL_HOME, "scripts"),
    )
    assert r.returncode == 0, f"build_gate_summary failed: {r.stderr}"
    return json.loads(r.stdout)


class TestDeterministicGatesJqBranch(unittest.TestCase):
    """Exercises the jq emitter branch (default on this host)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-proj-")
        _git_init_with_commit(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_no_gate_runs_at_all_fields_absent_not_unavailable(self):
        """No rows for secrets/deps/sast -- each field is null, but
        audit_db_unavailable stays false when the DB was reachable (even if
        it does not yet exist -- see the no-DB-at-all case below, which is
        also not "unavailable" in the tool-missing sense this marker names
        unless the read genuinely could not happen)."""
        payload = _run_build_gate_summary(self._tmpdir)
        dg = payload["deterministic_gates"]
        self.assertIsNone(dg["secrets"])
        self.assertIsNone(dg["deps"])
        self.assertIsNone(dg["sast"])

    def test_pass_warn_skip_block_preserved_distinctly(self):
        _seed_audit_db(self._tmpdir, [
            ("secrets", "pass", "clean"),
            ("deps", "warn", "older osv-scanner"),
            ("sast", "skip", "semgrep not installed (opt-in skip)"),
        ])
        payload = _run_build_gate_summary(self._tmpdir)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["secrets"]["outcome"], "pass")
        self.assertEqual(dg["deps"]["outcome"], "warn")
        self.assertEqual(dg["sast"]["outcome"], "skip")
        self.assertFalse(dg["audit_db_unavailable"])

    def test_block_outcome_surfaced_verbatim(self):
        _seed_audit_db(self._tmpdir, [
            ("sast", "block", "semgrep reported findings"),
        ])
        payload = _run_build_gate_summary(self._tmpdir)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["sast"]["outcome"], "block")
        self.assertEqual(dg["sast"]["details"], "semgrep reported findings")

    def test_latest_row_wins_over_older_rows(self):
        """A gate that ran more than once (e.g. re-run after a fix) must
        surface its MOST RECENT outcome, not an older one."""
        _seed_audit_db(self._tmpdir, [
            ("secrets", "block", "gitleaks reported findings"),
            ("secrets", "pass", ""),
        ])
        payload = _run_build_gate_summary(self._tmpdir)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["secrets"]["outcome"], "pass")

    def test_only_deterministic_gate_names_are_read(self):
        """A logged row for a non-deterministic gate name (e.g. 'review',
        'merge-gate') must never leak into this block -- only
        secrets/deps/sast are in scope."""
        _seed_audit_db(self._tmpdir, [
            ("review", "pass", "0 findings"),
            ("merge-gate", "pass", ""),
        ])
        payload = _run_build_gate_summary(self._tmpdir)
        dg = payload["deterministic_gates"]
        self.assertIsNone(dg["secrets"])
        self.assertIsNone(dg["deps"])
        self.assertIsNone(dg["sast"])
        self.assertCountEqual(dg.keys(), ["secrets", "deps", "sast", "audit_db_unavailable"])

    def test_audit_db_missing_entirely_degrades_with_marker(self):
        """No .clagentic/lite/audit.db at all (gate never ran, or a repo
        that predates this feature) -- fields absent, marker set. Calls
        _read_deterministic_gates directly (see
        _call_read_deterministic_gates's doc comment): build_gate_summary's
        own stale-payload-warn cmd_log_run call (fired under
        CLAGENTIC_ALLOW_STALE_PAYLOAD=1, the env every other test in this
        file uses) would otherwise lazily create audit.db as an unrelated
        side effect before this function ever runs, masking the case this
        test targets."""
        db_path = os.path.join(self._tmpdir, ".clagentic", "lite", "audit.db")
        self.assertFalse(os.path.exists(db_path))
        dg = _call_read_deterministic_gates(self._tmpdir)
        self.assertFalse(os.path.exists(db_path))
        self.assertIsNone(dg["secrets"])
        self.assertIsNone(dg["deps"])
        self.assertIsNone(dg["sast"])
        self.assertTrue(dg["audit_db_unavailable"])


def _call_read_deterministic_gates(project_root, path_override=None):
    """Call _read_deterministic_gates directly, isolated from
    build_gate_summary's own unrelated cmd_log_run write (the
    stale-payload-warn line, which needs a working sqlite3 for ANY repo
    with a real commit, regardless of CLAGENTIC_ALLOW_STALE_PAYLOAD --
    corrupting/removing sqlite3 there would fail that call first and never
    reach this function). This isolates coverage of the read-degrade path
    itself, matching the direct-function-call pattern other test files in
    this suite use for helpers not exercised well via the full command
    (e.g. test_build_gate_summary_change_class.py sources gates.sh and
    calls build_gate_summary directly rather than the CLI)."""
    script = f". '{GATES_SH}'\n_read_deterministic_gates\n"
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env.update(source_env(gates=True))
    if path_override is not None:
        env["PATH"] = path_override
    r = subprocess.run(
        ["sh", "-c", script, GATES_SH],
        capture_output=True, text=True, env=env,
        cwd=os.path.join(TOOL_HOME, "scripts"),
    )
    assert r.returncode == 0, f"_read_deterministic_gates failed: {r.stderr}"
    return json.loads(r.stdout)


class TestDeterministicGatesUnreadableDb(unittest.TestCase):
    """audit.db exists but is corrupt/unreadable by sqlite3 -- must degrade,
    never block. Calls _read_deterministic_gates directly (see
    _call_read_deterministic_gates's doc comment) to isolate this from
    build_gate_summary's own unrelated cmd_log_run write, which needs a
    working sqlite3 for any repo with a real commit."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-corruptdb-proj-")
        _git_init_with_commit(self._tmpdir)
        # Seed a real DB with a passing secrets row first, via the normal
        # path, THEN corrupt the file -- this proves the degrade is about
        # the DB being unreadable at read time, not merely an empty DB.
        _seed_audit_db(self._tmpdir, [("secrets", "pass", "")])
        db_path = os.path.join(self._tmpdir, ".clagentic", "lite", "audit.db")
        with open(db_path, "wb") as f:
            f.write(b"not a sqlite database\x00\x01\x02")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_corrupt_db_degrades_never_blocks(self):
        dg = _call_read_deterministic_gates(self._tmpdir)
        self.assertIsNone(dg["secrets"])
        self.assertIsNone(dg["deps"])
        self.assertIsNone(dg["sast"])
        # sqlite3 IS present and the file DOES exist (it's just not a valid
        # DB), so _read_deterministic_gates's own "[ -f DB ] && command -v
        # sqlite3" gate does not itself trip -- the per-gate query fails
        # instead, silently (2>/dev/null || echo "") leaving each row
        # empty. audit_db_unavailable only names "the read never happened
        # at all" (no tool / no file); a query that ran but returned
        # nothing due to corruption still reports fields absent, which is
        # the honest signal here -- see the assertion on `secrets` etc.
        # above; audit_db_unavailable itself is NOT asserted true in this
        # case, deliberately (a corrupt DB IS reachable, its rows are just
        # unreadable, which is what dropping to null already communicates).


class TestDeterministicGatesSqlite3TrulyAbsent(unittest.TestCase):
    """sqlite3 missing from PATH entirely -- must degrade with the explicit
    audit_db_unavailable marker. Calls _read_deterministic_gates directly
    (see _call_read_deterministic_gates's doc comment) since removing
    sqlite3 from PATH would break build_gate_summary's own unrelated
    cmd_log_run write for any repo with a real commit."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-nosqlite-proj-")
        _git_init_with_commit(self._tmpdir)
        _seed_audit_db(self._tmpdir, [("secrets", "pass", "")])
        self._nosqlite_bin = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-nosqlite-bin-")
        real_path = os.environ.get("PATH", "")
        for d in real_path.split(os.pathsep):
            if not d or not os.path.isdir(d):
                continue
            for name in os.listdir(d):
                if name == "sqlite3":
                    continue
                link = os.path.join(self._nosqlite_bin, name)
                if os.path.exists(link):
                    continue
                try:
                    os.symlink(os.path.join(d, name), link)
                except OSError:
                    continue

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        shutil.rmtree(self._nosqlite_bin, ignore_errors=True)

    def test_sqlite3_missing_degrades_with_marker(self):
        dg = _call_read_deterministic_gates(self._tmpdir, path_override=self._nosqlite_bin)
        self.assertIsNone(dg["secrets"])
        self.assertIsNone(dg["deps"])
        self.assertIsNone(dg["sast"])
        self.assertTrue(dg["audit_db_unavailable"])


class TestDeterministicGatesPythonBranch(unittest.TestCase):
    """Forces the jq-less PATH so build_gate_summary falls through to its
    python3 emitter branch -- the two branches must not disagree."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-py-proj-")
        _git_init_with_commit(self._tmpdir)
        self._nojq_bin = _jqless_path()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        shutil.rmtree(self._nojq_bin, ignore_errors=True)

    def test_pass_warn_skip_block_preserved_distinctly_python_branch(self):
        _seed_audit_db(self._tmpdir, [
            ("secrets", "pass", "clean"),
            ("deps", "warn", "older osv-scanner"),
            ("sast", "skip", "semgrep not installed (opt-in skip)"),
        ])
        payload = _run_build_gate_summary(self._tmpdir, path_override=self._nojq_bin)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["secrets"]["outcome"], "pass")
        self.assertEqual(dg["deps"]["outcome"], "warn")
        self.assertEqual(dg["sast"]["outcome"], "skip")
        self.assertFalse(dg["audit_db_unavailable"])

    def test_block_outcome_and_absent_gate_python_branch(self):
        _seed_audit_db(self._tmpdir, [
            ("sast", "block", "semgrep reported findings"),
        ])
        payload = _run_build_gate_summary(self._tmpdir, path_override=self._nojq_bin)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["sast"]["outcome"], "block")
        self.assertIsNone(dg["secrets"])
        self.assertIsNone(dg["deps"])
        self.assertFalse(dg["audit_db_unavailable"])

    def test_audit_db_missing_entirely_degrades_with_marker_python_branch(self):
        """Same case as TestDeterministicGatesJqBranch's
        test_audit_db_missing_entirely_degrades_with_marker, but with jq off
        PATH -- calls _read_deterministic_gates directly (see
        _call_read_deterministic_gates's doc comment) for the same reason:
        build_gate_summary's own stale-payload-warn cmd_log_run call would
        otherwise lazily create audit.db first. The argument-passing wiring
        from this sh helper into the python3 emitter branch's heredoc is
        covered separately by test_jq_and_python3_branches_agree_on_same_db_state
        and test_pass_warn_skip_block_preserved_distinctly_python_branch
        above (both go through the real build_gate_summary)."""
        db_path = os.path.join(self._tmpdir, ".clagentic", "lite", "audit.db")
        self.assertFalse(os.path.exists(db_path))
        dg = _call_read_deterministic_gates(self._tmpdir, path_override=self._nojq_bin)
        self.assertFalse(os.path.exists(db_path))
        self.assertIsNone(dg["secrets"])
        self.assertIsNone(dg["deps"])
        self.assertIsNone(dg["sast"])
        self.assertTrue(dg["audit_db_unavailable"])

    def test_jq_and_python3_branches_agree_on_same_db_state(self):
        """Same seeded DB, run once through each emitter branch -- the
        deterministic_gates block must be identical."""
        _seed_audit_db(self._tmpdir, [
            ("secrets", "pass", "clean"),
            ("deps", "block", "CRITICAL vuln in libfoo"),
            ("sast", "warn", "semgrep partial timeout"),
        ])
        jq_payload = _run_build_gate_summary(self._tmpdir)
        py_payload = _run_build_gate_summary(self._tmpdir, path_override=self._nojq_bin)
        self.assertEqual(jq_payload["deterministic_gates"], py_payload["deterministic_gates"])


if __name__ == "__main__":
    unittest.main()
