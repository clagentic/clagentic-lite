"""
Regression tests for lr-acf632: `_read_deterministic_gates` (scripts/gates.sh)
used to read a gate_runs row via one `sqlite3 -separator '|'` query and split
it with `cut -d'|' -f1`/`-f2-`. `cut` is LINE-oriented: a `details` value
containing a literal embedded newline made its own trailing lines bleed into
the `outcome` field on the next `cut` invocation, corrupting the
pass/warn/skip/block distinction `_read_deterministic_gates` exists to
preserve -- the lr-367a21 root-cause invariant, reopened by a different
mechanism.

This is the DB-round-trip test the lr-367a21 sanitize suite
(test_build_gate_summary_deterministic_gates_sanitize.py) deliberately routed
around -- see that file's `_HOSTILE_DETAILS` doc comment, which names this
defect and says newline handling is only covered indirectly, at the
`_llm_field_sanitize` unit level, not through the real DB round-trip. This
file closes that gap: it seeds a genuinely multi-line `details` value through
the real `gates.sh log-run` -> sqlite3 INSERT -> `_read_deterministic_gates`
SELECT path (not a mock), on BOTH JSON-emitter branches (jq and python3).

Sources the ACTUAL sh function from gates.sh (not a Python reimplementation),
same sourcing pattern as test_build_gate_summary_deterministic_gates.py.

Run with:
  python3 -m unittest scripts.test_build_gate_summary_deterministic_gates_newline -v
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

# Plain multi-line text -- no hostile content required to reproduce the
# defect (per the task's own finding). Three lines so a `cut`-based
# line-oriented mis-split would visibly smear the trailing lines into a
# would-be "outcome" field on the NEXT gate's query, not just truncate.
_MULTILINE_DETAILS = "line one: summary\nline two: extra context\nline three: trailing note"


def _git_init_with_commit(path):
    """`git init -q` alone leaves HEAD unborn (no commits). Mirrors the
    identical helper in test_build_gate_summary_deterministic_gates.py."""
    subprocess.run(["git", "init", "-q", path], check=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", path, "commit", "--allow-empty", "-q", "-m", "init"], check=True)


def _jqless_path():
    """Build a PATH with every real-PATH executable symlinked EXCEPT jq.
    Identical helper to test_build_gate_summary_deterministic_gates.py."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-nl-nojq-bin-")
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
    rows are the ones _read_deterministic_gates should surface as latest)."""
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


class TestMultilineDetailsRoundTripJqBranch(unittest.TestCase):
    """Exercises the jq emitter branch (default on this host)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-nl-proj-")
        _git_init_with_commit(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_multiline_details_does_not_corrupt_own_outcome(self):
        """A single gate's own multi-line details must not corrupt its own
        outcome field -- the direct reproduction of the defect."""
        _seed_audit_db(self._tmpdir, [("sast", "pass", _MULTILINE_DETAILS)])
        payload = _run_build_gate_summary(self._tmpdir)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["sast"]["outcome"], "pass")
        self.assertEqual(dg["sast"]["details"], _MULTILINE_DETAILS)

    def test_multiline_details_does_not_corrupt_a_later_gates_outcome(self):
        """The line-oriented `cut` mis-split bled a details value's trailing
        lines into the NEXT `cut -f1` invocation for a different row read --
        seed one gate with multi-line details and assert every gate's
        outcome is still a clean member of the closed pass/warn/skip/block
        set, not a fragment of another gate's details text."""
        _seed_audit_db(self._tmpdir, [
            ("secrets", "pass", _MULTILINE_DETAILS),
            ("deps", "warn", "older osv-scanner"),
            ("sast", "block", "semgrep reported findings"),
        ])
        payload = _run_build_gate_summary(self._tmpdir)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["secrets"]["outcome"], "pass")
        self.assertEqual(dg["secrets"]["details"], _MULTILINE_DETAILS)
        self.assertEqual(dg["deps"]["outcome"], "warn")
        self.assertEqual(dg["deps"]["details"], "older osv-scanner")
        self.assertEqual(dg["sast"]["outcome"], "block")
        self.assertEqual(dg["sast"]["details"], "semgrep reported findings")
        for gate in ("secrets", "deps", "sast"):
            self.assertIn(dg[gate]["outcome"], ("pass", "warn", "skip", "block"))


class TestMultilineDetailsRoundTripPythonBranch(unittest.TestCase):
    """Forces the jq-less PATH so build_gate_summary falls through to its
    python3 emitter branch -- the fix must hold on both branches, since the
    underlying row-read shape (shared by both) is what changed."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-detgates-nl-py-proj-")
        _git_init_with_commit(self._tmpdir)
        self._nojq_bin = _jqless_path()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        shutil.rmtree(self._nojq_bin, ignore_errors=True)

    def test_multiline_details_does_not_corrupt_own_outcome_python_branch(self):
        _seed_audit_db(self._tmpdir, [("deps", "block", _MULTILINE_DETAILS)])
        payload = _run_build_gate_summary(self._tmpdir, path_override=self._nojq_bin)
        dg = payload["deterministic_gates"]
        self.assertEqual(dg["deps"]["outcome"], "block")
        self.assertEqual(dg["deps"]["details"], _MULTILINE_DETAILS)

    def test_jq_and_python3_branches_agree_on_multiline_details(self):
        """Both emitter branches must not diverge on a multi-line details
        value -- same branch-agreement invariant lr-367a21 established for
        plain and hostile-but-single-line details, now proven for embedded
        newlines specifically."""
        _seed_audit_db(self._tmpdir, [
            ("secrets", "pass", _MULTILINE_DETAILS),
            ("deps", "warn", _MULTILINE_DETAILS),
            ("sast", "skip", _MULTILINE_DETAILS),
        ])
        jq_payload = _run_build_gate_summary(self._tmpdir)
        py_payload = _run_build_gate_summary(self._tmpdir, path_override=self._nojq_bin)
        self.assertEqual(jq_payload["deterministic_gates"], py_payload["deterministic_gates"])


if __name__ == "__main__":
    unittest.main()
