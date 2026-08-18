"""
Regression tests for lr-33958f (PR-C fold-in, BOBBIE PR #142 review 2:
bobbie.sast.unbounded-truncation-drops-severity).

A truncated adversarial audit must never be silently presented as complete.
cmd_adversarial (scripts/gates.sh) persists a dropped-count sidecar
(last-adversarial-findings-meta.json) recording how many findings its count
cap actually dropped (see the write site's own comment). This file covers
the read side: build_gate_summary must read that sidecar back and surface
"adversarial_findings_dropped_count" in the gate-summary payload fed to the
Merge Gate and the audit trail, defaulting to 0 (fail-open) when the sidecar
is absent or unparseable.

Sources the ACTUAL sh function from gates.sh (not a Python reimplementation),
same sourcing pattern as test_build_gate_summary_change_class.py.

Run with: python3 -m unittest scripts.test_build_gate_summary_dropped_count -v
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run_build_gate_summary(findings, meta, project_root):
    """Write findings to last-adversarial-findings.json (or skip if None)
    and meta to last-adversarial-findings-meta.json (or skip if None), then
    call build_gate_summary. Returns the parsed JSON payload."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-dropped-")
    try:
        sourced_gates = GATES_SH

        clagentic_dir = os.path.join(project_root, ".clagentic", "lite")
        os.makedirs(clagentic_dir, exist_ok=True)
        if findings is not None:
            findings_path = os.path.join(clagentic_dir, "last-adversarial-findings.json")
            with open(findings_path, "w") as f:
                json.dump(findings, f)
        if meta is not None:
            meta_path = os.path.join(clagentic_dir, "last-adversarial-findings-meta.json")
            if isinstance(meta, str):
                with open(meta_path, "w") as f:
                    f.write(meta)
            else:
                with open(meta_path, "w") as f:
                    json.dump(meta, f)

        script = f". '{sourced_gates}'\nbuild_gate_summary\n"
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = project_root
        env["CLAGENTIC_ALLOW_STALE_PAYLOAD"] = "1"
        env.update(source_env(gates=True))

        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        assert r.returncode == 0, f"build_gate_summary failed: {r.stderr}"
        return json.loads(r.stdout)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestAdversarialFindingsDroppedCount(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-dropped-proj-")
        subprocess.run(["git", "init", "-q", self._tmpdir], check=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_no_meta_sidecar_defaults_to_zero(self):
        """No last-adversarial-findings-meta.json (predates this feature, or
        the adversarial gate never ran) -- fail-open to 0, not an error."""
        payload = _run_build_gate_summary([], None, self._tmpdir)
        self.assertEqual(payload["adversarial_findings_dropped_count"], 0)

    def test_meta_sidecar_dropped_count_surfaced_verbatim(self):
        findings = [{"file": "a.py", "line": 1, "category": "CWE-1", "message": "m",
                     "severity": "low", "reachable": "no", "tier": "advisory", "class": "durable"}]
        meta = {"dropped_count": 7, "total_before_cap": 8}
        payload = _run_build_gate_summary(findings, meta, self._tmpdir)
        self.assertEqual(payload["adversarial_findings_dropped_count"], 7)

    def test_zero_dropped_count_surfaced_as_zero(self):
        findings = [{"file": "a.py", "line": 1, "category": "CWE-1", "message": "m",
                     "severity": "low", "reachable": "no", "tier": "advisory", "class": "durable"}]
        meta = {"dropped_count": 0, "total_before_cap": 1}
        payload = _run_build_gate_summary(findings, meta, self._tmpdir)
        self.assertEqual(payload["adversarial_findings_dropped_count"], 0)

    def test_malformed_meta_sidecar_defaults_to_zero(self):
        """An unparseable sidecar must not break build_gate_summary or the
        merge-gate payload -- fail-open, matching every other optional
        gate-plumbing file this function reads."""
        payload = _run_build_gate_summary([], "not valid json at all", self._tmpdir)
        self.assertEqual(payload["adversarial_findings_dropped_count"], 0)

    def test_meta_sidecar_missing_field_defaults_to_zero(self):
        payload = _run_build_gate_summary([], {"total_before_cap": 5}, self._tmpdir)
        self.assertEqual(payload["adversarial_findings_dropped_count"], 0)


if __name__ == "__main__":
    unittest.main()
