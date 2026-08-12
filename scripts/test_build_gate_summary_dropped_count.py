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
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")


def _functions_only_source(dest_dir):
    """Same truncation/symlink pattern as test_build_gate_summary_change_class.py."""
    with open(GATES_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in gates.sh"
    dest = os.path.join(dest_dir, "gates.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
    for fname in ("platform.sh", "review-merge.sh", "host-adapter.sh"):
        os.symlink(os.path.join(real_scripts_dir, fname), os.path.join(dest_dir, fname))
    return dest


def _run_build_gate_summary(findings, meta, project_root):
    """Write findings to last-adversarial-findings.json (or skip if None)
    and meta to last-adversarial-findings-meta.json (or skip if None), then
    call build_gate_summary. Returns the parsed JSON payload."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-dropped-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)

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
