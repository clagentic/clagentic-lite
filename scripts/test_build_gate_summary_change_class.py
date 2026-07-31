"""
Regression tests for lr-4f8316: build_gate_summary threading the resolved
change class (durable/ephemeral) and the class-downgrade count into the
gate-summary payload fed to the Merge Gate and the audit trail.

_parse_adversarial_findings already enum-validates each finding's `class`
field (see test_change_class_parsing.py). This file covers the next stage
of the pipeline: build_gate_summary (scripts/gates.sh) reads
last-adversarial-findings.json and must derive:

  - resolved_change_class: "ephemeral" if any finding declares
    class:"ephemeral", else "durable" if there is at least one finding,
    else null (nothing to resolve on a clean pass with no findings).
  - adversarial_downgraded_by_class_count: count of findings that met the
    blocking-eligible bar on reachability + severity but rode as
    tier:"advisory" under class:"ephemeral".

Sources the ACTUAL sh function from gates.sh (not a Python
reimplementation), same sourcing pattern as test_adversarial_tier_parsing.py
and test_merge_gate_recheck.py.

Run with: python3 -m unittest scripts.test_build_gate_summary_change_class -v
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
    """Same truncation/symlink pattern as test_adversarial_tier_parsing.py."""
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
    for fname in ("platform.sh", "review-merge.sh"):
        os.symlink(os.path.join(real_scripts_dir, fname), os.path.join(dest_dir, fname))
    return dest


def _run_build_gate_summary(findings, project_root):
    """Write findings (a list of finding dicts, or None to skip the file
    entirely) to last-adversarial-findings.json, source gates.sh (functions
    only) with CLAGENTIC_PROJECT_ROOT/CLAGENTIC_ALLOW_STALE_PAYLOAD set, and
    call build_gate_summary. Returns the parsed JSON payload.
    """
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-class-")
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

        script = f". '{sourced_gates}'\nbuild_gate_summary\n"
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = project_root
        # Skip the SHA-staleness check entirely — these tests exercise the
        # class-threading logic, not the staleness guard (already covered
        # by test_wrapper_staleness.py).
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


class TestResolvedChangeClass(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-class-proj-")
        subprocess.run(["git", "init", "-q", self._tmpdir], check=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_no_findings_at_all_resolved_class_is_null(self):
        """No last-adversarial-findings.json file (adversarial gate never
        ran, or predates this feature) -- nothing to resolve."""
        payload = _run_build_gate_summary(None, self._tmpdir)
        self.assertIsNone(payload["resolved_change_class"])
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 0)

    def test_empty_findings_array_resolved_class_is_null(self):
        """A clean adversarial pass (empty array, not absent file) is also
        "nothing to resolve" -- there is no diff-wide class judgment to
        report when there were no findings to carry it."""
        payload = _run_build_gate_summary([], self._tmpdir)
        self.assertIsNone(payload["resolved_change_class"])
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 0)

    def test_all_durable_findings_resolve_to_durable(self):
        findings = [
            {"file": "a.py", "line": 1, "category": "CWE-89", "message": "sqli",
             "severity": "critical", "reachable": "yes", "tier": "blocking", "class": "durable"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["resolved_change_class"], "durable")

    def test_any_ephemeral_finding_resolves_whole_diff_to_ephemeral(self):
        """One diff has one resolved class in practice -- 'any finding says
        ephemeral' is the mechanical resolution rule."""
        findings = [
            {"file": "a.py", "line": 1, "category": "CWE-1", "message": "m1",
             "severity": "low", "reachable": "no", "tier": "advisory", "class": "durable"},
            {"file": "migrate.py", "line": 5, "category": "CWE-770", "message": "growth",
             "severity": "high", "reachable": "yes", "tier": "advisory", "class": "ephemeral"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["resolved_change_class"], "ephemeral")


class TestDowngradedByClassCount(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-downgrade-")
        subprocess.run(["git", "init", "-q", self._tmpdir], check=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_reachable_high_ephemeral_advisory_counts_as_downgraded(self):
        findings = [
            {"file": "job.py", "line": 10, "category": "CWE-770",
             "message": "unbounded growth in one-shot job",
             "severity": "high", "reachable": "yes", "tier": "advisory",
             "class": "ephemeral"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 1)

    def test_reachable_critical_ephemeral_advisory_counts_as_downgraded(self):
        findings = [
            {"file": "job.py", "line": 10, "category": "CWE-770",
             "message": "unbounded growth", "severity": "critical",
             "reachable": "yes", "tier": "advisory", "class": "ephemeral"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 1)

    def test_blocking_tier_never_counted_as_downgraded(self):
        """A security-floor finding (tier:blocking regardless of class) must
        never be counted as 'downgraded' -- it was not downgraded, it is
        still gating."""
        findings = [
            {"file": "job.py", "line": 10, "category": "CWE-78",
             "message": "RCE via injected param", "severity": "critical",
             "reachable": "yes", "tier": "blocking", "class": "ephemeral"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 0)

    def test_durable_class_advisory_finding_not_counted(self):
        """An advisory finding under class:durable was not downgraded BY
        CLASS -- it is advisory for an ordinary reason (unreachable, low
        severity), not because of an ephemeral exemption."""
        findings = [
            {"file": "a.py", "line": 1, "category": "CWE-89",
             "message": "sqli in dead code", "severity": "critical",
             "reachable": "no", "tier": "advisory", "class": "durable"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 0)

    def test_low_severity_ephemeral_advisory_not_counted(self):
        """A low-severity finding was never blocking-eligible in the first
        place (severity gate alone excludes it) -- it should not inflate
        the class-downgrade count, which specifically means 'class is what
        moved it off the blocking path'."""
        findings = [
            {"file": "a.py", "line": 1, "category": "CWE-1",
             "message": "minor style nit", "severity": "low",
             "reachable": "yes", "tier": "advisory", "class": "ephemeral"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 0)

    def test_multiple_findings_only_matching_shape_counted(self):
        findings = [
            {"file": "a.py", "line": 1, "category": "CWE-770", "message": "growth1",
             "severity": "high", "reachable": "yes", "tier": "advisory", "class": "ephemeral"},
            {"file": "b.py", "line": 2, "category": "CWE-770", "message": "growth2",
             "severity": "critical", "reachable": "yes", "tier": "advisory", "class": "ephemeral"},
            {"file": "c.py", "line": 3, "category": "CWE-78", "message": "rce",
             "severity": "critical", "reachable": "yes", "tier": "blocking", "class": "ephemeral"},
            {"file": "d.py", "line": 4, "category": "CWE-1", "message": "nit",
             "severity": "low", "reachable": "no", "tier": "advisory", "class": "durable"},
        ]
        payload = _run_build_gate_summary(findings, self._tmpdir)
        self.assertEqual(payload["adversarial_downgraded_by_class_count"], 2)
        self.assertEqual(payload["resolved_change_class"], "ephemeral")


if __name__ == "__main__":
    unittest.main()
