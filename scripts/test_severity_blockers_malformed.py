"""
Direct tests of severity_blockers() (scripts/gates.sh) for severities that are
not strings. A number, boolean or object cannot be ranked, so it must count as
blocking on BOTH implementation branches (jq present, and python3-only with jq
hidden from PATH). A null or missing severity keeps its original behavior:
rank 0, not blocking.
"""
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from test_source_helpers import GATES_SH, PLATFORM_SH, TOOL_HOME, path_without, source_env


def _finding(**over):
    base = {"file": "app.py", "line": 2, "category": "security", "message": "m"}
    base.update(over)
    return base


class TestSeverityBlockersMalformedSeverity(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-sb-malformed-")
        self._shadows = []

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        for s in self._shadows:
            shutil.rmtree(s, ignore_errors=True)

    def _run(self, findings, hide_jq):
        review_path = os.path.join(self._tmpdir, "review.json")
        with open(review_path, "w") as f:
            json.dump({"summary": "x", "findings": findings}, f)
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{GATES_SH}'
            severity_blockers '{review_path}' high
        """)
        env = os.environ.copy()
        env.update(source_env(gates=True))
        if hide_jq:
            shadow = path_without("jq")
            self._shadows.append(shadow)
            env["PATH"] = shadow
        r = subprocess.run(
            ["sh", "-c", script, GATES_SH],
            capture_output=True, text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"), env=env,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def _both(self, findings):
        return {
            "jq": self._run(findings, hide_jq=False),
            "python3": self._run(findings, hide_jq=True),
        }

    def test_branch_selection_is_real(self):
        if shutil.which("jq") is None:
            self.skipTest("jq not installed; the jq branch cannot be exercised")
        shadow = path_without("jq")
        self._shadows.append(shadow)
        self.assertFalse(os.path.exists(os.path.join(shadow, "jq")))

    def test_numeric_severity_blocks(self):
        for branch, out in self._both([_finding(severity=3)]).items():
            self.assertEqual(out, "1", branch)

    def test_boolean_severity_blocks(self):
        for sev in (True, False):
            for branch, out in self._both([_finding(severity=sev)]).items():
                self.assertEqual(out, "1", f"{branch} severity={sev}")

    def test_object_severity_blocks(self):
        for branch, out in self._both([_finding(severity={"level": "low"})]).items():
            self.assertEqual(out, "1", branch)

    def test_null_severity_does_not_block(self):
        for branch, out in self._both([_finding(severity=None)]).items():
            self.assertEqual(out, "0", branch)

    def test_missing_severity_does_not_block(self):
        for branch, out in self._both([_finding()]).items():
            self.assertEqual(out, "0", branch)

    def test_malformed_severity_still_honors_exclusions(self):
        findings = [
            _finding(severity=3, _deferral_matched=True),
            _finding(severity=True, _recurrence_demoted=True),
        ]
        for branch, out in self._both(findings).items():
            self.assertEqual(out, "0", branch)


if __name__ == "__main__":
    unittest.main()
