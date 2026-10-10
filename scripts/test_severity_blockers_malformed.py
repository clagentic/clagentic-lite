"""
Direct tests of severity_blockers() (scripts/gates.sh) for severities that are
not strings. A number, boolean or object cannot be ranked, so it must count as
blocking. A null or missing severity keeps its original behavior: rank 0, not
blocking. The count comes from the one python3 implementation in the finding
pipeline; with python3 absent the function fails closed.
"""
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from isolated_env import shared_env
from test_source_helpers import GATES_SH, PLATFORM_SH, path_without, source_env


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

    def _run(self, findings, hide_tool=None):
        review_path = os.path.join(self._tmpdir, "review.json")
        with open(review_path, "w") as f:
            json.dump({"summary": "x", "findings": findings}, f)
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{GATES_SH}'
            severity_blockers '{review_path}' high
        """)
        env = shared_env(project=self._tmpdir)
        env.update(source_env(gates=True))
        if hide_tool:
            shadow = path_without(hide_tool)
            self._shadows.append(shadow)
            env["PATH"] = shadow
        r = subprocess.run(
            ["sh", "-c", script, GATES_SH],
            capture_output=True, text=True,
            cwd=self._tmpdir, env=env,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_numeric_severity_blocks(self):
        self.assertEqual(self._run([_finding(severity=3)]), "1")

    def test_boolean_severity_blocks(self):
        for sev in (True, False):
            self.assertEqual(self._run([_finding(severity=sev)]), "1", f"severity={sev}")

    def test_object_severity_blocks(self):
        self.assertEqual(self._run([_finding(severity={"level": "low"})]), "1")

    def test_null_severity_does_not_block(self):
        self.assertEqual(self._run([_finding(severity=None)]), "0")

    def test_missing_severity_does_not_block(self):
        self.assertEqual(self._run([_finding()]), "0")

    def test_malformed_severity_cannot_be_excused_by_an_annotation(self):
        # The old exemption annotations are gone: a finding that carries one
        # (a model can write anything) counts like any other.
        findings = [
            _finding(severity=3, _deferral_matched=True),
            _finding(severity=True, _recurrence_demoted=True),
        ]
        self.assertEqual(self._run(findings), "2")

    def test_names_that_are_not_ranks_block_and_known_names_are_stripped(self):
        findings = [_finding(severity="blocker"), _finding(severity="crit"),
                    _finding(severity="high "), _finding(severity="HIGH"), _finding(severity="low")]
        self.assertEqual(self._run(findings), "4")

    def test_result_does_not_depend_on_jq_being_installed(self):
        findings = [_finding(severity=3), _finding(severity="HIGH"), _finding(severity="low")]
        self.assertEqual(self._run(findings, hide_tool="jq"), "2")

    def test_missing_python3_fails_closed_with_the_sentinel(self):
        self.assertEqual(self._run([_finding(severity="low")], hide_tool="python3"), "99")


if __name__ == "__main__":
    unittest.main()
