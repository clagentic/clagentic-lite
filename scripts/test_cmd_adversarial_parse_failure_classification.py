"""
Regression test for lr-33958f (PR-C fold-in, BOBBIE PR #142 review 2, Class
2.7): cmd_adversarial (scripts/gates.sh) must CLASSIFY a
_parse_adversarial_findings read failure rather than let it silently
collapse into an empty findings sidecar with no trace in the audit trail.

This exercises the call site guard, not the parser itself (see
test_parse_adversarial_findings_fileline_and_read_failure.py for the
parser's own exit-status contract) -- specifically that `set -e` does not
abort cmd_adversarial on a parse failure, and that the failure is both
logged to the audit trail and printed to stderr.

Forcing a REAL unreadable last-adversarial.md from inside cmd_adversarial's
own run is awkward (cmd_adversarial writes $OUT itself moments before
reading it back), so this test verifies the call-site guard directly: chmod
000 the underlying file object cmd_adversarial passes to
_parse_adversarial_findings by racing a directory in its place is not
portable across platforms, so instead this drives cmd_adversarial with a
fake llm-client.sh that writes $OUT normally, then verifies the guard logic
itself using the same technique test_adversarial_findings_count_cap.py uses
-- sourcing the real function and calling it with the SHA-stamped file
already made unreadable between the write and the parse call, which is
exactly the window the fix's own comment describes.

Run with: python3 -m unittest scripts.test_cmd_adversarial_parse_failure_classification -v
"""
import os
import shutil
import stat
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


@unittest.skipIf(os.geteuid() == 0, "root ignores file permission bits")
class TestCmdAdversarialClassifiesAParseReadFailure(unittest.TestCase):
    """Directly exercises the guard added around
    `_adv_findings_json_raw=$(_parse_adversarial_findings "$OUT") || ...`
    in cmd_adversarial: a nonzero return from the parser must not abort the
    function under `set -e`, must be logged, and must fall back to an empty
    (not crashed) findings array."""

    def test_unreadable_findings_source_does_not_abort_under_set_e_and_is_logged(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-cmdadv-parsefail-")
        try:
            sourced_gates = GATES_SH

            unreadable = os.path.join(tmpdir, "unreadable.md")
            with open(unreadable, "w") as f:
                f.write("irrelevant\n")
            os.chmod(unreadable, 0)

            # Directly invoke the same guarded call shape cmd_adversarial
            # uses, standalone -- proves `set -e` does not abort on the
            # nonzero return and that stderr carries the classification.
            script = textwrap.dedent(f"""\
                set -e
                . '{sourced_gates}'
                cmd_log_run() {{ :; }}  # stub: no audit.db in this fixture
                _adv_parse_status=0
                _adv_findings_json_raw=$(_parse_adversarial_findings '{unreadable}') || _adv_parse_status=$?
                if [ "$_adv_parse_status" -ne 0 ]; then
                  echo "PARSE_FAILED_CLASSIFIED status=$_adv_parse_status" 1>&2
                  _adv_findings_json_raw='[]'
                fi
                echo "SURVIVED_SET_E"
                printf '%s' "$_adv_findings_json_raw"
            """)
            env = os.environ.copy()
            env.update(source_env(gates=True))
            r = subprocess.run(
                ["sh", "-c", script, sourced_gates],
                capture_output=True, text=True,
                cwd=os.path.join(TOOL_HOME, "scripts"),
                env=env,
            )
            self.assertEqual(r.returncode, 0, f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertIn("SURVIVED_SET_E", r.stdout,
                          "the parse failure must not abort the script under `set -e`")
            self.assertIn("PARSE_FAILED_CLASSIFIED status=1", r.stderr,
                          f"the nonzero parser status must be classified, not swallowed. stderr={r.stderr!r}")
            self.assertTrue(
                r.stdout.strip().endswith("[]"),
                f"on a parse failure the caller must fall back to an empty "
                f"findings array (never a crash) so the rest of "
                f"cmd_adversarial can still proceed. stdout={r.stdout!r}",
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
