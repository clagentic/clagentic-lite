"""
validate_output (scripts/llm-client.sh) checks the model's own severity against
the closed set under either name it can arrive as: `severity`, and
`severity_claimed`, which is what the Reviewer prompt asks for now that the
severity that counts is computed from facts. A value outside the set fails the
chain step like any other schema violation. Both the jq and the python3 branch
are exercised, since the two must agree.

Run with: python3 -m unittest scripts.test_validate_output_severity_claimed -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_review_findings_forged_field_stripped import _call_validate_output  # noqa: E402

BASE = {"file": "a.py", "line": 1, "category": "style", "message": "m",
        "issue_class": "none — isolated", "class_fix": "n/a — isolated"}


def envelope(**finding):
    return {"summary": "s", "checked": [], "findings": [dict(BASE, **finding)]}


class TestSeverityClaimedIsChecked(unittest.TestCase):
    def accepted(self, document, jq_available):
        _, _, rc = _call_validate_output(document, jq_available=jq_available)
        return rc == 0

    def test_a_known_value_is_accepted_in_either_case_on_both_branches(self):
        for jq_available in (True, False):
            for value in ("low", "MEDIUM", "High", "critical"):
                with self.subTest(jq=jq_available, value=value):
                    self.assertTrue(self.accepted(envelope(severity_claimed=value), jq_available))

    def test_an_unknown_or_non_string_value_is_rejected_on_both_branches(self):
        for jq_available in (True, False):
            for value in ("blocker", "crit", "", 5, ["high"]):
                with self.subTest(jq=jq_available, value=value):
                    self.assertFalse(self.accepted(envelope(severity_claimed=value), jq_available))

    def test_the_older_name_is_still_checked(self):
        for jq_available in (True, False):
            with self.subTest(jq=jq_available):
                self.assertTrue(self.accepted(envelope(severity="high"), jq_available))
                self.assertFalse(self.accepted(envelope(severity="blocker"), jq_available))

    def test_a_finding_with_neither_is_not_a_schema_violation(self):
        for jq_available in (True, False):
            with self.subTest(jq=jq_available):
                self.assertTrue(self.accepted(envelope(), jq_available))

    def test_a_bad_value_in_a_single_key_wrapper_is_rejected_too(self):
        wrapped = {"result": envelope(severity_claimed="blocker")}
        for jq_available in (True, False):
            with self.subTest(jq=jq_available):
                self.assertFalse(self.accepted(wrapped, jq_available))
        good = {"result": envelope(severity_claimed="high")}
        self.assertTrue(self.accepted(good, True))


if __name__ == "__main__":
    unittest.main()
