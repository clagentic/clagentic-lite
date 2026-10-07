"""
The review-verdict render path must neither fail on a large findings list nor
turn an unreadable one into "Findings: none".

One argv string over the kernel's MAX_ARG_STRLEN (~128 KiB) fails exec with
E2BIG, and the caller then degraded a real result into a false "no review
recorded". The findings reach python3 by file (_stage_payload_file).

Covers: _render_review_verdict_lines with a payload over the limit; with an
unreadable or corrupt findings payload (exit 2, no output, never "none");
and _build_ship_pr_body, whose review section says the record could not be
read instead of "no recorded review verdict" when the ledger entry's findings
are corrupt.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Comfortably past MAX_ARG_STRLEN (131072) once serialized.
_OVER_LIMIT_BYTES = 300 * 1024


def _big_findings():
    message = "x" * 1000
    count = _OVER_LIMIT_BYTES // 1000 + 1
    return [
        {"severity": "high", "file": "a%d.py" % i, "line": 1, "category": "c", "message": message}
        for i in range(count)
    ]


def _repo(tmp):
    repo = os.path.join(tmp, "repo")
    subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True, timeout=60)
    with open(os.path.join(repo, "seed.txt"), "w") as f:
        f.write("seed\n")
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(["git", "-C", repo, "add", "seed.txt"], check=True, env=env, timeout=60)
    subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "seed"], check=True, env=env, timeout=60)
    return repo


def _run(repo, script, extra_env=None):
    env = os.environ.copy()
    env.update(source_env(gates=True))
    env["CLAGENTIC_PROJECT_ROOT"] = repo
    env.update(extra_env or {})
    full = ". '%s'\n%s\n" % (GATES_SH, script)
    return subprocess.run(["sh", "-c", full, GATES_SH], capture_output=True, text=True,
                          env=env, cwd=repo, timeout=120)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-handoff-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = _repo(self.tmp)


class TestRenderPayloads(_Base):
    def test_render_reports_an_over_limit_findings_list(self):
        findings = _big_findings()
        self.assertGreater(len(json.dumps(findings)), 131072)
        listing = os.path.join(self.tmp, "findings.json")
        with open(listing, "w") as f:
            json.dump(findings, f)
        res = _run(self.repo, "_render_review_verdict_lines head1 \"$(cat '%s')\"" % listing)
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        self.assertIn("Findings: %d total" % len(findings), res.stdout)

    def test_render_reports_an_empty_list_as_none(self):
        res = _run(self.repo, "_render_review_verdict_lines head1 '[]'")
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        self.assertIn("Findings: none", res.stdout)

    def test_render_fails_closed_on_corrupt_findings(self):
        for label, payload in (("truncated", '[{"severity": "high"'),
                               ("not json", "not json at all"),
                               ("an object", '{"severity": "high"}'),
                               ("null", "null")):
            with self.subTest(payload=label):
                res = _run(self.repo, "_render_review_verdict_lines head1 '%s'" % payload)
                self.assertEqual(res.returncode, 2, res.stderr[-500:])
                self.assertEqual(res.stdout, "")

    def test_stage_payload_file_round_trips_an_over_limit_payload(self):
        res = _run(self.repo,
                   "p=$(python3 -c \"print('y' * %d)\")\n"
                   "f=$(_stage_payload_file clagentic-test \"$p\") || exit 3\n"
                   "wc -c < \"$f\"\nrm -f \"$f\"" % _OVER_LIMIT_BYTES)
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        self.assertEqual(int(res.stdout.strip()), _OVER_LIMIT_BYTES)


class TestShipBodyReviewSection(_Base):
    """The ship PR body's review section, driven by a real ledger file."""

    def _body(self, entry_line):
        head = subprocess.run(["git", "-C", self.repo, "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True, timeout=60).stdout.strip()
        ledger_dir = os.path.join(self.repo, ".clagentic", "lite")
        os.makedirs(ledger_dir, exist_ok=True)
        with open(os.path.join(ledger_dir, "review-ledger.jsonl"), "w") as f:
            f.write(entry_line.replace("HEADSHA", head) + "\n")
        return _run(self.repo, "_build_ship_pr_body main \"$(git rev-parse HEAD)\"")

    def test_corrupt_entry_findings_say_the_record_could_not_be_read(self):
        corrupt = ('{"ts":"t","branch":"main","gate":"review","base_sha":"b",'
                   '"head_sha":"HEADSHA","verdict":"pass","findings":"corrupt"}')
        res = self._body(corrupt)
        self.assertIn("could not be read", res.stdout, res.stderr[-500:])
        self.assertNotIn("no recorded review verdict", res.stdout)
        self.assertNotIn("Findings: none", res.stdout)

    def test_unparseable_entry_says_the_record_could_not_be_read(self):
        res = self._body('{"head_sha":"HEADSHA","verdict":"pass","findings":[{"severity"')
        self.assertNotIn("Findings: none", res.stdout, res.stderr[-500:])

    def test_readable_empty_findings_are_reported_as_none(self):
        ok = ('{"ts":"t","branch":"main","gate":"review","base_sha":"b",'
              '"head_sha":"HEADSHA","verdict":"pass","findings":[]}')
        res = self._body(ok)
        self.assertIn("Findings: none", res.stdout, res.stderr[-500:])
        self.assertNotIn("could not be read", res.stdout)


if __name__ == "__main__":
    unittest.main()
