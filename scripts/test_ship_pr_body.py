"""
Acceptance tests for lr-429b32: ship-time PR body renders review provenance
(and degrades honestly) instead of cmd_ship's PR-open path relying entirely
on the adapter's own commit-message-scrape default.

SCOPE:
  1. _build_ship_pr_body BRANCH HEAD_SHA (scripts/gates.sh) renders four
     required sections: what changed/why, review provenance, trade-offs,
     out of scope.
  2. Review provenance (section 2) is the only section backed by real data --
     it reuses the ledger lookup and _render_review_verdict_lines rather than
     re-deriving verdict rendering, and has three honest states: an anchored
     verdict at the exact head_sha; a ledger entry for the branch at a
     DIFFERENT head_sha (stale, must say so); no usable ledger entry at all
     (never reviewed / no JSON tool / no ledger file).
  3. Sections 1/3/4 have no mechanical source in this codebase and must say
     so explicitly -- never a fabricated summary, never a bare empty
     heading.
  4. scripts/host-adapter.sh's gh adapter threading (BODY_FILE optional
     third arg) is covered separately in test_host_adapter_publish.py; this
     file is scoped to the gate-side render function only.

VERIFICATION: direct-source tests against the real scripts/gates.sh via the
CLAGENTIC_GATES_SOURCE_ONLY / CLAGENTIC_GATES_DELIBERATE_SOURCE guard
(test_source_helpers.source_env), mirroring test_gates_source_guard.py's
_init_repo pattern -- a real, remoteless temp git repo, no network, no host.

Run with: python3 -m unittest scripts.test_ship_pr_body -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _init_repo(root):
    subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
    env = {**os.environ, **_GIT_ENV}
    with open(os.path.join(root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    subprocess.run(["git", "add", "app.py"], check=True, cwd=root, env=env, timeout=30)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], check=True, cwd=root, env=env, timeout=30)
    subprocess.run(["git", "checkout", "-q", "-b", "feat/example"], check=True, cwd=root, env=env, timeout=30)


def _head_sha(root):
    r = subprocess.run(["git", "rev-parse", "HEAD"], check=True, cwd=root,
                        capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def _write_ledger_entry(repo, branch, head_sha, verdict, findings=None):
    ledger_dir = os.path.join(repo, ".clagentic", "lite")
    os.makedirs(ledger_dir, exist_ok=True)
    ledger_path = os.path.join(ledger_dir, "review-ledger.jsonl")
    entry = {
        "ts": "2026-08-18T00:00:00Z", "branch": branch, "base_sha": "",
        "head_sha": head_sha, "verdict": verdict, "findings": findings or [],
        "config": {"block_severity": "high", "cross_round_dedup": True, "recurrence_threshold": 2},
    }
    with open(ledger_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return ledger_path


def _call_build_ship_pr_body(repo, branch, head_sha):
    """Dot-source the real gates.sh (source-guard sentinels set) and call
    _build_ship_pr_body directly, scoped to `repo` via CLAGENTIC_PROJECT_ROOT
    -- mirrors test_gates_source_guard.py's _source_and_call shape."""
    env = os.environ.copy()
    env.update(source_env(gates=True))
    env["CLAGENTIC_PROJECT_ROOT"] = repo
    script = textwrap.dedent(f"""\
        . '{GATES_SH}'
        _build_ship_pr_body '{branch}' '{head_sha}'
    """)
    return subprocess.run(
        ["sh", "-c", script, GATES_SH],
        capture_output=True, text=True, env=env, cwd=repo, timeout=30,
    )


class TestBuildShipPrBody(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-ship-pr-body-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)
        self._head = _head_sha(self._repo)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_always_renders_four_required_sections(self):
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        for heading in (
            "## What changed and why",
            "## Review provenance",
            "## Trade-offs taken and rejected",
            "## Explicitly out of scope",
        ):
            self.assertIn(heading, r.stdout)

    def test_no_ledger_entry_at_all_renders_honest_reviewer_none(self):
        """No ledger file exists for this branch -- must say "reviewer:
        none", never a bare empty heading and never a fabricated verdict."""
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reviewer: none", r.stdout)
        self.assertIn("no recorded review verdict", r.stdout)
        self.assertNotIn("verdict: pass", r.stdout)
        self.assertNotIn("verdict: block", r.stdout)

    def test_anchored_pass_at_exact_head_renders_real_verdict(self):
        """A ledger entry whose head_sha matches this PR's head exactly must
        render the real verdict/head_sha/findings-count, reusing the same
        rendering core the posted review-verdict comment uses."""
        _write_ledger_entry(self._repo, "feat/example", self._head, "pass")
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verdict: pass", r.stdout)
        self.assertIn(self._head, r.stdout)
        self.assertIn("Findings: none", r.stdout)
        self.assertNotIn("reviewer: none", r.stdout)

    def test_anchored_block_verdict_with_findings_renders_counts(self):
        findings = [
            {"severity": "high", "file": "app.py", "line": 2, "category": "security",
             "message": "sql injection", "_ledger_recurring": False},
            {"severity": "medium", "file": "app.py", "line": 5, "category": "style",
             "message": "long line", "_ledger_recurring": True},
        ]
        _write_ledger_entry(self._repo, "feat/example", self._head, "block", findings)
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verdict: block", r.stdout)
        self.assertIn("Findings: 2 total", r.stdout)
        self.assertIn("high: 1", r.stdout)
        self.assertIn("medium: 1", r.stdout)
        self.assertIn("Recurring from a prior round (1)", r.stdout)
        self.assertIn("long line", r.stdout)

    def test_ledger_entry_for_branch_at_different_head_renders_stale_notice(self):
        """A verdict exists for this branch, but not at the head being
        shipped (new commits landed since the last review round) -- must
        say the review is stale relative to this head, never silently
        present the older verdict as if it still applies."""
        _write_ledger_entry(self._repo, "feat/example", "0000000000000000000000000000000000dead", "pass")
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reviewer:", r.stdout)
        self.assertIn("does not cover this PR's head", r.stdout)
        self.assertIn("0000000000000000000000000000000000dead", r.stdout)
        self.assertIn(self._head, r.stdout)
        self.assertNotIn("verdict: pass", r.stdout,
                          "a stale verdict must never be presented as if it covers the current head")

    def test_ledger_entry_for_a_different_branch_is_ignored(self):
        """A passing verdict recorded against a DIFFERENT branch must never
        leak into this branch's review-provenance section."""
        _write_ledger_entry(self._repo, "some-other-branch", self._head, "pass")
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reviewer: none", r.stdout)

    def test_unanchored_verdict_entry_is_not_treated_as_a_real_pass(self):
        """An 'unanchored' ledger entry (empty head_sha at record time) must
        never be read as covering any real head -- same posture
        _ledger_anchored_pass_at_head already enforces for the merge gate."""
        _write_ledger_entry(self._repo, "feat/example", "", "unanchored")
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reviewer:", r.stdout)
        self.assertNotIn("verdict: pass", r.stdout)

    def test_placeholder_sections_never_silently_empty(self):
        """Sections 1/3/4 have no mechanical data source -- each must carry
        an explicit sentence naming that gap, never a heading with nothing
        under it (the degrade-honestly acceptance bar applies to every
        section, not only review provenance)."""
        r = _call_build_ship_pr_body(self._repo, "feat/example", self._head)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Not recorded by tooling", r.stdout)
        # Every required heading must be followed by non-whitespace content
        # before the next heading (or end of string) -- a mechanical proxy
        # for "never a bare empty heading."
        sections = r.stdout.split("## ")[1:]
        self.assertTrue(sections, "no sections rendered at all")
        for section in sections:
            body = section.split("\n", 1)[1] if "\n" in section else ""
            self.assertTrue(body.strip(), "section %r rendered with no body" % section.split("\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
