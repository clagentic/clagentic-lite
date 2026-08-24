"""
Acceptance tests for lr-01ae73: SHA-anchored review ledger.

SCOPE (matches the task's six items):
  1. Review ledger under .clagentic/lite/ recording per review run: base_sha,
     head_sha, verdict, structured findings, timestamp, gate config in
     effect. Append-only per branch.
  2. Anchored verdicts: cmd_review always records the (base_sha, head_sha)
     pair it evaluated. A verdict with no resolvable head SHA is recorded as
     "unanchored" and treated as NO verdict by consumers.
  3. Delta re-review: when a branch has a prior verdicted head_sha, review
     evaluates only that SHA..HEAD by default. An unresolvable prior SHA
     (rebase/amend/force-push) falls back to full-range and says so.
  4. Merge-gate consumption: the merge/ship path reads the ledger and
     requires a passing verdict whose head_sha equals current HEAD. Stale or
     missing verdict-at-HEAD means re-review, never proceed.
  5. Findings carry stable identity across rounds (content-hash) so the
     ledger marks a finding recurring vs new -- RECORDING ONLY, no severity
     demotion (lr-66e598's demotion policy is explicitly not resurrected).
  6. docs/GATES.md documents the ledger format and anchored-verdict contract
     (covered by review, not by this test file).

VERIFICATION DISCIPLINE (task comment #2): every acceptance criterion,
including "repo with no remote at all," is proven repo-locally via temp git
repos and stub llm-client.sh -- no enrolled host, no live remote, no running
session. Mirrors the harness pattern already established by
test_review_recurrence_demotion.py (TestRecurrenceViaCmdReview) and
test_merge_gate_state_cache.py.

Two layers:
  1. TestLedgerPrimitivesDirect -- calls ledger_append / ledger_latest_for_branch
     / ledger_entries_for_branch (review-merge.sh) directly, no git involved.
  2. TestReviewLedgerViaCmdReview / TestMergeGateLedgerConsumption -- drive the
     real cmd_review / cmd_merge_gate end to end against a real (remoteless)
     git repo with a stub llm-client.sh.

Run with: python3 -m unittest scripts.test_review_ledger -v
"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")
REVIEW_MERGE_SH = os.path.join(TOOL_HOME, "scripts", "review-merge.sh")

_GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


# ---------------------------------------------------------------------------
# Layer 1: ledger_append / ledger_latest_for_branch / ledger_entries_for_branch
# direct calls, no git repo needed.
# ---------------------------------------------------------------------------

def _run_review_merge_fn(call_line, env_overrides=None):
    """Source platform.sh + review-merge.sh and run one call line, returning
    (stdout, stderr, returncode)."""
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    script = textwrap.dedent(f"""\
        . '{PLATFORM_SH}'
        . '{REVIEW_MERGE_SH}'
        {call_line}
    """)
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env)


class TestLedgerPrimitivesDirect(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-ledger-prim-")
        self._ledger = os.path.join(self._tmpdir, "review-ledger.jsonl")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_append_creates_file_and_parent_dir(self):
        nested_ledger = os.path.join(self._tmpdir, "nested", "review-ledger.jsonl")
        line = json.dumps({"branch": "feat/x", "head_sha": "abc123", "verdict": "pass"})
        r = _run_review_merge_fn(f"ledger_append '{nested_ledger}' '{line}' 0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(nested_ledger))
        with open(nested_ledger) as f:
            content = f.read()
        self.assertEqual(content.count("\n"), 1)
        self.assertEqual(json.loads(content.strip()), json.loads(line))

    def test_append_is_append_only_prior_entries_retained(self):
        for i in range(3):
            line = json.dumps({"branch": "feat/x", "head_sha": f"sha{i}", "verdict": "pass"})
            r = _run_review_merge_fn(f"ledger_append '{self._ledger}' '{line}' 0")
            self.assertEqual(r.returncode, 0, r.stderr)
        with open(self._ledger) as f:
            lines = [l for l in f.read().split("\n") if l]
        self.assertEqual(len(lines), 3, "all three entries must be retained, append-only")
        shas = [json.loads(l)["head_sha"] for l in lines]
        self.assertEqual(shas, ["sha0", "sha1", "sha2"], "order must be chronological (append order)")

    def test_latest_for_branch_returns_most_recent_only(self):
        for i in range(3):
            line = json.dumps({"branch": "feat/x", "head_sha": f"sha{i}", "verdict": "pass"})
            _run_review_merge_fn(f"ledger_append '{self._ledger}' '{line}' 0")
        r = _run_review_merge_fn(f"ledger_latest_for_branch '{self._ledger}' 'feat/x'")
        self.assertEqual(r.returncode, 0, r.stderr)
        entry = json.loads(r.stdout.strip())
        self.assertEqual(entry["head_sha"], "sha2")

    def test_latest_for_branch_ignores_other_branches(self):
        _run_review_merge_fn(
            f"ledger_append '{self._ledger}' '{json.dumps({'branch': 'feat/a', 'head_sha': 'aaa', 'verdict': 'pass'})}' 0"
        )
        _run_review_merge_fn(
            f"ledger_append '{self._ledger}' '{json.dumps({'branch': 'feat/b', 'head_sha': 'bbb', 'verdict': 'pass'})}' 0"
        )
        r = _run_review_merge_fn(f"ledger_latest_for_branch '{self._ledger}' 'feat/a'")
        entry = json.loads(r.stdout.strip())
        self.assertEqual(entry["head_sha"], "aaa")

    def test_latest_for_branch_no_entries_prints_nothing(self):
        r = _run_review_merge_fn(f"ledger_latest_for_branch '{self._ledger}' 'feat/never-seen'")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "")

    def test_missing_ledger_file_is_safe_noop(self):
        missing = os.path.join(self._tmpdir, "does-not-exist.jsonl")
        r = _run_review_merge_fn(f"ledger_latest_for_branch '{missing}' 'feat/x'")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "")

    def test_entries_for_branch_returns_all_in_order(self):
        for i in range(4):
            line = json.dumps({"branch": "feat/x", "head_sha": f"sha{i}", "verdict": "pass"})
            _run_review_merge_fn(f"ledger_append '{self._ledger}' '{line}' 0")
        r = _run_review_merge_fn(f"ledger_entries_for_branch '{self._ledger}' 'feat/x'")
        lines = [l for l in r.stdout.split("\n") if l]
        self.assertEqual(len(lines), 4)
        shas = [json.loads(l)["head_sha"] for l in lines]
        self.assertEqual(shas, ["sha0", "sha1", "sha2", "sha3"])

    def test_per_branch_cap_drops_oldest_first_other_branches_untouched(self):
        for i in range(5):
            line = json.dumps({"branch": "feat/x", "head_sha": f"x{i}", "verdict": "pass"})
            _run_review_merge_fn(f"ledger_append '{self._ledger}' '{line}' 3")
        other_line = json.dumps({"branch": "feat/y", "head_sha": "y0", "verdict": "pass"})
        _run_review_merge_fn(f"ledger_append '{self._ledger}' '{other_line}' 3")

        r = _run_review_merge_fn(f"ledger_entries_for_branch '{self._ledger}' 'feat/x'")
        lines = [l for l in r.stdout.split("\n") if l]
        shas = [json.loads(l)["head_sha"] for l in lines]
        self.assertEqual(len(shas), 3, "cap must limit feat/x to 3 entries")
        self.assertEqual(shas, ["x2", "x3", "x4"], "oldest entries dropped first")

        r_other = _run_review_merge_fn(f"ledger_entries_for_branch '{self._ledger}' 'feat/y'")
        other_lines = [l for l in r_other.stdout.split("\n") if l]
        self.assertEqual(len(other_lines), 1, "capping feat/x must never touch feat/y's entries")

    def test_zero_max_disables_cap(self):
        for i in range(10):
            line = json.dumps({"branch": "feat/x", "head_sha": f"x{i}", "verdict": "pass"})
            _run_review_merge_fn(f"ledger_append '{self._ledger}' '{line}' 0")
        r = _run_review_merge_fn(f"ledger_entries_for_branch '{self._ledger}' 'feat/x'")
        lines = [l for l in r.stdout.split("\n") if l]
        self.assertEqual(len(lines), 10, "max=0 must mean unlimited")


# ---------------------------------------------------------------------------
# Layer 2: cmd_review end-to-end, real (remoteless) git repo, stub llm-client.sh.
# ---------------------------------------------------------------------------

def _setup_project(tmpdir):
    clagentic_dir = os.path.join(tmpdir, ".clagentic", "lite")
    os.makedirs(clagentic_dir, exist_ok=True)
    db_path = os.path.join(clagentic_dir, "audit.db")
    conn = sqlite3.connect(db_path)
    conn.execute(textwrap.dedent("""\
        CREATE TABLE IF NOT EXISTS gate_runs (
          id         INTEGER PRIMARY KEY,
          ts         TEXT NOT NULL,
          gate       TEXT NOT NULL,
          outcome    TEXT NOT NULL,
          details    TEXT,
          session_id TEXT,
          branch     TEXT
        )
    """))
    conn.commit()
    conn.close()
    return tmpdir


def _git(args, cwd, env=None):
    e = os.environ.copy()
    e.update(_GIT_IDENTITY_ENV)
    if env:
        e.update(env)
    return subprocess.run(["git"] + args, cwd=cwd, env=e, check=True,
                           capture_output=True, text=True)


def _init_git_repo_no_remote(project_root):
    """A repo with NO remote configured at all (AC6: 'repo with no remote')."""
    _git(["init", "-q", "-b", "main", project_root], cwd=None)
    with open(os.path.join(project_root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    _git(["add", "app.py"], cwd=project_root)
    _git(["commit", "-q", "-m", "seed"], cwd=project_root)
    _git(["checkout", "-q", "-b", "feat/example"], cwd=project_root)
    # Verify no remote exists -- the precondition this suite claims to prove.
    r = subprocess.run(["git", "remote"], cwd=project_root, capture_output=True, text=True)
    assert r.stdout.strip() == "", "test setup must produce a repo with no remote"


def _init_git_repo_with_local_file_remote(tmpdir, project_root):
    """A repo with a LOCAL FILE-PATH 'origin' (a bare repo on the same
    filesystem, no network involved at all) -- used only by tests that
    exercise get_review_diff's pre-existing (not introduced by this task)
    full-branch-diff-against-origin/<default> fallback, which requires
    proving origin/<default> freshness via a real `git fetch`/`git
    ls-remote`. This is still fully local/offline verification (no host, no
    network, no running session) -- 'origin' here is a directory on disk,
    exercised the same way test_sast_baseline_scope.py and
    test_bleed_scope.py already do for their own baseline-freshness tests.
    Distinct from _init_git_repo_no_remote, which proves the AC6 "no remote
    at all" scenario for the ledger's OWN capabilities (recording,
    delta-scoping off a prior verdict, merge-gate consumption) -- those
    never need to reach this fallback at all once a first verdict exists.

    project_root must NOT already be an initialized git repo (this creates
    a fresh one) -- callers use a subdirectory distinct from setUp()'s own
    self._project fixture, which _init_git_repo_no_remote already seeded
    and committed into."""
    bare_remote = os.path.join(tmpdir, "origin.git")
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", bare_remote], check=True)
    os.makedirs(project_root, exist_ok=True)
    _git(["init", "-q", "-b", "main", project_root], cwd=None)
    _git(["remote", "add", "origin", bare_remote], cwd=project_root)
    with open(os.path.join(project_root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    _git(["add", "app.py"], cwd=project_root)
    _git(["commit", "-q", "-m", "seed"], cwd=project_root)
    _git(["push", "-q", "origin", "main"], cwd=project_root)
    _git(["checkout", "-q", "-b", "feat/example"], cwd=project_root)
    return bare_remote


def _commit_file(project_root, name, content, msg):
    path = os.path.join(project_root, name)
    with open(path, "w") as f:
        f.write(content)
    _git(["add", name], cwd=project_root)
    _git(["commit", "-q", "-m", msg], cwd=project_root)
    return _git(["rev-parse", "HEAD"], cwd=project_root).stdout.strip()


def _stage_file(project_root, name, content):
    """Stage (but do not commit) a file change. get_review_diff's HIGHEST
    priority path is the staged diff (git diff --cached) -- it never
    consults the ledger or the branch-diff-against-default fallback, so it
    never needs a remote. This is how round 1 (no prior ledger entry yet)
    is driven in this suite's fixtures: a repo with NO remote configured at
    all (AC6) cannot prove origin/<default> freshness, so the ONLY diff
    source that works with zero prior ledger state is a staged one --
    matches test_review_recurrence_demotion.py's own _stage_identical_recreation
    pattern for the identical reason."""
    path = os.path.join(project_root, name)
    with open(path, "w") as f:
        f.write(content)
    _git(["add", name], cwd=project_root)


def _commit_staged(project_root, msg):
    """Commit whatever is currently staged (advances HEAD without changing
    the working tree contents) -- used after a round that reviewed a staged
    diff, so the NEXT round's ledger-anchored delta path has a real,
    committed head_sha to diff against (delta re-review's fast path,
    prior_head resolved + ancestor-of-HEAD, never touches origin either)."""
    _git(["commit", "-q", "-m", msg], cwd=project_root)
    return _git(["rev-parse", "HEAD"], cwd=project_root).stdout.strip()


def _make_stub_llm_client(tmpdir, envelopes_by_round, capture_diffs=False):
    """Stub llm-client.sh that returns one envelope per call, in order
    (clamped to the last one once exhausted). When capture_diffs is True,
    also writes each invocation's stdin (the diff) to
    <tmpdir>/diffs/round-N.txt so tests can assert on delta-scoping."""
    scripts_dir = os.path.join(tmpdir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    counter_file = os.path.join(tmpdir, "round-counter")
    envelopes_json_path = os.path.join(tmpdir, "envelopes.json")
    diffs_dir = os.path.join(tmpdir, "diffs")
    os.makedirs(diffs_dir, exist_ok=True)
    with open(envelopes_json_path, "w") as f:
        json.dump(envelopes_by_round, f)

    script = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import json, os, sys

        role = sys.argv[1] if len(sys.argv) > 1 else ""
        counter_file = {counter_file!r}
        envelopes_path = {envelopes_json_path!r}
        diffs_dir = {diffs_dir!r}
        capture_diffs = {capture_diffs!r}

        diff_text = sys.stdin.read()

        if role != "review":
            sys.stderr.write("stub llm-client.sh: unexpected role %r\\n" % role)
            sys.exit(1)

        try:
            with open(counter_file) as cf:
                n = int(cf.read().strip() or "0")
        except FileNotFoundError:
            n = 0
        n += 1
        with open(counter_file, "w") as cf:
            cf.write(str(n))

        if capture_diffs:
            with open(os.path.join(diffs_dir, "round-%d.txt" % n), "w") as df:
                df.write(diff_text)

        with open(envelopes_path) as ef:
            envelopes = json.load(ef)

        idx = min(n - 1, len(envelopes) - 1)
        sys.stdout.write(json.dumps(envelopes[idx]))
    """)
    with open(stub, "w") as f:
        f.write(script)
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return tmpdir


def _setup_fake_tool_home(fake_tool_home):
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
    for fname in os.listdir(real_scripts_dir):
        if not fname.endswith(".sh"):
            continue
        if fname == "llm-client.sh":
            continue
        src = os.path.join(real_scripts_dir, fname)
        dst = os.path.join(scripts_dir, fname)
        if not os.path.exists(dst):
            os.symlink(src, dst)
    real_share = os.path.join(TOOL_HOME, "share")
    fake_share = os.path.join(fake_tool_home, "share")
    if not os.path.exists(fake_share) and os.path.isdir(real_share):
        os.symlink(real_share, fake_share)


def _run_review(extra_args, fake_tool_home, project_root, env_overrides=None):
    _setup_fake_tool_home(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    if env_overrides:
        env.update(env_overrides)
    cmd = ["sh", fake_gates, "review"] + extra_args
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=project_root)


def _run_merge_gate(fake_tool_home, project_root, decision="approve", env_overrides=None):
    _setup_fake_tool_home(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    # merge-gate's own llm-client.sh invocation (role="merge-gate") needs a
    # stub too -- separate from the review stub, always returns a fixed
    # decision (this suite is testing the STALE-PAYLOAD short-circuit path,
    # which never reaches the LLM call at all when it fires correctly).
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    stub = os.path.join(scripts_dir, "llm-client.sh")
    payload = json.dumps({"decision": decision, "reason": "test"})
    with open(stub, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            echo called >> {os.path.join(fake_tool_home, "merge_gate_calls.txt")!r}
            printf '%s\\n' '{payload}'
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    if env_overrides:
        env.update(env_overrides)
    cmd = ["sh", fake_gates, "merge-gate"]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=project_root)


_CLEAN_ENVELOPE = {"summary": "clean", "checked": ["security"], "findings": []}


def _finding(message="a finding", file="app.py", line=2, severity="high"):
    return {
        "severity": severity, "file": file, "line": line, "category": "security",
        "message": message, "evidence": "x", "suggestion": "y",
        "issue_class": "none — isolated", "class_fix": "n/a — isolated",
    }


def _envelope(findings):
    return {"summary": "test", "checked": ["security"], "findings": findings}


def _ledger_path(project_root):
    return os.path.join(project_root, ".clagentic", "lite", "review-ledger.jsonl")


def _read_ledger_entries(project_root, branch):
    path = _ledger_path(project_root)
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("branch") == branch:
                out.append(entry)
    return out


class TestReviewLedgerViaCmdReview(unittest.TestCase):
    """AC1, AC2, AC3, AC5, AC6."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-ledger-e2e-")
        self._project = _setup_project(self._tmpdir)
        _init_git_repo_no_remote(self._project)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # --------------------------------------------------------------- AC1/AC2
    def test_anchored_pass_verdict_recorded_with_base_and_head_sha(self):
        """Given a completed review on branch B at HEAD X, the ledger
        contains a verdict entry keyed to (base_sha, X) with structured
        findings. Round 1 uses a STAGED diff -- get_review_diff's highest
        priority path, needed here because this repo has no remote (AC6)
        and a committed-but-unstaged round-1 diff would otherwise fall
        through to the branch-diff-against-default path, which requires
        proving origin/<default> freshness and cannot on a remoteless repo
        (a PRE-EXISTING gates.sh property, unrelated to this task)."""
        # HEAD at review time is the seed commit from setUp() -- a staged
        # (uncommitted) diff is reviewed ON TOP OF that commit, so the
        # anchor _git_repo_scoped_head_sha resolves (and the ledger
        # records) is the seed commit's SHA, not a SHA that "contains" the
        # staged content -- staging never moves HEAD, only committing does
        # (same anchor semantics _stamp_envelope's pre-existing SHA stamp
        # already used before this task).
        head_x = _git(["rev-parse", "HEAD"], cwd=self._project).stdout.strip()
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        result = _run_review([], self._tmpdir, self._project)
        self.assertEqual(result.returncode, 0, result.stderr)

        entries = _read_ledger_entries(self._project, "feat/example")
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["head_sha"], head_x)
        self.assertEqual(entry["verdict"], "pass")
        self.assertIn("findings", entry)
        self.assertEqual(entry["findings"], [])
        self.assertIn("base_sha", entry)
        self.assertIn("config", entry)
        self.assertIn("block_severity", entry["config"])
        self.assertIn("ts", entry)

    def test_block_verdict_recorded_with_findings(self):
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding()])])
        result = _run_review([], self._tmpdir, self._project)
        self.assertEqual(result.returncode, 1, result.stderr)

        entries = _read_ledger_entries(self._project, "feat/example")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["verdict"], "block")
        self.assertEqual(len(entries[0]["findings"]), 1)
        self.assertEqual(entries[0]["findings"][0]["message"], "a finding")

    # ------------------------------------------------------------------ AC2
    def test_unanchored_when_head_unresolvable_never_reads_as_pass(self):
        """A verdict with no resolvable head SHA is recorded as unanchored
        and treated as NO verdict by consumers (proven via the merge-gate
        consumption test class below for the 'treated as no verdict' half;
        this half proves the RECORDING side using a non-git REPO_ROOT)."""
        non_git_dir = os.path.join(self._tmpdir, "not-a-repo")
        os.makedirs(non_git_dir, exist_ok=True)
        _setup_project(non_git_dir)
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        result = _run_review([], self._tmpdir, non_git_dir)
        # get_review_diff prints "REPO_ROOT is not a git repo — empty diff"
        # and cmd_review still runs the (empty-diff) review; the ledger
        # write path is still exercised with an empty head_sha.
        self.assertIn("not a git repo", result.stderr)
        ledger_path = _ledger_path(non_git_dir)
        if os.path.exists(ledger_path):
            with open(ledger_path) as f:
                lines = [l for l in f.read().split("\n") if l]
            for line in lines:
                entry = json.loads(line)
                self.assertEqual(entry["verdict"], "unanchored",
                                  "a review with no resolvable head_sha must "
                                  "never be recorded as pass/block")

    # ------------------------------------------------------------------ AC5
    def test_finding_marked_recurring_on_second_round(self):
        """Given a finding that appeared in a prior round on the same
        branch, when it appears again, the ledger marks it recurring. Both
        rounds use a staged diff (get_review_diff's highest-priority path,
        no remote needed) -- delta-scoping itself is covered separately by
        test_delta_review_is_default_second_round_scoped_to_new_commit_only;
        this test is purely about the recurrence ANNOTATION."""
        env_off = {"CLAGENTIC_CROSS_ROUND_DEDUP": "0"}

        _stage_file(self._project, "feature.py", "print('hi')\nprint('bye')\n")
        _commit_staged(self._project, "add feature")
        # Re-stage the SAME content as a no-op modification so round 1 has
        # a staged diff to review (get_review_diff's staged-diff priority
        # path) -- the committed baseline above exists so round 2's delta
        # diff has something to compare against.
        _stage_file(self._project, "feature.py", "print('hi')\nprint('bye')\nx = 1\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding(file="feature.py", line=3)])])
        r1 = _run_review([], self._tmpdir, self._project, env_off)
        self.assertEqual(r1.returncode, 1, r1.stderr)

        entries = _read_ledger_entries(self._project, "feat/example")
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["findings"][0]["_ledger_recurring"],
                          "the very first report of a finding must not be marked recurring")

        _commit_staged(self._project, "round 1 commit")
        _stage_file(self._project, "feature2.py", "print('another')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding(file="feature.py", line=3)])])
        r2 = _run_review([], self._tmpdir, self._project, env_off)
        self.assertEqual(r2.returncode, 1, r2.stderr)

        entries = _read_ledger_entries(self._project, "feat/example")
        self.assertEqual(len(entries), 2)
        second = entries[1]
        recurring_flags = [f["_ledger_recurring"] for f in second["findings"]]
        self.assertIn(True, recurring_flags,
                       "a finding reported in a prior round, reported again, "
                       "must be marked _ledger_recurring: true")

    def test_ledger_recurrence_never_touches_severity_or_blocking(self):
        """Recording recurrence must never demote severity or exempt a
        finding from blocking -- that policy (lr-66e598) is explicitly not
        resurrected by this task. A recurring finding still blocks."""
        env_off = {"CLAGENTIC_CROSS_ROUND_DEDUP": "0"}
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding(file="feature.py", line=1)])])
        r1 = _run_review([], self._tmpdir, self._project, env_off)
        self.assertEqual(r1.returncode, 1, r1.stderr)
        _commit_staged(self._project, "round 1 commit")

        _stage_file(self._project, "feature2.py", "print('another')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding(file="feature.py", line=1)])])
        r2 = _run_review([], self._tmpdir, self._project, env_off)
        self.assertEqual(r2.returncode, 1,
                          "a recurring finding recorded by the ledger must still block -- "
                          "the ledger's _ledger_recurring marker carries no severity-demotion "
                          "policy of its own (severity_blockers() never reads it)")

    # ------------------------------------------------------------------ AC3
    def test_delta_review_is_default_second_round_scoped_to_new_commit_only(self):
        """When a branch has a prior verdicted head_sha, review evaluates
        only that SHA..HEAD by default -- proven by asserting the SECOND
        round's diff sent to the reviewer contains only the second commit's
        change, not the first commit's. Round 1 uses a LOCAL-FILE-REMOTE
        fixture (still fully offline) so its review covers "first.py" via
        the pre-existing branch-diff-against-default path, establishing a
        ledger head_sha whose commit genuinely contains first.py's addition
        -- round 2 then commits a NEW file and relies purely on the delta
        path (never touches the remote again -- prior_head resolves as an
        ancestor of HEAD directly)."""
        project2 = os.path.join(self._tmpdir, "project-with-remote")
        _init_git_repo_with_local_file_remote(self._tmpdir, project2)
        _stage_file(project2, "first.py", "first content\n")
        _commit_staged(project2, "first commit")
        _git(["push", "-q", "-u", "origin", "feat/example"], cwd=project2)
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE, _CLEAN_ENVELOPE], capture_diffs=True)
        r1 = _run_review([], self._tmpdir, project2)
        self.assertEqual(r1.returncode, 0, r1.stderr)

        _commit_file(project2, "second.py", "second content\n", "second commit")
        r2 = _run_review([], self._tmpdir, project2)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("delta re-review", r2.stderr)

        diff_round2 = os.path.join(self._tmpdir, "diffs", "round-2.txt")
        self.assertTrue(os.path.exists(diff_round2))
        with open(diff_round2) as f:
            diff_text = f.read()
        self.assertIn("second.py", diff_text)
        self.assertNotIn("first.py", diff_text,
                          "the default delta re-review must scope round 2's diff to "
                          "ONLY the new commit, not re-include round 1's already-verdicted change")

    def test_full_review_flag_forces_full_range_regardless_of_ledger(self):
        """--full-review forces the full-branch-diff-against-default path
        (pre-existing gates.sh mechanism, requires a resolvable origin/<default>
        to prove freshness) -- uses a SEPARATE project fixture (with a
        local-file-remote), still fully offline/local, no network host
        involved -- distinct from setUp()'s no-remote self._project, which
        this path cannot use (already committed/branched with no remote)."""
        project2 = os.path.join(self._tmpdir, "project-with-remote")
        _init_git_repo_with_local_file_remote(self._tmpdir, project2)
        _stage_file(project2, "first.py", "first content\n")
        _commit_staged(project2, "first commit")
        _git(["push", "-q", "-u", "origin", "feat/example"], cwd=project2)
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE, _CLEAN_ENVELOPE], capture_diffs=True)
        r1 = _run_review([], self._tmpdir, project2)
        self.assertEqual(r1.returncode, 0, r1.stderr)

        _stage_file(project2, "second.py", "second content\n")
        _commit_staged(project2, "second commit")
        r2 = _run_review(["--full-review"], self._tmpdir, project2)
        self.assertEqual(r2.returncode, 0, r2.stderr)

        diff_round2 = os.path.join(self._tmpdir, "diffs", "round-2.txt")
        with open(diff_round2) as f:
            diff_text = f.read()
        self.assertIn("second.py", diff_text)
        self.assertIn("first.py", diff_text,
                       "--full-review must include the FULL branch diff, "
                       "not just the delta since the prior verdict")

    def test_no_prior_verdict_first_round_is_full_range_and_says_so(self):
        project2 = os.path.join(self._tmpdir, "project-with-remote")
        _init_git_repo_with_local_file_remote(self._tmpdir, project2)
        _stage_file(project2, "first.py", "first content\n")
        _commit_staged(project2, "first commit")
        _git(["push", "-q", "-u", "origin", "feat/example"], cwd=project2)
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        r1 = _run_review([], self._tmpdir, project2)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertIn("no prior passing anchored verdict", r1.stderr)

    # ------------------------------------------------------------------ AC4
    def test_rebase_invalidates_prior_sha_falls_back_to_full_range_and_says_so(self):
        """Given a rebase that invalidates the prior verdicted SHA, when
        review runs, it falls back to full-range review and says so in
        output. The fallback itself needs a resolvable origin/<default>
        (pre-existing full-range path), so this uses a separate
        local-file-remote project fixture; the DETECTION of the invalidated
        SHA is proven purely from local git state (rev-parse + merge-base
        --is-ancestor), independent of the remote."""
        project2 = os.path.join(self._tmpdir, "project-with-remote")
        _init_git_repo_with_local_file_remote(self._tmpdir, project2)
        _stage_file(project2, "first.py", "first content\n")
        _commit_staged(project2, "first commit")
        _git(["push", "-q", "-u", "origin", "feat/example"], cwd=project2)
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE, _CLEAN_ENVELOPE], capture_diffs=True)
        r1 = _run_review([], self._tmpdir, project2)
        self.assertEqual(r1.returncode, 0, r1.stderr)

        # Simulate a rebase/amend: rewrite the tip commit so the prior
        # verdicted SHA is no longer reachable as an ancestor of HEAD.
        _git(["commit", "--amend", "-q", "-m", "first commit (amended)"], cwd=project2)
        _stage_file(project2, "second.py", "second content\n")
        _commit_staged(project2, "second commit")

        r2 = _run_review([], self._tmpdir, project2)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("no longer an ancestor of HEAD", r2.stderr,
                       "an amend/rebase must be detected and reported on stderr")
        self.assertIn("full-range", r2.stderr)

        diff_round2 = os.path.join(self._tmpdir, "diffs", "round-2.txt")
        with open(diff_round2) as f:
            diff_text = f.read()
        self.assertIn("second.py", diff_text)
        self.assertIn("first.py", diff_text,
                       "fallback must widen to full-range coverage, "
                       "never silently narrow after an unresolvable prior SHA")

    # ------------------------------------------------------------------ AC6
    def test_since_last_review_flag_still_accepted_as_noop(self):
        """Backward compatibility: --since-last-review is still accepted
        (it names the same behavior that is now the default)."""
        _stage_file(self._project, "first.py", "first content\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        result = _run_review(["--since-last-review"], self._tmpdir, self._project)
        self.assertEqual(result.returncode, 0, result.stderr)


class TestMergeGateLedgerConsumption(unittest.TestCase):
    """AC3 (stale verdict refused), AC6 (no remote)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-ledger-mg-")
        self._project = _setup_project(self._tmpdir)
        _init_git_repo_no_remote(self._project)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _merge_gate_calls(self):
        path = os.path.join(self._tmpdir, "merge_gate_calls.txt")
        if not os.path.exists(path):
            return 0
        with open(path) as f:
            return f.read().count("called")

    def test_passing_verdict_at_head_lets_merge_gate_proceed(self):
        """Given a passing verdict at X and HEAD still X, merge-gate must
        NOT refuse on staleness grounds (it may still call the LLM, which
        the stub approves). Review runs against a staged diff (no remote
        needed) -- the ledger's recorded head_sha is the commit BENEATH the
        staged change (staging never moves HEAD), so HEAD must NOT advance
        past that commit afterward, or the anchor would legitimately go
        stale -- this test deliberately leaves the staged edit uncommitted."""
        _stage_file(self._project, "feature.py", "print('hi')\n")
        head = _commit_staged(self._project, "add feature")
        _stage_file(self._project, "feature.py", "print('hi')\nprint('again')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        r1 = _run_review([], self._tmpdir, self._project)
        self.assertEqual(r1.returncode, 0, r1.stderr)

        # Also need a last-adversarial.md stamp fresh at the same HEAD, or
        # build_gate_summary's existing adversarial-staleness check fires
        # instead -- write one directly, stamped, matching the existing
        # merge-gate test fixtures' pattern (test_wrapper_staleness.py).
        ad_path = os.path.join(self._project, ".clagentic", "lite", "last-adversarial.md")
        with open(ad_path, "w") as f:
            f.write(f"<!-- clagentic-diff-sha: {head} -->\n# Adversarial audit\nclean\n")

        r2 = _run_merge_gate(self._tmpdir, self._project, decision="approve")
        self.assertEqual(r2.returncode, 0, f"stdout={r2.stdout!r} stderr={r2.stderr!r}")
        self.assertEqual(self._merge_gate_calls(), 1,
                          "an anchored pass at current HEAD must let merge-gate reach the LLM call")

    def test_new_commit_after_verdict_refuses_as_stale_no_llm_call(self):
        """Given a passing verdict at X and a new commit Y on B, when
        ship/merge-gate runs, it refuses to treat X's verdict as current and
        requires review at Y -- deterministically, without an LLM call."""
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        r1 = _run_review([], self._tmpdir, self._project)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        _commit_staged(self._project, "add feature")

        head_x = _git(["rev-parse", "HEAD"], cwd=self._project).stdout.strip()
        ad_path = os.path.join(self._project, ".clagentic", "lite", "last-adversarial.md")
        with open(ad_path, "w") as f:
            f.write(f"<!-- clagentic-diff-sha: {head_x} -->\n# Adversarial audit\nclean\n")

        # New commit Y -- HEAD moves past the ledger's verdicted SHA.
        _commit_file(self._project, "more.py", "print('more')\n", "commit Y")

        r2 = _run_merge_gate(self._tmpdir, self._project, decision="approve")
        self.assertEqual(r2.returncode, 1,
                          f"merge-gate must refuse when HEAD has moved past the ledger's "
                          f"verdicted SHA\nstdout={r2.stdout}\nstderr={r2.stderr}")
        self.assertEqual(self._merge_gate_calls(), 0,
                          "a stale-payload refusal must be deterministic -- no LLM call")
        self.assertIn("stale", r2.stdout.lower())

    def test_no_review_ever_run_on_this_branch_refuses(self):
        """A branch with a ledger (this repo HAS used the review-ledger
        feature, via a review on a DIFFERENT branch) but no verdict of its
        own at all must still refuse -- 'missing verdict-at-HEAD means
        re-review, never proceed' applies per-branch, not merely per-repo.
        (There is no ledger-totally-absent bootstrap exemption at all as of
        the lr-01ae73 PEACHES/coordinator fold-in on PR #162 -- see
        test_hand_written_last_review_with_no_ledger_never_passes below for
        that narrower, now-closed case.)"""
        # Branch off feat/example (setUp's default) into a SEPARATE branch,
        # review there (seeding a ledger entry keyed to THAT branch), then
        # switch back to feat/example, which never had its own review.
        _git(["checkout", "-q", "-b", "feat/other-branch"], cwd=self._project)
        _stage_file(self._project, "other.py", "print('other')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        r_other = _run_review([], self._tmpdir, self._project)
        self.assertEqual(r_other.returncode, 0, r_other.stderr)
        _commit_staged(self._project, "other branch commit")

        _git(["checkout", "-q", "feat/example"], cwd=self._project)
        _commit_file(self._project, "feature.py", "print('hi')\n", "add feature (never reviewed)")
        head = _git(["rev-parse", "HEAD"], cwd=self._project).stdout.strip()
        ad_path = os.path.join(self._project, ".clagentic", "lite", "last-adversarial.md")
        with open(ad_path, "w") as f:
            f.write(f"<!-- clagentic-diff-sha: {head} -->\n# Adversarial audit\nclean\n")

        r = _run_merge_gate(self._tmpdir, self._project, decision="approve")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertEqual(self._merge_gate_calls(), 0)

    def test_blocked_verdict_at_head_still_refuses(self):
        """A ledger verdict of 'block' at current HEAD must never be
        misread as an anchored pass -- isolates the property from mere
        staleness (test_new_commit_after_verdict_... already covers that
        case) by leaving the staged edit uncommitted, so HEAD stays exactly
        at the SHA the block verdict was recorded against (same pattern as
        test_passing_verdict_at_head_lets_merge_gate_proceed)."""
        _stage_file(self._project, "feature.py", "print('hi')\n")
        head = _commit_staged(self._project, "add feature")
        _stage_file(self._project, "feature.py", "print('hi')\nprint('again')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding()])])
        r1 = _run_review([], self._tmpdir, self._project)
        self.assertEqual(r1.returncode, 1, r1.stderr)

        ad_path = os.path.join(self._project, ".clagentic", "lite", "last-adversarial.md")
        with open(ad_path, "w") as f:
            f.write(f"<!-- clagentic-diff-sha: {head} -->\n# Adversarial audit\nclean\n")

        r2 = _run_merge_gate(self._tmpdir, self._project, decision="approve")
        self.assertEqual(r2.returncode, 1)
        self.assertEqual(self._merge_gate_calls(), 0,
                          "a ledger entry recorded as verdict=block at HEAD must never "
                          "be read as an anchored pass by the merge gate")

    def test_hand_written_last_review_with_no_ledger_never_passes(self):
        """PEACHES/coordinator finding on PR #162 (comment 5260223912): a
        repo with NO ledger file at all and a hand-written, correctly-
        SHA-stamped last-review.json must NOT pass the merge gate. Before
        this fix, a "no ledger file exists" bootstrap exemption let this
        exact scenario through -- indistinguishable from a ledger deleted
        specifically to bypass the anchored-verdict requirement, and
        contradicting item 4 ("stale or missing verdict-at-HEAD means
        re-review, never proceed") permanently for any repo/tooling path
        that never calls cmd_review. This never invokes cmd_review at all
        -- last-review.json is hand-written directly, exactly the shape
        item 4 must close."""
        _commit_file(self._project, "feature.py", "print('hi')\n", "add feature")
        head = _git(["rev-parse", "HEAD"], cwd=self._project).stdout.strip()

        clagentic_dir = os.path.join(self._project, ".clagentic", "lite")
        os.makedirs(clagentic_dir, exist_ok=True)
        review_path = os.path.join(clagentic_dir, "last-review.json")
        with open(review_path, "w") as f:
            json.dump({"summary": "clean", "checked": [], "findings": [],
                       "_clagentic_diff_sha": head}, f)

        ad_path = os.path.join(clagentic_dir, "last-adversarial.md")
        with open(ad_path, "w") as f:
            f.write(f"<!-- clagentic-diff-sha: {head} -->\n# Adversarial audit\nclean\n")

        ledger_path = _ledger_path(self._project)
        self.assertFalse(os.path.exists(ledger_path),
                          "test setup must produce a repo with NO ledger file at all")

        r = _run_merge_gate(self._tmpdir, self._project, decision="approve")
        self.assertEqual(r.returncode, 1,
                          f"a hand-written, freshly-stamped last-review.json with NO "
                          f"ledger entry must still refuse -- there is no bootstrap "
                          f"exemption\nstdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertEqual(self._merge_gate_calls(), 0,
                          "the refusal must be deterministic -- no LLM call")
        self.assertIn("stale", r.stdout.lower())


if __name__ == "__main__":
    unittest.main()
