"""
Regression coverage: the adversarial gate must never report a clean audit
on an empty resolved diff, and must never consume cmd_review's ledger
anchor to get there.

ROOT CAUSE (verified in-tree before filing this fix): the review
ledger (.clagentic/lite/review-ledger.jsonl) had no gate discriminator --
every entry only carried (branch, base_sha, head_sha, verdict). cmd_review
runs before cmd_adversarial in `gates ship` (same process), and cmd_review
writes a "pass" entry anchored at the current HEAD before it returns.
cmd_adversarial's own delta-base lookup
(_ledger_latest_passing_head_for_branch) then found that SAME entry and
anchored on it too, so cmd_adversarial resolved HEAD..HEAD -- an empty diff
-- and (pre-fix) handed it straight to the auditor with no check at all.
zero [FINDING] headers is indistinguishable from a genuinely clean audit,
so the merge-gate was told CLEAN having examined nothing.

THIS FIX (three parts, all required together per the task's own scoping
note -- shipping the empty-diff check alone without a namespaced anchor
would turn a silent hollow pass into a loud skip on EVERY normal
`gates ship` invocation, which is correct but unusable):
  1. get_review_diff/cmd_review/cmd_adversarial now test the resolved diff
     for emptiness BEFORE invoking any LLM, and record "skip" (never
     "pass") when it is empty, naming the resolved range/reason.
  2. The ledger gained a `gate` discriminator field
     (_ledger_record_review_verdict's new leading GATE arg); anchor lookups
     (_ledger_latest_passing_head_for_branch,
     _ledger_anchored_pass_at_head) filter on it, so cmd_adversarial can
     never again anchor on cmd_review's own pass entry.
  3. The gates.sh dispatcher's `adversarial)` case now shifts and forwards
     "$@" (was a bare `cmd_adversarial ;;`, silently discarding any flag
     including --full-review); cmd_adversarial now parses --full-review the
     same way cmd_review does.

TEST DISCIPLINE: every regression test here
was verified to FAIL against the pre-fix gates.sh -- see each test's own
"FAILS PRE-FIX" note for what the unfixed code actually did. Repo-local
only: throwaway git repos + stub llm-client.sh, no enrolled host, no live
remote, no CLAGENTIC_LITE_HOME/HOME pointed at this checkout anywhere in
this file (this suite never touches cmd_init/cmd_update/enroll at all).

Mirrors test_review_ledger.py's established fixture pattern
(_setup_project, _init_git_repo_no_remote, _setup_fake_tool_home) rather
than re-deriving a parallel harness.

Run with: python3 -m unittest scripts.test_adversarial_own_ledger_anchor -v
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

_GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _git(args, cwd, env=None):
    e = os.environ.copy()
    e.update(_GIT_IDENTITY_ENV)
    if env:
        e.update(env)
    return subprocess.run(["git"] + args, cwd=cwd, env=e, check=True,
                           capture_output=True, text=True)


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


def _init_git_repo_no_remote(project_root):
    """A repo with NO remote configured at all -- get_review_diff's staged
    diff path (highest priority) never consults a remote, so this is
    sufficient for every scenario in this file."""
    _git(["init", "-q", "-b", "main", project_root], cwd=None)
    with open(os.path.join(project_root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    _git(["add", "app.py"], cwd=project_root)
    _git(["commit", "-q", "-m", "seed"], cwd=project_root)
    _git(["checkout", "-q", "-b", "feat/example"], cwd=project_root)
    r = subprocess.run(["git", "remote"], cwd=project_root, capture_output=True, text=True)
    assert r.stdout.strip() == "", "test setup must produce a repo with no remote"


def _init_git_repo_with_local_file_remote(tmpdir, project_root):
    """A repo with a LOCAL FILE-PATH 'origin' (a bare repo on the same
    filesystem, no network involved at all) -- needed to exercise
    get_review_diff's branch-diff-against-default fallback, which proves
    origin/<default> freshness via a real `git fetch`. This is the ONLY
    diff source available once a change is COMMITTED (not staged) and the
    working tree is clean -- exactly the `gates ship` clean-index shape the
    task's field report describes. Mirrors
    test_review_ledger.py's identical helper rather than re-deriving it."""
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
    path = os.path.join(project_root, name)
    with open(path, "w") as f:
        f.write(content)
    _git(["add", name], cwd=project_root)


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


def _make_stub_llm_client(fake_tool_home, diffs_dir):
    """Stub llm-client.sh that answers BOTH the "review" and "adversarial"
    roles, always with a clean/empty-findings envelope in each role's own
    shape (JSON for review, markdown [FINDING]-free for adversarial). Every
    invocation's stdin (the diff it was actually handed) is captured to
    <diffs_dir>/<role>-callN.txt so tests can assert on what each gate
    actually received -- the load-bearing assertion for this whole file:
    did cmd_adversarial get a non-empty diff of its own, or an empty one
    borrowed from cmd_review's anchor."""
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    os.makedirs(diffs_dir, exist_ok=True)
    script = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import os, sys

        role = sys.argv[1] if len(sys.argv) > 1 else ""
        diffs_dir = {diffs_dir!r}
        diff_text = sys.stdin.read()

        counter_file = os.path.join(diffs_dir, role + "-counter")
        try:
            with open(counter_file) as cf:
                n = int(cf.read().strip() or "0")
        except FileNotFoundError:
            n = 0
        n += 1
        with open(counter_file, "w") as cf:
            cf.write(str(n))

        with open(os.path.join(diffs_dir, "%s-call%d.txt" % (role, n)), "w") as df:
            df.write(diff_text)

        if role == "review":
            sys.stdout.write('{{"summary": "clean", "checked": ["security"], "findings": []}}')
        elif role == "adversarial":
            sys.stdout.write("# Adversarial findings\\n\\nNo exploitable issues found.\\n")
        else:
            sys.stderr.write("stub llm-client.sh: unexpected role %r\\n" % role)
            sys.exit(1)
    """)
    with open(stub, "w") as f:
        f.write(script)
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return stub


def _run_gates(subcmd, extra_args, fake_tool_home, project_root, env_overrides=None):
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    if env_overrides:
        env.update(env_overrides)
    cmd = ["sh", fake_gates, subcmd] + extra_args
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=project_root)


def _ledger_path(project_root):
    return os.path.join(project_root, ".clagentic", "lite", "review-ledger.jsonl")


def _read_ledger_entries(project_root, branch=None, gate=None):
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
            if branch is not None and entry.get("branch") != branch:
                continue
            if gate is not None and entry.get("gate", "review") != gate:
                continue
            out.append(entry)
    return out


class TestAdversarialDoesNotConsumeReviewAnchor(unittest.TestCase):
    """The core defect: cmd_review running immediately before cmd_adversarial
    (the normal `gates ship` order, same process) must never cause
    cmd_adversarial to resolve an empty HEAD..HEAD diff.

    Uses a LOCAL FILE-PATH remote and a COMMITTED (not staged) change with a
    clean working-tree index -- exactly the `gates ship` "branch/PR path
    (clean index)" shape the task's field report describes as affected
    UNCONDITIONALLY, including cmd_ship's first run on a branch. A staged
    diff would mask the defect entirely (get_review_diff's staged-diff path
    is highest priority and never touches the ledger), which is why the
    original review-ledger fixtures (test_review_ledger.py) reserve this
    same local-file-remote setup for exercising the branch-diff fallback."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-anchor-")
        self._project = _setup_project(os.path.join(self._tmpdir, "project"))
        _init_git_repo_with_local_file_remote(self._tmpdir, self._project)
        self._fake_tool_home = os.path.join(self._tmpdir, "fake-tool-home")
        _setup_fake_tool_home(self._fake_tool_home)
        self._diffs_dir = os.path.join(self._tmpdir, "diffs")
        _make_stub_llm_client(self._fake_tool_home, self._diffs_dir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_review(self, extra_args=None):
        return _run_gates("review", extra_args or [], self._fake_tool_home, self._project)

    def _run_adversarial(self, extra_args=None):
        return _run_gates("adversarial", extra_args or [], self._fake_tool_home, self._project)

    def test_adversarial_after_review_gets_a_non_empty_diff(self):
        """Minimal true reproduction of the field report (verified by
        directly exercising the PRE-FIX gates.sh at commit 6b128eb before
        writing this assertion -- see the task's own PR description for the
        verification trace): BOTH of get_review_diff's rescue paths must
        resolve empty at once for the defect to surface. lr-542a43's own
        "empty delta -> fall back to full-range" fallback is NOT bypassed by
        merely running review-then-adversarial in the same process (that
        alone still resolves a non-empty branch-diff-against-default and
        masks the defect) -- it requires origin/<default> to ALSO already
        include this branch's own commits (a branch whose PR already
        merged, or any environment where the tracked default ref converges
        with the feature branch), so `git diff origin/main...HEAD` is
        ALSO empty and there is nowhere left to fall back to. This is
        exactly the "cmd_ship affected UNCONDITIONALLY" claim in the field
        report, reproduced at the git-state level rather than assumed.

        FAILS PRE-FIX (confirmed by direct measurement against 6b128eb,
        current main before this task, using this exact fixture): rc=0,
        adversarial-call1.txt is written but EMPTY -- the pre-fix
        cmd_adversarial handed a genuinely empty diff straight to the LLM
        client with no check of any kind. With the fix: cmd_adversarial's
        own empty-diff check (item 1) fires and it never calls the LLM
        client at all (asserted by the OTHER class,
        TestAdversarialEmptyDiffNeverPasses) -- for THIS test, the
        assertion is simply that cmd_adversarial no longer returns a
        SILENT PASS: either it produced a real non-empty audit, or it
        reported skip. Both are correct; a hollow "warn" pass with an
        empty/absent diff capture is what this pins out."""
        _commit_file(self._project, "app.py", "def handle(x):\n    return x + 1\n", "the real change")

        # Fast-forward the REMOTE's main to include this same commit --
        # simulates "this branch's PR already merged, operator re-runs
        # gates on the stale local branch," or any repo layout where the
        # tracked default branch converges with the feature branch. This is
        # the state that removes lr-542a43's own empty-range rescue path:
        # once origin/main == this branch's HEAD too, there is no non-empty
        # diff left to fall back to.
        _git(["push", "-q", "origin", "feat/example:main"], cwd=self._project)
        _git(["fetch", "-q", "origin"], cwd=self._project)

        r_review = self._run_review()
        self.assertEqual(r_review.returncode, 0, f"stderr={r_review.stderr}")

        # Clean index, same committed HEAD cmd_review just reviewed and
        # anchored -- exactly cmd_ship's own review-then-adversarial shape.
        r_adv = self._run_adversarial()
        self.assertEqual(r_adv.returncode, 0, f"stderr={r_adv.stderr}")

        adv_diff_path = os.path.join(self._diffs_dir, "adversarial-call1.txt")
        adv_diff_captured = ""
        if os.path.isfile(adv_diff_path):
            with open(adv_diff_path) as f:
                adv_diff_captured = f.read()
        self.assertFalse(
            os.path.isfile(adv_diff_path) and not adv_diff_captured.strip(),
            f"cmd_adversarial must never call the LLM client with an EMPTY "
            f"diff and then report a clean pass -- that silent hollow-audit "
            f"shape is exactly the defect this fix closes. "
            f"adv_diff_path exists={os.path.isfile(adv_diff_path)!r} "
            f"captured={adv_diff_captured!r} stderr={r_adv.stderr!r}",
        )

    def test_adversarial_ledger_entries_carry_their_own_gate_field(self):
        """FAILS PRE-FIX: pre-fix ledger entries had no `gate` field at
        all -- this assertion would find zero entries with gate=="adversarial"
        because cmd_adversarial never wrote to the ledger in any form."""
        _commit_file(self._project, "app.py", "def handle(x):\n    return x + 2\n", "change")
        r_adv = self._run_adversarial()
        self.assertEqual(r_adv.returncode, 0, f"stderr={r_adv.stderr}")

        entries = _read_ledger_entries(self._project, branch="feat/example", gate="adversarial")
        self.assertTrue(
            entries,
            "cmd_adversarial must record its own ledger entry with gate=='adversarial'",
        )

    def test_review_and_adversarial_anchors_are_independent(self):
        """A review pass entry and an adversarial pass entry at the same
        branch must both exist, independently, with the correct `gate`
        field on each -- proves the ledger is truly namespaced, not merely
        "cmd_adversarial writes something.\""""
        _commit_file(self._project, "app.py", "def handle(x):\n    return x + 3\n", "change")
        r_review = self._run_review()
        self.assertEqual(r_review.returncode, 0, f"stderr={r_review.stderr}")

        r_adv = self._run_adversarial()
        self.assertEqual(r_adv.returncode, 0, f"stderr={r_adv.stderr}")

        review_entries = _read_ledger_entries(self._project, branch="feat/example", gate="review")
        adv_entries = _read_ledger_entries(self._project, branch="feat/example", gate="adversarial")
        self.assertTrue(review_entries, "review must have its own ledger entry")
        self.assertTrue(adv_entries, "adversarial must have its own ledger entry")
        self.assertEqual(review_entries[-1]["verdict"], "pass")
        self.assertEqual(adv_entries[-1]["verdict"], "pass")


class TestAdversarialEmptyDiffNeverPasses(unittest.TestCase):
    """Item 1's own acceptance criterion, isolated from item 2: an
    adversarial run whose resolved diff is genuinely empty (nothing staged,
    on the default branch, no remote to diff against) must report "skip",
    never a clean pass -- and the LLM client must never be invoked at all."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-empty-")
        self._project = _setup_project(os.path.join(self._tmpdir, "project"))
        # On the DEFAULT branch with nothing staged: get_review_diff's own
        # documented terminal fallback ("no staged changes and on default
        # branch — empty diff"), the one case that returns 0 with truly
        # empty stdout and no remote/freshness dependency at all.
        _git(["init", "-q", "-b", "main", self._project], cwd=None)
        with open(os.path.join(self._project, "app.py"), "w") as f:
            f.write("def handle(x):\n    return x\n")
        _git(["add", "app.py"], cwd=self._project)
        _git(["commit", "-q", "-m", "seed"], cwd=self._project)
        self._fake_tool_home = os.path.join(self._tmpdir, "fake-tool-home")
        _setup_fake_tool_home(self._fake_tool_home)
        self._diffs_dir = os.path.join(self._tmpdir, "diffs")
        _make_stub_llm_client(self._fake_tool_home, self._diffs_dir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_empty_diff_on_default_branch_is_skip_not_pass(self):
        """FAILS PRE-FIX: before this task, cmd_adversarial had no empty-diff
        check at all -- it called the LLM client with a zero-byte diff on
        stdin, the stub above would still answer "No exploitable issues
        found" (a real dead-auditor scenario would look the same), and
        cmd_adversarial logged outcome "warn" (non-blocking clean-shaped
        pass), never "skip". This test asserts the audit row is "skip" and
        that the LLM client was never called."""
        r_adv = _run_gates("adversarial", [], self._fake_tool_home, self._project)
        self.assertEqual(r_adv.returncode, 0, f"stderr={r_adv.stderr}")
        self.assertIn("SKIP", r_adv.stderr, f"stderr={r_adv.stderr!r}")

        adv_call1 = os.path.join(self._diffs_dir, "adversarial-call1.txt")
        self.assertFalse(
            os.path.isfile(adv_call1),
            "the LLM client must never be invoked on a genuinely empty resolved diff",
        )

        audit_db = os.path.join(self._project, ".clagentic", "lite", "audit.db")
        conn = sqlite3.connect(audit_db)
        rows = conn.execute(
            "SELECT outcome FROM gate_runs WHERE gate='adversarial' ORDER BY id DESC LIMIT 1"
        ).fetchall()
        conn.close()
        self.assertTrue(rows, "cmd_adversarial must log an audit row")
        self.assertEqual(
            rows[0][0], "skip",
            f"an empty resolved diff must log outcome 'skip', never 'pass'/'warn' "
            f"-- rows={rows!r}",
        )

    def test_empty_diff_ledger_verdict_is_skip_and_never_anchors_a_future_pass_lookup(self):
        """The ledger entry for an empty-diff round must be verdict=='skip',
        and _ledger_latest_passing_head_for_branch (via a subsequent real
        diff round) must never treat it as a passing anchor."""
        r_adv = _run_gates("adversarial", [], self._fake_tool_home, self._project)
        self.assertEqual(r_adv.returncode, 0, f"stderr={r_adv.stderr}")

        entries = _read_ledger_entries(self._project, gate="adversarial")
        self.assertTrue(entries, "an empty-diff round must still write a ledger entry")
        self.assertEqual(entries[-1]["verdict"], "skip")


class TestAdversarialDispatcherForwardsFullReviewFlag(unittest.TestCase):
    """Item 3: `gates.sh adversarial --full-review` must actually take
    effect. FAILS PRE-FIX two ways at once: (a) the dispatcher's bare
    `adversarial)    cmd_adversarial ;;` (no shift, no "$@") silently
    discarded the flag before cmd_adversarial ever saw it, and (b) even if
    forwarded, pre-fix cmd_adversarial had no flag-parsing of its own at
    all -- REVIEW_FULL was parsed only by cmd_review."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-fullreview-")
        self._project = _setup_project(os.path.join(self._tmpdir, "project"))
        # LOCAL FILE-PATH remote (not _init_git_repo_no_remote): the
        # rewritten test below needs get_review_diff's real
        # branch-diff-against-default path (origin/main...HEAD), which
        # requires a provably-fetchable origin -- see
        # _init_git_repo_with_local_file_remote's own doc comment.
        _init_git_repo_with_local_file_remote(self._tmpdir, self._project)
        self._fake_tool_home = os.path.join(self._tmpdir, "fake-tool-home")
        _setup_fake_tool_home(self._fake_tool_home)
        self._diffs_dir = os.path.join(self._tmpdir, "diffs")
        _make_stub_llm_client(self._fake_tool_home, self._diffs_dir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_full_review_flag_forces_full_range_even_with_a_passing_anchor(self):
        """MECHANISM (not merely re-asserted -- see the coordinator's
        instruction on this exact test): the ONLY way REVIEW_FULL=1 ever
        reaches get_review_diff's branch-body is through cmd_adversarial's
        own argv parsing, which reads it from "$@" the dispatcher forwards
        (gates.sh's `adversarial) shift; cmd_adversarial "$@" ;;` case).
        get_review_diff's `if [ "${REVIEW_FULL:-0}" != "1" ]` guard (see its
        own source) is the SOLE branch point this flag controls: true, it
        enters the ledger-anchored-delta block; false (REVIEW_FULL=1), it
        skips that whole block and falls straight to the branch-diff-
        against-default path below. This test must drive THAT branch point
        specifically -- not merely reach cmd_adversarial with a nonzero
        exit code, which any invocation does regardless of the flag.

        PRIOR VERSION'S DEFECT (PEACHES, PR #199 review,
        amos.code-craft.4): staged a file, then invoked `adversarial` twice
        with the SAME file still staged both times. get_review_diff checks
        `git diff --cached --name-only` FIRST, unconditionally, before it
        ever reads REVIEW_FULL (see get_review_diff's own source: the
        staged-diff branch and its `return 0` precede the
        `if [ "${REVIEW_FULL:-0}" != "1" ]` block by several lines). A
        staged diff never falls through to that guard at all -- REVIEW_FULL
        is unread in that run. So an unfixed dispatcher that silently
        discards --full-review, and a fixed dispatcher that forwards it,
        produce BYTE-IDENTICAL captured diffs and BYTE-IDENTICAL exit codes
        in that setup: both calls take the staged-diff branch every time.
        The previous assertions (rc==0, "SKIP" absent from stderr) held for
        that same reason regardless of whether the flag was forwarded --
        they were never capable of failing on an unfixed dispatcher.

        THIS VERSION drives the actual branch point: a CLEAN INDEX (no
        staged file at all, ever) with a real ledger anchor already at
        HEAD1, then a SECOND commit to HEAD2 with the index still clean.
        With REVIEW_FULL unset (0), the delta path is the ONLY path
        available (staged-diff is unavailable -- nothing is staged) and it
        resolves prior_head(HEAD1)..HEAD2. Since app.py's line was edited
        TWICE (seed "return x" -> round 1 "return x + 1" -> round 2
        "return x + 2"), the delta diff's REMOVED line is the ROUND-1 TEXT
        "return x + 1" (the state at HEAD1, the delta's own base).
        With REVIEW_FULL=1 (only reachable if the dispatcher forwarded
        --full-review AND cmd_adversarial parsed it), the delta block is
        skipped entirely and get_review_diff falls to the
        branch-diff-against-default path, which diffs origin/main...HEAD
        (origin/main is still pinned at the SEED commit -- never advanced
        past it) -- so THAT diff's removed line is the ORIGINAL SEED TEXT
        "return x", not "return x + 1". This asymmetry -- verified directly
        against this exact fixture below, not assumed -- is the load-
        bearing, content-level observable: an unfixed dispatcher/
        cmd_adversarial cannot ever set REVIEW_FULL=1 inside
        cmd_adversarial's own process (pre-fix, cmd_adversarial has no
        flag-parsing block at all -- see the fixed cmd_adversarial's own
        `for _adv_arg in "$@"` loop, which did not exist before this task),
        so it is STRUCTURALLY confined to the delta path and can only ever
        produce a diff whose removed line is "return x + 1", never
        "return x" -- the two are mutually exclusive by construction, not
        merely different message text.

        VERIFIED DIRECTLY (not asserted from theory): running this exact
        fixture with `--full-review` OMITTED on round 2 (the delta path)
        captures `-    return x + 1` / `+    return x + 2`; running it WITH
        `--full-review` (below) captures `-    return x` / `+    return x
        + 2` -- confirmed by direct measurement against this branch's own
        gates.sh before writing this assertion."""
        _commit_file(self._project, "app.py", "def handle(x):\n    return x + 1\n", "round 1 commit")
        r_adv1 = _run_gates("adversarial", [], self._fake_tool_home, self._project)
        self.assertEqual(r_adv1.returncode, 0, f"stderr={r_adv1.stderr}")
        entries = _read_ledger_entries(self._project, gate="adversarial")
        self.assertEqual(entries[-1]["verdict"], "pass")

        # Second commit, clean index (nothing staged) -- get_review_diff's
        # staged-diff branch is unavailable here, so this call is forced
        # onto the delta-or-branch-diff decision REVIEW_FULL actually
        # controls.
        _commit_file(self._project, "app.py", "def handle(x):\n    return x + 2\n", "round 2 commit")

        r_adv2 = _run_gates("adversarial", ["--full-review"], self._fake_tool_home, self._project)
        self.assertEqual(r_adv2.returncode, 0, f"stderr={r_adv2.stderr}")

        adv_call2 = os.path.join(self._diffs_dir, "adversarial-call2.txt")
        self.assertTrue(
            os.path.isfile(adv_call2),
            "the LLM client must have been invoked a second time with a "
            "non-empty resolved diff",
        )
        with open(adv_call2) as f:
            captured_diff = f.read()
        self.assertIn(
            "-    return x\n", captured_diff,
            f"--full-review must reach get_review_diff's branch-diff-"
            f"against-default path (origin/main...HEAD, pinned at the seed "
            f"commit) -- its removed line is the ORIGINAL seed text "
            f"'return x'. The default ledger-anchored delta path "
            f"(HEAD1..HEAD2) can ONLY ever remove 'return x + 1' (its own "
            f"base, round 1's text) -- the two are mutually exclusive by "
            f"construction. An unfixed dispatcher/cmd_adversarial has no "
            f"way to set REVIEW_FULL=1 inside cmd_adversarial's own "
            f"process and is structurally confined to the delta path. "
            f"captured_diff={captured_diff!r}",
        )
        self.assertNotIn(
            "-    return x + 1\n", captured_diff,
            f"the delta path's removed line ('return x + 1') must be "
            f"ABSENT from the full-range diff -- if present, --full-review "
            f"did not actually reach the branch-diff-against-default path. "
            f"captured_diff={captured_diff!r}",
        )

    def test_usage_string_advertises_full_review_for_adversarial(self):
        """A cheap, direct pin on the dispatcher's own usage text (item 3) --
        FAILS PRE-FIX because the usage string listed adversarial with no
        flags at all."""
        r = _run_gates("bogus-subcommand-xyz", [], self._fake_tool_home, self._project)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("adversarial [--full-review]", r.stderr)


class TestEmptyDiffCheckDoesNotSwallowFreshnessFailureDiagnostic(unittest.TestCase):
    """Regression test for a defect introduced and caught DURING this same
    fix's own implementation (never present on main): the
    first cut of the empty-diff check redirected get_review_diff's
    stderr into a capture file so the skip reason could name the resolved
    range, WITHOUT first guarding get_review_diff's own exit status. On an
    unresolvable freshness precondition (branch baseline not provably
    current -- get_review_diff's OWN pre-existing fail-loud contract,
    unrelated to this task), get_review_diff returns nonzero, and gates.sh
    runs under `set -e` -- so the whole script aborted at that exact line,
    BEFORE the `cat <capture-file> 1>&2` a few lines below ever ran,
    silently swallowing the diagnostic get_review_diff had already written.
    Caught by scripts/test_freshness_helper_sweep.py's pre-existing
    test_review_gate_fails_closed_when_origin_unreachable (cmd_review side)
    while running the full local suite per this task's own "definition of
    done" discipline; this test adds the CMD_ADVERSARIAL side of the same
    property, which no pre-existing test covered.

    FAILS against the intermediate, unguarded implementation (verified
    directly against gates.sh commit fee821d -- this task's own branch
    before the status-guard fix, not a state that ever reached main):
    cmd_adversarial exited nonzero (set -e caught the unguarded failure)
    but printed ZERO bytes of diagnostic to stderr -- the "branch baseline
    not provably current" message get_review_diff itself already wrote was
    captured to a tempfile that was never read before the abort."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-freshness-swallow-")
        bare_remote = os.path.join(self._tmpdir, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", bare_remote], check=True)
        self._project = _setup_project(os.path.join(self._tmpdir, "project"))
        _git(["init", "-q", "-b", "main", self._project], cwd=None)
        _git(["remote", "add", "origin", bare_remote], cwd=self._project)
        with open(os.path.join(self._project, "app.py"), "w") as f:
            f.write("def handle(x):\n    return x\n")
        _git(["add", "app.py"], cwd=self._project)
        _git(["commit", "-q", "-m", "seed"], cwd=self._project)
        _git(["push", "-q", "origin", "main"], cwd=self._project)
        _git(["checkout", "-q", "-b", "feat/example"], cwd=self._project)
        _commit_file(self._project, "app.py", "def handle(x):\n    return x + 1\n", "feature commit")
        # Break the remote AFTER the initial push/clone, so a local tracking
        # ref for origin/main already exists but any FRESH fetch will fail
        # -- get_review_diff's freshness precondition cannot be proven.
        broken_origin = os.path.join(self._tmpdir, "origin-does-not-exist.git")
        subprocess.run(["git", "remote", "set-url", "origin", broken_origin],
                        check=True, cwd=self._project)

        self._fake_tool_home = os.path.join(self._tmpdir, "fake-tool-home")
        _setup_fake_tool_home(self._fake_tool_home)
        self._diffs_dir = os.path.join(self._tmpdir, "diffs")
        _make_stub_llm_client(self._fake_tool_home, self._diffs_dir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_adversarial_surfaces_the_freshness_failure_not_silence(self):
        r = _run_gates("adversarial", [], self._fake_tool_home, self._project)
        self.assertNotEqual(
            r.returncode, 0,
            "an unresolvable freshness precondition must still abort "
            "cmd_adversarial (get_review_diff's own pre-existing fail-loud "
            f"contract, unrelated to this task). stdout={r.stdout!r}",
        )
        combined = r.stdout + r.stderr
        self.assertIn(
            "not provably current", combined,
            f"the freshness failure diagnostic get_review_diff writes to "
            f"its own stderr must be surfaced, not silently swallowed by "
            f"the empty-diff check's stderr capture. "
            f"returncode={r.returncode} output={combined!r}",
        )


class TestLegacyLedgerEntryNeverAnchorsAnExplicitGateLookup(unittest.TestCase):
    """PEACHES, PR #199 review, amos.code-craft.10: a ledger entry written
    before the `gate` field existed (e.g. by lr-01ae73-era gates.sh, months
    before this fix) has NO `gate` key at all. `_ledger_latest_passing_head_
    for_branch` and `_ledger_anchored_pass_at_head`'s READ paths (gates.sh,
    originally lines 1582/1596/1679/1695 in the fold-in report) defaulted a
    MISSING gate field to "review" via `(.gate // "review")` -- so a
    pre-schema entry silently became a valid anchor for a "review" lookup
    forever, on every machine with a live pre-existing review-ledger.jsonl.
    That is the exact fail-toward-LESS-coverage shape this task forbids:
    an entry the CURRENT code never wrote (and whose provenance this fix's
    own gate-namespacing was specifically designed to make explicit) still
    got treated as authoritative because the READER assumed a default
    identity for it, rather than the WRITER ever having stated one.

    MECHANISM this test drives directly (not inferred): hand-writes a
    review-ledger.jsonl entry with NO `gate` key at HEAD1 (exactly the
    on-disk shape a real pre-existing installed ledger has -- verified
    against this fixture's own JSON below, not assumed), commits a second
    change to HEAD2 with a clean index, then runs `gates.sh review`
    (nothing staged, forcing get_review_diff onto the ledger-anchored-delta
    lookup this fix changed). Under the OLD `(.gate // "review") == $g`
    read, the legacy entry defaults to "review", satisfies cmd_review's own
    `gate="review"` lookup, and the delta is computed as HEAD1..HEAD2 (a
    diff containing only the second commit). Under the FIXED strict
    `.gate == $g` read, the legacy entry's `gate` key is absent entirely
    (`null` on read), `null == "review"` is false, it can never anchor
    ANY explicit gate lookup, and get_review_diff falls through to
    full-range (origin/main...HEAD, both commits) instead -- MORE
    coverage, never less, which is exactly what this task's own doctrine
    requires ("fail toward MORE coverage or a hard error -- never a
    silently narrower diff", get_review_diff's own comment).

    Distinguishing observable: same construction as
    TestAdversarialDispatcherForwardsFullReviewFlag's own rewritten test
    above -- app.py's line is edited seed("return x") -> round1("return x
    + 1") -> round2("return x + 2"). The delta path's removed line is
    ALWAYS "return x + 1" (its own base); the full-range path's removed
    line is ALWAYS "return x" (origin/main is pinned at the seed). These
    are mutually exclusive by construction, not merely different text --
    asserting on the correct one PROVES which code path actually ran."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-legacy-ledger-")
        self._project = _setup_project(os.path.join(self._tmpdir, "project"))
        _init_git_repo_with_local_file_remote(self._tmpdir, self._project)
        self._fake_tool_home = os.path.join(self._tmpdir, "fake-tool-home")
        _setup_fake_tool_home(self._fake_tool_home)
        self._diffs_dir = os.path.join(self._tmpdir, "diffs")
        _make_stub_llm_client(self._fake_tool_home, self._diffs_dir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_legacy_ledger_entry(self, head_sha):
        """Hand-write a review-ledger.jsonl entry in the PRE-SCHEMA shape
        (lr-01ae73-era, before this fix's `gate` field existed): {ts,
        branch, base_sha, head_sha, verdict, findings, config} -- NO `gate`
        key at all. This is what a real operator's existing
        .clagentic/lite/review-ledger.jsonl looks like on any machine that
        ran `gates review` before this fix shipped."""
        ledger_path = _ledger_path(self._project)
        os.makedirs(os.path.dirname(ledger_path), exist_ok=True)
        legacy_entry = {
            "ts": "2026-01-01T00:00:00Z",
            "branch": "feat/example",
            "base_sha": "",
            "head_sha": head_sha,
            "verdict": "pass",
            "findings": [],
            "config": {"block_severity": "high", "cross_round_dedup": True, "recurrence_threshold": 2},
        }
        with open(ledger_path, "w") as f:
            f.write(json.dumps(legacy_entry) + "\n")
        # Confirm the fixture itself is genuinely gate-less before trusting
        # the rest of the test on it.
        with open(ledger_path) as f:
            on_disk = json.loads(f.readline())
        assert "gate" not in on_disk, "fixture setup bug: legacy entry must have no gate key"

    def test_legacy_entry_falls_through_to_full_range_not_a_narrow_delta(self):
        head1 = _commit_file(self._project, "app.py", "def handle(x):\n    return x + 1\n", "round 1 commit")
        self._write_legacy_ledger_entry(head1)

        # Second commit, clean index -- forces get_review_diff onto the
        # ledger-anchored-delta-or-branch-diff decision the legacy entry's
        # `gate` field (or lack of one) actually controls.
        _commit_file(self._project, "app.py", "def handle(x):\n    return x + 2\n", "round 2 commit")

        r_review = _run_gates("review", [], self._fake_tool_home, self._project)
        self.assertEqual(r_review.returncode, 0, f"stderr={r_review.stderr}")

        review_call1 = os.path.join(self._diffs_dir, "review-call1.txt")
        self.assertTrue(os.path.isfile(review_call1), "the LLM client must have been invoked")
        with open(review_call1) as f:
            captured_diff = f.read()

        self.assertIn(
            "-    return x\n", captured_diff,
            f"a legacy ledger entry with no `gate` field must NEVER anchor "
            f"an explicit gate lookup -- get_review_diff must fall through "
            f"to the full-range branch-diff-against-default path (removed "
            f"line 'return x', the seed text) rather than treating the "
            f"legacy entry as a valid 'review' anchor and computing a "
            f"narrow HEAD1..HEAD2 delta (which would remove 'return x + 1' "
            f"instead -- mutually exclusive by construction). "
            f"captured_diff={captured_diff!r}",
        )
        self.assertNotIn(
            "-    return x + 1\n", captured_diff,
            f"the delta path's removed line ('return x + 1') must be "
            f"ABSENT -- its presence would mean the legacy entry silently "
            f"anchored the delta lookup, exactly the fail-toward-LESS-"
            f"coverage defect this test guards against. "
            f"captured_diff={captured_diff!r}",
        )


if __name__ == "__main__":
    unittest.main()
