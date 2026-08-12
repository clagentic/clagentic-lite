"""
Acceptance tests for lr-2b07a8: host-adapter publish layer.

SCOPE (matches the task's five items):
  1. Minimal host-adapter contract (scripts/host-adapter.sh):
     host_adapter_available / host_adapter_open_change_request /
     host_adapter_post_comment / host_adapter_read_comments.
  2. cmd_ship's existing open-a-PR path refactored onto the adapter (was a
     direct `gh` call in gates.sh; now calls host_adapter_open_change_request).
  3. After a review verdict lands in the ledger (lr-01ae73), it is published
     through the adapter as ONE comment per review run: verdict, head_sha,
     findings summary, recurring-finding markers.
  4. Fallback contract: no remote / no auth / no adapter means the local
     ledger IS the complete flow (not degraded) -- publish is skipped with a
     one-line notice, and a publish FAILURE never changes the verdict or
     blocks the gate, and is logged to the audit db.
  5. docs/GATES.md documents the adapter contract (covered by review, not by
     this test file).

VERIFICATION DISCIPLINE (task comment #4, overrides the description where
they conflict): this host has no enrolled repos and no authenticated
remotes to a real change-request thread. Every AC below is verified
repo-locally against a STUB/FAKE adapter -- a fake `gh` executable placed on
PATH ahead of the real one (there may be no real `gh` on this host at all),
so `command -v gh` succeeds, `gh pr view <branch>`/`gh pr create`/`gh pr
comment` are FULLY intercepted, and no network call, real credential, or
enrolled repo is ever touched. This proves adapter CONTRACT compliance
(one-comment-per-run, failure-never-gates, the fallback path when no stub is
on PATH at all) -- it does not and cannot prove behavior against a real git
host, which is explicitly out of scope for builder AC per comment #4.

Two layers:
  1. TestHostAdapterContractDirect -- sources host-adapter.sh directly and
     calls host_adapter_available / host_adapter_open_change_request /
     host_adapter_post_comment / host_adapter_read_comments against a fake
     `gh` on PATH, no git repo needed beyond a remote URL.
  2. TestPublishViaCmdReview -- drives the real cmd_review end to end
     against a real (remoteless or fake-github-remote) git repo with a stub
     llm-client.sh AND a stub `gh`, asserting exactly one comment is posted
     per review run, the comment names head_sha/verdict/findings, and a
     publish failure never flips cmd_review's own exit code.
  3. TestHostNeutralGrep -- the literal grep AC: gate logic files, grepped
     for vendor host names, contain none outside scripts/host-adapter.sh.

Run with: python3 -m unittest scripts.test_host_adapter_publish -v
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
HOST_ADAPTER_SH = os.path.join(TOOL_HOME, "scripts", "host-adapter.sh")

_GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Vendor host-name tokens the "host-neutral by contract" AC forbids outside
# adapter implementation files. Matches the task's own enumeration (github,
# gitlab, gitea/forgejo) plus the vendor CLI invocation shape those hosts'
# adapters use. Deliberately narrower than a bare substring match on
# "github"/"gitlab": those words also occur in unrelated doc-link domains
# this codebase legitimately references (e.g. an osv-scanner install hint
# pointing at google.github.io) that have nothing to do with which git host
# this repo's own change requests live on -- the AC is about vendor CHOICE
# leaking into gate logic, not about every substring occurrence of a common
# word fragment.
_VENDOR_TOKENS = [
    "github.com", "gitlab.com", "gitea.", "forgejo.",
    "gh pr view", "gh pr create", "gh pr comment",
]

# Gate-logic files the host-neutral AC applies to. scripts/host-adapter.sh
# is the one sanctioned exception (it IS the adapter implementation file).
_GATE_LOGIC_FILES = [
    os.path.join(TOOL_HOME, "scripts", "gates.sh"),
    os.path.join(TOOL_HOME, "scripts", "review-merge.sh"),
]


def _git(args, cwd, env=None):
    e = os.environ.copy()
    e.update(_GIT_IDENTITY_ENV)
    if env:
        e.update(env)
    return subprocess.run(["git"] + args, cwd=cwd, env=e, check=True,
                           capture_output=True, text=True)


def _init_git_repo_no_remote(project_root):
    _git(["init", "-q", "-b", "main", project_root], cwd=None)
    with open(os.path.join(project_root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    _git(["add", "app.py"], cwd=project_root)
    _git(["commit", "-q", "-m", "seed"], cwd=project_root)
    _git(["checkout", "-q", "-b", "feat/example"], cwd=project_root)
    r = subprocess.run(["git", "remote"], cwd=project_root, capture_output=True, text=True)
    assert r.stdout.strip() == "", "test setup must produce a repo with no remote"


def _init_git_repo_with_github_remote(project_root):
    """A repo whose `origin` remote URL merely LOOKS like a github.com URL
    (a local bare repo cannot literally be github.com) -- sufficient to
    drive _host_adapter_detect's remote-sniff arm without any real network
    reachability, since the fake `gh` stub on PATH intercepts every call
    before anything would need to resolve that host."""
    _git(["init", "-q", "-b", "main", project_root], cwd=None)
    _git(["remote", "add", "origin", "https://github.com/example/example.git"], cwd=project_root)
    with open(os.path.join(project_root, "app.py"), "w") as f:
        f.write("def handle(x):\n    return x\n")
    _git(["add", "app.py"], cwd=project_root)
    _git(["commit", "-q", "-m", "seed"], cwd=project_root)
    _git(["checkout", "-q", "-b", "feat/example"], cwd=project_root)


def _stage_file(project_root, name, content):
    path = os.path.join(project_root, name)
    with open(path, "w") as f:
        f.write(content)
    _git(["add", name], cwd=project_root)


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


def _make_stub_llm_client(tmpdir, envelopes_by_round, capture_diffs=False):
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


def _make_fake_gh(bin_dir, calls_file, mode="ok", pr_exists=False):
    """A fake `gh` executable that intercepts exactly the subcommands
    scripts/host-adapter.sh's gh adapter uses: `pr view`, `pr create`,
    `pr comment`, `pr view --json comments --jq`. Records every invocation
    (argv, joined) as one line in calls_file so tests can assert on
    one-comment-per-run / never-called-when-no-adapter.

    mode:
      "ok"        -- every subcommand succeeds.
      "comment_fail" -- `pr comment` exits 1 (simulates an auth/network
                        publish failure), everything else succeeds.
    pr_exists: when True, `pr view <branch>` (no --json) exits 0 (PR already
      open); when False it exits 1 (no PR yet, forcing `pr create`).
    """
    os.makedirs(bin_dir, exist_ok=True)
    gh_path = os.path.join(bin_dir, "gh")
    bodies_dir = os.path.join(os.path.dirname(calls_file), "posted-bodies")
    script = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import os, sys, json

        calls_file = {calls_file!r}
        bodies_dir = {bodies_dir!r}
        mode = {mode!r}
        pr_exists = {pr_exists!r}

        argv = sys.argv[1:]
        with open(calls_file, "a") as f:
            f.write(" ".join(argv) + "\\n")

        if argv[:2] == ["pr", "view"] and "--json" in argv:
            print(json.dumps({{"comments": []}}))
            sys.exit(0)
        if argv[:2] == ["pr", "view"]:
            sys.exit(0 if pr_exists else 1)
        if argv[:2] == ["pr", "create"]:
            sys.exit(0)
        if argv[:2] == ["pr", "comment"]:
            # Persist the posted body BEFORE the caller's own cleanup can
            # delete its --body-file, so tests can inspect what was
            # actually sent without racing gates.sh's `rm -f`.
            if "--body-file" in argv:
                src = argv[argv.index("--body-file") + 1]
                os.makedirs(bodies_dir, exist_ok=True)
                dst = os.path.join(bodies_dir, "body-%d.txt" % len(open(calls_file).readlines()))
                with open(src) as sf, open(dst, "w") as df:
                    df.write(sf.read())
            sys.exit(1 if mode == "comment_fail" else 0)
        sys.exit(0)
    """)
    with open(gh_path, "w") as f:
        f.write(script)
    os.chmod(gh_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return gh_path


def _read_calls(calls_file):
    if not os.path.exists(calls_file):
        return []
    with open(calls_file) as f:
        return [l for l in f.read().split("\n") if l]


def _read_posted_bodies(tmpdir):
    """Every comment body the fake `gh` intercepted, in post order --
    persisted by _make_fake_gh's `pr comment` handler before gates.sh's own
    `rm -f` on its --body-file tmp path can race it."""
    bodies_dir = os.path.join(tmpdir, "posted-bodies")
    if not os.path.isdir(bodies_dir):
        return []
    names = sorted(os.listdir(bodies_dir), key=lambda n: int(n.split("-")[1].split(".")[0]))
    out = []
    for name in names:
        with open(os.path.join(bodies_dir, name)) as f:
            out.append(f.read())
    return out


_CLEAN_ENVELOPE = {"summary": "clean", "checked": ["security"], "findings": []}


def _finding(message="a finding", file="app.py", line=2, severity="high"):
    return {
        "severity": severity, "file": file, "line": line, "category": "security",
        "message": message, "evidence": "x", "suggestion": "y",
        "issue_class": "none — isolated", "class_fix": "n/a — isolated",
    }


def _envelope(findings):
    return {"summary": "test", "checked": ["security"], "findings": findings}


def _run_review(extra_args, fake_tool_home, project_root, env_overrides=None, path_prepend=None):
    _setup_fake_tool_home(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    if path_prepend:
        env["PATH"] = path_prepend + os.pathsep + env.get("PATH", "")
    if env_overrides:
        env.update(env_overrides)
    cmd = ["sh", fake_gates, "review"] + extra_args
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=project_root)


def _run_review_merge_fn(call_line, env_overrides=None, path_prepend=None):
    """Source platform.sh + host-adapter.sh (host-adapter.sh does not itself
    source platform.sh/review-merge.sh -- it only needs run_bounded, which
    gates.sh provides in the real invocation path; direct-call tests below
    stub run_bounded themselves where needed) and run one call line."""
    env = os.environ.copy()
    if path_prepend:
        env["PATH"] = path_prepend + os.pathsep + env.get("PATH", "")
    if env_overrides:
        env.update(env_overrides)
    script = textwrap.dedent(f"""\
        . '{PLATFORM_SH}'
        run_bounded() {{
          _rb_timeout="$1"; shift
          [ "${{1:-}}" = "--" ] && shift
          "$@"
        }}
        . '{HOST_ADAPTER_SH}'
        {call_line}
    """)
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env)


# ---------------------------------------------------------------------------
# Layer 1: host-adapter.sh direct contract calls, fake `gh` on PATH.
# ---------------------------------------------------------------------------

class TestHostAdapterContractDirect(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adapter-direct-")
        self._bin = os.path.join(self._tmpdir, "bin")
        self._calls = os.path.join(self._tmpdir, "calls.txt")
        self._repo = os.path.join(self._tmpdir, "repo")
        _init_git_repo_with_github_remote(self._repo)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_available_true_with_github_remote_and_gh_on_path(self):
        _make_fake_gh(self._bin, self._calls)
        r = _run_review_merge_fn(
            "host_adapter_available",
            env_overrides={"REPO_ROOT": self._repo},
            path_prepend=self._bin,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_available_false_with_no_remote(self):
        no_remote_repo = os.path.join(self._tmpdir, "no-remote-repo")
        _init_git_repo_no_remote(no_remote_repo)
        _make_fake_gh(self._bin, self._calls)
        r = _run_review_merge_fn(
            "host_adapter_available",
            env_overrides={"REPO_ROOT": no_remote_repo},
            path_prepend=self._bin,
        )
        self.assertNotEqual(r.returncode, 0)

    def test_available_false_with_github_remote_but_no_gh_on_path(self):
        # A PATH with `sh`/`git` but deliberately NO `gh` -- this host may
        # have a real `gh` installed system-wide, so a bare "/usr/bin:/bin"
        # PATH would leak it in and defeat the "no adapter tooling" case
        # this test exists to prove. Build an isolated bin dir with only the
        # specific tools needed to run the probe itself.
        isolated_bin = os.path.join(self._tmpdir, "isolated-bin")
        os.makedirs(isolated_bin, exist_ok=True)
        for tool in ("sh", "git"):
            real = shutil.which(tool)
            self.assertIsNotNone(real, "test host must have %s on PATH" % tool)
            os.symlink(real, os.path.join(isolated_bin, tool))
        r = _run_review_merge_fn(
            "host_adapter_available",
            env_overrides={"REPO_ROOT": self._repo, "PATH": isolated_bin},
        )
        self.assertNotEqual(r.returncode, 0)

    def test_open_change_request_reuses_existing_pr_without_create(self):
        _make_fake_gh(self._bin, self._calls, pr_exists=True)
        r = _run_review_merge_fn(
            "cd '%s' && host_adapter_open_change_request main feat/example" % self._repo,
            env_overrides={"REPO_ROOT": self._repo},
            path_prepend=self._bin,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = _read_calls(self._calls)
        self.assertTrue(any(c.startswith("pr view") for c in calls))
        self.assertFalse(any(c.startswith("pr create") for c in calls),
                           "an existing PR must never trigger a second create call")

    def test_open_change_request_creates_when_none_exists(self):
        _make_fake_gh(self._bin, self._calls, pr_exists=False)
        r = _run_review_merge_fn(
            "cd '%s' && host_adapter_open_change_request main feat/example" % self._repo,
            env_overrides={"REPO_ROOT": self._repo},
            path_prepend=self._bin,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = _read_calls(self._calls)
        self.assertTrue(any(c.startswith("pr create") for c in calls))

    def test_post_comment_posts_body_file_contents(self):
        _make_fake_gh(self._bin, self._calls)
        body_file = os.path.join(self._tmpdir, "body.txt")
        with open(body_file, "w") as f:
            f.write("verdict: pass\nhead_sha: abc123\n")
        r = _run_review_merge_fn(
            "cd '%s' && host_adapter_post_comment '%s'" % (self._repo, body_file),
            env_overrides={"REPO_ROOT": self._repo},
            path_prepend=self._bin,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = _read_calls(self._calls)
        self.assertTrue(any(c.startswith("pr comment") for c in calls))
        self.assertTrue(any("--body-file" in c for c in calls))

    def test_read_comments_returns_json_lines(self):
        _make_fake_gh(self._bin, self._calls)
        r = _run_review_merge_fn(
            "cd '%s' && host_adapter_read_comments" % self._repo,
            env_overrides={"REPO_ROOT": self._repo},
            path_prepend=self._bin,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_config_override_wins_over_remote_sniff(self):
        # CLAGENTIC_REPO_HOST=github with gh present must resolve the
        # adapter even without inspecting the remote URL's exact form.
        _make_fake_gh(self._bin, self._calls)
        r = _run_review_merge_fn(
            "host_adapter_available",
            env_overrides={"REPO_ROOT": self._repo, "CLAGENTIC_REPO_HOST": "github"},
            path_prepend=self._bin,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_config_none_does_not_force_unavailable_when_remote_matches(self):
        # "none" explicitly opts out of the config fast-path but must still
        # fall through to remote-sniff -- "none" is not a global kill switch
        # in this contract (only "no adapter discoverable at all" is).
        _make_fake_gh(self._bin, self._calls)
        r = _run_review_merge_fn(
            "host_adapter_available",
            env_overrides={"REPO_ROOT": self._repo, "CLAGENTIC_REPO_HOST": "none"},
            path_prepend=self._bin,
        )
        self.assertEqual(r.returncode, 0, r.stderr)


# ---------------------------------------------------------------------------
# Layer 2: publish via real cmd_review, stub llm-client.sh + stub gh.
# ---------------------------------------------------------------------------

class TestPublishViaCmdReview(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-publish-e2e-")
        self._project = _setup_project(self._tmpdir)
        self._bin = os.path.join(self._tmpdir, "bin")
        self._calls = os.path.join(self._tmpdir, "calls.txt")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_no_remote_no_adapter_skip_notice_review_unaffected(self):
        """AC2 (fallback): no remote at all -- review runs exactly as
        lr-01ae73's local flow, plus a single skip notice, gate outcome
        unaffected (a clean envelope still passes)."""
        _init_git_repo_no_remote(self._project)
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        result = _run_review([], self._tmpdir, self._project)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no host adapter available", result.stdout + result.stderr)

    def test_remote_and_adapter_available_posts_exactly_one_comment(self):
        """AC1: enrolled repo, authenticated remote, available adapter --
        the anchored verdict is posted as ONE comment, naming head_sha."""
        _init_git_repo_with_github_remote(self._project)
        head_sha = _git(["rev-parse", "HEAD"], cwd=self._project).stdout.strip()
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        _make_fake_gh(self._bin, self._calls)
        result = _run_review([], self._tmpdir, self._project, path_prepend=self._bin)
        self.assertEqual(result.returncode, 0, result.stderr)

        calls = _read_calls(self._calls)
        comment_calls = [c for c in calls if c.startswith("pr comment")]
        self.assertEqual(len(comment_calls), 1,
                          "exactly one comment must be posted per review run: %r" % calls)

        bodies = _read_posted_bodies(self._tmpdir)
        self.assertEqual(len(bodies), 1)
        self.assertIn(head_sha, bodies[0], "comment body must name head_sha")
        self.assertIn("pass", bodies[0])

    def test_second_review_round_marks_recurring_findings_in_comment(self):
        """AC5: a second review round on the same change-request marks
        findings that recurred from the prior round in the published
        comment.

        CLAGENTIC_CROSS_ROUND_DEDUP=0: cross-round content-hash dedup
        (_cross_round_dedup, a DIFFERENT, narrower mechanism than the
        ledger's own (file, category, message) recurrence marking -- see
        docs/GATES.md "Stable finding identity across rounds") would
        otherwise silently drop an identically-reported finding from $OUT
        before _ledger_record_review_verdict ever sees it, since this
        fixture's round 2 re-reports the exact same finding verbatim. That
        is pre-existing, correct dedup behavior for its own purpose
        (suppressing repeat noise in the rendered review output) and is
        orthogonal to what THIS test verifies: that a finding which DOES
        reach the ledger a second time is marked _ledger_recurring and that
        the marker surfaces in the published comment. Opting out here
        isolates that property from the unrelated dedup mechanism."""
        _init_git_repo_with_github_remote(self._project)
        _make_fake_gh(self._bin, self._calls)
        dedup_off = {"CLAGENTIC_CROSS_ROUND_DEDUP": "0"}

        # Round 1: a finding that will recur.
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding(message="sql injection risk")])])
        r1 = _run_review([], self._tmpdir, self._project, path_prepend=self._bin, env_overrides=dedup_off)
        self.assertEqual(r1.returncode, 1, r1.stderr)

        # Round 2: same finding reported again (recurring), plus a new one.
        _git(["commit", "-q", "-m", "round1"], cwd=self._project)
        _stage_file(self._project, "other.py", "print('bye')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([
            _finding(message="sql injection risk"),
            _finding(message="brand new issue", file="other.py"),
        ])])
        r2 = _run_review([], self._tmpdir, self._project, path_prepend=self._bin, env_overrides=dedup_off)
        self.assertEqual(r2.returncode, 1, r2.stderr)

        calls = _read_calls(self._calls)
        comment_calls = [c for c in calls if c.startswith("pr comment")]
        self.assertEqual(len(comment_calls), 2, "one comment per round: %r" % calls)

        bodies = _read_posted_bodies(self._tmpdir)
        self.assertEqual(len(bodies), 2)
        round2_body = bodies[-1]
        self.assertIn("Recurring from a prior round", round2_body)
        self.assertIn("sql injection risk", round2_body)
        recurring_section = round2_body.split("Recurring from a prior round", 1)[1]
        self.assertNotIn("brand new issue", recurring_section,
                          "only the recurring finding, not the new one, belongs in the recurring section")

    def test_publish_failure_never_changes_verdict_or_blocks_gate(self):
        """AC3: a publish failure (simulated auth/network failure on `gh pr
        comment`) leaves the local verdict standing and the gate outcome
        unchanged -- a clean envelope must still exit 0."""
        _init_git_repo_with_github_remote(self._project)
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        _make_fake_gh(self._bin, self._calls, mode="comment_fail")
        result = _run_review([], self._tmpdir, self._project, path_prepend=self._bin)
        self.assertEqual(result.returncode, 0,
                          "a publish failure must never flip cmd_review's own exit code: %s" % result.stderr)

        ledger_path = os.path.join(self._project, ".clagentic", "lite", "review-ledger.jsonl")
        self.assertTrue(os.path.exists(ledger_path))
        with open(ledger_path) as f:
            entry = json.loads(f.read().strip().split("\n")[-1])
        self.assertEqual(entry["verdict"], "pass",
                          "the local ledger verdict must stand regardless of publish failure")

    def test_publish_failure_logged_to_audit_db(self):
        """AC3: publish failures are logged to the audit db."""
        _init_git_repo_with_github_remote(self._project)
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_CLEAN_ENVELOPE])
        _make_fake_gh(self._bin, self._calls, mode="comment_fail")
        _run_review([], self._tmpdir, self._project, path_prepend=self._bin)

        db_path = os.path.join(self._project, ".clagentic", "lite", "audit.db")
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT gate, outcome, details FROM gate_runs WHERE gate='review-publish' ORDER BY id DESC"
        ).fetchall()
        conn.close()
        self.assertTrue(rows, "a review-publish audit row must exist")
        self.assertEqual(rows[0][1], "block", "the logged outcome must reflect the publish failure")

    def test_block_verdict_also_publishes_one_comment(self):
        """Publish runs on a blocking verdict too, not only a passing one."""
        _init_git_repo_with_github_remote(self._project)
        _stage_file(self._project, "feature.py", "print('hi')\n")
        _make_stub_llm_client(self._tmpdir, [_envelope([_finding()])])
        _make_fake_gh(self._bin, self._calls)
        result = _run_review([], self._tmpdir, self._project, path_prepend=self._bin)
        self.assertEqual(result.returncode, 1, result.stderr)

        calls = _read_calls(self._calls)
        comment_calls = [c for c in calls if c.startswith("pr comment")]
        self.assertEqual(len(comment_calls), 1)
        bodies = _read_posted_bodies(self._tmpdir)
        self.assertEqual(len(bodies), 1)
        self.assertIn("block", bodies[0])


# ---------------------------------------------------------------------------
# Layer 3: host-neutral-by-contract grep AC.
# ---------------------------------------------------------------------------

class TestHostNeutralGrep(unittest.TestCase):
    """Given gate logic files, when grepped for vendor host names, then none
    appear outside adapter implementation files. This is the literal AC from
    lr-2b07a8 -- pinned here so the property is defended going forward, not
    just true on the day it merges."""

    def test_no_vendor_tokens_in_gate_logic_files(self):
        for path in _GATE_LOGIC_FILES:
            with open(path, encoding="utf-8") as f:
                content = f.read().lower()
            for token in _VENDOR_TOKENS:
                self.assertNotIn(
                    token.lower(), content,
                    "vendor token %r found in gate-logic file %s -- vendor names/CLIs "
                    "belong ONLY in scripts/host-adapter.sh" % (token, path)
                )

    def test_host_adapter_file_itself_is_exempt_and_contains_gh(self):
        # Sanity check the test's own exemption logic isn't vacuous: the
        # adapter implementation file legitimately DOES reference the
        # vendor CLI it wraps.
        with open(HOST_ADAPTER_SH, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("gh", content)


if __name__ == "__main__":
    unittest.main()
