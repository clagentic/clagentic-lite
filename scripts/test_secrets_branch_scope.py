"""
Regression tests for lr-51112e: cmd_secrets' feature-branch/no-staged-changes
path used to run `gitleaks git --redact --no-banner $CFG_ARG` with no
--log-opts at all -- it walked EVERY commit reachable from HEAD, not just
the commits the current branch actually introduced. A finding already
present on the default branch (secrets committed before this feature
existed, or before secrets scanning was even enabled) then blocked EVERY
feature branch, and the "scanning branch history" log line misattributed
the finding to the branch under review.

FIX (mirrors cmd_bleed's and cmd_sast's own scoping precedent exactly --
reuse, not a third mechanism): default scope is now
merge-base(<provably-current origin/CLAGENTIC_DEFAULT_BRANCH>, HEAD)..HEAD,
passed to gitleaks via --log-opts. Opt-in full-history scan remains
available via `gates.sh secrets --full-scan` or
CLAGENTIC_SECRETS_FULL_SCAN=1. An unverifiable baseline (no remote, fetch
failure/timeout, shallow clone with no common ancestor, REPO_ROOT not
provably scoped) WIDENS to full history rather than silently narrowing or
skipping -- same "never silently narrow, only a verified baseline narrows"
doctrine cmd_bleed's branch-diff scoping and cmd_sast's --baseline-commit
scoping both already apply to their own freshness resolution
(_gate_resolve_fresh_default_branch_ref, scripts/gates.sh).

The staged-diff path (gitleaks git --staged --pre-commit) and the
older-gitleaks (`gitleaks protect`) fallback are both UNCHANGED by this
task -- see TestSecretsStagedPathUnchanged below for the regression pin.

Companion coverage: scripts/test_gates_dispatcher_forwards_args.py pins the
dispatcher-sweep half of this task (every gates.sh subcommand that accepts
arguments must forward them via `shift; cmd_X "$@"`, not drop them).

Run with: python3 -m unittest scripts.test_secrets_branch_scope -v
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REAL_SCRIPTS_DIR = os.path.join(TOOL_HOME, "scripts")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Realistic, non-example synthetic secrets, assembled from short fragments at
# runtime -- same discipline scripts/gates.sh's own _gitleaks_positive_control
# and scripts/test_secrets_positive_control.py use, so this test file itself
# never becomes something `gates.sh secrets` blocks on when scanning this
# repo's own history. Two distinct rule families (AWS key pair, GitHub PAT)
# so a single upstream rule regression cannot silently blind every case here.
_AWS_KEY = "".join(["AKIA", "58QN", "ZR3T", "MK9P", "X4WL"])
_AWS_SECRET = "".join([
    "K3nR", "gT8m", "Xq2Z", "vB7s", "Lp5W", "cY1d", "Hn4F", "jE9A", "oU6t", "Zr3M",
])
_GITHUB_PAT = "".join([
    "ghp_", "7bN2", "kL9x", "Qm4Z", "pW6v", "Rj3F", "tD8c", "Xa5Y", "Nh1G", "Su0e", "Vk2i",
])


def _gitleaks_available():
    return shutil.which("gitleaks") is not None


def _gitleaks_git_subcommand_available():
    """This task's branch-history scope fix only applies to the `gitleaks
    git` code path (8.19+ -- corrected from 8.18, PEACHES PR #218 review,
    comment 5833150249; capability-probed by cmd_secrets itself via
    `gitleaks git --help`, never a version-string parse -- see
    docs/GATES.md's own "Version floor" note). An older installed gitleaks
    (Ubuntu 24.04's `apt install gitleaks` ships 8.16.0, below this floor)
    has no history-scan subcommand at all -- cmd_secrets' pre-existing,
    UNCHANGED-by-this-task fallback for that case is to skip the scan
    entirely on a feature branch with a clean index (see "older gitleaks
    cannot scan history" in scripts/gates.sh) rather than run anything this
    file's scope logic touches. Skip this whole module rather than assert
    against a code path this task did not change."""
    if not _gitleaks_available():
        return False
    try:
        r = subprocess.run(["gitleaks", "git", "--help"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        # PEACHES PR #218 review (comment 5833150249): `except Exception`
        # here converted a programming error (e.g. a bad subprocess.run
        # call, a typo'd kwarg) into a silent skip of all ten regression
        # tests gated on this probe -- the exact failure mode this task's
        # own doctrine (no bare except) exists to prevent. Only the probe's
        # OWN anticipated failure modes are caught: gitleaks missing/broken
        # (OSError, e.g. ENOENT/EACCES/binary-corrupted) or hanging past the
        # 30s bound (subprocess.TimeoutExpired). Anything else -- a real bug
        # in this probe -- must fail the suite loudly instead of masquerading
        # as "gitleaks git subcommand not available".
        return False
    return r.returncode == 0


def _run_cmd_secrets(project_root, extra_args=None, extra_env=None, bin_dir=None, cwd=None):
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    # Keep the positive-control canary out of these tests' way -- it is
    # covered independently by test_secrets_positive_control.py and would
    # otherwise add ~1-2s of scratch-repo scanning to every case here for no
    # benefit to what THIS file is testing (branch-history scope).
    env["CLAGENTIC_SKIP_SECRETS_CANARY"] = "1"
    if bin_dir:
        env["PATH"] = bin_dir + os.pathsep + env["PATH"]
    if extra_env:
        env.update(extra_env)
    gates_sh = os.path.join(REAL_SCRIPTS_DIR, "gates.sh")
    cmd = ["sh", gates_sh, "secrets"] + (extra_args or [])
    # cwd defaults to project_root (every pre-existing call site's exact
    # prior behavior, byte-for-byte) -- a caller that wants to exercise
    # CWD-independence (PEACHES PR #217 review, comment 5821185384) passes a
    # DIFFERENT directory here while CLAGENTIC_PROJECT_ROOT still names the
    # real target repo, the same split a wrapper/`.clagentic-project` layout
    # or a hook invoked from a subdirectory produces in the field.
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd or project_root, timeout=120)


def _init_origin_and_work(tmp):
    origin = os.path.join(tmp, "origin.git")
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    work = os.path.join(tmp, "work")
    subprocess.run(["git", "clone", "-q", origin, work], check=True)
    return origin, work


def _commit_secret_on_main(work, filename, secret_line):
    env = {**os.environ, **_GIT_ENV}
    path = os.path.join(work, filename)
    with open(path, "w") as f:
        f.write(secret_line + "\n")
    subprocess.run(["git", "add", filename], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "pre-existing secret on main"], check=True, cwd=work, env=env)
    subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=env)


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.19+)")
class TestSecretsBranchScopeDoesNotFlagPreExistingDefaultBranchFinding(unittest.TestCase):
    """The exact reported defect: a secret already committed to the default
    branch, before the feature branch existed, must NOT block the feature
    branch -- only a finding actually reachable via the branch's own
    merge-base..HEAD range should."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-secrets-scope-")
        _origin, self._work = _init_origin_and_work(self._tmp)
        _commit_secret_on_main(self._work, "legacy_config.py", f'AWS_KEY = "{_AWS_KEY}"\nAWS_SECRET = "{_AWS_SECRET}"')

        env = {**os.environ, **_GIT_ENV}
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        clean = os.path.join(self._work, "new_feature.py")
        with open(clean, "w") as f:
            f.write("def handle(x):\n    return x\n")
        subprocess.run(["git", "add", "new_feature.py"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "feature commit, no secret"], check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_pre_existing_default_branch_secret_does_not_block_feature_branch(self):
        result = _run_cmd_secrets(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 0,
                         f"a secret already on main before this branch existed must not block "
                         f"this branch's own scoped scan\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("branch diff", result.stderr)

    def test_full_scan_flag_still_catches_the_pre_existing_secret(self):
        result = _run_cmd_secrets(self._work, extra_args=["--full-scan"],
                                  extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"--full-scan must still reach the pre-existing default-branch secret\n"
                         f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("full history", result.stderr)

    def test_full_scan_env_var_still_catches_the_pre_existing_secret(self):
        result = _run_cmd_secrets(self._work, extra_env={
            "CLAGENTIC_DEFAULT_BRANCH": "main",
            "CLAGENTIC_SECRETS_FULL_SCAN": "1",
        })
        self.assertEqual(result.returncode, 1,
                         f"CLAGENTIC_SECRETS_FULL_SCAN=1 must still reach the pre-existing "
                         f"default-branch secret\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("full history", result.stderr)


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.19+)")
class TestSecretsBranchScopeStillCatchesInBranchHistory(unittest.TestCase):
    """In-branch history still counts (task's own explicit requirement,
    engram 7617259): a secret introduced then removed EARLIER on this same
    branch is still inside merge-base..HEAD and must still block --
    gitleaks scans full blob history within a --log-opts range, not just the
    tip tree."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-secrets-inbranch-")
        _origin, self._work = _init_origin_and_work(self._tmp)
        env = {**os.environ, **_GIT_ENV}

        readme = os.path.join(self._work, "README")
        with open(readme, "w") as f:
            f.write("hello\n")
        subprocess.run(["git", "add", "README"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)

        # Introduce a secret, then remove it in a later commit on the SAME
        # branch -- the working tree at HEAD is clean, but the secret is
        # still reachable in the branch's own committed history.
        leaked = os.path.join(self._work, "config.py")
        with open(leaked, "w") as f:
            f.write(f'GITHUB_TOKEN = "{_GITHUB_PAT}"\n')
        subprocess.run(["git", "add", "config.py"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "oops, committed a token"], check=True, cwd=self._work, env=env)

        with open(leaked, "w") as f:
            f.write("GITHUB_TOKEN = os.environ['GITHUB_TOKEN']\n")
        subprocess.run(["git", "add", "config.py"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "fix: read token from env instead"], check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_introduced_then_removed_in_branch_still_blocks(self):
        result = _run_cmd_secrets(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"a secret introduced then removed earlier on this branch must still "
                         f"block -- scoping narrows what's reachable, never what's caught within "
                         f"that range\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("branch diff", result.stderr)


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.19+)")
class TestSecretsBranchScopeFreshness(unittest.TestCase):
    """BOBBIE-class freshness precondition (mirrors
    test_bleed_scope.py's TestBleedBranchDiffFreshness and
    test_sast_baseline_scope.py's analogous test exactly): a stale/
    unverifiable origin/<default-branch> resolution must WIDEN to full
    history, never silently narrow past a pre-existing secret it can no
    longer prove is out of range."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-secrets-fresh-")
        self._bin = os.path.join(self._tmp, "bin")
        _origin, self._work = _init_origin_and_work(self._tmp)
        _commit_secret_on_main(self._work, "legacy_config.py", f'AWS_KEY = "{_AWS_KEY}"\nAWS_SECRET = "{_AWS_SECRET}"')

        env = {**os.environ, **_GIT_ENV}
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        clean = os.path.join(self._work, "new_feature.py")
        with open(clean, "w") as f:
            f.write("def handle(x):\n    return x\n")
        subprocess.run(["git", "add", "new_feature.py"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "feature commit, no secret"], check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_git_shim_disagreeing_ls_remote(self, fake_sha):
        """Same shim shape as test_bleed_scope.py's and
        test_sast_baseline_scope.py's own copies -- cmd_secrets now shares
        the identical _gate_resolve_fresh_default_branch_ref helper, so the
        same simulation isolates the same branch here."""
        real_git = shutil.which("git")
        os.makedirs(self._bin, exist_ok=True)
        path = os.path.join(self._bin, "git")
        with open(path, "w") as f:
            f.write(textwrap.dedent(f"""\
                #!/bin/sh
                for _arg in "$@"; do
                  if [ "$_arg" = "ls-remote" ]; then
                    echo "{fake_sha}	refs/heads/main"
                    exit 0
                  fi
                done
                exec {real_git} "$@"
            """))
        os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    def test_stale_unverifiable_baseline_widens_to_full_history_not_narrowed_scan(self):
        fake_sha = "abcdef1234567890abcdef1234567890abcdef12"
        self._write_git_shim_disagreeing_ls_remote(fake_sha)

        result = _run_cmd_secrets(
            self._work,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
            bin_dir=self._bin,
        )
        self.assertEqual(result.returncode, 1,
                         f"a stale/unverifiable branch baseline must widen to full history and "
                         f"still catch the pre-existing secret, never silently narrow past it\n"
                         f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("full history", result.stderr)
        self.assertIn("not provably current", result.stderr)
        self.assertNotIn("branch diff", result.stderr)

    def test_no_remote_widens_to_full_history(self):
        """No `origin` remote at all is a distinct unverifiable-baseline
        case from a stale ls-remote disagreement -- _gate_resolve_fresh_default_branch_ref's
        own `git fetch origin` call fails outright. Must widen, not skip or
        silently pass."""
        subprocess.run(["git", "remote", "remove", "origin"], check=True, cwd=self._work)
        result = _run_cmd_secrets(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"no remote at all must widen to full history and still catch the "
                         f"pre-existing secret\nstdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("full history", result.stderr)
        self.assertNotIn("branch diff", result.stderr)


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.19+)")
class TestSecretsLogLineNamesScopeAndRange(unittest.TestCase):
    """Task requirement 4: the log line and cmd_log_run's audit detail must
    state scope+range, not just "scanning branch history" with no further
    detail."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-secrets-logline-")
        _origin, self._work = _init_origin_and_work(self._tmp)
        env = {**os.environ, **_GIT_ENV}
        readme = os.path.join(self._work, "README")
        with open(readme, "w") as f:
            f.write("hello\n")
        subprocess.run(["git", "add", "README"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        clean = os.path.join(self._work, "new_feature.py")
        with open(clean, "w") as f:
            f.write("def handle(x):\n    return x\n")
        subprocess.run(["git", "add", "new_feature.py"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "feature commit"], check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_pass_line_names_branch_diff_range_and_commit_count(self):
        result = _run_cmd_secrets(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("branch diff", result.stderr)
        self.assertIn("commits)", result.stderr)

    def test_full_scan_line_names_the_full_scan_reason(self):
        result = _run_cmd_secrets(self._work, extra_args=["--full-scan"],
                                  extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("full history (--full-scan)", result.stderr)

    def test_full_scan_env_var_line_names_the_env_var_reason_not_the_flag(self):
        """PEACHES PR #217 review (comment 5820512826): the trigger source
        must be preserved distinctly -- an env-only trigger must NOT claim
        "(--full-scan)" in the log line/audit detail, since no CLI flag was
        passed. Regression pin for the collapsed-boolean defect: before the
        fix, _SECRETS_FULL_SCAN was a single boolean and every env-only
        trigger unconditionally logged "(--full-scan)"."""
        result = _run_cmd_secrets(self._work, extra_env={
            "CLAGENTIC_DEFAULT_BRANCH": "main",
            "CLAGENTIC_SECRETS_FULL_SCAN": "1",
        })
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("full history (CLAGENTIC_SECRETS_FULL_SCAN=1)", result.stderr)
        self.assertNotIn("full history (--full-scan)", result.stderr,
                         f"env-only trigger must not claim a CLI flag was supplied\n"
                         f"stdout={result.stdout}\nstderr={result.stderr}")

    def test_full_scan_flag_and_env_var_both_set_names_both_reasons(self):
        """Both triggers can be set at once (redundant, not a conflict) --
        the log line/audit detail names both rather than silently picking
        one and discarding the other."""
        result = _run_cmd_secrets(self._work, extra_args=["--full-scan"], extra_env={
            "CLAGENTIC_DEFAULT_BRANCH": "main",
            "CLAGENTIC_SECRETS_FULL_SCAN": "1",
        })
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("full history (--full-scan, CLAGENTIC_SECRETS_FULL_SCAN=1)", result.stderr)


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestSecretsStagedPathUnchanged(unittest.TestCase):
    """Task requirement 5: the staged path (--staged --pre-commit) is
    unchanged by this task -- a staged secret still blocks regardless of
    branch-scope logic, and the branch-scope machinery is never consulted
    when the index is non-empty."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-secrets-staged-")
        _origin, self._work = _init_origin_and_work(self._tmp)
        env = {**os.environ, **_GIT_ENV}
        readme = os.path.join(self._work, "README")
        with open(readme, "w") as f:
            f.write("hello\n")
        subprocess.run(["git", "add", "README"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_staged_secret_blocks_regardless_of_branch_scope(self):
        env = {**os.environ, **_GIT_ENV}
        leaked = os.path.join(self._work, "config.py")
        with open(leaked, "w") as f:
            f.write(f'GITHUB_TOKEN = "{_GITHUB_PAT}"\n')
        subprocess.run(["git", "add", "config.py"], check=True, cwd=self._work, env=env)

        result = _run_cmd_secrets(self._work, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"})
        self.assertEqual(result.returncode, 1,
                         f"a staged secret must still block\nstdout={result.stdout}\nstderr={result.stderr}")
        # The branch-scope log line ("no staged changes -- scanning ...")
        # must NOT appear -- the staged path short-circuits before any of
        # the branch-scope machinery runs.
        self.assertNotIn("no staged changes", result.stderr)


class TestSecretsScanIsCwdIndependent(unittest.TestCase):
    """Regression pin for PEACHES PR #217 review, comment 5821185384: every
    gitleaks invocation inside cmd_secrets used to omit an explicit target
    directory, so gitleaks performed its OWN repo discovery from the
    process's CWD rather than $REPO_ROOT -- in a wrapper/
    `.clagentic-project` layout, or any invocation whose CWD differs from
    REPO_ROOT (a hook invoked from a subdirectory, an orchestrator that cds
    elsewhere before shelling out), gitleaks silently scanned the WRONG
    tree (or a clean unrelated one) while cmd_secrets reported whatever
    that unrelated scan found -- a FALSE PASS on the real target, not an
    error. Every gitleaks call site now passes "$REPO_ROOT" explicitly, the
    same CWD-independence `_git -C "$REPO_ROOT"` already guarantees for
    every plain git call in this file.

    Exercises the `gitleaks protect --staged` fallback path specifically
    (not `gitleaks git`) -- runnable on gitleaks 8.16 (this host's
    installed version; `gitleaks git` needs 8.19+, see
    _gitleaks_git_subcommand_available's own docstring above), so this
    class carries NO version-gate skip and always runs for real. The
    `gitleaks git` staged/branch-history call sites received the identical
    fix but are exercised by the 8.19+-gated classes above; this class
    proves the fix at the ONE call site this host can run for real,
    the class-level property (fix the pattern, not the line) is the same
    fix applied uniformly to all three call sites in cmd_secrets."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-secrets-cwd-")
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        _origin, self._work = _init_origin_and_work(self._tmp)
        env = {**os.environ, **_GIT_ENV}
        readme = os.path.join(self._work, "README")
        with open(readme, "w") as f:
            f.write("hello\n")
        subprocess.run(["git", "add", "README"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)

        # A separate, unrelated directory to invoke gates.sh FROM -- neither
        # a git repo itself nor an ancestor/descendant of self._work. If
        # gitleaks were still resolving its target from CWD rather than
        # $REPO_ROOT, it would either error on a non-repo CWD (a DIFFERENT
        # failure than a false pass, still proving the bug) or, on a host
        # where an ancestor of this elsewhere-dir happens to be a repo,
        # silently scan that unrelated tree instead.
        self._elsewhere = os.path.join(self._tmp, "elsewhere")
        os.makedirs(self._elsewhere)

    @unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
    def test_staged_secret_still_blocks_when_invoked_from_a_different_cwd(self):
        env = {**os.environ, **_GIT_ENV}
        leaked = os.path.join(self._work, "config.py")
        with open(leaked, "w") as f:
            f.write(f'GITHUB_TOKEN = "{_GITHUB_PAT}"\n')
        subprocess.run(["git", "add", "config.py"], check=True, cwd=self._work, env=env)

        result = _run_cmd_secrets(
            self._work,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
            cwd=self._elsewhere,
        )
        self.assertEqual(
            result.returncode, 1,
            f"a staged secret must still block when gates.sh is invoked from a CWD "
            f"other than the target repo -- CLAGENTIC_PROJECT_ROOT (not CWD) must "
            f"decide what gitleaks scans\nstdout={result.stdout}\nstderr={result.stderr}",
        )

    @unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
    def test_clean_staged_index_still_passes_when_invoked_from_a_different_cwd(self):
        """The other direction of the same property: a CLEAN staged index in
        the real target repo must still report a clean pass when invoked
        from an unrelated CWD -- proving the scan actually reached the real
        target (and found nothing) rather than, say, erroring out in a way
        that happened to also return non-blocking."""
        clean = os.path.join(self._work, "clean.py")
        with open(clean, "w") as f:
            f.write("def handle(x):\n    return x\n")
        env = {**os.environ, **_GIT_ENV}
        subprocess.run(["git", "add", "clean.py"], check=True, cwd=self._work, env=env)

        result = _run_cmd_secrets(
            self._work,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
            cwd=self._elsewhere,
        )
        self.assertEqual(
            result.returncode, 0,
            f"a clean staged index in the real target repo must still pass when "
            f"invoked from a different CWD\nstdout={result.stdout}\nstderr={result.stderr}",
        )


class TestGitleaksGitInvocationUsesPositionalRepoNotSourceFlag(unittest.TestCase):
    """Regression pin for PEACHES PR #218 review (comment 5833150249):
    `gitleaks git` never accepted `--source` as its own flag -- per
    upstream gitleaks' own cobra command definitions (cmd/git.go,
    confirmed from the v8.19.0 introduction of the `git` subcommand through
    the current v8.30.1), `git`'s `Use` string has always been
    `"git [flags] [repo]"` with `Args: cobra.MaximumNArgs(1)`: the repo is
    a positional argument. `--source` briefly appeared to work on `git`
    only via root.go's global persistent flag, removed at v8.20.0 -- so
    `gitleaks git --source=...` fails with an unknown-flag error on every
    gitleaks release from 8.20.0 onward, blocking every secrets gate even
    on a clean repo.

    Reads the REAL scripts/gates.sh source text directly (never a
    hand-copied re-implementation, which could silently drift from what
    ships) so a future edit that reintroduces `--source` on a `gitleaks
    git` call is caught here rather than only discovered against a live
    modern gitleaks install (this host's installed gitleaks, 8.16, predates
    the `git` subcommand entirely and cannot itself catch this by running
    the gate -- see _gitleaks_git_subcommand_available's own docstring)."""

    def test_both_gitleaks_git_call_sites_use_positional_repo_arg(self):
        """PEACHES PR #218 review (comment 5834286140): the selector here
        used to be `"gitleaks git " in line and "run_bounded" in line and
        "REPO_ROOT" in line` -- requiring "REPO_ROOT" in the SELECTOR means
        a call site that forgot to pin REPO_ROOT (the exact defect this
        test exists to catch) would simply never be selected at all, so the
        sweep would silently report "found N" for whatever N conforming
        lines happen to exist and never even look at the non-conforming
        one. The selector now finds every REAL `gitleaks git` scan
        invocation by the broadest reliable property -- a `run_bounded`
        call naming `gitleaks git` -- and the REPO_ROOT pin is asserted
        AFTERWARDS, on every selected line, so an unpinned call site fails
        the assertion instead of silently vanishing from the swept set."""
        with open(os.path.join(REAL_SCRIPTS_DIR, "gates.sh")) as f:
            src = f.read()
        # Scoped to the cmd_secrets FUNCTION BODY (found mechanically by its
        # own `cmd_secrets()` definition line through the next top-level
        # `^}` at column 0, never a hand-picked line range that could drift
        # from the real file) -- this is what task requirement (2) means by
        # "the broadest reliable selector": every gitleaks invocation WITHIN
        # cmd_secrets, not a narrower property-of-interest filter.
        # _gitleaks_positive_control's canary scan is a genuinely different
        # function (its own scratch-dir-scoped `cd "$_gpc_dir" && ...`, see
        # that function's own doc comment for why `cd`, not a
        # positional/--source arg, is correct there) and is out of scope
        # for this pin by construction, not by an ad hoc substring filter
        # that could just as easily exclude a real non-conforming line.
        secrets_start = src.index("\ncmd_secrets()")
        secrets_end = src.index("\n}", secrets_start)
        secrets_body = src[secrets_start:secrets_end]
        git_call_lines = [
            line for line in secrets_body.splitlines()
            if "gitleaks git " in line and "run_bounded" in line
        ]
        self.assertEqual(
            len(git_call_lines), 2,
            msg=f"expected exactly 2 `gitleaks git` scan invocations in cmd_secrets "
                f"(branch-history and staged/pre-commit) -- found {len(git_call_lines)}: "
                f"{git_call_lines}. Update this pin if cmd_secrets legitimately "
                f"gained/lost a gitleaks git call site.",
        )
        for line in git_call_lines:
            self.assertNotIn(
                "--source", line,
                msg=f"a `gitleaks git` call site still passes `--source` -- this "
                    f"flag does not exist on the `git` subcommand from gitleaks "
                    f"8.20.0 onward (removed with the global persistent flag) and "
                    f"was NEVER a git-local flag at any version; every gitleaks "
                    f"git call must pass $REPO_ROOT as a positional argument "
                    f"instead: {line!r}",
            )
            self.assertIn(
                '-- "$REPO_ROOT"', line,
                msg=f"`gitleaks git` call site does not pass $REPO_ROOT as a "
                    f"`--`-terminated positional argument: {line!r}",
            )

    def test_selector_catches_a_call_site_that_forgot_the_repo_root_pin(self):
        """Negative control (PEACHES PR #218 review, comment 5834286140):
        proves the selector above actually SELECTS an unpinned `gitleaks
        git` call site rather than silently excluding it. Exercises the
        same selector expression against a synthetic source line, not the
        real gates.sh -- if a future call site in gates.sh really did drop
        the REPO_ROOT pin, `test_both_gitleaks_git_call_sites_use_positional_repo_arg`
        above would fail its own `-- "$REPO_ROOT"` assertion; this test
        only pins that the SELECTOR itself would have caught it, which is
        the property PEACHES's finding was about."""
        unpinned_line = '      if run_bounded "$_SECRETS_TIMEOUT" -- gitleaks git --redact --no-banner $CFG_ARG; then'
        selected = "gitleaks git " in unpinned_line and "run_bounded" in unpinned_line
        self.assertTrue(
            selected,
            msg="the selector must match a run_bounded gitleaks git call site even "
                "when it has no REPO_ROOT pin -- a selector requiring REPO_ROOT would "
                "silently exclude exactly this non-conforming line",
        )
        self.assertNotIn(
            '-- "$REPO_ROOT"', unpinned_line,
            msg="sanity check on the fixture itself: this synthetic line must actually "
                "be missing the pin, or this test is not exercising what it claims to",
        )

    def test_gitleaks_protect_fallback_still_uses_source_flag_unaffected(self):
        """The older `gitleaks protect` fallback is a genuinely separate
        code path (its own runProtect, never merged with `git`'s
        positional-arg design) that registers its own local `-s`/
        `--source` flag, confirmed unchanged through gitleaks 8.30.1 --
        this fix must NOT touch it."""
        with open(os.path.join(REAL_SCRIPTS_DIR, "gates.sh")) as f:
            src = f.read()
        protect_call_lines = [
            line for line in src.splitlines()
            if "gitleaks protect " in line and "run_bounded" in line
        ]
        self.assertEqual(len(protect_call_lines), 1,
                          msg=f"expected exactly 1 `gitleaks protect` invocation "
                              f"(older-gitleaks fallback): {protect_call_lines}")
        self.assertIn("--source", protect_call_lines[0],
                       msg="the gitleaks protect fallback must keep using "
                           "--source -- it is a separate code path from "
                           "`git` and was never affected by this fix")


if __name__ == "__main__":
    unittest.main()
