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
    git` code path (8.18+, capability-probed by cmd_secrets itself via
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
    except Exception:
        return False
    return r.returncode == 0


def _run_cmd_secrets(project_root, extra_args=None, extra_env=None, bin_dir=None):
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
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=project_root, timeout=120)


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


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.18+)")
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


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.18+)")
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


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.18+)")
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


@unittest.skipUnless(_gitleaks_git_subcommand_available(), "gitleaks git subcommand not available (needs 8.18+)")
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


if __name__ == "__main__":
    unittest.main()
