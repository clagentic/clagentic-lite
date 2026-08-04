"""
Regression tests for lr-06b87e: cmd_sast baseline scoping.

cmd_sast (scripts/gates.sh) used to run
`semgrep --config=auto --error --severity=ERROR` with no path argument,
scanning the ENTIRE working tree on every invocation. Pre-existing findings
in files a branch never touched were attributed to that branch and blocked
the gate.

The fix scopes the scan to diff-introduced findings via semgrep's native
`--baseline-commit=<merge-base>`, resolved as
`git merge-base origin/<default-branch> HEAD`. This is strictly a
narrowing: every failure to resolve a trustworthy baseline (old semgrep,
detached HEAD, on the default branch, unresolvable origin/<default-branch>,
failed merge-base -- e.g. a shallow clone) falls back to the EXACT prior
full-tree behavior and blocks on whatever it finds. A scoping bug must
never silently narrow to an empty/partial scan -- that would turn a gate
bug into a security bypass.

These tests stub semgrep itself (a fixed-behavior fake binary recording its
own argv) so the resolution logic in cmd_sast is exercised deterministically
against REAL git repos/branches, without depending on network access or a
real semgrep scan's runtime. One test (TestRealSemgrepSupportsBaselineFlag)
asserts a property about the actual installed semgrep binary, so a future
downgrade that drops --baseline-commit support is caught here rather than
silently degrading every future run to full-tree scoping.

Run with: python3 -m unittest scripts.test_sast_baseline_scope -v
"""
import os
import shutil
import sqlite3
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


def _write_fake_semgrep(bin_dir, supports_baseline=True, exit_code=0):
    """Write a fake `semgrep` executable onto bin_dir that records its argv
    to $SEMGREP_ARGV_FILE and exits with exit_code. Its `scan --help` output
    advertises --baseline-commit only when supports_baseline is True, since
    cmd_sast probes support via
    `semgrep scan --help | grep -q -- --baseline-commit` (modern semgrep is
    a command group -- --baseline-commit is a `scan` subcommand flag and
    does not appear in the top-level `semgrep --help`, confirmed against the
    real installed binary).
    """
    os.makedirs(bin_dir, exist_ok=True)
    path = os.path.join(bin_dir, "semgrep")
    help_line = "--baseline-commit TEXT   Only report findings..." if supports_baseline else ""
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "scan" ] && [ "$2" = "--help" ]; then
              echo "usage: semgrep scan [OPTIONS]"
              echo "{help_line}"
              exit 0
            fi
            printf '%s\\n' "$*" >> "$SEMGREP_ARGV_FILE"
            exit {exit_code}
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _init_repo(root):
    subprocess.run(["git", "init", "-q", root], check=True)
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "initial"],
                    check=True, cwd=root, env=env)


def _run_cmd_sast(project_root, bin_dir, argv_file, extra_env=None):
    """Run `sh -c '. gates.sh helper source; cmd_sast'`-equivalent by
    invoking the real gates.sh's `sast` subcommand as a subprocess, with a
    fake semgrep shadowing PATH ahead of the real one, and CLAGENTIC_PROJECT_ROOT
    pointed at project_root.
    """
    env = os.environ.copy()
    env["PATH"] = bin_dir + os.pathsep + env["PATH"]
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["SEMGREP_ARGV_FILE"] = argv_file
    # Isolate from any real global/repo config that might set these.
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "0"
    if extra_env:
        env.update(extra_env)

    gates_sh = os.path.join(REAL_SCRIPTS_DIR, "gates.sh")
    result = subprocess.run(
        ["sh", gates_sh, "sast"],
        capture_output=True, text=True, env=env, cwd=project_root,
    )
    return result


def _last_sast_audit_details(project_root):
    """cmd_log_run writes to .clagentic/lite/audit.db, not stderr -- the
    fail-closed/scoped-mode reason text lives in the `details` column of the
    most recent `gate=sast` row, so assertions on that text must read the
    audit DB rather than grep process output."""
    db_path = os.path.join(project_root, ".clagentic", "lite", "audit.db")
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT details FROM gate_runs WHERE gate='sast' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


class TestBaselineScopingActivates(unittest.TestCase):
    """Baseline scoping activates when every resolution condition holds:
    modern semgrep, feature branch, resolvable origin/<default>, real
    merge-base."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-sast-")
        self._bin = os.path.join(self._tmp, "bin")
        self._argv_file = os.path.join(self._tmp, "argv.log")
        open(self._argv_file, "w").close()

        # "origin" bare repo with a main branch, and a local clone/checkout
        # with a feature branch one commit ahead -- the standard PR shape.
        origin = os.path.join(self._tmp, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", origin], check=True)

        self._work = os.path.join(self._tmp, "work")
        subprocess.run(["git", "clone", "-q", origin, self._work], check=True)
        env = {**os.environ, **_GIT_ENV}
        readme = os.path.join(self._work, "README")
        with open(readme, "w") as f:
            f.write("hello\n")
        subprocess.run(["git", "add", "README"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        with open(readme, "a") as f:
            f.write("feature change\n")
        subprocess.run(["git", "add", "README"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "feature commit"], check=True, cwd=self._work, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_baseline_commit_flag_passed_on_feature_branch(self):
        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=0)
        result = _run_cmd_sast(
            self._work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self._argv_file) as f:
            argv_lines = f.read()
        self.assertIn("--baseline-commit=", argv_lines,
                       f"expected --baseline-commit in semgrep invocation; stderr={result.stderr}")
        self.assertIn("scoping to diff-introduced findings", result.stderr)

    def test_baseline_commit_resolves_to_actual_merge_base(self):
        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=0)
        merge_base = subprocess.run(
            ["git", "merge-base", "origin/main", "HEAD"],
            check=True, capture_output=True, text=True, cwd=self._work,
        ).stdout.strip()

        result = _run_cmd_sast(
            self._work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self._argv_file) as f:
            argv_lines = f.read()
        self.assertIn(f"--baseline-commit={merge_base}", argv_lines)

    def test_blocking_still_happens_on_scoped_findings(self):
        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=1)
        result = _run_cmd_sast(
            self._work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 1)
        details = _last_sast_audit_details(self._work)
        self.assertIn("ERROR-severity findings introduced since", details or "")


class TestFailClosedFallbacks(unittest.TestCase):
    """Every resolution failure must fall back to the exact prior full-tree
    invocation (no --baseline-commit flag at all) and still block on
    findings -- never silently narrow to an empty/partial scan."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-sast-fc-")
        self._bin = os.path.join(self._tmp, "bin")
        self._argv_file = os.path.join(self._tmp, "argv.log")
        open(self._argv_file, "w").close()

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _assert_full_tree_fallback(self, result):
        self.assertIn("full-tree scan", result.stderr, result.stderr)
        with open(self._argv_file) as f:
            argv_lines = f.read()
        self.assertNotIn("--baseline-commit", argv_lines,
                          "fallback must invoke semgrep exactly as before -- no "
                          "baseline flag, no path restriction")
        # Confirm the exact prior invocation shape is preserved byte-for-byte.
        self.assertIn("--config=auto --error --severity=ERROR", argv_lines)

    def test_old_semgrep_without_baseline_support_falls_back(self):
        work = os.path.join(self._tmp, "work")
        _init_repo_with_branch_setup(self._tmp, work)
        _write_fake_semgrep(self._bin, supports_baseline=False, exit_code=0)

        result = _run_cmd_sast(
            work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_full_tree_fallback(result)
        self.assertIn("does not support --baseline-commit", result.stderr)

    def test_old_semgrep_without_baseline_support_still_blocks(self):
        """The critical fail-closed property: a resolution failure degrades
        to full-tree AND STILL BLOCKS on findings -- it never becomes a
        silent skip."""
        work = os.path.join(self._tmp, "work")
        _init_repo_with_branch_setup(self._tmp, work)
        _write_fake_semgrep(self._bin, supports_baseline=False, exit_code=1)

        result = _run_cmd_sast(
            work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 1)
        self._assert_full_tree_fallback(result)

    def test_detached_head_falls_back(self):
        work = os.path.join(self._tmp, "work")
        _init_repo_with_branch_setup(self._tmp, work)
        env = {**os.environ, **_GIT_ENV}
        head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True,
            text=True, cwd=work,
        ).stdout.strip()
        subprocess.run(["git", "checkout", "-q", head_sha], check=True, cwd=work, env=env)

        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=0)
        result = _run_cmd_sast(
            work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_full_tree_fallback(result)
        self.assertIn("detached HEAD", result.stderr)

    def test_on_default_branch_falls_back(self):
        work = os.path.join(self._tmp, "work")
        _init_repo_with_branch_setup(self._tmp, work)
        env = {**os.environ, **_GIT_ENV}
        subprocess.run(["git", "checkout", "-q", "main"], check=True, cwd=work, env=env)

        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=0)
        result = _run_cmd_sast(
            work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_full_tree_fallback(result)
        self.assertIn("on default branch", result.stderr)

    def test_missing_origin_remote_falls_back(self):
        """No 'origin' remote at all (e.g. a local-only repo) must not
        crash cmd_sast or silently narrow -- it must fall back cleanly."""
        work = os.path.join(self._tmp, "work_no_origin")
        os.makedirs(work)
        _init_repo(work)
        env = {**os.environ, **_GIT_ENV}
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=env)
        readme = os.path.join(work, "f.txt")
        with open(readme, "w") as f:
            f.write("x\n")
        subprocess.run(["git", "add", "f.txt"], check=True, cwd=work, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "feature"], check=True, cwd=work, env=env)

        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=0)
        result = _run_cmd_sast(
            work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_full_tree_fallback(result)
        self.assertIn("not resolvable", result.stderr)

    def test_shallow_clone_missing_base_falls_back(self):
        """A shallow clone whose fetch of the base ref never pulls in the
        actual common ancestor must not fabricate a baseline -- merge-base
        resolution fails and cmd_sast falls back to full-tree.

        Constructed so main and feature diverge at an early commit (c2) that
        is NOT present in either side's shallow (depth=1) history --
        `git merge-base origin/main HEAD` genuinely fails (exit 1, empty
        output) in this shape, verified directly against the real git
        binary before being folded into this test.

        Origin is addressed via an explicit file:// URL rather than a bare
        local path -- git's "local clone" optimization silently ignores
        --depth for path-style local origins (confirmed against the real
        git binary), which would make this fixture accidentally pull full
        history and fail to reproduce the shallow-clone condition at all."""
        origin = os.path.join(self._tmp, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
        origin_url = "file://" + origin

        seed = os.path.join(self._tmp, "seed")
        subprocess.run(["git", "clone", "-q", origin_url, seed], check=True)
        env = {**os.environ, **_GIT_ENV}

        def _commit(name, msg):
            with open(os.path.join(seed, name), "w") as f:
                f.write(msg + "\n")
            subprocess.run(["git", "add", name], check=True, cwd=seed, env=env)
            subprocess.run(["git", "commit", "-q", "-m", msg], check=True, cwd=seed, env=env)

        _commit("f0.txt", "c0")
        _commit("f1.txt", "c1")
        _commit("f2.txt", "c2")
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=seed, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=seed, env=env)
        _commit("feat0.txt", "feat0")
        subprocess.run(["git", "push", "-q", "origin", "HEAD:feature"], check=True, cwd=seed, env=env)
        subprocess.run(["git", "checkout", "-q", "main"], check=True, cwd=seed, env=env)
        _commit("m3.txt", "m3")
        _commit("m4.txt", "m4")
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=seed, env=env)
        subprocess.run(["git", "checkout", "-q", "feature"], check=True, cwd=seed, env=env)
        _commit("feat1.txt", "feat1")
        subprocess.run(["git", "push", "-q", "origin", "HEAD:feature"], check=True, cwd=seed, env=env)

        work = os.path.join(self._tmp, "shallow_work")
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", "feature",
             "--no-single-branch", origin_url, work],
            check=True,
        )
        subprocess.run(["git", "checkout", "-q", "feature"], check=True, cwd=work, env=env)

        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=0)
        result = _run_cmd_sast(
            work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self._assert_full_tree_fallback(result)
        self.assertIn("merge-base resolution failed", result.stderr,
                       "the skip reason is echoed inline in the full-tree-scan "
                       "notice line, not just logged to the audit DB")


def _init_repo_with_branch_setup(tmp, work):
    """Shared origin+feature-branch fixture used by several fallback tests."""
    origin = os.path.join(tmp, "origin.git")
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    subprocess.run(["git", "clone", "-q", origin, work], check=True)
    env = {**os.environ, **_GIT_ENV}
    readme = os.path.join(work, "README")
    with open(readme, "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=work, env=env)
    subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=env)
    subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=env)
    with open(readme, "a") as f:
        f.write("feature change\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "feature commit"], check=True, cwd=work, env=env)


class TestSemgrepIgnoreStillHonored(unittest.TestCase):
    """.semgrepignore is native semgrep behavior (no clagentic-lite code
    reads it) -- this just confirms the fix does not remove or shadow it by
    checking the invocation never adds a path argument that would make
    semgrep treat .semgrepignore differently."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-sast-ignore-")
        self._bin = os.path.join(self._tmp, "bin")
        self._argv_file = os.path.join(self._tmp, "argv.log")
        open(self._argv_file, "w").close()

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_no_path_argument_added_in_baseline_mode(self):
        work = os.path.join(self._tmp, "work")
        _init_repo_with_branch_setup(self._tmp, work)
        _write_fake_semgrep(self._bin, supports_baseline=True, exit_code=0)

        result = _run_cmd_sast(
            work, self._bin, self._argv_file,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self._argv_file) as f:
            argv_lines = f.read().strip()
        # Exactly --config=auto --error --severity=ERROR --baseline-commit=<sha>,
        # no trailing path -- semgrep still walks (and applies .semgrepignore
        # to) the whole tree; --baseline-commit only narrows which findings
        # are REPORTED, not what gets walked.
        parts = argv_lines.split()
        self.assertNotIn(".", parts)
        self.assertEqual(parts[0], "--config=auto")


@unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
class TestRealSemgrepSupportsBaselineFlag(unittest.TestCase):
    """cmd_sast probes --baseline-commit support via `semgrep --help`. If a
    future semgrep release renames or drops the flag, this test catches it
    directly against the real installed binary -- a silent probe failure
    would otherwise permanently degrade every run to full-tree scoping
    without anyone noticing."""

    def test_help_advertises_baseline_commit(self):
        result = subprocess.run(
            ["semgrep", "scan", "--help"], capture_output=True, text=True,
        )
        self.assertIn("--baseline-commit", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
