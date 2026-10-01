"""
Regression tests for what `enroll`, `update` and `doctor` may write into an
enrolled repo's TRACKED files (.gitignore, CLAUDE.md), in each layout.

Covered defects:
  D1  enroll appended harness patterns to the tracked .gitignore even when
      the operator had moved them to .git/info/exclude.
  D2  `enroll --force` overwrote a CLAUDE.md that has no managed-by marker.
  D3  doctor advised `enroll --force` for a missing CLAUDE.md in a layout
      where that file is deliberately absent.
  D4  the wrapper layout stamped CLAUDE.md and edited .gitignore in the
      nested repo.
  D5  update's ephemeral-file migration deleted every blank line of the
      user's .gitignore.

Every scenario runs against a throwaway clone of the tool (never the live
checkout) and throwaway scratch repos under a temp HOME.

Run with: python3 -m unittest scripts.test_enroll_tracked_file_writes -v
"""
import os
import pty
import shutil
import subprocess
import tempfile
import unittest

from scripts.test_support import clone_this_tool_home_with_overlay

HARNESS_PATTERNS = [".claude/", ".clagentic/lite/"]


def _git(path, *args):
    return subprocess.run(["git", "-C", path] + list(args), check=True,
                          capture_output=True, text=True).stdout.strip()


def _init_repo(path, commit=False):
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", path], check=True, capture_output=True)
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    if commit:
        with open(os.path.join(path, "README"), "w") as f:
            f.write("x\n")
        _git(path, "add", "README")
        _git(path, "commit", "-q", "-m", "init")


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-tracked-writes-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.tool_home = os.path.join(self.tmpdir, "tool-home")
        clone_this_tool_home_with_overlay(self.tool_home)
        self.cli = os.path.join(self.tool_home, "bin", "clagentic-lite")

    def _env(self, **extra):
        # Scrub every CLAGENTIC_* variable so an exported operator setting
        # (e.g. CLAGENTIC_IGNORE_TARGET) cannot change a result.
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAGENTIC_")}
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.tool_home
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.update(extra)
        return env

    def run_cli(self, argv, cwd, **env_extra):
        proc = subprocess.run([self.cli] + argv, cwd=cwd, env=self._env(**env_extra),
                              capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout, proc.stderr

    def run_cli_tty(self, argv, cwd, answer=b"\n", **env_extra):
        """Run with a pty on stdin so the nested-repo (wrapper) prompt fires."""
        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen([self.cli] + argv, cwd=cwd, env=self._env(**env_extra),
                                    stdin=slave, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            os.close(slave)
            os.write(master, answer)
            out, err = proc.communicate(timeout=120)
            return proc.returncode, out, err
        finally:
            os.close(master)

    def run_doctor(self, cwd, repo):
        """Run doctor and assert its exit code is explained by its own output.

        The scratch tool home was never `init`ed, so doctor reports unrelated
        FAIL lines (missing hook shims, PATH) and exits 1. The exit code must be
        non-zero exactly when a FAIL line exists, and no FAIL line may concern
        the enrolled repo under test.
        """
        rc, out, err = self.run_cli(["doctor"], cwd=cwd)
        fail_lines = [l for l in (out + err).splitlines() if l.lstrip().startswith("FAIL")]
        self.assertEqual(rc, 1 if fail_lines else 0, out + err)
        for line in fail_lines:
            self.assertNotIn(repo, line, line)
        return rc, out, err

    def exclude_lines(self, repo):
        path = _git(repo, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude")
        if not os.path.isfile(path):
            return []
        return _read(path).decode().splitlines()


class TestRegularLayout(_Base):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_repo(self.repo)

    def test_default_target_writes_gitignore(self):
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        lines = _read(os.path.join(self.repo, ".gitignore")).decode().splitlines()
        for pat in HARNESS_PATTERNS:
            self.assertIn(pat, lines)

    def test_exclude_target_leaves_gitignore_byte_identical(self):
        gi = os.path.join(self.repo, ".gitignore")
        original = b"build/\n\n# keep\n\nnode_modules/\n"
        _write(gi, original)
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo,
                                   CLAGENTIC_IGNORE_TARGET="exclude")
        self.assertEqual(rc, 0, err)
        self.assertEqual(_read(gi), original)
        for pat in HARNESS_PATTERNS:
            self.assertIn(pat, self.exclude_lines(self.repo))
        # Second enroll is a no-op; so is a forced re-enroll.
        before = self.exclude_lines(self.repo)
        rc, _o, err = self.run_cli(["enroll", "--force", self.repo], cwd=self.repo,
                                   CLAGENTIC_IGNORE_TARGET="exclude")
        self.assertEqual(rc, 0, err)
        self.assertEqual(_read(gi), original)
        self.assertEqual(self.exclude_lines(self.repo), before)

    def test_exclude_target_does_not_create_gitignore(self):
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo,
                                   CLAGENTIC_IGNORE_TARGET="exclude")
        self.assertEqual(rc, 0, err)
        self.assertFalse(os.path.exists(os.path.join(self.repo, ".gitignore")))

    def test_patterns_already_in_info_exclude_are_not_readded_to_gitignore(self):
        # D1: the operator moved the patterns to info/exclude on purpose.
        exclude = os.path.join(self.repo, ".git", "info", "exclude")
        os.makedirs(os.path.dirname(exclude), exist_ok=True)
        _write(exclude, ("\n".join(HARNESS_PATTERNS) + "\n").encode())
        gi = os.path.join(self.repo, ".gitignore")
        original = b"build/\n"
        _write(gi, original)
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        self.assertEqual(_read(gi), original)

    def test_gitignore_without_trailing_newline_is_not_glued(self):
        gi = os.path.join(self.repo, ".gitignore")
        _write(gi, b"build/")
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        lines = _read(gi).decode().splitlines()
        self.assertEqual(lines[0], "build/")
        for pat in HARNESS_PATTERNS:
            self.assertIn(pat, lines)

    def test_governance_files_stay_trackable(self):
        _init_repo(self.repo)
        rc, _o, err = self.run_cli(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, err)
        os.makedirs(os.path.join(self.repo, ".clagentic"), exist_ok=True)
        for name in ("adversarial-acks.json", "osv-ignore", "accepted-risks.md", "config"):
            _write(os.path.join(self.repo, ".clagentic", name), b"x\n")
            proc = subprocess.run(["git", "-C", self.repo, "check-ignore", "-q",
                                   ".clagentic/" + name])
            self.assertNotEqual(proc.returncode, 0, name + " must not be ignored")


class TestForceNeverClobbersProjectClaudeMd(_Base):
    def test_force_leaves_unmanaged_claude_md_and_names_manual_step(self):
        repo = os.path.join(self.tmpdir, "repo")
        _init_repo(repo)
        target = os.path.join(repo, "CLAUDE.md")
        original = b"# Project rules\n\nDo not touch.\n"
        _write(target, original)
        rc, _o, err = self.run_cli(["enroll", "--force", repo], cwd=repo)
        self.assertEqual(rc, 0, err)
        self.assertEqual(_read(target), original)
        self.assertIn("delete or rename", err)


class TestWorktreeAndSubmodule(_Base):
    def test_worktree_exclude_resolves_through_git_path(self):
        main = os.path.join(self.tmpdir, "main-repo")
        _init_repo(main, commit=True)
        wt = os.path.join(self.tmpdir, "linked-wt")
        _git(main, "worktree", "add", "-q", "-b", "wt-branch", wt)
        self.assertTrue(os.path.isfile(os.path.join(wt, ".git")), "worktree .git must be a file")
        before = _read(os.path.join(wt, ".git"))
        rc, _o, err = self.run_cli(["enroll", wt], cwd=wt, CLAGENTIC_IGNORE_TARGET="exclude")
        self.assertEqual(rc, 0, err)
        self.assertEqual(_read(os.path.join(wt, ".git")), before)
        self.assertTrue(os.path.isfile(os.path.join(wt, ".git")))
        for pat in HARNESS_PATTERNS:
            self.assertIn(pat, self.exclude_lines(wt))
        self.assertFalse(os.path.exists(os.path.join(wt, ".gitignore")))

    def test_submodule_exclude_resolves_through_git_path(self):
        sub_src = os.path.join(self.tmpdir, "sub-src")
        _init_repo(sub_src, commit=True)
        parent = os.path.join(self.tmpdir, "parent")
        _init_repo(parent, commit=True)
        subprocess.run(["git", "-C", parent, "-c", "protocol.file.allow=always",
                        "submodule", "add", "-q", sub_src, "sub"],
                       check=True, capture_output=True)
        sub = os.path.join(parent, "sub")
        self.assertTrue(os.path.isfile(os.path.join(sub, ".git")), "submodule .git must be a file")
        before = _read(os.path.join(sub, ".git"))
        rc, _o, err = self.run_cli(["enroll", sub], cwd=sub, CLAGENTIC_IGNORE_TARGET="exclude")
        self.assertEqual(rc, 0, err)
        self.assertEqual(_read(os.path.join(sub, ".git")), before)
        for pat in HARNESS_PATTERNS:
            self.assertIn(pat, self.exclude_lines(sub))


class TestWrapperLayout(_Base):
    def setUp(self):
        super().setUp()
        self.wrapper = os.path.join(self.tmpdir, "wrapper")
        self.nested = os.path.join(self.wrapper, "proj")
        os.makedirs(self.wrapper)
        _init_repo(self.nested)
        self.gi = os.path.join(self.nested, ".gitignore")
        self.original_gi = b"dist/\n\n# mine\n"
        _write(self.gi, self.original_gi)

    def _enroll_wrapper(self):
        rc, out, err = self.run_cli_tty(["enroll", self.wrapper], cwd=self.wrapper)
        self.assertEqual(rc, 0, out + err)

    def test_nested_repo_tracked_files_untouched(self):
        self._enroll_wrapper()
        self.assertEqual(_read(self.gi), self.original_gi)
        self.assertFalse(os.path.exists(os.path.join(self.nested, "CLAUDE.md")))
        for pat in HARNESS_PATTERNS:
            self.assertIn(pat, self.exclude_lines(self.nested))
        # Wrapper files are stamped.
        self.assertTrue(os.path.isfile(os.path.join(self.wrapper, "CLAUDE.md")))
        self.assertTrue(os.path.isfile(os.path.join(self.wrapper, ".claude", "settings.json")))
        self.assertTrue(os.path.isfile(os.path.join(self.wrapper, ".clagentic-project")))

    def test_doctor_reports_no_missing_claude_md_warning(self):
        self._enroll_wrapper()
        rc, out, err = self.run_doctor(self.tmpdir, self.nested)
        self.assertIn("no CLAUDE.md by design", out)
        for line in out.splitlines():
            if self.nested in line and "CLAUDE.md" in line:
                self.assertNotIn("WARN", line, line)
                self.assertNotIn("missing", line, line)

    def test_managed_nested_claude_md_keeps_restamp_behavior(self):
        managed = os.path.join(self.nested, "CLAUDE.md")
        template = _read(os.path.join(self.tool_home, "share", "hook-shims", "CLAUDE.md.template"))
        _write(managed, template + b"\nproject-owned line\n")
        self._enroll_wrapper()
        body = _read(managed)
        self.assertIn(b"managed-by: clagentic", body)
        self.assertIn(b"project-owned line", body)

    def test_doctor_info_for_existing_harness_lines_in_nested_gitignore(self):
        self._enroll_wrapper()
        _write(self.gi, self.original_gi + b".claude/\n")
        rc, out, err = self.run_doctor(self.tmpdir, self.nested)
        self.assertTrue(any("INFO" in l and self.nested in l and ".gitignore" in l
                            for l in out.splitlines()), out)
        self.assertEqual(_read(self.gi), self.original_gi + b".claude/\n")


class TestWrapperLayoutTwoLevelsDeep(_Base):
    def test_deeply_nested_repo_is_treated_as_wrapper_enrolled(self):
        wrapper = os.path.join(self.tmpdir, "wrapper")
        nested = os.path.join(wrapper, "group", "proj")
        _init_repo(nested)
        gi = os.path.join(nested, ".gitignore")
        original = b"dist/\n\n# mine\n"
        _write(gi, original)
        rc, out, err = self.run_cli_tty(["enroll", wrapper], cwd=wrapper)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(_read(gi), original)
        self.assertFalse(os.path.exists(os.path.join(nested, "CLAUDE.md")))
        for pat in HARNESS_PATTERNS:
            self.assertIn(pat, self.exclude_lines(nested))


class TestUpdateMigrationPreservesGitignore(_Base):
    def test_only_legacy_lines_change(self):
        repo = os.path.join(self.tmpdir, "repo")
        _init_repo(repo)
        rc, _o, err = self.run_cli(["enroll", repo], cwd=repo)
        self.assertEqual(rc, 0, err)
        # Simulate a pre-migration repo: ephemeral file at the old location,
        # no new lite/ dir, legacy per-file patterns mixed into user content.
        shutil.rmtree(os.path.join(repo, ".clagentic", "lite"))
        _write(os.path.join(repo, ".clagentic", "audit.db"), b"x")
        gi = os.path.join(repo, ".gitignore")
        _write(gi, b"build/\n\n# comment\n.clagentic/audit.db\n\n.clagentic/memory.db\nvendor/\n.claude/\n")
        # The migration runs before update touches the tool home. The overlay
        # leaves the scratch tool home dirty, so a non-tty update then refuses
        # (fail closed) -- after the migration, which is all this test needs.
        self.run_cli(["update"], cwd=repo)
        self.assertEqual(
            _read(gi),
            b"build/\n\n# comment\n\nvendor/\n.claude/\n.clagentic/lite/\n",
        )


if __name__ == "__main__":
    unittest.main()
