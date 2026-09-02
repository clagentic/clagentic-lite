"""
Regression tests for lr-684947's remaining concerns beyond the empty-token
fix (scripts/test_router_settings_stamp.py /
scripts/test_router_bedrock_settings_stamp.py cover that one):

    Concern 1 -- `clagentic-lite rotate`: walks the registry, re-stamps every
    enrolled repo's settings.json, names an unreachable/stale member on
    stderr, and exits non-zero if any member could not be rotated.

    Concern 2 -- `apiKeyHelper` (CLAGENTIC_ROUTER_USE_API_KEY_HELPER=1): the
    literal ANTHROPIC_AUTH_TOKEN key is REMOVED (not merely supplemented)
    when the helper is stamped, because apiKeyHelper ranks below
    ANTHROPIC_AUTH_TOKEN in Claude Code's own credential precedence -- a
    non-empty literal alongside the helper would silently win.

    Concern 4 -- `clagentic-lite doctor` reports how many enrolled repos
    hold a stamped literal credential vs. an apiKeyHelper.

    Agnostic-tool hardening -- .claude/settings.json is stamped at mode
    0600, not the default-umask 0644, on every stamp path (enroll, restamp,
    rotate).

Acceptance test 3 from lr-684947 comment #1 (three enrolled repos, one
deleted, `rotate` names it and exits non-zero) is TestRotate's own
test_rotate_reports_unreachable_member_and_exits_nonzero.
Acceptance test 4 (doctor prints the stamped-token count) is
TestDoctorTokenCount. Acceptance test 5 (enrolling into a repo with no
.gitignore creates one containing .claude/, and git status --porcelain
shows no .claude/ entry) is TestGitignoreRegression -- pre-existing
behavior (bin/clagentic-lite's _enroll_one), given a dedicated regression
test here per the task's explicit ask, since none existed before.

Run with: python3 -m unittest scripts/test_router_token_rotate_and_credential_hardening.py -v
"""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


def _init_git_repo(path):
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", path], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Test"],
                    check=True, capture_output=True)
    fpath = os.path.join(path, "init.txt")
    with open(fpath, "w") as f:
        f.write("initial\n")
    subprocess.run(["git", "-C", path, "add", "init.txt"], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "commit", "-m", "initial"], check=True, capture_output=True)


def _run_cli(argv, cwd, home, env_extra=None):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
    env.pop("CLAGENTIC_HOME", None)
    env.pop("CLAGENTIC_ROUTER_URL", None)
    env.pop("CLAGENTIC_ROUTER_TOKEN", None)
    env.pop("CLAGENTIC_ROUTER_USE_API_KEY_HELPER", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [CLI] + argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestSettingsJsonMode0600(unittest.TestCase):
    """Agnostic-tool hardening: .claude/settings.json is never left at the
    default-umask mode (typically 0644) -- a released tool cannot know
    whether it runs on a single-user workstation or a shared host."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-settings-mode-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_enroll_stamps_settings_json_at_0600(self):
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        mode = stat.S_IMODE(os.stat(settings_path).st_mode)
        self.assertEqual(oct(mode), oct(0o600), msg=f"settings.json mode was {oct(mode)}, expected 0600")

    def test_enroll_stamps_0600_even_with_no_router_configured(self):
        """Mode tightening applies unconditionally -- not just when a
        credential is actually present today."""
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        self.assertNotIn('"env"', raw)  # no router configured
        mode = stat.S_IMODE(os.stat(settings_path).st_mode)
        self.assertEqual(oct(mode), oct(0o600))


class TestApiKeyHelper(unittest.TestCase):
    """CLAGENTIC_ROUTER_USE_API_KEY_HELPER=1 (concern 2): stamps a top-level
    apiKeyHelper command and REMOVES the literal ANTHROPIC_AUTH_TOKEN --
    apiKeyHelper ranks below ANTHROPIC_AUTH_TOKEN in Claude Code's own
    credential chain, so leaving both would make the helper silently inert."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-api-key-helper-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_helper_stamped_and_literal_token_removed(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token-value",
                "CLAGENTIC_ROUTER_USE_API_KEY_HELPER": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        parsed = json.loads(raw)
        self.assertIn("apiKeyHelper", parsed, msg=raw)
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", parsed["env"], msg=raw)
        # The literal token value itself must never appear anywhere in the
        # stamped file -- the whole point of the helper path.
        self.assertNotIn("test-token-value", raw, msg=raw)
        # Base URL still stamps normally.
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8765")

    def test_helper_off_by_default_even_with_token_set(self):
        """Opt-in only -- setting CLAGENTIC_ROUTER_TOKEN alone must not
        silently switch delivery mechanisms."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token-value",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertNotIn("apiKeyHelper", parsed, msg=parsed)
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "test-token-value")

    def test_helper_command_reads_from_global_config_not_embedded_literal(self):
        """The stamped apiKeyHelper command string must not itself contain
        the token value -- it reads GLOBAL_CONFIG at Claude Code's own call
        time, so rotating the token is a single-file edit."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "super-secret-value",
                "CLAGENTIC_ROUTER_USE_API_KEY_HELPER": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        helper_cmd = parsed["apiKeyHelper"]
        self.assertNotIn("super-secret-value", helper_cmd)
        self.assertIn("CLAGENTIC_ROUTER_TOKEN", helper_cmd)
        self.assertIn(os.path.join(self.home, ".config", "clagentic", "lite", "config"), helper_cmd)

    def test_helper_command_survives_a_space_in_global_config_path(self):
        """bobbie.sast.1 (lr-684947 fold-in): GLOBAL_CONFIG is substituted
        into the generated apiKeyHelper command string. A $HOME containing a
        space (unremarkable on macOS) must not split into two grep argv
        tokens -- the helper must still execute and return the token."""
        space_home = os.path.join(self.tmpdir, "home with space")
        os.makedirs(space_home)
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=space_home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "space-path-token",
                "CLAGENTIC_ROUTER_USE_API_KEY_HELPER": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        parsed = json.loads(raw)  # must remain valid JSON despite the embedded quoting
        helper_cmd = parsed["apiKeyHelper"]
        self.assertNotIn('"', helper_cmd, msg=helper_cmd)  # no double quotes to JSON-escape

        # Global config is written by `init`, not `enroll` -- write it by
        # hand here to exercise the helper command as Claude Code would run
        # it (a fresh sh -c invocation, independent of this process's env).
        global_config_dir = os.path.join(space_home, ".config", "clagentic", "lite")
        os.makedirs(global_config_dir, exist_ok=True)
        global_config_path = os.path.join(global_config_dir, "config")
        with open(global_config_path, "w") as f:
            f.write("CLAGENTIC_ROUTER_TOKEN=space-path-token\n")

        proc = subprocess.run(
            ["sh", "-c", helper_cmd],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout!r} stderr={proc.stderr!r}")
        self.assertEqual(proc.stdout.strip(), "space-path-token", msg=proc.stdout)


class TestRotate(unittest.TestCase):
    """`clagentic-lite rotate` (concern 1): walks the registry, re-stamps
    every enrolled repo, names an unreachable member, exits non-zero if any
    member is stale."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-rotate-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)

    def test_rotate_with_no_registry_is_a_clean_noop(self):
        rc, out, err = _run_cli(["rotate"], cwd=self.home, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

    def test_rotate_updates_token_across_enrolled_repos(self):
        repo_a = os.path.join(self.tmpdir, "repo-a")
        repo_b = os.path.join(self.tmpdir, "repo-b")
        _init_git_repo(repo_a)
        _init_git_repo(repo_b)

        for repo in (repo_a, repo_b):
            rc, out, err = _run_cli(
                ["enroll", repo],
                cwd=repo,
                home=self.home,
                env_extra={
                    "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                    "CLAGENTIC_ROUTER_TOKEN": "old-token",
                },
            )
            self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        rc, out, err = _run_cli(
            ["rotate"],
            cwd=self.home,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "new-rotated-token",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        for repo in (repo_a, repo_b):
            settings_path = os.path.join(repo, ".claude", "settings.json")
            with open(settings_path) as f:
                parsed = json.load(f)
            self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "new-rotated-token",
                              msg=f"{repo} settings.json was not rotated: {parsed}")

    def test_rotate_reports_unreachable_member_and_exits_nonzero(self):
        """Acceptance test 3 (lr-684947 comment #1): 3 enrolled repos, one
        deleted -- rotate exits non-zero, names the unreachable member, and
        the surviving two carry the new value."""
        repo_a = os.path.join(self.tmpdir, "repo-a")
        repo_b = os.path.join(self.tmpdir, "repo-b")
        repo_c = os.path.join(self.tmpdir, "repo-c")
        for repo in (repo_a, repo_b, repo_c):
            _init_git_repo(repo)
            rc, out, err = _run_cli(
                ["enroll", repo],
                cwd=repo,
                home=self.home,
                env_extra={
                    "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                    "CLAGENTIC_ROUTER_TOKEN": "old-token",
                },
            )
            self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        # Delete repo_c entirely -- still a registry member, but unreachable.
        shutil.rmtree(repo_c)

        rc, out, err = _run_cli(
            ["rotate"],
            cwd=self.home,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "new-rotated-token",
            },
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn(repo_c, err, msg=err)

        for repo in (repo_a, repo_b):
            settings_path = os.path.join(repo, ".claude", "settings.json")
            with open(settings_path) as f:
                parsed = json.load(f)
            self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "new-rotated-token",
                              msg=f"{repo} settings.json was not rotated: {parsed}")

    def test_rotate_reports_settings_json_missing(self):
        """A registry entry whose directory and .git both still exist but
        whose .claude/settings.json is gone (e.g. manually deleted, or an
        enroll that was interrupted) is reported stale by name, not
        silently skipped."""
        repo = os.path.join(self.tmpdir, "repo-nosettings")
        _init_git_repo(repo)
        rc, out, err = _run_cli(
            ["enroll", repo],
            cwd=repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "old-token",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        os.remove(os.path.join(repo, ".claude", "settings.json"))

        rc, out, err = _run_cli(["rotate"], cwd=self.home, home=self.home)
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn(repo, err, msg=err)


class TestDoctorTokenCount(unittest.TestCase):
    """Acceptance test 4 (lr-684947 comment #1): `doctor` reports how many
    enrolled repos hold a stamped credential."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-doctor-count-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)

    def test_doctor_counts_stamped_literal_tokens(self):
        repo_a = os.path.join(self.tmpdir, "repo-a")
        repo_b = os.path.join(self.tmpdir, "repo-b")
        _init_git_repo(repo_a)
        _init_git_repo(repo_b)

        rc, out, err = _run_cli(
            ["enroll", repo_a],
            cwd=repo_a,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "token-a",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        rc, out, err = _run_cli(["enroll", repo_b], cwd=repo_b, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.home,
            home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("1 enrolled repo(s) hold a stamped literal credential", out, msg=out)

    def test_doctor_counts_zero_when_no_router_configured_anywhere(self):
        repo = os.path.join(self.tmpdir, "repo-plain")
        _init_git_repo(repo)
        rc, out, err = _run_cli(["enroll", repo], cwd=repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.home,
            home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("0 enrolled repo(s) hold a stamped literal credential", out, msg=out)

    def test_doctor_prints_no_fan_out_summary_when_no_registry_exists(self):
        """amos.path-choice.3 (lr-684947 fold-in): on a host with no
        registry at all, doctor must print only '(no registry at ...)' and
        must NOT also print a 0-literal/0-helper fan-out summary -- that
        would announce a fan-out statistic to a user who never enrolled
        anything. No enroll call in this test -- self.home has no registry
        by construction."""
        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.home,
            home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("(no registry at", out, msg=out)
        self.assertNotIn("router token/credential fan-out", out, msg=out)

    def test_doctor_distinguishes_helper_from_literal_count(self):
        repo = os.path.join(self.tmpdir, "repo-helper")
        _init_git_repo(repo)
        rc, out, err = _run_cli(
            ["enroll", repo],
            cwd=repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "token-helper",
                "CLAGENTIC_ROUTER_USE_API_KEY_HELPER": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.home,
            home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("0 enrolled repo(s) hold a stamped literal credential", out, msg=out)
        self.assertIn("1 hold an apiKeyHelper", out, msg=out)


class TestGitignoreRegression(unittest.TestCase):
    """Acceptance test 5 (lr-684947 comment #1): enrolling into a repo with
    no .gitignore creates one containing .claude/, and
    `git status --porcelain` shows no .claude/ entry. Pre-existing behavior
    (bin/clagentic-lite's _enroll_one, currently around line 2433 per the
    task brief -- confirm current line before citing it, it moves); worth a
    dedicated regression test given what it protects (the supported
    enrollment path never committing a stamped credential), and none
    existed before this task."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-gitignore-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_enroll_creates_gitignore_with_claude_pattern(self):
        gitignore_path = os.path.join(self.repo, ".gitignore")
        self.assertFalse(os.path.isfile(gitignore_path), "test fixture should start with no .gitignore")

        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "some-token",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        self.assertTrue(os.path.isfile(gitignore_path), ".gitignore was not created")
        with open(gitignore_path) as f:
            content = f.read()
        self.assertIn(".claude/", content.splitlines())

    def test_enrolled_settings_json_never_shows_in_git_status(self):
        """The end-to-end property the .gitignore write exists to
        guarantee: a settings.json carrying a live credential never shows
        up as trackable in git status, on the supported enrollment path."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "some-token",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        status = subprocess.run(
            ["git", "-C", self.repo, "status", "--porcelain"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertNotIn(".claude/settings.json", status, msg=status)
        self.assertNotIn(".claude", status, msg=status)


if __name__ == "__main__":
    unittest.main()
