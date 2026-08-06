"""
Regression tests for the clagentic-router settings.json env-block stamp
(lr-49f25e).

CLAGENTIC_ROUTER_URL is the opt-in switch. The load-bearing property this
file proves mechanically (per the task's "prove it with a test, do not
assert it" acceptance bar) is:

    With CLAGENTIC_ROUTER_URL unset, `clagentic-lite enroll` stamps a
    .claude/settings.json byte-for-byte identical to the pre-router
    baseline -- the plain __CLAGENTIC_LITE_HOME__ substitution of
    share/hook-shims/claude-settings.template, nothing else.

A secondary test proves the opt-in path actually works when set: the env
block appears with the router URL and token substituted in.

These tests invoke the ACTUAL bin/clagentic-lite `enroll` command via
subprocess against a real temp git repo -- a Python reimplementation of the
sed/line-substitution logic would not catch a regression in the real shell
code (same rationale as test_bin_clagentic_lite_symlink_self_locate.py).

Run with: python3 -m unittest scripts/test_router_settings_stamp.py -v
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")
TEMPLATE = os.path.join(TOOL_HOME, "share", "hook-shims", "claude-settings.template")


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


class TestRouterSettingsStampInertWhenUnset(unittest.TestCase):
    """CLAGENTIC_ROUTER_URL unset: settings.json must be byte-for-byte
    identical to plain __CLAGENTIC_LITE_HOME__ substitution -- no env block,
    no trace that the router feature exists in the stamped artifact."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-stamp-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def _expected_baseline(self):
        """The exact output the pre-router sed-only substitution would have
        produced: __CLAGENTIC_LITE_HOME__ replaced, no other transformation."""
        with open(TEMPLATE) as f:
            lines = f.readlines()
        out = []
        for line in lines:
            if "__CLAGENTIC_ROUTER_ENV_BLOCK__" in line:
                continue  # sentinel line must vanish entirely when unset
            out.append(line.replace("__CLAGENTIC_LITE_HOME__", TOOL_HOME))
        return "".join(out)

    def test_enroll_settings_json_byte_identical_to_baseline(self):
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        self.assertTrue(os.path.isfile(settings_path), "settings.json was not stamped")
        with open(settings_path) as f:
            actual = f.read()

        self.assertEqual(actual, self._expected_baseline(),
                          msg="settings.json diverged from the pre-router baseline "
                              "with CLAGENTIC_ROUTER_URL unset -- inert-when-unset violated")
        self.assertNotIn("__CLAGENTIC_ROUTER_ENV_BLOCK__", actual)
        self.assertNotIn("ANTHROPIC_BASE_URL", actual)
        self.assertNotIn('"env"', actual)

    def test_enroll_settings_json_is_valid_json(self):
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        # Strip the $comment-carrying first line's trailing content isn't
        # valid JSON on its own with a bare $comment key duplicated across
        # both stamp variants -- just confirm the whole file parses.
        json.loads(raw)


class TestRouterSettingsStampWhenSet(unittest.TestCase):
    """CLAGENTIC_ROUTER_URL set: env block appears with the configured URL
    and token substituted in, and CLAUDE_SETTINGS_VERSION reflects v6."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-stamp-set-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_enroll_stamps_env_block_when_router_url_set(self):
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
            raw = f.read()

        parsed = json.loads(raw)
        self.assertIn("env", parsed, msg=raw)
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8765")
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "test-token-value")
        self.assertNotIn("__CLAGENTIC_ROUTER_ENV_BLOCK__", raw)

    def test_enroll_stamps_empty_token_when_url_set_but_token_unset(self):
        """Router URL set without a token (e.g. passthrough-only use) still
        stamps the ANTHROPIC_AUTH_TOKEN key, explicitly empty -- never
        silently omitted."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765"},
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertIn("ANTHROPIC_AUTH_TOKEN", parsed["env"])
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "")

    def test_settings_version_marker_is_v6(self):
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        self.assertIn("clagentic-settings-version: v6", raw, msg=raw)


class TestRouterSettingsStampRestamp(unittest.TestCase):
    """`clagentic-lite update --restamp` re-stamps settings.json through the
    same shared renderer -- inert-when-unset holds on the restamp path too,
    not just first-time enroll.

    IMPORTANT: `cmd_update` runs `git -C "$CLAGENTIC_LITE_HOME" stash push`
    (and, on a non-tty, `stash drop`) against whatever CLAGENTIC_LITE_HOME
    points at when it finds local modifications -- so this test MUST point
    CLAGENTIC_LITE_HOME at a throwaway git clone of the real checkout, never
    at the real dev checkout itself. Pointing it at the real tree would let
    `update`'s non-tty "discard uncommitted changes" path silently stash-and
    -drop a developer's in-progress edits.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-restamp-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

        # Throwaway clone of the real checkout -- cmd_update's git pull/stash
        # logic runs against THIS, never against TOOL_HOME.
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        subprocess.run(["git", "clone", "-q", TOOL_HOME, self.fake_tool_home],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", self.fake_tool_home, "config", "user.email", "test@example.com"],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", self.fake_tool_home, "config", "user.name", "Test"],
                        check=True, capture_output=True)

    def _run_cli_fake_home(self, argv, cwd, env_extra=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        env.pop("CLAGENTIC_ROUTER_TOKEN", None)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite")] + argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_restamp_with_router_url_set_adds_env_block(self):
        rc, out, err = self._run_cli_fake_home(["enroll", self.repo], cwd=self.repo)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        # Simulate a stale install: downgrade the version marker so
        # cmd_update's version-compare decides a restamp is needed.
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        raw = raw.replace("clagentic-settings-version: v6", "clagentic-settings-version: v5")
        with open(settings_path, "w") as f:
            f.write(raw)

        # Register the repo so cmd_update's restamp sweep finds it.
        registry_dir = os.path.join(self.home, ".local", "state", "clagentic")
        os.makedirs(registry_dir, exist_ok=True)
        with open(os.path.join(registry_dir, "registry"), "w") as f:
            f.write(self.repo + "\n")

        rc, out, err = self._run_cli_fake_home(
            ["update", "--restamp"],
            cwd=self.repo,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "restamp-token",
                "CLAGENTIC_SKIP_FETCH": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8765")


class TestRouterUrlValidation(unittest.TestCase):
    """CLAGENTIC_ROUTER_URL is a traffic-interception primitive (BOBBIE
    finding, PR #146 review 5208927288) -- validated before it is ever
    stamped into settings.json or probed by doctor. Three classes:
        malformed  -- refused (enroll/update fail, nothing stamped)
        nonlocal   -- allowed, but warned loudly (stamp time AND doctor)
        local      -- silent, same as before this change

    Unset stays untouched by any of this -- covered by
    TestRouterSettingsStampInertWhenUnset above; this class only adds cases
    for a URL that IS set, so it does not regress that proof.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-url-validation-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_malformed_url_refused_at_enroll(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "not-a-url"},
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("not a well-formed", err, msg=err)
        self.assertIn("CLAGENTIC_ROUTER_URL", err, msg=err)

    def test_malformed_url_leaves_no_settings_json_env_block(self):
        """A refused enroll must not leave a half-written settings.json with
        the malformed value baked in -- die() aborts before any output is
        written to the target file (redirection creates the file, but the
        function's own stdout is empty when it dies before printing)."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "ftp://example.com"},
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        if os.path.isfile(settings_path):
            with open(settings_path) as f:
                content = f.read()
            self.assertNotIn("ftp://example.com", content, msg=content)

    def test_url_with_no_host_refused(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "http://"},
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("CLAGENTIC_ROUTER_URL", err, msg=err)

    def test_valid_localhost_accepted_silently(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "http://localhost:8765"},
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertNotIn("NON-LOCAL", err, msg=err)
        self.assertNotIn("WARN", err, msg=err)

    def test_valid_127_0_0_1_accepted_silently(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765"},
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertNotIn("NON-LOCAL", err, msg=err)

    def test_nonlocal_host_allowed_but_warned_at_stamp_time(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "http://router.example.com:8765"},
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("NON-LOCAL", err, msg=err)
        self.assertIn("router.example.com", err, msg=err)
        self.assertIn("credentials", err, msg=err)

        # Allowed means it still stamps -- this is a warning, not a refusal.
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://router.example.com:8765")

    def test_doctor_reports_malformed_url_as_fail(self):
        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1", "CLAGENTIC_ROUTER_URL": "not-a-url"},
        )
        # doctor itself never dies on a bad probe target -- it reports FAIL
        # (via _fail, which writes to stderr, same as every other doctor
        # check) and continues the rest of the diagnostic sweep.
        self.assertIn("FAIL", err, msg=err)
        self.assertIn("not a well-formed", err, msg=err)
        self.assertIn("== doctor summary:", out, msg=out)

    def test_doctor_reports_nonlocal_host_warning(self):
        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_SKIP_UPDATE_ALERT": "1",
                "CLAGENTIC_ROUTER_URL": "http://router.example.com:8765",
            },
        )
        self.assertIn("NON-LOCAL", out, msg=out)
        self.assertIn("router.example.com", out, msg=out)

    def test_doctor_silent_on_local_host_beyond_the_probe_itself(self):
        """Doctor still runs its GET /version probe (which will report
        unreachable in this sandbox -- no live router) but must not print
        any NON-LOCAL/malformed warning for a well-formed local URL."""
        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_SKIP_UPDATE_ALERT": "1",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:19999",
            },
        )
        self.assertNotIn("NON-LOCAL", out, msg=out)
        self.assertNotIn("not a well-formed", out, msg=out)


if __name__ == "__main__":
    unittest.main()
