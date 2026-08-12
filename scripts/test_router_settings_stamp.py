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

    def test_settings_version_marker_is_v7(self):
        # v6 -> v7 bumped by lr-4af4c4 (ANTHROPIC_BEDROCK_BASE_URL /
        # AWS_BEARER_TOKEN_BEDROCK support) -- a migration, not a
        # content-only change.
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        self.assertIn("clagentic-settings-version: v7", raw, msg=raw)


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
        raw = raw.replace("clagentic-settings-version: v7", "clagentic-settings-version: v6")
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


class TestRouterUrlClassifierBypasses(unittest.TestCase):
    """Negative fixtures for bobbie.sast.access-control-bypass, PR #146
    review 5209002495 (second round on _router_url_classify):

        Finding 1 -- USERINFO BYPASS: the classifier split host:port on the
        first ":" without ever stripping RFC 3986 userinfo, so
        "http://127.0.0.1:x@evil.com/" read as host "127.0.0.1" while the
        real HTTP connection target is evil.com.

        Finding 2 -- GLOB-PREFIX BYPASS: "127.*" was a shell glob PREFIX
        match, not an IP literal/CIDR test, so any host merely starting
        with "127." (e.g. "127.0.0.1.evil.com") classified local.

    Both were the same underlying defect: string-shaped matching standing
    in for structured parsing of a fully attacker-controlled value. Each
    case here asserts BOTH the intended classification (via enroll's
    exit code / stamped settings.json) AND the corresponding signal (a
    NON-LOCAL warning in stderr, or none) actually fires -- not just one
    or the other.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-url-bypass-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def _assert_nonlocal(self, url):
        """Asserts a URL is classified nonlocal: enroll succeeds (allowed,
        not refused), a NON-LOCAL warning fires naming the URL, AND the
        value is still stamped verbatim (allowed-but-warned, not silently
        rewritten to something safe)."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": url},
        )
        self.assertEqual(rc, 0, msg=f"url={url!r} stdout={out!r} stderr={err!r}")
        self.assertIn("NON-LOCAL", err, msg=f"url={url!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], url,
                          msg=f"url={url!r}: allowed means still stamped verbatim")

    def _assert_local(self, url):
        """Asserts a URL is classified local: enroll succeeds and NO
        NON-LOCAL warning fires."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": url},
        )
        self.assertEqual(rc, 0, msg=f"url={url!r} stdout={out!r} stderr={err!r}")
        self.assertNotIn("NON-LOCAL", err, msg=f"url={url!r} stderr={err!r}")

    # ---- Finding 1: userinfo bypass ----

    def test_userinfo_bypass_single_at_classified_nonlocal(self):
        """The exact PoC from the finding: naive first-':' split reads
        '127.0.0.1' as host; the real connection target is evil.com."""
        self._assert_nonlocal("http://127.0.0.1:x@evil.com/")

    def test_userinfo_bypass_double_at_resolves_to_last_at(self):
        """'a@b@evil.com' must resolve host to evil.com (the LAST
        unescaped '@'), not 'b@evil.com' (a naive first/only-@ split).

        Uses `doctor`, not `enroll`: doctor's NON-LOCAL warning prints the
        EXTRACTED host explicitly ("(host: <host>)"), which is what this
        test needs to pin down -- enroll's warning only echoes the full
        original URL verbatim, and "b@evil.com" is trivially a substring
        of "http://a@b@evil.com/" regardless of how the host was parsed,
        so asserting against enroll's message would not actually prove
        anything about which host was extracted."""
        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_SKIP_UPDATE_ALERT": "1",
                "CLAGENTIC_ROUTER_URL": "http://a@b@evil.com/",
            },
        )
        self.assertIn("NON-LOCAL", out, msg=out)
        self.assertIn("host: evil.com", out, msg=out)
        self.assertNotIn("host: b@evil.com", out, msg=out)

    def test_userinfo_with_local_looking_prefix_still_nonlocal(self):
        self._assert_nonlocal("http://localhost:pw@evil.com/")

    def test_userinfo_stripped_correctly_for_genuinely_local_target(self):
        """A userinfo-bearing URL whose REAL host is local must still
        classify local -- userinfo stripping must not overcorrect into
        treating every userinfo-bearing URL as nonlocal."""
        self._assert_local("http://user:pass@127.0.0.1:8765/")

    # ---- Finding 2: glob-prefix bypass ----

    def test_glob_prefix_bypass_ip_suffix_classified_nonlocal(self):
        """The exact PoC from the finding: '127.*' matched this as a
        string prefix with no '@' trick required at all."""
        self._assert_nonlocal("http://127.0.0.1.evil.com/")

    def test_glob_prefix_bypass_localhost_suffix_classified_nonlocal(self):
        self._assert_nonlocal("http://localhost.evil.com/")

    def test_127_x_x_x_still_classifies_local_bounded(self):
        """127.0.0.0/8 membership must still work for real addresses in
        the range -- only the STRING-PREFIX shape was the bug, not
        127.0.0.0/8 recognition itself."""
        self._assert_local("http://127.1.2.3:8765/")
        self._assert_local("http://127.255.255.254/")

    def test_127_out_of_range_octet_classified_nonlocal(self):
        """'127.0.0.256' is not a valid IPv4 address (octet > 255) --
        FAIL TOWARD WARNING: an unrecognized/invalid form is nonlocal,
        never silently treated as local."""
        self._assert_nonlocal("http://127.0.0.256/")

    def test_five_segment_ip_shape_classified_nonlocal(self):
        self._assert_nonlocal("http://127.0.0.1.1/")

    # ---- Encodings the finding explicitly calls out: fail toward warning ----

    def test_ipv6_mapped_ipv4_classified_nonlocal(self):
        """[::ffff:127.0.0.1] is IPv4-mapped IPv6 loopback -- this
        classifier does not attempt to parse it; per the FAIL TOWARD
        WARNING policy it must classify nonlocal, not local."""
        self._assert_nonlocal("http://[::ffff:127.0.0.1]/")

    def test_octal_ip_encoding_classified_nonlocal(self):
        """0177.0.0.1 is an octal encoding of 127.0.0.1 some HTTP clients
        accept -- not decimal-octet parseable by _ipv4_octet_in_range
        (which rejects any non-pure-decimal-digit input), so it falls
        through to nonlocal rather than being silently accepted as local."""
        self._assert_nonlocal("http://0177.0.0.1/")

    def test_decimal_ip_encoding_classified_nonlocal(self):
        """2130706433 is the single-integer decimal encoding of
        127.0.0.1 -- not four dot-separated octets, so it is not
        recognized as local."""
        self._assert_nonlocal("http://2130706433/")

    def test_hex_ip_encoding_classified_nonlocal(self):
        self._assert_nonlocal("http://0x7f.0.0.1/")

    # ---- Bracketed/loopback IPv6 forms ----

    def test_bracketed_ipv6_loopback_classified_local(self):
        self._assert_local("http://[::1]/")

    def test_bracketed_ipv6_loopback_with_port_classified_local(self):
        """Port after the closing bracket must not be mistaken for part
        of the host, and must not cause the bracket-stripping logic to
        misfire."""
        self._assert_local("http://[::1]:8765/")

    def test_bare_ipv6_loopback_classified_local(self):
        self._assert_local("http://::1/")

    def test_0_0_0_0_classified_local(self):
        self._assert_local("http://0.0.0.0:8765/")


class TestRouterSettingsStampPreservesExistingFileOnRefusal(unittest.TestCase):
    """bobbie.bleed.partial-write, PR #146 review 5209002495, finding 3:
    _render_claude_settings was invoked via shell '>' redirection at all
    three stamp sites, which TRUNCATES the target file before the
    function body (including URL validation) ever runs. A die() on a
    malformed CLAGENTIC_ROUTER_URL during a re-enroll or `update
    --restamp` against an EXISTING settings.json therefore emptied a
    previously-working file. The prior test suite only covered
    fresh-enroll, where no file existed yet -- this class covers the
    missed case: an EXISTING file must survive a refused re-stamp
    byte-for-byte.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-partial-write-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_reenroll_with_malformed_url_preserves_existing_settings_json(self):
        # First enroll succeeds with no router configured -- a real,
        # working settings.json now exists.
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path, "rb") as f:
            before = f.read()
        self.assertTrue(len(before) > 0)

        # Re-enroll with --force and a malformed router URL -- must be
        # refused, and must NOT truncate/modify the existing file.
        rc, out, err = _run_cli(
            ["enroll", "--force", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "not-a-url"},
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        with open(settings_path, "rb") as f:
            after = f.read()
        self.assertEqual(before, after,
                          msg="existing settings.json was modified/truncated by a refused re-stamp")
        self.assertGreater(len(after), 0, "existing settings.json was truncated to empty")

    def test_restamp_with_malformed_url_preserves_existing_settings_json(self):
        """Same property via the update --restamp path (the exact path
        BOBBIE's fold-in brief named) -- runs against a throwaway git
        clone of the checkout, never the real dev tree (see
        TestRouterSettingsStampRestamp's own docstring for why).

        NOTE: `git clone` reflects committed HEAD only, not uncommitted
        working-tree edits -- this test (and TestRouterSettingsStampRestamp
        above, which established the pattern) must be run against a
        checkout where the change under test is already committed, or it
        silently exercises stale pre-fix code. cmd_update's own `git pull
        --ff-only` requires a real clone with an upstream, which is why a
        plain `git init` + working-tree copy (no clone) is not a viable
        substitute here the way it would be for a plain `cmd_init` test
        (init never pulls)."""
        fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        subprocess.run(["git", "clone", "-q", TOOL_HOME, fake_tool_home],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", fake_tool_home, "config", "user.email", "test@example.com"],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", fake_tool_home, "config", "user.name", "Test"],
                        check=True, capture_output=True)

        def run_fake_home(argv, env_extra=None):
            env = dict(os.environ)
            env["HOME"] = self.home
            env["CLAGENTIC_LITE_HOME"] = fake_tool_home
            env.pop("CLAGENTIC_HOME", None)
            env.pop("CLAGENTIC_ROUTER_URL", None)
            env.pop("CLAGENTIC_ROUTER_TOKEN", None)
            if env_extra:
                env.update(env_extra)
            proc = subprocess.run(
                [os.path.join(fake_tool_home, "bin", "clagentic-lite")] + argv,
                cwd=self.repo,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return proc.returncode, proc.stdout, proc.stderr

        rc, out, err = run_fake_home(["enroll", self.repo])
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path, "rb") as f:
            before = f.read()
        self.assertTrue(len(before) > 0)

        registry_dir = os.path.join(self.home, ".local", "state", "clagentic")
        os.makedirs(registry_dir, exist_ok=True)
        with open(os.path.join(registry_dir, "registry"), "w") as f:
            f.write(self.repo + "\n")

        # Force a restamp attempt with a malformed router URL configured --
        # must be refused for that repo without touching its existing file.
        # (cmd_update's restamp loop may abort processing further repos on
        # a die() from one repo's stamp -- out of scope for this fix per
        # the fold-in brief, which asked only that the FILE ITSELF survive
        # a refused stamp, not that the multi-repo loop continue past it.)
        run_fake_home(
            ["update", "--restamp"],
            env_extra={"CLAGENTIC_ROUTER_URL": "not-a-url", "CLAGENTIC_SKIP_FETCH": "1"},
        )

        with open(settings_path, "rb") as f:
            after = f.read()
        self.assertEqual(before, after,
                          msg="existing settings.json was modified/truncated by a refused restamp")
        self.assertGreater(len(after), 0, "existing settings.json was truncated to empty")


if __name__ == "__main__":
    unittest.main()
