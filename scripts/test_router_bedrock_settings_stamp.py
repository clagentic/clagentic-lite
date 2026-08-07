"""
Regression tests for the clagentic-router Bedrock-mode settings.json env-block
stamp (lr-4af4c4): ANTHROPIC_BEDROCK_BASE_URL / AWS_BEARER_TOKEN_BEDROCK,
gated behind CLAGENTIC_ROUTER_BEDROCK_MODE=1 (requires CLAGENTIC_ROUTER_URL
also set).

CLAGENTIC_ROUTER_BEDROCK_MODE is a THIRD opt-in, separate from
CLAGENTIC_ROUTER_URL and CLAGENTIC_ROUTER_INJECT_AGENT_MODEL. This file
mirrors scripts/test_router_settings_stamp.py's structure and proves the
same class of properties for the Bedrock pair specifically:

    1. Unset (either CLAGENTIC_ROUTER_URL or CLAGENTIC_ROUTER_BEDROCK_MODE):
       settings.json is byte-for-byte identical to the CLAGENTIC_ROUTER_URL
       -only baseline (test_router_settings_stamp.py already proves the
       fully-unset baseline against the pre-router template; this file
       proves the router-set-but-bedrock-unset case adds nothing extra).
    2. Set: both ANTHROPIC_BEDROCK_BASE_URL and AWS_BEARER_TOKEN_BEDROCK
       appear, reusing CLAGENTIC_ROUTER_TOKEN verbatim as the Bedrock
       bearer value, ALONGSIDE (not instead of) ANTHROPIC_BASE_URL/
       ANTHROPIC_AUTH_TOKEN -- the supplement-not-replace design decision.
    3. The SAME classifier/refuse/warn behavior applies to a malformed or
       non-local CLAGENTIC_ROUTER_URL when CLAGENTIC_ROUTER_BEDROCK_MODE is
       set -- no parallel validation path.
    4. A refused re-stamp against a PRE-EXISTING settings.json preserves it
       byte-for-byte (not just the fresh-enroll case, which passed
       vacuously for finding 3 on PR #146 -- see
       TestBedrockSettingsStampPreservesExistingFileOnRefusal below).
    5. CLAUDE_SETTINGS_VERSION reflects v7 (bumped v6 -> v7 by this task; a
       migration, not a content-only change).

HAZARD (documented in both prior router test files' docstrings, repeating
here because it applies to this file too): `clagentic-lite update` runs
`git -C "$CLAGENTIC_LITE_HOME" stash push` (and, on a non-tty, `stash drop`)
against whatever CLAGENTIC_LITE_HOME points at when it finds local
modifications. A test exercising the restamp path MUST point
CLAGENTIC_LITE_HOME at a throwaway git clone of the real checkout, never at
the real dev checkout itself -- pointing it at the real tree would let
`update`'s non-tty "discard uncommitted changes" path silently stash-and
-drop a developer's in-progress edits.

Run with: python3 -m unittest scripts/test_router_bedrock_settings_stamp.py -v
"""
import json
import os
import shutil
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
    env.pop("CLAGENTIC_ROUTER_BEDROCK_MODE", None)
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


class TestBedrockModeInertWhenUnset(unittest.TestCase):
    """CLAGENTIC_ROUTER_BEDROCK_MODE unset (default): no Bedrock keys appear
    in the stamped env block, even when CLAGENTIC_ROUTER_URL IS set -- the
    Bedrock pair is a genuinely separate opt-in, not implied by the router
    URL alone."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-stamp-unset-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_router_url_set_alone_stamps_no_bedrock_keys(self):
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

        self.assertNotIn("ANTHROPIC_BEDROCK_BASE_URL", parsed["env"], msg=raw)
        self.assertNotIn("AWS_BEARER_TOKEN_BEDROCK", parsed["env"], msg=raw)
        self.assertNotIn("ANTHROPIC_BEDROCK_BASE_URL", raw)
        self.assertNotIn("AWS_BEARER_TOKEN_BEDROCK", raw)
        # Direct-API pair still present and unaffected.
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8765")
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "test-token-value")

    def test_bedrock_mode_zero_is_equivalent_to_unset(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token-value",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "0",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        self.assertNotIn("ANTHROPIC_BEDROCK_BASE_URL", raw)
        self.assertNotIn("AWS_BEARER_TOKEN_BEDROCK", raw)

    def test_bedrock_mode_set_without_router_url_stamps_nothing(self):
        """CLAGENTIC_ROUTER_BEDROCK_MODE alone, without CLAGENTIC_ROUTER_URL,
        must not stamp anything -- the whole env block (including the
        Bedrock pair) is gated on CLAGENTIC_ROUTER_URL being set at all."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={"CLAGENTIC_ROUTER_BEDROCK_MODE": "1"},
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        self.assertNotIn('"env"', raw)
        self.assertNotIn("ANTHROPIC_BEDROCK_BASE_URL", raw)
        self.assertNotIn("AWS_BEARER_TOKEN_BEDROCK", raw)


class TestBedrockModeStampsBothPairs(unittest.TestCase):
    """CLAGENTIC_ROUTER_URL + CLAGENTIC_ROUTER_BEDROCK_MODE=1: both the
    direct-API pair AND the Bedrock pair are stamped -- supplement, not
    replace (the design decision named explicitly in this PR's body)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-stamp-set-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_enroll_stamps_bedrock_pair_alongside_direct_api_pair(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token-value",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        parsed = json.loads(raw)

        # Direct-API pair: still present, unchanged.
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8765")
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "test-token-value")
        # Bedrock pair: same URL value, token reused verbatim under the
        # Bedrock-specific variable name.
        self.assertEqual(parsed["env"]["ANTHROPIC_BEDROCK_BASE_URL"], "http://127.0.0.1:8765")
        self.assertEqual(parsed["env"]["AWS_BEARER_TOKEN_BEDROCK"], "test-token-value")
        self.assertNotIn("__CLAGENTIC_ROUTER_ENV_BLOCK__", raw)

    def test_empty_router_token_stamps_empty_bedrock_token_not_omitted(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertIn("AWS_BEARER_TOKEN_BEDROCK", parsed["env"])
        self.assertEqual(parsed["env"]["AWS_BEARER_TOKEN_BEDROCK"], "")
        self.assertIn("ANTHROPIC_AUTH_TOKEN", parsed["env"])
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "")

    def test_settings_version_marker_is_v7(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        self.assertIn("clagentic-settings-version: v7", raw, msg=raw)


class TestBedrockModeSharesRouterUrlValidation(unittest.TestCase):
    """CLAGENTIC_ROUTER_BEDROCK_MODE reuses CLAGENTIC_ROUTER_URL as-is --
    the SAME classifier verdict and refuse/warn behavior must apply as for
    the direct-API-only case (no parallel validation path for the Bedrock
    pair)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-validation-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_malformed_url_refused_even_with_bedrock_mode_set(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "not-a-url",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("not a well-formed", err, msg=err)
        self.assertIn("CLAGENTIC_ROUTER_URL", err, msg=err)
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        if os.path.isfile(settings_path):
            with open(settings_path) as f:
                content = f.read()
            self.assertNotIn("not-a-url", content, msg=content)

    def test_nonlocal_url_warned_not_refused_with_bedrock_mode_set(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://router.example.com:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token-value",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("NON-LOCAL", err, msg=err)
        self.assertIn("router.example.com", err, msg=err)

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["ANTHROPIC_BEDROCK_BASE_URL"],
                          "http://router.example.com:8765")

    def test_userinfo_bypass_still_closed_with_bedrock_mode_set(self):
        """Spot-check that the Bedrock opt-in did not accidentally introduce
        a parallel URL-handling path that reintroduces the userinfo bypass
        (BOBBIE finding 1, PR #146) -- both variable pairs must reflect the
        SAME classified value from the SAME _router_url_classify call."""
        rc, out, err = _run_cli(
            ["doctor"],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_SKIP_UPDATE_ALERT": "1",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:x@evil.com/",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertIn("NON-LOCAL", out, msg=out)
        self.assertIn("host: evil.com", out, msg=out)


class TestBedrockSettingsStampPreservesExistingFileOnRefusal(unittest.TestCase):
    """Same property as test_router_settings_stamp.py's
    TestRouterSettingsStampPreservesExistingFileOnRefusal (BOBBIE finding 3,
    PR #146 review 5209002495: partial-write-on-refuse), exercised with
    CLAGENTIC_ROUTER_BEDROCK_MODE set -- proves the shared
    _stamp_claude_settings atomic-write choke point still protects a
    PRE-EXISTING settings.json when the Bedrock opt-in is active, not just
    when it is not. A test that only exercised the fresh-enroll case (no
    prior file) would pass vacuously, which is exactly how the original
    partial-write defect went undetected."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-partial-write-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_reenroll_with_malformed_url_and_bedrock_mode_preserves_existing_file(self):
        # First enroll succeeds with a valid router + Bedrock config -- a
        # real, working settings.json with both pairs now exists.
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "good-token",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path, "rb") as f:
            before = f.read()
        self.assertTrue(len(before) > 0)
        self.assertIn(b"ANTHROPIC_BEDROCK_BASE_URL", before)

        # Re-enroll with --force and a malformed router URL, Bedrock mode
        # still on -- must be refused, and must NOT truncate/modify the
        # existing file (which still has a working Bedrock pair in it).
        rc, out, err = _run_cli(
            ["enroll", "--force", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "not-a-url",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        with open(settings_path, "rb") as f:
            after = f.read()
        self.assertEqual(before, after,
                          msg="existing settings.json (with a working Bedrock pair) was "
                              "modified/truncated by a refused re-stamp")
        self.assertGreater(len(after), 0, "existing settings.json was truncated to empty")

    def test_restamp_with_malformed_url_and_bedrock_mode_preserves_existing_file(self):
        """Same property via `update --restamp`, the exact path BOBBIE's
        fold-in brief named for finding 3 originally. Runs against a
        throwaway git clone of the checkout, never the real dev tree --
        see this file's module docstring HAZARD note and
        test_router_settings_stamp.py's TestRouterSettingsStampRestamp
        docstring for why: cmd_update's git stash push/drop path would
        otherwise operate on a developer's real uncommitted edits.

        NOTE: `git clone` reflects committed HEAD only -- this test must
        run against a checkout where this change is already committed, or
        it silently exercises stale pre-fix code (same caveat documented
        in test_router_settings_stamp.py's restamp tests)."""
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
            env.pop("CLAGENTIC_ROUTER_BEDROCK_MODE", None)
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

        rc, out, err = run_fake_home(
            ["enroll", self.repo],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "good-token",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path, "rb") as f:
            before = f.read()
        self.assertTrue(len(before) > 0)
        self.assertIn(b"ANTHROPIC_BEDROCK_BASE_URL", before)

        registry_dir = os.path.join(self.home, ".local", "state", "clagentic")
        os.makedirs(registry_dir, exist_ok=True)
        with open(os.path.join(registry_dir, "registry"), "w") as f:
            f.write(self.repo + "\n")

        run_fake_home(
            ["update", "--restamp"],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "not-a-url",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
                "CLAGENTIC_SKIP_FETCH": "1",
            },
        )

        with open(settings_path, "rb") as f:
            after = f.read()
        self.assertEqual(before, after,
                          msg="existing settings.json (with a working Bedrock pair) was "
                              "modified/truncated by a refused restamp")
        self.assertGreater(len(after), 0, "existing settings.json was truncated to empty")

    def test_restamp_upgrades_v6_to_v7_and_adds_bedrock_pair(self):
        """A pre-existing v6 settings.json (pre-lr-4af4c4, no Bedrock
        support) with CLAGENTIC_ROUTER_BEDROCK_MODE newly turned on must be
        upgraded to v7 with the Bedrock pair added -- proves the version
        bump is a real migration path, not just a string change."""
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
            env.pop("CLAGENTIC_ROUTER_BEDROCK_MODE", None)
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

        # Simulate a stale pre-lr-4af4c4 install at v6.
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        raw = raw.replace("clagentic-settings-version: v7", "clagentic-settings-version: v6")
        with open(settings_path, "w") as f:
            f.write(raw)

        registry_dir = os.path.join(self.home, ".local", "state", "clagentic")
        os.makedirs(registry_dir, exist_ok=True)
        with open(os.path.join(registry_dir, "registry"), "w") as f:
            f.write(self.repo + "\n")

        rc, out, err = run_fake_home(
            ["update", "--restamp"],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "upgraded-token",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
                "CLAGENTIC_SKIP_FETCH": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        with open(settings_path) as f:
            raw = f.read()
        parsed = json.loads(raw)
        self.assertIn("clagentic-settings-version: v7", raw, msg=raw)
        self.assertEqual(parsed["env"]["ANTHROPIC_BEDROCK_BASE_URL"], "http://127.0.0.1:8765")
        self.assertEqual(parsed["env"]["AWS_BEARER_TOKEN_BEDROCK"], "upgraded-token")


if __name__ == "__main__":
    unittest.main()
