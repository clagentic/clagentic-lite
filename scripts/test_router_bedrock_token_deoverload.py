"""
Regression coverage for lr-6d4a1f's de-overload of AWS_BEARER_TOKEN_BEDROCK
(description scope item 3 / AC 5): "Given any declared mode, when settings
are stamped, then AWS_BEARER_TOKEN_BEDROCK never carries the router token
value; a config that attempts the old overload is rejected with a clear
message."

BACKGROUND: prior to this task, CLAGENTIC_ROUTER_TOKEN was reused verbatim
as AWS_BEARER_TOKEN_BEDROCK -- nothing could distinguish a router admin
token from a real AWS Bedrock bearer token by value alone (root cause of
lr-b20c0a). scripts/test_router_bedrock_settings_stamp.py's
test_enroll_stamps_bedrock_pair_alongside_direct_api_pair locks in that
this OLD behavior is UNCHANGED when CLAGENTIC_AUTH_MODE is UNDECLARED (AC 1:
byte-identical for every existing install, none of which have ever set
CLAGENTIC_AUTH_MODE). This file covers the NEW behavior once
CLAGENTIC_AUTH_MODE is declared: CLAGENTIC_ROUTER_BEDROCK_TOKEN becomes the
sole source for AWS_BEARER_TOKEN_BEDROCK, and reusing CLAGENTIC_ROUTER_TOKEN
under a declared mode is refused.

Run with: python3 -m unittest scripts.test_router_bedrock_token_deoverload -v
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
    env.pop("CLAGENTIC_ROUTER_BEDROCK_TOKEN", None)
    env.pop("CLAGENTIC_AUTH_MODE", None)
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


class _StampTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bedrock-deoverload-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)


class TestUndeclaredPreservesOldOverloadBehavior(_StampTestBase):
    """AC 1: CLAGENTIC_AUTH_MODE UNDECLARED -> byte-identical to today's
    behavior, including the pre-existing token-reuse shape. Duplicate-in-
    spirit of test_router_bedrock_settings_stamp.py's own coverage, kept
    here as the explicit control case this file's contradicting tests are
    measured against."""

    def test_undeclared_still_reuses_router_token(self):
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
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["AWS_BEARER_TOKEN_BEDROCK"], "test-token-value")


class TestDeclaredModeUsesDistinctToken(_StampTestBase):
    """A declared mode with CLAGENTIC_ROUTER_BEDROCK_TOKEN explicitly set:
    AWS_BEARER_TOKEN_BEDROCK carries THAT value, never CLAGENTIC_ROUTER_TOKEN."""

    def test_declared_mode_with_distinct_bedrock_token_is_used(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "router-admin-token",
                "CLAGENTIC_ROUTER_BEDROCK_TOKEN": "real-aws-bedrock-bearer-token",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["AWS_BEARER_TOKEN_BEDROCK"], "real-aws-bedrock-bearer-token")
        # Direct-API pair is unaffected -- still the router token.
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "router-admin-token")

    def test_declared_mode_with_bedrock_token_unset_and_router_token_unset_stamps_empty(self):
        """Neither token set at all: stamps an empty AWS_BEARER_TOKEN_BEDROCK,
        same not-omitted convention the pre-existing UNDECLARED path uses --
        no refusal, because there is no old-overload ATTEMPT (nothing to
        reuse) when CLAGENTIC_ROUTER_TOKEN itself is also unset."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-api-key",
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


class TestDeclaredModeRefusesOldOverload(_StampTestBase):
    """The exact old-overload shape (CLAGENTIC_ROUTER_TOKEN set,
    CLAGENTIC_ROUTER_BEDROCK_TOKEN unset) under a DECLARED mode is refused
    with a clear message, not silently accepted."""

    def test_bedrock_sso_with_only_router_token_set_is_refused(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "router-admin-token",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("refusing to reuse CLAGENTIC_ROUTER_TOKEN", err, msg=err)
        self.assertIn("CLAGENTIC_ROUTER_BEDROCK_TOKEN", err, msg=err)

    def test_bedrock_api_key_with_only_router_token_set_is_refused(self):
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-api-key",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "router-admin-token",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("refusing to reuse CLAGENTIC_ROUTER_TOKEN", err, msg=err)

    def test_refusal_does_not_truncate_existing_settings_json(self):
        """Same atomic-write protection every other refusal path in this
        file already carries (BOBBIE finding, PR #146) -- a refused stamp
        must not touch a pre-existing, working settings.json."""
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

        rc, out, err = _run_cli(
            ["enroll", "--force", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "router-admin-token",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        with open(settings_path, "rb") as f:
            after = f.read()
        self.assertEqual(before, after)
        self.assertGreater(len(after), 0)

    def test_declared_mode_without_bedrock_mode_flag_is_not_refused(self):
        """Refusal only applies when the Bedrock pair is actually about to
        be stamped (CLAGENTIC_ROUTER_BEDROCK_MODE=1). A declared mode with
        the Bedrock stamp opt-out left off has nothing to refuse -- neither
        AWS_BEARER_TOKEN_BEDROCK nor ANTHROPIC_BEDROCK_BASE_URL are stamped
        at all in that case (pre-existing, unrelated gate)."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "router-admin-token",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        self.assertNotIn("AWS_BEARER_TOKEN_BEDROCK", raw)

    def test_declared_mode_with_matching_explicit_value_is_allowed(self):
        """An operator who explicitly sets CLAGENTIC_ROUTER_BEDROCK_TOKEN to
        the SAME value as CLAGENTIC_ROUTER_TOKEN is not refused -- the
        refusal targets the OLD OVERLOAD SHAPE (reuse via omission), not a
        deliberate, explicit choice to use the same value for both."""
        rc, out, err = _run_cli(
            ["enroll", self.repo],
            cwd=self.repo,
            home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "same-value",
                "CLAGENTIC_ROUTER_BEDROCK_TOKEN": "same-value",
                "CLAGENTIC_ROUTER_BEDROCK_MODE": "1",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["AWS_BEARER_TOKEN_BEDROCK"], "same-value")


if __name__ == "__main__":
    unittest.main()
