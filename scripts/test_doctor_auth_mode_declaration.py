"""
Regression coverage for lr-6d4a1f's `doctor` host auth-mode declaration
check (description AC 6): "Given a declared mode that contradicts observed
ambient env, when doctor runs, then it reports the contradiction naming
both sources."

Run with: python3 -m unittest scripts.test_doctor_auth_mode_declaration -v
"""
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


def _run_doctor(cwd, home, env_extra=None):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
    env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
    env.pop("CLAGENTIC_HOME", None)
    env.pop("CLAGENTIC_AUTH_MODE", None)
    env.pop("CLAUDE_CODE_USE_BEDROCK", None)
    env.pop("ANTHROPIC_API_KEY", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [CLI, "doctor"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class _DoctorTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-doctor-auth-mode-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)


class TestUndeclaredIsOk(_DoctorTestBase):
    def test_undeclared_reports_ok_no_warn(self):
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home)
        self.assertIn("CLAGENTIC_AUTH_MODE is UNDECLARED", out, msg=out)
        self.assertNotIn("contradiction", out, msg=out)


class TestDeclaredNoContradictionIsOk(_DoctorTestBase):
    def test_anthropic_oauth_with_no_bedrock_ambient_is_ok(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_AUTH_MODE": "anthropic-oauth"},
        )
        self.assertIn("OK   CLAGENTIC_AUTH_MODE=anthropic-oauth", out, msg=out)
        self.assertNotIn("contradiction", out, msg=out)

    def test_bedrock_sso_with_valid_cache_and_no_api_key_is_ok(self):
        sso_cache_dir = os.path.join(self.tmpdir, "sso-cache")
        os.makedirs(sso_cache_dir)
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": sso_cache_dir,
            },
        )
        self.assertIn("OK   CLAGENTIC_AUTH_MODE=bedrock-sso", out, msg=out)
        self.assertNotIn("contradiction", out, msg=out)
        self.assertNotIn("no AWS SSO token cache", out, msg=out)


class TestContradictionsNamedBothSources(_DoctorTestBase):
    def test_direct_api_mode_but_bedrock_env_set_warns_both_sources(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "anthropic-oauth",
                "CLAUDE_CODE_USE_BEDROCK": "1",
            },
        )
        self.assertIn("contradiction", out, msg=out)
        self.assertIn("CLAGENTIC_AUTH_MODE=anthropic-oauth", out, msg=out)
        self.assertIn("CLAUDE_CODE_USE_BEDROCK=1", out, msg=out)

    def test_enterprise_mode_but_bedrock_env_set_warns_both_sources(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "enterprise",
                "CLAUDE_CODE_USE_BEDROCK": "1",
            },
        )
        self.assertIn("contradiction", out, msg=out)
        self.assertIn("CLAGENTIC_AUTH_MODE=enterprise", out, msg=out)

    def test_bedrock_mode_but_direct_api_key_ambient_warns_both_sources(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "ANTHROPIC_API_KEY": "sk-fixture-not-real",
            },
        )
        self.assertIn("contradiction", out, msg=out)
        self.assertIn("CLAGENTIC_AUTH_MODE=bedrock-sso", out, msg=out)
        self.assertIn("ANTHROPIC_API_KEY", out, msg=out)

    def test_bedrock_mode_with_bedrock_flag_and_api_key_both_set_no_contradiction(self):
        """CLAUDE_CODE_USE_BEDROCK=1 alongside ANTHROPIC_API_KEY is not a
        contradiction -- ANTHROPIC_API_KEY is simply inert under Bedrock
        mode, not evidence of a different auth mode."""
        sso_cache_dir = os.path.join(self.tmpdir, "sso-cache")
        os.makedirs(sso_cache_dir)
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": sso_cache_dir,
                "ANTHROPIC_API_KEY": "sk-fixture-not-real",
                "CLAUDE_CODE_USE_BEDROCK": "1",
            },
        )
        self.assertNotIn("contradiction", out, msg=out)


class TestUnrecognizedValueWarns(_DoctorTestBase):
    def test_typo_value_warns_treated_as_undeclared(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_AUTH_MODE": "bedrok-sso"},
        )
        self.assertIn("not a recognized value", out, msg=out)
        self.assertIn("bedrok-sso", out, msg=out)
        self.assertIn("treated as UNDECLARED", out, msg=out)


class TestMissingSsoCacheWarnsAtDoctorTime(_DoctorTestBase):
    def test_bedrock_sso_missing_cache_dir_warns(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": "/nonexistent/cache/dir/xyz",
            },
        )
        self.assertIn("no AWS SSO token cache directory found", out, msg=out)
        self.assertIn("/nonexistent/cache/dir/xyz", out, msg=out)


if __name__ == "__main__":
    unittest.main()
