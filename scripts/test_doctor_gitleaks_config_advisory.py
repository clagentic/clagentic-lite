"""
Regression tests for lr-170808's "Advisory, not only code" scope item:
`clagentic-lite doctor` warns an operator, on a routine run, when an
ENROLLED repo's own .gitleaks.toml declares no [[rules]] and does not set
[extend] useDefault = true -- i.e. before the operator ever hits the
scan-time BLOCK that scripts/gates.sh's own preflight
(_gitleaks_config_declares_rules) now enforces on exactly that condition.

Without this, a repo whose .gitleaks.toml was rules-less before the
gates.sh fix landed presents its first post-upgrade `secrets` scan as an
unexplained new failure rather than a named, anticipated consequence of a
correct fix.

Mirrors test_doctor_gitleaks_version_floor.py's own subprocess-invocation
pattern, and test_cli_config_file_loaded.py's REGISTRY-file-writing pattern
(TestConfigFileRouterUrlHonored.test_update_restamp_stamps_router_env_block_from_config_file)
for exercising cmd_doctor's "6. Registry + enrolled repos" per-repo loop
(bin/clagentic-lite ~line 2368), which this scope item extends with a new
.gitleaks.toml check rather than building a parallel warning path.

`doctor` never runs `git -C "$CLAGENTIC_LITE_HOME" stash`, unlike `update`,
so CLAGENTIC_LITE_HOME can point straight at the live checkout here -- no
throwaway clone needed for this file specifically.

Run with: python3 -m unittest scripts.test_doctor_gitleaks_config_advisory -v
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


class _DoctorGitleaksAdvisoryTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-doctor-gl-advisory-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

        # Register the repo directly (REGISTRY file write), the same way
        # test_cli_config_file_loaded.py's restamp test does -- doctor's
        # "enrolled repos" loop only visits paths listed here, and this
        # test targets that loop specifically, not enroll's own side effects.
        registry_dir = os.path.join(self.home, ".local", "state", "clagentic")
        os.makedirs(registry_dir, exist_ok=True)
        self.registry_path = os.path.join(registry_dir, "registry")
        with open(self.registry_path, "w") as f:
            f.write(self.repo + "\n")

    def _write_gitleaks_toml(self, body):
        with open(os.path.join(self.repo, ".gitleaks.toml"), "w") as f:
            f.write(body)

    def _run_doctor(self):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        proc = subprocess.run(
            [CLI, "doctor"], cwd=self.repo, env=env,
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode, proc.stdout, proc.stderr


class TestRulesLessConfigWarns(_DoctorGitleaksAdvisoryTestBase):
    def test_allowlist_only_config_warns(self):
        """The exact reported shape: an [allowlist]-only .gitleaks.toml,
        the most natural file to write when the intent is 'suppress known
        false positives' -- and the one that silently loads zero rules."""
        self._write_gitleaks_toml(
            "[allowlist]\n"
            "paths = ['''testdata/.*''']\n"
        )
        rc, out, err = self._run_doctor()
        self.assertIn(
            "WARN  %s: .gitleaks.toml defines no [[rules]] and has no "
            "[extend] useDefault = true." % self.repo,
            out, msg=out,
        )
        self.assertIn("secrets gate will now BLOCK on your next scan", out, msg=out)

    def test_empty_config_warns(self):
        self._write_gitleaks_toml("")
        rc, out, err = self._run_doctor()
        self.assertIn(".gitleaks.toml defines no [[rules]]", out, msg=out)


class TestRulesDeclaredConfigDoesNotWarn(_DoctorGitleaksAdvisoryTestBase):
    def test_explicit_rules_table_ok(self):
        self._write_gitleaks_toml(
            "[[rules]]\n"
            'id = "custom-rule"\n'
            'regex = \'\'\'custom-secret-[0-9]+\'\'\'\n'
        )
        rc, out, err = self._run_doctor()
        self.assertNotIn("defines no [[rules]]", out, msg=out)
        self.assertIn(".gitleaks.toml declares rules or extends the default ruleset", out, msg=out)

    def test_extend_use_default_true_ok(self):
        self._write_gitleaks_toml(
            "[extend]\n"
            "useDefault = true\n"
            "\n"
            "[allowlist]\n"
            "paths = ['''testdata/.*''']\n"
        )
        rc, out, err = self._run_doctor()
        self.assertNotIn("defines no [[rules]]", out, msg=out)
        self.assertIn(".gitleaks.toml declares rules or extends the default ruleset", out, msg=out)


class TestNoConfigFileNotWarned(_DoctorGitleaksAdvisoryTestBase):
    def test_no_gitleaks_toml_is_silent(self):
        """No config file at all is unaffected -- gitleaks runs with its
        full built-in ruleset, and this is intentionally not warned on."""
        rc, out, err = self._run_doctor()
        self.assertNotIn("gitleaks.toml", out, msg=out)


if __name__ == "__main__":
    unittest.main()
