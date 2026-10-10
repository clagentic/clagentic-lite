"""
Render inputs through the REAL `clagentic-lite update` and `doctor` paths.

test_render_inputs_global_only.py proves the resolver on extracted functions.
This file proves it where the defect actually lived: after `git pull`, `update`
re-execs the freshly pulled binary. The new process inherits the environment
the first one built, including the repo-local values the env loaders exported
and the latch that says the global load is done, so it skips the global load
and would snapshot the repo's values into the ONE plugin every project shares.

HAZARD: every `update` here runs against a throwaway clone (never this
checkout), as scripts/test_update_self_heals_from_broken_version.py does.

Run with: python3 -m unittest scripts.test_render_inputs_update_reexec -v
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

from scripts.isolated_env import shared_cli, shared_tool_home
from scripts.test_support import clone_this_tool_home_with_overlay

AGENTS = ("builder", "reviewer", "auditor", "merge-gate", "troubleshooter")

GLOBAL_CONFIG = "CLAGENTIC_GATE_AGENT_MODEL=sonnet\n"
REPO_CONFIG = (
    "CLAGENTIC_BUILDER_AGENT_MODEL=opus\n"
    "CLAGENTIC_REVIEWER_CMD=codex\n"
    "CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\n"
    "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1\n"
)
# The stamp fingerprint the global-only inputs above must produce: only the
# gate carries a pinned model.
EXPECTED_FINGERPRINT = (
    "am_builder=-,am_reviewer=-,am_auditor=-,am_merge-gate=sonnet,am_troubleshooter=-"
)


def _git(*args):
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _write_fake_claude(bin_dir):
    path = os.path.join(bin_dir, "claude")
    with open(path, "w") as f:
        f.write(textwrap.dedent("""\
            #!/bin/sh
            case "$*" in
              *"plugin list"*) printf 'clagentic-lite@clagentic-lite\\n' ;;
              *"--version"*) printf 'claude 1.2.3 (test stub)\\n' ;;
            esac
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


class _RealPathBase(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="clagentic-test-render-reexec-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.bin_dir = os.path.join(self.tmp, "stub-bin")
        os.makedirs(self.bin_dir)
        _write_fake_claude(self.bin_dir)
        self.cfg_dir = os.path.join(self.home, ".config", "clagentic", "lite")
        os.makedirs(self.cfg_dir)
        with open(os.path.join(self.cfg_dir, "config"), "w") as f:
            f.write(GLOBAL_CONFIG)

    def _make_enrolled_repo(self, repo_config):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, ".clagentic"))
        _git("init", "-q", "-b", "main", repo)
        _git("-C", repo, "config", "user.email", "test@example.com")
        _git("-C", repo, "config", "user.name", "Test")
        with open(os.path.join(repo, "f.txt"), "w") as f:
            f.write("x\n")
        _git("-C", repo, "add", "f.txt")
        _git("-C", repo, "commit", "-q", "-m", "init")
        with open(os.path.join(repo, ".clagentic", "config"), "w") as f:
            f.write(repo_config)
        # Registry membership is what makes the CLI trust (and source) the
        # repo's own config; without it the repo values never enter the env.
        reg_dir = os.path.join(self.home, ".local", "state", "clagentic")
        os.makedirs(reg_dir)
        with open(os.path.join(reg_dir, "registry"), "w") as f:
            f.write(repo + "\n")
        return repo

    def _env(self, install, extra=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAGENTIC_")}
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = install
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        if extra:
            env.update(extra)
        return env

    def _rendered(self, install):
        base = os.path.join(install, ".clagentic", "rendered-plugin", "plugins", "clagentic-lite")
        files = {}
        for agent in AGENTS:
            with open(os.path.join(base, "agents", f"{agent}.md")) as f:
                files[agent] = f.read()
        with open(os.path.join(base, ".claude-plugin", "plugin.json")) as f:
            plugin_json = f.read()
        return files, plugin_json


class TestUpdateReexecRendersFromTheGlobalFileOnly(_RealPathBase):
    def setUp(self):
        super().setUp()
        upstream = os.path.join(self.tmp, "upstream")
        clone_this_tool_home_with_overlay(upstream)
        _git("-C", upstream, "add", "-A")
        _git("-C", upstream, "commit", "-q", "--allow-empty", "-m", "overlay current on-disk state")
        self.install = os.path.join(self.tmp, "install")
        _git("clone", "-q", upstream, self.install)
        _git("-C", self.install, "config", "user.email", "test@example.com")
        _git("-C", self.install, "config", "user.name", "Test")
        # One more upstream commit, so `git pull --ff-only` moves HEAD and
        # update takes its re-exec branch.
        _git("-C", upstream, "commit", "-q", "--allow-empty", "-m", "a new upstream commit")
        self.pre_sha = _git("-C", self.install, "rev-parse", "HEAD")
        self.repo = self._make_enrolled_repo(REPO_CONFIG)

    def _update(self, extra_env=None):
        return subprocess.run(
            [os.path.join(self.install, "bin", "clagentic-lite"), "update"],
            cwd=self.repo, env=self._env(self.install, extra_env),
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
        )

    def test_update_reexec_renders_the_global_only_plugin_and_stamp(self):
        result = self._update()
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=combined)
        self.assertIn("re-executing updated binary", combined, msg=combined)
        self.assertNotEqual(_git("-C", self.install, "rev-parse", "HEAD"), self.pre_sha)

        files, plugin_json = self._rendered(self.install)
        # None of the repo's render-affecting values reached the shared plugin.
        self.assertNotIn("model:", files["builder"])
        self.assertNotIn("role:", files["reviewer"])
        self.assertEqual(files["merge-gate"].splitlines()[2], "model: sonnet")
        for agent in ("auditor", "troubleshooter"):
            self.assertNotIn("model:", files[agent], msg=agent)
        self.assertIn(EXPECTED_FINGERPRINT, plugin_json)

    def test_doctor_in_the_same_setup_names_each_ignored_repo_render_key(self):
        # The same fixture, through the real `doctor`: the repo file is what
        # carries the render keys the update above must not have applied.
        result = subprocess.run(
            [os.path.join(self.install, "bin", "clagentic-lite"), "doctor"],
            cwd=self.repo, env=self._env(self.install),
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
        )
        self.assertIn(result.returncode, (0, 1), msg=result.stderr)
        self.assertIn("WARN CLAGENTIC_BUILDER_AGENT_MODEL is set in", result.stdout, msg=result.stdout)
        self.assertIn("has no effect anywhere when set per repo", result.stdout, msg=result.stdout)


class TestDoctorNamesAnIgnoredExportedRenderKey(unittest.TestCase):
    """The env-inheritance half of the defect, through the real `doctor`: with
    the loader latch already set (as after update's re-exec), an exported render
    key whose value differs from the global file is reported as ignored."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="clagentic-test-doctor-env-info-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        cfg_dir = os.path.join(self.home, ".config", "clagentic", "lite")
        os.makedirs(cfg_dir)
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write(GLOBAL_CONFIG)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        _git("init", "-q", "-b", "main", self.repo)

    def _doctor(self, extra_env):
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAGENTIC_")}
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = shared_tool_home()
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.update(extra_env)
        return subprocess.run(
            [shared_cli(), "doctor"], cwd=self.repo, env=env,
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
        )

    def test_a_differing_exported_value_is_reported_and_the_plugin_does_not_use_it(self):
        result = self._doctor({
            "CLAGENTIC_GLOBAL_ENV_LOADED": "1",
            "CLAGENTIC_BUILDER_AGENT_MODEL": "opus",
        })
        self.assertIn(result.returncode, (0, 1), msg=result.stderr)
        self.assertIn("INFO CLAGENTIC_BUILDER_AGENT_MODEL is exported", result.stdout, msg=result.stdout)
        self.assertIn("ignored for dispatched-agent render", result.stdout)
        # The effective per-role report is the global file's: builder inherits.
        self.assertIn("builder agent model: inherit", result.stdout, msg=result.stdout)
        self.assertNotIn("opus", result.stdout)

    def test_an_exported_value_equal_to_the_global_file_is_not_reported(self):
        result = self._doctor({
            "CLAGENTIC_GLOBAL_ENV_LOADED": "1",
            "CLAGENTIC_GATE_AGENT_MODEL": "sonnet",
        })
        self.assertIn(result.returncode, (0, 1), msg=result.stderr)
        self.assertNotIn("is exported in this environment", result.stdout, msg=result.stdout)


if __name__ == "__main__":
    unittest.main()
