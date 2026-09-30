"""
Tests that every render-affecting key is read from GLOBAL config plus the
environment only, never from the current repo's .clagentic/config.

The rendered plugin is one per user. If the render read a repo-local value,
the plugin baked for every project would flip depending on which repo
`update` was last run from. bin/clagentic-lite snapshots the render inputs
right after the global config load and before the registry-gated per-repo
load; these tests reproduce that exact ordering in a throwaway `sh`:

    global load -> source render block (snapshot) -> per-repo load -> render

Same extraction technique as test_agent_model_keys.py: real function
definitions sourced into `sh`, bin/clagentic-lite's dispatch never executed.

Run with: python3 -m unittest scripts.test_render_inputs_global_only -v
"""
import os
import subprocess
import textwrap
import unittest

from scripts.test_unified_plugin_render import PLATFORM_SH, _RenderTestBase

DOCTOR_KEYS = "_doctor_check_repo_render_keys\n"


class _GlobalOnlyBase(_RenderTestBase):
    def _make_repo(self, name, config_body=None):
        repo = os.path.join(self.tmp, name)
        os.makedirs(os.path.join(repo, ".clagentic"))
        subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True)
        if config_body is not None:
            with open(os.path.join(repo, ".clagentic", "config"), "w") as f:
                f.write(config_body)
        return repo

    def _write_global_config(self, body):
        cfg_dir = os.path.join(self.fake_home_dir, ".config", "clagentic", "lite")
        os.makedirs(cfg_dir, exist_ok=True)
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write(body)

    def _run_in_repo(self, repo, script_body):
        """Global load, then the render block (snapshot), then the per-repo
        load, then script_body, run with cwd inside `repo`."""
        env = os.environ.copy()
        env["CLAGENTIC_LITE_HOME"] = self.fake_home
        env["HOME"] = self.fake_home_dir
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        for key in list(env):
            if key.startswith("CLAGENTIC_") and key != "CLAGENTIC_LITE_HOME":
                del env[key]
        script = (
            f". '{PLATFORM_SH}'\n"
            "say()  { printf '[clagentic-lite] %s\\n' \"$*\"; }\n"
            "warn() { printf '[clagentic-lite] WARN: %s\\n' \"$*\" 1>&2; }\n"
            "GLOBAL_CONFIG=\"$HOME/.config/clagentic/lite/config\"\n"
            "ds_load_global_env\n"
            f". '{self.helpers_sh}'\n"
            "ds_load_repo_env\n"
            f"{textwrap.dedent(script_body)}\n"
        )
        return subprocess.run(
            ["sh", "-c", script, "global-only-test"],
            capture_output=True, text=True, env=env, cwd=repo,
        )

    def _render_and_read(self, repo):
        result = self._run_in_repo(repo, "_render_clagentic_lite_plugin_dir\n_render_stamp\n")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        files = {}
        for agent in ("builder", "reviewer", "auditor", "merge-gate", "troubleshooter"):
            with open(self._rendered_agent_path(agent)) as f:
                files[agent] = f.read()
        return files, result.stdout.strip()


class TestPerRepoRenderKeysAreIgnored(_GlobalOnlyBase):
    def test_render_and_stamp_identical_from_repo_a_and_repo_b(self):
        repo_a = self._make_repo("repo-a", "CLAGENTIC_BUILDER_AGENT_MODEL=opus\n")
        repo_b = self._make_repo("repo-b")
        files_a, stamp_a = self._render_and_read(repo_a)
        files_b, stamp_b = self._render_and_read(repo_b)
        self.assertEqual(files_a, files_b)
        self.assertEqual(stamp_a, stamp_b)
        self.assertNotIn("model:", files_a["builder"])

    def test_per_repo_router_keys_do_not_change_the_render(self):
        repo = self._make_repo(
            "repo-router",
            "CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\n"
            "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1\n"
            "CLAGENTIC_REVIEWER_CMD=codex\n",
        )
        baseline = self._make_repo("repo-plain")
        files_r, stamp_r = self._render_and_read(repo)
        files_p, stamp_p = self._render_and_read(baseline)
        self.assertEqual(files_r, files_p)
        self.assertEqual(stamp_r, stamp_p)
        self.assertNotIn("role:reviewer-chain", files_r["reviewer"])

    def test_global_config_value_still_applies(self):
        # Positive control: the same key in the GLOBAL config is honored,
        # from any repo, and a per-repo value does not override it.
        self._write_global_config("CLAGENTIC_BUILDER_AGENT_MODEL=sonnet\n")
        repo = self._make_repo("repo-override", "CLAGENTIC_BUILDER_AGENT_MODEL=opus\n")
        files, _ = self._render_and_read(repo)
        self.assertEqual(files["builder"].splitlines()[2], "model: sonnet")

    def test_global_router_keys_apply_from_any_repo(self):
        self._write_global_config(
            "CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\n"
            "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1\n"
            "CLAGENTIC_REVIEWER_CMD=codex\n"
        )
        files, _ = self._render_and_read(self._make_repo("repo-x"))
        self.assertEqual(files["reviewer"].splitlines()[2], "model: role:reviewer-chain")


class TestDoctorWarnsOnPerRepoRenderKey(_GlobalOnlyBase):
    def test_warns_naming_key_and_file(self):
        repo = self._make_repo("repo-warn", "export CLAGENTIC_GATE_AGENT_MODEL=opus\n")
        result = self._run_in_repo(repo, DOCTOR_KEYS)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("WARN CLAGENTIC_GATE_AGENT_MODEL is set in", result.stdout)
        self.assertIn(os.path.join(".clagentic", "config"), result.stdout)
        self.assertIn("no effect on dispatched agents", result.stdout)

    def test_warns_for_per_repo_router_key(self):
        repo = self._make_repo("repo-warn-router", "CLAGENTIC_ROUTER_URL=http://127.0.0.1:1\n")
        result = self._run_in_repo(repo, DOCTOR_KEYS)
        self.assertIn("WARN CLAGENTIC_ROUTER_URL is set in", result.stdout)

    def test_silent_when_unset_or_commented(self):
        repo = self._make_repo("repo-quiet", "# CLAGENTIC_BUILDER_AGENT_MODEL=opus\nCLAGENTIC_BUILDER_TIER=fast\n")
        result = self._run_in_repo(repo, DOCTOR_KEYS)
        self.assertEqual(result.stdout, "")


class TestAgentModelDisplayMatchesValidator(_GlobalOnlyBase):
    def test_bracketed_value_displays_unmangled(self):
        repo = self._make_repo("repo-display")
        result = self._run_in_repo(
            repo,
            "_agent_model_value_is_valid 'sonnet[1m]' && echo valid\n"
            "_agent_model_display 'sonnet[1m]'\n",
        )
        self.assertEqual(result.stdout.split(), ["valid", "sonnet[1m]"], msg=result.stderr)

    def test_every_valid_character_survives_display(self):
        repo = self._make_repo("repo-display-all")
        value = "aZ09._:/@[]-x"
        result = self._run_in_repo(
            repo,
            f"_agent_model_value_is_valid '{value}' && echo valid\n"
            f"_agent_model_display '{value}'\n",
        )
        self.assertEqual(result.stdout.split(), ["valid", value], msg=result.stderr)


if __name__ == "__main__":
    unittest.main()
