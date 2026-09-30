"""
Tests that every render-affecting key is read from the GLOBAL config FILE only:
never from the current repo's .clagentic/config, and never from the inherited
process environment.

The rendered plugin is one per user. If the render read a repo-local value, the
plugin baked for every project would flip depending on which repo `update` was
last run from. The environment is no safer: the env loaders export whatever
they source and latch, so a process that `update` re-execs into inherits the
repo's values with the global load already marked done. bin/clagentic-lite
therefore resolves the render inputs by sourcing the global config file in a
subshell that starts with every CLAGENTIC_* variable unset.

Same extraction technique as test_agent_model_keys.py: real function
definitions sourced into `sh`, bin/clagentic-lite's dispatch never executed.
The real update/re-exec path is covered in test_render_inputs_update_reexec.py.

Run with: python3 -m unittest scripts.test_render_inputs_global_only -v
"""
import os
import subprocess
import textwrap
import unittest

from scripts.test_unified_plugin_render import PLATFORM_SH, _RenderTestBase

DOCTOR_KEYS = "_doctor_check_repo_render_keys\n"
DOCTOR_ENV = "_doctor_check_env_render_keys\n"
DOCTOR_BOTH = DOCTOR_KEYS + DOCTOR_ENV

NO_EFFECT_TEXT = "has no effect anywhere when set per repo; set it in"
CLI_PATH_TEXT = "still applies to the gate/CLI path; ignored for dispatched-agent render"

AGENTS = ("builder", "reviewer", "auditor", "merge-gate", "troubleshooter")


class _GlobalOnlyBase(_RenderTestBase):
    def _make_repo(self, name, config_body=None):
        repo = os.path.join(self.tmp, name)
        os.makedirs(os.path.join(repo, ".clagentic"))
        subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True)
        if config_body is not None:
            with open(os.path.join(repo, ".clagentic", "config"), "w") as f:
                f.write(config_body)
        return repo

    def _global_config_path(self, old=False):
        parts = (".config", "clagentic", "config") if old else (".config", "clagentic", "lite", "config")
        return os.path.join(self.fake_home_dir, *parts)

    def _write_global_config(self, body, old=False):
        path = self._global_config_path(old)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body)

    def _run_in_repo(self, repo, script_body, exported_env=None):
        """Global load, then the render block (snapshot), then the per-repo
        load, then script_body, run with cwd inside `repo`. exported_env is
        exported into the child verbatim (an inherited variable)."""
        env = self._scrubbed_env()
        env["HOME"] = self.fake_home_dir
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        if exported_env:
            env.update(exported_env)
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

    def _render_and_read(self, repo, exported_env=None):
        result = self._run_in_repo(
            repo, "_render_clagentic_lite_plugin_dir\n_render_stamp\n", exported_env=exported_env
        )
        files = {}
        for agent in AGENTS:
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


class TestInheritedEnvNeverReachesTheRender(_GlobalOnlyBase):
    """The re-exec scenario in miniature: the process environment already holds
    the repo's values and the loader latch says the global load is done."""

    REPO_CONFIG = (
        "CLAGENTIC_BUILDER_AGENT_MODEL=opus\n"
        "CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\n"
        "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1\n"
        "CLAGENTIC_REVIEWER_CMD=codex\n"
    )
    INHERITED = {
        "CLAGENTIC_GLOBAL_ENV_LOADED": "1",
        "CLAGENTIC_BUILDER_AGENT_MODEL": "opus",
        "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
        "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
        "CLAGENTIC_REVIEWER_CMD": "codex",
    }

    def setUp(self):
        super().setUp()
        self._write_global_config("CLAGENTIC_GATE_AGENT_MODEL=sonnet\n")
        self.repo = self._make_repo("repo-inherited", self.REPO_CONFIG)

    def test_latched_process_with_repo_values_exported_renders_global_only(self):
        files, stamp = self._render_and_read(self.repo, exported_env=self.INHERITED)
        control, control_stamp = self._render_and_read(self._make_repo("repo-control"))
        self.assertEqual(files, control)
        self.assertEqual(stamp, control_stamp)
        self.assertNotIn("model:", files["builder"])
        self.assertNotIn("role:reviewer-chain", files["reviewer"])
        self.assertEqual(files["merge-gate"].splitlines()[2], "model: sonnet")

    def test_an_exported_value_without_the_latch_never_applies_either(self):
        exported = {k: v for k, v in self.INHERITED.items() if k != "CLAGENTIC_GLOBAL_ENV_LOADED"}
        files, _ = self._render_and_read(self._make_repo("repo-nolatch"), exported_env=exported)
        self.assertNotIn("model:", files["builder"])
        self.assertNotIn("role:reviewer-chain", files["reviewer"])

    def test_the_global_file_wins_over_an_exported_value_for_the_same_key(self):
        self._write_global_config("CLAGENTIC_BUILDER_AGENT_MODEL=sonnet\n")
        files, _ = self._render_and_read(self.repo, exported_env=self.INHERITED)
        self.assertEqual(files["builder"].splitlines()[2], "model: sonnet")

    def test_an_exported_key_is_not_visible_through_the_render_input_reader(self):
        result = self._run_in_repo(
            self.repo,
            '_render_input CLAGENTIC_BUILDER_AGENT_MODEL\n',
            exported_env=self.INHERITED,
        )
        self.assertEqual(result.stdout, "")

    def test_a_config_file_that_references_an_unset_variable_still_resolves(self):
        # The subshell starts with every CLAGENTIC_* variable unset and must not
        # abort on a reference to one.
        self._write_global_config(
            'CLAGENTIC_BUILDER_AGENT_MODEL="${CLAGENTIC_SOME_UNSET_THING:-sonnet}"\n'
        )
        files, _ = self._render_and_read(self._make_repo("repo-unset-ref"))
        self.assertEqual(files["builder"].splitlines()[2], "model: sonnet")


class TestGlobalConfigLocation(_GlobalOnlyBase):
    def test_deprecated_brand_root_path_is_read_when_the_new_path_is_absent(self):
        self._write_global_config("CLAGENTIC_BUILDER_AGENT_MODEL=sonnet\n", old=True)
        files, _ = self._render_and_read(self._make_repo("repo-old"))
        self.assertEqual(files["builder"].splitlines()[2], "model: sonnet")

    def test_the_new_path_wins_and_the_two_are_never_merged(self):
        self._write_global_config("CLAGENTIC_BUILDER_AGENT_MODEL=sonnet\n", old=True)
        self._write_global_config("CLAGENTIC_GATE_AGENT_MODEL=opus\n")
        files, _ = self._render_and_read(self._make_repo("repo-both"))
        self.assertNotIn("model:", files["builder"])
        self.assertEqual(files["merge-gate"].splitlines()[2], "model: opus")

    def test_no_global_config_at_all_renders_the_checked_in_files(self):
        files, _ = self._render_and_read(self._make_repo("repo-none"))
        for agent in AGENTS:
            self.assertNotIn("model:", files[agent], msg=agent)

class TestDoctorWarnsOnPerRepoRenderKey(_GlobalOnlyBase):
    def test_warns_naming_key_and_file(self):
        repo = self._make_repo("repo-warn", "export CLAGENTIC_GATE_AGENT_MODEL=opus\n")
        result = self._run_in_repo(repo, DOCTOR_KEYS)
        self.assertIn("WARN CLAGENTIC_GATE_AGENT_MODEL is set in", result.stdout)
        self.assertIn(os.path.join(".clagentic", "config"), result.stdout)

    def test_agent_model_keys_say_they_have_no_effect_anywhere_per_repo(self):
        for role in ("BUILDER", "REVIEWER", "AUDITOR", "GATE", "TROUBLESHOOTER"):
            with self.subTest(role=role):
                repo = self._make_repo(f"repo-am-{role}", f"CLAGENTIC_{role}_AGENT_MODEL=opus\n")
                out = self._run_in_repo(repo, DOCTOR_KEYS).stdout
                self.assertIn(NO_EFFECT_TEXT, out)
                self.assertIn(os.path.join(".config", "clagentic", "lite", "config"), out)
                self.assertNotIn(CLI_PATH_TEXT, out)

    def test_inject_switch_says_it_has_no_effect_anywhere_per_repo(self):
        repo = self._make_repo("repo-inject", "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1\n")
        out = self._run_in_repo(repo, DOCTOR_KEYS).stdout
        self.assertIn("WARN CLAGENTIC_ROUTER_INJECT_AGENT_MODEL is set in", out)
        self.assertIn(NO_EFFECT_TEXT, out)
        self.assertNotIn(CLI_PATH_TEXT, out)

    def test_router_url_says_it_still_applies_to_the_cli_path(self):
        # llm-client.sh reads CLAGENTIC_ROUTER_URL on the gate path, so the
        # per-repo value is not inert there and the text must not claim it is.
        repo = self._make_repo("repo-warn-router", "CLAGENTIC_ROUTER_URL=http://127.0.0.1:1\n")
        out = self._run_in_repo(repo, DOCTOR_KEYS).stdout
        self.assertIn("WARN CLAGENTIC_ROUTER_URL is set in", out)
        self.assertIn(CLI_PATH_TEXT, out)
        self.assertNotIn(NO_EFFECT_TEXT, out)

    ROUTER_GLOBAL = (
        "CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\n"
        "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1\n"
    )

    def test_injection_cmd_key_warns_only_while_router_injection_is_on(self):
        for role in ("REVIEWER", "AUDITOR", "GATE"):
            with self.subTest(role=role):
                repo = self._make_repo(f"repo-cmd-{role}", f"CLAGENTIC_{role}_CMD=codex\n")
                off = self._run_in_repo(repo, DOCTOR_KEYS)
                self.assertEqual(off.stdout, "", msg=f"{role} CMD warned with injection off")
                self._write_global_config(self.ROUTER_GLOBAL)
                on = self._run_in_repo(repo, DOCTOR_KEYS)
                self.assertIn(f"WARN CLAGENTIC_{role}_CMD is set in", on.stdout)
                self.assertIn(CLI_PATH_TEXT, on.stdout)
                self.assertNotIn(NO_EFFECT_TEXT, on.stdout)
                os.remove(self._global_config_path())

    def test_builder_and_troubleshooter_cmd_never_warn(self):
        self._write_global_config(self.ROUTER_GLOBAL)
        for role in ("BUILDER", "TROUBLESHOOTER"):
            with self.subTest(role=role):
                repo = self._make_repo(f"repo-cmd-{role}", f"CLAGENTIC_{role}_CMD=codex\n")
                self.assertEqual(self._run_in_repo(repo, DOCTOR_KEYS).stdout, "")

    def test_always_keys_warn_regardless_of_router_state(self):
        for key in (
            "CLAGENTIC_ROUTER_URL", "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL",
            "CLAGENTIC_BUILDER_AGENT_MODEL", "CLAGENTIC_REVIEWER_AGENT_MODEL",
            "CLAGENTIC_AUDITOR_AGENT_MODEL", "CLAGENTIC_GATE_AGENT_MODEL",
            "CLAGENTIC_TROUBLESHOOTER_AGENT_MODEL",
        ):
            with self.subTest(key=key):
                repo = self._make_repo(f"repo-{key}", f"{key}=x\n")
                self.assertIn(f"WARN {key} is set in", self._run_in_repo(repo, DOCTOR_KEYS).stdout)

    def test_the_warning_set_and_the_injection_rule_share_one_table(self):
        # Every _CMD key the table marks 'injection' belongs to a role that
        # _plugin_agent_needs_injection can inject; every 'never' one does not.
        repo = self._make_repo("repo-table")
        result = self._run_in_repo(
            repo,
            "_render_key_table | grep -E '_CMD ' \n"
            "for p in BUILDER REVIEWER AUDITOR GATE TROUBLESHOOTER; do\n"
            "  eval \"_RI_CLAGENTIC_${p}_CMD=codex\"\n"
            "  _RI_CLAGENTIC_ROUTER_URL=http://x _RI_CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1\n"
            "  if _plugin_agent_needs_injection $p; then echo \"inject $p\"; else echo \"skip $p\"; fi\n"
            "done\n",
        )
        table = {}
        verdicts = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts and parts[0].startswith("CLAGENTIC_"):
                table[parts[0]] = parts[1]
            elif parts and parts[0] in ("inject", "skip"):
                verdicts[parts[1]] = parts[0]
        self.assertEqual(len(table), 5, msg=result.stdout)
        for role, verdict in verdicts.items():
            expected = "inject" if table[f"CLAGENTIC_{role}_CMD"] == "injection" else "skip"
            self.assertEqual(verdict, expected, msg=role)
        self.assertEqual(table["CLAGENTIC_BUILDER_CMD"], "never")
        self.assertEqual(table["CLAGENTIC_REVIEWER_CMD"], "injection")

    def test_the_warning_text_class_comes_from_the_table(self):
        repo = self._make_repo("repo-classes")
        result = self._run_in_repo(repo, "_render_key_table\n")
        classes = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            self.assertEqual(len(parts), 3, msg=f"table row needs KEY WHEN PATH: {line!r}")
            classes[parts[0]] = parts[2]
        self.assertEqual(classes["CLAGENTIC_BUILDER_AGENT_MODEL"], "render")
        self.assertEqual(classes["CLAGENTIC_ROUTER_INJECT_AGENT_MODEL"], "render")
        self.assertEqual(classes["CLAGENTIC_ROUTER_URL"], "both")
        self.assertEqual(classes["CLAGENTIC_REVIEWER_CMD"], "both")

    def test_silent_when_unset_or_commented(self):
        repo = self._make_repo("repo-quiet", "# CLAGENTIC_BUILDER_AGENT_MODEL=opus\nCLAGENTIC_BUILDER_TIER=fast\n")
        result = self._run_in_repo(repo, DOCTOR_KEYS)
        self.assertEqual(result.stdout, "")


class TestDoctorInfoOnExportedRenderKey(_GlobalOnlyBase):
    def setUp(self):
        super().setUp()
        self.repo = self._make_repo("repo-env")
        self._write_global_config("CLAGENTIC_GATE_AGENT_MODEL=sonnet\n")

    def test_differing_exported_value_is_reported_as_ignored(self):
        # The loader re-reads the global file, so drive the differing value
        # through the latch, as a re-exec'd process would see it.
        out = self._run_in_repo(
            self.repo, DOCTOR_ENV,
            exported_env={"CLAGENTIC_GLOBAL_ENV_LOADED": "1", "CLAGENTIC_GATE_AGENT_MODEL": "opus"},
        ).stdout
        self.assertIn("INFO CLAGENTIC_GATE_AGENT_MODEL", out)
        self.assertIn("ignored for dispatched-agent render", out)
        self.assertIn(os.path.join(".config", "clagentic", "lite", "config"), out)

    def test_an_exported_value_equal_to_the_global_file_is_silent(self):
        out = self._run_in_repo(
            self.repo, DOCTOR_ENV,
            exported_env={"CLAGENTIC_GLOBAL_ENV_LOADED": "1", "CLAGENTIC_GATE_AGENT_MODEL": "sonnet"},
        ).stdout
        self.assertEqual(out, "")

    def test_an_exported_value_for_a_key_unset_in_the_global_file_is_reported(self):
        out = self._run_in_repo(
            self.repo, DOCTOR_ENV,
            exported_env={"CLAGENTIC_GLOBAL_ENV_LOADED": "1", "CLAGENTIC_BUILDER_AGENT_MODEL": "opus"},
        ).stdout
        self.assertIn("INFO CLAGENTIC_BUILDER_AGENT_MODEL", out)

    def test_a_key_the_render_ignores_is_not_reported(self):
        out = self._run_in_repo(
            self.repo, DOCTOR_ENV,
            exported_env={"CLAGENTIC_GLOBAL_ENV_LOADED": "1", "CLAGENTIC_BUILDER_CMD": "codex"},
        ).stdout
        self.assertEqual(out, "")

    def test_a_key_already_warned_about_per_repo_is_not_reported_twice(self):
        repo = self._make_repo("repo-env-both", "CLAGENTIC_BUILDER_AGENT_MODEL=opus\n")
        out = self._run_in_repo(
            repo, DOCTOR_BOTH,
            exported_env={"CLAGENTIC_GLOBAL_ENV_LOADED": "1", "CLAGENTIC_BUILDER_AGENT_MODEL": "opus"},
        ).stdout
        self.assertEqual(out.count("CLAGENTIC_BUILDER_AGENT_MODEL"), 1, msg=out)
        self.assertIn("WARN CLAGENTIC_BUILDER_AGENT_MODEL is set in", out)

    def test_the_exported_value_itself_is_never_printed(self):
        out = self._run_in_repo(
            self.repo, DOCTOR_ENV,
            exported_env={
                "CLAGENTIC_GLOBAL_ENV_LOADED": "1",
                "CLAGENTIC_BUILDER_AGENT_MODEL": "a\x1b[31mb-marker",
            },
        ).stdout
        self.assertIn("INFO CLAGENTIC_BUILDER_AGENT_MODEL", out)
        self.assertNotIn("marker", out)
        self.assertNotIn("\x1b", out)


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
