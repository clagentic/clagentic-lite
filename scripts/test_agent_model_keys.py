"""
Tests for the per-role agent-path model keys (CLAGENTIC_<ROLE>_AGENT_MODEL).

Two model paths exist: the gate/CLI path (llm-client.sh, configured by
CLAGENTIC_<ROLE>_CMD/_TIER/_CHAIN) and the Agent path (Claude Code dispatching
clagentic-lite:<role>), where the model is the session model unless the
rendered agent file has a `model:` frontmatter line. These tests cover the
render/stamp/doctor mechanism that lets every role set that line.

Same technique as test_unified_plugin_render.py: the real function
definitions are extracted from bin/clagentic-lite and sourced into a
throwaway `sh`; bin/clagentic-lite's own subcommands are never executed.

Run with: python3 -m unittest scripts.test_agent_model_keys -v
"""
import os
import re
import unittest

from scripts.test_unified_plugin_render import (
    AGENTS_SRC,
    CLI,
    _RenderTestBase,
)

# (env prefix, agent file)
ROLES = (
    ("BUILDER", "builder"),
    ("REVIEWER", "reviewer"),
    ("AUDITOR", "auditor"),
    ("GATE", "merge-gate"),
    ("TROUBLESHOOTER", "troubleshooter"),
)

ROUTER_ENV = {
    "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
    "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
    "CLAGENTIC_REVIEWER_CMD": "codex",
}

DOCTOR = (
    "test_ok() { printf 'OK:%s\\n' \"$*\"; }\n"
    "_doctor_check_agent_models test_ok\n"
)


def _source_lines(agent):
    with open(os.path.join(AGENTS_SRC, f"{agent}.md")) as f:
        return f.read().splitlines(keepends=True)


def _frontmatter(lines):
    """Lines strictly between the opening and closing '---'."""
    assert lines[0].strip() == "---"
    end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    return lines[1:end]


class _AgentModelBase(_RenderTestBase):
    def _run(self, script_body, extra_env=None):
        # Ambient operator config must never leak into these tests.
        saved = {}
        for role, _ in ROLES:
            key = f"CLAGENTIC_{role}_AGENT_MODEL"
            saved[key] = os.environ.pop(key, None)
        try:
            return super()._run(script_body, extra_env=extra_env)
        finally:
            for key, val in saved.items():
                if val is not None:
                    os.environ[key] = val

    def _render(self, extra_env=None):
        result = self._run("_render_clagentic_lite_plugin_dir", extra_env=extra_env)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return result

    def _rendered_lines(self, agent):
        with open(self._rendered_agent_path(agent)) as f:
            return f.read().splitlines(keepends=True)

    def _stamp(self, extra_env=None):
        result = self._run("_render_stamp", extra_env=extra_env)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return result.stdout

    def _doctor(self, extra_env=None):
        result = self._run(DOCTOR, extra_env=extra_env)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return result.stdout


class TestRenderPinnedModel(_AgentModelBase):
    def test_unset_is_byte_identical_to_checked_in_files(self):
        self._render()
        for _, agent in ROLES:
            self.assertEqual(self._rendered_lines(agent), _source_lines(agent), msg=agent)

    def test_each_role_key_sets_line_three_and_leaves_others_unchanged(self):
        for prefix, agent in ROLES:
            with self.subTest(role=prefix):
                self._render(extra_env={f"CLAGENTIC_{prefix}_AGENT_MODEL": "opus"})
                rendered = self._rendered_lines(agent)
                self.assertEqual(rendered[2], "model: opus\n")
                # Removing the one inserted line restores the source exactly.
                self.assertEqual(rendered[:2] + rendered[3:], _source_lines(agent))
                self.assertEqual(
                    sum(1 for l in _frontmatter(rendered) if l.startswith("model:")), 1
                )
                for other_prefix, other in ROLES:
                    if other != agent:
                        self.assertEqual(
                            self._rendered_lines(other), _source_lines(other), msg=other
                        )

    def test_full_ids_and_inherit_are_accepted(self):
        for value in (
            "inherit",
            "example-model-id-1",
            "example.provider.model-v1:0",
            "sonnet[1m]",
            "arn:example:bedrock:region:000000000000:profile/example",
        ):
            with self.subTest(value=value):
                self._render(extra_env={"CLAGENTIC_BUILDER_AGENT_MODEL": value})
                self.assertEqual(self._rendered_lines("builder")[2], f"model: {value}\n")

    def test_builder_is_never_router_referenced(self):
        env = dict(ROUTER_ENV, CLAGENTIC_BUILDER_CMD="codex")
        self._render(extra_env=env)
        self.assertEqual(self._rendered_lines("builder"), _source_lines("builder"))


class TestRouterPrecedence(_AgentModelBase):
    def test_router_wins_over_agent_model_for_reviewer(self):
        env = dict(ROUTER_ENV, CLAGENTIC_REVIEWER_AGENT_MODEL="opus")
        self._render(extra_env=env)
        rendered = self._rendered_lines("reviewer")
        self.assertEqual(rendered[2], "model: role:reviewer-chain\n")
        self.assertNotIn("model: opus\n", rendered)

    def test_doctor_reports_shadowed_key(self):
        env = dict(ROUTER_ENV, CLAGENTIC_REVIEWER_AGENT_MODEL="opus")
        out = self._doctor(extra_env=env)
        self.assertIn("reviewer agent model: router: role:reviewer-chain", out)
        self.assertIn("CLAGENTIC_REVIEWER_AGENT_MODEL=opus is SHADOWED", out)

    def test_router_off_for_role_lets_agent_model_apply(self):
        # Router is on, but auditor's CMD is claude: injection does not apply
        # to it, so the pinned value is used.
        env = dict(ROUTER_ENV, CLAGENTIC_AUDITOR_CMD="claude", CLAGENTIC_AUDITOR_AGENT_MODEL="opus")
        self._render(extra_env=env)
        self.assertEqual(self._rendered_lines("auditor")[2], "model: opus\n")


class TestInvalidValue(_AgentModelBase):
    INVALID = (
        "opus\nname: evil",
        "opus: x",
        "opus:",
        'opus"',
        "'opus'",
        "opus # c",
        "op us",
        "---",
        "-opus",
        "{a: b}",
        "opus\r",
    )

    def test_invalid_values_render_no_model_line_and_warn(self):
        for value in self.INVALID:
            with self.subTest(value=value):
                result = self._render(extra_env={"CLAGENTIC_BUILDER_AGENT_MODEL": value})
                self.assertIn("CLAGENTIC_BUILDER_AGENT_MODEL has an invalid value", result.stderr)
                rendered = self._rendered_lines("builder")
                # Byte-identical to the source: frontmatter cannot have been altered.
                self.assertEqual(rendered, _source_lines("builder"))
                self.assertFalse(any(l.startswith("model:") for l in _frontmatter(rendered)))

    def test_warn_does_not_echo_raw_control_characters(self):
        result = self._render(
            extra_env={"CLAGENTIC_BUILDER_AGENT_MODEL": "a\x1b[31mb\nname: evil"}
        )
        self.assertNotIn("\x1b", result.stderr)

    def test_doctor_reports_invalid_value(self):
        out = self._doctor(extra_env={"CLAGENTIC_BUILDER_AGENT_MODEL": "opus: x"})
        self.assertIn("invalid value", out)
        self.assertIn("builder agent model: inherit", out)

    def test_invalid_value_is_not_written_into_the_stamp(self):
        stamp = self._stamp(extra_env={"CLAGENTIC_BUILDER_AGENT_MODEL": 'x"y'})
        self.assertIn("am_builder=invalid", stamp)
        self.assertNotIn('x"y', stamp)


class TestStamp(_AgentModelBase):
    def test_changing_only_the_value_changes_the_stamp(self):
        base = self._stamp()
        a = self._stamp(extra_env={"CLAGENTIC_TROUBLESHOOTER_AGENT_MODEL": "sonnet"})
        b = self._stamp(extra_env={"CLAGENTIC_TROUBLESHOOTER_AGENT_MODEL": "opus"})
        self.assertEqual(len({base, a, b}), 3, msg=(base, a, b))

    def test_doctor_reports_stale_and_update_would_rerender(self):
        self._render()
        result = self._run(
            "test_ok() { printf 'OK:%s\\n' \"$*\"; }\n"
            "_doctor_check_render_stamp_staleness test_ok\n",
            extra_env={"CLAGENTIC_GATE_AGENT_MODEL": "opus"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("STALE", result.stdout, msg=result.stdout)
        # The re-render itself picks the new value up.
        self._render(extra_env={"CLAGENTIC_GATE_AGENT_MODEL": "opus"})
        fresh = self._run(
            "test_ok() { printf 'OK:%s\\n' \"$*\"; }\n"
            "_doctor_check_render_stamp_staleness test_ok\n",
            extra_env={"CLAGENTIC_GATE_AGENT_MODEL": "opus"},
        )
        self.assertIn("OK:", fresh.stdout, msg=fresh.stdout)

    def test_render_version_is_bumped_past_v1(self):
        # The extracted block does not define the constant, so read it from
        # the CLI source directly.
        with open(CLI) as f:
            match = re.search(r'^PLUGIN_RENDER_VERSION="([^"]*)"', f.read(), re.M)
        self.assertIsNotNone(match)
        self.assertNotEqual(match.group(1), "v1")


class TestDoctorPerRole(_AgentModelBase):
    def test_inherit_when_unset_for_all_roles(self):
        out = self._doctor()
        for _, agent in ROLES:
            self.assertIn(f"OK:{agent} agent model: inherit", out)

    def test_pinned(self):
        out = self._doctor(extra_env={"CLAGENTIC_BUILDER_AGENT_MODEL": "opus"})
        self.assertIn("OK:builder agent model: pinned: opus", out)
        self.assertIn("OK:reviewer agent model: inherit", out)

    def test_router(self):
        out = self._doctor(extra_env=ROUTER_ENV)
        self.assertIn("OK:reviewer agent model: router: role:reviewer-chain", out)
        self.assertNotIn("SHADOWED", out)


if __name__ == "__main__":
    unittest.main()
