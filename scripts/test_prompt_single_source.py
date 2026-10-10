"""
Drift test for the single-sourced Reviewer and Auditor instruction text.

The shared material (role rules, output schema, Pre-Report Gate, false-positive
list, reachability and change-class rules) used to be written out twice per
role: once in the Claude Code agent file and once in the gate-path prompt
(ds_review_prompt / ds_adversarial_prompt, scripts/llm-client.sh). It now lives
in plugins/clagentic-lite/prompts/<role>.shared.txt, and both surfaces are
generated from it. These tests fail if either surface stops carrying a block,
carries a block out of order, or grows a second hand-written copy.

Every path is under a temp dir and nothing here writes the live checkout.
"""
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, PLATFORM_SH, TOOL_HOME, source_env  # noqa: E402
from test_unified_plugin_render import _RenderTestBase  # noqa: E402

PROMPTS_DIR = os.path.join(TOOL_HOME, "plugins", "clagentic-lite", "prompts")
AGENTS_DIR = os.path.join(TOOL_HOME, "plugins", "clagentic-lite", "agents")
ROLES = {"reviewer": "ds_review_prompt", "auditor": "ds_adversarial_prompt"}
MARKER_RE = re.compile(r"^\{\{shared:([a-z]+):([a-z-]+)\}\}$", re.M)


def parse_blocks(role):
    """[(name, text)] in file order. A block is the lines after its '@@@ name'
    marker up to the next marker; text carries no trailing newline."""
    blocks = []
    with open(os.path.join(PROMPTS_DIR, role + ".shared.txt")) as handle:
        for line in handle.read().split("\n")[:-1]:
            if line.startswith("@@@ "):
                blocks.append((line[4:], []))
            else:
                blocks[-1][1].append(line)
    return [(name, "\n".join(lines)) for name, lines in blocks]


def gate_prompt(func):
    """Output of the real gate prompt function, with no deferrals, invariants
    or change-class hint in play (a bare temp project root and HOME)."""
    with tempfile.TemporaryDirectory(prefix="clagentic-test-prompt-") as tmp:
        env = os.environ.copy()
        for key in [k for k in env if k.startswith("CLAGENTIC_")]:
            del env[key]
        env.update(source_env(llm_client=True))
        env["HOME"] = tmp
        env["CLAGENTIC_PROJECT_ROOT"] = tmp
        script = f". '{LLM_CLIENT_SH}'\n{func}\n"
        result = subprocess.run(["sh", "-c", script, LLM_CLIENT_SH], capture_output=True,
                                text=True, cwd=tmp, env=env)
    assert result.returncode == 0, result.stderr
    return result.stdout


class TestSharedSourceShape(unittest.TestCase):
    def test_every_role_has_a_source_with_unique_non_empty_blocks(self):
        for role in ROLES:
            with self.subTest(role=role):
                blocks = parse_blocks(role)
                names = [n for n, _ in blocks]
                self.assertEqual(len(names), len(set(names)), names)
                self.assertTrue(all(t.strip() for _, t in blocks))

    def test_no_block_carries_a_marker_or_task_id(self):
        for role in ROLES:
            for name, text in parse_blocks(role):
                with self.subTest(role=role, block=name):
                    self.assertNotIn("{{shared:", text)
                    self.assertIsNone(re.search(r"\blr-[0-9a-f]{4,}\b", text))


class TestGatePathCarriesTheSharedSource(unittest.TestCase):
    def test_gate_prompt_carries_every_block_verbatim_and_in_order(self):
        for role, func in ROLES.items():
            prompt = gate_prompt(func)
            position = -1
            for name, text in parse_blocks(role):
                with self.subTest(role=role, block=name):
                    found = prompt.find(text)
                    self.assertNotEqual(found, -1, "block missing from the gate prompt")
                    self.assertGreater(found, position, "block out of source order")
                    position = found

    def test_gate_functions_hold_no_second_copy_of_a_block(self):
        with open(LLM_CLIENT_SH) as handle:
            source = handle.read()
        for role in ROLES:
            for name, text in parse_blocks(role):
                with self.subTest(role=role, block=name):
                    anchor = "\n".join(text.split("\n")[:2])
                    self.assertNotIn(anchor, source)


class TestAgentPathCarriesTheSharedSource(_RenderTestBase):
    def render_agent(self, role):
        result = self._run("_render_clagentic_lite_plugin_dir")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self._rendered_agent_path(role)) as handle:
            return handle.read()

    def test_rendered_agent_carries_every_block_verbatim_and_in_order(self):
        for role in ROLES:
            rendered = self.render_agent(role)
            self.assertNotIn("{{shared:", rendered)
            position = -1
            for name, text in parse_blocks(role):
                with self.subTest(role=role, block=name):
                    found = rendered.find(text)
                    self.assertNotEqual(found, -1, "block missing from the rendered agent file")
                    self.assertGreater(found, position, "block out of source order")
                    position = found

    def test_rendered_agent_and_gate_prompt_agree_on_the_shared_text(self):
        for role, func in ROLES.items():
            rendered, prompt = self.render_agent(role), gate_prompt(func)
            for name, text in parse_blocks(role):
                with self.subTest(role=role, block=name):
                    self.assertIn(text, rendered)
                    self.assertIn(text, prompt)

    def test_model_line_still_lands_on_line_three_of_an_expanded_agent(self):
        result = self._run("_render_clagentic_lite_plugin_dir", extra_env={
            "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
            "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
            "CLAGENTIC_REVIEWER_CMD": "codex",
        })
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self._rendered_agent_path("reviewer")) as handle:
            lines = handle.read().splitlines()
        self.assertEqual((lines[1], lines[2]), ("name: reviewer", "model: role:reviewer-chain"))

    def test_an_unresolvable_marker_fails_the_render_instead_of_leaving_a_hole(self):
        bad = os.path.join(self.fake_home, "plugins", "clagentic-lite", "agents", "reviewer.md")
        with open(bad, "a") as handle:
            handle.write("\n{{shared:reviewer:no-such-block}}\n")
        result = self._run("_render_clagentic_lite_plugin_dir")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no-such-block", result.stderr)
        self.assertFalse(os.path.exists(self._rendered_agent_path("reviewer")))


class TestAgentTemplates(unittest.TestCase):
    def test_each_template_has_one_marker_per_block_and_no_inline_copy(self):
        for role in ROLES:
            with open(os.path.join(AGENTS_DIR, role + ".md")) as handle:
                template = handle.read()
            referenced = MARKER_RE.findall(template)
            blocks = parse_blocks(role)
            with self.subTest(role=role):
                self.assertEqual(sorted(referenced),
                                 sorted((role, name) for name, _ in blocks))
            for name, text in blocks:
                with self.subTest(role=role, block=name):
                    anchor = "\n".join(text.split("\n")[:2])
                    self.assertNotIn(anchor, template)


class TestHelpersFailLoudly(unittest.TestCase):
    def run_sh(self, home, body):
        with tempfile.TemporaryDirectory(prefix="clagentic-test-prompt-") as tmp:
            env = os.environ.copy()
            for key in [k for k in env if k.startswith("CLAGENTIC_")]:
                del env[key]
            for key in ("TOOL_HOME", "_DS_REAL_HOME"):
                env.pop(key, None)
            env.update({"HOME": tmp, "CLAGENTIC_LITE_HOME": home})
            script = textwrap.dedent(f". '{PLATFORM_SH}'\n{body}\n")
            return subprocess.run(["sh", "-c", script, "x"], capture_output=True, text=True,
                                  cwd=tmp, env=env)

    def test_missing_source_and_missing_block_are_errors(self):
        with tempfile.TemporaryDirectory(prefix="clagentic-test-prompt-") as home:
            missing_source = self.run_sh(home, "ds_prompt_block reviewer schema")
            self.assertEqual(missing_source.returncode, 1)
            self.assertIn("not found", missing_source.stderr)
            prompts = os.path.join(home, "plugins", "clagentic-lite", "prompts")
            os.makedirs(prompts)
            with open(os.path.join(prompts, "reviewer.shared.txt"), "w") as handle:
                handle.write("@@@ schema\nonly block\n")
            ok = self.run_sh(home, "ds_prompt_block reviewer schema")
            self.assertEqual((ok.returncode, ok.stdout), (0, "only block\n"))
            missing_block = self.run_sh(home, "ds_prompt_blocks reviewer schema nope")
            self.assertEqual(missing_block.returncode, 1)
            self.assertIn("nope", missing_block.stderr)

    def test_blocks_are_joined_by_one_blank_line(self):
        with tempfile.TemporaryDirectory(prefix="clagentic-test-prompt-") as home:
            prompts = os.path.join(home, "plugins", "clagentic-lite", "prompts")
            os.makedirs(prompts)
            with open(os.path.join(prompts, "reviewer.shared.txt"), "w") as handle:
                handle.write("@@@ a\none\ntwo\n@@@ b\nthree\n")
            result = self.run_sh(home, "ds_prompt_blocks reviewer a b")
            self.assertEqual(result.stdout, "one\ntwo\n\nthree\n")


if __name__ == "__main__":
    unittest.main()
