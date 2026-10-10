"""
The Builder role must not write the two governance files the gates read to
decide what is accepted: .clagentic/dispositions.json and
.clagentic/risk-profile.json.

pre-write-guard W-007 covers the Write and Edit tools; pre-bash-guard R-021
covers the shell. R-021 is a static match on the command text, so it also
normalizes './' and '../' segments and treats a 'cd' into .clagentic followed by
a write as covered; each spelling that used to slip past is a case below, for
both files. Each test runs the real hook template as a subprocess with the
PreToolUse JSON on stdin (command / file_path / agent_type at the top level;
agent_type present only inside a named subagent), the same payload a
foreground and a background Agent call produce for these fields. A captured
background payload from a live session is a post-merge check.

Run with: python3 -m unittest scripts.test_risk_profile_write_block -v
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from scripts.findings_test_support import git, make_repo
from scripts.isolated_env import shared_env

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WRITE_HOOK = os.path.join(TOOL_HOME, "share", "hook-shims", "pre-write-guard.sh.template")
BASH_HOOK = os.path.join(TOOL_HOME, "share", "hook-shims", "pre-bash-guard.sh.template")

BUILDER_SPELLINGS = ("clagentic-lite:builder", "builder", "Builder", "clagentic-lite:BUILDER")
OTHER_ROLES = ("clagentic-lite:reviewer", "general-purpose", "clagentic-lite:auditor", None)

FILES = ("dispositions.json", "risk-profile.json")

# Spellings that reach either file, with {f} the file name and {g} a glob that
# expands to it without spelling it. Several never name the file at all.
SPELLINGS = (
    'echo x > .clagentic/{f}',
    'echo x > .clagentic/./{f}',
    'echo x > .clagentic/lite/../{f}',
    'echo x > .clagentic//{f}',
    'echo x > .clagentic/lite/./../{f}',
    'echo x > .clagentic/lite/../../.clagentic/{f}',
    'echo x > ./.clagentic/../.clagentic/{f}',
    'cp /tmp/x .clagentic/{g}',
    'cp /tmp/x .clagentic/./{g}',
    'cp /tmp/x .clagentic/lite/../{g}',
    'cp /tmp/x .clagentic//{g}',
    'cp /tmp/x .clagentic/lite/./../{g}',
    'cd .clagentic && cp /tmp/x {g}',
    'cd .clagentic; cp /tmp/x {g}',
    'cd .clagentic && echo x > {g}',
    'cd ./.clagentic && mv /tmp/x {g}',
    'cd .clagentic/ && tee {g} < /tmp/x',
    'cd "$PWD/.clagentic" && cp /tmp/x {g}',
    "cd '.clagentic' && sed -i s/a/b/ {g}",
    'cd .clagentic/lite/.. && cp /tmp/x {g}',
    'pushd .clagentic && cp /tmp/x {g}',
    'true && cd .clagentic && truncate -s0 {g}',
    'cd .clagentic && python3 -c "open(\'{f}\', \'w\').write(\'{{}}\')"',
    'ECHO X > .CLAGENTIC/./{F}',
)
GLOBS = {"dispositions.json": "d*", "risk-profile.json": "r*"}

HARMLESS = (
    'ls',
    'git status',
    'ls .clagentic/lite',
    'ls .clagentic/lite/*.json',
    'ls .clagentic/lite/../lite',
    'cd src && cp /tmp/x d*',
    'cd .clagentic/lite && ls',
    'cd .clagentic && ls',
    'echo x > docs/notes.txt',
    'cp /tmp/x lite/d*',
    'clagentic-lite gates profile',
    'clagentic-lite gates dispositions-lint',
)


def render(template, name):
    return template.format(f=name, F=name.upper(), g=GLOBS[name])


def run_hook(hook, payload, cwd, env=None):
    proc = subprocess.run(["sh", hook], input=json.dumps(payload), cwd=cwd, env=env or shared_env(),
                          capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stderr


class Repo(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="clagentic-test-profile-block-")
        self.addCleanup(shutil.rmtree, self.repo, True)
        make_repo(self.repo)
        git(self.repo, "checkout", "-q", "-b", "feat/x")


def bash_payload(command, agent_type):
    payload = {"command": command}
    if agent_type is not None:
        payload["agent_type"] = agent_type
    return payload


class TestShellChannel(Repo):
    def test_every_spelling_is_refused_for_the_builder_for_both_files(self):
        for name in FILES:
            for template in SPELLINGS:
                command = render(template, name)
                for agent_type in BUILDER_SPELLINGS[:2]:
                    with self.subTest(agent_type=agent_type, command=command):
                        rc, stderr = run_hook(BASH_HOOK, bash_payload(command, agent_type), self.repo)
                        self.assertEqual(rc, 2, stderr)
                        self.assertIn("R-021", stderr)

    def test_every_builder_spelling_of_the_role_is_refused(self):
        for agent_type in BUILDER_SPELLINGS:
            for command in ('cd .clagentic && cp /tmp/x r*', 'echo x > .clagentic/./risk-profile.json'):
                with self.subTest(agent_type=agent_type, command=command):
                    rc, stderr = run_hook(BASH_HOOK, bash_payload(command, agent_type), self.repo)
                    self.assertEqual(rc, 2, stderr)

    def test_other_roles_and_the_main_session_are_not_stopped_by_r021(self):
        for agent_type in OTHER_ROLES:
            for name in FILES:
                for template in SPELLINGS[:6] + SPELLINGS[12:15]:
                    command = render(template, name)
                    with self.subTest(agent_type=agent_type, command=command):
                        rc, stderr = run_hook(BASH_HOOK, bash_payload(command, agent_type), self.repo)
                        self.assertNotIn("R-021", stderr)

    def test_the_builder_keeps_commands_that_reach_neither_file(self):
        for agent_type in BUILDER_SPELLINGS[:2]:
            for command in HARMLESS:
                with self.subTest(agent_type=agent_type, command=command):
                    rc, stderr = run_hook(BASH_HOOK, bash_payload(command, agent_type), self.repo)
                    self.assertEqual(rc, 0, stderr)
                    self.assertNotIn("R-021", stderr)

    def test_the_allow_list_variable_is_not_an_escape(self):
        env = shared_env()
        env["CLAGENTIC_ALLOW_BASH_RULES"] = "R-021"
        for command in ('cd .clagentic && cp /tmp/x r*', 'echo x > .clagentic/risk-profile.json'):
            with self.subTest(command=command):
                rc, stderr = run_hook(BASH_HOOK, bash_payload(command, "builder"), self.repo, env)
                self.assertEqual(rc, 2, stderr)

    def test_the_refusal_names_both_files_and_says_what_to_do_instead(self):
        rc, stderr = run_hook(BASH_HOOK, bash_payload("echo x > .clagentic/risk-profile.json", "Builder"),
                              self.repo)
        self.assertIn("risk-profile.json", stderr)
        self.assertIn("dispositions.json", stderr)
        self.assertIn("Read tool", stderr)

    def test_the_normalization_helper_is_exercised_by_the_template_itself(self):
        with open(BASH_HOOK) as handle:
            source = handle.read()
        self.assertIn("_pbg_normalize_paths", source)
        self.assertIn("risk-profile.json", source)


class TestWriteToolChannel(Repo):
    def target(self, *parts):
        return os.path.join(self.repo, *parts)

    def payload(self, path, agent_type):
        payload = {"file_path": path}
        if agent_type is not None:
            payload["agent_type"] = agent_type
        return payload

    def test_every_builder_spelling_is_refused_by_w007_for_the_profile(self):
        for agent_type in BUILDER_SPELLINGS:
            with self.subTest(agent_type=agent_type):
                rc, stderr = run_hook(
                    WRITE_HOOK, self.payload(self.target(".clagentic", "risk-profile.json"), agent_type),
                    self.repo)
                self.assertEqual(rc, 2, stderr)
                self.assertIn("W-007", stderr)

    def test_a_different_case_of_the_path_is_the_same_file(self):
        for parts in ((".CLAGENTIC", "risk-profile.json"), (".clagentic", "Risk-Profile.JSON")):
            with self.subTest(parts=parts):
                rc, stderr = run_hook(WRITE_HOOK, self.payload(self.target(*parts), "builder"), self.repo)
                self.assertEqual(rc, 2, stderr)
                self.assertIn("W-007", stderr)

    def test_other_roles_do_not_trip_w007(self):
        for agent_type in OTHER_ROLES:
            with self.subTest(agent_type=agent_type):
                rc, stderr = run_hook(
                    WRITE_HOOK, self.payload(self.target(".clagentic", "risk-profile.json"), agent_type),
                    self.repo)
                self.assertNotIn("W-007", stderr)

    def test_the_builder_can_still_write_other_files(self):
        rc, stderr = run_hook(WRITE_HOOK, self.payload(self.target("notes.txt"), "builder"), self.repo)
        self.assertEqual(rc, 0, stderr)


class TestHookVersion(unittest.TestCase):
    def test_all_six_templates_carry_the_bumped_version_the_installer_compares(self):
        with open(os.path.join(TOOL_HOME, "bin", "clagentic-lite")) as handle:
            constant = [line for line in handle if line.startswith("CLAUDE_HOOKS_VERSION=")][0]
        version = constant.split('"')[1]
        hooks = os.path.join(TOOL_HOME, "share", "hook-shims")
        names = [n for n in os.listdir(hooks) if n.endswith(".sh.template")]
        self.assertEqual(len(names), 6)
        for name in names:
            with self.subTest(name=name):
                with open(os.path.join(hooks, name)) as handle:
                    self.assertIn("clagentic-hooks-version: " + version, handle.read())
        self.assertGreaterEqual(int(version[1:]), 7)


if __name__ == "__main__":
    unittest.main()
