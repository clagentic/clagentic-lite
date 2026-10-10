"""
The Builder role must not write .clagentic/dispositions.json on any channel.

The file is the operator's record of what has been accepted; the gate code
clears findings from it, so a Builder that could write it could clear its own
findings. pre-write-guard W-007 covers the Write and Edit tools and
pre-bash-guard R-021 covers the shell. Both read the role from the payload's
agent_type, which is matched without regard to case or namespace.

Each test runs the real hook template as a subprocess, with the PreToolUse JSON
on stdin as the other hook tests build it (file_path / command / agent_type at
the top level; agent_type present only inside a named subagent). The same
payload is what a foreground and a background Agent call produce for these
fields, so both are covered by the role variants below; a captured background
payload from a live session is a post-merge check.

Run with: python3 -m unittest scripts.test_builder_dispositions_write_block -v
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

BUILDER_SPELLINGS = ("clagentic-lite:builder", "builder", "Builder", "clagentic-lite:Builder",
                     "BUILDER", "clagentic-lite:BUILDER")
OTHER_ROLES = ("clagentic-lite:reviewer", "general-purpose", "clagentic-lite:auditor", None)

# Every ordinary way to write a file from the shell, spelled on the file.
WRITING_COMMANDS = (
    'echo "{}" > .clagentic/dispositions.json',
    'echo "{}" >> .clagentic/dispositions.json',
    'printf x | tee .clagentic/dispositions.json',
    'tee -a .clagentic/dispositions.json < /dev/null',
    'cp /tmp/x .clagentic/dispositions.json',
    'mv /tmp/x .clagentic/dispositions.json',
    "sed -i 's/a/b/' .clagentic/dispositions.json",
    "perl -pi -e 's/a/b/' .clagentic/dispositions.json",
    "python3 -c \"open('.clagentic/dispositions.json', 'w').write('{}')\"",
    'cd .clagentic && echo x > dispositions.json',
    'dd if=/dev/null of=.clagentic/dispositions.json',
    'git checkout origin/main -- .clagentic/dispositions.json',
    'rm .clagentic/dispositions.json',
    'ln -sf /tmp/x .clagentic/dispositions.json',
    'truncate -s0 .clagentic/dispositions.json',
    'install -m 644 /tmp/x .clagentic/dispositions.json',
    'echo x > .CLAGENTIC/Dispositions.JSON',
    'echo x > ./.clagentic/../.clagentic/dispositions.json',
    'echo x > "$PWD/.clagentic/dispositions.json"',
    # The name is never spelled: a glob in the first segment under .clagentic/.
    'echo x > .clagentic/d*',
    'echo x > .clagentic/dispositions.js?n',
    'cp /tmp/x .clagentic/*',
)

HARMLESS_COMMANDS = (
    'ls',
    'git status',
    'git diff --stat',
    'ls .clagentic/lite',
    'ls .clagentic/lite/*.json',
    'echo x > docs/notes.txt',
    'python3 -m py_compile scripts/x.py',
    'clagentic-lite gates dispositions-lint',
)


def _env():
    return shared_env()


def run_hook(hook, payload, cwd):
    proc = subprocess.run(["sh", hook], input=json.dumps(payload), cwd=cwd, env=_env(),
                          capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stderr


def init_repo(path):
    make_repo(path)
    git(path, "checkout", "-q", "-b", "feat/x")


class Repo(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="clagentic-test-disp-block-")
        self.addCleanup(shutil.rmtree, self.repo, True)
        init_repo(self.repo)


def bash_payload(command, agent_type):
    payload = {"command": command}
    if agent_type is not None:
        payload["agent_type"] = agent_type
    return payload


def write_payload(path, agent_type):
    payload = {"file_path": path}
    if agent_type is not None:
        payload["agent_type"] = agent_type
    return payload


class TestShellChannel(Repo):
    def test_every_writing_command_is_refused_for_every_builder_spelling(self):
        for agent_type in BUILDER_SPELLINGS:
            for command in WRITING_COMMANDS:
                with self.subTest(agent_type=agent_type, command=command):
                    rc, stderr = run_hook(BASH_HOOK, bash_payload(command, agent_type), self.repo)
                    self.assertEqual(rc, 2, stderr)
                    self.assertIn("R-021", stderr)

    def test_other_roles_and_the_main_session_are_not_stopped_by_r021(self):
        for agent_type in OTHER_ROLES:
            for command in WRITING_COMMANDS:
                with self.subTest(agent_type=agent_type, command=command):
                    rc, stderr = run_hook(BASH_HOOK, bash_payload(command, agent_type), self.repo)
                    self.assertNotIn("R-021", stderr)

    def test_the_builder_keeps_every_command_that_does_not_name_the_file(self):
        for agent_type in BUILDER_SPELLINGS:
            for command in HARMLESS_COMMANDS:
                with self.subTest(agent_type=agent_type, command=command):
                    rc, stderr = run_hook(BASH_HOOK, bash_payload(command, agent_type), self.repo)
                    self.assertEqual(rc, 0, stderr)

    def test_the_allow_list_variable_is_not_an_escape(self):
        env = _env()
        env["CLAGENTIC_ALLOW_BASH_RULES"] = "R-021"
        proc = subprocess.run(
            ["sh", BASH_HOOK], input=json.dumps(bash_payload(WRITING_COMMANDS[0], "builder")),
            cwd=self.repo, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_the_refusal_says_what_to_do_instead(self):
        rc, stderr = run_hook(BASH_HOOK, bash_payload(WRITING_COMMANDS[0], "Builder"), self.repo)
        self.assertIn("stanza", stderr)
        self.assertIn("Read tool", stderr)

    def test_malformed_payload_still_fails_closed_before_the_rule(self):
        proc = subprocess.run(["sh", BASH_HOOK], input="{not json", cwd=self.repo, env=_env(),
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)


class TestWriteToolChannel(Repo):
    def target(self, *parts):
        return os.path.join(self.repo, *parts)

    def test_every_builder_spelling_is_refused_by_w007(self):
        for agent_type in BUILDER_SPELLINGS:
            with self.subTest(agent_type=agent_type):
                rc, stderr = run_hook(
                    WRITE_HOOK, write_payload(self.target(".clagentic", "dispositions.json"), agent_type),
                    self.repo)
                self.assertEqual(rc, 2, stderr)
                self.assertIn("W-007", stderr)

    def test_a_different_case_of_the_path_is_the_same_file(self):
        for agent_type in BUILDER_SPELLINGS:
            for parts in ((".CLAGENTIC", "dispositions.json"), (".clagentic", "Dispositions.JSON"),
                          (".Clagentic", "DISPOSITIONS.JSON")):
                with self.subTest(agent_type=agent_type, parts=parts):
                    rc, stderr = run_hook(WRITE_HOOK, write_payload(self.target(*parts), agent_type),
                                          self.repo)
                    self.assertEqual(rc, 2, stderr)
                    self.assertIn("W-007", stderr)

    def test_other_roles_do_not_trip_w007(self):
        for agent_type in OTHER_ROLES:
            with self.subTest(agent_type=agent_type):
                rc, stderr = run_hook(
                    WRITE_HOOK, write_payload(self.target(".clagentic", "dispositions.json"), agent_type),
                    self.repo)
                self.assertNotIn("W-007", stderr)

    def test_the_builder_can_still_write_other_files(self):
        for agent_type in BUILDER_SPELLINGS:
            with self.subTest(agent_type=agent_type):
                rc, stderr = run_hook(WRITE_HOOK, write_payload(self.target("notes.txt"), agent_type),
                                      self.repo)
                self.assertEqual(rc, 0, stderr)


class TestOneDefinitionOfTheRole(unittest.TestCase):
    def test_both_hooks_use_the_shared_matcher(self):
        for hook in (WRITE_HOOK, BASH_HOOK):
            with open(hook) as handle:
                self.assertIn("ds_agent_is_builder", handle.read(), hook)

    def test_the_matcher_itself(self):
        script = ('. "%s/scripts/platform.sh"; ds_agent_is_builder "$1"' % TOOL_HOME)
        for agent_type, expected in (("Builder", 0), ("clagentic-lite:Builder", 0), ("builder", 0),
                                     ("clagentic-lite:reviewer", 1), ("", 1)):
            with self.subTest(agent_type=agent_type):
                proc = subprocess.run(["sh", "-c", script, "sh", agent_type], env=_env(),
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, expected, proc.stderr)


if __name__ == "__main__":
    unittest.main()
