"""
Regression tests for the router agent-model-injection feature
(CLAGENTIC_ROUTER_INJECT_AGENT_MODEL, lr-49f25e).

This is the UNVERIFIED half of the router integration (claude-code GH#44385
territory: whether Claude Code actually honors a subagent frontmatter
`model:` field set to a non-standard string). These tests do NOT and cannot
verify that Claude Code honors the injected field -- only clagentic-lite's
own local role: this codebase materializes exactly the rendered agents dir
it claims to, injects model: only where the spec says it should, and never
touches the checked-in agents/*.md files. What Claude Code does with the
rendered output is out of scope here by design (see README "Verifying on
your machine").

Load-bearing property under test: CLAGENTIC_ROUTER_INJECT_AGENT_MODEL is a
SEPARATE opt-in from CLAGENTIC_ROUTER_URL -- setting the router URL alone
must never trigger this rendering/install path.

Run with: python3 -m unittest scripts/test_router_agent_model_injection.py -v
"""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")
AGENTS_SRC = os.path.join(TOOL_HOME, "plugins", "clagentic-lite", "agents")


def _write_fake_claude(bin_dir, argv_log):
    """Fake `claude` CLI that records every invocation's argv and always
    succeeds. `plugin list` returns empty so install (not update) is always
    exercised -- deterministic across repeated test runs."""
    fake = os.path.join(bin_dir, "claude")
    with open(fake, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_log}'
            case "$1 $2" in
              "plugin list") exit 0 ;;  # empty output = nothing installed yet
            esac
            exit 0
        """))
    os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return fake


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


class TestRouterAgentModelInjection(unittest.TestCase):
    """All tests run `clagentic-lite init` in a throwaway CLAGENTIC_LITE_HOME
    (a real clone of the checkout) with a fake `claude` on PATH -- never the
    real dev checkout (cmd_update/cmd_init do not stash on init, but init
    still runs prereq checks and plugin installs that should not touch the
    real tool home or hit the network)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-inject-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

        # Copy the WORKING TREE (not a git clone of HEAD) so uncommitted edits
        # under test are exercised -- a `git clone` only reflects committed
        # content and would silently test stale code during development.
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        shutil.copytree(TOOL_HOME, self.fake_tool_home,
                         ignore=shutil.ignore_patterns(".git"))

        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)

        self.bin_dir = os.path.join(self.tmpdir, "fakebin")
        os.makedirs(self.bin_dir)
        self.argv_log = os.path.join(self.tmpdir, "claude-argv.log")
        open(self.argv_log, "w").close()
        _write_fake_claude(self.bin_dir, self.argv_log)

    def _run_cli(self, argv, env_extra=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        env["CLAGENTIC_SKIP_FETCH"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        env.pop("CLAGENTIC_ROUTER_TOKEN", None)
        env.pop("CLAGENTIC_ROUTER_INJECT_AGENT_MODEL", None)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite")] + argv,
            cwd=self.tmpdir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            input="n\n",  # decline any interactive prompt (--reconfigure etc.)
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _argv_lines(self):
        with open(self.argv_log) as f:
            return [l.strip() for l in f if l.strip()]

    def _router_agents_dir(self):
        return os.path.join(self.fake_tool_home, ".clagentic", "router-agents")

    def test_router_url_alone_does_not_trigger_injection(self):
        """Setting CLAGENTIC_ROUTER_URL without CLAGENTIC_ROUTER_INJECT_AGENT_MODEL
        must never render or install the router-agents plugin -- the two keys
        are separate opt-ins by design."""
        rc, out, err = self._run_cli(
            ["init"],
            env_extra={"CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765"},
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertFalse(os.path.isdir(self._router_agents_dir()),
                          "router-agents dir was rendered with only ROUTER_URL set")
        argv = self._argv_lines()
        self.assertFalse(any("clagentic-lite-router" in l for l in argv),
                          msg=f"claude invoked with router plugin name unexpectedly: {argv}")

    def test_neither_key_set_no_router_agents_dir(self):
        rc, out, err = self._run_cli(["init"])
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertFalse(os.path.isdir(self._router_agents_dir()))

    def test_both_keys_set_renders_and_installs(self):
        rc, out, err = self._run_cli(
            ["init"],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
                "CLAGENTIC_AUDITOR_CMD": "codex",
                "CLAGENTIC_GATE_CMD": "claude",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        rendered_dir = os.path.join(self._router_agents_dir(), "plugins",
                                     "clagentic-lite-router", "agents")
        self.assertTrue(os.path.isdir(rendered_dir),
                         f"router agents dir was not rendered; stdout={out!r} stderr={err!r}")

        argv = self._argv_lines()
        self.assertTrue(any("clagentic-lite-router" in l for l in argv),
                         msg=f"claude was never invoked with the router plugin: {argv}")

    def test_reviewer_gets_model_field_when_cmd_is_codex(self):
        rc, out, err = self._run_cli(
            ["init"],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        rendered = os.path.join(self._router_agents_dir(), "plugins",
                                 "clagentic-lite-router", "agents", "reviewer.md")
        with open(rendered) as f:
            content = f.read()
        self.assertIn("model: role:reviewer-chain", content, msg=content)
        # Injected line must sit immediately after "name: reviewer" (line 2).
        lines = content.splitlines()
        self.assertEqual(lines[1], "name: reviewer")
        self.assertEqual(lines[2], "model: role:reviewer-chain")

    def test_gate_role_keeps_no_model_field_when_cmd_is_claude(self):
        """merge-gate stays on claude by default config -- no model: field,
        same as today's inherit-from-session behavior."""
        rc, out, err = self._run_cli(
            ["init"],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
                "CLAGENTIC_GATE_CMD": "claude",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        rendered = os.path.join(self._router_agents_dir(), "plugins",
                                 "clagentic-lite-router", "agents", "merge-gate.md")
        with open(rendered) as f:
            content = f.read()
        self.assertNotIn("model:", content, msg=content)

    def test_checked_in_agent_files_never_modified(self):
        """The rendered dir is a copy under .clagentic/router-agents/ --
        plugins/clagentic-lite/agents/*.md in the checkout itself must be
        byte-for-byte untouched regardless of injection."""
        before = {}
        for name in ("reviewer.md", "auditor.md", "merge-gate.md", "builder.md"):
            with open(os.path.join(self.fake_tool_home, "plugins", "clagentic-lite",
                                    "agents", name)) as f:
                before[name] = f.read()

        rc, out, err = self._run_cli(
            ["init"],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
                "CLAGENTIC_AUDITOR_CMD": "codex",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        for name, content in before.items():
            with open(os.path.join(self.fake_tool_home, "plugins", "clagentic-lite",
                                    "agents", name)) as f:
                after = f.read()
            self.assertEqual(before[name], after, msg=f"{name} was modified by injection")

    def test_builder_never_injected_even_if_cmd_is_non_claude(self):
        """Task spec is explicit: a tool-using builder role must never be
        pointed through the router (routed mode drops tool-calling)."""
        rc, out, err = self._run_cli(
            ["init"],
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_BUILDER_CMD": "codex",
            },
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        rendered_dir = os.path.join(self._router_agents_dir(), "plugins",
                                     "clagentic-lite-router", "agents")
        self.assertFalse(os.path.exists(os.path.join(rendered_dir, "builder.md")),
                          "builder.md must never be rendered into the router-agents plugin")


if __name__ == "__main__":
    unittest.main()
