"""
Regression test for lr-e33f73 item 2: `clagentic-lite init` stamps
CLAGENTIC_CONFIG_SCHEMA_VERSION into a freshly-written global config,
following the same version-constant pattern as SHIM_VERSION /
CLAUDE_SETTINGS_VERSION / etc (bin/clagentic-lite, top of file).

HAZARD (PEACHES PR #193 review finding 1): `cmd_init` is NOT read-only
against CLAGENTIC_LITE_HOME -- it materializes $CLAGENTIC_LITE_HOME/.claude/
hooks/*.sh from share/hook-shims/*.sh.template (_stamp_claude_hooks, always
runs, unconditionally) and may run `git -C "$CLAGENTIC_LITE_HOME" fetch`.
Pointing CLAGENTIC_LITE_HOME at the real dev checkout is exactly the class
of defect the HAZARD discipline in test_enroll_reenroll_no_force.py:22-27
and test_router_bedrock_settings_stamp.py:375-387 exists to prevent -- this
file previously did that and was corrected by that review. Every test here
now points CLAGENTIC_LITE_HOME at a throwaway `git clone` of the real
checkout (never the live tree itself), mirroring
test_update_nontty_discard_guard.py's `_clone_tool_home` helper exactly.

NOTE: `git clone` reflects committed HEAD only -- these tests must run
against a checkout where CONFIG_SCHEMA_VERSION and the stamping change are
already committed, or they silently exercise stale pre-fix code (same
caveat documented in the sibling router-stamp test files).

Run with: python3 -m unittest scripts.test_init_config_schema_version_stamp -v
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _clone_tool_home(dest):
    subprocess.run(["git", "clone", "-q", TOOL_HOME, dest], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.name", "Test"],
                    check=True, capture_output=True)


def _current_schema_version(fake_tool_home):
    bin_path = os.path.join(fake_tool_home, "bin", "clagentic-lite")
    with open(bin_path) as f:
        for line in f:
            m = re.match(r'^CONFIG_SCHEMA_VERSION="([^"]*)"', line)
            if m:
                return m.group(1)
    raise AssertionError("CONFIG_SCHEMA_VERSION constant not found in bin/clagentic-lite")


def _run_init(fake_tool_home, home, argv=None, extra_env=None):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = fake_tool_home
    env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
    env.pop("CLAGENTIC_HOME", None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [os.path.join(fake_tool_home, "bin", "clagentic-lite")] + (argv or ["init"]),
        cwd=fake_tool_home,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestInitStampsConfigSchemaVersion(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-init-schema-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.config_path = os.path.join(self.home, ".config", "clagentic", "config")
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)

    def test_fresh_init_stamps_current_schema_version(self):
        _run_init(self.fake_tool_home, self.home)
        self.assertTrue(os.path.isfile(self.config_path),
                         msg="init must write a global config")
        with open(self.config_path) as f:
            body = f.read()
        expected = _current_schema_version(self.fake_tool_home)
        self.assertIn("CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % expected, body, msg=body)

    def test_reconfigure_restamps_current_schema_version(self):
        _run_init(self.fake_tool_home, self.home)
        # Simulate an older install by blanking the stamped version, then
        # re-run with --reconfigure (the only refresh path that touches an
        # existing config -- a plain second `init` short-circuits and must
        # NOT restamp, proven by the sibling test below).
        expected = _current_schema_version(self.fake_tool_home)
        with open(self.config_path) as f:
            body = f.read()
        body = body.replace(
            "CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % expected,
            "CLAGENTIC_CONFIG_SCHEMA_VERSION=v0",
        )
        with open(self.config_path, "w") as f:
            f.write(body)

        _run_init(self.fake_tool_home, self.home, argv=["init", "--reconfigure"])
        with open(self.config_path) as f:
            after = f.read()
        self.assertIn("CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % expected, after, msg=after)

    def test_plain_second_init_does_not_touch_existing_config(self):
        """A plain re-run of `init` (no --reconfigure) on an already-
        configured machine must short-circuit and leave the existing config
        byte-for-byte untouched -- this is the exact non-destructive
        boundary the task's safety constraint depends on."""
        _run_init(self.fake_tool_home, self.home)
        with open(self.config_path) as f:
            before = f.read()
        # Simulate a user customization the second init must not clobber.
        customized = before.replace("CLAGENTIC_BUILDER_CMD=claude",
                                     "CLAGENTIC_BUILDER_CMD=my-custom-value")
        with open(self.config_path, "w") as f:
            f.write(customized)

        _run_init(self.fake_tool_home, self.home)
        with open(self.config_path) as f:
            after = f.read()
        self.assertEqual(customized, after,
                          msg="a plain second `init` must not rewrite an existing config")


if __name__ == "__main__":
    unittest.main()
