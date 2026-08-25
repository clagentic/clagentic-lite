"""
Regression test for lr-e33f73 item 2: `clagentic-lite init` stamps
CLAGENTIC_CONFIG_SCHEMA_VERSION into a freshly-written global config,
following the same version-constant pattern as SHIM_VERSION /
CLAUDE_SETTINGS_VERSION / etc (bin/clagentic-lite, top of file).

CLAGENTIC_LITE_HOME is always the real, read-only tool checkout here (never
mutated by `init` itself -- only HOME/.config is written to) -- matching
test_enroll_reenroll_no_force.py's own environment-hazard discipline. This
file never calls `update`, so lr-55a27a's non-tty discard guard is not in
play.

Run with: python3 -m unittest scripts.test_init_config_schema_version_stamp -v
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


def _current_schema_version():
    bin_path = os.path.join(TOOL_HOME, "bin", "clagentic-lite")
    with open(bin_path) as f:
        for line in f:
            m = re.match(r'^CONFIG_SCHEMA_VERSION="([^"]*)"', line)
            if m:
                return m.group(1)
    raise AssertionError("CONFIG_SCHEMA_VERSION constant not found in bin/clagentic-lite")


def _run_init(home, extra_env=None):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
    env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
    env.pop("CLAGENTIC_HOME", None)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [CLI, "init"],
        cwd=TOOL_HOME,
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

    def test_fresh_init_stamps_current_schema_version(self):
        _run_init(self.home)
        self.assertTrue(os.path.isfile(self.config_path),
                         msg="init must write a global config")
        with open(self.config_path) as f:
            body = f.read()
        expected = _current_schema_version()
        self.assertIn("CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % expected, body, msg=body)

    def test_reconfigure_restamps_current_schema_version(self):
        _run_init(self.home)
        # Simulate an older install by blanking the stamped version, then
        # re-run with --reconfigure (the only refresh path that touches an
        # existing config -- a plain second `init` short-circuits and must
        # NOT restamp, proven by the sibling test below).
        with open(self.config_path) as f:
            body = f.read()
        body = body.replace(
            "CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % _current_schema_version(),
            "CLAGENTIC_CONFIG_SCHEMA_VERSION=v0",
        )
        with open(self.config_path, "w") as f:
            f.write(body)

        # --reconfigure is a CLI flag, not an env var -- invoke directly.
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        subprocess.run(
            [CLI, "init", "--reconfigure"],
            cwd=TOOL_HOME, env=env, capture_output=True, text=True,
            timeout=30, stdin=subprocess.DEVNULL,
        )
        with open(self.config_path) as f:
            after = f.read()
        expected = _current_schema_version()
        self.assertIn("CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % expected, after, msg=after)

    def test_plain_second_init_does_not_touch_existing_config(self):
        """A plain re-run of `init` (no --reconfigure) on an already-
        configured machine must short-circuit and leave the existing config
        byte-for-byte untouched -- this is the exact non-destructive
        boundary the task's safety constraint depends on."""
        _run_init(self.home)
        with open(self.config_path) as f:
            before = f.read()
        # Simulate a user customization the second init must not clobber.
        customized = before.replace("CLAGENTIC_BUILDER_CMD=claude",
                                     "CLAGENTIC_BUILDER_CMD=my-custom-value")
        with open(self.config_path, "w") as f:
            f.write(customized)

        _run_init(self.home)
        with open(self.config_path) as f:
            after = f.read()
        self.assertEqual(customized, after,
                          msg="a plain second `init` must not rewrite an existing config")


if __name__ == "__main__":
    unittest.main()
