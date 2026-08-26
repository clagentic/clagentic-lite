"""
Regression tests for lr-25e73e item 4: `clagentic-lite init --reconfigure`
used to cp-CLOBBER the existing global config (_write_global_config),
destroying every user customization. It now MERGES: every user-set value
survives verbatim, new keys from share/config.example are added.

HAZARD, read before editing this file: every test here points
CLAGENTIC_LITE_HOME at a throwaway `git clone` of the real checkout, never
the live dev checkout -- `cmd_init` materializes .claude/hooks/ and may run
`git fetch` against CLAGENTIC_LITE_HOME, so it is not read-only. Follows
_clone_tool_home from test_init_config_schema_version_stamp.py exactly
(scripts/test_support.py) -- the clone is overlaid with the checkout's
current on-disk content so an uncommitted edit under test is never
invisible to this suite.

Run with: python3 -m unittest scripts.test_init_reconfigure_merge -v
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

from scripts.test_support import clone_this_tool_home_with_overlay

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_clone_tool_home = clone_this_tool_home_with_overlay


def _current_schema_version(fake_tool_home):
    bin_path = os.path.join(fake_tool_home, "bin", "clagentic-lite")
    with open(bin_path) as f:
        for line in f:
            m = re.match(r'^CONFIG_SCHEMA_VERSION="([^"]*)"', line)
            if m:
                return m.group(1)
    raise AssertionError("CONFIG_SCHEMA_VERSION constant not found in bin/clagentic-lite")


class _InitReconfigureMergeTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-init-reconfigure-merge-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.config_path = os.path.join(self.home, ".config", "clagentic", "lite", "config")
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)

    def _run(self, argv, extra_env=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite")] + argv,
            cwd=self.fake_tool_home,
            env=env,
            capture_output=True,
            text=True,
            # 60s, not 30 -- init runs several real subprocess probes (LLM CLI
            # version/auth checks, `claude plugin list`, etc) whose wall-clock
            # cost varies under load; observed to occasionally exceed 30s
            # under a full concurrent test-suite run (same rationale as
            # test_doctor_config_drift.py's own 60s timeout, lr-e33f73).
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _read(self):
        with open(self.config_path) as f:
            return f.read()

    def _write(self, body):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w") as f:
            f.write(body)
        os.chmod(self.config_path, 0o600)


class TestReconfigurePreservesCustomizedValues(_InitReconfigureMergeTestBase):
    def test_customized_value_survives_reconfigure(self):
        self._run(["init"])
        before = self._read()
        customized = before.replace(
            "CLAGENTIC_BUILDER_CMD=claude", "CLAGENTIC_BUILDER_CMD=my-custom-value"
        )
        self._write(customized)

        self._run(["init", "--reconfigure"])
        after = self._read()
        self.assertIn("CLAGENTIC_BUILDER_CMD=my-custom-value", after, msg=after)

    def test_multiple_customized_values_all_survive(self):
        self._run(["init"])
        before = self._read()
        customized = (
            before.replace("CLAGENTIC_BUILDER_CMD=claude", "CLAGENTIC_BUILDER_CMD=custom-builder")
            .replace("CLAGENTIC_REPO_HOST=github", "CLAGENTIC_REPO_HOST=gitlab")
            .replace("CLAGENTIC_BLOCK_SEVERITY=high", "CLAGENTIC_BLOCK_SEVERITY=critical")
        )
        self._write(customized)

        self._run(["init", "--reconfigure"])
        after = self._read()
        self.assertIn("CLAGENTIC_BUILDER_CMD=custom-builder", after, msg=after)
        self.assertIn("CLAGENTIC_REPO_HOST=gitlab", after, msg=after)
        self.assertIn("CLAGENTIC_BLOCK_SEVERITY=critical", after, msg=after)

    def test_value_containing_equals_sign_round_trips(self):
        """A value containing '=' after the key's own first '=' must round-
        trip verbatim -- the config is dot-sourced POSIX sh (ds_load_global_env,
        scripts/platform.sh), so the value itself must stay unquoted-shell-safe
        (no embedded spaces/quotes) for the fixture to be a realistic config
        line at all; '=' characters alone are fine unquoted. Uses
        CLAGENTIC_BUILDER_CHAIN, an ACTIVE key by default (unlike
        CLAGENTIC_ROUTER_URL, which ships commented-out and would need
        activating first to exercise the preservation path at all)."""
        self._run(["init"])
        before = self._read()
        customized = before.replace(
            "CLAGENTIC_BUILDER_CHAIN=codex:default,claude:flagship",
            "CLAGENTIC_BUILDER_CHAIN=codex:default=extra,claude:flagship=more"
        )
        self.assertNotEqual(before, customized, msg="fixture assumption broke: key text not found")
        self._write(customized)

        self._run(["init", "--reconfigure"])
        after = self._read()
        self.assertIn("CLAGENTIC_BUILDER_CHAIN=codex:default=extra,claude:flagship=more",
                       after, msg=after)

    def test_uncomments_a_previously_commented_key_the_user_activated(self):
        self._run(["init"])
        before = self._read()
        # CLAGENTIC_REVIEW_CHUNKING ships commented-out; simulate the user
        # having uncommented + set it.
        customized = before.replace(
            "# CLAGENTIC_REVIEW_CHUNKING=1", "CLAGENTIC_REVIEW_CHUNKING=1"
        )
        self.assertNotEqual(before, customized, msg="fixture assumption broke: key text not found")
        self._write(customized)

        self._run(["init", "--reconfigure"])
        after = self._read()
        self.assertIn("\nCLAGENTIC_REVIEW_CHUNKING=1", after, msg=after)


class TestReconfigureAddsNewKeys(_InitReconfigureMergeTestBase):
    def test_key_missing_from_old_config_is_added(self):
        self._write(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        self._run(["init", "--reconfigure"])
        after = self._read()
        self.assertIn("CLAGENTIC_REVIEWER_CMD", after, msg=after)


class TestReconfigureSchemaVersionAlwaysCurrent(_InitReconfigureMergeTestBase):
    def test_stale_schema_version_is_restamped_not_preserved(self):
        self._run(["init"])
        expected = _current_schema_version(self.fake_tool_home)
        before = self._read()
        customized = before.replace(
            "CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % expected,
            "CLAGENTIC_CONFIG_SCHEMA_VERSION=v0",
        )
        self._write(customized)

        self._run(["init", "--reconfigure"])
        after = self._read()
        self.assertIn("CLAGENTIC_CONFIG_SCHEMA_VERSION=%s" % expected, after, msg=after)
        self.assertNotIn("CLAGENTIC_CONFIG_SCHEMA_VERSION=v0", after, msg=after)


class TestReconfigureEdgeCases(_InitReconfigureMergeTestBase):
    def test_malformed_line_skipped_without_error(self):
        """"Malformed" here means a line that is valid dot-sourceable POSIX
        sh (this file is dot-sourced by ds_load_global_env at every CLI
        invocation, including init's own startup -- see scripts/platform.sh)
        but not a CLAGENTIC_*= assignment the preservation capture recognizes
        -- e.g. a bare comment with an '=' sign in its prose. Arbitrary
        non-shell text is not a supported "malformed line" case for this
        file format: it would break dot-sourcing itself, before the merge
        code ever runs, which is a pre-existing property of every
        config-reading command, not something introduced by lr-25e73e.
        The preservation capture only ever captures ACTIVE CLAGENTIC_*=
        assignment lines by design (see _write_global_config's own comment)
        -- a non-assignment comment line is correctly NOT captured/preserved
        verbatim by that mechanism; this test asserts the run still
        completes cleanly (no error) and the real assignment survives, not
        that the incidental comment text is preserved."""
        self._write(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "# not a real key= assignment, just a comment with an = sign in it\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        rc, out, err = self._run(["init", "--reconfigure"])
        self.assertEqual(rc, 0, msg=err)
        after = self._read()
        self.assertIn("CLAGENTIC_BUILDER_CMD=claude", after, msg=after)

    def test_crlf_line_endings_do_not_break_merge(self):
        """A CRLF-terminated config is NOT something bin/clagentic-lite
        tolerates at all today (ds_load_global_env dot-sources the raw file
        unconditionally at CLI startup, scripts/platform.sh -- a \\r before
        the trailing newline on every line breaks POSIX sh dot-sourcing
        outright, before any merge code runs; this is pre-existing behavior
        for every config-reading command, not something lr-25e73e changes or
        is scoped to fix). The realistic in-scope case is a single line a
        user pasted from a Windows editor carrying a stray CRLF while the
        rest of the file is normal LF -- the file's own dot-source still
        parses (only that one line's value would carry a trailing \\r if
        untreated), and the preservation capture in _write_global_config
        strips a trailing \\r on read (sub(/\\r$/, "") -- see its comment)
        so that value round-trips clean rather than carrying the stray
        byte forward on every future reconfigure."""
        self._run(["init"])
        before = self._read()
        # Only the customized line carries a CRLF ending; every other line
        # (including the CLI-critical CLAGENTIC_LITE_HOME stamp) stays LF so
        # the file is still validly dot-sourceable at CLI startup.
        crlf_body = before.replace(
            "CLAGENTIC_BUILDER_CMD=claude\n", "CLAGENTIC_BUILDER_CMD=crlf-value\r\n"
        )
        self._write(crlf_body)

        rc, out, err = self._run(["init", "--reconfigure"])
        self.assertEqual(rc, 0, msg=err)
        after = self._read()
        self.assertIn("CLAGENTIC_BUILDER_CMD=crlf-value", after, msg=after)
        self.assertNotIn("crlf-value\r", after,
                          msg="preserved value must not carry a stray CRLF byte forward")

    def test_chmod_600_preserved_throughout(self):
        self._run(["init"])
        self._run(["init", "--reconfigure"])
        mode = stat.S_IMODE(os.stat(self.config_path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_never_leaks_a_configured_value_on_reconfigure(self):
        secret = "sk-reconfigure-secret-must-not-print"
        self._run(["init"])
        before = self._read()
        # CLAGENTIC_ROUTER_TOKEN ships commented-out ("# CLAGENTIC_ROUTER_TOKEN=");
        # activate it (an ACTIVE assignment) so the preservation capture --
        # which only ever captures active KEY=VALUE lines, by design -- has a
        # user-set value to carry forward.
        customized = before.replace(
            "# CLAGENTIC_ROUTER_TOKEN=", "CLAGENTIC_ROUTER_TOKEN=%s" % secret, 1
        )
        self.assertNotEqual(before, customized, msg="fixture assumption broke: key text not found")
        self._write(customized)

        rc, out, err = self._run(["init", "--reconfigure"])
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, err)
        after = self._read()
        self.assertIn(secret, after)


class TestPlainInitStillShortCircuits(_InitReconfigureMergeTestBase):
    def test_plain_second_init_does_not_touch_existing_config(self):
        """Unchanged guardrail: without --reconfigure, a second `init` must
        leave the config byte-for-byte untouched (merge logic must never run
        on the short-circuit path)."""
        self._run(["init"])
        before = self._read()
        customized = before.replace(
            "CLAGENTIC_BUILDER_CMD=claude", "CLAGENTIC_BUILDER_CMD=untouched-value"
        )
        self._write(customized)

        self._run(["init"])
        after = self._read()
        self.assertEqual(customized, after)


if __name__ == "__main__":
    unittest.main()
