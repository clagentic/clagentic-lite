"""
Regression tests for lr-25e73e item 3 (amending lr-e33f73's deferred items
3-4): `clagentic-lite update` never refreshed an existing
~/.config/clagentic/config, and neither did a plain `doctor` run beyond a
WARN. OPERATOR DECISION (lr-25e73e task thread, comment #2): `update` now
LOUDLY reports missing keys and names the one-command remedy on every run;
the append pass itself only runs behind an explicit `--refresh-config` flag.
Appended keys are ALWAYS commented out -- the flag controls whether keys are
appended, never whether they arrive active.

HAZARD, read before editing this file: every test here points
CLAGENTIC_LITE_HOME at a throwaway `git clone` of the real checkout, never
at the live dev checkout itself -- follows _clone_tool_home from
test_update_nontty_discard_guard.py / test_doctor_config_drift.py exactly.
`cmd_update` is emphatically NOT read-only (git pull, hook re-stamp, plugin
render/install) -- pointing CLAGENTIC_LITE_HOME at the live tree here is
exactly the class of defect PEACHES blocked lr-e33f73's first SHA for.

Run with: python3 -m unittest scripts.test_update_refresh_config -v
"""
import os
import shutil
import stat
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


def _read(path):
    with open(path) as f:
        return f.read()


class _UpdateRefreshConfigTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-update-refresh-config-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.config_dir = os.path.join(self.home, ".config", "clagentic", "lite")
        os.makedirs(self.config_dir)
        self.config_path = os.path.join(self.config_dir, "config")
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)

    def _write_global_config(self, body):
        with open(self.config_path, "w") as f:
            f.write(body)
        os.chmod(self.config_path, 0o600)

    def _run_update(self, argv=None, extra_env=None):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_UPDATE_ALLOW_DISCARD", None)
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite")] + (argv or ["update"]),
            cwd=self.fake_tool_home,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout, proc.stderr


class TestPlainUpdateReportsButDoesNotAppend(_UpdateRefreshConfigTestBase):
    def test_bare_update_reports_missing_keys_loudly_and_names_remedy(self):
        self._write_global_config(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        before = _read(self.config_path)
        rc, out, err = self._run_update()
        combined = out + err
        self.assertIn("CLAGENTIC_REVIEW_CHUNKING", combined, msg=combined)
        self.assertIn("--refresh-config", combined, msg=combined)
        after = _read(self.config_path)
        self.assertEqual(before, after,
                          msg="a bare `update` must never append keys -- report only")

    def test_bare_update_does_not_grow_the_config_file(self):
        self._write_global_config("CLAGENTIC_LITE_HOME=/fake/home\n")
        before_size = os.path.getsize(self.config_path)
        self._run_update()
        after_size = os.path.getsize(self.config_path)
        self.assertEqual(before_size, after_size)


class TestRefreshConfigAppendsCommentedOut(_UpdateRefreshConfigTestBase):
    def test_refresh_config_appends_missing_keys_commented_out(self):
        self._write_global_config(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        rc, out, err = self._run_update(argv=["update", "--refresh-config"])
        after = _read(self.config_path)
        self.assertIn("CLAGENTIC_REVIEW_CHUNKING", after, msg=after)
        # Must be commented out -- never appear as an ACTIVE assignment.
        self.assertNotIn("\nCLAGENTIC_REVIEW_CHUNKING=", after, msg=after)
        for line in after.splitlines():
            if "CLAGENTIC_REVIEW_CHUNKING=" in line:
                self.assertTrue(line.lstrip().startswith("#"),
                                 msg="appended key must be commented out: %r" % line)

    def test_refresh_config_preserves_existing_content_verbatim(self):
        original = (
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "# my own comment, preserve me\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        self._write_global_config(original)
        self._run_update(argv=["update", "--refresh-config"])
        after = _read(self.config_path)
        self.assertTrue(after.startswith(original),
                         msg="existing content/ordering/comments must survive untouched: %r" % after)

    def test_refresh_config_does_not_duplicate_already_commented_key(self):
        """A key present in commented-out form must not be double-appended.
        Counts actual KEY=... assignment lines (active or commented), not
        raw substring occurrences -- config.example's own documentation
        prose for a NEIGHBORING key (CLAGENTIC_REVIEW_CHUNK_BYTES) mentions
        "CLAGENTIC_REVIEW_CHUNKING=1" in a sentence, which a naive substring
        count would also catch."""
        self._write_global_config(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
            "# CLAGENTIC_REVIEW_CHUNKING=1\n"
        )
        self._run_update(argv=["update", "--refresh-config"])
        after = _read(self.config_path)
        key_lines = [
            line for line in after.splitlines()
            if line.lstrip("# ").startswith("CLAGENTIC_REVIEW_CHUNKING=")
        ]
        self.assertEqual(len(key_lines), 1, msg=after)

    def test_refresh_config_no_op_when_nothing_missing(self):
        example_path = os.path.join(self.fake_tool_home, "share", "config.example")
        with open(example_path) as f:
            example_body = f.read()
        self._write_global_config(example_body)
        before = _read(self.config_path)
        rc, out, err = self._run_update(argv=["update", "--refresh-config"])
        after = _read(self.config_path)
        self.assertEqual(before, after)
        self.assertIn("no drift", out + err, msg=out + err)

    def test_refresh_config_chmod_600_preserved(self):
        self._write_global_config("CLAGENTIC_LITE_HOME=/fake/home\n")
        self._run_update(argv=["update", "--refresh-config"])
        mode = stat.S_IMODE(os.stat(self.config_path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_refresh_config_never_leaks_a_configured_value(self):
        """SECRETS: no configured VALUE may appear in any output stream on
        any path. Plant a fake credential-shaped value and assert it never
        surfaces in stdout/stderr, on either the report or the append path."""
        secret = "sk-super-secret-token-should-never-print"
        self._write_global_config(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "CLAGENTIC_ROUTER_TOKEN=%s\n" % secret
        )
        rc, out, err = self._run_update(argv=["update", "--refresh-config"])
        self.assertNotIn(secret, out)
        self.assertNotIn(secret, err)
        after = _read(self.config_path)
        self.assertIn(secret, after, msg="the value itself must still round-trip in the file")

    def test_refresh_config_malformed_line_skipped_not_errored(self):
        self._write_global_config(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "this is not a valid config line at all\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        rc, out, err = self._run_update(argv=["update", "--refresh-config"])
        after = _read(self.config_path)
        self.assertIn("this is not a valid config line at all", after,
                       msg="malformed lines must survive untouched, not error out")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                      "running as root -- permission bits do not block root's "
                      "own writes, so this scenario cannot be exercised here")
    def test_refresh_config_readonly_config_skips_without_crashing(self):
        self._write_global_config("CLAGENTIC_LITE_HOME=/fake/home\n")
        os.chmod(self.config_path, 0o400)
        try:
            rc, out, err = self._run_update(argv=["update", "--refresh-config"])
            combined = out + err
            self.assertIn("not writable", combined, msg=combined)
        finally:
            os.chmod(self.config_path, 0o600)


if __name__ == "__main__":
    unittest.main()
