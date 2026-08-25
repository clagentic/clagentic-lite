"""
Regression tests for lr-e33f73: `clagentic-lite update` never refreshes an
existing ~/.config/clagentic/config, so a config key shipped after a given
install's `init` run is invisible to that install forever, with nothing
anywhere telling the operator it exists. `_doctor_check_config_drift`
(bin/clagentic-lite) closes the visibility gap by diffing the KEY SET (never
values) in share/config.example against the installed global config on every
`clagentic-lite doctor` run.

Uses a constructed global config (never the real share/config.example
verbatim) so drift is exercised deterministically regardless of how many
real keys config.example currently has -- these tests point GLOBAL_CONFIG at
a throwaway file under a temp HOME, never at a real ~/.config/clagentic/config.

`doctor` never runs `git -C "$CLAGENTIC_LITE_HOME" stash` (only `update`
does -- see test_update_nontty_discard_guard.py's HAZARD discipline), so
CLAGENTIC_LITE_HOME can point straight at the live checkout here, matching
test_doctor_gitleaks_config_advisory.py's own precedent.

Run with: python3 -m unittest scripts.test_doctor_config_drift -v
"""
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


class _DoctorConfigDriftTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-doctor-config-drift-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.config_dir = os.path.join(self.home, ".config", "clagentic")
        os.makedirs(self.config_dir)
        self.config_path = os.path.join(self.config_dir, "config")

    def _write_global_config(self, body):
        with open(self.config_path, "w") as f:
            f.write(body)

    def _run_doctor(self):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        proc = subprocess.run(
            [CLI, "doctor"], cwd=self.tmpdir, env=env,
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode, proc.stdout, proc.stderr


class TestNoGlobalConfigSkipsSilently(_DoctorConfigDriftTestBase):
    def test_no_config_file_is_skipped_not_warned(self):
        """No global config yet (pre-init machine) -- doctor should point at
        `init`, not report drift against a file that does not exist."""
        rc, out, err = self._run_doctor()
        self.assertIn("global config drift:", out, msg=out)
        self.assertIn("run `clagentic-lite init`", out, msg=out)
        self.assertNotIn("missing", out.split("global config drift:", 1)[1].split("\n\n")[0],
                          msg=out)


class TestMissingKeysReported(_DoctorConfigDriftTestBase):
    def test_missing_key_is_named(self):
        """A config missing a real key from config.example (here,
        CLAGENTIC_REVIEW_CHUNKING -- the exact key from the field incident
        this task was filed against) is named explicitly, by variable name,
        in doctor output."""
        # Deliberately sparse -- only a couple of keys, so the drift is large
        # and unambiguous regardless of config.example's current full shape.
        self._write_global_config(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        rc, out, err = self._run_doctor()
        self.assertIn("global config drift:", out, msg=out)
        self.assertIn("WARN global config at", out, msg=out)
        self.assertIn("CLAGENTIC_REVIEW_CHUNKING", out, msg=out)
        # config.example carries CLAGENTIC_REVIEW_CHUNKING only as a
        # commented-out (inert) key -- the drift check must still surface it,
        # since a commented-out key in a fresh install is exactly as
        # invisible to the operator as a genuinely-new key.
        self.assertIn("CLAGENTIC_ROUTER_URL", out, msg=out)

    def test_missing_count_is_reported(self):
        self._write_global_config("CLAGENTIC_LITE_HOME=/fake/home\n")
        rc, out, err = self._run_doctor()
        self.assertIn("key(s) present in share/config.example", out, msg=out)


class TestNoDriftWhenAllKeysPresent(_DoctorConfigDriftTestBase):
    def test_full_config_example_copy_reports_no_drift(self):
        """A config that is a verbatim copy of config.example (the shape
        `clagentic-lite init` itself produces) must report clean -- no
        false positive on an install that is genuinely current, and no
        false positive on config.example's own commented-out keys, since
        both the installed file and the source template carry the same
        commented lines here."""
        example_path = os.path.join(TOOL_HOME, "share", "config.example")
        with open(example_path) as f:
            example_body = f.read()
        self._write_global_config(example_body)
        rc, out, err = self._run_doctor()
        self.assertIn("global config drift:", out, msg=out)
        section = out.split("global config drift:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("no drift", section, msg=out)
        self.assertNotIn("WARN", section, msg=out)

    def test_values_are_never_compared_only_key_names(self):
        """A config with every key present but a NON-DEFAULT value for one
        of them must still report no drift -- this check diffs key names
        only, never values, so it can never flag or touch a user's
        customization. Uses CLAGENTIC_DEFAULT_BRANCH, a key no OTHER doctor
        check consumes, so a leaked value elsewhere in doctor's unrelated
        output can't produce a false failure here."""
        example_path = os.path.join(TOOL_HOME, "share", "config.example")
        with open(example_path) as f:
            lines = f.readlines()
        customized = []
        for line in lines:
            if line.startswith("CLAGENTIC_DEFAULT_BRANCH="):
                customized.append("CLAGENTIC_DEFAULT_BRANCH=my-custom-branch\n")
            else:
                customized.append(line)
        self._write_global_config("".join(customized))
        rc, out, err = self._run_doctor()
        section = out.split("global config drift:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("no drift", section, msg=out)
        self.assertNotIn("my-custom-branch", out, msg=out)


if __name__ == "__main__":
    unittest.main()
