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

HAZARD (PEACHES PR #193 review, finding 1 -- class re-audit): `cmd_doctor`
itself never runs a mutating `git` subcommand and every `_doctor_check_*`
helper it calls (including `_doctor_check_config_drift`) is read-only
against $CLAGENTIC_LITE_HOME. There IS one conditional write path inside
`cmd_doctor` -- an auto-restamp of .clagentic/lite/builder-contract.md for
any repo listed in $HOME/.local/state/clagentic/registry -- but it is keyed
off $HOME's registry, not $CLAGENTIC_LITE_HOME directly, and every test
below uses a fresh tempdir HOME with no registry file, so that path can
never fire here. Even so, CLAGENTIC_LITE_HOME below points at a throwaway
`git clone` of the real checkout (never the live tree itself), matching
test_update_nontty_discard_guard.py's `_clone_tool_home` helper exactly --
the stronger, doubt-free guarantee, rather than relying on the doctor-is-
read-only argument alone.

Run with: python3 -m unittest scripts.test_doctor_config_drift -v
"""
import os
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


class _DoctorConfigDriftTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-doctor-config-drift-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.config_dir = os.path.join(self.home, ".config", "clagentic")
        os.makedirs(self.config_dir)
        self.config_path = os.path.join(self.config_dir, "config")
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)

    def _write_global_config(self, body):
        with open(self.config_path, "w") as f:
            f.write(body)

    def _run_doctor(self):
        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = self.fake_tool_home
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        # 60s, not 30 (test_doctor_gitleaks_config_advisory.py's own default):
        # `doctor` runs several real subprocess probes (LLM CLI version/auth
        # checks, `claude plugin list`, etc) whose wall-clock cost varies
        # under load -- observed to occasionally exceed 30s specifically
        # under a full concurrent test-suite run, not in isolation. This is
        # resource contention, not a defect in the drift check itself.
        proc = subprocess.run(
            [os.path.join(self.fake_tool_home, "bin", "clagentic-lite"), "doctor"],
            cwd=self.tmpdir, env=env,
            capture_output=True, text=True, timeout=60,
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

    def test_schema_version_key_excluded_from_drift_output(self):
        """PEACHES PR #193 review, finding 3: CLAGENTIC_CONFIG_SCHEMA_VERSION
        is auto-managed bookkeeping (config.example itself says "Do not
        hand-edit" for it) -- it must never appear in the drift list telling
        an operator which keys to "review and add any you want", even when
        a sparse config is genuinely missing it. Reporting it there directly
        contradicted the template's own "do not hand-edit" instruction."""
        self._write_global_config(
            "CLAGENTIC_LITE_HOME=/fake/home\n"
            "CLAGENTIC_BUILDER_CMD=claude\n"
        )
        rc, out, err = self._run_doctor()
        section = out.split("global config drift:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("WARN", section, msg=out)
        self.assertNotIn("CLAGENTIC_CONFIG_SCHEMA_VERSION", section, msg=out)

    def test_missing_count_is_reported(self):
        self._write_global_config("CLAGENTIC_LITE_HOME=/fake/home\n")
        rc, out, err = self._run_doctor()
        self.assertIn("key(s) present in share/config.example", out, msg=out)

    def test_names_the_refresh_config_remedy_not_the_stale_protocol_citation(self):
        """lr-25e73e item 5: the WARN used to cite AGENTS.md "Template
        version-bump protocol" as the reason `update` does not add missing
        keys automatically -- that section governs the four version-constant
        template artifacts and does not actually cover share/config.example
        (task thread comment #2). Now that a remedy command exists
        (`update --refresh-config`), doctor must name it instead."""
        self._write_global_config("CLAGENTIC_LITE_HOME=/fake/home\n")
        rc, out, err = self._run_doctor()
        self.assertIn("update --refresh-config", out, msg=out)
        self.assertNotIn("Template version-bump protocol", out, msg=out)


class TestNoDriftWhenAllKeysPresent(_DoctorConfigDriftTestBase):
    def test_full_config_example_copy_reports_no_drift(self):
        """A config that is a verbatim copy of config.example (the shape
        `clagentic-lite init` itself produces) must report clean -- no
        false positive on an install that is genuinely current, and no
        false positive on config.example's own commented-out keys, since
        both the installed file and the source template carry the same
        commented lines here."""
        example_path = os.path.join(self.fake_tool_home, "share", "config.example")
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
        example_path = os.path.join(self.fake_tool_home, "share", "config.example")
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
