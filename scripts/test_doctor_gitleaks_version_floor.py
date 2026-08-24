"""
Regression tests for lr-170808 scope item 4: `clagentic-lite doctor` reports
the installed gitleaks version and warns below the 8.18 floor that
feature-branch history scanning (cmd_secrets, scripts/gates.sh) is
unavailable -- a standing coverage gap, not a per-run surprise. Also warns
below 8.25 (the [[allowlists]]/condition="AND" floor .gitleaks.toml's own
header comment already documents).

Uses a fake `gitleaks` binary on PATH ahead of any real one so the version
comparison is exercised deterministically for both the below-floor and
at-or-above-floor cases, mirroring test_doctor_router_blind_checks.py's own
subprocess-invocation pattern against the real `clagentic-lite doctor` CLI.

Run with: python3 -m unittest scripts.test_doctor_gitleaks_version_floor -v
"""
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


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


def _write_fake_gitleaks(bin_dir, version_output):
    os.makedirs(bin_dir, exist_ok=True)
    path = os.path.join(bin_dir, "gitleaks")
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "version" ]; then
              printf '%s\\n' "{version_output}"
              exit 0
            fi
            exit 1
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _run_doctor(cwd, home, fake_bin_dir=None, env_extra=None):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
    env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
    env.pop("CLAGENTIC_HOME", None)
    env.pop("CLAGENTIC_ROUTER_URL", None)
    if fake_bin_dir:
        env["PATH"] = fake_bin_dir + os.pathsep + env.get("PATH", "")
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [CLI, "doctor"], cwd=cwd, env=env,
        capture_output=True, text=True, timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class _DoctorGitleaksTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-doctor-gitleaks-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)
        self.fake_bin = os.path.join(self.tmpdir, "fakebin")


class TestBelowHistoryFloorWarns(_DoctorGitleaksTestBase):
    def test_ubuntu_2404_apt_version_warns_history_scan_unavailable(self):
        """The exact reported environment: 8.16.0-1ubuntu0.24.04.3, below
        the 8.18 history-scan floor."""
        _write_fake_gitleaks(self.fake_bin, "8.16.0-1ubuntu0.24.04.3")
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, fake_bin_dir=self.fake_bin)
        self.assertIn("WARN gitleaks 8.16.0 < 8.18.0", out, msg=out)
        self.assertIn("feature-branch history scanning is UNAVAILABLE", out, msg=out)

    def test_below_allowlist_floor_also_warns(self):
        _write_fake_gitleaks(self.fake_bin, "8.16.0")
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, fake_bin_dir=self.fake_bin)
        self.assertIn("< 8.25.0", out, msg=out)
        self.assertIn("misread by older gitleaks", out, msg=out)


class TestAtOrAboveFloorReportsOk(_DoctorGitleaksTestBase):
    def test_8_18_0_ok_for_history_but_warns_allowlist(self):
        _write_fake_gitleaks(self.fake_bin, "8.18.0")
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, fake_bin_dir=self.fake_bin)
        self.assertIn("OK   gitleaks 8.18.0 (>= 8.18.0", out, msg=out)
        self.assertIn("< 8.25.0", out, msg=out)

    def test_8_30_1_ok_for_both_floors(self):
        _write_fake_gitleaks(self.fake_bin, "8.30.1")
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, fake_bin_dir=self.fake_bin)
        self.assertIn("OK   gitleaks 8.30.1 (>= 8.18.0", out, msg=out)
        self.assertNotIn("misread by older gitleaks", out, msg=out)


class TestGitleaksNotOnPath(_DoctorGitleaksTestBase):
    def test_missing_gitleaks_reports_info_not_a_hard_fail(self):
        """Build a PATH with every real-PATH executable symlinked EXCEPT
        gitleaks, so `command -v gitleaks` genuinely fails inside the
        subprocess without also breaking git/sqlite3/python3/etc doctor
        needs. Mirrors test_build_gate_summary_deterministic_gates.py's
        _jqless_path() helper."""
        no_gitleaks_bin = os.path.join(self.tmpdir, "no-gitleaks-bin")
        os.makedirs(no_gitleaks_bin)
        real_path = os.environ.get("PATH", "")
        for d in real_path.split(os.pathsep):
            if not d or not os.path.isdir(d):
                continue
            for name in os.listdir(d):
                if name == "gitleaks":
                    continue
                link = os.path.join(no_gitleaks_bin, name)
                if os.path.exists(link):
                    continue
                try:
                    os.symlink(os.path.join(d, name), link)
                except OSError:
                    continue

        env = dict(os.environ)
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        env["PATH"] = no_gitleaks_bin
        proc = subprocess.run(
            [CLI, "doctor"], cwd=self.repo, env=env,
            capture_output=True, text=True, timeout=30,
        )
        self.assertIn("INFO gitleaks: not on PATH", proc.stdout, msg=proc.stdout)


if __name__ == "__main__":
    unittest.main()
