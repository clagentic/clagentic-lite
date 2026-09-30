"""
cmd_deps must scan REPO_ROOT, not whatever directory gates.sh was started in.

osv-scanner was given "." (and CLAGENTIC_OSV_EXCLUDE paths) which resolve
against the process CWD. In a wrapper/.clagentic-project layout, or when a hook
runs from a subdirectory, that scanned the wrong tree and reported a clean
pass. Every osv-scanner invocation, including the legacy flat one, now runs in
a subshell that cds to REPO_ROOT first.

A stub osv-scanner records its working directory, so the test observes where
the scan really ran rather than inferring it from output.

Run with: python3 -m unittest scripts.test_deps_scan_cwd -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH  # noqa: E402

_STUB_V2 = """#!/bin/sh
case "$1" in
  --version) echo "osv-scanner version: 2.0.0"; exit 0 ;;
esac
pwd -P > "$OSV_STUB_CWD_FILE"
echo '{"results":[]}'
exit 0
"""

# A release that predates the scan subcommand: no parseable version and
# `scan --help` prints no USAGE block, so cmd_deps takes the legacy branch.
_STUB_LEGACY = """#!/bin/sh
case "$1" in
  --version) echo "legacy"; exit 0 ;;
  scan) exit 1 ;;
esac
pwd -P > "$OSV_STUB_CWD_FILE"
exit 0
"""


class TestDepsScanIsCwdIndependent(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-deps-cwd-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        self.repo = os.path.join(self.tmp, "repo")
        self.elsewhere = os.path.join(self.tmp, "elsewhere")
        self.bin = os.path.join(self.tmp, "bin")
        self.cwd_file = os.path.join(self.tmp, "osv-cwd")
        for d in (self.home, self.elsewhere, self.bin):
            os.makedirs(d)
        env = self._env()
        subprocess.run(["git", "init", "-q", "-b", "main", self.repo],
                       check=True, env=env)

    def _env(self):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("GIT_") and not k.startswith("CLAGENTIC_")}
        env["HOME"] = self.home
        env["PATH"] = self.bin + os.pathsep + env.get("PATH", "")
        env["CLAGENTIC_PROJECT_ROOT"] = self.repo
        env["OSV_STUB_CWD_FILE"] = self.cwd_file
        return env

    def _install_stub(self, body):
        path = os.path.join(self.bin, "osv-scanner")
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)

    def _run_deps_from_elsewhere(self):
        return subprocess.run(
            ["sh", GATES_SH, "deps"], env=self._env(), cwd=self.elsewhere,
            capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL,
        )

    def _scan_cwd(self):
        with open(self.cwd_file) as f:
            return f.read().strip()

    def test_scan_subcommand_runs_in_repo_root(self):
        self._install_stub(_STUB_V2)
        r = self._run_deps_from_elsewhere()
        self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
        self.assertEqual(self._scan_cwd(), os.path.realpath(self.repo))

    def test_legacy_flat_invocation_runs_in_repo_root(self):
        self._install_stub(_STUB_LEGACY)
        r = self._run_deps_from_elsewhere()
        self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
        self.assertEqual(self._scan_cwd(), os.path.realpath(self.repo))


if __name__ == "__main__":
    unittest.main()
