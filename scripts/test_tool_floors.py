"""
External security-tool version floors and enrolled-repo remote checks, shared
by `clagentic-lite doctor` and `clagentic-lite update`.

Covers: the single floor table (scripts/tool-floors.sh) drives both commands;
below-floor, missing and unparseable tools warn and are never reported OK;
an upgrade is attempted only for a detected, unprivileged install method and
never through sudo; update's exit status is unaffected; the one version
comparison (ds_version_ge) works with and without `sort -V`; and the remote
check reports an authentication failure by name, distinct from a timeout,
under the git environment gates.sh uses.

HAZARD: every update run points CLAGENTIC_LITE_HOME at a throwaway clone
(scripts/test_support.py), never at this checkout. Doctor runs read-only
against this checkout, as the other doctor tests do. Scanners, brew, pipx and
sudo are stubs on PATH; nothing here touches a real package manager or the
developer's own credentials.

Run with: python3 -m unittest scripts.test_tool_floors -v
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest

from scripts.test_gates_git_env_remote_auth import (
    _AUTH_PASS, _AUTH_USER, _HAVE_TIMEOUT, _HangingServer, _ScratchBase,
    _Server,
)
from scripts.test_support import clone_this_tool_home_with_overlay

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")
FLOORS_SH = os.path.join(TOOL_HOME, "scripts", "tool-floors.sh")


def _write_exec(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(body))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP
             | stat.S_IROTH | stat.S_IXOTH)
    return path


def _version_script(version):
    return f"""\
        #!/bin/sh
        case "$1" in
          version|--version) printf '%s\\n' "{version}"; exit 0 ;;
        esac
        exit 1
    """


def _sh(script, env=None):
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                          env=env or dict(os.environ), timeout=60)


class TestVersionCompare(unittest.TestCase):
    def _ge(self, inst, minimum, env=None):
        r = _sh(f". '{PLATFORM_SH}'\nds_version_ge '{inst}' '{minimum}'", env)
        return r.returncode == 0

    def test_ordering(self):
        self.assertTrue(self._ge("8.19.0", "8.19.0"))
        self.assertTrue(self._ge("8.30.1", "8.25.0"))
        self.assertTrue(self._ge("9.0.0", "8.25.0"))
        self.assertFalse(self._ge("8.18.4", "8.19.0"))
        self.assertFalse(self._ge("8.9.0", "8.19.0"))
        self.assertTrue(self._ge("8.100.0", "8.19.0"))

    def test_empty_or_garbage_never_passes_a_floor(self):
        self.assertFalse(self._ge("", "8.19.0"))
        self.assertFalse(self._ge("unknown", "8.19.0"))

    def test_same_answers_without_sort_v(self):
        tmp = tempfile.mkdtemp(prefix="clagentic-test-nosortv-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        real_sort = shutil.which("sort")
        _write_exec(os.path.join(tmp, "sort"), f"""\
            #!/bin/sh
            for a in "$@"; do [ "$a" = "-V" ] && exit 2; done
            exec {real_sort} "$@"
        """)
        env = dict(os.environ)
        env["PATH"] = tmp + os.pathsep + env["PATH"]
        probe = _sh("sort -V /dev/null", env)
        self.assertNotEqual(probe.returncode, 0)
        for inst, minimum, want in (
            ("8.19.0", "8.19.0", True), ("8.30.1", "8.25.0", True),
            ("8.18.4", "8.19.0", False), ("8.9.0", "8.19.0", False),
            ("8.100.0", "8.19.0", True), ("", "8.19.0", False),
        ):
            self.assertEqual(self._ge(inst, minimum, env), want,
                             msg=f"{inst} >= {minimum}")

    def test_extract_takes_the_first_triple(self):
        r = _sh(f". '{PLATFORM_SH}'\n"
                "ds_version_extract 'osv-scanner version: 2.0.3 build 1.2.3'")
        self.assertEqual(r.stdout, "2.0.3")
        r = _sh(f". '{PLATFORM_SH}'\nds_version_extract '8.16.0-1ubuntu0.24.04.3'")
        self.assertEqual(r.stdout, "8.16.0")
        r = _sh(f". '{PLATFORM_SH}'\nds_version_extract 'no digits here'")
        self.assertEqual(r.stdout, "")


class TestFloorTableSweep(unittest.TestCase):
    """Discovery is git-ls-files driven, never a hardcoded list."""

    def _tracked(self):
        out = subprocess.run(["git", "-C", TOOL_HOME, "ls-files", "-z"],
                             check=True, capture_output=True).stdout
        return [p.decode() for p in out.split(b"\0") if p]

    def test_every_security_tool_has_a_table_row(self):
        with open(CLI) as f:
            m = re.search(r'^CLAGENTIC_SECURITY_TOOLS="([^"]+)"', f.read(), re.M)
        self.assertIsNotNone(m)
        for tool in m.group(1).split():
            r = _sh(f". '{PLATFORM_SH}'\n. '{FLOORS_SH}'\n"
                    f"printf '%s\\n' \"$DS_TOOL_FLOOR_TABLE\" | grep -c '^{tool}|'")
            self.assertGreaterEqual(int(r.stdout.strip() or 0), 1,
                                    msg=f"{tool} has no row in DS_TOOL_FLOOR_TABLE")

    def test_every_row_is_well_formed_and_none_has_a_reason(self):
        r = _sh(f". '{PLATFORM_SH}'\n. '{FLOORS_SH}'\nprintf '%s\\n' \"$DS_TOOL_FLOOR_TABLE\"")
        for line in r.stdout.splitlines():
            fields = line.split("|")
            self.assertEqual(len(fields), 5, msg=line)
            self.assertTrue(re.fullmatch(r"\d+\.\d+\.\d+|none", fields[2]), msg=line)
            self.assertTrue(fields[3] and fields[4], msg=line)

    def test_no_second_copy_of_the_comparison_or_the_floors(self):
        offenders = []
        for rel in self._tracked():
            if not (rel == "bin/clagentic-lite" or
                    (rel.startswith("scripts/") and rel.endswith(".sh"))):
                continue
            if rel in ("scripts/platform.sh", "scripts/tool-floors.sh"):
                continue
            with open(os.path.join(TOOL_HOME, rel)) as f:
                for n, line in enumerate(f, 1):
                    code = line.strip()
                    if code.startswith("#"):
                        continue
                    if "sort -V" in code or re.search(r"GITLEAKS_\w*MIN_VERSION", code):
                        offenders.append(f"{rel}:{n}: {code}")
        self.assertEqual(offenders, [])


class _ToolHome(unittest.TestCase):
    """Per-test scratch HOME, stub directory and recorded command log."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-floors-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.stubs = os.path.join(self.tmp, "stubs")
        self.log = os.path.join(self.tmp, "calls.log")
        open(self.log, "w").close()
        _write_exec(os.path.join(self.stubs, "sudo"),
                    f'#!/bin/sh\necho "sudo $*" >> "{self.log}"\nexit 1\n')

    def _calls(self):
        with open(self.log) as f:
            return f.read()

    def _env(self, tool_home, path_dirs, extra=None):
        env = dict(os.environ)
        for k in [k for k in env if k.startswith("GIT_")]:
            del env[k]
        env["HOME"] = self.home
        env["CLAGENTIC_LITE_HOME"] = tool_home
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        env["CLAGENTIC_UPDATE_ALLOW_DISCARD"] = "1"
        env["PATH"] = os.pathsep.join(path_dirs + [self.stubs]) + os.pathsep + env["PATH"]
        env.pop("CLAGENTIC_HOME", None)
        env.pop("CLAGENTIC_ROUTER_URL", None)
        if extra:
            env.update(extra)
        return env

    def _run(self, tool_home, argv, path_dirs, extra=None, timeout=180):
        return subprocess.run(
            [os.path.join(tool_home, "bin", "clagentic-lite")] + argv,
            cwd=tool_home, env=self._env(tool_home, path_dirs, extra),
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL)

    def _clone(self):
        dest = os.path.join(self.tmp, "tool-home")
        clone_this_tool_home_with_overlay(dest)
        return dest


class TestDoctorUsesTheFloorTable(_ToolHome):
    def _doctor(self, path_dirs):
        r = self._run(TOOL_HOME, ["doctor"], path_dirs, timeout=60)
        return r.stdout + r.stderr

    def _plain(self, name, version):
        d = os.path.join(self.tmp, "plain-" + name)
        _write_exec(os.path.join(d, name), _version_script(version))
        return d

    def test_below_floor_warns_with_loss_and_upgrade_line(self):
        out = self._doctor([self._plain("gitleaks", "8.16.0")])
        self.assertIn("WARN gitleaks 8.16.0 < 8.19.0", out)
        self.assertIn("Upgrade gitleaks:", out)

    def test_floorless_tool_reports_version_and_reason_not_ok(self):
        out = self._doctor([self._plain("semgrep", "1.85.0")])
        self.assertIn("INFO semgrep 1.85.0: no floor recorded", out)
        self.assertNotIn("OK   semgrep 1.85.0 (>=", out)

    def test_unparseable_version_is_never_ok(self):
        out = self._doctor([self._plain("gitleaks", "development build")])
        self.assertIn("INFO gitleaks: on PATH but version unparseable", out)
        self.assertIn("Cannot confirm", out)
        self.assertNotIn("OK   gitleaks", out)

    def test_both_floors_met_reports_ok_for_each(self):
        out = self._doctor([self._plain("gitleaks", "8.30.1")])
        self.assertIn("OK   gitleaks 8.30.1 (>= 8.19.0", out)
        self.assertIn("OK   gitleaks 8.30.1 (>= 8.25.0", out)


class TestUpdateFloors(_ToolHome):
    def _brew_layout(self, version="8.16.0", brew_body=None, tool="gitleaks"):
        prefix = os.path.join(self.tmp, "brewroot")
        real = os.path.join(prefix, "Cellar", tool, version, "bin", tool)
        _write_exec(real, _version_script(version))
        os.makedirs(os.path.join(prefix, "bin"), exist_ok=True)
        os.symlink(os.path.join("..", "Cellar", tool, version, "bin", tool),
                   os.path.join(prefix, "bin", tool))
        if brew_body is None:
            brew_body = f"""\
                case "$1" in
                  --prefix) printf '%s\\n' "{prefix}" ;;
                  upgrade)
                    echo "brew $*" >> "{self.log}"
                    cat > "{real}" <<'STUB'
#!/bin/sh
case "$1" in version|--version) echo 8.30.1 ;; esac
STUB
                    ;;
                esac
                exit 0
            """
        _write_exec(os.path.join(prefix, "bin", "brew"), "#!/bin/sh\n" + textwrap.dedent(brew_body))
        return prefix

    def _update(self, path_dirs, extra=None):
        r = self._run(self._clone(), ["update"], path_dirs, extra)
        return r.returncode, r.stdout, r.stderr

    def test_brew_install_is_upgraded_and_rechecked(self):
        prefix = self._brew_layout()
        rc, out, err = self._update([os.path.join(prefix, "bin")])
        self.assertIn("brew upgrade gitleaks", self._calls())
        self.assertIn("gitleaks now meets its version floors", out, msg=out + err)
        self.assertNotIn("gitleaks 8.16.0 is below", err)
        self.assertNotIn("sudo", self._calls())

    def test_failed_upgrade_warns_with_the_manual_command(self):
        prefix = self._brew_layout(brew_body=f"""\
            case "$1" in
              --prefix) printf '%s\\n' "{os.path.join(self.tmp, 'brewroot')}" ;;
              upgrade) echo "brew $*" >> "{self.log}"; exit 1 ;;
            esac
            exit 0
        """)
        rc, out, err = self._update([os.path.join(prefix, "bin")])
        self.assertIn("gitleaks 8.16.0 is below the required 8.19.0", err)
        self.assertIn("the automatic upgrade attempt failed", err)
        self.assertIn("Upgrade: brew upgrade gitleaks", err)

    def test_upgrade_that_does_not_reach_the_floor_still_warns(self):
        prefix = self._brew_layout(brew_body=f"""\
            case "$1" in
              --prefix) printf '%s\\n' "{os.path.join(self.tmp, 'brewroot')}" ;;
              upgrade) echo "brew $*" >> "{self.log}" ;;
            esac
            exit 0
        """)
        rc, out, err = self._update([os.path.join(prefix, "bin")])
        self.assertIn("brew upgrade gitleaks", self._calls())
        self.assertIn("still below the floor", err)

    def test_update_exit_status_is_unaffected_by_warnings(self):
        ok_dir = os.path.join(self.tmp, "ok")
        _write_exec(os.path.join(ok_dir, "gitleaks"), _version_script("8.30.1"))
        rc_ok, _, _ = self._update([ok_dir])
        old_dir = os.path.join(self.tmp, "old")
        _write_exec(os.path.join(old_dir, "gitleaks"), _version_script("8.16.0"))
        rc_old, _, err = self._update([old_dir])
        self.assertIn("is below the required", err)
        self.assertEqual(rc_old, rc_ok)

    def test_undetected_install_method_is_never_upgraded(self):
        prefix = self._brew_layout()
        # A distro-style binary outside brew's prefix, with brew also present.
        plain = os.path.join(self.tmp, "usrbin")
        _write_exec(os.path.join(plain, "gitleaks"), _version_script("8.16.0"))
        rc, out, err = self._update([plain, os.path.join(prefix, "bin")])
        self.assertNotIn("upgrade", self._calls())
        self.assertIn("install method not detected", err)
        self.assertNotIn("sudo", self._calls())

    @unittest.skipIf(os.geteuid() == 0, "root can write any prefix")
    def test_unwritable_brew_prefix_is_never_upgraded(self):
        prefix = self._brew_layout()
        os.chmod(prefix, 0o555)
        self.addCleanup(os.chmod, prefix, 0o755)
        rc, out, err = self._update([os.path.join(prefix, "bin")])
        self.assertNotIn("upgrade", self._calls())
        self.assertIn("install method not detected", err)

    def test_pipx_venv_install_is_upgraded(self):
        real = os.path.join(self.tmp, "pipx", "venvs", "gitleaks", "bin", "gitleaks")
        _write_exec(real, _version_script("8.16.0"))
        shim_dir = os.path.join(self.tmp, "localbin")
        os.makedirs(shim_dir)
        os.symlink(real, os.path.join(shim_dir, "gitleaks"))
        _write_exec(os.path.join(shim_dir, "pipx"), (
            "#!/bin/sh\n"
            f'echo "pipx $*" >> "{self.log}"\n'
            f'printf \'#!/bin/sh\\ncase "$1" in version|--version) echo 8.30.1 ;; esac\\n\' > "{real}"\n'
            "exit 0\n"))
        rc, out, err = self._update([shim_dir])
        self.assertIn("pipx upgrade gitleaks", self._calls())
        self.assertIn("gitleaks now meets its version floors", out, msg=out + err)
        self.assertNotIn("sudo", self._calls())

    def test_a_tool_with_no_recorded_floor_is_never_upgraded(self):
        real = os.path.join(self.tmp, "pipx", "venvs", "semgrep", "bin", "semgrep")
        _write_exec(real, _version_script("0.1.0"))
        shim_dir = os.path.join(self.tmp, "localbin")
        os.makedirs(shim_dir)
        os.symlink(real, os.path.join(shim_dir, "semgrep"))
        _write_exec(os.path.join(shim_dir, "pipx"),
                    f'#!/bin/sh\necho "pipx $*" >> "{self.log}"\nexit 0\n')
        self._update([shim_dir])
        self.assertNotIn("pipx upgrade semgrep", self._calls())

    def test_missing_tool_is_reported_and_never_installed(self):
        bare = os.path.join(self.tmp, "bare")
        _write_exec(os.path.join(bare, "brew"),
                    f'#!/bin/sh\necho "brew $*" >> "{self.log}"\nexit 0\n')
        _write_exec(os.path.join(bare, "pipx"),
                    f'#!/bin/sh\necho "pipx $*" >> "{self.log}"\nexit 0\n')
        real_path = os.environ["PATH"]
        gl = shutil.which("gitleaks", path=real_path)
        if gl:
            self.skipTest("a real gitleaks is on PATH; cannot prove 'missing'")
        rc, out, err = self._update([bare])
        self.assertIn("gitleaks is not installed", err)
        self.assertNotIn("install", self._calls())

    def test_unparseable_version_warns_and_is_not_upgraded(self):
        prefix = self._brew_layout()
        real = os.path.join(prefix, "Cellar", "gitleaks", "8.16.0", "bin", "gitleaks")
        _write_exec(real, "#!/bin/sh\necho 'custom build'\n")
        rc, out, err = self._update([os.path.join(prefix, "bin")])
        self.assertIn("gitleaks is installed but its version could not be read", err)
        self.assertNotIn("upgrade", self._calls())


class _RemoteBase(_ScratchBase, _ToolHome):
    """Scratch origin repo plus a registry entry pointing at its work clone."""

    def setUp(self):
        _ScratchBase.setUp(self)
        # _ScratchBase owns self.tmp/self.home/self.env; add the stub state
        # _ToolHome would have created.
        self.stubs = os.path.join(self.tmp, "stubs")
        self.log = os.path.join(self.tmp, "calls.log")
        open(self.log, "w").close()
        self._register(self.work)

    def _register(self, path):
        reg = os.path.join(self.home, ".local", "state", "clagentic", "registry")
        os.makedirs(os.path.dirname(reg), exist_ok=True)
        with open(reg, "w") as f:
            f.write(path + "\n")

    def _doctor_out(self, extra=None):
        env = dict(self.env)
        env.update({"CLAGENTIC_LITE_HOME": TOOL_HOME,
                    "CLAGENTIC_SKIP_UPDATE_ALERT": "1"})
        if extra:
            env.update(extra)
        r = subprocess.run([CLI, "doctor"], cwd=self.work, env=env,
                           capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr


class TestDoctorRemoteCheck(_RemoteBase):
    def test_reachable_origin_is_ok(self):
        server = self._start(_Server(self.tmp, require_auth=False))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out()
        self.assertIn("origin reachable", out)

    def test_auth_failure_is_named_with_gits_error_and_helpers(self):
        self._write_global_config([("credential.helper", "store")])
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out()
        self.assertIn("origin authentication FAILED", out)
        self.assertRegex(out, r"(?i)fatal:.*(authentication|username|credentials)")
        self.assertIn("credential.helper git would consult: store", out)
        self.assertNotIn("timed out", out)

    def test_auth_failure_with_no_helper_says_none_configured(self):
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out()
        self.assertIn("origin authentication FAILED", out)
        self.assertIn("credential.helper git would consult: none configured", out)

    def test_inline_helper_script_and_its_secret_are_never_echoed(self):
        self._write_global_config([(
            "credential.helper",
            "!f() { echo username=nobody; echo password=wrong-pw-s3cret; }; f")])
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out()
        self.assertIn("origin authentication FAILED", out)
        self.assertNotIn("wrong-pw-s3cret", out)
        self.assertIn("credential.helper git would consult: !f()", out)

    def test_configured_helper_authenticates(self):
        self._write_global_config([(
            "credential.helper",
            f"!f() {{ echo username={_AUTH_USER}; echo password={_AUTH_PASS}; }}; f")])
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out()
        self.assertIn("origin reachable", out)
        self.assertNotIn("authentication FAILED", out)

    def test_url_credentials_are_masked(self):
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://user:url-s3cret@127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out()
        self.assertNotIn("url-s3cret", out)

    @unittest.skipUnless(_HAVE_TIMEOUT, "no timeout/gtimeout binary")
    def test_timeout_is_reported_as_network_not_auth(self):
        server = self._start(_HangingServer())
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out({"CLAGENTIC_REMOTE_CHECK_TIMEOUT_SEC": "2"})
        self.assertIn("origin unreachable (network, not authentication)", out)
        self.assertIn("timed out after 2s", out)
        self.assertNotIn("authentication FAILED", out)

    def test_inherited_git_dir_does_not_redirect_the_check(self):
        server = self._start(_Server(self.tmp, require_auth=False))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        other = os.path.join(self.tmp, "other")
        subprocess.run(["git", "init", "-q", "-b", "main", other], check=True,
                       env=self.env, capture_output=True)
        out = self._doctor_out({"GIT_DIR": os.path.join(other, ".git")})
        self.assertIn(f"{self.work}: origin reachable", out)

    def test_no_origin_is_skipped_not_failed(self):
        subprocess.run(["git", "-C", self.work, "remote", "remove", "origin"],
                       check=True, env=self.env, capture_output=True)
        out = self._doctor_out()
        self.assertIn("remote check skipped", out)
        self.assertNotIn("authentication FAILED", out)

    def test_a_subdirectory_of_a_repo_is_not_checked_as_that_repo(self):
        sub = os.path.join(self.work, "sub")
        os.makedirs(sub)
        self._register(sub)
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        out = self._doctor_out()
        self.assertIn("remote check skipped (not the root of a git repo)", out)
        self.assertNotIn("authentication FAILED", out)


class TestUpdateRemoteCheck(_RemoteBase):
    def _update(self):
        tool_home = os.path.join(self.tmp, "tool-home")
        clone_this_tool_home_with_overlay(tool_home)
        env = dict(self.env)
        env.update({"CLAGENTIC_LITE_HOME": tool_home,
                    "CLAGENTIC_SKIP_UPDATE_ALERT": "1",
                    "CLAGENTIC_UPDATE_ALLOW_DISCARD": "1"})
        r = subprocess.run([os.path.join(tool_home, "bin", "clagentic-lite"), "update"],
                           cwd=tool_home, env=env, capture_output=True, text=True,
                           timeout=180, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr

    def test_update_reports_auth_failure_and_keeps_its_exit_status(self):
        good = self._start(_Server(self.tmp, require_auth=False))
        self._set_origin(f"http://127.0.0.1:{good.port}/remote.git")
        rc_ok, out_ok = self._update()
        self.assertNotIn("authentication FAILED", out_ok)
        shutil.rmtree(os.path.join(self.tmp, "tool-home"))

        bad = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{bad.port}/remote.git")
        rc_bad, out_bad = self._update()
        self.assertIn("origin authentication FAILED", out_bad)
        self.assertIn("credential.helper git would consult: none configured", out_bad)
        self.assertEqual(rc_bad, rc_ok)


if __name__ == "__main__":
    unittest.main()
