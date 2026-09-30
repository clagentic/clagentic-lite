"""
gates.sh must not break the user's own git configuration.

Two defects, one class: how gates.sh runs external commands on a deployed
user's host.

1. A process-wide scrub of git's environment used to set
   GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_NOSYSTEM=1 for every later git
   call. That wipes credential.helper, url.*.insteadOf, http.* and
   core.sshCommand, so every fetch, ls-remote and push against a private
   remote failed authentication. The scrub is now split: the process-wide one
   clears only repo-redirecting variables; the config wipe is confined to the
   secrets canary's scratch repo.

2. `gates ship` handed the `_git` shell function to run_bounded, which execs a
   program, so the push never ran and a fully green ship was logged as a push
   failure.

Everything here runs against scratch repos and a throwaway HOME. Nothing
depends on the developer's own credentials, remotes, or installed helpers.

Run with: python3 -m unittest scripts.test_gates_git_env_remote_auth -v
"""
import base64
import functools
import http.server
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

_HAVE_TIMEOUT = bool(shutil.which("timeout") or shutil.which("gtimeout"))
_AUTH_USER = "gate-test-user"
_AUTH_PASS = "gate-test-pass"


def _clean_git_env(home):
    """A minimal environment with an isolated HOME and no inherited git
    variables, so the user's real configuration can never leak in."""
    env = {
        k: v for k, v in os.environ.items()
        if not k.startswith("GIT_") and not k.startswith("CLAGENTIC_")
    }
    env["HOME"] = home
    env["XDG_CONFIG_HOME"] = os.path.join(home, ".config")
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def _git(args, cwd=None, env=None, check=True):
    return subprocess.run(
        ["git"] + args, cwd=cwd, env=env, check=check,
        capture_output=True, text=True,
    )


class _DumbGitHandler(http.server.SimpleHTTPRequestHandler):
    """Serves a bare repo over git's dumb HTTP protocol, optionally demanding
    Basic auth. Dumb HTTP is enough for fetch and ls-remote."""

    require_auth = False

    def do_GET(self):
        if self.require_auth:
            want = "Basic " + base64.b64encode(
                f"{_AUTH_USER}:{_AUTH_PASS}".encode()).decode()
            if self.headers.get("Authorization") != want:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="gate-test"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        super().do_GET()

    def log_message(self, *args):
        pass


class _Server:
    def __init__(self, directory, require_auth):
        handler = type("H", (_DumbGitHandler,), {"require_auth": require_auth})
        self.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            functools.partial(handler, directory=directory),
        )
        self.port = self.httpd.server_address[1]
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class _HangingServer:
    """Accepts connections and never answers: a remote that stalls."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._conns = []
        self._stop = False
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
                self._conns.append(conn)
            except (socket.timeout, OSError):
                continue

    def stop(self):
        self._stop = True
        for c in self._conns:
            c.close()
        self.sock.close()


class _ScratchBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-gitenv-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.env = _clean_git_env(self.home)
        self._write_global_config()

        self.bare = os.path.join(self.tmp, "remote.git")
        self.work = os.path.join(self.tmp, "work")
        seed = os.path.join(self.tmp, "seed")
        _git(["init", "-q", "-b", "main", seed], env=self.env)
        with open(os.path.join(seed, "README"), "w") as f:
            f.write("hello\n")
        _git(["add", "README"], cwd=seed, env=self.env)
        _git(["commit", "-q", "-m", "initial"], cwd=seed, env=self.env)
        _git(["clone", "-q", "--bare", seed, self.bare], env=self.env)
        _git(["clone", "-q", self.bare, self.work], env=self.env)
        _git(["update-server-info"], cwd=self.bare, env=self.env)

    def _write_global_config(self, extra=None):
        cfg = os.path.join(self.home, ".gitconfig")
        _git(["config", "--file", cfg, "user.name", "Gate Test"], env=self.env)
        _git(["config", "--file", cfg, "user.email", "gate@example.invalid"],
             env=self.env)
        for key, value in (extra or []):
            _git(["config", "--file", cfg, "--add", key, value], env=self.env)

    def _set_origin(self, url):
        _git(["remote", "set-url", "origin", url], cwd=self.work, env=self.env)

    def _start(self, server):
        self.addCleanup(server.stop)
        return server

    def _run_sourced(self, body, extra_env=None, timeout=90):
        env = dict(self.env)
        env.update(source_env(gates=True))
        env["CLAGENTIC_PROJECT_ROOT"] = self.work
        if extra_env:
            env.update(extra_env)
        script = f". '{GATES_SH}'\n{body}\n"
        return subprocess.run(
            ["sh", "-c", script, GATES_SH],
            env=env, capture_output=True, text=True, timeout=timeout,
        )

    def _resolve(self, timeout_sec=20, extra_env=None):
        """Call the real freshness helper; report its exit status plus
        everything it printed (tip on stdout, reason on stderr)."""
        body = (
            f'_out=$(_gate_resolve_fresh_default_branch_ref main {timeout_sec} 2>&1)'
            ' && _rc=0 || _rc=$?\n'
            'printf "%s\\n%s\\n" "$_rc" "$_out"\n'
        )
        r = self._run_sourced(body, extra_env=extra_env)
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        rc, _, out = r.stdout.partition("\n")
        return int(rc), out.strip()

    def _head_sha(self, repo, ref="HEAD"):
        return _git(["rev-parse", ref], cwd=repo, env=self.env).stdout.strip()


class TestFreshRefHonoursUserGitConfig(_ScratchBase):

    def test_credential_helper_authenticates_the_fetch(self):
        """A global credential helper must still supply credentials to the
        gate's fetch/ls-remote against an auth-requiring HTTPS-style remote.
        Before the split the scrub pointed GIT_CONFIG_GLOBAL at /dev/null, the
        helper was never consulted, and the fetch failed with 401."""
        self._write_global_config([(
            "credential.helper",
            f"!f() {{ echo username={_AUTH_USER}; echo password={_AUTH_PASS}; }}; f",
        )])
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")

        rc, out = self._resolve()
        self.assertEqual(rc, 0, msg=out)
        self.assertEqual(out, self._head_sha(self.bare, "refs/heads/main"))

    def test_url_insteadof_rewrite_is_honoured(self):
        server = self._start(_Server(self.tmp, require_auth=False))
        self._write_global_config([(
            f"url.http://127.0.0.1:{server.port}/.insteadOf",
            "http://mirror.invalid/",
        )])
        self._set_origin("http://mirror.invalid/remote.git")

        rc, out = self._resolve()
        self.assertEqual(rc, 0, msg=out)
        self.assertEqual(out, self._head_sha(self.bare, "refs/heads/main"))

    def test_inherited_git_dir_still_targets_repo_root(self):
        """The narrow scrub must keep doing its original job: an inherited
        GIT_DIR (as a git hook exports) must not redirect `_git`."""
        other = os.path.join(self.tmp, "other")
        _git(["init", "-q", "-b", "main", other], env=self.env)
        body = '_git rev-parse --show-toplevel\n'
        r = self._run_sourced(
            body, extra_env={"GIT_DIR": os.path.join(other, ".git")})
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertEqual(
            os.path.realpath(r.stdout.strip()), os.path.realpath(self.work))


class TestFetchFailureReason(_ScratchBase):

    def test_failure_reason_carries_gits_own_error(self):
        """A refused connection is a failure, not a timeout, and the reason
        names git's error so the operator can see why."""
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        self._set_origin(f"http://127.0.0.1:{port}/remote.git")

        rc, out = self._resolve()
        self.assertEqual(rc, 1)
        self.assertIn("failed (exit", out)
        self.assertNotIn("timed out", out)
        self.assertRegex(out, r"(?i)(could not connect|unable to access|fatal)")

    def test_reason_is_git_fatal_line_not_its_trailing_hint(self):
        """git ends a multi-line failure on a generic hint ('and the
        repository exists.'); the reason must carry the fatal: line."""
        self._set_origin(os.path.join(self.tmp, "no-such-repo.git"))

        rc, out = self._resolve()
        self.assertEqual(rc, 1)
        self.assertIn("failed (exit", out)
        self.assertIn("fatal:", out)
        self.assertNotIn("and the repository exists", out)

    @unittest.skipUnless(_HAVE_TIMEOUT, "no timeout/gtimeout binary")
    def test_timeout_is_reported_as_a_timeout(self):
        server = self._start(_HangingServer())
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")

        rc, out = self._resolve(timeout_sec=1)
        self.assertEqual(rc, 1)
        self.assertIn("timed out after 1s", out)
        self.assertNotIn("failed (exit", out)

    def test_credentials_in_the_remote_url_are_masked(self):
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        self._set_origin(f"http://user:s3cr3t-token@127.0.0.1:{port}/remote.git")

        rc, out = self._resolve()
        self.assertEqual(rc, 1)
        self.assertNotIn("s3cr3t-token", out)


class TestFailureReasonMasksCredentials(_ScratchBase):
    """_bounded_failure_reason echoes git's own error line, and git can quote
    the remote URL in it."""

    def _reason(self, stderr_text):
        err = os.path.join(self.tmp, "err.txt")
        with open(err, "w") as f:
            f.write(stderr_text)
        r = self._run_sourced(f'_bounded_failure_reason 128 5 "{err}"\n')
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        return r.stdout

    def test_userinfo_is_masked_up_to_the_last_at_sign(self):
        """A password that itself contains '@' must not leak its tail."""
        out = self._reason(
            "fatal: unable to access 'https://bob:p@ss-tail@host.example/r.git/': 401\n")
        self.assertNotIn("ss-tail", out)
        self.assertNotIn("p@ss", out)
        self.assertNotIn("bob", out)
        self.assertIn("https://***@host.example/r.git/", out)

    def test_plain_userinfo_is_masked(self):
        out = self._reason(
            "fatal: unable to access 'https://bob:s3cr3t@host.example/r.git/': 401\n")
        self.assertNotIn("s3cr3t", out)
        self.assertIn("https://***@host.example", out)

    def test_query_string_values_are_masked(self):
        out = self._reason(
            "fatal: unable to access 'https://host.example/r.git/?token=abc123&x=keep1': 401\n")
        self.assertNotIn("abc123", out)
        self.assertNotIn("keep1", out)
        self.assertIn("token=***", out)
        self.assertIn("x=***", out)

    def test_a_url_without_credentials_is_left_readable(self):
        out = self._reason(
            "fatal: unable to access 'https://host.example/r.git/': Could not resolve host\n")
        self.assertIn("https://host.example/r.git/", out)
        self.assertIn("Could not resolve host", out)


class TestGitNeverPromptsForCredentials(_ScratchBase):
    """A missing credential must fail at once with git's own error, not wait
    on a prompt until the timeout fires. The test env deliberately leaves
    GIT_TERMINAL_PROMPT unset so only the gate's own setting can turn the
    prompt off."""

    def setUp(self):
        super().setUp()
        self.env.pop("GIT_TERMINAL_PROMPT", None)
        self.spy_log = os.path.join(self.tmp, "git-spy.log")
        spy_dir = os.path.join(self.tmp, "spy-bin")
        os.makedirs(spy_dir)
        real_git = shutil.which("git")
        spy = os.path.join(spy_dir, "git")
        with open(spy, "w") as f:
            f.write(
                "#!/bin/sh\n"
                f"printf '%s|%s\\n' \"${{GIT_TERMINAL_PROMPT-unset}}\" \"$*\" >> '{self.spy_log}'\n"
                f"exec '{real_git}' \"$@\"\n"
            )
        os.chmod(spy, 0o755)
        self.spy_env = {"PATH": spy_dir + os.pathsep + self.env.get("PATH", "")}

    def _spied(self, verb):
        if not os.path.exists(self.spy_log):
            return []
        with open(self.spy_log) as f:
            return [ln.strip() for ln in f if f" {verb} " in ln]

    def test_fetch_and_ls_remote_run_with_the_prompt_disabled(self):
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")

        rc, out = self._resolve(extra_env=self.spy_env)
        self.assertEqual(rc, 1, msg=out)
        fetches = self._spied("fetch")
        self.assertTrue(fetches, "no git fetch was observed")
        for line in fetches:
            self.assertTrue(line.startswith("0|"), msg=line)

    def test_credential_requiring_remote_fails_fast_with_gits_error(self):
        import time
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")

        started = time.monotonic()
        rc, out = self._resolve(timeout_sec=30, extra_env=self.spy_env)
        self.assertLess(time.monotonic() - started, 20, msg=out)
        self.assertEqual(rc, 1, msg=out)
        self.assertIn("failed (exit", out)
        self.assertNotIn("timed out", out)
        self.assertRegex(out, r"(?i)(authentication failed|could not read|fatal)")


class TestCanaryIgnoresUserHooks(_ScratchBase):

    def _hooks_dir(self):
        hooks = os.path.join(self.tmp, "global-hooks")
        os.makedirs(hooks)
        self.sentinel = os.path.join(self.tmp, "hook-fired")
        hook = os.path.join(hooks, "post-commit")
        with open(hook, "w") as f:
            f.write(f"#!/bin/sh\ntouch '{self.sentinel}'\n")
        os.chmod(hook, 0o755)
        self._write_global_config([("core.hooksPath", hooks)])

    def test_control_global_hook_fires_for_a_normal_commit(self):
        """Proves the fixture is live, so the canary assertion below cannot
        pass vacuously."""
        self._hooks_dir()
        with open(os.path.join(self.work, "f"), "w") as f:
            f.write("x\n")
        _git(["add", "f"], cwd=self.work, env=self.env)
        _git(["commit", "-q", "-m", "x", "--no-verify"], cwd=self.work,
             env=self.env)
        self.assertTrue(os.path.exists(self.sentinel))

    def test_canary_commit_does_not_fire_a_global_hook(self):
        self._hooks_dir()
        r = self._run_sourced('_gitleaks_positive_control "" >/dev/null 2>&1 || true\n')
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        self.assertFalse(
            os.path.exists(self.sentinel),
            "the canary's scratch commit fired the user's global post-commit hook",
        )


class TestShipPush(_ScratchBase):
    """`gates ship` must actually run `git push` (the `_git` shell function
    cannot be exec'd by the timeout wrapper) and report its outcome
    truthfully."""

    def setUp(self):
        super().setUp()
        _git(["checkout", "-q", "-b", "feature"], cwd=self.work, env=self.env)
        with open(os.path.join(self.work, "feature.txt"), "w") as f:
            f.write("feature\n")
        _git(["add", "feature.txt"], cwd=self.work, env=self.env)
        _git(["commit", "-q", "-m", "feature work"], cwd=self.work, env=self.env)

    def _ship(self, extra_env=None, timeout=120):
        env = dict(self.env)
        env.update({
            "CLAGENTIC_PROJECT_ROOT": self.work,
            # No gate is named, so every gate is skipped and logged: the
            # sequence reaches the push without needing any scanner.
            "CLAGENTIC_GATES": "none",
            "CLAGENTIC_REPO_HOST": "none",
        })
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["sh", GATES_SH, "ship"], env=env, cwd=self.work,
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )

    def test_green_ship_lands_the_branch_and_reports_pass(self):
        r = self._ship()
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, msg=out)
        self.assertNotIn("push failed", out)
        self.assertEqual(
            self._head_sha(self.bare, "refs/heads/feature"),
            self._head_sha(self.work),
        )

    def test_rejecting_remote_reports_push_failed_with_gits_error(self):
        hook = os.path.join(self.bare, "hooks", "pre-receive")
        with open(hook, "w") as f:
            f.write("#!/bin/sh\necho rejected-by-test-hook >&2\nexit 1\n")
        os.chmod(hook, 0o755)

        r = self._ship()
        out = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, msg=out)
        self.assertIn("push failed (exit", out)
        self.assertIn("failed to push some refs", out)
        self.assertIn("rejected-by-test-hook", out)
        self.assertNotIn("timed out", out)

    @unittest.skipUnless(_HAVE_TIMEOUT, "no timeout/gtimeout binary")
    def test_hanging_remote_reports_a_timeout(self):
        server = self._start(_HangingServer())
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")

        r = self._ship(extra_env={"CLAGENTIC_SHIP_TIMEOUT_SEC": "2"})
        out = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, msg=out)
        self.assertIn("push timed out after 2s", out)
        self.assertIn("may include pre-push hook time", out)

    @unittest.skipUnless(_HAVE_TIMEOUT, "no timeout/gtimeout binary")
    def test_pre_push_hook_slower_than_the_old_flat_bound_still_succeeds(self):
        """The push runs the enrolled pre-push hook. A hook that takes longer
        than the old 120s default, but well inside the computed bound (deps +
        sast + allowance), must give a successful push, not a false timeout."""
        hook = os.path.join(self.work, ".git", "hooks", "pre-push")
        with open(hook, "w") as f:
            f.write("#!/bin/sh\nsleep 125\nexit 0\n")
        os.chmod(hook, 0o755)

        r = self._ship(timeout=400)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, msg=out)
        self.assertNotIn("timed out", out)
        self.assertEqual(
            self._head_sha(self.bare, "refs/heads/feature"),
            self._head_sha(self.work),
        )

    def test_push_runs_with_the_credential_prompt_disabled(self):
        env_log = os.path.join(self.tmp, "push-env.log")
        spy_dir = os.path.join(self.tmp, "spy-bin")
        os.makedirs(spy_dir)
        real_git = shutil.which("git")
        spy = os.path.join(spy_dir, "git")
        with open(spy, "w") as f:
            f.write(
                "#!/bin/sh\n"
                f"printf '%s|%s\\n' \"${{GIT_TERMINAL_PROMPT-unset}}\" \"$*\" >> '{env_log}'\n"
                f"exec '{real_git}' \"$@\"\n"
            )
        os.chmod(spy, 0o755)
        self.env.pop("GIT_TERMINAL_PROMPT", None)

        r = self._ship(extra_env={
            "PATH": spy_dir + os.pathsep + self.env.get("PATH", "")})
        self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
        with open(env_log) as f:
            pushes = [ln.strip() for ln in f if " push " in ln]
        self.assertTrue(pushes, "no git push was observed")
        for line in pushes:
            self.assertTrue(line.startswith("0|"), msg=line)

    def test_credential_requiring_remote_push_fails_fast_with_gits_error(self):
        import time
        server = self._start(_Server(self.tmp, require_auth=True))
        self._set_origin(f"http://127.0.0.1:{server.port}/remote.git")
        self.env.pop("GIT_TERMINAL_PROMPT", None)

        started = time.monotonic()
        r = self._ship(timeout=60)
        out = r.stdout + r.stderr
        self.assertLess(time.monotonic() - started, 30, msg=out)
        self.assertNotEqual(r.returncode, 0, msg=out)
        self.assertIn("push failed (exit", out)
        self.assertNotIn("timed out", out)
        self.assertRegex(out, r"(?i)(authentication failed|could not read|fatal)")


if __name__ == "__main__":
    unittest.main()
