"""
Regression tests for lr-1ad8da: pre-push gate input domain.

cmd_pre_push (scripts/gates.sh) ran deps + sast unconditionally since
6fe6fe6 (Initial commit). When a push's diff touches no file either gate
reads, the gate's verdict cannot possibly change -- yet a pre-existing
finding still blocks the push, and the only escape (--no-verify) disables
every gate, including ones that genuinely apply.

The fix: each domain-eligible gate (deps, sast -- NEVER secrets) declares
an input domain (an allowlist of what it reads). cmd_pre_push snapshots
git's own pre-push stdin protocol once and hands it to cmd_deps/cmd_sast,
which each independently decide whether this push's changed-path set can
possibly affect their verdict. A gate that is genuinely out of domain logs
outcome "not_applicable" (a THIRD state, never "pass") and skips its real
scan. Any inconclusive range (no stdin, multiple refs, a new branch, a
force push, a shallow clone, ...) makes the whole push inconclusive, which
means RUN the gate, never skip it.

These tests exercise `gates.sh pre-push` end-to-end (real git, fake
osv-scanner/semgrep shims recording their own invocation) against real
temporary git repositories with a real origin remote, feeding git's actual
pre-push stdin protocol on stdin -- the same integration shape
test_bleed_scope.py and test_sast_baseline_scope.py already use for their
own change-scoping mechanisms.

Run with: python3 -m unittest scripts.test_gate_input_domain -v
"""
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REAL_SCRIPTS_DIR = os.path.join(TOOL_HOME, "scripts")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

_ZERO_SHA = "0" * 40


def _write_fake_tool(bin_dir, name, argv_file, exit_code=0, extra_body=""):
    """Write a fake `name` executable onto bin_dir that appends its argv to
    argv_file and exits with exit_code. Used for osv-scanner and semgrep --
    both are only ever probed/invoked AFTER a domain check has already
    decided to run the real gate, so a minimal stub is sufficient; the
    not_applicable-path tests assert the stub is never invoked at all.
    """
    os.makedirs(bin_dir, exist_ok=True)
    path = os.path.join(bin_dir, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            {extra_body}
            printf '%s\\n' "$*" >> "{argv_file}"
            exit {exit_code}
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_fake_osv_scanner(bin_dir, argv_file, exit_code=0):
    # cmd_deps probes `osv-scanner --version` to pick an invocation style;
    # answer with a modern version string so the v2 `scan source` path is
    # taken deterministically across hosts.
    extra_body = textwrap.dedent("""\
        if [ "$1" = "--version" ]; then
          echo "osv-scanner version: 2.0.0"
          exit 0
        fi
    """)
    return _write_fake_tool(bin_dir, "osv-scanner", argv_file, exit_code, extra_body)


def _write_fake_semgrep(bin_dir, argv_file, exit_code=0):
    extra_body = textwrap.dedent("""\
        if [ "$1" = "scan" ] && [ "$2" = "--help" ]; then
          echo "usage: semgrep scan [OPTIONS]"
          echo "--baseline-commit TEXT   Only report findings..."
          exit 0
        fi
    """)
    return _write_fake_tool(bin_dir, "semgrep", argv_file, exit_code, extra_body)


def _init_origin_and_work(tmp):
    origin = os.path.join(tmp, "origin.git")
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    work = os.path.join(tmp, "work")
    subprocess.run(["git", "clone", "-q", origin, work], check=True)
    return origin, work


def _commit(work, path, content, msg, env):
    full = os.path.join(work, path)
    os.makedirs(os.path.dirname(full) or work, exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    subprocess.run(["git", "add", path], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", msg], check=True, cwd=work, env=env)


def _sha(work, ref):
    return subprocess.run(
        ["git", "rev-parse", ref], check=True, capture_output=True, text=True, cwd=work,
    ).stdout.strip()


def _run_pre_push(work, bin_dir, stdin_text, extra_env=None):
    env = os.environ.copy()
    env["PATH"] = bin_dir + os.pathsep + env["PATH"]
    env["CLAGENTIC_PROJECT_ROOT"] = work
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "0"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "0"
    if extra_env:
        env.update(extra_env)
    gates_sh = os.path.join(REAL_SCRIPTS_DIR, "gates.sh")
    return subprocess.run(
        ["sh", gates_sh, "pre-push"],
        input=stdin_text, capture_output=True, text=True, env=env, cwd=work,
    )


def _last_audit_row(work, gate):
    db_path = os.path.join(work, ".clagentic", "lite", "audit.db")
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT outcome, details FROM gate_runs WHERE gate=? ORDER BY id DESC LIMIT 1",
            (gate,),
        ).fetchone()
    finally:
        conn.close()
    return row  # (outcome, details) or None


class TestDepsSkipsOutOfDomain(unittest.TestCase):
    """A push that touches only a documentation file (no manifest, no
    lockfile, no gate config) must not invoke osv-scanner at all -- deps
    logs not_applicable instead of pass, and semgrep still runs normally
    (sast has its own, unrelated domain -- a doc file is also out of ITS
    domain, so both gates should skip in this fixture; asserted
    separately per-gate below via two different fixtures for clarity)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-deps-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "README.md", "hello\nmore docs\n", "docs-only change", env)
        self._new_sha = _sha(self._work, "HEAD")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _stdin(self):
        return f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"

    def test_deps_reports_not_applicable_and_never_invokes_osv_scanner(self):
        result = _run_pre_push(
            self._work, self._bin, self._stdin(),
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertEqual(f.read(), "", "osv-scanner must never be invoked for an out-of-domain push")
        outcome, details = _last_audit_row(self._work, "deps")
        self.assertEqual(outcome, "not_applicable")
        self.assertIn("domain=", details or "")
        self.assertIn("changed=", details or "")
        self.assertIn("derivation=", details or "")

    def test_sast_also_reports_not_applicable_for_a_docs_only_push(self):
        result = _run_pre_push(
            self._work, self._bin, self._stdin(),
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._sast_argv) as f:
            self.assertEqual(f.read(), "", "semgrep must never be invoked for an out-of-domain push")
        outcome, _details = _last_audit_row(self._work, "sast")
        self.assertEqual(outcome, "not_applicable")


class TestDepsRunsWhenManifestChanged(unittest.TestCase):
    """A push that touches a real manifest file must still run osv-scanner
    normally -- the mechanism narrows only genuinely out-of-domain pushes,
    never a real dependency change."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-deps-in-",)
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "package.json", '{"name": "x", "version": "1.0.0"}\n', "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "package.json", '{"name": "x", "version": "1.0.1"}\n', "bump dep", env)
        self._new_sha = _sha(self._work, "HEAD")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_deps_runs_osv_scanner_when_manifest_in_diff(self):
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "osv-scanner must run when a manifest is in the changed-path set")
        outcome, _details = _last_audit_row(self._work, "deps")
        self.assertEqual(outcome, "pass")


class TestGateConfigChangeForcesEveryGateToRun(unittest.TestCase):
    """A push that touches ONE gate's own config file must prevent EVERY
    domain-eligible gate from skipping on that push -- not just the gate
    the config belongs to. This is the mechanical closure of the
    privilege-escalation shape the task names: weaken a gate's config and
    skip the gate that would have noticed, in the same push.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-cfg-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        # ONLY a semgrep-exclude config change -- no manifest, no source
        # file. Deps would ordinarily be out of domain for this diff alone.
        _commit(
            self._work, ".clagentic/semgrep-exclude", "some.rule.id\n",
            "widen semgrep exclusions", env,
        )
        self._new_sha = _sha(self._work, "HEAD")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_deps_still_runs_when_only_sast_config_changed(self):
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "deps must run when ANY gate's config changed, even though "
                "the config file belongs to sast, not deps",
            )
        outcome, _details = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")


class TestFailClosedInconclusiveCases(unittest.TestCase):
    """Every enumerated inconclusive case must run every gate, never skip.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-failclosed-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "README.md", "hello\nmore docs\n", "docs-only change", env)
        self._new_sha = _sha(self._work, "HEAD")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_no_stdin_at_all_runs_every_gate(self):
        # Empty stdin -- no ref lines at all. Must be treated as
        # inconclusive (run every gate), not as "nothing changed" (skip).
        result = _run_pre_push(
            self._work, self._bin, "",
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "no stdin at all must run deps, never skip")
        with open(self._sast_argv) as f:
            self.assertNotEqual(f.read(), "", "no stdin at all must run sast, never skip")
        outcome, _ = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")

    def test_new_branch_with_no_remote_base_runs_every_gate(self):
        # Remote sha is the all-zero sentinel -- a brand-new ref with no
        # merge-base on the remote side.
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {_ZERO_SHA}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "a new-branch push (no remote base) must run deps, never skip")

    def test_deletion_push_runs_every_gate(self):
        # Local sha is the all-zero sentinel -- a deletion push, nothing to
        # diff FROM.
        stdin = f"refs/heads/feature {_ZERO_SHA} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "a deletion push must run deps, never skip")

    def test_force_push_with_unrelated_remote_sha_runs_every_gate(self):
        # A remote sha that is NOT an ancestor of the pushed sha -- the
        # force-push/history-rewrite shape.
        fake_remote_sha = "1" * 40
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {fake_remote_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "an unresolvable/force-pushed remote sha must run deps, never skip")

    def test_multiple_refs_one_inconclusive_runs_every_gate(self):
        # First ref line is a clean, resolvable docs-only diff (would be
        # out of domain alone); second ref line is a deletion push
        # (inconclusive). The union must be inconclusive -- the whole push
        # runs every gate, not just a partial skip on the first ref.
        stdin = (
            f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
            f"refs/heads/other {_ZERO_SHA} refs/heads/other {self._base_sha}\n"
        )
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "one inconclusive ref among several must make the WHOLE "
                "push inconclusive, running deps regardless of the other "
                "ref's own resolvable (and otherwise out-of-domain) range",
            )


class TestAlwaysRunAllGatesOverride(unittest.TestCase):
    """CLAGENTIC_ALWAYS_RUN_ALL_GATES=1 disables the mechanism entirely --
    every gate runs unconditionally, matching pre-lr-1ad8da behavior."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-override-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "README.md", "hello\nmore docs\n", "docs-only change", env)
        self._new_sha = _sha(self._work, "HEAD")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_override_runs_deps_despite_docs_only_push(self):
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main", "CLAGENTIC_ALWAYS_RUN_ALL_GATES": "1"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "CLAGENTIC_ALWAYS_RUN_ALL_GATES=1 must run deps unconditionally")
        outcome, _ = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")


class TestSecretsNeverEligibleForDomainSkip(unittest.TestCase):
    """secrets is NOT ELIGIBLE for this mechanism at all -- load-bearing:
    this is what stops the feature from degenerating into "skip gates on
    docs." A credential pastes into Markdown exactly as easily as source.
    cmd_secrets never even calls CLAGENTIC_GATE_REFS_FILE-gated code, so
    this is really an absence-of-behavior test: gitleaks (or its
    fail-closed block) fires regardless of domain."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-secrets-")
        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_cmd_secrets_has_no_domain_short_circuit(self):
        # Direct source-level check: cmd_secrets' own body never references
        # CLAGENTIC_GATE_REFS_FILE or _gate_skip_or_run_domain. This is a
        # static assertion on the shipped script, not a dynamic one --
        # secrets' unconditional-scan contract is exactly what the task
        # requires: "universal domain, no eligibility for out-of-domain
        # skip," and the simplest proof that stays true across every future
        # edit to cmd_secrets is that the function body never even
        # mentions the mechanism.
        gates_sh = os.path.join(REAL_SCRIPTS_DIR, "gates.sh")
        with open(gates_sh) as f:
            text = f.read()
        start = text.index("cmd_secrets() {")
        end = text.index("\ncmd_deps()", start)
        secrets_body = text[start:end]
        self.assertNotIn("CLAGENTIC_GATE_REFS_FILE", secrets_body)
        self.assertNotIn("_gate_skip_or_run_domain", secrets_body)


class TestDirectInvocationUnaffected(unittest.TestCase):
    """A direct, non-hook `gates.sh deps`/`gates.sh sast` invocation (no
    CLAGENTIC_GATE_REFS_FILE set) must behave exactly as before this task
    -- the mechanism only ever narrows the pre-push HOOK path."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-direct-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "README.md", "hello\nmore docs\n", "docs-only change", env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_direct_deps_invocation_ignores_domain_mechanism(self):
        env = os.environ.copy()
        env["PATH"] = self._bin + os.pathsep + env["PATH"]
        env["CLAGENTIC_PROJECT_ROOT"] = self._work
        env["CLAGENTIC_ALLOW_MISSING_OSV"] = "0"
        env.pop("CLAGENTIC_GATE_REFS_FILE", None)
        gates_sh = os.path.join(REAL_SCRIPTS_DIR, "gates.sh")
        result = subprocess.run(
            ["sh", gates_sh, "deps"],
            capture_output=True, text=True, env=env, cwd=self._work,
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "a direct `gates.sh deps` call (no CLAGENTIC_GATE_REFS_FILE) "
                "must run osv-scanner exactly as before this task",
            )
        outcome, _ = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")


class TestShallowCloneRunsEveryGate(unittest.TestCase):
    """A shallow clone (--depth 1) makes any merge-base/diff computed
    against a commit outside the fetched depth unreliable --
    `--is-shallow-repository` must make the whole push inconclusive (STRONG
    form: the scanner is actually invoked), even for an otherwise
    docs-only-looking diff."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-shallow-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin = os.path.join(self._tmp, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", self._origin], check=True)
        seed = os.path.join(self._tmp, "seed")
        subprocess.run(["git", "clone", "-q", self._origin, seed], check=True)
        for i in range(3):
            _commit(seed, "README.md", f"hello {i}\n", f"c{i}", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=seed, env=env)
        self._base_sha = _sha(seed, "HEAD")

        # --depth is ignored for a local filesystem-path clone; a file://
        # URL forces git to honor it and produce a genuinely shallow clone.
        self._work = os.path.join(self._tmp, "work")
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", "main", "file://" + self._origin, self._work],
            check=True,
        )
        is_shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"], cwd=self._work,
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        assert is_shallow == "true", "fixture setup did not produce a real shallow clone"

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "README.md", "hello docs-only change\n", "docs-only", env)
        self._new_sha = _sha(self._work, "HEAD")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_shallow_clone_runs_deps(self):
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "a shallow clone must run deps, never skip")
        outcome, _ = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")


class TestGraftedHistoryRunsEveryGate(unittest.TestCase):
    """Grafted history (.git/info/grafts) is NOT caught by
    --is-shallow-repository (a separate mechanism) and can make the
    ancestor check give a false positive by forging one commit as
    another's parent. A non-empty info/grafts must make the whole push
    inconclusive."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-graft-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "README.md", "hello docs-only change\n", "docs-only", env)
        self._new_sha = _sha(self._work, "HEAD")

        # A minimal, harmless graft: give base_sha a (nonexistent, but
        # syntactically valid 40-hex) fake parent. The exact content only
        # needs to make info/grafts non-empty -- the guard checked here is
        # presence, not semantic validity of the graft.
        grafts_path = os.path.join(self._work, ".git", "info", "grafts")
        os.makedirs(os.path.dirname(grafts_path), exist_ok=True)
        with open(grafts_path, "w") as f:
            f.write(self._base_sha + "\n")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_grafted_history_runs_deps(self):
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "grafted history must run deps, never skip")
        outcome, _ = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")


class TestMergeCommitCapturesFullDiff(unittest.TestCase):
    """A merge commit introducing a manifest via a non-first-parent branch
    must still run deps -- `git diff old..new --raw` reports the full
    diff, not first-parent-only, so a merge's actual file introductions
    are captured regardless of which parent introduced them."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-merge-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

        env = {**os.environ, **_GIT_ENV}
        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        # feature: docs-only change.
        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        _commit(self._work, "README.md", "hello docs\n", "docs change", env)

        # side: introduces a manifest, branched from base_sha (not
        # feature) -- base_sha rather than a local branch literally named
        # "main", since this fixture's local default branch name (whatever
        # init.defaultBranch resolves to on the host) need not be "main"
        # even though the bare origin's ref is pushed to refs/heads/main.
        subprocess.run(["git", "checkout", "-q", "-b", "side", self._base_sha], check=True, cwd=self._work, env=env)
        _commit(self._work, "package.json", '{"name": "x"}\n', "add manifest", env)

        # Merge side into feature -- package.json enters via the SECOND
        # parent, not feature's own first-parent history.
        subprocess.run(["git", "checkout", "-q", "feature"], check=True, cwd=self._work, env=env)
        subprocess.run(
            ["git", "merge", "-q", "--no-ff", "-m", "merge side", "side"],
            check=True, cwd=self._work, env=env,
        )
        self._new_sha = _sha(self._work, "HEAD")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_merge_commit_introducing_manifest_runs_deps(self):
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "a merge commit introducing a manifest via a non-first-parent "
                "branch must still run deps",
            )
        outcome, _ = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")


class TestSubmodulePointerChangeRunsEveryGate(unittest.TestCase):
    """A submodule pointer (gitlink, raw diff mode 160000) bump, with no
    other changed path, must run every gate -- a gitlink path essentially
    never matches a source/manifest domain glob on its own, which would
    otherwise satisfy the 'every changed path proven out of domain' skip
    condition despite the bump being able to introduce arbitrary new
    dependency/source content this push's own diff cannot see."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-submod-")
        env = {**os.environ, **_GIT_ENV}

        sub_origin = os.path.join(self._tmp, "sub.git")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", sub_origin], check=True)
        sub_work = os.path.join(self._tmp, "sub_work")
        subprocess.run(["git", "clone", "-q", sub_origin, sub_work], check=True)
        subprocess.run(["git", "checkout", "-q", "-b", "main"], check=True, cwd=sub_work, env=env)
        _commit(sub_work, "f.txt", "a\n", "sub1", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=sub_work, env=env)
        _commit(sub_work, "f.txt", "b\n", "sub2", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=sub_work, env=env)

        self._origin, self._work = _init_origin_and_work(self._tmp)
        _commit(self._work, "README.md", "hello\n", "initial", env)
        subprocess.run(
            ["git", "-c", "protocol.file.allow=always", "submodule", "add", "-q", sub_origin, "subm"],
            check=True, cwd=self._work, env=env,
        )
        subprocess.run(["git", "commit", "-q", "-m", "add submodule"], check=True, cwd=self._work, env=env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=self._work, env=env)
        self._base_sha = _sha(self._work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=self._work, env=env)
        # A genuine, further bump of the submodule tip (a THIRD sub commit,
        # made after the submodule was already added at sub2) -- not merely
        # re-pointing at the commit already staged by `submodule add`.
        _commit(sub_work, "f.txt", "c\n", "sub3", env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=sub_work, env=env)
        sub_new_sha = _sha(sub_origin, "main")
        subprocess.run(
            ["git", "update-index", "--cacheinfo", f"160000,{sub_new_sha},subm"],
            check=True, cwd=self._work, env=env,
        )
        subprocess.run(["git", "commit", "-q", "-m", "bump submodule"], check=True, cwd=self._work, env=env)
        self._new_sha = _sha(self._work, "HEAD")

        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_submodule_bump_runs_deps_and_sast(self):
        stdin = f"refs/heads/feature {self._new_sha} refs/heads/feature {self._base_sha}\n"
        result = _run_pre_push(
            self._work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(f.read(), "", "a submodule pointer bump must run deps, never skip")
        with open(self._sast_argv) as f:
            self.assertNotEqual(f.read(), "", "a submodule pointer bump must run sast, never skip")
        outcome, _ = _last_audit_row(self._work, "deps")
        self.assertNotEqual(outcome, "not_applicable")


class TestModeAndSymlinkChangesWithQuotableFilenames(unittest.TestCase):
    """A content-identical mode flip, or a new symlink, on a path
    containing a space (git C-quotes such a path as `"file with
    space.py"` INCLUDING the quote characters unless the diff is read
    NUL-delimited) must still be caught -- this is the direct fail-open
    proof for the quoting defect BOBBIE and PEACHES both found on
    PR #215 (_gate_resolve_changed_paths now reads `git diff -z
    --no-renames --raw`, never quoted)."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-modesym-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)
        self._env = {**os.environ, **_GIT_ENV}

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_mode_flip_on_space_named_py_file_runs_sast(self):
        origin, work = _init_origin_and_work(self._tmp)
        fname = "quoted name.py"
        _commit(work, fname, "print('hi')\n", "initial", self._env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=self._env)
        base_sha = _sha(work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=self._env)
        full = os.path.join(work, fname)
        os.chmod(full, os.stat(full).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        subprocess.run(["git", "add", fname], check=True, cwd=work, env=self._env)
        subprocess.run(
            ["git", "commit", "-q", "-m", "mode flip only, byte-identical content"],
            check=True, cwd=work, env=self._env,
        )
        new_sha = _sha(work, "HEAD")

        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"
        result = _run_pre_push(
            work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._sast_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "a content-identical mode flip on a space-containing .py "
                "path must still run sast",
            )
        outcome, _ = _last_audit_row(work, "sast")
        self.assertNotEqual(outcome, "not_applicable")

    def test_symlink_creation_with_space_in_path_runs_sast(self):
        origin, work = _init_origin_and_work(self._tmp)
        _commit(work, "README.md", "hello\n", "initial", self._env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=self._env)
        base_sha = _sha(work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=self._env)
        link_name = "linked script with space.py"
        os.symlink("target.py", os.path.join(work, link_name))
        subprocess.run(["git", "add", link_name], check=True, cwd=work, env=self._env)
        subprocess.run(
            ["git", "commit", "-q", "-m", "add symlink with space in name"],
            check=True, cwd=work, env=self._env,
        )
        new_sha = _sha(work, "HEAD")

        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"
        result = _run_pre_push(
            work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._sast_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "a new symlink at a space-containing .py path must still run sast",
            )
        outcome, _ = _last_audit_row(work, "sast")
        self.assertNotEqual(outcome, "not_applicable")


class TestVendoredAndLiterateDocsHaveNoDirectoryCarveOut(unittest.TestCase):
    """Domain matching is by file NAME/EXTENSION shape only -- there is no
    directory-based carve-out anywhere in this mechanism. A manifest
    vendored under docs/ still matches the deps domain; a literate/
    compiled document with a source extension under docs/ still matches
    the sast domain."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-vendored-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)
        self._env = {**os.environ, **_GIT_ENV}

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_manifest_vendored_under_docs_runs_deps(self):
        origin, work = _init_origin_and_work(self._tmp)
        _commit(work, "README.md", "hello\n", "initial", self._env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=self._env)
        base_sha = _sha(work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=self._env)
        _commit(work, "docs/vendor/package.json", '{"name": "x"}\n', "vendored manifest under docs", self._env)
        new_sha = _sha(work, "HEAD")

        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"
        result = _run_pre_push(
            work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "a manifest file vendored under docs/ must still run deps",
            )
        outcome, _ = _last_audit_row(work, "deps")
        self.assertNotEqual(outcome, "not_applicable")

    def test_literate_doc_with_source_extension_under_docs_runs_sast(self):
        origin, work = _init_origin_and_work(self._tmp)
        _commit(work, "README.md", "hello\n", "initial", self._env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=self._env)
        base_sha = _sha(work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=self._env)
        _commit(
            work, "docs/tutorial.py", "# literate doc executed as a tutorial\nprint('hi')\n",
            "literate doc under docs", self._env,
        )
        new_sha = _sha(work, "HEAD")

        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"
        result = _run_pre_push(
            work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._sast_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "a literate/compiled document with a source extension under "
                "docs/ must still run sast",
            )
        outcome, _ = _last_audit_row(work, "sast")
        self.assertNotEqual(outcome, "not_applicable")


class TestGateConfigPathSweep(unittest.TestCase):
    """Finding 3 (PEACHES, PR #215): the config-in-every-domain rule was
    tested with only 1 of _gate_config_paths' entries. Table-driven sweep
    of every declared config path -- each, alone, with no manifest/source
    file in the diff, must still force deps to run (the mechanical
    closure of the privilege-escalation shape: weaken a gate's config and
    skip the gate that would have noticed, in the same push)."""

    # Mirrors _gate_config_paths (scripts/gates.sh) exactly. Kept as a
    # literal list, not parsed from the shell source, so a change to
    # either side is a visible diff in code review rather than a silent
    # desync -- this is a regression test asserting a specific declared
    # set, not a generic "whatever the function currently returns" check.
    _CONFIG_PATHS = [
        ".gitleaks.toml",
        ".clagentic/osv-ignore",
        ".clagentic/semgrep-exclude",
        ".semgrepignore",
        ".clagentic/config",
        ".clagentic-bleed-ignore",
        ".clagentic/bleed-patterns",
        ".clagentic/deferrals.json",
        ".clagentic/adversarial-acks.json",
        ".clagentic/accepted-risks.md",
    ]

    def test_every_declared_config_path_forces_deps_to_run(self):
        for cfg_path in self._CONFIG_PATHS:
            with self.subTest(cfg_path=cfg_path):
                tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-cfgsweep-")
                try:
                    bin_dir = os.path.join(tmp, "bin")
                    osv_argv = os.path.join(tmp, "osv_argv.log")
                    open(osv_argv, "w").close()
                    sast_argv = os.path.join(tmp, "sast_argv.log")
                    open(sast_argv, "w").close()
                    _write_fake_osv_scanner(bin_dir, osv_argv, exit_code=0)
                    _write_fake_semgrep(bin_dir, sast_argv, exit_code=0)

                    env = {**os.environ, **_GIT_ENV}
                    origin, work = _init_origin_and_work(tmp)
                    _commit(work, "README.md", "hello\n", "initial", env)
                    subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=env)
                    base_sha = _sha(work, "HEAD")

                    subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=env)
                    # .clagentic/config is sourced as shell by gates.sh
                    # itself -- arbitrary content there is a syntax-error
                    # risk. Every other config path is inert data (TOML/
                    # JSON/list/markdown), never executed.
                    content = "# test\n" if cfg_path == ".clagentic/config" else "x\n"
                    _commit(work, cfg_path, content, f"touch {cfg_path}", env)
                    new_sha = _sha(work, "HEAD")

                    stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"
                    result = _run_pre_push(
                        work, bin_dir, stdin,
                        extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
                    )
                    with open(osv_argv) as f:
                        osv_out = f.read()
                    self.assertNotEqual(
                        osv_out, "",
                        f"deps must run when {cfg_path} changed alone "
                        f"(rc={result.returncode}, stderr={result.stderr})",
                    )
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)


class TestDomainExtraGlobsWidenOnly(unittest.TestCase):
    """CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS / CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS
    are documented in share/config.example as widen-only. Enforce that by
    test, not just by reading the append-only implementation (Finding 4,
    PEACHES PR #215): the override must (a) genuinely widen a novel
    manifest/source shape into domain, and (b) be unable to narrow an
    already-in-domain path out of domain no matter what pattern is set."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-domain-extraglobs-")
        self._bin = os.path.join(self._tmp, "bin")
        self._osv_argv = os.path.join(self._tmp, "osv_argv.log")
        open(self._osv_argv, "w").close()
        self._sast_argv = os.path.join(self._tmp, "sast_argv.log")
        open(self._sast_argv, "w").close()
        _write_fake_osv_scanner(self._bin, self._osv_argv, exit_code=0)
        _write_fake_semgrep(self._bin, self._sast_argv, exit_code=0)
        self._env = {**os.environ, **_GIT_ENV}

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _push_with_new_file(self, fname, content):
        origin, work = _init_origin_and_work(self._tmp)
        _commit(work, "README.md", "hello\n", "initial", self._env)
        subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=self._env)
        base_sha = _sha(work, "HEAD")

        subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=self._env)
        _commit(work, fname, content, f"add {fname}", self._env)
        new_sha = _sha(work, "HEAD")
        return work, base_sha, new_sha

    def test_deps_extra_glob_widens_a_novel_manifest_shape(self):
        work, base_sha, new_sha = self._push_with_new_file("custom.lockfile", "novel-ecosystem-lock\n")
        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"

        # Without the override: not a recognized manifest shape -- skips.
        result_before = _run_pre_push(
            work, self._bin, stdin, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result_before.returncode, 0, f"stdout={result_before.stdout}\nstderr={result_before.stderr}")
        with open(self._osv_argv) as f:
            self.assertEqual(f.read(), "", "an unrecognized manifest shape must skip deps without the override")
        outcome, _ = _last_audit_row(work, "deps")
        self.assertEqual(outcome, "not_applicable")

        # With the override: the novel shape is now in-domain -- runs.
        result_after = _run_pre_push(
            work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main", "CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS": "*.lockfile"},
        )
        self.assertEqual(result_after.returncode, 0, f"stdout={result_after.stdout}\nstderr={result_after.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS must widen domain to catch a novel manifest shape",
            )
        outcome, _ = _last_audit_row(work, "deps")
        self.assertNotEqual(outcome, "not_applicable")

    def test_deps_extra_glob_cannot_narrow_an_existing_manifest_match(self):
        work, base_sha, new_sha = self._push_with_new_file("package.json", '{"name": "x"}\n')
        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"

        # package.json is ALREADY in the built-in domain. An EXTRA_GLOBS
        # value that matches nothing relevant must not be able to narrow
        # that -- append-only semantics mean this can only ever add
        # patterns, never remove or override the built-in list.
        result = _run_pre_push(
            work, self._bin, stdin,
            extra_env={
                "CLAGENTIC_DEFAULT_BRANCH": "main",
                "CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS": "*.nonsense-unrelated-ext",
            },
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._osv_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "an unrelated CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS value must "
                "never narrow an already-in-domain manifest out of domain",
            )
        outcome, _ = _last_audit_row(work, "deps")
        self.assertNotEqual(outcome, "not_applicable")

    def test_sast_extra_glob_widens_a_novel_source_shape(self):
        work, base_sha, new_sha = self._push_with_new_file("script.novelext", "print('hi')\n")
        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"

        result_before = _run_pre_push(
            work, self._bin, stdin, extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main"},
        )
        self.assertEqual(result_before.returncode, 0, f"stdout={result_before.stdout}\nstderr={result_before.stderr}")
        with open(self._sast_argv) as f:
            self.assertEqual(f.read(), "", "an unrecognized source shape must skip sast without the override")

        result_after = _run_pre_push(
            work, self._bin, stdin,
            extra_env={"CLAGENTIC_DEFAULT_BRANCH": "main", "CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS": "*.novelext"},
        )
        self.assertEqual(result_after.returncode, 0, f"stdout={result_after.stdout}\nstderr={result_after.stderr}")
        with open(self._sast_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS must widen domain to catch a novel source shape",
            )
        outcome, _ = _last_audit_row(work, "sast")
        self.assertNotEqual(outcome, "not_applicable")

    def test_sast_extra_glob_cannot_narrow_an_existing_source_match(self):
        work, base_sha, new_sha = self._push_with_new_file("app.py", "print('hi')\n")
        stdin = f"refs/heads/feature {new_sha} refs/heads/feature {base_sha}\n"

        result = _run_pre_push(
            work, self._bin, stdin,
            extra_env={
                "CLAGENTIC_DEFAULT_BRANCH": "main",
                "CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS": "*.nonsense-unrelated-ext",
            },
        )
        self.assertEqual(result.returncode, 0, f"stdout={result.stdout}\nstderr={result.stderr}")
        with open(self._sast_argv) as f:
            self.assertNotEqual(
                f.read(), "",
                "an unrelated CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS value must "
                "never narrow an already-in-domain source file out of domain",
            )
        outcome, _ = _last_audit_row(work, "sast")
        self.assertNotEqual(outcome, "not_applicable")


if __name__ == "__main__":
    unittest.main()
