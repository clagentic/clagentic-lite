"""
Pinning tests for lr-bdddcf: scripts/gates.sh gained a source guard
(CLAGENTIC_GATES_SOURCE_ONLY) around its trailing ds_load_env-branch +
subcommand dispatch so the file can be safely `.`-sourced by a caller that
only wants its functions.

Mirrors test_llm_client_source_guard.py's structure and rationale exactly --
see that file's module docstring for the full "why a behavioral test, not a
diff inspection" argument. Applied here to gates.sh's two guarded top-level
statements: the `ds_load_env` conditional and the `case "${1:-}"` dispatch.

Run with: python3 -m unittest scripts.test_gates_source_guard -v
"""
import os
import subprocess
import sys
import tempfile
import unittest

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path,
# regardless of which documented `unittest`/`pytest` invocation form is used.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

_USAGE_PREFIX = "usage: gates.sh {init|"

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _init_repo(root):
    subprocess.run(["git", "init", "-q", root], check=True)
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "initial"],
                    check=True, cwd=root, env=env, timeout=30)


class TestExecutedAsScriptDispatchUnchanged(unittest.TestCase):
    """Real `sh gates.sh <subcommand>` invocations, sentinel unset -- this
    is the default/production path every hook and gate call uses."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gates-guard-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, args):
        env = os.environ.copy()
        env.pop("CLAGENTIC_GATES_SOURCE_ONLY", None)
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        return subprocess.run(
            [GATES_SH, *args],
            capture_output=True, text=True, env=env, cwd=self._repo,
            timeout=30,
        )

    def test_unrecognized_subcommand_prints_usage_and_exits_1(self):
        r = self._run(["not-a-real-subcommand"])
        self.assertEqual(r.returncode, 1)
        self.assertIn(_USAGE_PREFIX, r.stderr)

    def test_no_subcommand_hits_the_same_unrecognized_branch(self):
        r = self._run([])
        self.assertEqual(r.returncode, 1)
        self.assertIn(_USAGE_PREFIX, r.stderr)

    def test_digest_subcommand_still_dispatches_through_ds_load_env(self):
        # `digest` (unlike `init`, which is special-cased to skip
        # ds_load_env) exercises both guarded statements: the
        # `[ "${1:-}" != "init" ]` branch that calls ds_load_env, and the
        # case arm that routes to cmd_digest. Local sqlite only, no network.
        r = self._run(["digest"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("clagentic-lite gate digest", r.stdout)


class TestExecutedAsScriptWithAmbientSentinelFailsClosed(unittest.TestCase):
    """BOBBIE fold-in (lr-bdddcf PR #177, comment 5333162549, bobbie.uncat.1)
    PLUS the coordinator-authorized A1 fail-closed amendment that followed:
    pins the scenario this task's whole risk framing is about -- gates.sh
    EXECUTED AS A SCRIPT (not sourced) while CLAGENTIC_GATES_SOURCE_ONLY is
    ambiently set in the environment (e.g. inherited from a parent shell or
    a shell profile), with NO CLAGENTIC_GATES_DELIBERATE_SOURCE asserting
    that the suppression is on purpose -- i.e. exactly the leak a developer
    with the sentinel exported would hit.

    BOBBIE's original comment asserted the guarded `if ... fi` (no else)
    already failed closed here because "the failed test becomes the
    script's exit status." That is wrong for an `if/fi` block (a false
    condition with no else exits 0, not the condition test's own status) --
    independently re-verified by the coordinator reading gates.sh directly.
    Empirical proof-of-gap: this exact scenario, run against gates.sh BEFORE
    the A1 amendment, exited 0 in every case (both a real subcommand and no
    subcommand at all) -- see PR #177 history. The A1 amendment added an
    `elif` that fires precisely when the suppress-sentinel is set without
    the deliberate-source signal, printing a stderr message naming both
    variables and exiting 1. This test pins THAT fixed behavior, not the
    guard's literal-last-statement structure BOBBIE's comment relied on.

    Consumers gate on exit status alone (scripts/smoke.sh, the pre-push/
    pre-commit hook-shim templates, bin/clagentic-lite's gates subcommand) --
    a neutered run that exited 0 would be misread as "gate passed" instead
    of "gate never ran." B (same PR) additionally has those consumers
    explicitly unset both variables before invoking gates.sh as a script, so
    this scenario should not reach them in practice; this test pins the
    file's own fail-closed behavior as defense-in-depth regardless.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gates-guard-amb-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run_as_script_with_ambient_sentinel(self, args):
        env = os.environ.copy()
        # Deliberately only the suppress-sentinel, NOT the deliberate-source
        # signal -- this is the ambient-leak shape, not real sourcing.
        env["CLAGENTIC_GATES_SOURCE_ONLY"] = "1"
        env.pop("CLAGENTIC_GATES_DELIBERATE_SOURCE", None)
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        return subprocess.run(
            [GATES_SH, *args],
            capture_output=True, text=True, env=env, cwd=self._repo,
            timeout=30,
        )

    def test_ambient_sentinel_with_real_subcommand_does_not_exit_0(self):
        # Under the old unguarded dispatch this would run cmd_digest and
        # exit 0. With the sentinel ambiently set and no deliberate-source
        # signal, dispatch is skipped -- the requested subcommand never runs
        # at all, so exiting 0 here would be silently misread as "digest
        # passed."
        r = self._run_as_script_with_ambient_sentinel(["digest"])
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_ambient_sentinel_with_real_subcommand_names_both_vars_on_stderr(self):
        r = self._run_as_script_with_ambient_sentinel(["digest"])
        self.assertIn("CLAGENTIC_GATES_SOURCE_ONLY", r.stderr)
        self.assertIn("CLAGENTIC_GATES_DELIBERATE_SOURCE", r.stderr)

    def test_ambient_sentinel_with_no_subcommand_does_not_exit_0(self):
        r = self._run_as_script_with_ambient_sentinel([])
        self.assertNotEqual(r.returncode, 0, r.stderr)


class TestSourceGuardWithDeliberateSignalStaysSilent(unittest.TestCase):
    """A1's other direction, pinned explicitly: suppress-sentinel set AND
    CLAGENTIC_GATES_DELIBERATE_SOURCE set together -- the real sourcing
    shape every existing test helper (via source_env(gates=True), which now
    emits both variables) and any real production reuser uses. Must stay
    completely silent and non-failing, unchanged from pre-amendment
    behavior, or A1 would have broken the ~30 migrated sourcing call sites
    it was supposed to leave untouched.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gates-guard-delib-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _source_and_call(self, script_body):
        env = os.environ.copy()
        env.update(source_env(gates=True))
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        script = f". '{GATES_SH}'\n{script_body}\n"
        return subprocess.run(
            ["sh", "-c", script, GATES_SH],
            capture_output=True, text=True, env=env, cwd=self._repo,
            timeout=30,
        )

    def test_deliberate_source_signal_keeps_sourcing_silent_and_exit_0(self):
        r = self._source_and_call("echo SOURCED_OK")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr, "")
        self.assertIn("SOURCED_OK", r.stdout)


class TestSourceGuardSuppressesDispatch(unittest.TestCase):
    """CLAGENTIC_GATES_SOURCE_ONLY=1 -- the new opt-in path a test harness
    (or a future in-process reuser) sets before dot-sourcing."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gates-guard-src-")
        self._repo = os.path.join(self._tmp, "repo")
        os.makedirs(self._repo)
        _init_repo(self._repo)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _source_and_call(self, script_body):
        env = os.environ.copy()
        env.update(source_env(gates=True))
        env["CLAGENTIC_PROJECT_ROOT"] = self._repo
        script = f". '{GATES_SH}'\n{script_body}\n"
        return subprocess.run(
            ["sh", "-c", script, GATES_SH],
            capture_output=True, text=True, env=env, cwd=self._repo,
            timeout=30,
        )

    def test_sourcing_with_sentinel_does_not_exit_or_print_usage(self):
        # $1 deliberately left unset in the sourcing shell -- under the old
        # unguarded dispatch this would hit the `*)` arm and `exit 1` before
        # this echo ever ran.
        r = self._source_and_call("echo SOURCED_OK")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(_USAGE_PREFIX, r.stderr)
        self.assertIn("SOURCED_OK", r.stdout)

    def test_sourcing_with_sentinel_exposes_real_functions(self):
        # _git_repo_root_is_scoped is a pure function defined well above the
        # dispatch -- proves the source guard makes the file's actual
        # functions callable post-source, not just "doesn't crash."
        r = self._source_and_call(
            '_git_repo_root_is_scoped && echo SCOPED_OK'
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SCOPED_OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
