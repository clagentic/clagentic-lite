"""
Regression tests for lr-716012: the SessionStart update-alert emit path had
ZERO test coverage. Every one of the ~20 occurrences of
CLAGENTIC_SKIP_UPDATE_ALERT across scripts/ set it to "1" to SUPPRESS the
alert during other tests, and the string "UPDATE AVAILABLE" appeared in no
test at all -- a regression in the emit path itself was undetectable.

This file builds a throwaway CLAGENTIC_LITE_HOME whose HEAD is genuinely
behind its own origin remote (a real bare repo, real `git fetch`, real
`git rev-list --count`), materializes the actual session-start.sh via
`clagentic-lite init` (share/hook-shims/session-start.sh.template ->
_stamp_claude_hooks in bin/clagentic-lite), then runs that MATERIALIZED
script directly and asserts:
  1. stdout parses as JSON (the hook's own emitted envelope).
  2. additionalContext contains "UPDATE AVAILABLE".
  3. the behind-count in the message matches the real commit count.

None of these tests set CLAGENTIC_SKIP_UPDATE_ALERT -- that is the entire
point: this is the one place in the suite that exercises the alert actually
FIRING, not being suppressed.

A companion test proves the "ahead N, behind 0" case stays silent even
when the clone is simultaneously ahead of its upstream by unrelated local
commits -- the behind-count (HEAD..upstream) must drive the notice
independent of the ahead-count (upstream..HEAD).

Run with: python3 -m unittest scripts/test_session_start_update_alert_emit.py -v
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


def _run(argv, cwd=None, env=None, timeout=30):
    return subprocess.run(
        argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
    )


def _git(args, cwd, check=True):
    return subprocess.run(
        ["git", "-C", cwd] + args, check=check,
        capture_output=True, text=True, timeout=15,
    )


def _materialize_fake_checkout(root):
    """Populate an EXISTING directory `root` with a minimal-but-real
    clagentic-lite checkout: the real bin/clagentic-lite, scripts/
    (platform.sh + friends), and share/ (hook-shims/*.template +
    config.example) -- same shape as test_claude_hooks_materialization.py's
    fixture, since `init` needs all of it to successfully materialize the
    hooks. Unlike that file's _make_fake_checkout, `root` may already exist
    and contain other content (here: a real git clone) -- this only adds the
    tool-tree files/dirs, it never creates or clears `root` itself.

    Returns the path to the copied bin/clagentic-lite."""
    bin_dir = os.path.join(root, "bin")
    scripts_dir = os.path.join(root, "scripts")
    share_dir = os.path.join(root, "share")
    hookshims_dir = os.path.join(share_dir, "hook-shims")
    os.makedirs(bin_dir, exist_ok=True)
    os.makedirs(scripts_dir, exist_ok=True)
    os.makedirs(hookshims_dir, exist_ok=True)

    dest_cli = os.path.join(bin_dir, "clagentic-lite")
    shutil.copyfile(CLI, dest_cli)
    os.chmod(dest_cli, 0o755)

    for name in ("platform.sh", "gates.sh", "memory.sh", "llm-client.sh"):
        src = os.path.join(TOOL_HOME, "scripts", name)
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(scripts_dir, name))

    src_hookshims = os.path.join(TOOL_HOME, "share", "hook-shims")
    for name in os.listdir(src_hookshims):
        shutil.copyfile(
            os.path.join(src_hookshims, name), os.path.join(hookshims_dir, name)
        )

    config_example = os.path.join(TOOL_HOME, "share", "config.example")
    shutil.copyfile(config_example, os.path.join(share_dir, "config.example"))

    return dest_cli


def _commit(repo, filename, content, message):
    path = os.path.join(repo, filename)
    with open(path, "w") as f:
        f.write(content)
    _git(["add", filename], cwd=repo)
    _git(["commit", "-q", "-m", message], cwd=repo)


class _BehindOriginFixtureBase(unittest.TestCase):
    """Shared fixture: a bare 'origin', a checkout cloned from it and used as
    CLAGENTIC_LITE_HOME, and an isolated $HOME so the real ~/.config and
    ~/.local/state are never touched."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-update-alert-")
        self._origin = os.path.join(self._tmpdir, "origin.git")
        self._checkout = os.path.join(self._tmpdir, "checkout")
        self._home = os.path.join(self._tmpdir, "home")
        os.makedirs(self._home)

        # Real bare origin remote.
        _run(["git", "init", "-q", "--bare", "-b", "main", self._origin],
             cwd=self._tmpdir, timeout=15)

        # Seed origin with an initial commit via a scratch clone.
        seed = os.path.join(self._tmpdir, "seed")
        _run(["git", "clone", "-q", self._origin, seed], timeout=15)
        _git(["config", "user.email", "t@example.com"], cwd=seed)
        _git(["config", "user.name", "t"], cwd=seed)
        _commit(seed, "f.txt", "one\n", "initial")
        _git(["push", "-q", "origin", "main"], cwd=seed)

        # Clone that becomes CLAGENTIC_LITE_HOME -- starts in sync with origin.
        _run(["git", "clone", "-q", self._origin, self._checkout], timeout=15)
        _git(["config", "user.email", "t@example.com"], cwd=self._checkout)
        _git(["config", "user.name", "t"], cwd=self._checkout)

        # Materialize the fake tool tree INTO the same checkout dir the git
        # clone lives in, so CLAGENTIC_LITE_HOME is simultaneously "a real
        # git repo behind its origin" and "a real clagentic-lite install".
        # These files are untracked additions inside the git checkout; that's
        # fine -- session-start.sh's repo-scoping check only cares that
        # `git -C CLAGENTIC_LITE_HOME rev-parse --show-toplevel` equals
        # CLAGENTIC_LITE_HOME, not that the tree is clean.
        self._cli = _materialize_fake_checkout(self._checkout)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _init_cli(self):
        """Run `clagentic-lite init` to materialize .claude/hooks/session-start.sh
        into CLAGENTIC_LITE_HOME, without skipping the update alert (only
        CLAGENTIC_SKIP_FETCH is set, to avoid init's OWN unrelated network
        prereq checks -- unrelated to the hook's own fetch, which runs later
        when the hook itself executes)."""
        env = dict(os.environ)
        env["CLAGENTIC_LITE_HOME"] = self._checkout
        env.pop("CLAGENTIC_HOME", None)
        env["HOME"] = self._home
        env["CLAGENTIC_SKIP_FETCH"] = "1"
        proc = _run([self._cli, "init"], cwd=self._checkout, env=env, timeout=30)
        self.assertEqual(
            proc.returncode, 0,
            msg=f"init failed: stdout={proc.stdout!r} stderr={proc.stderr!r}",
        )
        hook = os.path.join(self._checkout, ".claude", "hooks", "session-start.sh")
        self.assertTrue(os.path.isfile(hook), "session-start.sh was not materialized")
        return hook

    def _run_hook(self, hook, extra_env=None):
        """Run the MATERIALIZED session-start.sh directly, with cwd outside
        any repo (an isolated empty dir) so the only signal under test is the
        CLAGENTIC_LITE_HOME update-alert block, not the recall/handoff/
        contract blocks (which need a real .clagentic/lite/ tree). Critically:
        CLAGENTIC_SKIP_UPDATE_ALERT is NEVER set here."""
        cwd = os.path.join(self._tmpdir, "session-cwd")
        os.makedirs(cwd, exist_ok=True)
        env = dict(os.environ)
        env["CLAGENTIC_LITE_HOME"] = self._checkout
        env.pop("CLAGENTIC_HOME", None)
        env["HOME"] = self._home
        env.pop("CLAGENTIC_SKIP_UPDATE_ALERT", None)
        if extra_env:
            env.update(extra_env)
        return _run(["sh", hook], cwd=cwd, env=env, timeout=30)


class TestUpdateAlertFiresWhenBehind(_BehindOriginFixtureBase):
    """Core deliverable (lr-716012 scope item 1): the emit path actually
    fires for a clone that is genuinely behind its origin, with the alert
    NOT suppressed."""

    def setUp(self):
        super().setUp()
        # Advance origin by two commits the checkout never pulls, then fetch
        # (but do not merge/pull) so the checkout has real, current
        # tracking-ref knowledge of how far behind it is -- exactly what an
        # enrolled user's stale clone looks like after the hook's own
        # rate-limited `git fetch` runs.
        seed = os.path.join(self._tmpdir, "seed")
        _commit(seed, "f.txt", "two\n", "second")
        _git(["push", "-q", "origin", "main"], cwd=seed)
        _commit(seed, "f.txt", "three\n", "third")
        _git(["push", "-q", "origin", "main"], cwd=seed)

    def test_alert_fires_stdout_is_json_and_contains_notice(self):
        hook = self._init_cli()
        # Force the hook's internal fetch to run this invocation (state file
        # absent -> _AGE >= _FETCH_INTERVAL) so it picks up the two commits
        # just pushed to origin above.
        result = self._run_hook(hook)

        self.assertEqual(
            result.returncode, 0,
            msg=f"hook exited non-zero: stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertTrue(
            result.stdout.strip(),
            f"hook produced no stdout at all -- stderr={result.stderr!r}",
        )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(
                f"hook stdout did not parse as JSON: {exc}\nstdout={result.stdout!r}"
            )
        self.assertIn("additionalContext", payload)
        self.assertIn(
            "UPDATE AVAILABLE",
            payload["additionalContext"],
            f"expected the update notice in additionalContext; got: {payload!r}",
        )
        self.assertIn(
            "2 commit(s) behind",
            payload["additionalContext"],
            f"expected the real behind-count (2) in the notice; got: {payload!r}",
        )

    def test_suppression_var_still_works_when_explicitly_set(self):
        """Sanity check the other direction: CLAGENTIC_SKIP_UPDATE_ALERT=1
        still suppresses, so this test file does not just prove the message
        is unconditionally emitted."""
        hook = self._init_cli()
        result = self._run_hook(hook, extra_env={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"})
        combined = (result.stdout or "") + (result.stderr or "")
        self.assertNotIn("UPDATE AVAILABLE", combined)


class TestUpdateAlertAheadAndBehindTogether(_BehindOriginFixtureBase):
    """lr-716012 scope item 3: a clone that is BOTH ahead (unrelated local
    commits never pushed) and behind (origin advanced separately) must still
    alert -- the behind-count, not a simple ancestor check, drives the
    notice. And a clone that is ONLY ahead (behind == 0) must stay silent."""

    def test_ahead_and_behind_still_alerts(self):
        # Local-only commit: checkout is now ahead of origin by 1.
        _commit(self._checkout, "local.txt", "local\n", "local-only commit")

        # Origin advances independently: checkout becomes behind by 2 as well.
        seed = os.path.join(self._tmpdir, "seed")
        _commit(seed, "f.txt", "two\n", "second")
        _git(["push", "-q", "origin", "main"], cwd=seed)
        _commit(seed, "f.txt", "three\n", "third")
        _git(["push", "-q", "origin", "main"], cwd=seed)

        # Confirm the fixture actually is ahead-and-behind before trusting
        # the hook's output about it.
        status = _git(["status", "-sb"], cwd=self._checkout, check=False)
        self.assertIn("ahead", status.stdout)

        hook = self._init_cli()
        result = self._run_hook(hook)

        self.assertEqual(
            result.returncode, 0,
            msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        payload = json.loads(result.stdout)
        self.assertIn(
            "UPDATE AVAILABLE",
            payload.get("additionalContext", ""),
            f"ahead-and-behind clone must still alert on the behind count; got: {payload!r}",
        )
        self.assertIn(
            "2 commit(s) behind",
            payload["additionalContext"],
            f"expected behind-count 2 despite local ahead-by-1; got: {payload!r}",
        )

    def test_ahead_only_stays_silent(self):
        # Local-only commit: checkout is ahead of origin by 1, behind by 0.
        _commit(self._checkout, "local.txt", "local\n", "local-only commit")

        status = _git(["status", "-sb"], cwd=self._checkout, check=False)
        self.assertIn("ahead", status.stdout)
        self.assertNotIn("behind", status.stdout)

        hook = self._init_cli()
        result = self._run_hook(hook)

        combined_stdout = result.stdout or ""
        if combined_stdout.strip():
            payload = json.loads(combined_stdout)
            self.assertNotIn(
                "UPDATE AVAILABLE",
                payload.get("additionalContext", ""),
                f"ahead-only (behind=0) clone must stay silent; got: {payload!r}",
            )
        # else: exit 0 with no stdout at all (CONTEXT empty) is also a pass --
        # the hook's own contract is "[ -z "$CONTEXT" ] && exit 0" with no output.


if __name__ == "__main__":
    unittest.main()
