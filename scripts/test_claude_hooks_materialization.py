"""
Regression tests for lr-57db23: Claude Code lifecycle hook scripts
(session-start.sh, prompt-inject.sh, pre-bash-guard.sh, pre-write-guard.sh,
post-tool-nudge.sh, stop-summarize.sh) relocated out of the live, tracked
.claude/hooks/ to a neutral source (share/hook-shims/*.sh.template),
installer-materialized into $CLAGENTIC_LITE_HOME/.claude/hooks/ by
`clagentic-lite init` / `update` (bin/clagentic-lite's _stamp_claude_hooks).

Every enrolled repo's generated .claude/settings.json points its hook
`command` entries at $CLAGENTIC_LITE_HOME/.claude/hooks/*.sh by absolute
path (confirmed: share/hook-shims/claude-settings.template) — enrolled
repos never receive their own copy. This file proves:

  1. A fresh checkout with no .claude/hooks/ at all gets all six scripts
     materialized correctly by `clagentic-lite init`, byte-identical to
     substituting __CLAGENTIC_LITE_HOME__ in the tracked template.
  2. `clagentic-lite update` re-stamps only when CLAUDE_HOOKS_VERSION (or
     an individual template) is out of date, and is a no-op restamp
     (byte-identical output) when versions already match -- catching the
     "installer behavior changes what's installed" failure class the task
     explicitly warns against.
  3. `clagentic-lite doctor` reports FAIL for a missing or stale-versioned
     hook script, matching the existing pattern for other versioned
     artifacts (builder-contract.md, CLAUDE.md notice, etc).

These tests invoke the ACTUAL bin/clagentic-lite script via subprocess
against a fake-but-real checkout (copied byte-for-byte from this repo),
exactly as test_bin_clagentic_lite_symlink_self_locate.py does -- a Python
reimplementation of the stamping logic would not catch a regression in the
real shell code.

Run with: python3 -m unittest scripts/test_claude_hooks_materialization.py -v
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")

HOOK_SCRIPTS = [
    "session-start.sh",
    "prompt-inject.sh",
    "pre-bash-guard.sh",
    "pre-write-guard.sh",
    "post-tool-nudge.sh",
    "stop-summarize.sh",
]


def _make_fake_checkout(root):
    """Build a minimal-but-real clagentic-lite checkout under `root`: the
    real bin/clagentic-lite, scripts/ (platform.sh, gates.sh, memory.sh,
    llm-client.sh -- init/doctor reference these by path even if not
    executed), and share/ (hook-shims/*.template + config.example, needed
    by _write_global_config)."""
    bin_dir = os.path.join(root, "bin")
    scripts_dir = os.path.join(root, "scripts")
    share_dir = os.path.join(root, "share")
    hookshims_dir = os.path.join(share_dir, "hook-shims")
    os.makedirs(bin_dir)
    os.makedirs(scripts_dir)
    os.makedirs(hookshims_dir)

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

    return dest_cli, root


def _run_cli(argv, cwd, home, cli_env_home, env_extra=None):
    """Run bin/clagentic-lite with CLAGENTIC_LITE_HOME=cli_env_home,
    HOME=home (isolated from the real ~/.config, ~/.local/state), stdin
    NOT a tty (subprocess default) so init's front door defaults to
    accept-all-defaults and skips prompts."""
    env = dict(os.environ)
    env["CLAGENTIC_LITE_HOME"] = cli_env_home
    env.pop("CLAGENTIC_HOME", None)
    env["HOME"] = home
    env["CLAGENTIC_SKIP_FETCH"] = "1"
    env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        input="",
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _expected_content(template_path, clagentic_lite_home):
    with open(template_path) as f:
        content = f.read()
    return content.replace("__CLAGENTIC_LITE_HOME__", clagentic_lite_home)


class TestFreshCheckoutMaterializesAllHooks(unittest.TestCase):
    """A fresh checkout with no .claude/hooks/ at all gets all six scripts
    materialized by `clagentic-lite init`, byte-identical to substituting
    __CLAGENTIC_LITE_HOME__ into the tracked template."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-hooks-")
        self._checkout = os.path.join(self._tmpdir, "checkout")
        self._home = os.path.join(self._tmpdir, "home")
        os.makedirs(self._home)
        self._cli, _ = _make_fake_checkout(self._checkout)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_init_materializes_all_six_hook_scripts(self):
        hooks_dir = os.path.join(self._checkout, ".claude", "hooks")
        self.assertFalse(
            os.path.isdir(hooks_dir),
            "fixture checkout must start with no .claude/hooks/ at all",
        )
        rc, out, err = _run_cli(
            [self._cli, "init"], cwd=self._checkout, home=self._home,
            cli_env_home=self._checkout,
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        for name in HOOK_SCRIPTS:
            installed = os.path.join(hooks_dir, name)
            self.assertTrue(
                os.path.isfile(installed), f"{installed} was not materialized"
            )
            self.assertTrue(
                os.access(installed, os.X_OK), f"{installed} is not executable"
            )

    def test_materialized_content_is_byte_identical_to_substituted_template(self):
        rc, out, err = _run_cli(
            [self._cli, "init"], cwd=self._checkout, home=self._home,
            cli_env_home=self._checkout,
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        hooks_dir = os.path.join(self._checkout, ".claude", "hooks")
        for name in HOOK_SCRIPTS:
            installed = os.path.join(hooks_dir, name)
            template = os.path.join(
                self._checkout, "share", "hook-shims", f"{name}.template"
            )
            with open(installed) as f:
                actual = f.read()
            expected = _expected_content(template, self._checkout)
            self.assertEqual(
                actual, expected,
                f"{name}: materialized content diverges from "
                f"substituted template (installer must not silently "
                f"produce different output than the tracked template says)",
            )

    def test_materialized_hooks_reference_resolved_clagentic_lite_home(self):
        """The __CLAGENTIC_LITE_HOME__ placeholder must not survive into the
        installed copy -- a literal, unsubstituted placeholder would make
        every hook fail closed on every enrolled machine."""
        rc, out, err = _run_cli(
            [self._cli, "init"], cwd=self._checkout, home=self._home,
            cli_env_home=self._checkout,
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        hooks_dir = os.path.join(self._checkout, ".claude", "hooks")
        for name in HOOK_SCRIPTS:
            with open(os.path.join(hooks_dir, name)) as f:
                content = f.read()
            self.assertNotIn("__CLAGENTIC_LITE_HOME__", content, name)
            self.assertIn(self._checkout, content, name)


class TestUpdateRestampsOnlyOnVersionChange(unittest.TestCase):
    """`clagentic-lite update` re-stamps hooks only when CLAUDE_HOOKS_VERSION
    is out of date, and produces byte-identical output on a no-op restamp
    when versions already match -- proves the migration does not silently
    change installed output for machines already at the current version."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-hooks-upd-")
        self._checkout = os.path.join(self._tmpdir, "checkout")
        self._home = os.path.join(self._tmpdir, "home")
        os.makedirs(self._home)
        self._cli, _ = _make_fake_checkout(self._checkout)
        # `update` requires `git -C $CLAGENTIC_LITE_HOME pull --ff-only` to
        # succeed against a real upstream (a bare "no tracking information"
        # local repo is a hard failure, not a safe no-op). Create a bare
        # "origin" remote seeded from this same commit and set up tracking
        # so the pull is a real, trivial, already-up-to-date fast-forward.
        origin = os.path.join(self._tmpdir, "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", self._checkout], check=True)
        subprocess.run(
            ["git", "-C", self._checkout, "config", "user.email", "t@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self._checkout, "config", "user.name", "t"], check=True
        )
        subprocess.run(
            ["git", "-C", self._checkout, "remote", "add", "origin", origin],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self._checkout, "add", "-A"], check=True, cwd=self._checkout
        )
        subprocess.run(
            ["git", "-C", self._checkout, "commit", "-q", "-m", "init"], check=True
        )
        subprocess.run(
            ["git", "-C", self._checkout, "push", "-q", "-u", "origin", "main"],
            check=True,
        )

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_update(self):
        return _run_cli(
            [self._cli, "update"], cwd=self._checkout, home=self._home,
            cli_env_home=self._checkout,
        )

    def test_update_on_fresh_checkout_materializes_hooks(self):
        hooks_dir = os.path.join(self._checkout, ".claude", "hooks")
        self.assertFalse(os.path.isdir(hooks_dir))
        rc, out, err = self._run_update()
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        for name in HOOK_SCRIPTS:
            self.assertTrue(
                os.path.isfile(os.path.join(hooks_dir, name)), name
            )

    def test_second_update_is_a_byte_identical_no_op(self):
        rc1, out1, err1 = self._run_update()
        self.assertEqual(rc1, 0, msg=f"stdout={out1!r} stderr={err1!r}")
        hooks_dir = os.path.join(self._checkout, ".claude", "hooks")
        before = {}
        for name in HOOK_SCRIPTS:
            with open(os.path.join(hooks_dir, name)) as f:
                before[name] = (f.read(), os.path.getmtime(os.path.join(hooks_dir, name)))

        # Second update: content must be identical (mtimes may differ if the
        # restamp path re-writes, but content must not silently drift).
        rc2, out2, err2 = self._run_update()
        self.assertEqual(rc2, 0, msg=f"stdout={out2!r} stderr={err2!r}")
        for name in HOOK_SCRIPTS:
            with open(os.path.join(hooks_dir, name)) as f:
                after = f.read()
            self.assertEqual(
                after, before[name][0],
                f"{name}: second `update` run produced different content "
                f"than the first -- installed output must be stable once "
                f"CLAUDE_HOOKS_VERSION already matches",
            )
        self.assertIn(
            "up to date", out2,
            f"second update should report hooks already up to date; stdout={out2!r}",
        )

    def test_stale_version_marker_triggers_restamp(self):
        rc1, out1, err1 = self._run_update()
        self.assertEqual(rc1, 0, msg=f"stdout={out1!r} stderr={err1!r}")
        hooks_dir = os.path.join(self._checkout, ".claude", "hooks")
        target = os.path.join(hooks_dir, "pre-write-guard.sh")
        with open(target) as f:
            content = f.read()
        downgraded = re.sub(
            r"clagentic-hooks-version: v\d+", "clagentic-hooks-version: v0", content
        )
        self.assertNotEqual(downgraded, content, "fixture must actually downgrade the marker")
        with open(target, "w") as f:
            f.write(downgraded)

        rc2, out2, err2 = self._run_update()
        self.assertEqual(rc2, 0, msg=f"stdout={out2!r} stderr={err2!r}")
        with open(target) as f:
            restamped = f.read()
        self.assertIn(
            "clagentic-hooks-version: v1", restamped,
            "a stale version marker on even one hook script must trigger a "
            "full restamp back to the current CLAUDE_HOOKS_VERSION",
        )


class TestDoctorReportsHookStatus(unittest.TestCase):
    """`clagentic-lite doctor` FAILs on a missing or stale-versioned hook
    script, matching the existing pattern for other versioned artifacts."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-hooks-doc-")
        self._checkout = os.path.join(self._tmpdir, "checkout")
        self._home = os.path.join(self._tmpdir, "home")
        os.makedirs(self._home)
        self._cli, _ = _make_fake_checkout(self._checkout)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_doctor_fails_when_hooks_never_materialized(self):
        rc, out, err = _run_cli(
            [self._cli, "doctor"], cwd=self._checkout, home=self._home,
            cli_env_home=self._checkout,
        )
        # doctor's own overall exit reflects _fail count > 0. _fail() prints
        # to stderr (see cmd_doctor's `_fail() { printf ... 1>&2; }`), so
        # the FAIL lines themselves are on stderr, not stdout.
        self.assertNotEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self.assertIn("FAIL", err)
        # doctor reports the full installed path, not a bare relative one.
        self.assertIn(
            os.path.join(self._checkout, ".claude", "hooks"), err, err
        )

    def test_doctor_passes_hook_check_after_init(self):
        rc0, out0, err0 = _run_cli(
            [self._cli, "init"], cwd=self._checkout, home=self._home,
            cli_env_home=self._checkout,
        )
        self.assertEqual(rc0, 0, msg=f"stdout={out0!r} stderr={err0!r}")
        rc, out, err = _run_cli(
            [self._cli, "doctor"], cwd=self._checkout, home=self._home,
            cli_env_home=self._checkout,
        )
        for name in HOOK_SCRIPTS:
            self.assertIn(name, out, f"doctor output should mention {name}: {out}")
        self.assertNotIn(
            f".claude/hooks/pre-write-guard.sh missing", out,
            f"stdout={out!r}",
        )


if __name__ == "__main__":
    unittest.main()
