"""
Regression tests for bin/clagentic-lite loading ~/.config/clagentic/config
and per-repo .clagentic/config via ds_load_env (lr-33fb89).

Root cause: bin/clagentic-lite read CLAGENTIC_* variables directly (chiefly
CLAGENTIC_ROUTER_URL/_TOKEN/_INJECT_AGENT_MODEL/_BEDROCK_MODE, consumed by
_stamp_claude_settings / the doctor router probe) but never called
ds_load_env (scripts/platform.sh) -- the single source of truth for reading
the global/per-repo config files every other entry point (hooks, gates.sh,
llm-client.sh, memory.sh, smoke.sh) already calls immediately after sourcing
platform.sh. A CLAGENTIC_ROUTER_URL written into ~/.config/clagentic/config
exactly as share/config.example and the README instruct had NO EFFECT on
enroll/update/doctor: no error, no warning, silent no-op -- indistinguishable
from "unset" to the pre-existing inert-when-unset test suite
(test_router_settings_stamp.py), which is structurally blind to this bug
class because it only ever exercises the exported-env path, never an actual
config FILE on disk.

This file is structurally blind-spot-closing, not a duplicate of
test_router_settings_stamp.py: every test here writes a REAL
~/.config/clagentic/config (or repo-local .clagentic/config) file on disk
and asserts the CLI, invoked in a shell that never exported the var, honors
it -- the exact gap the task's acceptance criteria calls out.

Covers:
    1. CLAGENTIC_ROUTER_URL set ONLY in the global config file -> `update
       --restamp` stamps the router env block into settings.json in a shell
       that never exported it.
    2. Same, and `doctor` probes the configured router instead of reporting
       it unconfigured.
    3. A repo-local .clagentic/config key resolves with ds_load_env's
       documented precedence (per-repo overrides global).
    4. No config file and no exported vars -> stamped artifacts are
       byte-for-byte identical to today (mechanical proof, not an
       assertion).
    5. PRECEDENCE: a config-file value for a key OTHER than
       CLAGENTIC_LITE_HOME overwrites an already-exported shell value for
       that same key -- config-file-wins, matching the established
       ds_load_env contract at every other entry point (gates.sh,
       llm-client.sh, memory.sh, smoke.sh, every hook shim). This is a
       deliberate consistency choice (see the doc comment at the
       ds_load_env call site in bin/clagentic-lite), not an assumption.
    6. THE HAZARD NAMED IN THE TASK: CLAGENTIC_LITE_HOME/CLAGENTIC_HOME set
       BOTH inline (env) and in the config file -- the inline/bootstrap
       value must win (the CLI already resolved and used it to locate its
       own scripts/platform.sh before any config file could be read), and
       the CLAGENTIC_HOME deprecation warning must still fire correctly.

HAZARD (PR #146 lesson, repeated here because two tests in this file touch
`update --restamp`): `clagentic-lite update` runs `git -C
"$CLAGENTIC_LITE_HOME" stash push` (and, on a non-tty, `stash drop`) against
whatever CLAGENTIC_LITE_HOME points at when it finds local modifications --
so CLAGENTIC_LITE_HOME must NEVER point at the live dev checkout in any test
here. Every restamp test below points it at a throwaway `git clone` of the
real checkout, exactly like test_router_settings_stamp.py's
TestRouterSettingsStampRestamp.

Run with: python3 -m unittest scripts/test_cli_config_file_loaded.py -v
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")
TEMPLATE = os.path.join(TOOL_HOME, "share", "hook-shims", "claude-settings.template")


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


def _write_global_config(home, body):
    """Write ~/.config/clagentic/config with the given body (a shell-sourceable
    KEY=VALUE block), as a real operator following share/config.example's
    instructions would -- NOT via `clagentic-lite init`, which is exactly the
    "shell that never ran init, config file present" shape the task describes."""
    cfg_dir = os.path.join(home, ".config", "clagentic")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, "config")
    with open(cfg_path, "w") as f:
        f.write(body)
    return cfg_path


def _run_cli(argv, cwd, home, env_extra=None, clagentic_lite_home=None,
             scrub_router=True, scrub_home_vars=True):
    """Run the CLI in a shell that has NOT exported any router var itself
    (env_extra is the only way a test can inject one) -- config-file-only
    is the exact path under test."""
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = clagentic_lite_home or TOOL_HOME
    if scrub_home_vars:
        env.pop("CLAGENTIC_HOME", None)
    if scrub_router:
        env.pop("CLAGENTIC_ROUTER_URL", None)
        env.pop("CLAGENTIC_ROUTER_TOKEN", None)
        env.pop("CLAGENTIC_ROUTER_BEDROCK_MODE", None)
        env.pop("CLAGENTIC_ROUTER_INJECT_AGENT_MODEL", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [CLI] + argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestConfigFileRouterUrlHonored(unittest.TestCase):
    """CLAGENTIC_ROUTER_URL set ONLY in ~/.config/clagentic/config -- the
    exact acceptance-criteria repro from the task. The calling shell never
    exports it; only a config FILE on disk carries it."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-cfgfile-router-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_enroll_stamps_router_env_block_from_config_file(self):
        _write_global_config(
            self.home,
            'CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\n'
            'CLAGENTIC_ROUTER_TOKEN=cfg-file-token\n',
        )
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertIn("env", parsed, msg="config-file-only CLAGENTIC_ROUTER_URL was not honored")
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8765")
        self.assertEqual(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], "cfg-file-token")

    def test_update_restamp_stamps_router_env_block_from_config_file(self):
        """The task's exact reproduction step 2: `clagentic-lite update
        --restamp` against an enrolled repo, in a shell that never exported
        the router vars, with CLAGENTIC_ROUTER_URL only in the config file."""
        fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        subprocess.run(["git", "clone", "-q", TOOL_HOME, fake_tool_home],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", fake_tool_home, "config", "user.email", "test@example.com"],
                        check=True, capture_output=True)
        subprocess.run(["git", "-C", fake_tool_home, "config", "user.name", "Test"],
                        check=True, capture_output=True)

        rc, out, err = _run_cli(
            ["enroll", self.repo], cwd=self.repo, home=self.home,
            clagentic_lite_home=fake_tool_home,
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            raw = f.read()
        raw = raw.replace("clagentic-settings-version: v7", "clagentic-settings-version: v6")
        with open(settings_path, "w") as f:
            f.write(raw)

        registry_dir = os.path.join(self.home, ".local", "state", "clagentic")
        os.makedirs(registry_dir, exist_ok=True)
        with open(os.path.join(registry_dir, "registry"), "w") as f:
            f.write(self.repo + "\n")

        _write_global_config(
            self.home,
            'CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765\n'
            'CLAGENTIC_ROUTER_TOKEN=cfg-file-restamp-token\n',
        )

        rc, out, err = _run_cli(
            ["update", "--restamp"], cwd=self.repo, home=self.home,
            clagentic_lite_home=fake_tool_home,
            env_extra={"CLAGENTIC_SKIP_FETCH": "1"},
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8765",
                          msg="config-file-only CLAGENTIC_ROUTER_URL was not honored by update --restamp")

    def test_doctor_probes_configured_router_instead_of_reporting_unconfigured(self):
        """Acceptance criterion: doctor probes the configured router rather
        than reporting it unconfigured, when the URL is config-file-only.

        Uses an http:// scheme doctor classifies "malformed" (no host at
        all) rather than a real reachability probe -- doctor's own
        reachability branch shells out to `$DS_TIMEOUT_CMD curl ...` and
        assigns its output via command substitution, which a strict POSIX
        `sh` (dash) aborts the whole script on when curl's own exit status
        is non-zero (e.g. connection refused) under `set -e`. That is a
        PRE-EXISTING fragility in cmd_doctor's router-reachability branch,
        independent of ds_load_env/config-file loading (this task's actual
        fix never touches that code path) -- see the PR body's followups
        section. Using the "malformed" branch instead exercises the exact
        same "was CLAGENTIC_ROUTER_URL read from the config file at all"
        question this test needs to answer, via a code path that does not
        shell out and so is not sensitive to that pre-existing bug.
        """
        _write_global_config(self.home, 'CLAGENTIC_ROUTER_URL=not-a-url\n')
        rc, out, err = _run_cli(
            ["doctor"], cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("clagentic-router probe:", out, msg=out)
        # The malformed-URL diagnostic (_fail, stderr) names the exact
        # config-file-only value -- proof doctor read and probed it rather
        # than silently treating it as unconfigured (which would print
        # nothing at all under "clagentic-router probe:").
        self.assertIn("not a well-formed", err, msg=err)
        self.assertIn("not-a-url", err, msg=err)


class TestConfigFileInertWhenAbsent(unittest.TestCase):
    """Acceptance criterion: no config file and no exported vars -> stamped
    artifacts are byte-for-byte identical to today. Proved mechanically
    (the exact pre-router-feature baseline), not asserted."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-cfgfile-absent-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def _expected_baseline(self):
        with open(TEMPLATE) as f:
            lines = f.readlines()
        out = []
        for line in lines:
            if "__CLAGENTIC_ROUTER_ENV_BLOCK__" in line:
                continue
            out.append(line.replace("__CLAGENTIC_LITE_HOME__", TOOL_HOME))
        return "".join(out)

    def test_no_config_file_no_env_settings_json_byte_identical(self):
        self.assertFalse(
            os.path.exists(os.path.join(self.home, ".config", "clagentic", "config")),
            "test setup error: a config file exists when the test requires none",
        )
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            actual = f.read()
        self.assertEqual(actual, self._expected_baseline(),
                          msg="wiring ds_load_env changed stamped output with no config file present")


class TestPerRepoConfigPrecedence(unittest.TestCase):
    """Acceptance criterion: a repo-local .clagentic/config resolves with the
    same precedence as every other ds_load_env entry point -- per-repo
    overrides global, both override an already-exported shell value for the
    same key (config-file-wins, ds_load_env's documented, tested contract)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-cfgfile-perrepo-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_per_repo_config_overrides_global_config(self):
        _write_global_config(self.home, 'CLAGENTIC_ROUTER_URL=http://127.0.0.1:1111\n')
        repo_cfg_dir = os.path.join(self.repo, ".clagentic")
        os.makedirs(repo_cfg_dir, exist_ok=True)
        with open(os.path.join(repo_cfg_dir, "config"), "w") as f:
            f.write('CLAGENTIC_ROUTER_URL=http://127.0.0.1:2222\n')

        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:2222",
                          msg="per-repo .clagentic/config did not override global config")

    def test_config_file_value_overwrites_already_exported_shell_value(self):
        """PRECEDENCE proof: config-file-wins over an already-exported shell
        var for a key OTHER than CLAGENTIC_LITE_HOME -- the deliberate
        consistency choice with every other ds_load_env entry point, not an
        assumption. The shell exports one URL; the config file sets a
        DIFFERENT one; the config file's value must be what gets stamped."""
        _write_global_config(self.home, 'CLAGENTIC_ROUTER_URL=http://127.0.0.1:3333\n')
        rc, out, err = _run_cli(
            ["enroll", self.repo], cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_ROUTER_URL": "http://127.0.0.1:4444"},
            scrub_router=False,
        )
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        settings_path = os.path.join(self.repo, ".claude", "settings.json")
        with open(settings_path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:3333",
                          msg="config-file value did not win over an already-exported shell value")


class TestClagenticLiteHomeExemptFromConfigFileOverride(unittest.TestCase):
    """THE HAZARD the task calls out explicitly: CLAGENTIC_LITE_HOME (and its
    deprecated alias CLAGENTIC_HOME) are read by both bin/clagentic-lite's
    own bootstrap AND the config file ds_load_env reads. Unlike every other
    key, the bootstrap-resolved/inline value MUST win -- the CLI already
    used it to locate and source scripts/platform.sh (the very file that
    defines ds_load_env) before any config file could be read at all. A
    config file silently repointing CLAGENTIC_LITE_HOME after that would
    split SCRIPTS_DIR (already loaded from tree A) from SHARE_DIR/every
    later path (built from tree B) -- a real behavior change, not simulated
    inertness. This class proves that exception holds, and that the
    CLAGENTIC_HOME deprecation warning still fires correctly."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-cfgfile-litehome-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_inline_clagentic_lite_home_wins_over_config_file_value(self):
        """A config file pointing CLAGENTIC_LITE_HOME at a bogus path must
        NOT redirect the running process away from the real, already-loaded
        checkout -- doctor's own report must still name the real checkout."""
        bogus_home = os.path.join(self.tmpdir, "bogus-does-not-exist")
        _write_global_config(self.home, f'CLAGENTIC_LITE_HOME={bogus_home}\n')

        rc, out, err = _run_cli(
            ["doctor"], cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        # doctor's overall rc reflects unrelated FAIL checks in a sandboxed
        # dev checkout (missing ~/.local/bin symlink, unmaterialized hooks,
        # etc. -- see test_router_settings_stamp.py's own doctor tests,
        # which likewise never assert rc == 0 here); what this test proves
        # is narrower: check #1's own line names the real checkout, not the
        # bogus config-file value.
        self.assertIn(f"CLAGENTIC_LITE_HOME={TOOL_HOME}", out, msg=out)
        self.assertNotIn(bogus_home, out, msg=out)

    def test_deprecated_clagentic_home_env_still_warns_with_config_file_present(self):
        """CLAGENTIC_HOME set inline (deprecated back-compat path), with
        CLAGENTIC_LITE_HOME unset, must still trigger the one-time
        deprecation warning and still resolve CLAGENTIC_LITE_HOME correctly
        from it, even with an (unrelated-key) config file present -- proving
        ds_load_env's config-file-wins behavior does not disturb the
        bootstrap fallback chain or the doctor advisory check that inspects
        it afterward."""
        _write_global_config(self.home, 'CLAGENTIC_ROUTER_TOKEN=irrelevant\n')

        # Force CLAGENTIC_LITE_HOME unset so resolution falls back to the
        # deprecated CLAGENTIC_HOME, exactly like the documented back-compat
        # path in bin/clagentic-lite's own bootstrap comment.
        env = dict(os.environ)
        env["HOME"] = self.home
        env.pop("CLAGENTIC_LITE_HOME", None)
        env["CLAGENTIC_HOME"] = TOOL_HOME
        env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
        proc = subprocess.run(
            [CLI, "doctor"], cwd=self.repo, env=env,
            capture_output=True, text=True, timeout=30,
        )
        self.assertIn("CLAGENTIC_HOME is deprecated", proc.stderr, msg=proc.stderr)
        self.assertIn(f"CLAGENTIC_LITE_HOME={TOOL_HOME}", proc.stdout, msg=proc.stdout)
        self.assertIn("WARN CLAGENTIC_HOME is set (deprecated)", proc.stdout, msg=proc.stdout)


if __name__ == "__main__":
    unittest.main()
