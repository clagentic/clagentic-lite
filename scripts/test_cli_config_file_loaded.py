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

PR #152 FOLD-IN (bobbie.sast.3, github.com/clagentic/clagentic-lite/pull/152
review comment): the original revision of this fix called the COMBINED
ds_load_env unconditionally from bin/clagentic-lite's dispatch, which
dot-sources (EXECUTES) a repo-local .clagentic/config with no trust check
at all -- reachable from `doctor`/`list`/`update` against a repo merely
cloned, never enrolled. The fix under test now splits the global load
(ds_load_global_env, unconditional -- operator-owned, not repo content)
from the repo-local load (ds_load_repo_env, gated on REGISTRY membership
via _cli_maybe_load_repo_env in bin/clagentic-lite). Additional coverage
added for this fold-in:
    7. TestPerRepoConfigPrecedence was revised: a repo-local override is
       NOT honored on the very first `enroll` call (the repo is not yet a
       REGISTRY member at that point), but IS honored on every subsequent
       invocation (doctor, update, a re-enroll) once it is.
    8. TestHostileRepoLocalConfigNotExecutedPreTrust: a hostile
       .clagentic/config that writes a sentinel file as a side effect must
       NOT execute against an unenrolled repo under doctor/list/update/show
       -- observable non-execution (sentinel absence), not merely a return
       code. Also proves enroll itself does not execute the repo it is in
       the middle of enrolling, and that the gate does not overcorrect
       (post-enrollment repo-local config still loads normally).
    9. test_doctor_unreachable_router_reports_failure_without_aborting:
       regression for a separate, pre-existing `set -e`/curl fragility in
       cmd_doctor's router-reachability probe (dash treats a bare
       assignment's failing command-substitution RHS as a top-level
       failure), escalated in-scope by the coordinator during this same
       fold-in since it is the same file/function this PR already touches.

PR #152 SECOND FOLD-IN (coordinator follow-through on bobbie.sast.3): the
first round's fix closed the CLI-DISPATCH path but left a second, deeper
one open -- `clagentic-lite enroll`'s own internal delegation
(bin/clagentic-lite _enroll_one) invokes `scripts/memory.sh init` and
`scripts/gates.sh init` as subprocesses, BEFORE the repo is registered.
Those scripts each called the combined ds_load_env unconditionally at
their own top level (memory.sh:15, gates.sh:27 pre-fix), independent of
bin/clagentic-lite's own gate, so the exact `git clone && cd && enroll`
shape -- the single most common enrollment workflow -- still executed a
hostile repo-local .clagentic/config, one process frame down from where
BOBBIE looked. Fixed by moving ds_load_env in both scripts to run for
every subcommand EXCEPT `init` (verified: cmd_init in both scripts reads
no config-file-sourced CLAGENTIC_* value at all, so this is a no-op for
`init`'s own behavior and a real gate for the pre-trust window).
test_first_enroll_does_not_execute_the_repo_being_enrolled now asserts
sentinel absence (previously only asserted enroll succeeded, explicitly
noting the subprocess path was unverified) -- this is the test that FAILED
on the first fold-in's code even though every CLI-dispatch-level test
passed, proving the two layers are genuinely independent execution paths.
Paired with test_second_invocation_against_enrolled_repo_honors_repo_local_config
(narrowness proof: the gate defers timing, it does not disable the
feature) and test_first_enroll_from_outside_target_repo_does_not_execute_it
(cwd-independence proof).

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
        Uses a malformed URL (doctor's own validation-refusal branch, which
        never shells out) to isolate "was CLAGENTIC_ROUTER_URL read from the
        config file at all" from the reachability-probe fix covered
        separately below."""
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

    def test_doctor_unreachable_router_reports_failure_without_aborting(self):
        """Regression for the set -e/curl fragility (PR #152 fold-in,
        coordinator-escalated to in-scope): cmd_doctor's router-reachability
        probe used to assign curl's command-substitution output directly to
        a bare variable, which a strict POSIX sh (dash) treats as a
        top-level failing command under `set -e` when curl exits non-zero
        (e.g. ECONNREFUSED -- the single most common real case, router
        configured but not running yet). That aborted the ENTIRE doctor run
        immediately after printing the "clagentic-router probe:" header,
        with no diagnostic and no later sections (memory tunables, env var
        migration, doctor summary) ever printing. This asserts the fix:
        doctor completes the full report and prints an actionable
        unreachable message, exactly the shape a user following the README
        (set CLAGENTIC_ROUTER_URL in the global config, router not started
        yet) would hit."""
        _write_global_config(self.home, 'CLAGENTIC_ROUTER_URL=http://127.0.0.1:19999\n')
        rc, out, err = _run_cli(
            ["doctor"], cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        # The report must reach its own final line -- proof the process did
        # not die mid-report the way it did before this fix.
        self.assertIn("== doctor summary:", out, msg=f"OUT={out}\nERR={err}")
        self.assertIn("clagentic-router probe:", out, msg=out)
        self.assertIn("clagentic-router unreachable at", err, msg=err)
        self.assertIn("127.0.0.1:19999", err, msg=err)
        # Sections that come AFTER the router probe in cmd_doctor's own
        # ordering must still have run -- the strongest proof this is not
        # merely "some text after the probe" but the actual rest of the
        # function completing.
        self.assertIn("memory tunables:", out, msg=out)
        self.assertIn("env var migration:", out, msg=out)


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
    same key (config-file-wins, ds_load_env's documented, tested contract).

    TRUST GATE (bobbie.sast.3, PR #152 fold-in): the repo-local layer is
    only loaded by bin/clagentic-lite once the repo is a REGISTRY member --
    i.e. from the SECOND invocation onward (doctor, update --restamp, a
    re-enroll), never on the FIRST `enroll` call that establishes trust in
    the first place. See _cli_maybe_load_repo_env's docstring in
    bin/clagentic-lite for why enroll itself must not execute the repo's
    own .clagentic/config as the price of enrolling it. This is a
    deliberate, narrow behavior change from this PR's earlier revision
    (which combined ds_load_env unconditionally and so honored a per-repo
    override on the very first enroll) -- the global config still applies
    at enroll time exactly as before; only the repo-local override layer is
    deferred to post-enrollment invocations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-cfgfile-perrepo-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)

    def test_per_repo_config_not_honored_on_first_enroll(self):
        """The trust-gate boundary itself: a per-repo override present at
        the moment of the FIRST enroll call must NOT be honored -- the repo
        is not yet a REGISTRY member when enroll's own CLI-bootstrap load
        runs. The global config value wins by omission (repo-local layer
        simply isn't loaded yet), not by any precedence contest."""
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
        self.assertEqual(parsed["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:1111",
                          msg="per-repo .clagentic/config was honored on the FIRST enroll call "
                              "-- trust gate did not hold (repo is not yet a REGISTRY member "
                              "at that point)")

    def test_per_repo_config_overrides_global_config_after_enrollment(self):
        """Once the repo IS a REGISTRY member (post-enroll), the repo-local
        override applies and wins over the global value -- the trust
        precondition, not the override mechanism itself, was gated."""
        _write_global_config(self.home, 'CLAGENTIC_ROUTER_URL=http://127.0.0.1:1111\n')

        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        repo_cfg_dir = os.path.join(self.repo, ".clagentic")
        os.makedirs(repo_cfg_dir, exist_ok=True)
        with open(os.path.join(repo_cfg_dir, "config"), "w") as f:
            f.write('CLAGENTIC_ROUTER_URL=http://127.0.0.1:2222\n')

        rc, out, err = _run_cli(
            ["doctor"], cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("127.0.0.1:2222", out + err,
                       msg=f"repo-local override was not honored post-enrollment: OUT={out} ERR={err}")
        self.assertNotIn("127.0.0.1:1111", out,
                          msg="global value leaked through instead of the repo-local override")

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


class TestHostileRepoLocalConfigNotExecutedPreTrust(unittest.TestCase):
    """Regression coverage for bobbie.sast.3 (PR #152 review comment on
    github.com/clagentic/clagentic-lite/pull/152): a repo-local
    .clagentic/config is REPO CONTENT, and dot-sourcing it EXECUTES it.
    Before this fold-in, bin/clagentic-lite's own CLI dispatch called the
    combined ds_load_env unconditionally for every subcommand, which
    dot-sources <ds_repo_root-of-cwd>/.clagentic/config with NO trust check
    at all -- an operator who clones an unfamiliar repo and runs
    `clagentic-lite doctor` (or `list`, or `update`) out of curiosity, cwd
    inside that clone, would have executed arbitrary shell from the clone
    before ever making a deliberate trust decision about it.

    THE FIX UNDER TEST: bin/clagentic-lite now loads the repo-local layer
    only via _cli_maybe_load_repo_env, gated on the repo's canonical path
    already being a member of $HOME/.local/state/clagentic/registry (i.e.
    the operator previously ran `enroll` for this exact repo on this exact
    machine). A REGISTRY entry cannot be forged by repo content -- it lives
    outside the repo entirely.

    ASSERTS OBSERVABLE NON-EXECUTION, not a function's return value: the
    hostile .clagentic/config writes a SENTINEL FILE as a side effect (the
    unambiguous proof dot-sourcing actually ran shell, not just that some
    CLAGENTIC_* variable ended up set -- a variable assignment alone could
    theoretically come from elsewhere, a side-effecting file write cannot).
    Every subcommand a plain `git clone && cd && clagentic-lite <cmd>`
    workflow would plausibly try FIRST on an unenrolled repo (doctor, list,
    update) is covered -- the sentinel must NOT appear for any of them.

    HAZARD (repeated per file convention): never point CLAGENTIC_LITE_HOME
    at the live dev checkout; the restamp-adjacent update test uses a
    throwaway git clone.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-hostile-repo-cfg-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)
        self.sentinel = os.path.join(self.tmpdir, "pwned.txt")

    def _plant_hostile_config(self):
        """A .clagentic/config that, if ever dot-sourced, writes a sentinel
        file OUTSIDE the repo -- proof of actual shell execution, not proof
        of a variable assignment (which a config file is also expected to
        do legitimately)."""
        cfg_dir = os.path.join(self.repo, ".clagentic")
        os.makedirs(cfg_dir, exist_ok=True)
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write(f'touch "{self.sentinel}"\nCLAGENTIC_ROUTER_URL=http://127.0.0.1:6666\n')

    def _assert_sentinel_absent(self, msg_prefix):
        self.assertFalse(
            os.path.exists(self.sentinel),
            msg=f"{msg_prefix}: hostile .clagentic/config was EXECUTED "
                f"(sentinel file present) against an unenrolled/untrusted repo",
        )

    def test_doctor_on_unenrolled_clone_does_not_execute_hostile_config(self):
        """The exact bobbie.sast.3 repro: clone (simulated by _init_git_repo
        + planting the hostile file directly, equivalent to a clone that
        already carries it), cd in, run doctor out of curiosity -- never
        enrolled."""
        self._plant_hostile_config()
        _run_cli(["doctor"], cwd=self.repo, home=self.home,
                  env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"})
        self._assert_sentinel_absent("doctor")

    def test_list_on_unenrolled_clone_does_not_execute_hostile_config(self):
        self._plant_hostile_config()
        _run_cli(["list"], cwd=self.repo, home=self.home)
        self._assert_sentinel_absent("list")

    def test_update_on_unenrolled_clone_does_not_execute_hostile_config(self):
        self._plant_hostile_config()
        _run_cli(["update"], cwd=self.repo, home=self.home,
                  env_extra={"CLAGENTIC_SKIP_FETCH": "1"})
        self._assert_sentinel_absent("update")

    def test_show_on_unenrolled_clone_does_not_execute_hostile_config(self):
        self._plant_hostile_config()
        _run_cli(["show", "memory"], cwd=self.repo, home=self.home)
        self._assert_sentinel_absent("show")

    def test_first_enroll_does_not_execute_the_repo_being_enrolled(self):
        """THE SHARPEST CASE, and the one the CLI-dispatch-only version of
        this test suite missed (coordinator follow-up on bobbie.sast.3,
        second round): the exact `git clone && cd && clagentic-lite enroll`
        shape, cwd INSIDE the not-yet-enrolled repo, hostile
        .clagentic/config already present. enroll is how a repo becomes
        trusted and cannot require prior trust as a precondition for
        reading it -- but it must also not execute the repo's own config as
        the PRICE of enrolling it. The very first `enroll` call for this
        repo must not trigger the sentinel, even though enroll succeeds and
        the repo ends up enrolled afterward.

        THIS NOW COVERS BOTH LAYERS: the CLI-dispatch trust gate
        (_cli_maybe_load_repo_env, bin/clagentic-lite -- excludes `enroll`
        entirely) AND the enroll-internal subprocess path (_enroll_one's
        `scripts/memory.sh init` / `scripts/gates.sh init` calls, which
        used to call the combined ds_load_env unconditionally regardless of
        the CLI-dispatch gate -- fixed by moving each script's ds_load_env
        call to run for every subcommand EXCEPT `init`, since cmd_init in
        both scripts reads no config-sourced CLAGENTIC_* value at all).
        Before that second fix, THIS test failed even though the
        CLI-dispatch-only tests above all passed -- proof the two layers
        are genuinely independent execution paths, not one gate protecting
        both."""
        self._plant_hostile_config()
        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self._assert_sentinel_absent("enroll (first call, cwd inside target repo)")

    def test_first_enroll_from_outside_target_repo_does_not_execute_it(self):
        """Companion to the above: enroll invoked with an explicit PATH
        argument from OUTSIDE the target repo (cwd is some other directory
        entirely) -- ds_repo_root() inside the memory.sh/gates.sh init
        subprocesses resolves from THEIR OWN cwd, which _enroll_one does not
        change before invoking them, so this should behave identically to
        the cwd-inside case. Confirms the fix does not depend on which
        directory the operator happened to run enroll from."""
        self._plant_hostile_config()
        outside_cwd = os.path.join(self.tmpdir, "elsewhere")
        os.makedirs(outside_cwd, exist_ok=True)
        rc, out, err = _run_cli(["enroll", self.repo], cwd=outside_cwd, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")
        self._assert_sentinel_absent("enroll (first call, cwd outside target repo)")

    def test_re_enrolled_or_post_enroll_repo_local_config_still_loads_safely(self):
        """Sanity check the gate is not overcorrecting: a repo-local config
        that is NOT hostile (no side effect, just a var assignment) still
        loads normally once the repo is a REGISTRY member -- the trust gate
        blocks EXECUTION-worthy risk pre-trust, it does not permanently
        disable the legitimate per-repo override feature post-trust."""
        cfg_dir = os.path.join(self.repo, ".clagentic")
        os.makedirs(cfg_dir, exist_ok=True)
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write("")  # enroll first with a benign (empty) config

        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        # Now write a benign, non-hostile override and confirm doctor picks
        # it up post-enrollment (same property as
        # TestPerRepoConfigPrecedence.test_per_repo_config_overrides_global_config_after_enrollment,
        # asserted again here in the same file/class as the hostile-config
        # negative case so the two properties are visibly paired).
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write("CLAGENTIC_ROUTER_URL=http://127.0.0.1:7777\n")
        rc, out, err = _run_cli(
            ["doctor"], cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("127.0.0.1:7777", out + err, msg=f"OUT={out}\nERR={err}")

    def test_second_invocation_against_enrolled_repo_honors_repo_local_config(self):
        """The narrowness proof the coordinator asked for, paired directly
        with test_first_enroll_does_not_execute_the_repo_being_enrolled: the
        SAME repo, enrolled with a BENIGN config first (so the pre-trust
        gate is proven not to interfere with a normal enrollment), then a
        SECOND invocation (doctor) against that now-enrolled repo, with the
        repo-local config still legitimately present, DOES honor it -- this
        gate narrows WHEN the repo-local layer loads (pre-trust vs
        post-trust), it does not permanently disable the feature the
        moment ANY .clagentic/config has ever existed in a repo's history."""
        cfg_dir = os.path.join(self.repo, ".clagentic")
        os.makedirs(cfg_dir, exist_ok=True)
        with open(os.path.join(cfg_dir, "config"), "w") as f:
            f.write("CLAGENTIC_ROUTER_URL=http://127.0.0.1:8888\n")

        rc, out, err = _run_cli(["enroll", self.repo], cwd=self.repo, home=self.home)
        self.assertEqual(rc, 0, msg=f"stdout={out!r} stderr={err!r}")

        rc, out, err = _run_cli(
            ["doctor"], cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertIn("127.0.0.1:8888", out + err,
                       msg=f"repo-local config was not honored on the SECOND (post-enrollment) "
                           f"invocation -- gate over-blocked: OUT={out} ERR={err}")


if __name__ == "__main__":
    unittest.main()
