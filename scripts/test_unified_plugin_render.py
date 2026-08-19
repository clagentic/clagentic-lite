"""
Regression tests for the single-plugin, config-aware render + stamp +
self-heal + migration design (lr-1b5a31, comment #1 supersedes the
description's disable/rename-invariant scope).

BACKGROUND: pre-lr-1b5a31, router agent-model injection installed a SECOND
plugin (clagentic-lite-router) alongside the checked-in clagentic-lite
plugin. Both registered agents under identical short names
(reviewer/auditor/merge-gate); Claude Code's dispatch between two same-name
plugins is load-order-determined, not intent-determined, so router
injection was silently inert whenever the base plugin won dispatch. The fix
removes the dual-plugin design entirely: there is now exactly ONE
clagentic-lite plugin, always rendered from the checked-in agent files, with
`model: role:<role>-chain` injected into frontmatter only when router
injection is live. The collision is structurally impossible post-fix.

lr-35315f HARDENING: the migration above converged `claude plugin list`
state but left a real enrolled machine with an ORPHANED-BUT-RESOLVABLE
legacy cache directory on disk -- `claude plugin uninstall` is a
package-manager call, not a filesystem removal, and an orphaned entry can
drop out of `plugin list` output while its cache directory (and the
router-model-carrying agent files inside it) remains resolvable by Claude
Code's agent resolver. TestLegacyRouterPluginCacheConvergence and
TestDoctorOrphanedRouterPluginCheck below construct that exact fixture
state (cache dir present, `.orphaned_at` present, injection flag unset)
directly on disk under a fixture HOME (never the real environment's HOME)
and assert convergence, idempotency, and doctor detection against it.

VERIFICATION SCOPE (per lr-1b5a31 comment #2): this host is the dev host —
clagentic-lite is never run enrolled here, and bin/clagentic-lite itself
must never be executed as a subprocess for any purpose (dispatch
directive). This suite follows the established technique from
scripts/test_sast_exclude_ladder.py / test_review_ledger.py /
test_host_adapter_publish.py: extract the real function definitions
verbatim out of bin/clagentic-lite via string-slicing between stable marker
comments, source them into a throwaway shell script, and invoke them as
real POSIX sh functions with `sh -c`. This proves the actual render/stamp/
migration/collision logic, not an approximation of it, without ever
dispatching bin/clagentic-lite's own subcommand entrypoints (cmd_init,
cmd_update, cmd_doctor) or gates.sh.

Run with: python3 -m unittest scripts.test_unified_plugin_render -v
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
AGENTS_SRC = os.path.join(TOOL_HOME, "plugins", "clagentic-lite", "agents")

# Extraction markers: stable anchors bracketing the whole "clagentic-lite
# plugin render" block in bin/clagentic-lite, from its section-header
# comment through the closing brace of _install_clagentic_lite_plugin. If
# these markers drift, the extraction assertion below fails loudly rather
# than silently testing stale/missing code.
_BLOCK_START_MARKER = "# ---------------------------------------------------------------- clagentic-lite plugin render (config-aware, single plugin)"
_BLOCK_END_MARKER = "# Stamp a wrapper-flavored CLAUDE.md into a non-git wrapper directory."


def _extract_render_functions():
    with open(CLI) as f:
        content = f.read()
    assert _BLOCK_START_MARKER in content, (
        "extraction marker drifted -- clagentic-lite plugin render section "
        "header not found; update this test's start marker"
    )
    start = content.index(_BLOCK_START_MARKER)
    assert _BLOCK_END_MARKER in content, (
        "extraction marker drifted -- end-of-block marker not found; "
        "update this test's end marker"
    )
    end = content.index(_BLOCK_END_MARKER, start)
    extracted = content[start:end]
    for fn in (
        "_plugin_agent_needs_injection() {",
        "_render_config_fingerprint() {",
        "_render_stamp() {",
        "_render_clagentic_lite_plugin_dir() {",
        "_installed_plugin_render_stamp() {",
        "_doctor_check_plugin_collision() {",
        "_doctor_check_render_stamp_staleness() {",
        "_doctor_check_orphaned_router_plugin() {",
        "_migrate_legacy_router_plugin() {",
        "_install_clagentic_lite_plugin() {",
    ):
        assert fn in extracted, (
            f"extraction marker drifted -- {fn} definition not found "
            "between the expected markers; update this test's anchors"
        )
    return extracted


def _write_fake_claude(bin_dir, argv_log, list_output=""):
    """Fake `claude` CLI that records every invocation's argv (space-joined
    per call) and always exits 0. `plugin list` prints list_output verbatim
    so collision/migration fixtures can control what "already installed"
    looks like without a real Claude Code install."""
    fake = os.path.join(bin_dir, "claude")
    with open(fake, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_log}'
            case "$1 $2" in
              "plugin list")
                cat <<'PLUGIN_LIST_EOF'
{list_output}
PLUGIN_LIST_EOF
                exit 0
                ;;
            esac
            exit 0
        """))
    os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return fake


class _RenderTestBase(unittest.TestCase):
    """Shared sourcing/exec plumbing for the extracted render/stamp/migrate
    functions. Never invokes bin/clagentic-lite's own dispatch -- only the
    plain shell functions extracted from it, sourced fresh per test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-unified-plugin-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        # Fake CLAGENTIC_LITE_HOME containing a real copy of plugins/clagentic-lite
        # so the extracted render function's relative source-file reads resolve.
        self.fake_home = os.path.join(self.tmp, "fake-tool-home")
        os.makedirs(self.fake_home)
        shutil.copytree(
            os.path.join(TOOL_HOME, "plugins"),
            os.path.join(self.fake_home, "plugins"),
        )

        self.helpers_sh = os.path.join(self.tmp, "render-helpers.sh")
        with open(self.helpers_sh, "w") as f:
            f.write("#!/bin/sh\n")
            f.write(_extract_render_functions())

        self.bin_dir = os.path.join(self.tmp, "fakebin")
        os.makedirs(self.bin_dir)
        self.argv_log = os.path.join(self.tmp, "claude-argv.log")
        open(self.argv_log, "w").close()

        # Fixture $HOME -- distinct from fake_home (CLAGENTIC_LITE_HOME).
        # _LEGACY_ROUTER_PLUGIN_CACHE_DIR = $HOME/.claude/plugins/cache/
        # clagentic-lite-router resolves under this fixture root only; see
        # _run's unconditional HOME pin above.
        self.fake_home_dir = os.path.join(self.tmp, "fake-home")
        os.makedirs(self.fake_home_dir)

    def _legacy_cache_dir(self):
        return os.path.join(
            self.fake_home_dir, ".claude", "plugins", "cache", "clagentic-lite-router",
        )

    def _write_legacy_cache_fixture(self, with_model_override=True):
        """Constructs the exact broken state from lr-35315f: a legacy plugin
        cache directory present on disk with a resolvable reviewer.md,
        carrying `model: role:reviewer-chain` when with_model_override."""
        agents_dir = os.path.join(
            self._legacy_cache_dir(), "clagentic-lite-router", "0.0.0-generated", "agents",
        )
        os.makedirs(agents_dir)
        body = "---\nname: reviewer\n"
        if with_model_override:
            body += "model: role:reviewer-chain\n"
        body += "---\nReviewer agent body.\n"
        with open(os.path.join(agents_dir, "reviewer.md"), "w") as f:
            f.write(body)
        orphan_marker = os.path.join(self._legacy_cache_dir(), ".orphaned_at")
        with open(orphan_marker, "w") as f:
            f.write("2026-08-12T12:39:56Z\n")
        return agents_dir

    def _write_claude(self, list_output=""):
        _write_fake_claude(self.bin_dir, self.argv_log, list_output=list_output)

    def _argv_lines(self):
        with open(self.argv_log) as f:
            return [l.strip() for l in f if l.strip()]

    def _run(self, script_body, extra_env=None):
        env = os.environ.copy()
        env["CLAGENTIC_LITE_HOME"] = self.fake_home
        # HOME is ALWAYS pinned to a fixture dir under self.tmp, never the
        # real environment's HOME -- _LEGACY_ROUTER_PLUGIN_CACHE_DIR derives
        # from $HOME (see bin/clagentic-lite), and several tests below
        # exercise `rm -rf` against that path. Pinning here, unconditionally,
        # for every _run call (not just the fixture-cache tests) means a
        # real HOME value can never reach that rm -rf regardless of which
        # test runs or what order they run in.
        env["HOME"] = self.fake_home_dir
        env["PATH"] = self.bin_dir + os.pathsep + env.get("PATH", "")
        env.pop("CLAGENTIC_ROUTER_URL", None)
        env.pop("CLAGENTIC_ROUTER_INJECT_AGENT_MODEL", None)
        for role in ("REVIEWER", "AUDITOR", "GATE", "BUILDER"):
            env.pop(f"CLAGENTIC_{role}_CMD", None)
        if extra_env:
            env.update(extra_env)
        # say()/warn() are used by the extracted functions but defined
        # elsewhere in bin/clagentic-lite -- provide minimal stand-ins so
        # the sourced block is self-contained.
        preamble = (
            "say()  { printf '[clagentic-lite] %s\\n' \"$*\"; }\n"
            "warn() { printf '[clagentic-lite] WARN: %s\\n' \"$*\" 1>&2; }\n"
        )
        script = f". '{self.helpers_sh}'\n{preamble}\n{textwrap.dedent(script_body)}\n"
        return subprocess.run(
            ["sh", "-c", script, "unified-plugin-render-test"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )

    def _rendered_agent_path(self, name):
        return os.path.join(
            self.fake_home, ".clagentic", "rendered-plugin",
            "plugins", "clagentic-lite", "agents", f"{name}.md",
        )

    def _rendered_plugin_json(self):
        return os.path.join(
            self.fake_home, ".clagentic", "rendered-plugin",
            "plugins", "clagentic-lite", ".claude-plugin", "plugin.json",
        )


class TestSinglePluginRenderNoInjection(_RenderTestBase):
    """AC: with router injection OFF, exactly one agent per role name is
    rendered and none carries model:."""

    def test_render_produces_exactly_one_copy_per_role_no_model_line(self):
        result = self._run("_render_clagentic_lite_plugin_dir")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        for role in ("builder", "reviewer", "auditor", "merge-gate", "troubleshooter"):
            rendered = self._rendered_agent_path(role)
            self.assertTrue(os.path.isfile(rendered), f"{role}.md not rendered")
            with open(rendered) as f:
                content = f.read()
            self.assertNotIn("model:", content,
                              msg=f"{role}.md carries model: with injection off")

        # Exactly one agents/ dir, exactly one file per role -- no second
        # plugin tree exists anywhere under the fake tool home.
        agents_dir = os.path.dirname(self._rendered_agent_path("reviewer"))
        names = sorted(os.listdir(agents_dir))
        self.assertEqual(
            names,
            ["auditor.md", "builder.md", "merge-gate.md", "reviewer.md", "troubleshooter.md"],
        )

    def test_checked_in_agent_files_never_modified(self):
        before = {}
        for name in ("reviewer.md", "auditor.md", "merge-gate.md", "builder.md"):
            with open(os.path.join(AGENTS_SRC, name)) as f:
                before[name] = f.read()

        result = self._run(
            "_render_clagentic_lite_plugin_dir",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        for name, content in before.items():
            with open(os.path.join(AGENTS_SRC, name)) as f:
                after = f.read()
            self.assertEqual(content, after, msg=f"{name} was modified by render")


class TestSinglePluginRenderWithInjection(_RenderTestBase):
    """AC: with router injection ON, exactly one agent per role name is
    rendered, and reviewer/auditor/merge-gate (when non-claude CMD) carry
    model: -- still exactly one copy, never two."""

    def _env(self, **role_cmds):
        env = {
            "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
            "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
        }
        for role, cmd in role_cmds.items():
            env[f"CLAGENTIC_{role}_CMD"] = cmd
        return env

    def test_reviewer_gets_model_field_when_cmd_is_codex(self):
        result = self._run(
            "_render_clagentic_lite_plugin_dir",
            extra_env=self._env(REVIEWER="codex"),
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self._rendered_agent_path("reviewer")) as f:
            content = f.read()
        self.assertIn("model: role:reviewer-chain", content, msg=content)
        lines = content.splitlines()
        self.assertEqual(lines[1], "name: reviewer")
        self.assertEqual(lines[2], "model: role:reviewer-chain")

        # Exactly one RENDERED reviewer.md exists -- no second rendered
        # plugin tree (e.g. a leftover clagentic-lite-router-style overlay).
        # The checked-in source under plugins/clagentic-lite/agents/ is a
        # separate, expected, read-only copy -- not counted here.
        matches = []
        for root, _dirs, files in os.walk(os.path.join(self.fake_home, ".clagentic")):
            for fn in files:
                if fn == "reviewer.md":
                    matches.append(os.path.join(root, fn))
        self.assertEqual(len(matches), 1, msg=f"expected exactly one rendered reviewer.md, found {matches}")

    def test_gate_role_keeps_no_model_field_when_cmd_is_claude(self):
        result = self._run(
            "_render_clagentic_lite_plugin_dir",
            extra_env=self._env(REVIEWER="codex", GATE="claude"),
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self._rendered_agent_path("merge-gate")) as f:
            content = f.read()
        self.assertNotIn("model:", content, msg=content)

    def test_builder_never_injected_even_if_cmd_is_non_claude(self):
        result = self._run(
            "_render_clagentic_lite_plugin_dir",
            extra_env=self._env(BUILDER="codex"),
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self._rendered_agent_path("builder")) as f:
            content = f.read()
        self.assertNotIn("model:", content, msg=content)

    def test_no_env_vars_still_installs_from_same_single_plugin_source(self):
        """Setting only CLAGENTIC_ROUTER_URL + INJECT=1 with no per-role CMD
        overrides (default config) must still render exactly one copy per
        role, with no model: line (no role opted into a non-claude CLI)."""
        result = self._run(
            "_render_clagentic_lite_plugin_dir",
            extra_env=self._env(),
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self._rendered_agent_path("reviewer")) as f:
            content = f.read()
        self.assertNotIn("model:", content, msg=content)


class TestRenderStampFingerprint(_RenderTestBase):
    """AC: generated plugin.json carries a stamp, and the stamp differs
    between config states (no-injection vs injection) and is reproducible
    for the same config state."""

    def test_stamp_written_into_plugin_json(self):
        result = self._run("_render_clagentic_lite_plugin_dir")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        with open(self._rendered_plugin_json()) as f:
            content = f.read()
        self.assertIn("clagenticStamp", content, msg=content)

    def test_stamp_differs_between_config_fingerprints(self):
        no_inject = self._run("_render_stamp")
        self.assertEqual(no_inject.returncode, 0, msg=no_inject.stderr)

        with_inject = self._run(
            "_render_stamp",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertEqual(with_inject.returncode, 0, msg=with_inject.stderr)
        self.assertNotEqual(no_inject.stdout.strip(), with_inject.stdout.strip(),
                             msg="render stamp did not change between config fingerprints")

    def test_stamp_stable_for_same_config_fingerprint(self):
        first = self._run(
            "_render_stamp",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_AUDITOR_CMD": "codex",
            },
        )
        second = self._run(
            "_render_stamp",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_AUDITOR_CMD": "codex",
            },
        )
        self.assertEqual(first.returncode, 0, msg=first.stderr)
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        self.assertEqual(first.stdout.strip(), second.stdout.strip())

    def test_router_url_alone_without_inject_key_produces_same_stamp_as_unset(self):
        """CLAGENTIC_ROUTER_URL alone (no INJECT_AGENT_MODEL=1) must be the
        same fingerprint as neither being set -- the two keys are separate
        opt-ins by design (pre-existing invariant, still true post-lr-1b5a31)."""
        neither = self._run("_render_stamp")
        url_only = self._run(
            "_render_stamp",
            extra_env={"CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765"},
        )
        self.assertEqual(neither.returncode, 0, msg=neither.stderr)
        self.assertEqual(url_only.returncode, 0, msg=url_only.stderr)
        self.assertEqual(neither.stdout.strip(), url_only.stdout.strip())

    def test_installed_plugin_render_stamp_round_trips(self):
        render = self._run(
            "_render_clagentic_lite_plugin_dir",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertEqual(render.returncode, 0, msg=render.stderr)

        readback = self._run(
            "_installed_plugin_render_stamp",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        expected_stamp = self._run(
            "_render_stamp",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertEqual(readback.returncode, 0, msg=readback.stderr)
        self.assertEqual(readback.stdout.strip(), expected_stamp.stdout.strip())

    def test_installed_stamp_empty_when_never_rendered(self):
        result = self._run("_installed_plugin_render_stamp")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class TestLegacyRouterPluginMigration(_RenderTestBase):
    """AC: legacy clagentic-lite-router plugin install is detected and
    uninstalled against a fixture install tree (claude plugin list output)."""

    def test_legacy_plugin_present_triggers_uninstall(self):
        self._write_claude(list_output="clagentic-lite-router@clagentic-lite-router\nclagentic-lite@clagentic-lite\n")
        result = self._run("_migrate_legacy_router_plugin")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        argv = self._argv_lines()
        uninstall_calls = [l for l in argv if l.startswith("plugin uninstall")]
        self.assertTrue(
            any("clagentic-lite-router" in l for l in uninstall_calls),
            msg=f"no uninstall call targeting the legacy plugin: {argv}",
        )

    def test_legacy_plugin_absent_no_uninstall_call(self):
        self._write_claude(list_output="clagentic-lite@clagentic-lite\n")
        result = self._run("_migrate_legacy_router_plugin")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        argv = self._argv_lines()
        self.assertFalse(
            any(l.startswith("plugin uninstall") for l in argv),
            msg=f"uninstall called with no legacy plugin present: {argv}",
        )

    def test_migration_runs_regardless_of_current_router_config(self):
        """Migration must converge a machine to the single-plugin model even
        when router injection is currently OFF -- a stale overlay from a
        prior ON period must still be removed."""
        self._write_claude(list_output="clagentic-lite-router@clagentic-lite-router\n")
        result = self._run("_migrate_legacy_router_plugin")  # no router env set
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        argv = self._argv_lines()
        self.assertTrue(
            any("clagentic-lite-router" in l and l.startswith("plugin uninstall") for l in argv),
            msg=f"migration did not run with router config off: {argv}",
        )

    def test_full_install_flow_migrates_and_installs_single_plugin(self):
        """End-to-end (within the extracted-function sandbox, never the real
        CLI dispatch): _install_clagentic_lite_plugin migrates the legacy
        plugin, renders, and installs/updates exactly the unified plugin --
        never re-installing a second clagentic-lite-router plugin."""
        self._write_claude(list_output="clagentic-lite-router@clagentic-lite-router\n")
        result = self._run(
            "_install_clagentic_lite_plugin",
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        argv = self._argv_lines()

        self.assertTrue(
            any("clagentic-lite-router" in l and l.startswith("plugin uninstall") for l in argv),
            msg=f"legacy plugin was not migrated: {argv}",
        )
        install_or_update = [
            l for l in argv
            if (l.startswith("plugin install") or l.startswith("plugin update"))
            and "clagentic-lite@clagentic-lite" in l
        ]
        self.assertTrue(install_or_update, msg=f"unified plugin was never installed/updated: {argv}")
        self.assertFalse(
            any("clagentic-lite-router@clagentic-lite-router" in l
                for l in argv if l.startswith("plugin install") or l.startswith("plugin update")),
            msg=f"a second router plugin was installed/updated: {argv}",
        )


class TestLegacyRouterPluginCacheConvergence(_RenderTestBase):
    """lr-35315f regression: reproduces the state that survived lr-1b5a31's
    migration on a real enrolled machine -- legacy plugin cache directory
    PRESENT on disk, `.orphaned_at` PRESENT, and CLAGENTIC_ROUTER_INJECT_
    AGENT_MODEL UNSET -- and asserts convergence + idempotency against it."""

    def test_orphaned_cache_present_but_plugin_list_silent_still_converges(self):
        """The exact gap this task closes: `claude plugin list` no longer
        mentions the legacy name (this is what "orphaned" meant on the real
        machine -- Claude Code dropped it from the list but not from disk),
        so the OLD code's list-gated branch never fires. The directory
        removal must still run and must still remove the fixture."""
        self._write_claude(list_output="clagentic-lite@clagentic-lite\n")  # no legacy entry
        self._write_legacy_cache_fixture(with_model_override=True)
        self.assertTrue(os.path.isdir(self._legacy_cache_dir()))

        result = self._run("_migrate_legacy_router_plugin")
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        self.assertFalse(
            os.path.isdir(self._legacy_cache_dir()),
            msg="orphaned legacy cache directory survived migration despite "
                "not appearing in `claude plugin list` output",
        )

    def test_no_resolvable_role_chain_agent_survives_convergence(self):
        """AC: after update, zero resolvable reviewer/auditor agents
        carrying a role:*-chain model override remain anywhere under the
        fixture HOME, and the base plugin render is the single live copy."""
        self._write_claude(list_output="clagentic-lite-router@clagentic-lite-router\n")
        self._write_legacy_cache_fixture(with_model_override=True)

        result = self._run(
            "_install_clagentic_lite_plugin",
            extra_env={"CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "0"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        self.assertFalse(os.path.isdir(self._legacy_cache_dir()))
        # Base render is the single live copy: exactly one reviewer.md exists
        # anywhere under the fixture tool home, with no model: override
        # (injection is unset in this fixture).
        matches = []
        for root, _dirs, files in os.walk(self.fake_home):
            for fn in files:
                if fn == "reviewer.md":
                    matches.append(os.path.join(root, fn))
        rendered = [m for m in matches if ".clagentic/rendered-plugin" in m.replace(os.sep, "/")]
        self.assertEqual(len(rendered), 1, msg=f"expected exactly one rendered reviewer.md: {matches}")
        with open(rendered[0]) as f:
            self.assertNotIn("model:", f.read())

    def test_migration_idempotent_second_run_is_a_noop_on_the_fixture(self):
        """AC: running update twice against the same fixture produces an
        identical result -- the second run finds no legacy directory and
        does nothing further to it (no error, no re-creation)."""
        self._write_claude(list_output="clagentic-lite-router@clagentic-lite-router\n")
        self._write_legacy_cache_fixture(with_model_override=True)

        first = self._run("_migrate_legacy_router_plugin")
        self.assertEqual(first.returncode, 0, msg=first.stderr)
        self.assertFalse(os.path.isdir(self._legacy_cache_dir()))

        second = self._run("_migrate_legacy_router_plugin")
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        self.assertFalse(
            os.path.isdir(self._legacy_cache_dir()),
            msg="second migration run recreated the legacy cache directory",
        )

    def test_no_legacy_cache_directory_is_a_clean_noop(self):
        """No fixture written at all -- migration must not fail or create
        anything when there is nothing to converge."""
        self._write_claude(list_output="clagentic-lite@clagentic-lite\n")
        result = self._run("_migrate_legacy_router_plugin")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertFalse(os.path.isdir(self._legacy_cache_dir()))


class TestDoctorOrphanedRouterPluginCheck(_RenderTestBase):
    """AC: given the orphaned-resolvable state deliberately constructed,
    doctor reports it explicitly (lr-35315f)."""

    def _script_with_reporters(self, body):
        reporters = (
            "test_ok()   { printf 'OK:%s\\n' \"$*\"; }\n"
            "test_fail() { printf 'FAIL:%s\\n' \"$*\"; }\n"
        )
        return reporters + body

    def test_orphaned_resolvable_cache_reported_as_fail(self):
        self._write_legacy_cache_fixture(with_model_override=True)
        result = self._run(
            self._script_with_reporters("_doctor_check_orphaned_router_plugin test_ok test_fail"),
            extra_env={"CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "0"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("FAIL:", result.stdout, msg=result.stdout)
        self.assertIn("reviewer.md", result.stdout)
        self.assertNotIn("OK:", result.stdout)

    def test_no_cache_directory_reported_as_ok(self):
        result = self._run(
            self._script_with_reporters("_doctor_check_orphaned_router_plugin test_ok test_fail"),
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("OK:", result.stdout, msg=result.stdout)
        self.assertNotIn("FAIL:", result.stdout)

    def test_cache_directory_without_model_override_still_flagged(self):
        """Even without a model: line, a leftover legacy cache directory
        should not exist post-migration -- flag it as FAIL too, just with
        the narrower message (no injection-specific framing)."""
        self._write_legacy_cache_fixture(with_model_override=False)
        result = self._run(
            self._script_with_reporters("_doctor_check_orphaned_router_plugin test_ok test_fail"),
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("FAIL:", result.stdout, msg=result.stdout)


class TestDoctorPluginCollisionCheck(_RenderTestBase):
    """AC: given the collision state deliberately reconstructed via a
    `claude plugin list` fixture, _doctor_check_plugin_collision reports it
    explicitly (through the caller's fail_fn)."""

    def _script_with_reporters(self, body):
        # Minimal _ok/_fail stand-ins distinguishable in stdout, mirroring
        # cmd_doctor's own closures (printf a tagged line) without pulling
        # in the whole cmd_doctor function.
        reporters = (
            "test_ok()   { printf 'OK:%s\\n' \"$*\"; }\n"
            "test_fail() { printf 'FAIL:%s\\n' \"$*\"; }\n"
        )
        return reporters + body

    def test_collision_across_two_plugins_reported_as_fail(self):
        self._write_claude(
            list_output="clagentic-lite@clagentic-lite\nthird-party-plugin@third-party-plugin\n"
        )
        # Fabricate a same-name collision: both plugins register "reviewer".
        # claude plugin list's real per-agent detail isn't modeled by this
        # fake CLI (it only lists plugin@plugin tokens) -- the parser under
        # test keys off token PREFIX collisions in the plugin-list output
        # itself, so reuse the plugin name as the colliding token to
        # exercise the same uniq -d code path deterministically.
        self._write_claude(
            list_output="reviewer@clagentic-lite\nreviewer@third-party-plugin\n"
        )
        result = self._run(self._script_with_reporters("_doctor_check_plugin_collision test_ok test_fail"))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("FAIL:", result.stdout, msg=result.stdout)
        self.assertIn("reviewer", result.stdout)

    def test_no_collision_reported_as_ok(self):
        self._write_claude(
            list_output="reviewer@clagentic-lite\nauditor@clagentic-lite\n"
        )
        result = self._run(self._script_with_reporters("_doctor_check_plugin_collision test_ok test_fail"))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("OK:", result.stdout, msg=result.stdout)
        self.assertNotIn("FAIL:", result.stdout, msg=result.stdout)

    def test_claude_not_on_path_skips_without_reporting(self):
        # No fake claude written, and PATH pinned to a fresh empty dir plus
        # the real /bin:/usr/bin (needed to resolve `sh` itself) -- excludes
        # self.bin_dir so no fake claude from another test leaks in, and
        # guarantees no real `claude` binary is reachable either.
        no_claude_dir = os.path.join(self.tmp, "empty-bin")
        os.makedirs(no_claude_dir, exist_ok=True)
        result = self._run(
            self._script_with_reporters("_doctor_check_plugin_collision test_ok test_fail"),
            extra_env={"PATH": no_claude_dir + os.pathsep + "/usr/bin" + os.pathsep + "/bin"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertNotIn("OK:", result.stdout)
        self.assertNotIn("FAIL:", result.stdout)
        self.assertIn("skipping", result.stdout)

    def test_empty_plugin_list_skips_without_reporting(self):
        self._write_claude(list_output="")
        result = self._run(self._script_with_reporters("_doctor_check_plugin_collision test_ok test_fail"))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertNotIn("OK:", result.stdout)
        self.assertNotIn("FAIL:", result.stdout)
        self.assertIn("skipping", result.stdout)


class TestDoctorRenderStampStalenessCheck(_RenderTestBase):
    """AC: artifact stamp != current config fingerprint -> advise update."""

    def _script_with_reporters(self, body):
        reporters = "test_ok() { printf 'OK:%s\\n' \"$*\"; }\n"
        return reporters + body

    def test_no_rendered_plugin_yet_reports_info_not_ok(self):
        result = self._run(self._script_with_reporters("_doctor_check_render_stamp_staleness test_ok"))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("INFO", result.stdout)
        self.assertNotIn("OK:", result.stdout)

    def test_stamp_matches_current_config_reports_ok(self):
        render = self._run("_render_clagentic_lite_plugin_dir")
        self.assertEqual(render.returncode, 0, msg=render.stderr)

        result = self._run(self._script_with_reporters("_doctor_check_render_stamp_staleness test_ok"))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("OK:", result.stdout, msg=result.stdout)

    def test_stamp_stale_after_config_change_reports_warn_advises_update(self):
        # Render once under no-injection config...
        render = self._run("_render_clagentic_lite_plugin_dir")
        self.assertEqual(render.returncode, 0, msg=render.stderr)

        # ...then check staleness under a DIFFERENT (injection-on) config --
        # simulates an operator flipping CLAGENTIC_ROUTER_INJECT_AGENT_MODEL
        # without having re-run `clagentic-lite update` yet.
        result = self._run(
            self._script_with_reporters("_doctor_check_render_stamp_staleness test_ok"),
            extra_env={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_INJECT_AGENT_MODEL": "1",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("STALE", result.stdout, msg=result.stdout)
        self.assertIn("clagentic-lite update", result.stdout)
        self.assertNotIn("OK:", result.stdout, msg=result.stdout)


if __name__ == "__main__":
    unittest.main()
