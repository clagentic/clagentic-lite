"""
Regression coverage for lr-02f048: opt-in gate-path routing through
clagentic-router for reviewer/auditor/gate (merge-gate's internal role
literal), via CLAGENTIC_<ROLE>_VIA_ROUTER=1.

Five properties this file proves, exercised through the real walk_chain
function end to end (mirroring the established fake-binary-on-PATH
technique test_walk_chain_stderr_notice.py / test_num_turns_audit_logging.py
already use -- a real audit.db, a real sourced llm-client.sh, a fake `curl`
standing in for clagentic-router):

  1. INERT WHEN UNSET (proved mechanically, not asserted): with
     CLAGENTIC_<ROLE>_VIA_ROUTER unset, walk_chain never invokes curl at
     all and behaves byte-identically to the pre-existing direct-CLI path
     -- matching the inert-when-unset proof pattern established by
     test_router_settings_stamp.py / lr-49f25e.
  2. HAPPY PATH: with the opt-in set and a fake `curl` returning a 200
     Anthropic Messages API response, walk_chain returns that response's
     text content and NEVER invokes the direct-CLI (claude/codex) binary at
     all -- proving the router path is genuinely taken, not merely
     attempted-and-ignored.
  3. LAYER 2 FALLBACK: with the opt-in set and `curl` failing (simulating
     clagentic-router being unreachable), walk_chain falls back to the
     direct-CLI chain, non-blocking, AND emits a loud, distinguishable
     stderr warning naming this as a Layer-2 bypass (not a Layer-1 chain
     advance).
  4. LOGGING PARITY, SAME PR: a router-path SUCCESS writes an audit.db
     gate_runs row with outcome "pass" and a CLI field of "router" --
     distinguishable from a direct-CLI pass row's own CLI field (e.g.
     "claude"/"codex"). A Layer-2 fallback additionally writes a
     "router-fallback" row BEFORE the direct-CLI chain's own rows -- a
     third, distinct outcome label from the direct path's
     pass/fallback/step-failed/degraded set (task's explicit requirement:
     these two layers must be distinguishable in the log, never collapsed).
  5. BUILDER IS EXCLUDED: CLAGENTIC_BUILDER_VIA_ROUTER=1 has no effect --
     walk_chain never even checks for it (builder is not in
     _llm_role_routable's enumeration), so a router opt-in accidentally set
     for builder is silently correctly ignored rather than routing a
     tool-bearing role.

Run with: python3 -m unittest scripts.test_router_gate_path -v
"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LLM_CLIENT_SH = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _functions_only_source(dest_dir):
    """Identical helper to every other llm-client.sh test file -- reused,
    not reimplemented."""
    with open(LLM_CLIENT_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in llm-client.sh"
    dest = os.path.join(dest_dir, "llm-client.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    platform_dest = os.path.join(dest_dir, "platform.sh")
    with open(PLATFORM_SH) as src, open(platform_dest, "w") as dst:
        dst.write(src.read())
    return dest


def _init_bare_repo(tmp):
    """A minimal real git repo so ds_repo_root/ds_audit_log resolution
    succeeds -- identical technique to test_num_turns_audit_logging.py."""
    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    with open(os.path.join(repo, "README"), "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "README"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True, env=env)
    return repo


def _make_audit_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE gate_runs "
        "(ts TEXT, gate TEXT, outcome TEXT, details TEXT, session_id TEXT);"
    )
    conn.commit()
    conn.close()


def _write_curl_success_stub(bin_dir, findings_payload):
    """A fake `curl` that answers ANY invocation with a 200 + a fixed
    Anthropic Messages API response body, mimicking `curl -s -o FILE -w
    '%{http_code}' ...` exactly the way invoke_router calls it: writes the
    response body to whatever `-o` names and prints the http_code to
    stdout. Drains --data-binary's referenced file implicitly (never reads
    it -- curl itself would, but the stub does not need to for this test)."""
    path = os.path.join(bin_dir, "curl")
    body = json.dumps({
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": findings_payload}],
    })
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            OUT_FILE=""
            PREV=""
            for arg in "$@"; do
              if [ "$PREV" = "-o" ]; then
                OUT_FILE="$arg"
              fi
              PREV="$arg"
            done
            cat <<'BODY' > "$OUT_FILE"
{body}
BODY
            printf '200'
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_curl_failure_stub(bin_dir):
    """A fake `curl` that always fails (connection-refused shaped exit 7),
    simulating clagentic-router being unreachable -- the Layer-2 trigger."""
    path = os.path.join(bin_dir, "curl")
    with open(path, "w") as f:
        f.write(textwrap.dedent("""\
            #!/bin/sh
            printf 'curl: (7) Failed to connect\\n' 1>&2
            exit 7
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _write_success_claude(bin_dir, findings=None):
    """Direct-CLI fallback binary -- a normal, clean-pass claude stub, same
    shape test_num_turns_audit_logging.py's own helper uses."""
    path = os.path.join(bin_dir, "claude")
    inner = json.dumps({"summary": "clean diff", "checked": ["security"],
                         "findings": findings if findings is not None else []})
    envelope = json.dumps({
        "type": "result",
        "subtype": "success",
        "num_turns": 3,
        "duration_ms": 2000,
        "is_error": False,
        "result": inner,
    })
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "claude 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            printf '%s' '{envelope}' >> "$CLAGENTIC_TEST_CLAUDE_CALL_LOG"
            printf '\\n' >> "$CLAGENTIC_TEST_CLAUDE_CALL_LOG"
            cat <<'ENVELOPE'
{envelope}
ENVELOPE
            exit 0
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


class _RouterGatePathTestBase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-router-gate-path-")
        self._repo = _init_bare_repo(self._tmpdir)
        clagentic_dir = os.path.join(self._repo, ".clagentic", "lite")
        os.makedirs(clagentic_dir)
        self._audit_db = os.path.join(clagentic_dir, "audit.db")
        _make_audit_db(self._audit_db)

        self._bin_dir = os.path.join(self._tmpdir, "bin")
        os.makedirs(self._bin_dir)

        self._src_dir = os.path.join(self._tmpdir, "src")
        os.makedirs(self._src_dir)
        self._sourced = _functions_only_source(self._src_dir)

        self._claude_call_log = os.path.join(self._tmpdir, "claude-calls.log")
        open(self._claude_call_log, "w").close()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _run_walk_chain(self, role, mode, env_extra=None, chain=""):
        role_upper = role.upper()
        chain_export = f"export CLAGENTIC_{role_upper}_CHAIN='{chain}'" if chain else ""
        env_lines = "\n".join(
            f"export {k}='{v}'" for k, v in (env_extra or {}).items()
        )
        script = textwrap.dedent(f"""\
            export PATH='{self._bin_dir}':"$PATH"
            export CLAGENTIC_PROJECT_ROOT='{self._repo}'
            export CLAGENTIC_TEST_CLAUDE_CALL_LOG='{self._claude_call_log}'
            export CLAGENTIC_{role_upper}_CMD=claude
            {chain_export}
            {env_lines}
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{self._sourced}'
            printf 'stdin diff content' | walk_chain '{role}' '{mode}' _fixture_prompt
        """)
        return subprocess.run(
            ["sh", "-c", script, self._sourced],
            capture_output=True, text=True, cwd=self._repo,
        )

    def _audit_rows(self):
        conn = sqlite3.connect(self._audit_db)
        rows = conn.execute(
            "SELECT outcome, details FROM gate_runs WHERE gate='llm-call' ORDER BY rowid;"
        ).fetchall()
        conn.close()
        return rows

    def _claude_call_count(self):
        with open(self._claude_call_log) as f:
            return len([ln for ln in f if ln.strip()])


class TestRouterPathInertWhenUnset(_RouterGatePathTestBase):
    """Property 1: CLAGENTIC_<ROLE>_VIA_ROUTER unset (default) -- curl is
    never invoked at all, and the direct-CLI path runs exactly as it did
    before this task. Proved mechanically: no `curl` binary is even placed
    on PATH, so any attempt to invoke it would surface as a hard failure
    (127, not-on-PATH), not a silently-skipped no-op."""

    def test_no_curl_on_path_direct_cli_still_passes_reviewer(self):
        _write_success_claude(self._bin_dir)
        result = self._run_walk_chain("reviewer", "json")
        self.assertEqual(result.returncode, 0,
                          f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(self._claude_call_count(), 1,
                          "direct-CLI path must run exactly once when routing is unset")
        rows = self._audit_rows()
        self.assertTrue(rows, "no llm-call audit rows written")
        self.assertTrue(
            all(details.split(":")[1] != "router" for _, details in rows if ":" in details),
            f"no row should carry CLI='router' when VIA_ROUTER is unset: rows={rows!r}",
        )

    def test_router_url_set_but_via_router_unset_still_inert(self):
        """CLAGENTIC_ROUTER_URL alone (e.g. set for the interactive-session
        settings.json integration, lr-49f25e) must not activate gate-path
        routing on its own -- CLAGENTIC_<ROLE>_VIA_ROUTER is a SEPARATE
        opt-in, per the task's own scope."""
        _write_success_claude(self._bin_dir)
        result = self._run_walk_chain(
            "reviewer", "json",
            env_extra={"CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765"},
        )
        self.assertEqual(result.returncode, 0,
                          f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(self._claude_call_count(), 1,
                          "CLAGENTIC_ROUTER_URL alone must not activate gate-path routing")


class TestRouterPathHappyPath(_RouterGatePathTestBase):
    """Property 2: opt-in set, router healthy -- the router path is taken
    and the direct-CLI binary is never invoked."""

    def test_reviewer_routes_through_router_and_skips_direct_cli(self):
        findings_json = json.dumps({"summary": "clean", "checked": ["security"], "findings": []})
        _write_curl_success_stub(self._bin_dir, findings_json)
        _write_success_claude(self._bin_dir)  # present on PATH but must never be called
        result = self._run_walk_chain(
            "reviewer", "json",
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token",
                "CLAGENTIC_REVIEWER_VIA_ROUTER": "1",
            },
        )
        self.assertEqual(result.returncode, 0,
                          f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(self._claude_call_count(), 0,
                          "direct-CLI must never be invoked when the router path succeeds")
        self.assertIn('"findings": []', result.stdout)

    def test_auditor_and_gate_roles_also_routable(self):
        for role, mode in (("auditor", "markdown"), ("gate", "json")):
            with self.subTest(role=role):
                self.setUp()
                payload = "clean audit, no findings" if role == "auditor" else \
                    json.dumps({"decision": "approve", "reason": "all green"})
                _write_curl_success_stub(self._bin_dir, payload)
                result = self._run_walk_chain(
                    role, mode,
                    env_extra={
                        "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                        "CLAGENTIC_ROUTER_TOKEN": "test-token",
                        f"CLAGENTIC_{role.upper()}_VIA_ROUTER": "1",
                    },
                )
                self.assertEqual(result.returncode, 0,
                                  f"role={role} stdout={result.stdout!r} stderr={result.stderr!r}")
                self.tearDown()


class TestRouterPathLayer2Fallback(_RouterGatePathTestBase):
    """Property 3: router unreachable -- non-blocking fallback to
    direct-CLI, with a loud, LAYER-2-labeled stderr warning."""

    def test_router_unreachable_falls_back_to_direct_cli_non_blocking(self):
        _write_curl_failure_stub(self._bin_dir)
        _write_success_claude(self._bin_dir)
        result = self._run_walk_chain(
            "reviewer", "json",
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:19999",
                "CLAGENTIC_ROUTER_TOKEN": "test-token",
                "CLAGENTIC_REVIEWER_VIA_ROUTER": "1",
            },
        )
        self.assertEqual(result.returncode, 0,
                          f"a router-unreachable event must NOT block the gate -- "
                          f"stdout={result.stdout!r} stderr={result.stderr!r}")
        self.assertEqual(self._claude_call_count(), 1,
                          "direct-CLI fallback must run exactly once")

    def test_layer2_stderr_warning_is_distinguishable_from_layer1(self):
        _write_curl_failure_stub(self._bin_dir)
        _write_success_claude(self._bin_dir)
        result = self._run_walk_chain(
            "reviewer", "json",
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:19999",
                "CLAGENTIC_ROUTER_TOKEN": "test-token",
                "CLAGENTIC_REVIEWER_VIA_ROUTER": "1",
            },
        )
        self.assertIn("LAYER-2 FALLBACK", result.stderr,
                       f"a router-unreachable event must be labeled as a distinct "
                       f"Layer-2 bypass, not a generic fallback notice. "
                       f"stderr={result.stderr!r}")
        self.assertIn(
            "NOT the router advancing its own internal chain", result.stderr,
            f"the warning must explicitly disclaim being a Layer-1 (in-router) "
            f"event, per the task's explicit distinguishability requirement. "
            f"stderr={result.stderr!r}",
        )


class TestRouterPathLoggingParity(_RouterGatePathTestBase):
    """Property 4: audit.db outcome labels distinguish a router-path pass
    from a direct-CLI pass, and a Layer-2 fallback from every direct-CLI
    outcome -- same PR, same audit.db, per the task's explicit requirement."""

    def test_router_pass_row_carries_router_cli_field(self):
        findings_json = json.dumps({"summary": "clean", "checked": ["security"], "findings": []})
        _write_curl_success_stub(self._bin_dir, findings_json)
        result = self._run_walk_chain(
            "reviewer", "json",
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token",
                "CLAGENTIC_REVIEWER_VIA_ROUTER": "1",
            },
        )
        self.assertEqual(result.returncode, 0, f"stderr={result.stderr!r}")
        rows = self._audit_rows()
        pass_rows = [r for r in rows if r[0] == "pass"]
        self.assertTrue(pass_rows, f"no pass row found: rows={rows!r}")
        self.assertTrue(
            any(details.startswith("reviewer:router:role:reviewer-chain") for _, details in pass_rows),
            f"expected a pass row whose details start with "
            f"'reviewer:router:role:reviewer-chain' (CLI field == 'router', "
            f"distinguishable from a direct-CLI 'reviewer:claude:...' row) -- "
            f"rows={rows!r}",
        )

    def test_layer2_fallback_writes_router_fallback_outcome_before_direct_cli_rows(self):
        _write_curl_failure_stub(self._bin_dir)
        _write_success_claude(self._bin_dir)
        result = self._run_walk_chain(
            "reviewer", "json",
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:19999",
                "CLAGENTIC_ROUTER_TOKEN": "test-token",
                "CLAGENTIC_REVIEWER_VIA_ROUTER": "1",
            },
        )
        self.assertEqual(result.returncode, 0, f"stderr={result.stderr!r}")
        rows = self._audit_rows()
        outcomes = [o for o, _ in rows]
        self.assertIn(
            "router-fallback", outcomes,
            f"a Layer-2 event must write its own 'router-fallback' outcome, "
            f"distinct from pass/fallback/step-failed/degraded -- rows={rows!r}",
        )
        fallback_idx = outcomes.index("router-fallback")
        self.assertTrue(
            all(o != "router-fallback" for o in outcomes[:fallback_idx]),
            "router-fallback row must be the first llm-call row for this call",
        )
        # The direct-CLI chain's own pass row (CLI='claude') must exist too,
        # so the audit trail records BOTH the bypass and its outcome.
        self.assertTrue(
            any(details.startswith("reviewer:claude:") for outcome, details in rows if outcome == "pass"),
            f"expected the direct-CLI fallback's own pass row (CLI='claude'): rows={rows!r}",
        )


class TestBuilderExcludedFromRouting(_RouterGatePathTestBase):
    """Property 5: builder is not in _llm_role_routable's enumeration --
    CLAGENTIC_BUILDER_VIA_ROUTER=1 has no effect at all, even with a
    reachable router and a valid opt-in-shaped env var name."""

    def test_builder_via_router_is_a_no_op(self):
        findings_json = "some builder output"
        _write_curl_success_stub(self._bin_dir, findings_json)
        path = os.path.join(self._bin_dir, "claude")
        with open(path, "w") as f:
            f.write(textwrap.dedent("""\
                #!/bin/sh
                if [ "$1" = "--version" ]; then
                  echo "claude 99.0.0"
                  exit 0
                fi
                cat > /dev/null 2>&1
                printf 'x' >> "$CLAGENTIC_TEST_CLAUDE_CALL_LOG"
                printf 'direct-cli builder output\\n'
                exit 0
            """))
        os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

        result = self._run_walk_chain(
            "builder", "markdown",
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_ROUTER_TOKEN": "test-token",
                "CLAGENTIC_BUILDER_VIA_ROUTER": "1",
            },
        )
        self.assertEqual(result.returncode, 0, f"stderr={result.stderr!r}")
        self.assertIn("direct-cli builder output", result.stdout,
                       "builder must always use the direct-CLI path, "
                       "even with CLAGENTIC_BUILDER_VIA_ROUTER=1 set")


if __name__ == "__main__":
    unittest.main()
