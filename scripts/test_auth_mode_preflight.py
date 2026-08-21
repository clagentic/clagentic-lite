"""
Regression coverage for lr-6d4a1f's mode-implied readiness preflight
(_llm_auth_mode_preflight, scripts/llm-client.sh), the description's scope
item 4: "Mode-implied readiness preflight before review/gate runs:
bedrock-sso reads the SSO cache expiresAt (env-overridable path, AGENTS.md
invariant 6) and fails fast with time-remaining when expired; ALL other
modes and UNDECLARED are a no-op."

Acceptance (description ACs 2/3, verbatim):
  2. Given auth_mode=bedrock-sso with a valid SSO cache, when a gate runs,
     then claude spawns in Bedrock protocol mode without any ambient env
     from the operator's interactive session.
  3. Given auth_mode=bedrock-sso with an expired SSO cache, when a review
     starts, then it fails within seconds with a message naming SSO expiry
     and the expiry timestamp -- not a 30s hang, not a schema/auth
     misreport.

This file tests _llm_auth_mode_preflight directly (unit-level, fast) plus
one end-to-end walk_chain integration case proving the failure surfaces
through the SAME degraded-envelope/exit-status channel every other
walk_chain failure uses (AC3's "not a schema/auth misreport" -- the
envelope's own "cause" field must read "auth-mode-preflight", never
"infra"/"unwrap" indistinguishably, and the summary/reason text must name
both the word "expired" and the actual expiry timestamp).

Run with: python3 -m unittest scripts.test_auth_mode_preflight -v
"""
import datetime
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _write_cache_file(cache_dir, expires_at, name="token.json"):
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, name)
    with open(path, "w") as f:
        json.dump({
            "startUrl": "https://example.invalid/start",
            "region": "us-east-1",
            "accessToken": "fixture-not-a-real-token",
            "expiresAt": expires_at,
        }, f)
    return path


def _run_preflight(env_extra):
    """Call _llm_auth_mode_preflight directly and report its return status
    plus $_LLM_AUTH_MODE_PREFLIGHT_REASON on stdout."""
    script = textwrap.dedent(f"""\
        . '{LLM_CLIENT_SH}'
        if _llm_auth_mode_preflight; then
          printf 'READY\\n'
        else
          printf 'NOT-READY\\t%s\\n' "$_LLM_AUTH_MODE_PREFLIGHT_REASON"
        fi
    """)
    env = dict(os.environ)
    env.update(source_env(llm_client=True))
    env.update(env_extra)
    r = subprocess.run(
        ["sh", "-c", script, LLM_CLIENT_SH],
        capture_output=True,
        text=True,
        cwd=TOOL_HOME,
        env=env,
        timeout=30,
    )
    return r


class TestNoOpForNonBedrockSso(unittest.TestCase):
    """UNDECLARED and every mode other than bedrock-sso are a no-op --
    ready=0 unconditionally, no filesystem access to any SSO cache dir at
    all (proven by pointing CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR at a path
    that does not exist -- if the preflight touched it, this would fail)."""

    def test_undeclared_is_ready(self):
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": "/nonexistent/cache/dir/xyz",
        })
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_anthropic_oauth_is_ready(self):
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "anthropic-oauth",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": "/nonexistent/cache/dir/xyz",
        })
        self.assertIn("READY", r.stdout)
        self.assertNotIn("NOT-READY", r.stdout)

    def test_enterprise_is_ready(self):
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "enterprise",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": "/nonexistent/cache/dir/xyz",
        })
        self.assertIn("READY", r.stdout)
        self.assertNotIn("NOT-READY", r.stdout)

    def test_bedrock_api_key_is_ready(self):
        """bedrock-api-key has no equivalent local expiry artifact -- the
        preflight is scoped to bedrock-sso specifically, see that
        function's own doc comment for why."""
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-api-key",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": "/nonexistent/cache/dir/xyz",
        })
        self.assertIn("READY", r.stdout)
        self.assertNotIn("NOT-READY", r.stdout)


class TestBedrockSsoValidCache(unittest.TestCase):
    """AC 2: a valid (non-expired) SSO cache is ready."""

    def test_valid_cache_is_ready(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-preflight-valid-")
        try:
            future = (datetime.datetime.now(datetime.timezone.utc)
                       + datetime.timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SUTC")
            _write_cache_file(tmpdir, future)
            r = _run_preflight({
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            })
            self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertNotIn("NOT-READY", r.stdout)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_multiple_cache_files_all_valid_is_ready(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-preflight-multi-valid-")
        try:
            future1 = (datetime.datetime.now(datetime.timezone.utc)
                       + datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SUTC")
            future2 = (datetime.datetime.now(datetime.timezone.utc)
                       + datetime.timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SUTC")
            _write_cache_file(tmpdir, future1, name="profile-a.json")
            _write_cache_file(tmpdir, future2, name="profile-b.json")
            r = _run_preflight({
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            })
            self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertNotIn("NOT-READY", r.stdout)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestBedrockSsoExpiredCache(unittest.TestCase):
    """AC 3: an expired SSO cache fails fast, naming both 'expired' and the
    actual expiry timestamp -- never a silent pass, never a bare hang."""

    def test_expired_cache_not_ready_names_expiry(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-preflight-expired-")
        try:
            past_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
            past = past_dt.strftime("%Y-%m-%dT%H:%M:%SUTC")
            _write_cache_file(tmpdir, past)
            r = _run_preflight({
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            })
            self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertIn("expired", r.stdout.lower())
            # The actual expiry timestamp (ISO date component) must appear
            # in the reason, not just the word "expired" -- an operator
            # needs the concrete time to judge how stale the session is.
            self.assertIn(past_dt.strftime("%Y-%m-%d"), r.stdout)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_soonest_expiry_reported_when_multiple_files_mixed(self):
        """One valid + one expired cache file: the preflight reports
        NOT-READY (conservative -- see the function's own doc comment) and
        names the EXPIRED (soonest) one, not the valid one."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-preflight-mixed-")
        try:
            past_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30)
            past = past_dt.strftime("%Y-%m-%dT%H:%M:%SUTC")
            future = (datetime.datetime.now(datetime.timezone.utc)
                      + datetime.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SUTC")
            _write_cache_file(tmpdir, past, name="expired-profile.json")
            _write_cache_file(tmpdir, future, name="valid-profile.json")
            r = _run_preflight({
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            })
            self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestBedrockSsoMissingOrUnparseableCache(unittest.TestCase):
    """A missing cache directory fails fast (nothing to read, cannot claim
    readiness); an empty or fully-unparseable cache directory fails OPEN
    (nothing PROVEN expired -- the preflight only ever blocks on a proven
    expiry, never on an absence of proof)."""

    def test_missing_cache_dir_not_ready(self):
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": "/nonexistent/cache/dir/xyz",
        })
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("no aws sso token cache", r.stdout.lower())

    def test_empty_cache_dir_is_ready(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-preflight-empty-")
        try:
            r = _run_preflight({
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            })
            self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertNotIn("NOT-READY", r.stdout)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_unparseable_json_file_is_ready(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-preflight-unparseable-")
        try:
            with open(os.path.join(tmpdir, "garbage.json"), "w") as f:
                f.write("not valid json{{{")
            r = _run_preflight({
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            })
            self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertNotIn("NOT-READY", r.stdout)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestWalkChainIntegration(unittest.TestCase):
    """End-to-end: a real walk_chain call for role=reviewer with an expired
    SSO cache fails through the SAME degraded-envelope channel every other
    walk_chain failure uses -- distinct 'cause', never conflated with a
    generic infra/unwrap/schema-invalid failure, and never a hang (AC3:
    'not a 30s hang, not a schema/auth misreport')."""

    def test_expired_cache_fails_fast_with_distinct_cause_not_schema_misreport(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-preflight-e2e-")
        try:
            past_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
            past = past_dt.strftime("%Y-%m-%dT%H:%M:%SUTC")
            _write_cache_file(tmpdir, past)

            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir)
            # A `claude` stub that would succeed if ever invoked -- proves
            # the preflight blocks BEFORE any LLM call is attempted at all,
            # not merely that the eventual call also happens to fail.
            claude_stub = os.path.join(bin_dir, "claude")
            with open(claude_stub, "w") as f:
                f.write(textwrap.dedent("""\
                    #!/bin/sh
                    if [ "$1" = "--version" ]; then
                      echo "claude 99.0.0"
                      exit 0
                    fi
                    echo "THIS MUST NEVER RUN" >&2
                    exit 1
                """))
            os.chmod(claude_stub, 0o755)

            script = textwrap.dedent(f"""\
                export PATH='{bin_dir}':"$PATH"
                export CLAGENTIC_REVIEWER_CMD=claude
                _fixture_prompt() {{ printf 'test prompt'; }}
                . '{LLM_CLIENT_SH}'
                printf 'stdin diff content' | walk_chain 'reviewer' 'json' _fixture_prompt
            """)
            env = dict(os.environ)
            env["CLAGENTIC_AUTH_MODE"] = "bedrock-sso"
            env["CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR"] = tmpdir
            env.update(source_env(llm_client=True))
            r = subprocess.run(
                ["sh", "-c", script, LLM_CLIENT_SH],
                capture_output=True,
                text=True,
                cwd=TOOL_HOME,
                env=env,
                timeout=10,  # generous ceiling for "fails within seconds", never 30s+
            )
            # POLARITY FLIP contract (INV-1): a distinct non-zero exit, never 0.
            self.assertEqual(r.returncode, 3, f"stdout={r.stdout!r} stderr={r.stderr!r}")
            self.assertNotIn("THIS MUST NEVER RUN", r.stderr,
                              "the claude stub was invoked -- the preflight did not block before the LLM call")
            envelope = json.loads(r.stdout)
            self.assertTrue(envelope.get("degraded"))
            self.assertEqual(
                envelope.get("cause"), "auth-mode-preflight",
                f"cause must be the distinct 'auth-mode-preflight' label, "
                f"never a generic infra/unwrap cause a caller could mistake "
                f"for a schema or auth misreport. envelope={envelope!r}",
            )
            self.assertIn("expired", envelope.get("summary", "").lower())
            self.assertIn(past_dt.strftime("%Y-%m-%d"), envelope.get("summary", ""))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
