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

lr-3583b5 FIX (freshest-match-per-startUrl, supersedes first-match/soonest-
across-all): the AWS SDK never cleans up stale SSO cache files, so multiple
files per startUrl is the NORMAL steady state. A preflight that resolves
"the" cache file by first-match (readdir/glob/lexical order) or by "soonest
expiry found across ALL files regardless of startUrl" both fail the same way
-- a fresh token for the SAME startUrl sitting alongside a stale leftover
from a prior login is ignored. The fix: enumerate every cache file, resolve
the target startUrl from the AWS profile/config this host would actually
use, restrict to startUrl-matching candidates, and select the one with the
LATEST expiresAt among those -- failing only if THAT one is expired. This
file's class-level test shape (per the task description) proves:
  (a) expired-then-fresh AND fresh-then-expired, same startUrl -- READY in
      both directions, proving the result is independent of file
      enumeration/creation order, not merely "not first-match" in one
      direction.
  (b) multiple startUrls interleaved -- a fresh token for a DIFFERENT
      startUrl is never selected; only same-startUrl candidates count.
  (c) a malformed file alongside a valid fresh one -- skipped, not fatal.
  (d) all-expired (same startUrl) -- NOT-READY, naming the freshest (least
      stale) of the expired candidates.
  (e) empty dir -- NOT-READY (FAIL CLOSED: no candidate exists, nothing is
      proven ready; supersedes the pre-lr-3583b5 fail-OPEN posture for this
      case, which is the class of "assume valid on absence of proof" the
      task description explicitly forbids).
  (f) missing/unreadable cache dir -- NOT-READY, unchanged from before.

This file tests _llm_auth_mode_preflight directly (unit-level, fast) plus
one end-to-end walk_chain integration case proving the failure surfaces
through the SAME degraded-envelope/exit-status channel every other
walk_chain failure uses (AC3's "not a schema/auth misreport" -- the
envelope's own "cause" field must read "auth-mode-preflight", never
"infra"/"unwrap" indistinguishably, and the summary/reason text must name
both the word "expired" and the actual expiry timestamp).

No real AWS dependency, no dependency on the developer's own ~/.aws -- every
test either points AWS_CONFIG_FILE at a fixture file (HOME is also
overridden in every subprocess call so an unset AWS_CONFIG_FILE cannot
accidentally resolve against the developer's real ~/.aws either) or
deliberately leaves it unresolvable to exercise the no-profile-resolved
fallback path.

Run with: python3 -m unittest scripts.test_auth_mode_preflight -v
"""
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Synthetic, obviously-fake startUrls -- never a realistic-looking org
# subdomain, per the task's explicit instruction not to invent one.
START_URL_A = "https://d-fixture-aaaa.awsapps.example/start"
START_URL_B = "https://d-fixture-bbbb.awsapps.example/start"


def _write_cache_file(cache_dir, expires_at, start_url=START_URL_A, name="token.json"):
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, name)
    with open(path, "w") as f:
        json.dump({
            "startUrl": start_url,
            "region": "us-east-1",
            "accessToken": "fixture-not-a-real-token",
            "expiresAt": expires_at,
        }, f)
    return path


def _future(hours=4):
    return (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SUTC")


def _past_dt(hours=1):
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)


def _past(hours=1):
    return _past_dt(hours=hours).strftime("%Y-%m-%dT%H:%M:%SUTC")


def _write_aws_config(home_dir, start_url=START_URL_A, profile="default"):
    """Write a fixture ~/.aws/config declaring one profile whose
    sso_start_url is start_url -- the resolvable-profile case. Returns the
    config file path."""
    aws_dir = os.path.join(home_dir, ".aws")
    os.makedirs(aws_dir, exist_ok=True)
    config_path = os.path.join(aws_dir, "config")
    section = "default" if profile == "default" else f"[profile {profile}]"
    header = "[default]" if profile == "default" else section
    with open(config_path, "w") as f:
        f.write(textwrap.dedent(f"""\
            {header}
            sso_start_url = {start_url}
            sso_region = us-east-1
            region = us-east-1
        """))
    return config_path


def _write_aws_config_sso_session(home_dir, start_url=START_URL_A, session_name="fixture-session"):
    """Write a fixture ~/.aws/config using the newer sso_session
    indirection: [default] sso_session = NAME, [sso-session NAME]
    sso_start_url = ..."""
    aws_dir = os.path.join(home_dir, ".aws")
    os.makedirs(aws_dir, exist_ok=True)
    config_path = os.path.join(aws_dir, "config")
    with open(config_path, "w") as f:
        f.write(textwrap.dedent(f"""\
            [default]
            sso_session = {session_name}
            region = us-east-1

            [sso-session {session_name}]
            sso_start_url = {start_url}
            sso_region = us-east-1
        """))
    return config_path


def _run_preflight(env_extra, home_dir=None):
    """Call _llm_auth_mode_preflight directly and report its return status
    plus $_LLM_AUTH_MODE_PREFLIGHT_REASON on stdout.

    home_dir, when given, is used as HOME for the subprocess AND as the
    resolution root for a default (unset) AWS_CONFIG_FILE -- this keeps
    every test hermetic against the developer's own ~/.aws regardless of
    whether the test wants profile resolution to succeed or to be absent.
    When home_dir is None, HOME is pointed at a fresh empty temp dir with no
    .aws/config at all (the "cannot resolve any profile" fallback case).
    """
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
    env.pop("AWS_CONFIG_FILE", None)
    env.pop("AWS_SHARED_CREDENTIALS_FILE", None)
    env.pop("AWS_PROFILE", None)
    env.pop("AWS_DEFAULT_PROFILE", None)
    env["HOME"] = home_dir if home_dir is not None else tempfile.mkdtemp(prefix="clagentic-test-preflight-home-")
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


class _TempDirCase(unittest.TestCase):
    def setUp(self):
        self._tmpdirs = []

    def tearDown(self):
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    def mkdtemp(self, prefix):
        d = tempfile.mkdtemp(prefix=prefix)
        self._tmpdirs.append(d)
        return d


class TestNoOpForNonBedrockSso(_TempDirCase):
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


class TestBedrockSsoValidCache(_TempDirCase):
    """AC 2: a valid (non-expired) SSO cache is ready."""

    def test_valid_cache_is_ready(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-valid-")
        _write_cache_file(tmpdir, _future())
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        })
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_multiple_cache_files_all_valid_is_ready(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-multi-valid-")
        _write_cache_file(tmpdir, _future(hours=2), name="profile-a.json")
        _write_cache_file(tmpdir, _future(hours=8), name="profile-b.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        })
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)


class TestFreshestMatchPerStartUrl(_TempDirCase):
    """lr-3583b5 core fix: a FRESH cache file for the resolved profile's
    startUrl makes the preflight READY even when a long-expired file for the
    SAME startUrl also sits in the cache dir -- order-independent (proven in
    both file-creation orders) -- and a fresh file for a DIFFERENT startUrl
    is never selected as if it were a match."""

    def test_expired_then_fresh_same_starturl_is_ready(self):
        """Expired file created (alphabetically/temporally) BEFORE the fresh
        one -- proves the fix does not merely reverse first-match to
        last-match."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-order-a-")
        home = self.mkdtemp("clagentic-test-preflight-order-a-home-")
        _write_aws_config(home, start_url=START_URL_A)
        _write_cache_file(tmpdir, _past(hours=999), start_url=START_URL_A, name="aaa-expired.json")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_A, name="zzz-fresh.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_fresh_then_expired_same_starturl_is_ready(self):
        """Fresh file created (alphabetically/temporally) BEFORE the expired
        one -- the opposite enumeration order from the previous test. Both
        must produce the identical READY outcome: the result must not
        depend on which file glob/readdir happens to enumerate first."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-order-b-")
        home = self.mkdtemp("clagentic-test-preflight-order-b-home-")
        _write_aws_config(home, start_url=START_URL_A)
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_A, name="aaa-fresh.json")
        _write_cache_file(tmpdir, _past(hours=999), start_url=START_URL_A, name="zzz-expired.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_fresh_wrong_starturl_not_selected_reports_not_ready(self):
        """The exact field-report reproduction, generalized: an expired file
        for startUrl A sits alongside a FRESH file for a DIFFERENT startUrl
        B. The fresh B file must never be treated as satisfying A -- the
        profile resolves to A, so only the expired A candidate is in scope,
        and the preflight must report NOT-READY naming A's expiry, not
        silently pass because *some* fresh file exists in the directory."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-wrong-url-")
        home = self.mkdtemp("clagentic-test-preflight-wrong-url-home-")
        _write_aws_config(home, start_url=START_URL_A)
        expired_a_dt = _past_dt(hours=1)
        _write_cache_file(tmpdir, expired_a_dt.strftime("%Y-%m-%dT%H:%M:%SUTC"),
                           start_url=START_URL_A, name="a-expired.json")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_B, name="b-fresh.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("expired", r.stdout.lower())
        self.assertIn(expired_a_dt.strftime("%Y-%m-%d"), r.stdout)

    def test_fresh_matching_starturl_selected_over_wrong_starturl_expired(self):
        """Mirror of the previous case: a FRESH file for the resolved
        startUrl A coexists with an EXPIRED file for a different startUrl B.
        The B file must not drag the preflight into NOT-READY -- only A's
        candidates matter."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-interleave-")
        home = self.mkdtemp("clagentic-test-preflight-interleave-home-")
        _write_aws_config(home, start_url=START_URL_A)
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_A, name="a-fresh.json")
        _write_cache_file(tmpdir, _past(hours=1),
                           start_url=START_URL_B, name="b-expired.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_sso_session_indirection_resolves_starturl(self):
        """The newer AWS config shape (profile -> sso_session -> [sso-session
        NAME] -> sso_start_url) resolves the same way as the legacy direct
        sso_start_url-on-profile shape."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-sso-session-")
        home = self.mkdtemp("clagentic-test-preflight-sso-session-home-")
        _write_aws_config_sso_session(home, start_url=START_URL_A)
        _write_cache_file(tmpdir, _past(hours=999), start_url=START_URL_A, name="expired.json")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_A, name="fresh.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_no_resolvable_profile_still_applies_freshest_wins_across_all(self):
        """When the AWS profile/config cannot be resolved at all (no config
        file present), startUrl-scoping is impossible -- every cache file is
        a candidate, but FRESHEST-WINS still applies across all of them
        (this is the documented fallback breadth, distinct from returning
        NOT-READY merely because resolution failed)."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-no-profile-")
        empty_home = self.mkdtemp("clagentic-test-preflight-no-profile-home-")
        _write_cache_file(tmpdir, _past(hours=999), start_url=START_URL_A, name="a-expired.json")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_B, name="b-fresh.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=empty_home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)


class TestBedrockSsoExpiredCache(_TempDirCase):
    """AC 3: an expired SSO cache fails fast, naming both 'expired' and the
    actual expiry timestamp -- never a silent pass, never a bare hang."""

    def test_expired_cache_not_ready_names_expiry(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-expired-")
        past_dt = _past_dt(hours=1)
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
        # The resolved cache path must also be named, so the next person
        # does not have to re-derive which file was consulted.
        self.assertIn(tmpdir, r.stdout)

    def test_all_expired_same_starturl_reports_freshest_of_the_expired(self):
        """(d) from the task's test shape: every candidate for the resolved
        startUrl is expired. NOT-READY, naming the FRESHEST (least stale) of
        the expired candidates -- the most actionable single timestamp,
        consistent with "select the freshest, then check whether even that
        one is expired.\""""
        tmpdir = self.mkdtemp("clagentic-test-preflight-all-expired-")
        home = self.mkdtemp("clagentic-test-preflight-all-expired-home-")
        _write_aws_config(home, start_url=START_URL_A)
        older_dt = _past_dt(hours=999)
        newer_dt = _past_dt(hours=1)
        _write_cache_file(tmpdir, older_dt.strftime("%Y-%m-%dT%H:%M:%SUTC"),
                           start_url=START_URL_A, name="older.json")
        _write_cache_file(tmpdir, newer_dt.strftime("%Y-%m-%dT%H:%M:%SUTC"),
                           start_url=START_URL_A, name="newer.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("expired", r.stdout.lower())
        # Names the NEWER (freshest-of-the-expired) timestamp, not the older one.
        self.assertIn(newer_dt.strftime("%Y-%m-%d"), r.stdout)


class TestBedrockSsoMissingOrUnparseableCache(_TempDirCase):
    """(c)/(e)/(f) from the task's test shape. A missing cache directory
    fails fast (nothing to read, cannot claim readiness). An empty cache
    directory now FAILS CLOSED (lr-3583b5: no candidate exists, so nothing
    is proven ready -- this supersedes the pre-fix fail-open posture for
    this specific case, which is exactly the "assume valid on absence of
    proof" shape the task description forbids). A cache dir with one
    malformed file ALONGSIDE a valid fresh one must not break resolution --
    the malformed file is skipped, not fatal, and the valid one still makes
    the preflight ready. A cache dir with ONLY unparseable files also fails
    closed, same as empty."""

    def test_missing_cache_dir_not_ready(self):
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": "/nonexistent/cache/dir/xyz",
        })
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("no aws sso token cache", r.stdout.lower())

    def test_empty_cache_dir_is_not_ready(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-empty-")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        })
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")

    def test_only_unparseable_json_files_is_not_ready(self):
        """Every file in the cache dir is malformed/non-JSON -- no candidate
        can be proven fresh, so this fails closed exactly like an empty dir
        (same underlying "zero candidates" condition)."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-unparseable-")
        with open(os.path.join(tmpdir, "garbage.json"), "w") as f:
            f.write("not valid json{{{")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        })
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")

    def test_malformed_file_alongside_valid_fresh_is_ready(self):
        """(c) from the task's test shape: a malformed cache file must not
        break resolution when a valid fresh token is present alongside it."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-malformed-plus-valid-")
        with open(os.path.join(tmpdir, "garbage.json"), "w") as f:
            f.write("not valid json{{{")
        _write_cache_file(tmpdir, _future(hours=4), name="valid.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        })
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_unreadable_cache_dir_permission_denied_not_ready(self):
        """(f) from the task's test shape, the permission-denied half of
        'missing/unreadable': a cache dir that exists but cannot be listed
        must not be silently treated as empty-and-therefore-proven-nothing
        in a way that differs from a genuinely empty dir -- both fail
        closed. Skipped when running as root (root bypasses directory
        permission bits, so the fixture cannot actually reproduce
        unreadability)."""
        if os.name != "posix" or hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("requires POSIX permissions and a non-root user")
        tmpdir = self.mkdtemp("clagentic-test-preflight-unreadable-")
        _write_cache_file(tmpdir, _future(hours=4), name="valid.json")
        os.chmod(tmpdir, 0o000)
        try:
            r = _run_preflight({
                "CLAGENTIC_AUTH_MODE": "bedrock-sso",
                "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            })
            self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        finally:
            os.chmod(tmpdir, 0o755)


class TestWalkChainIntegration(_TempDirCase):
    """End-to-end: a real walk_chain call for role=reviewer with an expired
    SSO cache fails through the SAME degraded-envelope channel every other
    walk_chain failure uses -- distinct 'cause', never conflated with a
    generic infra/unwrap/schema-invalid failure, and never a hang (AC3:
    'not a 30s hang, not a schema/auth misreport')."""

    def test_expired_cache_fails_fast_with_distinct_cause_not_schema_misreport(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-e2e-")
        past_dt = _past_dt(hours=2)
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
        env["HOME"] = self.mkdtemp("clagentic-test-preflight-e2e-home-")
        env.pop("AWS_CONFIG_FILE", None)
        env.pop("AWS_SHARED_CREDENTIALS_FILE", None)
        env.pop("AWS_PROFILE", None)
        env.pop("AWS_DEFAULT_PROFILE", None)
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


if __name__ == "__main__":
    unittest.main()
