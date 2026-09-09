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
fail-closed path.

PR #216 review fold-in (four findings, same file/function -- not a separate
task, see the PR's own fold-in-duty framing):
  1. SESSION IDENTITY (TestSessionIdentityCacheKey): the AWS CLI/SDKs key an
     sso_session-backed cache file by SHA1(session_name), NOT by startUrl.
     Filtering by startUrl alone (the lr-3583b5 shape above) can select a
     FRESH sibling session's file while the resolved session's own file is
     expired -- fail-open, the same defect class relocated. Fixed: resolve
     the exact SHA1-keyed file for the resolved session (or the legacy
     startUrl-keyed file for a profile with no sso_session), falling back to
     the startUrl-filtered scan ONLY when neither direct lookup resolves.
  2. NO-PROFILE FALLBACK REVERSED TO FAIL CLOSED
     (test_no_resolvable_profile_fails_closed, formerly asserted the
     opposite): an unresolvable profile is genuine ambiguity under the
     task's own fail-closed mandate. The prior "freshest wins across all
     cache files" fallback for this case is REMOVED, not merely
     supplemented -- this is the one behavior change in this fold-in that
     flips an existing test's assertion rather than adding new coverage.
  3. REASON TEXT NON-POSITIONAL (see the shell-side python3 contract
     comment in llm-client.sh itself): the python3->shell handoff was
     restructured from fixed tab-field positions to newline-delimited
     "key=value" pairs, and several tests here now assert the REASON TEXT
     itself, not just the bare "NOT-READY" marker, for the empty-dir and
     unparseable-only cases specifically (the ones the positional bug
     silently discarded the reason for).
  4. MISSING PYTHON3 FAILS CLOSED (TestNoPython3FailsClosed): this PR moved
     ALL cache/config parsing onto python3 (json.load + configparser, no
     shell-side fallback parser by design) -- a host without python3 now
     performs ZERO validation, so the pre-existing fail-open posture for
     that case became load-bearing under this PR's own change and is fixed
     alongside it.

PR #216 SECOND review fold-in (BOBBIE blocking finding 1 +
nit finding 2, TestPartialSessionResolutionFailsClosed):
  1. PARTIAL SESSION RESOLUTION WAS STILL FAIL-OPEN: a profile declaring
     sso_session = X whose [sso-session X] block is missing, or present but
     lacking sso_start_url, is PARTIAL resolution -- a session name with no
     usable start URL. The pre-fix _resolve_profile() returned this as
     resolved=True, target_start_url=None: an INCOHERENT state that made
     the directory-scan fallback filter (`if target_start_url is not
     None`) a silent no-op, widening the candidate set to every *.json in
     the cache dir, freshest-wins across unrelated sibling sessions -- the
     exact fail-open this task exists to eliminate, reached through
     realistic config drift (a deleted/renamed sso-session block). FIXED:
     _resolve_profile()'s return contract was reworked from a raw tuple
     with representable-incoherent fields to a tagged
     (kind, key, ..., unresolved_reason) contract where "unresolved" is the
     ONLY kind that carries no usable key, and the caller fails closed on
     "unresolved" BEFORE the directory-scan fallback is even reachable --
     see llm-client.sh's own updated _resolve_profile docstring for the
     full kind enumeration ("session"/"legacy"/"none"/"unresolved").
  2. ESCAPING CONSISTENCY (nit): target_start_url is now `!r`-escaped in
     the "no-candidate" reason string, matching session_name and profile
     elsewhere in the same function -- it could never forge a verdict (the
     python3 exit code carries that, not parsed reason text), but
     inconsistent escaping in one function invites a real gap later.

PR #216 THIRD review fold-in (PEACHES finding 1 blocking + finding 2 nit,
PEACHES was blocked on a tooling failure and could not post -- findings
relayed via task lr-3583b5 comment thread):
  1. FOURTH INSTANCE OF THE PATTERN -- UNHANDLED resolve_kind FALLS THROUGH
     TO THE UNFILTERED SCAN: the caller dispatch (`if resolve_kind ==
     "unresolved": ...`) handled the four known kinds but had no matching
     `else` -- an unexpected resolve_kind value fell straight through to
     "every kind other than unresolved reaches here" and on into the
     unfiltered directory scan. Same shape as first-match-wins, the
     no-profile fallback, and partial session resolution before it: an
     absent/unexpected value silently widening the candidate set instead of
     failing closed. FIXED as a totality property: the dispatch is now an
     explicit if/elif chain over all four known kinds plus a final `else`
     that fails closed by construction (NOT-READY, kind
     "resolve-kind-unexpected", reason naming the actual value) -- the scan
     is unreachable from the else branch, not merely avoided by convention.
     TestUnexpectedResolveKindFailsClosed below extracts the REAL embedded
     python3 source verbatim from llm-client.sh and monkeypatches
     _resolve_profile (by appending a redefinition after the extracted
     source -- Python's later-def-wins semantics, not an edit to the
     production file) to return a kind outside the enumeration, proving the
     fix against the actual dispatch code, not a reimplementation of it.
  2. TEST THEATRE (nit): test_directory_scan_never_reached_without_a_filter_
     or_unresolved_state asserted textual str.index() ORDERING in the
     source, not control-flow reachability -- true only because the
     function was flat with no intervening branches; a reordering-
     insensitive refactor could keep it green while breaking the property.
     REPLACED with a real behavioral reachability assertion
     (test_scan_not_entered_for_any_non_none_kind_without_matching_
     candidates, using a decoy fresh token for an unrelated session that
     must NOT be selected) that exercises the actual preflight through
     every resolve_kind, including the unexpected one -- not source text.

Run with: python3 -m unittest scripts.test_auth_mode_preflight -v
"""
import datetime
import hashlib
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


def _sha1_cache_name(cache_key_input):
    """Reproduce the AWS CLI/SDK's own SSO token cache filename derivation:
    SHA1 hex digest of the cache-key input (a session name for sso_session-
    backed profiles, a startUrl for legacy direct profiles), ".json"
    appended. PR #216 finding 1 fixture helper -- writes a cache file at the
    exact path the SDK itself would load, distinct from _write_cache_file's
    arbitrary name (used for the startUrl-scan fallback paths)."""
    return hashlib.sha1(cache_key_input.encode("utf-8")).hexdigest() + ".json"


def _write_session_keyed_cache_file(cache_dir, expires_at, session_name, start_url):
    """Write a cache file at the SHA1(session_name)-derived path -- the
    modern sso_session cache-key mechanism PR #216 finding 1 requires this
    preflight to use, rather than filtering by startUrl alone."""
    return _write_cache_file(cache_dir, expires_at, start_url=start_url,
                              name=_sha1_cache_name(session_name))


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


def _extract_preflight_python_source():
    """Pull the embedded python3 heredoc body VERBATIM out of the real
    llm-client.sh, between the `<<'PY'` that opens it and the line
    containing only `PY` that closes it (scripts/llm-client.sh, inside
    _llm_auth_mode_preflight). This is the exact source _lamp_result runs in
    production -- extracting it (rather than re-typing an equivalent copy)
    is what lets TestUnexpectedResolveKindFailsClosed below prove the fix
    against the real dispatch code, not a reimplementation that could drift
    from it and pass for the wrong reason."""
    with open(LLM_CLIENT_SH) as f:
        lines = f.readlines()
    start = end = None
    for i, line in enumerate(lines):
        if start is None and "<<'PY'" in line:
            start = i + 1
            continue
        if start is not None and line.rstrip("\n") == "PY":
            end = i
            break
    if start is None or end is None:
        raise AssertionError(
            "could not locate the <<'PY' ... PY heredoc block in "
            f"{LLM_CLIENT_SH} -- extraction markers may have drifted"
        )
    return "".join(lines[start:end])


_RESOLVE_CALL_MARKER = (
    "resolve_kind, resolve_key, config_path, creds_path, profile, "
    "unresolved_reason = _resolve_profile()"
)


def _run_preflight_python_with_resolve_kind_override(tmpdir, override_src):
    """Run the REAL embedded preflight python source, with _resolve_profile
    REDEFINED between its own definition and the single call site that
    invokes it (`resolve_kind, ... = _resolve_profile()`, the
    _RESOLVE_CALL_MARKER line) -- Python's later-def-wins name binding, not
    a mutation of the original function object or an edit to llm-client.sh
    itself. The extracted source is split at that exact call-site line (the
    first executable statement after every def in the file), the override
    def is spliced in immediately before it, and the call then binds to the
    override -- proving the fix against the REAL dispatch code that follows
    (the if/elif/else over resolve_kind), not a reimplementation of it that
    could drift and pass for the wrong reason.

    Splitting at the call site (rather than appending after the whole
    script, which would run too late -- the real call already executed by
    then) is required because _resolve_profile() is invoked as the first
    statement of the script body, not merely defined and left for a test
    harness to call separately.

    Returns the completed subprocess.CompletedProcess; stdout carries the
    newline-delimited key=value contract on NOT-READY (exit 1), nothing on
    READY (exit 0) -- same contract _llm_auth_mode_preflight's shell side
    parses from $_lamp_result.
    """
    base_src = _extract_preflight_python_source()
    if _RESOLVE_CALL_MARKER not in base_src:
        raise AssertionError(
            "the _resolve_profile() call-site line has drifted from the "
            "expected text -- update _RESOLVE_CALL_MARKER to match "
            "llm-client.sh's current source"
        )
    before, after = base_src.split(_RESOLVE_CALL_MARKER, 1)
    full_src = before + override_src + "\n\n" + _RESOLVE_CALL_MARKER + after
    r = subprocess.run(
        [sys.executable, "-", tmpdir],
        input=full_src,
        capture_output=True,
        text=True,
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
        home = self.mkdtemp("clagentic-test-preflight-valid-home-")
        _write_aws_config(home, start_url=START_URL_A)
        _write_cache_file(tmpdir, _future(), start_url=START_URL_A)
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_multiple_cache_files_all_valid_is_ready(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-multi-valid-")
        home = self.mkdtemp("clagentic-test-preflight-multi-valid-home-")
        _write_aws_config(home, start_url=START_URL_A)
        _write_cache_file(tmpdir, _future(hours=2), start_url=START_URL_A, name="profile-a.json")
        _write_cache_file(tmpdir, _future(hours=8), start_url=START_URL_A, name="profile-b.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
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

    def test_no_resolvable_profile_fails_closed(self):
        """PR #216 finding 2 (reverses the pre-fold-in behavior this test
        used to assert): when the AWS profile/config cannot be resolved at
        all (no config file present), that is GENUINE AMBIGUITY under the
        task's own fail-closed mandate -- there is no way to know which
        cache file, if any, corresponds to the profile that will actually be
        used at call time. The prior "freshest wins across all files"
        fallback here masked exactly this: a fresh token for an unrelated
        profile/startUrl could make the preflight report READY while the
        actually-active profile's own credential state was never examined.
        NOT-READY, naming which config path(s) were consulted and which
        profile name was sought -- never a silent pass merely because SOME
        fresh file exists somewhere in the cache dir."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-no-profile-")
        empty_home = self.mkdtemp("clagentic-test-preflight-no-profile-home-")
        _write_cache_file(tmpdir, _past(hours=999), start_url=START_URL_A, name="a-expired.json")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_B, name="b-fresh.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=empty_home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        # Names the profile that was sought and the config path(s)
        # consulted -- an operator must not be left with a bare "not-ready"
        # after this fold-in's finding 3 fix either.
        self.assertIn("default", r.stdout)
        self.assertIn(os.path.join(empty_home, ".aws", "config"), r.stdout)


class TestSessionIdentityCacheKey(_TempDirCase):
    """PR #216 finding 1: modern AWS SDKs key the SSO token cache by
    SHA1(session_name), NOT by startUrl -- two sso_sessions can share a
    startUrl while using SEPARATE cache files. Filtering candidates by
    startUrl alone (this preflight's behavior before this fold-in) can
    select a FRESH sibling session's file while the RESOLVED session's own
    file is expired, reporting READY on an actually-expired credential --
    fail-open, the exact defect class lr-3583b5 exists to close, just
    relocated from "first match wins" to "wrong match wins"."""

    def test_two_sessions_share_starturl_resolved_expired_sibling_fresh_is_not_ready(self):
        """The reproduction PEACHES built the finding on: sso_session "a"
        (the resolved/active one) and sso_session "b" (a sibling, unrelated
        to the active profile) share one startUrl. Session "a"'s own
        SHA1-keyed cache file is expired; session "b"'s is fresh. Because
        the ACTIVE profile resolves to session "a", only "a"'s own cache
        file may be consulted -- "b"'s freshness must never leak in via a
        startUrl match. MUST fail without the fix (pre-fix code filtered by
        startUrl alone and would have found "b"'s fresh file a "match")."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-session-key-")
        home = self.mkdtemp("clagentic-test-preflight-session-key-home-")

        aws_dir = os.path.join(home, ".aws")
        os.makedirs(aws_dir, exist_ok=True)
        with open(os.path.join(aws_dir, "config"), "w") as f:
            f.write(textwrap.dedent(f"""\
                [default]
                sso_session = session-a
                region = us-east-1

                [profile other]
                sso_session = session-b
                region = us-east-1

                [sso-session session-a]
                sso_start_url = {START_URL_A}
                sso_region = us-east-1

                [sso-session session-b]
                sso_start_url = {START_URL_A}
                sso_region = us-east-1
            """))

        expired_dt = _past_dt(hours=1)
        _write_session_keyed_cache_file(
            tmpdir, expired_dt.strftime("%Y-%m-%dT%H:%M:%SUTC"),
            session_name="session-a", start_url=START_URL_A,
        )
        _write_session_keyed_cache_file(
            tmpdir, _future(hours=4),
            session_name="session-b", start_url=START_URL_A,
        )

        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            "AWS_PROFILE": "default",
        }, home_dir=home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("expired", r.stdout.lower())
        self.assertIn(expired_dt.strftime("%Y-%m-%d"), r.stdout)

    def test_two_sessions_share_starturl_resolved_fresh_sibling_expired_is_ready(self):
        """Mirror of the previous case: the resolved session's OWN file is
        fresh even though a sibling session sharing the same startUrl is
        expired. The sibling's staleness must never drag the resolved
        session into NOT-READY -- only the resolved session's own
        SHA1-keyed file matters."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-session-key-mirror-")
        home = self.mkdtemp("clagentic-test-preflight-session-key-mirror-home-")

        aws_dir = os.path.join(home, ".aws")
        os.makedirs(aws_dir, exist_ok=True)
        with open(os.path.join(aws_dir, "config"), "w") as f:
            f.write(textwrap.dedent(f"""\
                [default]
                sso_session = session-a
                region = us-east-1

                [sso-session session-a]
                sso_start_url = {START_URL_A}
                sso_region = us-east-1

                [sso-session session-b]
                sso_start_url = {START_URL_A}
                sso_region = us-east-1
            """))

        _write_session_keyed_cache_file(
            tmpdir, _future(hours=4),
            session_name="session-a", start_url=START_URL_A,
        )
        _write_session_keyed_cache_file(
            tmpdir, _past(hours=999),
            session_name="session-b", start_url=START_URL_A,
        )

        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            "AWS_PROFILE": "default",
        }, home_dir=home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)

    def test_legacy_profile_without_sso_session_keys_by_starturl(self):
        """The legacy shape (sso_start_url set directly on the profile, no
        sso_session indirection) has no session name to hash -- the SDK
        keys its cache file by SHA1(startUrl) instead, and this preflight
        must match that convention (not SHA1 of anything else) for the
        direct-lookup path to find it."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-legacy-key-")
        home = self.mkdtemp("clagentic-test-preflight-legacy-key-home-")
        _write_aws_config(home, start_url=START_URL_A)
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_A,
                           name=_sha1_cache_name(START_URL_A))
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("NOT-READY", r.stdout)


class TestPartialSessionResolutionFailsClosed(_TempDirCase):
    """PR #216 (fold-in #2) finding 1: a profile can declare sso_session = X
    while the referenced [sso-session X] block is missing entirely, or is
    present but itself lacks sso_start_url. Both are PARTIAL resolution --
    a session name with no usable start URL -- which the pre-fix
    _resolve_profile() reported as resolved=True with target_start_url=None,
    an incoherent state that made the directory-scan fallback's
    `if target_start_url is not None` filter a no-op, silently widening the
    candidate set to every *.json in the cache dir (freshest-wins across
    unrelated sibling sessions -- the exact fail-open this task exists to
    close, reached through realistic config drift: a profile referencing a
    session block someone deleted or renamed).

    Both cases below MUST fail NOT-READY, naming the unresolvable session,
    and must NEVER be satisfied by an unrelated fresh cache file elsewhere
    in the directory -- without the fix, both would incorrectly report
    READY off of the sibling's freshness."""

    def test_sso_session_block_missing_entirely_fails_closed(self):
        """default declares sso_session = ghost-session, but no
        [sso-session ghost-session] block exists anywhere in the config --
        deleted or renamed out from under the profile. A fresh, totally
        unrelated cache file sits in the directory; it must never be
        selected as if it satisfied the unresolvable profile."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-missing-session-block-")
        home = self.mkdtemp("clagentic-test-preflight-missing-session-block-home-")

        aws_dir = os.path.join(home, ".aws")
        os.makedirs(aws_dir, exist_ok=True)
        with open(os.path.join(aws_dir, "config"), "w") as f:
            f.write(textwrap.dedent("""\
                [default]
                sso_session = ghost-session
                region = us-east-1
            """))

        # An unrelated fresh cache file -- MUST NOT be picked up by a
        # widened, unfiltered directory scan.
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_B,
                           name="unrelated-fresh.json")

        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            "AWS_PROFILE": "default",
        }, home_dir=home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("ghost-session", r.stdout)
        self.assertIn("default", r.stdout)

    def test_sso_session_block_present_without_start_url_fails_closed(self):
        """default declares sso_session = incomplete-session, and
        [sso-session incomplete-session] EXISTS but has no sso_start_url of
        its own (e.g. sso_region only) -- still unresolvable, same failure
        class as the missing-block case, must not be conflated with a
        legitimate 'profile declares neither mechanism' (kind 'none') which
        DOES fall back to an unfiltered scan legitimately."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-incomplete-session-block-")
        home = self.mkdtemp("clagentic-test-preflight-incomplete-session-block-home-")

        aws_dir = os.path.join(home, ".aws")
        os.makedirs(aws_dir, exist_ok=True)
        with open(os.path.join(aws_dir, "config"), "w") as f:
            f.write(textwrap.dedent("""\
                [default]
                sso_session = incomplete-session
                region = us-east-1

                [sso-session incomplete-session]
                sso_region = us-east-1
            """))

        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_B,
                           name="unrelated-fresh.json")

        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
            "AWS_PROFILE": "default",
        }, home_dir=home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("incomplete-session", r.stdout)
        self.assertIn("default", r.stdout)

    def test_scan_not_entered_for_unresolved_or_unexpected_kind_decoy_never_selected(self):
        """PR #216 THIRD fold-in, PEACHES finding 2: replaces the prior
        source-order str.index() assertion (theatre -- true only because the
        function was flat with no intervening branches; a reordering-
        insensitive refactor could keep it green while breaking the
        property). This is a REAL behavioral reachability assertion: for
        both resolve_kind states that must never reach the unfiltered
        directory scan ("unresolved" via a genuinely unresolvable profile,
        and an out-of-enumeration kind via the fault-injection harness), a
        DECOY fresh cache file for an unrelated session is seeded in the
        cache dir. If the scan were ever reached for either state, the
        decoy's freshness would make the preflight report READY (the
        unfiltered scan matches everything when no filter is active) -- so
        asserting NOT-READY, with a reason that names the actual failure
        (not the decoy), is a direct behavioral proof the scan was never
        entered, observed through the preflight's own output rather than
        through source text."""
        # State 1: resolve_kind == "unresolved" (no config file at all).
        tmpdir = self.mkdtemp("clagentic-test-scan-unreached-unresolved-")
        empty_home = self.mkdtemp("clagentic-test-scan-unreached-unresolved-home-")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_B,
                           name="decoy-fresh.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=empty_home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("decoy-fresh.json", r.stdout)

        # State 2: an out-of-enumeration resolve_kind (fault-injected --
        # _resolve_profile can never actually return this today; see
        # TestUnexpectedResolveKindFailsClosed for the fuller version of
        # this same harness). Reuses the identical decoy-selection proof.
        tmpdir2 = self.mkdtemp("clagentic-test-scan-unreached-unexpected-")
        _write_cache_file(tmpdir2, _future(hours=4), start_url=START_URL_B,
                           name="decoy-fresh.json")
        override_src = textwrap.dedent("""\
            def _resolve_profile():
                return "bogus-kind-from-test", None, "/fixture/config", "/fixture/creds", "default", None
        """)
        r2 = _run_preflight_python_with_resolve_kind_override(tmpdir2, override_src)
        self.assertEqual(r2.returncode, 1, f"stdout={r2.stdout!r} stderr={r2.stderr!r}")
        self.assertIn("kind=resolve-kind-unexpected", r2.stdout)
        self.assertNotIn("decoy-fresh.json", r2.stdout)


class TestUnexpectedResolveKindFailsClosed(unittest.TestCase):
    """PR #216 THIRD fold-in, PEACHES finding 1 (BLOCKING): the caller
    dispatch over resolve_kind handled the four known kinds (session,
    legacy, none, unresolved) but had no exhaustiveness guard -- an
    unexpected resolve_kind value fell through to the unfiltered directory
    scan (fail-open, the fourth instance of this preflight's recurring
    pattern). Uses _run_preflight_python_with_resolve_kind_override to force
    _resolve_profile to return a value outside the closed enumeration
    against the REAL, unmodified dispatch code extracted from llm-client.sh
    -- proving the fix by execution, not by inspection. MUST FAIL without
    the fix (pre-fix code has no else branch at all; the override would
    silently reach the scan and, depending on what's in the cache dir,
    either report READY off an unrelated file or NOT-READY with a
    "no-candidate" reason that never names the unexpected kind)."""

    def setUp(self):
        self._tmpdirs = []

    def tearDown(self):
        for d in self._tmpdirs:
            shutil.rmtree(d, ignore_errors=True)

    def mkdtemp(self, prefix):
        d = tempfile.mkdtemp(prefix=prefix)
        self._tmpdirs.append(d)
        return d

    def test_unexpected_kind_reports_not_ready_naming_the_kind(self):
        tmpdir = self.mkdtemp("clagentic-test-unexpected-kind-")
        override_src = textwrap.dedent("""\
            def _resolve_profile():
                return "totally-unexpected-kind", None, "/fixture/config", "/fixture/creds", "default", None
        """)
        r = _run_preflight_python_with_resolve_kind_override(tmpdir, override_src)
        self.assertEqual(r.returncode, 1, f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("status=not-ready", r.stdout)
        self.assertIn("kind=resolve-kind-unexpected", r.stdout)
        self.assertIn("totally-unexpected-kind", r.stdout,
                       "the reason must name the actual unexpected value, "
                       "not a generic message")

    def test_unexpected_kind_never_selects_a_decoy_fresh_file(self):
        """The scan-reachability half of the proof: even with a fresh,
        otherwise-selectable cache file sitting in the directory, an
        unexpected resolve_kind must never reach the unfiltered scan that
        would pick it up. Without the fix, the fall-through path reaches
        `if freshest_path is None:` with target_start_url/session_name
        undefined-or-None depending on how far the incoherent state
        propagates -- this test does not assume which failure shape the
        unfixed code takes, only that the decoy must never be reported as
        satisfying readiness."""
        tmpdir = self.mkdtemp("clagentic-test-unexpected-kind-decoy-")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_A,
                           name="decoy-fresh.json")
        override_src = textwrap.dedent("""\
            def _resolve_profile():
                return "totally-unexpected-kind", None, "/fixture/config", "/fixture/creds", "default", None
        """)
        r = _run_preflight_python_with_resolve_kind_override(tmpdir, override_src)
        self.assertEqual(r.returncode, 1, f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("kind=resolve-kind-unexpected", r.stdout)
        self.assertNotIn("decoy-fresh.json", r.stdout)
        self.assertNotIn("status=ready", r.stdout)


class TestBedrockSsoExpiredCache(_TempDirCase):
    """AC 3: an expired SSO cache fails fast, naming both 'expired' and the
    actual expiry timestamp -- never a silent pass, never a bare hang."""

    def test_expired_cache_not_ready_names_expiry(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-expired-")
        home = self.mkdtemp("clagentic-test-preflight-expired-home-")
        _write_aws_config(home, start_url=START_URL_A)
        past_dt = _past_dt(hours=1)
        past = past_dt.strftime("%Y-%m-%dT%H:%M:%SUTC")
        _write_cache_file(tmpdir, past, start_url=START_URL_A)
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
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
        home = self.mkdtemp("clagentic-test-preflight-empty-home-")
        _write_aws_config(home, start_url=START_URL_A)
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        # PR #216 finding 3: the REASON text must survive, not just the bare
        # "NOT-READY" marker -- an empty dir is not the same problem as a
        # missing dir or an expired cache, and the operator must be told
        # which one they hit, not left with an opaque lockout.
        self.assertIn("no aws sso cache file with a parseable expiresat", r.stdout.lower())

    def test_only_unparseable_json_files_is_not_ready(self):
        """Every file in the cache dir is malformed/non-JSON -- no candidate
        can be proven fresh, so this fails closed exactly like an empty dir
        (same underlying "zero candidates" condition)."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-unparseable-")
        home = self.mkdtemp("clagentic-test-preflight-unparseable-home-")
        _write_aws_config(home, start_url=START_URL_A)
        with open(os.path.join(tmpdir, "garbage.json"), "w") as f:
            f.write("not valid json{{{")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        # Same finding-3 strengthening: the reason must be present, not
        # discarded -- this exercises a different code path (every file
        # present but none parseable) than the empty-dir case above.
        self.assertIn("no aws sso cache file with a parseable expiresat", r.stdout.lower())

    def test_malformed_file_alongside_valid_fresh_is_ready(self):
        """(c) from the task's test shape: a malformed cache file must not
        break resolution when a valid fresh token is present alongside it."""
        tmpdir = self.mkdtemp("clagentic-test-preflight-malformed-plus-valid-")
        home = self.mkdtemp("clagentic-test-preflight-malformed-plus-valid-home-")
        _write_aws_config(home, start_url=START_URL_A)
        with open(os.path.join(tmpdir, "garbage.json"), "w") as f:
            f.write("not valid json{{{")
        _write_cache_file(tmpdir, _future(hours=4), start_url=START_URL_A, name="valid.json")
        r = _run_preflight({
            "CLAGENTIC_AUTH_MODE": "bedrock-sso",
            "CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR": tmpdir,
        }, home_dir=home)
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


class TestNoPython3FailsClosed(_TempDirCase):
    """PR #216 finding 4: this preflight's ENTIRE cache/config parsing path
    is python3's json.load + configparser (no fallback parser, by design --
    see AGENTS.md/the constraints: never hand-roll a shell JSON parser).
    Pre-fold-in, a host with no python3 on PATH reported READY unconditionally
    -- ZERO validation performed, silently. This PR moves ALL cache parsing
    onto python3, so that fail-open became load-bearing rather than a
    pre-existing, unrelated quirk: fold-in scope, same file, same function,
    same failure class as findings 1/2/3. NOT-READY, naming the missing
    interpreter, is the fix."""

    def test_missing_python3_reports_not_ready_naming_interpreter(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-no-python3-")
        home = self.mkdtemp("clagentic-test-preflight-no-python3-home-")
        _write_cache_file(tmpdir, _future(hours=4))

        # A PATH containing only a handful of POSIX coreutils (via symlinks
        # to the real binaries) and NO python3 -- `sh` itself must still be
        # reachable to run the preflight at all. This deliberately does NOT
        # rely on `command -v python3` failing by chance; it constructs a
        # PATH that structurally cannot resolve python3.
        fake_bin = self.mkdtemp("clagentic-test-preflight-no-python3-bin-")
        for tool in ("sh", "cat", "printf", "test", "cut", "date", "mkdir",
                     "rm", "ls", "grep", "sed", "true", "false", "expr",
                     "dirname", "basename", "uname", "id", "env", "sort",
                     "head", "tail", "wc", "tr", "mktemp"):
            real = shutil.which(tool)
            if real:
                try:
                    os.symlink(real, os.path.join(fake_bin, tool))
                except OSError:
                    pass

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
        env["HOME"] = home
        env["CLAGENTIC_AUTH_MODE"] = "bedrock-sso"
        env["CLAGENTIC_AUTH_MODE_SSO_CACHE_DIR"] = tmpdir
        env["PATH"] = fake_bin
        r = subprocess.run(
            ["sh", "-c", script, LLM_CLIENT_SH],
            capture_output=True,
            text=True,
            cwd=TOOL_HOME,
            env=env,
            timeout=30,
        )
        self.assertIn("NOT-READY", r.stdout, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("python3", r.stdout.lower())


class TestWalkChainIntegration(_TempDirCase):
    """End-to-end: a real walk_chain call for role=reviewer with an expired
    SSO cache fails through the SAME degraded-envelope channel every other
    walk_chain failure uses -- distinct 'cause', never conflated with a
    generic infra/unwrap/schema-invalid failure, and never a hang (AC3:
    'not a 30s hang, not a schema/auth misreport')."""

    def test_expired_cache_fails_fast_with_distinct_cause_not_schema_misreport(self):
        tmpdir = self.mkdtemp("clagentic-test-preflight-e2e-")
        home = self.mkdtemp("clagentic-test-preflight-e2e-home-")
        _write_aws_config(home, start_url=START_URL_A)
        past_dt = _past_dt(hours=2)
        past = past_dt.strftime("%Y-%m-%dT%H:%M:%SUTC")
        _write_cache_file(tmpdir, past, start_url=START_URL_A)

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
        env["HOME"] = home
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
