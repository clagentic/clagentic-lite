"""
Acceptance tests for lr-b82538: prompt-inject.sh.template emitted its
UserPromptSubmit payload by raw string concatenation, so any successful
recall (KEYWORDS is newline-separated by construction, MATCHES is
multi-row sqlite3 output that can carry embedded newlines/quotes/control
bytes) produced invalid JSON. Severity was inverted: the hook is
documented always-exit-0-on-failure and honored that on every FAILURE
path, but broke exactly on SUCCESS -- the feature never worked for any
user with a populated memory database.

The fix is a CLASS fix, not a site fix (AGENTS.md non-negotiable 8):
ds_json_escape (scripts/platform.sh) is hoisted verbatim from
session-start.sh.template's own correct, already-portable escaper, and
every JSON-emitting shim (session-start, prompt-inject, post-tool-nudge)
now calls it instead of carrying its own copy.

Six tests below are the reporter's own acceptance criteria, adopted
as-is (task lr-b82538, comment #1):
  1. Hostile payload (double-quote, backslash, literal newline, tab,
     0x07) in a seeded memory row: every JSON-emitting shim's stdout
     parses under a real json parser, exit 0.
  2. Five keywords: stdout parses and additionalContext contains all
     five ON ONE LINE (comma-space joined, not the old newline list).
  3. Empty-result path unchanged: exit 0, no stdout.
  4. CLAGENTIC_DISABLE_RECALL=1: exit 0, no stdout (prompt-inject only
     -- the only shim with this env var).
  5. platform.sh unavailable: exit 0, no stdout (existing behavior).
  6. Regression guard: every shim template containing "additionalContext"
     must also contain "_json_escape" or "ds_json_escape" -- a real test,
     not a comment, discovered via `git ls-files` against the TRACKED,
     SHIPPED set (never glob.glob() against the filesystem, and never a
     hardcoded site list), per AGENTS.md's "Sweeping-test discovery
     convention".

Non-goals (reporter's, honored): no change to recall ranking, the FTS5
path, the keyword filter, the SQL escaping, or the MIN_KEYWORDS gate; the
two guard hooks (pre-bash-guard, pre-write-guard) are NOT touched -- they
correctly emit no JSON (exit 2 + stderr) and are excluded from test 6's
sweep by construction (they contain neither marker string, which is a
PASS for the sweep, not a gap -- see test 6's own assertion shape).

Run with: python3 -m unittest scripts/test_hook_json_emission_acceptance.py -v
"""
import json
import os
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HOOK_SHIMS_DIR = os.path.join(TOOL_HOME, "share", "hook-shims")
MEMORY_SH = os.path.join(TOOL_HOME, "scripts", "memory.sh")

PROMPT_INJECT = os.path.join(HOOK_SHIMS_DIR, "prompt-inject.sh.template")
SESSION_START = os.path.join(HOOK_SHIMS_DIR, "session-start.sh.template")
POST_TOOL_NUDGE = os.path.join(HOOK_SHIMS_DIR, "post-tool-nudge.sh.template")

# Hostile payload: double-quote, backslash, literal newline, tab, and a
# 0x07 (BEL) control byte -- exactly the reporter's test-1 spec.
HOSTILE_SUMMARY = 'has "quotes" and \\backslash\\ and\nnewline\tand\x07bell'


def _init_repo(tmp):
    subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)


def _mem_env(tmp, **overrides):
    env = dict(os.environ)
    env["CLAGENTIC_PROJECT_ROOT"] = tmp
    env["HOME"] = os.environ.get("HOME", "/root")
    env.update(overrides)
    return env


def _seed_memory_db(tmp, summary, tags="seed", extra_rows=None):
    """Seed .clagentic/lite/memory.db via the real memory.sh CLI (init +
    log-turn), matching test_fts5_recall.py's convention. `extra_rows`, if
    given, is a list of (summary, tags) tuples logged after the primary
    row, newest-first in ORDER BY ts DESC (LIMIT 3 in the hooks)."""
    env = _mem_env(tmp)
    subprocess.run(["sh", MEMORY_SH, "init"], env=env, capture_output=True,
                    text=True, check=True)
    subprocess.run(
        ["sh", MEMORY_SH, "log-turn", summary, tags, "seed"],
        env=env, capture_output=True, text=True, check=True,
    )
    for extra_summary, extra_tags in (extra_rows or []):
        subprocess.run(
            ["sh", MEMORY_SH, "log-turn", extra_summary, extra_tags, "seed"],
            env=env, capture_output=True, text=True, check=True,
        )


def _run_shim(template_path, cwd, payload=None, env_overrides=None):
    env = dict(os.environ)
    env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
    env["HOME"] = os.environ.get("HOME", "/root")
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    if env_overrides:
        env.update(env_overrides)
    stdin_bytes = None
    if payload is not None:
        stdin_bytes = json.dumps(payload).encode() if isinstance(payload, dict) else payload
    return subprocess.run(
        ["/bin/sh", template_path],
        input=stdin_bytes,
        capture_output=True,
        env=env,
        cwd=cwd,
        timeout=30,
    )


class _RepoFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-json-emit-")
        _init_repo(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)


class TestAcceptance1HostilePayloadParses(_RepoFixture):
    """A memory row containing a double-quote, backslash, literal newline,
    tab, and 0x07 must not break JSON emission -- every shim whose
    additionalContext could carry it must produce parseable stdout."""

    def test_prompt_inject_hostile_summary_parses(self):
        _seed_memory_db(self._tmp, HOSTILE_SUMMARY, tags="findme")
        result = _run_shim(
            PROMPT_INJECT, self._tmp,
            payload={"prompt": "please find findme term now"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        stdout = result.stdout.decode()
        self.assertTrue(stdout.strip(), f"expected stdout, got none. stderr={result.stderr!r}")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"prompt-inject stdout did not parse as JSON: {exc}\nstdout={stdout!r}")
        self.assertIn("additionalContext", payload)
        self.assertIn("quotes", payload["additionalContext"])

    def test_session_start_hostile_summary_parses(self):
        _seed_memory_db(self._tmp, HOSTILE_SUMMARY, tags="findme")
        result = _run_shim(
            SESSION_START, self._tmp,
            env_overrides={"CLAGENTIC_SKIP_UPDATE_ALERT": "1"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        stdout = result.stdout.decode()
        self.assertTrue(stdout.strip(), f"expected stdout, got none. stderr={result.stderr!r}")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"session-start stdout did not parse as JSON: {exc}\nstdout={stdout!r}")
        self.assertIn("additionalContext", payload)
        self.assertIn("quotes", payload["additionalContext"])


class TestAcceptance2KeywordsJoinedOneLine(_RepoFixture):
    """Five keywords: stdout parses and additionalContext contains all
    five on one line (comma-space joined), not the old broken newline
    list."""

    def test_five_keywords_all_on_one_line(self):
        _seed_memory_db(
            self._tmp,
            "alpha bravo charlie delta echo session notes",
            tags="alpha bravo charlie delta echo",
        )
        result = _run_shim(
            PROMPT_INJECT, self._tmp,
            payload={"prompt": "alpha bravo charlie delta echo please"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        stdout = result.stdout.decode()
        payload = json.loads(stdout)
        ctx = payload["additionalContext"]
        for kw in ("alpha", "bravo", "charlie", "delta", "echo"):
            self.assertIn(kw, ctx, f"expected keyword {kw!r} in additionalContext: {ctx!r}")
        # "on one line": the bracketed keyword list segment itself must not
        # contain a literal (unescaped) newline byte -- the defect was a RAW
        # 0x0A landing inside the JSON string; the escaped stdout string
        # must not have re-introduced one via decoding a broken payload.
        prefix = ctx.split("]:")[0]
        self.assertNotIn("\n", prefix, f"keyword segment spans multiple lines: {prefix!r}")
        # Comma-space joined, not the old newline-separated shape.
        self.assertIn(", ", prefix, f"expected comma-space-joined keywords: {prefix!r}")


class TestAcceptance3EmptyResultUnchanged(_RepoFixture):
    """No matching memory rows: exit 0, no stdout -- unchanged behavior."""

    def test_no_match_no_stdout(self):
        _seed_memory_db(self._tmp, "totally unrelated content here", tags="other")
        result = _run_shim(
            PROMPT_INJECT, self._tmp,
            payload={"prompt": "zzzznomatch yyyynotfound xxxxabsent wwwwgone"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout, b"", f"expected no stdout, got {result.stdout!r}")


class TestAcceptance4DisableRecallEnvVar(_RepoFixture):
    """CLAGENTIC_DISABLE_RECALL=1: exit 0, no stdout."""

    def test_disable_recall_short_circuits(self):
        _seed_memory_db(self._tmp, HOSTILE_SUMMARY, tags="findme")
        result = _run_shim(
            PROMPT_INJECT, self._tmp,
            payload={"prompt": "please find findme term now"},
            env_overrides={"CLAGENTIC_DISABLE_RECALL": "1"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout, b"", f"expected no stdout, got {result.stdout!r}")


class TestAcceptance5PlatformShUnavailable(_RepoFixture):
    """platform.sh unavailable (CLAGENTIC_LITE_HOME does not resolve to a
    real checkout): exit 0, no stdout -- existing pre-lr-b82538 behavior at
    prompt-inject.sh.template's own "unavailable" branch, unchanged."""

    def test_missing_platform_sh_short_circuits(self):
        _seed_memory_db(self._tmp, HOSTILE_SUMMARY, tags="findme")
        bogus_home = os.path.join(self._tmp, "nonexistent-clagentic-home")
        result = _run_shim(
            PROMPT_INJECT, self._tmp,
            payload={"prompt": "please find findme term now"},
            env_overrides={"CLAGENTIC_LITE_HOME": bogus_home},
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"", f"expected no stdout, got {result.stdout!r}")


class TestSessionStartEscaperUnavailableFailsClosed(_RepoFixture):
    """PR #210 fold-in (lr-b82538, BOBBIE finding 1 / PEACHES finding 1,
    two independent confirmations plus a PEACHES repro): session-start.sh
    .template's escaper-unavailable branch previously set CONTEXT_JSON to
    the raw, unescaped CONTEXT and emitted it -- CONTEXT can carry
    untrusted sqlite3 summary text. Same technique as
    TestAcceptance5PlatformShUnavailable (bogus CLAGENTIC_LITE_HOME so
    platform.sh never sources and ds_json_escape is undefined), but with a
    seeded memory row so CONTEXT is non-empty and the branch under test is
    actually reached -- must now fail CLOSED (exit 0, no stdout), not emit
    broken JSON."""

    def test_missing_platform_sh_with_nonempty_context_emits_nothing(self):
        _seed_memory_db(self._tmp, HOSTILE_SUMMARY, tags="findme")
        bogus_home = os.path.join(self._tmp, "nonexistent-clagentic-home")
        result = _run_shim(
            SESSION_START, self._tmp,
            env_overrides={
                "CLAGENTIC_LITE_HOME": bogus_home,
                "CLAGENTIC_SKIP_UPDATE_ALERT": "1",
            },
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout, b"",
            f"expected fail-closed (no stdout) when ds_json_escape is "
            f"unavailable, got {result.stdout!r} -- this must never be the "
            f"raw, unescaped CONTEXT string",
        )


def _write_failing_python3_stub(bin_dir):
    """A `python3` stub that always exits nonzero with no stdout, placed
    ahead of the real python3 on PATH. Exercises ds_json_escape's OWN
    runtime failure (`command -v python3` succeeds, the python3 -c call
    itself fails) -- distinct from platform.sh-unavailable (where
    ds_json_escape is undefined entirely). This is the branch
    post-tool-nudge.sh.template's `_json_escape` wrapper previously papered
    over with `|| printf '%s' "$1"`, falling back to the raw, unescaped
    value on ANY failure (BOBBIE finding 2, PR #210, lr-b82538 fold-in)."""
    path = os.path.join(bin_dir, "python3")
    with open(path, "w") as f:
        f.write("#!/bin/sh\ncat >/dev/null 2>&1\nexit 1\n")
    os.chmod(path, 0o755)
    return path


class TestPostToolNudgeEscaperFailureFailsClosed(unittest.TestCase):
    """PR #210 fold-in (lr-b82538, BOBBIE finding 2): post-tool-nudge.sh
    .template's local _json_escape wrapper fell back to the RAW unescaped
    value on ANY ds_json_escape failure (stderr swallowed, OR-fallback
    fires), not merely unavailability -- reachable via the git-workflow
    nudge message (section 2, GIT_MSG) whenever ds_json_escape itself
    errors at runtime. A failing `python3` stub ahead of the real one on
    PATH forces exactly that: `command -v python3` succeeds so
    ds_json_escape takes the python3 branch, which then fails. Must now
    fail closed: that message segment is dropped (empty), not emitted raw
    -- proven here by asserting the raw GIT_MSG text never reaches stdout,
    and that whatever ships still parses as JSON."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-json-emit-ptn-")
        _init_repo(self._tmp)
        os.makedirs(os.path.join(self._tmp, ".clagentic", "lite"), exist_ok=True)
        self._stub_dir = tempfile.mkdtemp(prefix="clagentic-test-stub-bin-")
        _write_failing_python3_stub(self._stub_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)
        shutil.rmtree(self._stub_dir, ignore_errors=True)

    def test_git_nudge_escaper_failure_drops_message_not_raw(self):
        env_overrides = {
            "PATH": self._stub_dir + os.pathsep + os.environ.get("PATH", ""),
            "CLAGENTIC_ENV_LOADED": "1",
        }
        result = _run_shim(
            POST_TOOL_NUDGE, self._tmp,
            payload={"session_id": "s1", "tool_name": "Bash",
                     "command": "git commit -m 'test'", "output": ""},
            env_overrides=env_overrides,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        stdout = result.stdout.decode()
        # The raw GIT_MSG text must never appear verbatim -- either it was
        # escaped correctly (impossible here, the stub always fails) or it
        # was dropped. Fail-open would emit this exact substring unescaped.
        self.assertNotIn(
            "clagentic-lite: changes committed", stdout,
            f"raw, unescaped GIT_MSG leaked into stdout despite a failing "
            f"escaper -- fail-open regression: {stdout!r}",
        )
        if stdout.strip():
            try:
                json.loads(stdout)
            except json.JSONDecodeError as exc:
                self.fail(f"stdout did not parse as JSON: {exc}\nstdout={stdout!r}")


class TestAcceptance6RegressionGuardSweep(unittest.TestCase):
    """Every shim template containing "additionalContext" must also
    contain "_json_escape" or "ds_json_escape". Discovery via `git
    ls-files` against the TRACKED, SHIPPED set -- never glob.glob() against
    the filesystem (a glob proves what's on disk, not what ships; an
    untracked stray template would silently pass), and never a hardcoded
    site list -- per AGENTS.md's "Sweeping-test discovery convention"
    (see scripts/test_posix_sh_dash_sweep.py's `_list_tracked_files`,
    the same convention this sweep now matches) and this task's own "the
    grep that finds violations must return nothing" spec. PEACHES PR #210
    review, lr-b82538 fold-in: the prior glob.glob() version, and the two
    stale comments claiming git-ls-files-equivalence, both corrected here
    -- this is the regression guard for the entire defect class, so
    proving the wrong set substantially weakens it."""

    def test_every_json_emitting_shim_calls_an_escaper(self):
        proc = subprocess.run(
            ["git", "-C", TOOL_HOME, "ls-files", "-z", "share/hook-shims"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        tracked = [p for p in proc.stdout.split("\0") if p]
        templates = sorted(
            os.path.join(TOOL_HOME, p) for p in tracked if p.endswith(".sh.template")
        )
        self.assertGreaterEqual(
            len(templates), 6,
            f"expected at least the six known hook shim templates, found {templates}",
        )
        violations = []
        emitters_found = 0
        for path in templates:
            with open(path, encoding="utf-8") as f:
                content = f.read()
            if "additionalContext" not in content:
                continue
            emitters_found += 1
            if "_json_escape" not in content and "ds_json_escape" not in content:
                violations.append(os.path.basename(path))
        self.assertGreaterEqual(
            emitters_found, 3,
            "expected at least the three known JSON-emitting shims "
            "(session-start, prompt-inject, post-tool-nudge) to be "
            "discovered by this sweep",
        )
        self.assertEqual(
            violations, [],
            f"these shim templates emit additionalContext with no "
            f"escaper call at all: {violations}",
        )

    def test_guard_hooks_correctly_excluded_no_json_emission(self):
        """Non-goal check: the two guard hooks (pre-bash-guard,
        pre-write-guard) must NOT have been moved to JSON output -- they
        remain outside this sweep's "emitters" set because they never
        contain the additionalContext marker at all."""
        for name in ("pre-bash-guard.sh.template", "pre-write-guard.sh.template"):
            path = os.path.join(HOOK_SHIMS_DIR, name)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn(
                "additionalContext", content,
                f"{name}: guard hooks must not emit JSON (exit 2 + stderr "
                f"is the correct, unaffected mechanism) -- non-goal violated",
            )


class TestPromptInjectContentCarriesThroughPostToolNudge(unittest.TestCase):
    """Sanity check that post-tool-nudge's own JSON emission (git-workflow
    nudge message, unrelated to memory.db) still parses after the hoist --
    proves the shared ds_json_escape wiring didn't regress the third
    JSON-emitting shim, even though its own defect wasn't in scope."""

    def test_git_commit_nudge_stdout_parses(self):
        tmp = tempfile.mkdtemp(prefix="clagentic-test-json-emit-ptn-")
        try:
            _init_repo(tmp)
            os.makedirs(os.path.join(tmp, ".clagentic", "lite"), exist_ok=True)
            result = _run_shim(
                POST_TOOL_NUDGE, tmp,
                payload={"session_id": "s1", "tool_name": "Bash",
                         "command": "git commit -m 'test'", "output": ""},
                env_overrides={"CLAGENTIC_ENV_LOADED": "1"},
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            stdout = result.stdout.decode()
            self.assertTrue(stdout.strip())
            payload = json.loads(stdout)
            self.assertIn("changes committed", payload["additionalContext"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
