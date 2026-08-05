"""
Sweeping regression coverage for lr-53dc6e (5.3 verified-SHA-discarded,
5.4 freshness -- the most serious site in that task).

Root cause class: several call sites in gates.sh resolve `origin/<branch>`
BY NAME (raw string interpolation: `origin/${VAR}`) for a diff or
merge-base, instead of using the already-fetched, already-verified SHA
that _gate_resolve_fresh_default_branch_ref (gates.sh) proves is current.
A name resolution can succeed against a STALE local tracking ref (present
but wrong) even when the freshness check that ran moments earlier failed
or was skipped -- a "successful-looking wrong resolution" that silently
narrows a diff-scoped security scan while producing a normal-looking
verdict. cmd_bleed was already hardened against this class; cmd_sast
(5.3), get_review_diff (5.4), and build_gate_summary (5.4) were not.

THIS TEST IS DELIBERATELY A SOURCE-LEVEL SWEEP, not three separate
incident-named tests. It greps gates.sh for every live (non-comment)
`origin/${VAR}` interpolation and asserts each one is EITHER inside
_gate_resolve_fresh_default_branch_ref's own body (where that pattern is
correct and expected) OR is not used to scope a diff/merge-base directly
(e.g. a log message built from an already-verified tip variable). Any
future call site that reintroduces a raw `origin/${...}` diff/merge-base
resolution outside the helper trips this test immediately -- it does not
need to be independently reported and separately fixed, which is exactly
the failure mode (replication without class-level defense) this task
exists to close.

Run with: python3 -m unittest scripts.test_freshness_helper_sweep -v
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Variables that are legitimately used in `origin/${VAR}` form outside the
# helper's own body: only as a HUMAN-READABLE LOG STRING built from a
# variable that was itself assigned from the helper's verified output
# (e.g. cmd_bleed's _BLEED_SCOPE_REASON message, which describes the diff
# that was already computed against _BLEED_FRESH_TIP two lines above, not a
# second independent resolution). Any bare git operation (diff, merge-base,
# rev-parse) using a raw `origin/${VAR}` name is what this sweep forbids.
_ALLOWED_LOG_STRING_VARS = {"_BLEED_DEFAULT_BRANCH"}

_HELPER_NAME = "_gate_resolve_fresh_default_branch_ref"


def _find_function_body_range(lines, func_name):
    """Return (start_line_idx, end_line_idx) 0-based, inclusive, for a
    `func_name() {` ... matching `}` block. Uses simple brace counting,
    which is sufficient here because gates.sh has no braces inside string
    literals in this function body."""
    start = None
    for i, line in enumerate(lines):
        if re.match(r'^' + re.escape(func_name) + r'\s*\(\)\s*\{', line):
            start = i
            break
    assert start is not None, f"could not find {func_name}() in gates.sh"
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if depth == 0 and i > start:
            return start, i
    raise AssertionError(f"could not find closing brace for {func_name}()")


class TestNoRawOriginRefResolutionOutsideHelper(unittest.TestCase):
    """Static sweep: every live `origin/${VAR}` git-operation site in
    gates.sh must be inside _gate_resolve_fresh_default_branch_ref itself.
    A call site outside the helper that resolves origin/<branch> by name
    for an actual git command (diff, merge-base, rev-parse) reintroduces
    the exact staleness class cmd_bleed, cmd_sast, and get_review_diff were
    hardened against."""

    def setUp(self):
        with open(GATES_SH) as f:
            self.lines = f.readlines()
        self.helper_start, self.helper_end = _find_function_body_range(
            self.lines, _HELPER_NAME)

    def test_helper_exists_and_has_a_body(self):
        self.assertGreater(self.helper_end, self.helper_start)

    def test_no_git_operation_uses_raw_origin_ref_outside_helper(self):
        origin_ref_re = re.compile(r'origin/\$\{?"?\$?(\w+)')
        # Matches an actual `_git`/`git` invocation (the repo's wrapper
        # function, gates.sh:50) whose subcommand is diff/merge-base/
        # rev-parse/ls-remote/fetch -- i.e. a live git OPERATION, not just
        # the English word "diff" appearing inside a log/reason string like
        # cmd_bleed's `_BLEED_SCOPE_REASON="branch diff vs origin/${...}"`.
        # A comment line (leading `#`, possibly indented) is exempt --
        # comments describing the anti-pattern (explaining what NOT to do)
        # are not live code.
        git_op_re = re.compile(r'\b_?git\b[^=]*\b(diff|merge-base|rev-parse|ls-remote|fetch)\b')

        violations = []
        for i, line in enumerate(self.lines):
            if 'origin/${' not in line and 'origin/"$' not in line:
                continue
            stripped = line.strip()
            if stripped.startswith('#'):
                continue  # comment, not live code
            if self.helper_start <= i <= self.helper_end:
                continue  # inside the helper itself -- correct by definition
            m = origin_ref_re.search(line)
            var_name = m.group(1) if m else None
            if var_name in _ALLOWED_LOG_STRING_VARS and not git_op_re.search(line):
                continue  # a log/reason string, not a git operation
            if git_op_re.search(line):
                violations.append((i + 1, line.rstrip('\n')))

        self.assertEqual(
            violations, [],
            f"found {len(violations)} live git-operation site(s) outside "
            f"{_HELPER_NAME}() resolving origin/<branch> by raw name instead "
            f"of the verified-fresh SHA -- this reintroduces the staleness "
            f"class:\n" + "\n".join(f"  gates.sh:{ln}: {txt}" for ln, txt in violations),
        )


def _init_bare_and_clone(tmp):
    origin = os.path.join(tmp, "origin.git")
    subprocess.run(["git", "init", "-q", "--bare", origin], check=True)
    work = os.path.join(tmp, "work")
    subprocess.run(["git", "clone", "-q", origin, work], check=True)
    env = {**os.environ, **_GIT_ENV}
    readme = os.path.join(work, "README")
    with open(readme, "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=work, env=env)
    subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], check=True, cwd=work, env=env)
    subprocess.run(["git", "checkout", "-q", "-b", "feature"], check=True, cwd=work, env=env)
    with open(readme, "a") as f:
        f.write("feature change\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=work, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "feature commit"], check=True, cwd=work, env=env)
    return origin, work


class TestGetReviewDiffFailsClosedOnUnfetchableOrigin(unittest.TestCase):
    """get_review_diff (5.4, the most serious site): when origin cannot be
    fetched/verified, it must fail toward MORE coverage or a hard error --
    never silently produce a narrower diff off a raw name resolution.

    This test breaks the freshness precondition by pointing `origin` at a
    path that no longer exists (fetch fails outright) and asserts cmd_review
    does NOT exit 0 with a silently-narrowed (possibly empty, possibly
    stale-local-state) diff -- it must fail loudly instead.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-freshness-review-")
        self._origin, self._work = _init_bare_and_clone(self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_review_gate_fails_closed_when_origin_unreachable(self):
        # Break the remote after the initial clone/fetch so a local
        # tracking ref for origin/main already exists (simulating "fetched
        # once, never refreshed") but any FRESH fetch this run will fail.
        broken_origin = os.path.join(self._tmp, "origin-does-not-exist.git")
        subprocess.run(
            ["git", "remote", "set-url", "origin", broken_origin],
            check=True, cwd=self._work,
        )

        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = self._work
        env["CLAGENTIC_DEFAULT_BRANCH"] = "main"
        env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
        result = subprocess.run(
            ["sh", GATES_SH, "review"],
            capture_output=True, text=True, env=env, cwd=self._work,
        )
        # Must NOT succeed quietly. The gate should either hard-error (set -e
        # aborting on get_review_diff's non-zero return) or otherwise report
        # the unverifiable baseline -- never exit 0 having silently produced
        # a diff off a stale/local-only resolution.
        combined = result.stdout + result.stderr
        self.assertIn(
            "not provably current", combined,
            f"expected the freshness failure to be surfaced, not silently "
            f"swallowed. returncode={result.returncode} output={combined!r}",
        )


if __name__ == "__main__":
    unittest.main()
