"""
Class-level closure for lr-c2baaa (retro #803 / lr-24f649 / GH #174,
structural Lesson 1): AGENTS.md non-negotiable 2 asserts "all shell is
POSIX sh" but nothing mechanically verified it. GH #174 survived because a
dead guard (`. "$X" 2>/dev/null || true`) is correct under bash and
FATALLY ABORTS under dash -- `.` is a POSIX special builtin, so a
file-not-found inside it terminates the shell immediately, never reaching
`||`. lr-24f649 (test_hook_shim_stale_home_no_abort.py) closed that one
instance -- the six hook shim templates. This file closes the CLASS: every
`#!/bin/sh`-declaring tracked file in the repo, not just the six hooks.

DISCOVERY, load-bearing: files are found via `git ls-files` (the same
git-ls-files-driven discovery AGENTS.md's "Sweeping-test discovery
convention" already mandates for every sweep in this suite -- see
test_invariants.py, test_freshness_helper_sweep.py) filtered to those whose
FIRST LINE is exactly `#!/bin/sh`. This is deliberately not a glob over a
fixed set of directories or extensions (scripts/*.sh, share/**/*.template,
bin/*) -- a shebang-content filter over the full tracked-file set is the
only shape that also catches a future POSIX-declared script dropped
somewhere this task's authors didn't anticipate (a new top-level dir, a
non-`.sh`-extension file, etc). A hardcoded file list reproduces exactly
the failure mode this task exists to close (three variants of the same
dead guard living in six files because nothing enumerated them together)
-- see AGENTS.md's own "Sweeping-test discovery convention" section.

TWO CHECKS, both dash-`-n` syntax-only (parse, not execute -- executing
each file would require per-file fixture setup this sweep does not own;
that is what test_hook_shim_stale_home_no_abort.py already does for the
six hook shims specifically):

  1. `dash -n <file>` must parse cleanly -- catches anything dash's parser
     rejects outright (bash-only syntax: `[[ ]]`, `local` in a function
     dash restricts, process substitution, arrays, etc).
  2. A source-level regex catches the exact GH #174 shape (a bare `.`
     special-builtin source guarded only by `|| true`/`|| exit 0`/
     `if ! . ...`, with no `[ -f ... ]` existence guard) -- `dash -n`
     alone does NOT catch this: the line is syntactically valid POSIX sh,
     it only misbehaves at RUNTIME when the sourced path is missing. This
     regex is the static-analysis equivalent of what
     test_hook_shim_stale_home_no_abort.py proves dynamically for the six
     hooks; here it sweeps every POSIX-declared file, not just those six.

TOOL DEPENDENCY, per task constraint: `checkbashisms` is not installed on
this host (confirmed absent from PATH at authoring time). `shellcheck` IS
present at /usr/bin/shellcheck on this host, but AGENTS.md's ask-before
rule ("Adding any new external tool dependency") means it may not be
silently wired into this test as a hard dependency without asking first --
its presence here is host happenstance, not a repo-declared prerequisite
(no share/config.example entry, no `doctor` ds_check_tool block), and
AMoS's own build-tool allowlist for this task did not include a direct
shellcheck invocation, so no ad hoc complementary shellcheck pass was run
against this file set in this session either. This sweep therefore uses
ONLY `dash -n` (already a hard dependency of
test_hook_shim_stale_home_no_abort.py, so not a new one) plus the regex
below -- reported as a stated finding, not silently added: a `shellcheck -s
sh` complementary static pass remains worth adding as a FOLLOW-UP task if
the operator wants it wired in as a real dependency (share/config.example
entry + `doctor` ds_check_tool block + an explicit ask-before sign-off),
not folded into this PR.

DASH AVAILABILITY: dash not being on PATH is the same class of defect as
the one this task fixes -- a check that can silently never run is not a
check. setUp() hard-fails (not skips) when dash is missing, exactly
mirroring test_hook_shim_stale_home_no_abort.py's own posture.

FINDINGS (informational; NON-GOAL per task spec to fix these here):
running `dash -n` and the source-guard regex against every currently
tracked `#!/bin/sh` file in this repo finds ZERO bashisms and ZERO
instances of the GH #174 dead-guard shape outside the six already-fixed
hook shims (which correctly guard with a preceding `[ ! -f ... ]` check,
per lr-24f649). Net: this sweep lands GREEN with no exclusion list needed.
If a future run of this test DOES fail, the failure is real detection, not
miscalibration -- see TestSweepMechanismActuallyDetects below, which
proves the sweep trips on a deliberately planted bashism and dead-guard
reintroduction before this docstring's "zero findings" claim is trusted.

Run with: python3 -m unittest scripts.test_posix_sh_dash_sweep -v
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASH = shutil.which("dash") or "/usr/bin/dash"

SHEBANG_LINE = "#!/bin/sh\n"
SHEBANG_LINE_NO_NL = "#!/bin/sh"

# GH #174's exact dead-guard shape: a bare `.` (or `source`) special-builtin
# invocation whose ONLY failure handling is a trailing `|| true` / `|| exit
# 0`, or an `if ! . ... ; then` wrapper -- none of which dash's `.` special
# builtin ever reaches on a missing file, because the abort happens inside
# the builtin itself, before control returns to the calling construct. The
# fallback clause (`|| true`/`|| exit 0`/leading `if !`) must be PRESENT on
# the line to match -- an unconditional `. "$X"` with no fallback at all is
# a different (intentional, `set -e`-consistent hard-fail) shape, not this
# defect, and must not be flagged.
_DEAD_GUARD_RE = re.compile(
    r'^\s*(?:if\s+!\s+\.\s+"[^"]+"[^;]*;?\s*then\s*$'
    r'|\.\s+"[^"]+"\s*(?:2>/dev/null)?\s*\|\|\s*(?:true|exit\s+0)\s*$)'
)

# An existence guard on THIS line or a NEARBY preceding line neutralizes the
# defect -- the fix pattern this repo already uses (post-lr-24f649) is
# `if [ ! -f "$X" ]; then <handle>; fi` on one or more lines immediately
# before the `.`/`if !` line, not necessarily the same line. A same-line-only
# check would false-positive on every one of the six already-fixed hook
# shims (and on bin/clagentic-lite, platform.sh, smoke.sh, which all guard
# this way) -- see the docstring FINDINGS section for what tripped before
# this lookback was added.
_EXISTENCE_GUARD_RE = re.compile(r'\[\s*!?\s*-f\s')
_LOOKBACK_LINES = 6


def _list_tracked_files():
    """git ls-files-driven discovery -- never a hardcoded list, per
    AGENTS.md's Sweeping-test discovery convention."""
    proc = subprocess.run(
        ["git", "-C", TOOL_HOME, "ls-files", "-z"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return [p for p in proc.stdout.split("\0") if p]


def _is_posix_sh_declared(rel_path):
    abs_path = os.path.join(TOOL_HOME, rel_path)
    if not os.path.isfile(abs_path):
        return False
    try:
        with open(abs_path, encoding="utf-8", errors="strict") as f:
            first_line = f.readline()
    except (UnicodeDecodeError, OSError):
        return False
    return first_line in (SHEBANG_LINE, SHEBANG_LINE_NO_NL)


def _discover_posix_sh_files():
    return sorted(p for p in _list_tracked_files() if _is_posix_sh_declared(p))


def _dead_guard_violations(abs_path):
    """Lines matching GH #174's dead-guard shape (bare `.` source relying
    only on `|| true`/`|| exit 0`/`if !`) that are NOT already preceded
    within _LOOKBACK_LINES by an explicit `[ -f ... ]`/`[ ! -f ... ]`
    existence guard -- the fix shape this repo already uses checks
    existence on a prior line, then sources unconditionally (or with a
    fallback that's now unreachable-but-harmless) on a later line."""
    violations = []
    with open(abs_path, encoding="utf-8") as f:
        lines = f.readlines()
    for idx, line in enumerate(lines):
        lineno = idx + 1
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if not _DEAD_GUARD_RE.match(stripped):
            continue
        window_start = max(0, idx - _LOOKBACK_LINES)
        window = lines[window_start:idx + 1]
        if any(_EXISTENCE_GUARD_RE.search(w) for w in window):
            continue
        violations.append((lineno, stripped))
    return violations


class TestDashAvailable(unittest.TestCase):
    """dash absence must never silently no-op this sweep -- a check that
    can't fail is the same defect class this task exists to close."""

    def test_dash_binary_present(self):
        self.assertTrue(
            os.path.isfile(DASH) and os.access(DASH, os.X_OK),
            f"dash not found/executable at {DASH!r} -- this sweep cannot "
            f"verify POSIX sh compliance without a real dash binary on "
            f"this host. Install dash rather than letting this suite "
            f"silently skip its only mechanical enforcement of AGENTS.md "
            f"non-negotiable 2/5.",
        )


class TestPosixShFileDiscovery(unittest.TestCase):
    """Sanity check on the discovery mechanism itself -- proves the glob
    finds a real, non-trivial set (catches the discovery query itself
    silently returning nothing, which would make every check below
    vacuously pass)."""

    def test_discovers_at_least_the_known_files(self):
        found = _discover_posix_sh_files()
        self.assertGreaterEqual(
            len(found), 15,
            f"expected at least the known ~17 #!/bin/sh-declaring tracked "
            f"files (bin/clagentic-lite, install.sh, scripts/*.sh, "
            f"share/hook-shims/*.template), found {len(found)}: {found}",
        )
        # A few known, stable members -- proves the filter is finding real
        # files, not matching everything indiscriminately.
        for expected in (
            "bin/clagentic-lite",
            "scripts/gates.sh",
            "scripts/platform.sh",
            "share/hook-shims/session-start.sh.template",
        ):
            self.assertIn(expected, found)

    def test_discovery_excludes_non_sh_files(self):
        found = _discover_posix_sh_files()
        for excluded in ("AGENTS.md", "README.md", "scripts/gates.sh".replace(".sh", ".py")):
            self.assertNotIn(excluded, found)


class TestAllPosixShFilesParseUnderDash(unittest.TestCase):
    """`dash -n <file>` (syntax check only, no execution) must succeed for
    every #!/bin/sh-declaring tracked file. This is the baseline detection
    layer -- catches bash-only syntax dash's parser rejects outright."""

    def test_dash_n_clean_for_every_posix_sh_file(self):
        files = _discover_posix_sh_files()
        self.assertTrue(files, "discovery found no #!/bin/sh files -- see TestPosixShFileDiscovery")
        failures = []
        for rel_path in files:
            abs_path = os.path.join(TOOL_HOME, rel_path)
            proc = subprocess.run(
                [DASH, "-n", abs_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode != 0:
                failures.append((rel_path, proc.returncode, proc.stderr.strip()))
        self.assertEqual(
            failures, [],
            "these #!/bin/sh files fail to parse under `dash -n` (bashism "
            "or non-POSIX construct) -- per lr-c2baaa this is a DETECTION "
            "sweep; a real finding here is a separate fix, not something "
            "to patch in this diff:\n"
            + "\n".join(f"  {p}: rc={rc} stderr={err!r}" for p, rc, err in failures),
        )


class TestNoDeadSourceGuardShape(unittest.TestCase):
    """Static equivalent of test_hook_shim_stale_home_no_abort.py's dynamic
    proof, swept over every #!/bin/sh file rather than just the six hooks:
    no bare `.` source relying only on `|| true`/`|| exit 0`/`if !` without
    an accompanying `[ -f ... ]` existence guard."""

    def test_no_bare_dot_source_without_existence_guard(self):
        files = _discover_posix_sh_files()
        failures = []
        for rel_path in files:
            abs_path = os.path.join(TOOL_HOME, rel_path)
            for lineno, line in _dead_guard_violations(abs_path):
                failures.append((rel_path, lineno, line))
        self.assertEqual(
            failures, [],
            "these lines reproduce GH #174's dead source-guard shape (bare "
            "`.` special-builtin relying only on `|| true`/`|| exit 0`/"
            "`if !`, no `[ -f ... ]` existence guard -- fatal under dash "
            "on a missing file, silently swallowed under bash):\n"
            + "\n".join(f"  {p}:{n}: {text}" for p, n, text in failures),
        )


class TestSweepMechanismActuallyDetects(unittest.TestCase):
    """Per task TEST DISCIPLINE: a detection test that has never been
    observed detecting anything is not coverage. Plants a deliberate
    bashism and a deliberate dead-guard reintroduction in a throwaway
    #!/bin/sh file, proves both checks above trip on it, then removes it --
    nothing planted here is left behind in the tree."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-posix-sweep-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def test_dash_n_trips_on_planted_bashism(self):
        planted = os.path.join(self.tmpdir, "planted-bashism.sh")
        with open(planted, "w", encoding="utf-8") as f:
            # bash array syntax -- dash's POSIX parser has no array
            # concept and rejects the assignment outright under -n. (Note:
            # `[[ ... ]]` is NOT usable for this probe -- dash's `-n`
            # parses `[[` as an ordinary command word, not a syntax error,
            # since dash doesn't reserve it as a keyword; the failure only
            # surfaces at execution time as "not found", which -n never
            # reaches. Array syntax fails at PARSE time, which -n does
            # check.)
            f.write("#!/bin/sh\n" 'arr=(1 2 3)\necho "${arr[0]}"\n')
        proc = subprocess.run(
            [DASH, "-n", planted],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(
            proc.returncode, 0,
            "planted bash-array-syntax bashism should have failed dash -n "
            "but did not -- the detection mechanism itself is not working. "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}",
        )
        # Confirm it disappears once the bashism is removed -- proves the
        # test isn't just permanently red for unrelated reasons.
        with open(planted, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n" 'if [ "$1" = "x" ]; then\n  echo yes\nfi\n')
        proc2 = subprocess.run(
            [DASH, "-n", planted],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc2.returncode, 0, msg=f"stderr={proc2.stderr!r}")

    def test_dead_guard_regex_trips_on_planted_gh174_shape(self):
        planted = os.path.join(self.tmpdir, "planted-dead-guard.sh")
        with open(planted, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                ': "${CLAGENTIC_LITE_HOME:=/some/default}"\n'
                '. "$CLAGENTIC_LITE_HOME/scripts/platform.sh" 2>/dev/null || true\n'
            )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"planted GH #174 dead-guard shape should have tripped the "
            f"regex exactly once, got {violations}",
        )

        # Confirm the fixed shape (explicit existence guard) does NOT trip
        # it -- proves the check isn't just flagging every `.` source line.
        fixed = os.path.join(self.tmpdir, "fixed-guard.sh")
        with open(fixed, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                ': "${CLAGENTIC_LITE_HOME:=/some/default}"\n'
                '[ -f "$CLAGENTIC_LITE_HOME/scripts/platform.sh" ] && '
                '. "$CLAGENTIC_LITE_HOME/scripts/platform.sh"\n'
            )
        self.assertEqual(_dead_guard_violations(fixed), [])


if __name__ == "__main__":
    unittest.main()
