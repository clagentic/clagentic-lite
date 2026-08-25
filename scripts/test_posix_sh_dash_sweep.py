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
FIRST LINE matches the real POSIX-sh shebang family -- see `_SHEBANG_RE`
below (`#!/bin/sh`, `#!/bin/sh -e`, `#!/usr/bin/env sh`, and other flag/arg
variants of both forms; NOT an exact-string match against a single literal,
which is what PR #202's first version did and which PEACHES correctly
flagged as a real discovery gap -- an exact match silently missed
`#!/usr/bin/env sh`, the increasingly common portable-by-intent form, and
any interpreter-with-flags variant). This is also deliberately not a glob
over a fixed set of directories or extensions (scripts/*.sh,
share/**/*.template, bin/*) -- a shebang-content filter over the full
tracked-file set is the only shape that also catches a future
POSIX-declared script dropped somewhere this task's authors didn't
anticipate (a new top-level dir, a non-`.sh`-extension file, a different
but-still-POSIX shebang spelling, etc). A hardcoded file list, or a discovery
filter that silently misses a whole class of real POSIX-sh declaration,
both reproduce exactly the failure mode this task exists to close (three
variants of the same dead guard living in six files because nothing
enumerated them together) -- see AGENTS.md's own "Sweeping-test discovery
convention" section.

TWO CHECKS. Their combined coverage is narrower than "verifies POSIX sh
compliance" would suggest -- stated precisely here rather than implied,
because an overclaimed detector manufactures exactly the false confidence
this task exists to remove:

  1. `dash -n <file>` -- PARSE-TIME ONLY, catches nothing at runtime.
     Confirmed empirically (see TestSweepMechanismActuallyDetects): dash's
     `-n` flag makes it read and parse the script without executing it, so
     it rejects constructs its grammar cannot parse at all (bash arrays,
     process substitution, here-strings, `((...))` arithmetic command
     forms, etc). It does GENUINELY NOT catch most real-world bashisms,
     which are grammatically valid POSIX sh tokens that only diverge in
     BEHAVIOR at runtime -- `[[ ... ]]` is the concrete case this sweep's
     own test discovered: dash's parser accepts `[[` as an ordinary,
     unrecognized command WORD (not a keyword, since dash doesn't reserve
     it), so `dash -n` reports success on a script containing `[[ ]]`; the
     failure only appears at execution as "not found". `local` inside a
     function, `echo -e` interpretation, `read` without `-r`, `function
     name() { }` -- all likewise parse cleanly and diverge only at
     runtime. This check's real, honest scope is: catches gross
     dash-incompatible GRAMMAR, not general bashism behavior.
  2. A source-level regex (`_dead_guard_operand` / `_dead_guard_violations`)
     catches the exact GH #174 shape (a bare `.` special-builtin source
     guarded only by `|| true`/`|| exit 0`/`if ! . ...`, with no `[ -f
     ... ]` existence guard for the SAME operand anywhere earlier in the
     file -- see `_EXISTENCE_GUARD_RE`'s docstring for the unbounded-
     lookback rationale and its own honest idiom-coverage limits) --
     `dash -n` alone does NOT catch this: the line is syntactically valid
     POSIX sh, it only misbehaves at RUNTIME when the sourced path is
     missing. This regex is the static-analysis equivalent of what
     test_hook_shim_stale_home_no_abort.py proves dynamically for the six
     hooks; here it sweeps every POSIX-declared file, not just those six.
     BECAUSE check 1 is parse-time-only (see above), this regex sweep is
     the load-bearing check for the actual GH #174 defect class -- check 1
     is a cheap grammar floor underneath it, not the primary detector.

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
tracked file matching the WIDENED shebang family finds ZERO bashisms and
ZERO instances of the GH #174 dead-guard shape outside the six
already-fixed hook shims (which correctly guard with a preceding
`[ ! -f ... ]` check, per lr-24f649). The widened filter does not discover
any file the exact-match version missed -- confirmed directly
(TestPosixShFileDiscovery.test_no_env_sh_or_flagged_shebang_file_in_current_tree):
this repo currently has zero `#!/usr/bin/env sh` or `#!/bin/sh <flags>`
tracked files, so there is no newly-discovered file to check for a bashism
in. Net: this sweep lands GREEN with no exclusion list needed. If a future
run of this test DOES fail, the failure is real detection, not
miscalibration -- see TestSweepMechanismActuallyDetects and
TestWidenedShebangFamilyDiscovery below, which prove the sweep trips on a
deliberately planted bashism/dead-guard reintroduction and correctly
discovers a deliberately planted `#!/usr/bin/env sh`/`#!/bin/sh -e` file,
respectively, before this docstring's claims are trusted.

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

# PEACHES PR #202 review, finding 2 (HOLDEN-verified real): an exact match
# against `#!/bin/sh` alone misses the rest of the real POSIX-sh shebang
# family -- `#!/usr/bin/env sh` (portable-by-intent, increasingly common),
# `#!/bin/sh -e` (interpreter with flags), and leading-whitespace variants.
# A discovery filter that silently misses a whole class of POSIX-sh
# declaration reproduces, INSIDE this detector, the exact failure mode the
# detector exists to prevent (GH #174: three dead-guard variants across six
# files because nothing enumerated them together). Widened rather than
# merely documented as narrow -- scoping the claim would preserve the blind
# spot, not close it. Covers, case-sensitively (shebangs are not
# case-insensitive in practice):
#   ^#!\s*/bin/sh(\s+\S.*)?$          -- #!/bin/sh, #!/bin/sh -e, etc.
#   ^#!\s*/usr/bin/env\s+sh(\s+\S.*)?$ -- #!/usr/bin/env sh, with args
# Optional leading whitespace before `#!` is intentionally NOT matched --
# a shebang is only meaningful to the kernel/exec at byte offset 0; leading
# whitespace before it is not a real POSIX-sh declaration shape at all (the
# line would not be honored as a shebang by exec() in the first place), so
# matching it would create false positives rather than close a real gap.
_SHEBANG_RE = re.compile(
    r'^#!\s*(?:/bin/sh|/usr/bin/env\s+sh)(?:\s+\S.*)?\s*$'
)

# GH #174's exact dead-guard shape: a bare `.` special-builtin invocation
# whose ONLY failure handling is a trailing `|| true` / `|| exit 0`, or an
# `if ! . ... ; then` wrapper -- none of which dash's `.` special
# builtin ever reaches on a missing file, because the abort happens inside
# the builtin itself, before control returns to the calling construct. The
# fallback clause (`|| true`/`|| exit 0`/leading `if !`) must be PRESENT on
# the line to match -- an unconditional `. "$X"` with no fallback at all is
# a different (intentional, `set -e`-consistent hard-fail) shape, not this
# defect, and must not be flagged.
_IF_DEAD_GUARD_RE = re.compile(
    r'^\s*if\s+!\s+\.\s+(?P<quote>["\'])(?P<operand>[^"\']+)(?P=quote)[^;]*;?\s*then\s*$'
)
_DOT_DEAD_GUARD_RE = re.compile(
    r'^\s*\.\s+(?P<quote>["\'])(?P<operand>[^"\']+)(?P=quote)\s*(?:2>/dev/null)?\s*'
    r'\|\|\s*(?:true|exit\s+0)\s*$'
)

# An existence guard for the SAME sourced operand on THIS line, or ANY
# preceding line in the file, neutralizes the defect -- the fix pattern this
# repo already uses (post-lr-24f649) is `if [ ! -f "$X" ]; then <handle>; fi`
# on one or more lines before the `.`/`if !` line, not necessarily adjacent
# to it (e.g. bin/clagentic-lite's bootstrap guard is ~30 lines above its
# `.` line). PEACHES PR #202 review, item (b) (HOLDEN-verified real): an
# earlier version of this check used a fixed 6-line lookback window, added
# to kill a same-line-only false positive on the six already-fixed hook
# shims -- but a FIXED window trades that false positive for a false
# NEGATIVE risk in the other direction: a real GH #174-shaped defect whose
# existence guard sits 7+ lines away (exactly bin/clagentic-lite's real
# shape) would have passed silently. The lookback is now UNBOUNDED --
# scans every line from the top of the file down to (and including) the
# flagged line for an existence guard matching the same operand -- which
# removes the distance-based false-negative risk entirely rather than
# tuning a magic number. This is deliberately still narrower than "any
# guard shape": it requires `[ -f ... ]` or `[ ! -f ... ]` testing the
# SAME sourced path string (see `_existence_guard_matches_operand`), the
# one idiom this repo's own post-lr-24f649 fix and the six hook shims all
# use. A different but equally-valid guard idiom (e.g. `test -f`, a
# `case`-based check, or a guard against a differently-spelled but
# equivalent path expression) is NOT covered by this pattern match and
# would still be flagged as a violation even if functionally safe -- that
# is a possible FALSE POSITIVE the regex approach cannot fully rule out
# without a real shell parser, stated plainly rather than implied away.
# No attempt is made to enumerate a complete guard-idiom set; `[ -f ... ]`/
# `[ ! -f ... ]` is what this repo actually uses everywhere today.
_EXISTENCE_GUARD_RE = re.compile(r'\[\s*!?\s*-f\s')


def _dead_guard_operand(stripped_line):
    for pattern in (_IF_DEAD_GUARD_RE, _DOT_DEAD_GUARD_RE):
        match = pattern.match(stripped_line)
        if match:
            return match.group("operand")
    return None


def _existence_guard_matches_operand(line, operand):
    if not _EXISTENCE_GUARD_RE.search(line):
        return False
    return f'"{operand}"' in line or f"'{operand}'" in line


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
    return bool(_SHEBANG_RE.match(first_line.rstrip("\n")))


def _discover_posix_sh_files():
    return sorted(p for p in _list_tracked_files() if _is_posix_sh_declared(p))


def _dead_guard_violations(abs_path):
    """Lines matching GH #174's dead-guard shape (bare `.` source relying
    only on `|| true`/`|| exit 0`/`if !`) that are NOT already preceded,
    ANYWHERE earlier in the file (unbounded lookback -- see
    _EXISTENCE_GUARD_RE's docstring for why this is not windowed), by an
    explicit `[ -f ... ]`/`[ ! -f ... ]` existence guard testing the SAME
    sourced operand -- the fix shape this repo already uses checks
    existence on a prior line (not necessarily adjacent), then sources
    unconditionally (or with a fallback that's now unreachable-but-
    harmless) on a later line."""
    violations = []
    with open(abs_path, encoding="utf-8") as f:
        lines = f.readlines()
    for idx, line in enumerate(lines):
        lineno = idx + 1
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        operand = _dead_guard_operand(stripped)
        if operand is None:
            continue
        preceding_and_self = lines[:idx + 1]
        if any(
            _existence_guard_matches_operand(w, operand)
            for w in preceding_and_self
        ):
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

    def test_no_env_sh_or_flagged_shebang_file_in_current_tree(self):
        """Sanity check on today's repo state, not the mechanism: confirms
        the repo currently has zero `#!/usr/bin/env sh` or `#!/bin/sh
        <flags>` tracked files, so TestWidenedShebangFamilyDiscovery below
        (which plants one) is testing real new-discovery behavior rather
        than a file that would have been found anyway."""
        for rel_path in _list_tracked_files():
            abs_path = os.path.join(TOOL_HOME, rel_path)
            if not os.path.isfile(abs_path):
                continue
            try:
                with open(abs_path, encoding="utf-8", errors="strict") as f:
                    first_line = f.readline().rstrip("\n")
            except (UnicodeDecodeError, OSError):
                continue
            if first_line in ("#!/usr/bin/env sh",) or (
                first_line.startswith("#!/bin/sh ") and first_line != "#!/bin/sh"
            ):
                self.fail(
                    f"{rel_path} already declares a non-bare-#!/bin/sh "
                    f"POSIX-sh shebang ({first_line!r}) -- update this "
                    f"sanity check's assumption, it no longer describes "
                    f"the tree"
                )


class TestWidenedShebangFamilyDiscovery(unittest.TestCase):
    """PEACHES PR #202 review, finding 2 (HOLDEN-verified real): the
    original version of this sweep matched only the exact literal
    `#!/bin/sh`, silently missing `#!/usr/bin/env sh` and `#!/bin/sh
    <flags>` -- a discovery gap inside the detector meant to close exactly
    this class of gap. Proves the WIDENED filter (_SHEBANG_RE) now
    discovers both forms, and that a bare-string match (the pre-fix
    behavior) would NOT have -- by asserting the widened regex directly
    against both the old exact-match pattern and against real fixture
    files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-posix-shebang-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _write_and_check(self, shebang_line):
        planted = os.path.join(self.tmpdir, "planted-shebang.sh")
        with open(planted, "w", encoding="utf-8") as f:
            f.write(shebang_line + "\necho ok\n")
        with open(planted, encoding="utf-8") as f:
            first_line = f.readline().rstrip("\n")
        return bool(_SHEBANG_RE.match(first_line))

    def test_env_sh_shebang_is_discovered(self):
        self.assertTrue(
            self._write_and_check("#!/usr/bin/env sh"),
            "#!/usr/bin/env sh must be discovered by the widened filter",
        )

    def test_env_sh_shebang_was_missed_by_the_old_exact_match(self):
        # The pre-fix behavior, reproduced directly: exact match against
        # the single literal '#!/bin/sh' only.
        old_exact_match = "#!/usr/bin/env sh" in ("#!/bin/sh\n", "#!/bin/sh")
        self.assertFalse(
            old_exact_match,
            "sanity check on the OLD behavior itself: #!/usr/bin/env sh "
            "must NOT match an exact-string comparison against '#!/bin/sh' "
            "-- if this assertion fails, the regression this test guards "
            "against no longer describes the old code",
        )

    def test_flagged_bin_sh_shebang_is_discovered(self):
        self.assertTrue(
            self._write_and_check("#!/bin/sh -e"),
            "#!/bin/sh -e must be discovered by the widened filter",
        )

    def test_flagged_bin_sh_shebang_was_missed_by_the_old_exact_match(self):
        old_exact_match = "#!/bin/sh -e" in ("#!/bin/sh\n", "#!/bin/sh")
        self.assertFalse(
            old_exact_match,
            "sanity check on the OLD behavior itself: #!/bin/sh -e must "
            "NOT match an exact-string comparison against '#!/bin/sh'",
        )

    def test_plain_bin_sh_still_discovered_after_widening(self):
        """Non-regression: widening must not narrow the original case."""
        self.assertTrue(self._write_and_check("#!/bin/sh"))

    def test_non_sh_shebang_still_excluded(self):
        """Negative control: #!/bin/bash and #!/usr/bin/env python3 must
        never match -- the widening targets the POSIX-sh family only, not
        every shebang."""
        self.assertFalse(self._write_and_check("#!/bin/bash"))
        self.assertFalse(self._write_and_check("#!/usr/bin/env python3"))
        self.assertFalse(self._write_and_check("#!/usr/bin/env bash"))


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

        # Confirm an unrelated nearby existence guard does NOT mask the
        # planted defect -- only a guard for the same sourced operand counts.
        unrelated_guard = os.path.join(self.tmpdir, "unrelated-guard.sh")
        with open(unrelated_guard, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                'if [ -f "$OTHER_FILE" ]; then\n'
                "  echo ok\n"
                "fi\n"
                ': "${CLAGENTIC_LITE_HOME:=/some/default}"\n'
                '. "$CLAGENTIC_LITE_HOME/scripts/platform.sh" 2>/dev/null || true\n'
            )
        self.assertEqual(
            len(_dead_guard_violations(unrelated_guard)), 1,
            "an unrelated nearby `[ -f ... ]` guard must not suppress the "
            "GH #174 dead-guard finding",
        )

        # Confirm the fixed shape (explicit existence guard for the same
        # operand) does NOT trip it -- proves the check isn't just flagging
        # every `.` source line.
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
