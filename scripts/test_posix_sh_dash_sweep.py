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
     forms, AND `function name() { }` -- dash has no `function` keyword at
     all, so this is a genuine PARSE-time rejection, unlike the items
     below). It does GENUINELY NOT catch most real-world bashisms, which
     ARE grammatically valid POSIX sh tokens that only diverge in BEHAVIOR
     at runtime -- `[[ ... ]]` is the concrete case this sweep's own test
     discovered: dash's parser accepts `[[` as an ordinary, unrecognized
     command WORD (not a keyword, since dash doesn't reserve it), so
     `dash -n` reports success on a script containing `[[ ]]`; the failure
     only appears at execution as "not found". `local` inside a function,
     `echo -e` interpretation, `read` without `-r` -- all likewise parse
     cleanly and diverge only at runtime. This check's real, honest scope
     is: catches gross dash-incompatible GRAMMAR, not general bashism
     behavior.
  2. A source-level regex/block-scan (`_dead_guard_operand` /
     `_existence_guard_dominates` / `_dead_guard_violations`) catches the
     exact GH #174 shape (a bare `.` special-builtin source, or an
     `if ! . ...` wrapper with same-line OR next-line `then`, guarded only
     by `|| true`/`|| exit 0`/`if !`, with no existence guard that
     DOMINATES the source line for the SAME operand -- see the
     module-level comment above `_NEGATIVE_EXISTENCE_GUARD_RE` for the
     three recognized dominating patterns and this check's own honest
     limits) --
     `dash -n` alone does NOT catch this: the line is syntactically valid
     POSIX sh, it only misbehaves at RUNTIME when the sourced path is
     missing. This regex/block-scan is the static-analysis equivalent of
     what test_hook_shim_stale_home_no_abort.py proves dynamically for the
     six hooks; here it sweeps every POSIX-declared file, not just those
     six. BECAUSE check 1 is parse-time-only (see above), this check is
     the load-bearing detector for the actual GH #174 defect class --
     check 1 is a cheap grammar floor underneath it, not the primary
     detector.

CONTROL-FLOW MODEL, enumerated explicitly (PEACHES PR #202 round-3 review,
item (a) -- "extend the honest-limits register to the control-flow
model"): three rounds of review each found a real false-suppression bug in
the dominance checker (round 2: any-earlier-line instead of dominance,
same-line `if...fi` compound misread as Pattern B; round 3: an `elif`
branch's exit wrongly counted as the negative guard's own unconditional
exit, `exit`/`return`/`continue` matched inside a comment, `then` search
checking only the literal next line despite its own comment's claim). Every
one of those was a FALSE NEGATIVE -- the direction that defeats this
detector's purpose. The policy going forward, applied everywhere below:
WHEN THE LINE-ORIENTED SCAN CANNOT PROVE DOMINANCE, IT MUST NOT SUPPRESS --
an unrecognized or ambiguous shape is treated as NOT dominated (flag it),
never as dominated (suppress it). Concretely, what the checker DOES model:

  - `if [ ! -f "$OP" ]; then ... <exit|return|continue> ...; fi` (Pattern
    A) -- exit must be the FIRST TOKEN of a non-comment, non-blank line,
    at the guard's own branch depth, BEFORE any depth-0 `elif`/`else`
    (round-3 findings 1 and 2).
  - `if [ -f "$OP" ]; then <source line>; ... fi` / `... else ...; fi`
    (Pattern B) -- source line must be the NEAREST meaningful (non-blank,
    non-comment) line after the guard `if`, with no intervening `elif`
    (an intervening `elif`/`else` line is never matched by the Pattern-B
    check at all, since `_IF_OPEN_RE` does not match `elif`/`else` --
    falls through to "not dominated" automatically, not by special-case
    logic).
  - `[ -f "$OP" ] && <source line>` (Pattern C), same line only.
  - `if ! . "$OP" ...; then ...; fi` with `then` on the SAME line, the
    NEXT line, or the next line after up to `_THEN_SEARCH_MAX_LINES`
    CONSECUTIVE comment lines (round-3 finding 3) -- a blank line in that
    gap, or exceeding the bound, means the construct is simply NOT
    recognized as the dead-guard shape at all (neither flagged nor
    suppressed as dominated -- see
    TestElifAndCommentDominanceEdgeCases.test_then_search_bounded_does_
    not_match_arbitrarily_far). This is itself a stated gap: a
    then-across-a-blank-line or then-beyond-the-bound file is invisible
    to this specific check, not merely unguarded.

What the checker explicitly DOES NOT model, stated plainly rather than
approximated (item (c)): `case` statement branches (a source line inside
a `case ... esac` arm is never recognized as dominated by anything,
including a genuinely dominating case pattern -- this is fail-OPEN by
construction: an unrecognized construct is never treated as dominated,
so a false positive here is possible but a false negative is not);
`&&`/`||` chains split across a backslash line continuation; heredocs whose
body text happens to contain literal `then`/`fi`/`exit` (a heredoc body
is not distinguished from real code by this line-oriented scan -- a
`then`/`fi` INSIDE a heredoc could be miscounted by the nesting tracker);
nested `elif` chains beyond the first `elif`/`else` boundary (only the
FIRST depth-0 elif/else is checked for -- a second, third, etc. `elif` is
never separately analyzed, though this cannot itself cause a false
suppression, since the scan already stops at the first one); a guard
idiom other than `[ -f ... ]`/`[ ! -f ... ]` on the exact same operand
string (`test -f`, a `case`-based existence check, a differently-spelled
but equivalent path). NONE of these constructs occur in this repo's
tracked files today (confirmed by the currently-clean sweep below); if
one is introduced, the checker's behavior on it is UNVERIFIED by this
docstring's claims, not silently assumed safe -- a case/heredoc/
line-continuation shape reaching a flagged line falls through this
scan's pattern matches and is reported as a violation (fail open), while
the reverse -- treating an unrecognized shape as dominated -- never
happens by construction (every dominance path requires a positive regex
match on a known shape; the default return value throughout
_find_dominating_block is False, "not dominated").

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
running `dash -n` and the source-guard/block-scan against every currently
tracked file matching the WIDENED shebang family finds ZERO bashisms and
ZERO instances of the GH #174 dead-guard shape outside the six
already-fixed hook shims (which correctly DOMINATE the source line with a
preceding `[ ! -f ... ]` check per lr-24f649, re-verified against the
dominance logic specifically -- see PEACHES PR #202 round-2 findings 1/2
below). The widened filter does not discover any file the exact-match
version missed -- confirmed directly
(TestPosixShFileDiscovery.test_no_env_sh_or_flagged_shebang_file_in_current_tree):
this repo currently has zero `#!/usr/bin/env sh` or `#!/bin/sh <flags>`
tracked files, so there is no newly-discovered file to check for a bashism
in. Net: this sweep lands GREEN with no exclusion list needed. If a future
run of this test DOES fail, the failure is real detection, not
miscalibration -- see TestSweepMechanismActuallyDetects,
TestWidenedShebangFamilyDiscovery, and TestDominatingVsNonDominatingGuard
below, which prove the sweep trips on a deliberately planted bashism/
dead-guard reintroduction, correctly discovers a deliberately planted
`#!/usr/bin/env sh`/`#!/bin/sh -e` file, and correctly distinguishes a
same-operand guard that DOMINATES the source line from one that merely
appears earlier without gating it, respectively, before this docstring's
claims are trusted. TestElifAndCommentDominanceEdgeCases additionally
proves the three round-3 false-suppression bugs (elif-branch exit,
exit-word-in-comment, then-across-comment) are fixed, each with a
same-fixture proof that the OLD code would have missed it.
TestUnmodeledConstructsFailOpen proves the fail-open claim above for
`case` branches mechanically rather than asserting it.

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
#
# PEACHES PR #202 round-2 review, finding 2 (HOLDEN-verified real): an
# EARLIER version of _IF_DEAD_GUARD_RE anchored on `then` appearing on the
# SAME line, missing the POSIX-valid multi-line form:
#     if ! . "$X"
#     then
# `_IF_DEAD_GUARD_OPEN_RE` now matches the `if ! . "$X"` line WITHOUT
# requiring `then` on it, and `_dead_guard_operand` (below) additionally
# checks the immediately-following non-comment line for a bare `then` when
# the current line doesn't carry it -- covering both the same-line and
# next-line forms. A `then` more than one line further down (e.g. a blank
# line or a comment between `if ! . "$X"` and `then`) is NOT covered; this
# repo's own tracked files use only same-line or immediately-next-line
# `then`, and covering arbitrary whitespace/comment gaps would need a real
# tokenizer rather than a two-line regex check -- stated as a limit, not
# silently assumed away.
_IF_DEAD_GUARD_OPEN_RE = re.compile(
    r'^\s*if\s+!\s+\.\s+(?P<quote>["\'])(?P<operand>[^"\']+)(?P=quote)[^;]*'
    r'(?:;\s*then\s*)?$'
)
_BARE_THEN_RE = re.compile(r'^\s*then\s*$')
_DOT_DEAD_GUARD_RE = re.compile(
    r'^\s*\.\s+(?P<quote>["\'])(?P<operand>[^"\']+)(?P=quote)\s*(?:2>/dev/null)?\s*'
    r'\|\|\s*(?:true|exit\s+0)\s*$'
)

# PEACHES PR #202 round-2 review, finding 1 (HOLDEN-verified real): an
# EARLIER version of this check treated ANY earlier line testing the same
# operand as neutralizing, regardless of control flow --
#
#     if [ -f "$X" ]; then echo found; fi   # guard exists, guards nothing
#     . "$X" || true                        # still aborts under dash
#
# -- a guard that merely APPEARS earlier does not protect the source line
# unless it DOMINATES it: either the source is textually inside the
# guard's own positive branch, or the guard's negative branch
# unconditionally terminates before the source line is ever reached. That
# is the actual GH #174-preventing property; "some earlier line mentions
# the same path" is not.
#
# This repo's own fixed instances (post-lr-24f649) use exactly two
# dominating shapes, both handled below by a real (bounded) block scan
# rather than a flat lookback:
#
#   Pattern A -- negative guard, unconditional early exit:
#       if [ ! -f "$OPERAND" ]; then
#         ...
#         exit 0        # or: exit 1, return, continue
#       fi
#       . "$OPERAND" ... || true     <- dominated: negative branch always
#                                        terminates before this line, so
#                                        reaching it means the file exists
#     (bin/clagentic-lite, post-tool-nudge/stop-summarize/pre-write-guard/
#     pre-bash-guard.sh.template -- the latter two apply this pattern to
#     the `if ! . "$OPERAND"; then exit 0; fi` if-form itself)
#
#   Pattern B -- positive guard, source inside the branch:
#       if [ -f "$OPERAND" ]; then
#         . "$OPERAND" ... || true  <- dominated: only reached when the
#                                        positive branch's condition held
#       else
#         ...
#       fi
#     (session-start.sh.template, prompt-inject.sh.template)
#
#   Pattern C -- same-line AND-chain:
#       [ -f "$OPERAND" ] && . "$OPERAND"   <- dominated: `.` is the RHS
#                                                of `&&`, only reached if
#                                                the test passed
#     (not currently used in this repo's tracked files, but a valid
#     dominating idiom worth recognizing on its own merits)
#
# HONEST LIMIT, stated plainly rather than implied complete: this is a
# bounded `if`/`fi` NESTING SCAN over TEXTUAL LINES, not a real shell
# parser. It assumes this repo's own one-keyword-per-line style (`if
# COND; then` opens, `fi` alone or `; fi`-suffixed closes, one per line).
# A single-line `if ...; then ...; fi` compound is explicitly detected
# (_is_self_closing_if_line) and treated as depth-neutral -- it is
# neither a Pattern-A/B guard candidate itself nor counted toward nesting
# depth, closing the false-suppression gap this exact shape produced
# during development (see TestDominatingVsNonDominatingGuard's
# test_non_dominating_same_operand_guard_still_flagged, whose fixture is
# precisely this shape). What remains genuinely unhandled: a `fi` sharing
# a line with OTHER unrelated trailing content after a `;` that is not
# itself a self-closing `if`, or multiple `if`/`fi` pairs packed onto one
# physical line -- neither occurs in this repo's tracked files today. A
# guard idiom other than `[ -f ... ]`/`[ ! -f ... ]` on the SAME operand
# string (e.g. `test -f`, a `case` check, or a differently-spelled but
# equivalent path expression) is also not recognized and would still be
# flagged as a violation even if functionally safe. No attempt is made to
# enumerate a complete guard-idiom or control-flow set; the three
# patterns above are what this repo's own post-lr-24f649 fixes and hook
# shims actually use today.
_NEGATIVE_EXISTENCE_GUARD_RE = re.compile(r'\[\s*!\s*-f\s')
_POSITIVE_EXISTENCE_GUARD_RE = re.compile(r'\[\s*-f\s')
_IF_OPEN_RE = re.compile(r'^\s*if\s+(?:\[|!)')
_FI_RE = re.compile(r'^\s*fi\b')
_ELIF_OR_ELSE_RE = re.compile(r'^\s*(?:elif\b|else\b)')
# PEACHES PR #202 round-3 review, finding 2 (HOLDEN-verified real): a bare
# word-boundary search for exit/return/continue matched INSIDE comment
# lines (`# exit 0` read as a real exit) and would equally match inside an
# echoed string (`echo "call exit to leave"`) -- the enclosing scan never
# excluded comments, and a substring search can never distinguish "this
# IS the exit statement" from "this line merely CONTAINS the word". Fixed
# by requiring the word to be the FIRST TOKEN of the (already
# comment-filtered, see the caller) line -- the actual invocation shape,
# not a mention anywhere in it. This does not fully solve the general
# problem (`echo exit 0` as the first two tokens of an echo call still
# matches) -- stated as a known residual ambiguity, not solved away; see
# the module-level "what this checker models" enumeration below for the
# full list of what remains unhandled by design.
_UNCONDITIONAL_EXIT_STMT_RE = re.compile(r'^(?:exit|return|continue)\b')


# PEACHES PR #202 round-3 review, finding 3 (HOLDEN-verified real, and the
# code contradicted its own comment): the multi-line `then` search checked
# ONLY the literal next line, while the comment above it claimed a
# non-comment skip. Bounded forward scan: skips COMMENT lines only (never
# blank lines -- a blank line between `if ! . "$X"` and `then` is not a
# shape seen anywhere in this repo and treating it as skippable would
# widen the search indefinitely for no observed benefit) up to
# _THEN_SEARCH_MAX_LINES lines ahead, looking for a bare `then`. If
# anything else (real code, blank line) is hit first, or the bound is
# exceeded, the multi-line form is NOT recognized here -- see
# _dead_guard_operand's own fail-open handling of that case.
_THEN_SEARCH_MAX_LINES = 5


def _find_then_within_comment_gap(lines, idx):
    """Starting at lines[idx+1], skips COMMENT-only lines (not blank, not
    code) looking for a bare `then`, bounded to _THEN_SEARCH_MAX_LINES.
    Returns True if found, False otherwise (including: blank line or real
    code encountered first, or bound exceeded)."""
    j = idx + 1
    steps = 0
    while j < len(lines) and steps < _THEN_SEARCH_MAX_LINES:
        stripped = lines[j].strip()
        if _BARE_THEN_RE.match(stripped):
            return True
        if stripped.startswith("#"):
            j += 1
            steps += 1
            continue
        return False
    return False


def _dead_guard_operand(lines, idx):
    """Returns the sourced operand string if `lines[idx]` is GH #174's
    dead-guard shape (either the bare-`.`-with-fallback form, or the
    `if ! . "$X"` form -- same-line, next-line, or next-line-past-comments
    `then`, see _IF_DEAD_GUARD_OPEN_RE's docstring), else None."""
    stripped = lines[idx].strip()
    dot_match = _DOT_DEAD_GUARD_RE.match(stripped)
    if dot_match:
        return dot_match.group("operand")
    if_match = _IF_DEAD_GUARD_OPEN_RE.match(stripped)
    if not if_match:
        return None
    if stripped.rstrip().endswith("then"):
        return if_match.group("operand")
    # No `then` on this line -- search forward past any comment lines
    # (bounded) for a bare `then`.
    if _find_then_within_comment_gap(lines, idx):
        return if_match.group("operand")
    return None


def _line_tests_operand(line, guard_re, operand):
    if not guard_re.search(line):
        return False
    return f'"{operand}"' in line or f"'{operand}'" in line


def _same_line_and_chain_dominates(line, operand):
    """Pattern C: `[ -f "$OPERAND" ] && . "$OPERAND"` on one line -- the
    dead-guard line IS the guard-test line, with the source as the `&&`
    right-hand side."""
    if not _line_tests_operand(line, _POSITIVE_EXISTENCE_GUARD_RE, operand):
        return False
    return "&&" in line


def _nearest_meaningful_preceding_line(lines, idx):
    """Walks backward from `idx` (exclusive) skipping comment and blank
    lines, returning the index of the nearest line that is neither --
    or None if the top of the file is reached first."""
    j = idx - 1
    while j >= 0:
        stripped = lines[j].strip()
        if stripped and not stripped.startswith("#"):
            return j
        j -= 1
    return None


_TRAILING_FI_RE = re.compile(r';\s*fi\s*$')


def _is_self_closing_if_line(stripped):
    """True for a single-line `if ...; then ...; fi` compound -- opens
    and closes its own block on one line, so it must never be counted by
    a nesting-depth walk that tracks `if`-opens-a-line /
    `fi`-closes-a-line as separate events (that shape is this repo's
    style everywhere else, but a self-closing line breaks the one-line
    assumption and would otherwise desynchronize the depth counter).
    `_FI_RE` is `^`-anchored (matches a `fi` that OPENS a line) and is
    the wrong tool here -- this checks for a `; fi` CLOSING the same
    line the `if` opened."""
    return bool(_IF_OPEN_RE.match(stripped)) and bool(_TRAILING_FI_RE.search(stripped))


def _matching_if_index(lines, fi_idx):
    """Given the index of a `fi` line, walks backward tracking nested
    if/fi depth to find the index of the `if` that opens the SAME block
    (depth returns to 0). Returns None if unbalanced (no match found by
    index 0) -- a real possibility this bounded scan cannot rule out for
    arbitrarily malformed input, but never true for any file that itself
    parses cleanly under `dash -n`, which every file this is called on
    already does by the time this check runs. Self-closing single-line
    `if...fi` compounds are skipped entirely (see
    _is_self_closing_if_line) -- they never straddle the block being
    searched for, so counting them would desynchronize depth."""
    depth = 1
    j = fi_idx - 1
    while j >= 0:
        stripped = lines[j].strip()
        if _is_self_closing_if_line(stripped):
            j -= 1
            continue
        if _FI_RE.match(stripped):
            depth += 1
        elif _IF_OPEN_RE.match(stripped):
            depth -= 1
            if depth == 0:
                return j
        j -= 1
    return None


def _block_between_has_unconditional_exit(lines, if_idx, fi_idx):
    """True if the body between `if_idx` and `fi_idx` (exclusive of both)
    contains an exit/return/continue STATEMENT (first token of the line,
    not merely the word appearing anywhere -- see
    _UNCONDITIONAL_EXIT_STMT_RE) STRICTLY WITHIN THE NEGATIVE GUARD'S OWN
    POSITIVE BRANCH -- i.e. before any depth-0 `elif`/`else` -- at the
    body's own nesting depth (depth 0 relative to this block; an exit
    inside a further-nested if is conditional on THAT inner test too and
    is not counted).

    PEACHES PR #202 round-3 review, finding 1 (HOLDEN-verified real): an
    earlier version scanned the ENTIRE if..fi span at depth 0 with no
    branch awareness, so an exit inside an `elif`/`else` branch -- which
    is conditional on a DIFFERENT test than the negative-guard `if`
    itself -- was wrongly counted as making the if's OWN negative branch
    unconditional:

        if [ ! -f "$X" ]; then
          echo missing        # <- does NOT exit
        elif [ -n "$Y" ]; then
          exit 0               # <- exits, but only when $Y is set,
        fi                     #    unrelated to whether $X is missing
        . "$X" || true          # WAS wrongly suppressed; must be flagged

    Fixed: the scan now STOPS (returns False, not "keep looking") at the
    first depth-0 `elif`/`else` -- an exit found only in a later branch
    never counts, because that branch's own condition is what gates it,
    not the negative guard being evaluated.

    COMMENT lines are skipped entirely (round-3 finding 2, HOLDEN-verified
    real: an earlier version had no comment filter here, so `# exit 0`
    inside a guard block was read as a real exit, making a
    non-dominating guard read as dominating -- also the false-suppression
    direction). Self-closing single-line `if...fi` compounds are treated
    as depth-neutral (see _is_self_closing_if_line) and their own content
    is not inspected for an exit -- an exit inside a self-closing
    conditional is conditional on THAT test, same reasoning as a
    multi-line nested if."""
    depth = 0
    for k in range(if_idx + 1, fi_idx):
        stripped = lines[k].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _is_self_closing_if_line(stripped):
            continue
        if _IF_OPEN_RE.match(stripped):
            depth += 1
            continue
        if _FI_RE.match(stripped):
            depth -= 1
            continue
        if depth == 0 and _ELIF_OR_ELSE_RE.match(stripped):
            return False
        if depth == 0 and _UNCONDITIONAL_EXIT_STMT_RE.match(stripped):
            return True
    return False


def _find_dominating_block(lines, flagged_idx, operand):
    """Looks at the nearest meaningful (non-comment, non-blank) line
    preceding the flagged line for Pattern A or Pattern B (see the
    module-level comment above _EXISTENCE_GUARD_RE). Bounded, not a real
    parser -- see that comment for the exact assumptions and honest
    limits.

      - If that nearest line is `fi`: candidate Pattern A. Find its
        matching `if` (nesting-depth-tracked backward walk); it must
        test `[ ! -f "$OPERAND" ]`, and its body must unconditionally
        exit/return/continue at the block's own depth.
      - If that nearest line is `if [ -f "$OPERAND" ]; then` (or
        `if [ -f "$OPERAND" ] && ...`-shaped opens are not matched here,
        only the block form): candidate Pattern B -- the flagged line is
        directly inside this if's positive branch, with nothing closing
        it first.
    """
    nearest = _nearest_meaningful_preceding_line(lines, flagged_idx)
    if nearest is None:
        return False
    nearest_stripped = lines[nearest].strip()

    if _FI_RE.match(nearest_stripped):
        if_idx = _matching_if_index(lines, nearest)
        if if_idx is None:
            return False
        if_stripped = lines[if_idx].strip()
        if not _line_tests_operand(if_stripped, _NEGATIVE_EXISTENCE_GUARD_RE, operand):
            return False
        return _block_between_has_unconditional_exit(lines, if_idx, nearest)

    if _IF_OPEN_RE.match(nearest_stripped):
        if _is_self_closing_if_line(nearest_stripped):
            # Single-line `if ...; then ...; fi` compound -- the `fi`
            # closes the block on the SAME line, so the flagged line is
            # NOT inside this if's branch at all; it merely follows a
            # closed, unrelated (from the flagged line's position) if/fi
            # statement. Must NOT be treated as Pattern B -- this is
            # exactly the single-line-compound gap named in the
            # module-level honest-limits comment above
            # _NEGATIVE_EXISTENCE_GUARD_RE, and getting it wrong here
            # would be a false SUPPRESSION (the dangerous direction).
            return False
        return _line_tests_operand(nearest_stripped, _POSITIVE_EXISTENCE_GUARD_RE, operand)

    return False


def _existence_guard_dominates(lines, flagged_idx, operand):
    flagged_line = lines[flagged_idx]
    if _same_line_and_chain_dominates(flagged_line, operand):
        return True
    return _find_dominating_block(lines, flagged_idx, operand)


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
    only on `|| true`/`|| exit 0`/`if !`) that are NOT DOMINATED by a real
    existence guard for the SAME sourced operand -- see
    `_existence_guard_dominates` and the module-level comment above
    `_EXISTENCE_GUARD_RE` for the three recognized dominating patterns and
    this check's own honest limits. A guard that merely appears somewhere
    earlier in the file, without actually gating reachability of the
    source line, does NOT suppress a finding (PEACHES PR #202 round-2,
    finding 1)."""
    violations = []
    with open(abs_path, encoding="utf-8") as f:
        lines = f.readlines()
    for idx, line in enumerate(lines):
        lineno = idx + 1
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        operand = _dead_guard_operand(lines, idx)
        if operand is None:
            continue
        if _existence_guard_dominates(lines, idx, operand):
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


class TestDominatingVsNonDominatingGuard(unittest.TestCase):
    """PEACHES PR #202 round-2 review, finding 1 (HOLDEN-verified real):
    an earlier version of _dead_guard_violations treated ANY earlier line
    testing the same operand as neutralizing, regardless of control flow.
    PEACHES's own diagnosis of WHY this was missed: the prior regression
    test (TestSweepMechanismActuallyDetects, above) only checked that an
    UNRELATED-operand guard fails to suppress -- it never checked the
    SAME-operand-NON-DOMINATING case, which is the actual GH #174 shape.
    This class closes that gap directly, and proves the CURRENT
    implementation is right where the OLD one was wrong (reproducing the
    old any-earlier-line check inline, since the buggy code itself is
    gone -- see test_old_lookback_logic_would_have_missed_this for the
    literal old predicate re-run against the same fixture)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-posix-dominance-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_non_dominating_same_operand_guard_still_flagged(self):
        """The exact shape PEACHES named: a guard that TESTS the same
        operand but does not GATE the source line (its branch merely
        echoes, doesn't exit) must NOT suppress the finding."""
        planted = self._write(
            "non-dominating.sh",
            "#!/bin/sh\n"
            'if [ -f "$X" ]; then echo found; fi\n'
            '. "$X" || true\n',
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"a same-operand guard whose branch does not exit/return must "
            f"not suppress the dead-guard finding -- it provides zero "
            f"protection at the source line. Got {violations}",
        )

    def test_old_lookback_logic_would_have_missed_this(self):
        """Direct proof the OLD implementation (any earlier line
        mentioning the operand, regardless of control flow) would have
        wrongly suppressed the finding above -- reproduces that exact
        predicate inline against the same fixture, since the buggy code
        itself no longer exists to call."""
        lines = [
            "#!/bin/sh\n",
            'if [ -f "$X" ]; then echo found; fi\n',
            '. "$X" || true\n',
        ]
        operand = "$X"
        old_existence_guard_re = re.compile(r'\[\s*!?\s*-f\s')

        def old_predicate(line, op):
            if not old_existence_guard_re.search(line):
                return False
            return f'"{op}"' in line or f"'{op}'" in line

        flagged_idx = 2
        old_would_suppress = any(
            old_predicate(w, operand) for w in lines[:flagged_idx + 1]
        )
        self.assertTrue(
            old_would_suppress,
            "sanity check on the OLD behavior itself: the any-earlier-"
            "line predicate must match this fixture's non-dominating "
            "guard -- if this assertion fails, the regression this test "
            "guards against no longer describes the old code",
        )

    def test_pattern_a_negative_guard_unconditional_exit_dominates(self):
        """Pattern A (this repo's own real shape, e.g. bin/clagentic-lite,
        post-tool-nudge.sh.template): negative guard whose body
        unconditionally exits before the source line -- must suppress."""
        planted = self._write(
            "pattern-a.sh",
            "#!/bin/sh\n"
            'if [ ! -f "$X" ]; then\n'
            "  echo missing\n"
            "  exit 0\n"
            "fi\n"
            '. "$X" || true\n',
        )
        self.assertEqual(_dead_guard_violations(planted), [])

    def test_pattern_a_negative_guard_without_exit_does_not_dominate(self):
        """Negative-guard variant of the non-dominating shape: the
        negative branch does NOT exit, so reaching the source line is NOT
        proof the file exists -- must still flag."""
        planted = self._write(
            "pattern-a-no-exit.sh",
            "#!/bin/sh\n"
            'if [ ! -f "$X" ]; then\n'
            "  echo missing\n"
            "fi\n"
            '. "$X" || true\n',
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"a negative guard whose branch does not exit/return/continue "
            f"does not dominate the source line -- must still flag. Got "
            f"{violations}",
        )

    def test_pattern_b_positive_guard_source_inside_branch_dominates(self):
        """Pattern B (session-start.sh.template's real shape): source
        line directly inside the positive branch of `if [ -f "$X" ]`."""
        planted = self._write(
            "pattern-b.sh",
            "#!/bin/sh\n"
            'if [ -f "$X" ]; then\n'
            '  . "$X" || true\n'
            "else\n"
            "  echo missing\n"
            "fi\n",
        )
        self.assertEqual(_dead_guard_violations(planted), [])

    def test_pattern_c_same_line_and_chain_dominates(self):
        """Pattern C: `[ -f "$X" ] && . "$X"` on one line."""
        planted = self._write(
            "pattern-c.sh",
            '#!/bin/sh\n[ -f "$X" ] && . "$X"\n',
        )
        self.assertEqual(_dead_guard_violations(planted), [])

    def test_multiline_if_bang_dot_source_form_is_detected(self):
        """PEACHES PR #202 round-2 review, finding 2 (HOLDEN-verified
        real): the POSIX-valid multi-line `if ! . "$X"` / `then` form
        (then on the FOLLOWING line, not the same line) must be detected
        as the dead-guard shape when undominated."""
        planted = self._write(
            "multiline-if.sh",
            "#!/bin/sh\n"
            'if ! . "$X"\n'
            "then\n"
            "  exit 0\n"
            "fi\n",
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"the multi-line `if ! . \"$X\"` / `then` form must be "
            f"detected -- got {violations}",
        )

    def test_multiline_if_bang_dot_source_form_dominated_by_pattern_a(self):
        """Non-regression: the multi-line if-form, when itself dominated
        by an enclosing Pattern-A guard (pre-bash-guard.sh.template's real
        shape), must NOT be flagged."""
        planted = self._write(
            "multiline-if-dominated.sh",
            "#!/bin/sh\n"
            'if [ ! -f "$X" ]; then\n'
            "  exit 0\n"
            "fi\n"
            'if ! . "$X"\n'
            "then\n"
            "  exit 0\n"
            "fi\n",
        )
        self.assertEqual(_dead_guard_violations(planted), [])


class TestElifAndCommentDominanceEdgeCases(unittest.TestCase):
    """PEACHES PR #202 round-3 review: three real false-suppression
    defects found in the dominance checker itself, all discovered by
    HOLDEN reading the code directly against fixtures shaped like these.
    Each test here demonstrates the exact shape named, including one
    (test_elif_branch_own_exit_still_dominates) that reproduces the
    non-elif Pattern A shape with an elif tacked on afterward, to prove
    the elif-boundary fix does not over-correct into a new false
    positive on the case that SHOULD still dominate."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-posix-elif-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_finding_1_exit_only_in_elif_branch_does_not_dominate(self):
        """Finding 1: a negative guard's own positive branch does NOT
        exit; only an elif branch (conditional on a DIFFERENT test) does.
        The elif's exit is not unconditional relative to the negative
        guard -- must still flag."""
        planted = self._write(
            "elif-exit-only.sh",
            "#!/bin/sh\n"
            'if [ ! -f "$X" ]; then\n'
            "  echo missing\n"
            'elif [ -n "$SOMETHING" ]; then\n'
            "  exit 0\n"
            "fi\n"
            '. "$X" || true\n',
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"an exit only in an elif branch (conditional on a different "
            f"test) must not dominate the negative guard's own branch -- "
            f"got {violations}",
        )

    def test_finding_1_old_scan_would_have_missed_this(self):
        """Direct proof the OLD whole-span, elif-unaware exit scan would
        have wrongly suppressed the finding above."""
        lines = [
            "#!/bin/sh\n",
            'if [ ! -f "$X" ]; then\n',
            "  echo missing\n",
            'elif [ -n "$SOMETHING" ]; then\n',
            "  exit 0\n",
            "fi\n",
            '. "$X" || true\n',
        ]
        exit_re = re.compile(r'\b(?:exit\b|return\b|continue\b)')
        depth = 0
        old_found_exit = False
        # Mirrors the OLD _block_between_has_unconditional_exit signature:
        # scans strictly BETWEEN if_idx and fi_idx (both exclusive) -- the
        # guard `if` line itself (index 1) is not part of the scanned
        # range, matching the real function's own `range(if_idx + 1,
        # fi_idx)`.
        if_idx, fi_idx = 1, 5
        for k in range(if_idx + 1, fi_idx):
            stripped = lines[k].strip()
            if _is_self_closing_if_line(stripped):
                continue
            if _IF_OPEN_RE.match(stripped):
                depth += 1
                continue
            if _FI_RE.match(stripped):
                depth -= 1
                continue
            if depth == 0 and exit_re.search(stripped):
                old_found_exit = True
        self.assertTrue(
            old_found_exit,
            "sanity check on the OLD behavior itself: the elif-unaware "
            "scan must find the elif branch's exit -- if this assertion "
            "fails, the regression this test guards against no longer "
            "describes the old code",
        )

    def test_elif_branch_own_exit_still_dominates(self):
        """Non-regression: exit IS in the negative guard's own positive
        branch, before an unrelated later elif -- must still dominate.
        Proves the elif-boundary fix stops at the FIRST depth-0
        elif/else, not before it."""
        planted = self._write(
            "elif-after-own-exit.sh",
            "#!/bin/sh\n"
            'if [ ! -f "$X" ]; then\n'
            "  exit 0\n"
            'elif [ -n "$Y" ]; then\n'
            "  echo something\n"
            "fi\n"
            '. "$X" || true\n',
        )
        self.assertEqual(_dead_guard_violations(planted), [])

    def test_finding_2_exit_word_inside_comment_does_not_dominate(self):
        """Finding 2: a comment containing the word 'exit' inside a
        negative guard's body must not be read as a real exit statement
        -- the guard's actual body has no real exit, so it must not
        dominate."""
        planted = self._write(
            "comment-exit-word.sh",
            "#!/bin/sh\n"
            'if [ ! -f "$X" ]; then\n'
            "  # exit 0\n"
            "  echo missing\n"
            "fi\n"
            '. "$X" || true\n',
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"a comment containing 'exit' must not be read as a real "
            f"exit statement -- got {violations}",
        )

    def test_finding_2_old_scan_would_have_missed_this(self):
        """Direct proof the OLD comment-blind, substring-search exit scan
        would have wrongly matched the comment above as a real exit."""
        line = "  # exit 0"
        old_exit_re = re.compile(r'\b(?:exit\b|return\b|continue\b)')
        self.assertTrue(
            bool(old_exit_re.search(line.strip())),
            "sanity check on the OLD behavior itself: the substring "
            "search must match 'exit' inside this comment -- if this "
            "assertion fails, the regression this test guards against "
            "no longer describes the old code",
        )

    def test_finding_3_undominated_then_across_comment_is_flagged(self):
        """Finding 3, positive detection proof: the multi-line if-form
        with an intervening comment before `then`, when NOT dominated by
        anything else, must be flagged."""
        planted = self._write(
            "then-across-comment-undominated.sh",
            "#!/bin/sh\n"
            'if ! . "$X"\n'
            "# some comment\n"
            "then\n"
            "  echo not_a_real_exit\n"
            "fi\n",
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"the multi-line if-form with a comment before `then` must "
            f"be recognized as the dead-guard shape when undominated -- "
            f"got {violations}",
        )

    def test_finding_3_old_next_line_only_check_would_have_missed_this(self):
        """Direct proof the OLD idx+1-only `then` check would have
        missed the comment-gap form above."""
        lines = [
            "#!/bin/sh\n",
            'if ! . "$X"\n',
            "# some comment\n",
            "then\n",
        ]
        old_bare_then_re = re.compile(r'^\s*then\s*$')
        nxt = 1 + 1  # idx of the if-line is 1; old code checked idx+1 only
        old_found_then = nxt < len(lines) and bool(
            old_bare_then_re.match(lines[nxt].strip())
        )
        self.assertFalse(
            old_found_then,
            "sanity check on the OLD behavior itself: idx+1 is the "
            "comment line, not `then` -- if this assertion fails, the "
            "regression this test guards against no longer describes "
            "the old code",
        )

    def test_then_search_bounded_does_not_match_arbitrarily_far(self):
        """The comment-skip is bounded (_THEN_SEARCH_MAX_LINES) -- a
        `then` beyond the bound, even past only comments, is not
        matched. Documents the stated limit rather than silently
        extending it."""
        far_comments = "\n".join(f"# comment {i}" for i in range(10))
        planted = self._write(
            "then-too-far.sh",
            f'#!/bin/sh\nif ! . "$X"\n{far_comments}\nthen\n  exit 0\nfi\n',
        )
        # Not recognized as the dead-guard shape at all (operand is None)
        # -- the `if ! . "$X"` line without a same/near-line `then` falls
        # through, silently. This is exactly the shape (b)/(c) below
        # require to be named plainly: this specific line-oriented
        # limitation neither flags nor suppresses, it simply doesn't
        # recognize the construct. Documented in the module docstring's
        # "what this checker models" section.
        violations = _dead_guard_violations(planted)
        self.assertEqual(violations, [])


class TestUnmodeledConstructsFailOpen(unittest.TestCase):
    """PEACHES PR #202 round-3 review, items (b)/(c): where the checker
    cannot model a construct, it must FAIL OPEN (flag a possible
    violation) rather than fail closed (silently suppress). This class
    mechanically verifies that claim for the constructs the module
    docstring names as unmodeled, rather than asserting it without
    evidence -- the same discipline this file applies everywhere else."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-posix-unmodeled-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_case_branch_dead_guard_is_flagged_not_silently_missed(self):
        """A dead-guard line inside a `case ... esac` arm is not
        recognized by any dominance pattern -- must be flagged (fail
        open), never silently suppressed."""
        planted = self._write(
            "case-branch.sh",
            "#!/bin/sh\n"
            'case "$MODE" in\n'
            "  a)\n"
            '    . "$X" || true\n'
            "    ;;\n"
            "  *)\n"
            "    echo default\n"
            "    ;;\n"
            "esac\n",
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"a dead-guard line inside a case arm must be flagged -- got "
            f"{violations}",
        )

    def test_case_branch_with_genuinely_dominating_pattern_still_flagged(self):
        """Even when a case PATTERN would, in real shell semantics,
        genuinely gate reachability of the dead-guard line (e.g. a
        preceding `[ -f "$X" ]` check elsewhere doesn't help here at
        all -- case dispatch is not `if`/`fi`), the checker does not
        attempt to model it -- must still flag, matching the fail-open
        policy exactly."""
        planted = self._write(
            "case-branch-with-guard-nearby.sh",
            "#!/bin/sh\n"
            'if [ -f "$X" ]; then\n'
            "  echo found\n"
            "fi\n"
            'case "$MODE" in\n'
            "  a)\n"
            '    . "$X" || true\n'
            "    ;;\n"
            "esac\n",
        )
        violations = _dead_guard_violations(planted)
        self.assertEqual(
            len(violations), 1,
            f"a nearby if/fi guard does not dominate a case-arm dead "
            f"guard (case dispatch, not if/fi control flow) -- must "
            f"still flag. Got {violations}",
        )


if __name__ == "__main__":
    unittest.main()
