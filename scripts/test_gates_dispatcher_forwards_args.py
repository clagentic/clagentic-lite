"""
Regression test for lr-51112e (dispatcher sweep, non-negotiable 8 "fix the
pattern, not the line"): every scripts/gates.sh subcommand whose cmd_X
function accepts arguments must be dispatched via `shift; cmd_X "$@"`, never
a bare `cmd_X` that silently drops everything after argv[0].

BACKGROUND: `secrets)` was dispatched as a bare `cmd_secrets` with no shift
and no "$@" forward -- lr-51112e's own --full-scan flag (see
scripts/test_secrets_branch_scope.py) would have been silently swallowed at
the dispatcher before ever reaching cmd_secrets, exactly the same shape a
prior task already fixed for `adversarial` (see the case block's own
comment history). This is a recurring defect CLASS, not a one-off typo --
this test sweeps every entry in the dispatcher's `case "${1:-}" in ... esac`
block mechanically, so a future subcommand added to that block with the same
argument-dropping shape is caught here rather than rediscovered by a user
whose flag silently did nothing.

Two layers of coverage, deliberately not just one:

  1. **Anchored static check** (`TestDispatcherCaseArmsShiftAndForwardArgv`):
     reads each subcommand's own case arm directly out of the REAL
     scripts/gates.sh source text (never a hand-copied re-implementation of
     the dispatch logic, which could silently drift from what ships) and
     asserts it both `shift`s (consumes the subcommand token) and forwards
     `"$@"` to its `cmd_X` call.
  2. **Runtime check** (`TestDispatcherActuallyForwardsArgvAtRuntime`):
     invokes the real `scripts/gates.sh secrets --full-scan` end-to-end and
     confirms the dispatcher does not error or swallow the trailing flag
     before it ever reaches `cmd_secrets`. The POSITIVE proof that a
     forwarded flag actually changes `cmd_secrets`' own behavior (scoped vs.
     full-history stderr output) lives in `test_secrets_branch_scope.py`,
     which needs `gitleaks git` (8.19+) to exercise meaningfully; this file
     stays gitleaks-version-independent so the dispatcher-forwarding
     property itself is verified on every installed gitleaks version, not
     only 8.19+.

Run with: python3 -m unittest scripts.test_gates_dispatcher_forwards_args -v
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH  # noqa: E402

# PEACHES PR #217 review (comment 5820512826): a hand-enumerated subcommand
# list can drift from the real dispatcher -- a newly added case arm that
# forgets `shift; cmd_X "$@"` would simply never be added to a static list
# either, so the sweep silently never reaches it. `_dispatcher_case_arms`
# below parses every arm out of the REAL `case "${1:-}" in ... esac` block in
# scripts/gates.sh mechanically, so the set of subcommands under test is
# always exactly what the dispatcher itself declares, not a maintained copy
# of it that can go stale the moment someone adds a tenth subcommand.
#
def _dispatcher_case_labels(block):
    """Return every case-arm LABEL (subcommand name) found in `block`,
    independent of how much of the arm's body is captured -- a separate,
    narrower regex than _dispatcher_case_arms' own body-matching one, used
    only to cross-check that every labeled arm actually got an entry in the
    parsed dict (see PEACHES PR #217 review, comment 5821185384 below)."""
    return re.findall(r'\n {4}([A-Za-z0-9_-]+)\)', block)


def _dispatcher_case_arms():
    """Parse every `SUBCOMMAND)  shift; cmd_X "$@" ;;`-shaped arm directly
    out of the real scripts/gates.sh dispatcher, keyed by subcommand name,
    value is the raw arm text. Excludes the trailing `*) echo usage...`
    catch-all (it has no cmd_X call and isn't a real subcommand). Raises if
    the parse finds nothing, so a dispatcher restructure that breaks this
    regex fails loudly here rather than silently sweeping zero entries.

    MULTI-LINE ARMS (PEACHES PR #217 review, comment 5821185384): the
    original body regex here was `([^\\n]*);;` -- `[^\\n]*` stops at the
    first newline, so a case arm written across multiple lines (e.g.
    `secrets)\\n    shift\\n    cmd_secrets "$@"\\n    ;;`) either failed to
    match its own `;;` terminator at all (silently omitting that arm from
    the swept set entirely -- the sweep then reports a clean pass while
    never having examined that arm) or matched a truncated, wrong body. The
    body pattern now spans newlines (`[\\s\\S]*?`, non-greedy so it stops at
    the FIRST `;;` rather than swallowing subsequent arms), and the caller
    below additionally asserts the parsed arm COUNT equals the number of
    case LABELS found by _dispatcher_case_labels -- a second, narrower
    regex that only needs to find `NAME)`, not the whole arm body -- so a
    future shape neither regex fully handles fails loudly here (arm count
    mismatch) instead of silently sweeping fewer arms than the dispatcher
    actually declares."""
    with open(GATES_SH) as f:
        src = f.read()
    case_start = src.index('\n  case "${1:-}" in')
    case_end = src.index('\n  esac', case_start)
    block = src[case_start:case_end]
    labels = _dispatcher_case_labels(block)
    arms = {}
    for m in re.finditer(
        r'\n {4}([A-Za-z0-9_-]+)\)([\s\S]*?);;',
        block,
    ):
        name, body = m.group(1), m.group(2)
        arms[name] = f"{name}){body};;"
    if not arms:
        raise AssertionError(
            f"mechanical parse of the case \"${{1:-}}\" in ... esac block found "
            f"no arms at all -- the dispatcher block shape in {GATES_SH} has "
            f"changed and this parser needs updating, not the assertions below"
        )
    if len(arms) != len(labels):
        raise AssertionError(
            f"dispatcher case block declares {len(labels)} label(s) "
            f"({sorted(set(labels))}) but the body parse only produced "
            f"{len(arms)} arm(s) ({sorted(arms)}) -- at least one case arm's "
            f"body could not be matched up to its own `;;` terminator (a "
            f"multi-line arm shape the body regex does not yet handle, or a "
            f"duplicate label) and was SILENTLY DROPPED from the swept set. "
            f"Fix the parser in {__file__}, not the assertions below -- a "
            f"dropped arm here means the shift/\"$@\" sweep never examined it."
        )
    return arms


# Subcommands under test = every real dispatcher arm, derived mechanically
# above -- never a hand-maintained list. `init` is genuinely argument-less by
# design (cmd_init ignores its own argv) but is swept identically to every
# other entry (see test_init_is_deliberately_argument_less_but_still_shifts),
# not carved out as a silent exception.
_SUBCOMMANDS_WITH_ARGS = [(name, ["--some-future-flag"]) for name in sorted(_dispatcher_case_arms())]


def _case_block_dispatches(subcommand):
    """Return the real dispatcher's own one-line case arm for `subcommand`,
    read directly from the mechanically parsed case block (see
    _dispatcher_case_arms) so this assertion can never silently drift from
    what ships -- a hand-copied re-implementation of the dispatch logic
    would only prove a COPY forwards args, not the real file."""
    arms = _dispatcher_case_arms()
    if subcommand not in arms:
        raise AssertionError(f"no dispatcher case arm found for {subcommand!r} in {GATES_SH}")
    return arms[subcommand]


def _expected_handler_name(subcommand):
    """Map a dispatcher subcommand LABEL to its cmd_X handler function name,
    e.g. "merge-gate" -> "cmd_merge_gate". Every real dispatcher arm in
    scripts/gates.sh follows this mapping (dashes become underscores,
    "cmd_" prefixed) -- confirmed against every current label
    (init/bleed/secrets/deps/sast/review/adversarial/merge-gate/
    render-review/render-manifest/deferrals-lint/audit-vocab-lint/ship/
    pre-push/log-run/digest/status/tail)."""
    return "cmd_" + subcommand.replace("-", "_")


# PEACHES PR #218 review (comment 5833150249): the prior version of this
# assertion only checked that `shift;`/`shift ;` and `"$@"` occurred
# SOMEWHERE in the arm, independently -- an arm shaped like
# `secrets) shift; log_args "$@"; cmd_secrets ;;` would pass both
# independent substring checks (it contains "shift;" and it contains
# '"$@"') while cmd_secrets itself still receives NO arguments at all,
# because "$@" was bound to a DIFFERENT call (log_args) in the same arm.
# The real property under test is the ORDERED, BOUND sequence
# `shift; cmd_X "$@"` -- shift immediately followed by the actual handler
# call with "$@" attached to THAT call, not merely present somewhere in the
# arm's text. Matched via a regex anchored on the literal expected handler
# name (derived mechanically, never hand-maintained -- see
# _expected_handler_name above) so a typo'd or wrong handler name in the
# arm is caught by the SAME assertion, not a separate one.
def _shift_then_bound_call_pattern(handler):
    return re.compile(r'shift\s*;\s*' + re.escape(handler) + r'\s+"\$@"')


class TestDispatcherCaseArmsShiftAndForwardArgv(unittest.TestCase):
    """Static-but-anchored check: every subcommand's own case arm, read
    directly from the real dispatcher source, must both `shift` (consume the
    subcommand token itself) and forward `"$@"` to its cmd_X call -- the
    exact shape lr-51112e's field report named as missing for
    secrets/deps/sast/ship/pre-push/digest (gates.sh's dispatcher, at the
    time of that report).

    Asserts the ORDERED, BOUND `shift; cmd_X "$@"` sequence directly (not
    "shift" and '"$@"' as two independent substring checks -- see PEACHES
    PR #218 review, comment 5833150249, and
    TestOrderedBindingRejectsArgvDroppedToADifferentCall below for the
    regression this closes)."""

    def test_every_subcommand_with_args_shifts_and_forwards(self):
        not_bound = []
        for subcommand, _extra_args in _SUBCOMMANDS_WITH_ARGS:
            arm = _case_block_dispatches(subcommand)
            handler = _expected_handler_name(subcommand)
            if not _shift_then_bound_call_pattern(handler).search(arm):
                not_bound.append((subcommand, handler, arm))
        self.assertEqual(
            not_bound, [],
            msg=f"dispatcher case arm(s) do not contain the ordered, bound "
                f"`shift; cmd_X \"$@\"` sequence -- either `shift` is missing, "
                f"`\"$@\"` is bound to a DIFFERENT call in the same arm (the "
                f"subcommand's own argv is then silently dropped before "
                f"reaching cmd_X), or the handler name does not match the "
                f"expected cmd_<subcommand> mapping: {not_bound}",
        )

    def test_init_is_deliberately_argument_less_but_still_shifts(self):
        """`init` takes no meaningful arguments (cmd_init ignores its own
        argv entirely), but the dispatcher arm itself was fixed to `shift;
        cmd_init "$@"` for consistency with every other entry, rather than
        being a second bare-call special case future maintainers have to
        remember the reason for."""
        arm = _case_block_dispatches("init")
        self.assertTrue(_shift_then_bound_call_pattern("cmd_init").search(arm))


class TestOrderedBindingRejectsArgvDroppedToADifferentCall(unittest.TestCase):
    """Regression pin for PEACHES PR #218 review, comment 5833150249: a
    negative control proving the ordered-binding assertion actually rejects
    the exact shape the old independent-substring-check version would have
    missed -- an arm that shifts and uses "$@" somewhere, but binds it to a
    call OTHER than the real cmd_X handler, must fail."""

    def test_shift_and_dollar_at_present_but_bound_to_wrong_call_fails(self):
        arm = 'secrets) shift; log_args "$@"; cmd_secrets ;;'
        handler = _expected_handler_name("secrets")
        self.assertIsNone(
            _shift_then_bound_call_pattern(handler).search(arm),
            msg="an arm binding \"$@\" to log_args instead of cmd_secrets "
                "must NOT satisfy the ordered-binding pattern -- cmd_secrets "
                "still receives no arguments in this shape",
        )

    def test_bare_cmd_call_with_no_dollar_at_fails(self):
        arm = 'secrets) shift; cmd_secrets ;;'
        handler = _expected_handler_name("secrets")
        self.assertIsNone(_shift_then_bound_call_pattern(handler).search(arm))

    def test_correctly_bound_shift_then_call_passes(self):
        arm = 'secrets) shift; cmd_secrets "$@" ;;'
        handler = _expected_handler_name("secrets")
        self.assertIsNotNone(_shift_then_bound_call_pattern(handler).search(arm))


class TestDispatcherParserHandlesMultiLineArms(unittest.TestCase):
    """Regression pin for PEACHES PR #217 review, comment 5821185384: the
    body regex used to be `([^\\n]*);;`, which stops at the FIRST newline --
    a multi-line case arm (a plausible style once an arm's body grows past
    one line) either failed to match its own `;;` terminator at all, or
    matched a truncated body missing the tokens under test. Both failure
    modes mean the shift/"$@" sweep silently never examines that arm.

    These tests exercise `_dispatcher_case_arms`/`_dispatcher_case_labels`
    directly against small SYNTHETIC case blocks (not the real gates.sh
    file) so the parser's own multi-line handling and count-mismatch guard
    are pinned independently of what gates.sh's dispatcher currently
    contains."""

    def test_multiline_arm_is_captured_in_full(self):
        block = (
            '\n  case "${1:-}" in\n'
            '    secrets)\n'
            '        shift\n'
            '        cmd_secrets "$@"\n'
            '        ;;\n'
            '    deps)           shift; cmd_deps "$@" ;;\n'
            '  esac'
        )
        arms = {}
        labels = _dispatcher_case_labels(block)
        for m in re.finditer(r'\n {4}([A-Za-z0-9_-]+)\)([\s\S]*?);;', block):
            name, body = m.group(1), m.group(2)
            arms[name] = f"{name}){body};;"
        self.assertEqual(sorted(arms), sorted(set(labels)))
        self.assertIn("secrets", arms)
        self.assertIn("shift", arms["secrets"])
        self.assertIn('"$@"', arms["secrets"])
        self.assertIn('cmd_secrets "$@"', arms["secrets"])

    def test_multiline_arm_missing_shift_is_detected_not_silently_dropped(self):
        """The actual regression this task fixes: a multi-line arm that
        FORGOT shift/"$@" must still be captured (and therefore still fail
        the shift/forward assertions in TestDispatcherCaseArmsShiftAndForwardArgv)
        -- not silently vanish from the parsed set, which would make the
        sweep report a clean pass despite the real defect."""
        block = (
            '\n  case "${1:-}" in\n'
            '    secrets)\n'
            '        cmd_secrets\n'
            '        ;;\n'
            '  esac'
        )
        arms = {}
        for m in re.finditer(r'\n {4}([A-Za-z0-9_-]+)\)([\s\S]*?);;', block):
            name, body = m.group(1), m.group(2)
            arms[name] = f"{name}){body};;"
        self.assertIn("secrets", arms, msg="a multi-line arm must still be parsed even when it "
                                            "lacks shift/\"$@\" -- silently dropping it would hide "
                                            "the exact defect this sweep exists to catch")
        self.assertNotIn("shift", arms["secrets"])
        self.assertNotIn('"$@"', arms["secrets"])

    def test_arm_count_mismatch_raises_loudly(self):
        """_dispatcher_case_arms itself (not the synthetic-block helpers
        above) must raise when the body regex produces fewer arms than the
        label regex finds -- the exact failure mode a body regex that still
        cannot handle some future arm shape (or a duplicate label silently
        collapsed by dict assignment) would otherwise hide silently. Patches
        open() so a SYNTHETIC source (a duplicate `secrets)` label -- two
        labels, one surviving dict entry) drives the real
        _dispatcher_case_arms code path end-to-end, not a hand-reimplemented
        copy of its parsing logic."""
        fake_src = (
            'x=1\n'
            '  case "${1:-}" in\n'
            '    secrets)        shift; cmd_secrets "$@" ;;\n'
            '    secrets)        shift; cmd_secrets "$@" ;;\n'
            '  esac\n'
        )

        class _FakeFile:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *exc):
                return False

            def read(self_inner):
                return fake_src

        real_open = open

        def _fake_open(path, *a, **kw):
            if path == GATES_SH:
                return _FakeFile()
            return real_open(path, *a, **kw)

        with unittest.mock.patch("builtins.open", side_effect=_fake_open):
            with self.assertRaises(AssertionError) as ctx:
                _dispatcher_case_arms()
        self.assertIn("SILENTLY DROPPED", str(ctx.exception))


class TestDispatcherActuallyForwardsArgvAtRuntime(unittest.TestCase):
    """Runtime check, not just source-text: invoke the REAL scripts/gates.sh
    end-to-end for `secrets --full-scan` inside a fresh scratch git repo and
    confirm the dispatcher does not error or otherwise choke on the trailing
    flag before reaching cmd_secrets -- a dispatcher that dropped the flag
    silently is indistinguishable from one that forwarded it correctly by
    exit code alone, but a dispatcher that CHOKED on the extra argv token
    (a shell syntax error, an "unbound variable" under a stricter shell, or
    gates.sh's own `*) echo "usage: ..." ; exit 1` catch-all firing because
    "secrets --full-scan" as a whole failed to match the `secrets)` arm) is
    caught here directly. See test_secrets_branch_scope.py for the POSITIVE
    proof that a forwarded --full-scan flag actually changes cmd_secrets'
    own scoping behavior (needs gitleaks 8.19+ to exercise meaningfully)."""

    def test_secrets_full_scan_flag_does_not_confuse_the_dispatcher(self):
        tmp = tempfile.mkdtemp(prefix="clagentic-test-dispatch-argv-")
        try:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            env = os.environ.copy()
            env["CLAGENTIC_PROJECT_ROOT"] = tmp
            env["CLAGENTIC_SKIP_SECRETS_CANARY"] = "1"
            r = subprocess.run(
                [GATES_SH, "secrets", "--full-scan"],
                capture_output=True, text=True, env=env, cwd=tmp, timeout=60,
            )
            self.assertNotIn("usage: gates.sh", r.stderr,
                             f"the dispatcher's own catch-all fired -- \"secrets --full-scan\" did "
                             f"not match the secrets) case arm\nstdout={r.stdout}\nstderr={r.stderr}")
            self.assertIn(r.returncode, (0, 1),
                         f"cmd_secrets should either pass (0) or block on a real/canary finding "
                         f"(1) -- any other exit code means the dispatcher or cmd_secrets itself "
                         f"errored on the extra argv token\nstdout={r.stdout}\nstderr={r.stderr}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
