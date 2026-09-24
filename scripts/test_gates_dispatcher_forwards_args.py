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
     which needs `gitleaks git` (8.18+) to exercise meaningfully; this file
     stays gitleaks-version-independent so the dispatcher-forwarding
     property itself is verified on every installed gitleaks version, not
     only 8.18+.

Run with: python3 -m unittest scripts.test_gates_dispatcher_forwards_args -v
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

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
def _dispatcher_case_arms():
    """Parse every `SUBCOMMAND)  shift; cmd_X "$@" ;;`-shaped arm directly
    out of the real scripts/gates.sh dispatcher, keyed by subcommand name,
    value is the raw arm text. Excludes the trailing `*) echo usage...`
    catch-all (it has no cmd_X call and isn't a real subcommand). Raises if
    the parse finds nothing, so a dispatcher restructure that breaks this
    regex fails loudly here rather than silently sweeping zero entries."""
    with open(GATES_SH) as f:
        src = f.read()
    case_start = src.index('\n  case "${1:-}" in')
    case_end = src.index('\n  esac', case_start)
    block = src[case_start:case_end]
    arms = {}
    for m in re.finditer(
        r'\n {4}([A-Za-z0-9_-]+)\)([^\n]*);;',
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


class TestDispatcherCaseArmsShiftAndForwardArgv(unittest.TestCase):
    """Static-but-anchored check: every subcommand's own case arm, read
    directly from the real dispatcher source, must both `shift` (consume the
    subcommand token itself) and forward `"$@"` to its cmd_X call -- the
    exact shape lr-51112e's field report named as missing for
    secrets/deps/sast/ship/pre-push/digest (gates.sh's dispatcher, at the
    time of that report)."""

    def test_every_subcommand_with_args_shifts_and_forwards(self):
        missing_shift = []
        missing_forward = []
        for subcommand, _extra_args in _SUBCOMMANDS_WITH_ARGS:
            arm = _case_block_dispatches(subcommand)
            if "shift;" not in arm and "shift ;" not in arm:
                missing_shift.append((subcommand, arm))
            if '"$@"' not in arm:
                missing_forward.append((subcommand, arm))
        self.assertEqual(
            missing_shift, [],
            msg=f"dispatcher case arm(s) missing `shift` before calling cmd_X -- "
                f"the subcommand token itself would leak into cmd_X's own argv[1]: {missing_shift}",
        )
        self.assertEqual(
            missing_forward, [],
            msg=f"dispatcher case arm(s) missing `\"$@\"` -- every argument after the "
                f"subcommand name is silently dropped before reaching cmd_X: {missing_forward}",
        )

    def test_init_is_deliberately_argument_less_but_still_shifts(self):
        """`init` takes no meaningful arguments (cmd_init ignores its own
        argv entirely), but the dispatcher arm itself was fixed to `shift;
        cmd_init "$@"` for consistency with every other entry, rather than
        being a second bare-call special case future maintainers have to
        remember the reason for."""
        arm = _case_block_dispatches("init")
        self.assertIn("shift", arm)
        self.assertIn('"$@"', arm)


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
    own scoping behavior (needs gitleaks 8.18+ to exercise meaningfully)."""

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
