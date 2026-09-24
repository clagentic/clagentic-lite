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
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH  # noqa: E402

# Every subcommand `scripts/gates.sh`'s own usage string documents as taking
# an argument. `init` is genuinely argument-less by design (cmd_init ignores
# its own argv) but is included below too, so its dispatcher arm's own
# `shift; cmd_init "$@"` consistency (see
# test_init_is_deliberately_argument_less_but_still_shifts) is swept the same
# way as every other entry, not carved out as a silent exception.
# `status`/`tail`/`render-manifest`/`deferrals-lint`/`audit-vocab-lint`/
# `render-review`/`log-run`/`review`/`merge-gate`/`bleed`/`adversarial`
# already forwarded correctly before this task -- included here anyway so a
# future regression on an already-correct entry is caught by the same sweep,
# not just the entries this task fixed.
_SUBCOMMANDS_WITH_ARGS = [
    ("init", []),
    ("bleed", ["--full-scan"]),
    ("secrets", ["--full-scan"]),
    ("deps", ["--some-future-flag"]),
    ("sast", ["--some-future-flag"]),
    ("review", ["--full-review"]),
    ("adversarial", ["--full-review"]),
    ("merge-gate", ["--recheck"]),
    ("render-review", ["some-file.json"]),
    ("render-manifest", ["some-file.json"]),
    ("deferrals-lint", ["some-file.json"]),
    ("audit-vocab-lint", ["some-file.sh"]),
    ("ship", ["--some-future-flag"]),
    ("pre-push", ["--some-future-flag"]),
    ("log-run", ["gate", "outcome", "details"]),
    ("digest", ["--some-future-flag"]),
    ("status", ["5"]),
    ("tail", ["--no-follow"]),
]


def _case_block_dispatches(subcommand):
    """Extract the real dispatcher's own one-line case arm for `subcommand`
    directly from the current scripts/gates.sh source, so this assertion can
    never silently drift from what ships -- a hand-copied re-implementation
    of the dispatch logic would only prove a COPY forwards args, not the
    real file. Returns the raw text of the arm (e.g.
    'secrets)        shift; cmd_secrets "$@" ;;')."""
    with open(GATES_SH) as f:
        src = f.read()
    marker = f'\n    {subcommand})'
    # bleed's own arm starts with "bleed)" with no leading space token before
    # the paren in the alignment gates.sh uses -- match on the exact token
    # boundary (subcommand followed immediately by `)`), not a substring
    # that could also match a longer subcommand name sharing a prefix.
    idx = src.find(marker)
    if idx == -1:
        raise AssertionError(f"no dispatcher case arm found for {subcommand!r} in {GATES_SH}")
    end = src.index(";;", idx)
    return src[idx:end + 2]


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
