"""
Every gates.sh subcommand must reject arguments it does not accept.

The dispatcher forwards "$@" to each cmd_X. A subcommand that silently
ignores an unknown argument turns a misspelled flag (`--fullscan`) into a
quietly different run: the operator believes they asked for a full scan and
got the default, scoped one. Each subcommand now fails loudly with a usage
line and a nonzero exit.

The subcommand list is read from the real dispatcher, not maintained here,
so a subcommand added later is swept automatically.

Run with: python3 -m unittest scripts.test_gates_unknown_args -v
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_gates_dispatcher_forwards_args import _dispatcher_case_arms  # noqa: E402
from test_source_helpers import GATES_SH, source_env  # noqa: E402

# Subcommands that legitimately take one optional positional argument.
_FILE_POSITIONAL = {"render-manifest", "render-review", "deferrals-lint",
                    "audit-vocab-lint", "status"}
# Subcommands with no accepted arguments at all. pre-push is separate: git
# invokes it with `<remote-name> <remote-url>`, so it takes exactly 0 or 2.
_NO_ARGS = {"init", "deps", "sast", "ship", "digest"}
# (subcommand, allowed flags) pairs, each of which must be accepted.
_ACCEPTED_FLAGS = {
    "secrets": ["--full-scan"],
    "bleed": ["--full-scan"],
    "review": ["--full-review", "--since-last-review", "--reset-dedup"],
    "adversarial": ["--full-review"],
    "merge-gate": ["--recheck"],
    "tail": ["--no-follow"],
}


class _Scratch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-unknown-args-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.home)
        env = self._env()
        subprocess.run(["git", "init", "-q", "-b", "main", self.repo],
                       check=True, env=env)

    def _env(self):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("GIT_") and not k.startswith("CLAGENTIC_")}
        env["HOME"] = self.home
        env["CLAGENTIC_PROJECT_ROOT"] = self.repo
        return env

    def _gates(self, *args):
        return subprocess.run(
            ["sh", GATES_SH, *args], env=self._env(), cwd=self.repo,
            capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL,
        )


class TestEverySubcommandRejectsAnUnknownOption(_Scratch):

    def test_unknown_option_is_a_usage_error_for_every_subcommand(self):
        arms = _dispatcher_case_arms()
        self.assertGreaterEqual(len(arms), 15, "dispatcher parse found too few arms")
        failures = []
        for name in sorted(arms):
            r = self._gates(name, "--definitely-not-a-flag")
            if r.returncode == 0 or "usage" not in r.stderr.lower():
                failures.append(
                    f"{name}: rc={r.returncode} stderr={r.stderr.strip()[:200]!r}")
        self.assertEqual(
            failures, [],
            "these subcommands accepted (or ignored) an unknown option:\n"
            + "\n".join(failures),
        )

    def test_misspelled_full_scan_does_not_narrow_silently(self):
        for sub in ("secrets", "bleed"):
            r = self._gates(sub, "--fullscan")
            self.assertEqual(r.returncode, 2, msg=f"{sub}: {r.stderr}")
            self.assertIn("--fullscan", r.stderr)
            self.assertIn("usage: gates.sh " + sub, r.stderr)


class TestPositionalArguments(_Scratch):

    def test_subcommands_without_arguments_reject_a_stray_positional(self):
        for sub in sorted(_NO_ARGS):
            r = self._gates(sub, "stray")
            self.assertEqual(r.returncode, 2, msg=f"{sub}: {r.stderr}")
            self.assertIn("unexpected argument 'stray'", r.stderr)

    def test_single_positional_subcommands_reject_a_second_one(self):
        for sub in sorted(_FILE_POSITIONAL):
            r = self._gates(sub, "one", "two")
            self.assertEqual(r.returncode, 2, msg=f"{sub}: {r.stderr}")
            self.assertIn("unexpected argument 'two'", r.stderr)

    def test_log_run_requires_two_or_three_arguments(self):
        for args in ([], ["gate"], ["g", "o", "d", "extra"]):
            r = self._gates("log-run", *args)
            self.assertEqual(r.returncode, 2, msg=f"{args}: {r.stderr}")
            self.assertIn("usage: gates.sh log-run", r.stderr)


class TestPrePushArguments(_Scratch):
    """git runs the hook as `pre-push <remote-name> <remote-url>` with ref
    lines on stdin. Exactly 0 or 2 positional arguments are valid."""

    def _pre_push(self, *args):
        env = self._env()
        # No scanner is available or wanted: the argument check runs before
        # any gate, and the valid forms only need to get past it.
        env["CLAGENTIC_GATES"] = "none"
        return subprocess.run(
            ["sh", GATES_SH, "pre-push", *args], env=env, cwd=self.repo,
            capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL,
        )

    def test_zero_and_two_positional_arguments_are_accepted(self):
        for args in ([], ["origin", "https://example.invalid/r.git"]):
            r = self._pre_push(*args)
            self.assertNotEqual(r.returncode, 2, msg=f"{args}: {r.stderr}")
            self.assertNotIn("usage: gates.sh pre-push", r.stderr)

    def test_one_positional_argument_is_rejected(self):
        r = self._pre_push("origin")
        self.assertEqual(r.returncode, 2, msg=r.stderr)
        self.assertIn("usage: gates.sh pre-push", r.stderr)

    def test_three_positional_arguments_are_rejected(self):
        r = self._pre_push("origin", "url", "extra")
        self.assertEqual(r.returncode, 2, msg=r.stderr)
        self.assertIn("usage: gates.sh pre-push", r.stderr)

    def test_a_flag_is_rejected_even_with_two_arguments(self):
        for args in (["--full-scan"], ["--no-verify", "url"]):
            r = self._pre_push(*args)
            self.assertEqual(r.returncode, 2, msg=f"{args}: {r.stderr}")
            self.assertIn("usage: gates.sh pre-push", r.stderr)


class TestAcceptedArgumentsStillWork(_Scratch):
    """The check must not reject the flags each subcommand documents."""

    def _check(self, sub, flags, positional=""):
        body = f'_gate_check_args {sub} "{" ".join(flags)}" "{positional}" ' + " ".join(
            flags + ([positional] if positional else [])) + "\n"
        env = self._env()
        env.update(source_env(gates=True))
        r = subprocess.run(
            ["sh", "-c", f". '{GATES_SH}'\n{body}", GATES_SH],
            env=env, cwd=self.repo, capture_output=True, text=True, timeout=60)
        return r

    def test_documented_flags_are_accepted(self):
        for sub, flags in _ACCEPTED_FLAGS.items():
            r = self._check(sub, flags)
            self.assertEqual(r.returncode, 0, msg=f"{sub}: {r.stderr}")

    def test_one_optional_positional_is_accepted(self):
        r = self._check("render-manifest", [], positional="FILE")
        self.assertEqual(r.returncode, 0, msg=r.stderr)

    def test_real_subcommands_run_with_their_documented_arguments(self):
        self.assertEqual(self._gates("init").returncode, 0)
        self.assertEqual(self._gates("status", "3").returncode, 0)
        self.assertEqual(self._gates("tail", "--no-follow").returncode, 0)
        self.assertEqual(self._gates("digest").returncode, 0)


if __name__ == "__main__":
    unittest.main()
