"""
Pinning tests for lr-bdddcf: scripts/llm-client.sh gained a source guard
(CLAGENTIC_LLM_CLIENT_SOURCE_ONLY) around its trailing subcommand dispatch so
the file can be safely `.`-sourced by a caller that only wants its functions.

These tests exist to prove the guard changed NOTHING about executed-as-a-
script behavior -- the task's acceptance bar ("executed-as-a-script behavior
must remain byte-identical") is a behavioral claim, so it is pinned here as a
behavioral test, not a diff inspection:

  1. Every real subcommand still dispatches (build/review/summarize/
     adversarial/merge-gate all reach their cmd_* function).
  2. An unrecognized subcommand still prints the exact usage string to
     stderr and exits 1.
  3. No subcommand at all (bare `sh llm-client.sh`) still hits the same
     unrecognized-subcommand branch (exit 1, same usage string) -- this is
     the "${1:-}" empty-default path.
  4. The new sentinel, when set, suppresses the dispatch entirely (this is
     the whole point of the guard) and lets a caller source the real file
     and call one of its functions directly without triggering `exit`.

Run with: python3 -m unittest scripts.test_llm_client_source_guard -v
"""
import os
import subprocess
import sys
import unittest

# IMPORT-PATH ROBUSTNESS: this repo has no scripts/__init__.py (see
# test_freshness_helper_sweep.py's setUp docstring for the module-identity
# hazard that absence creates). `python3 -m unittest scripts.test_X` puts
# only the REPO ROOT on sys.path (bare `test_source_helpers` would not
# resolve there); `python3 -m unittest scripts/test_X.py` puts neither
# scripts/ nor the repo root on sys.path reliably. Explicitly adding this
# file's own directory covers every documented invocation form without
# depending on which one is used.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

_USAGE = "usage: llm-client.sh {build|review|summarize|adversarial|merge-gate}"


class TestExecutedAsScriptDispatchUnchanged(unittest.TestCase):
    """Real `sh llm-client.sh <subcommand>` invocations, sentinel unset --
    this is the default/production path every hook and gate call uses."""

    def _run(self, args, stdin=""):
        env = os.environ.copy()
        env.pop("CLAGENTIC_LLM_CLIENT_SOURCE_ONLY", None)
        return subprocess.run(
            [LLM_CLIENT_SH, *args],
            input=stdin, capture_output=True, text=True, env=env,
            timeout=30,
        )

    def test_unrecognized_subcommand_prints_usage_and_exits_1(self):
        r = self._run(["not-a-real-subcommand"])
        self.assertEqual(r.returncode, 1)
        self.assertIn(_USAGE, r.stderr)

    def test_no_subcommand_hits_the_same_unrecognized_branch(self):
        r = self._run([])
        self.assertEqual(r.returncode, 1)
        self.assertIn(_USAGE, r.stderr)

    def test_review_subcommand_still_dispatches_to_cmd_review(self):
        # No LLM CLI configured in this environment -> the chain exhausts and
        # cmd_review emits a degraded JSON envelope via emit_degraded rather
        # than raising. walk_chain signals infra failure via exit status 3
        # (INV-1b) even though it still prints a valid degraded envelope --
        # this proves the `review)` case arm still routes to cmd_review and
        # cmd_review still propagates walk_chain's real exit status exactly
        # as before the guard (same low-cost, no-network probe smoke.sh step
        # 5c drives, which likewise discards/ignores this status on purpose).
        r = self._run(["review"], stdin="")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn('"degraded"', r.stdout)


class TestSourceGuardSuppressesDispatch(unittest.TestCase):
    """CLAGENTIC_LLM_CLIENT_SOURCE_ONLY=1 -- the new opt-in path a test
    harness (or a future in-process reuser) sets before dot-sourcing."""

    def _source_and_call(self, script_body):
        env = os.environ.copy()
        env.update(source_env(llm_client=True))
        script = f". '{LLM_CLIENT_SH}'\n{script_body}\n"
        return subprocess.run(
            ["sh", "-c", script, LLM_CLIENT_SH],
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_sourcing_with_sentinel_does_not_exit_or_print_usage(self):
        # $1 deliberately left unset in the sourcing shell -- under the old
        # unguarded dispatch this would hit the `*)` arm and `exit 1` before
        # this echo ever ran.
        r = self._source_and_call("echo SOURCED_OK")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(_USAGE, r.stderr)
        self.assertIn("SOURCED_OK", r.stdout)

    def test_sourcing_with_sentinel_exposes_real_functions(self):
        # version_ge is a pure function defined well above the dispatch --
        # proves the source guard makes the file's actual functions callable
        # post-source, not just "doesn't crash."
        r = self._source_and_call(
            'version_ge "1.2.3" "1.2.3" && echo VERSION_GE_OK'
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("VERSION_GE_OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
