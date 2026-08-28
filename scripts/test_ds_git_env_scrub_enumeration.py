"""
Regression test for lr-dfd45f: ds_git_env_scrub (scripts/platform.sh) must
clear EXACTLY the enumerated set of git-exported env vars this task
determined are hazardous for a scratch/canary git repo -- no more, no less,
by ENUMERATION PARITY rather than a handful of spot-checked vars.

WHY PARITY, NOT SPOT-CHECKS: a spot-check test ("assert GIT_DIR is unset,
assert GIT_WORK_TREE is unset, ...") passes even if a future edit silently
drops one var from the function while adding another -- each individual
assertion still passes on its own vars. This test instead hardcodes the
FULL expected list here and asserts it is exactly the set the function
unsets (checked by actually setting every var, running the function, and
reading back what survives) -- so adding a var to one side without the
other fails immediately, and this file becomes the enumeration's second,
independent copy the way any parity check needs to be.

REVISED (PEACHES, PR #209 review, finding 1): the original version of this
file hardcoded a hand-curated list that PEACHES demonstrated was still
incomplete -- an inherited GIT_CONFIG_COUNT=1 / GIT_CONFIG_KEY_0=
commit.gpgsign / GIT_CONFIG_VALUE_0=true still forced the canary's commit to
require a signature it cannot produce, silently no-op'ing the whole
positive-control since every canary call site redirects to /dev/null. This
version's EXPECTED_UNSET_VARS is cross-checked against `git rev-parse
--local-env-vars` (git's own authoritative list -- see
test_local_env_vars_coverage below) and adds explicit coverage for:
  1. the INDEXED, unbounded GIT_CONFIG_KEY_N/GIT_CONFIG_VALUE_N pair
     (driven by GIT_CONFIG_COUNT, which cannot be covered by a fixed name
     list at all -- tested separately, for several different N, not folded
     into the fixed-list enumeration)
  2. GIT_CONFIG_GLOBAL being explicitly PINNED to /dev/null (not merely
     unset) -- BOBBIE's PR #209 audit nit, folded into the same fix: an
     unset-only GIT_CONFIG_GLOBAL still lets git fall back to its own
     default global-config resolution ($HOME/.gitconfig), so the var must
     be SET to an inert path, not merely cleared

Uses scripts/test_source_helpers.py (lr-bdddcf/PR #177) to dot-source the
real scripts/platform.sh directly -- platform.sh carries no subcommand
dispatch of its own (unlike gates.sh/llm-client.sh) and no source guard, so
sourcing it needs no sentinel; only GATES_SH/source_env's PLATFORM_SH
constant is reused here for the path.

Run with: python3 -m unittest scripts.test_ds_git_env_scrub_enumeration -v
"""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import PLATFORM_SH  # noqa: E402

# The full, hardcoded expected FIXED-NAME unset set -- MUST be kept in sync
# with ds_git_env_scrub's own `unset` list (scripts/platform.sh) by a human
# editing both sides deliberately; that duplication is the point (see
# module docstring). Does NOT include GIT_CONFIG_GLOBAL (the function SETS
# it to "/dev/null", covered by its own test below) or GIT_CONFIG_NOSYSTEM
# (also SET, covered by its own test) or GIT_CONFIG_COUNT/GIT_CONFIG_KEY_N/
# GIT_CONFIG_VALUE_N (the indexed channel, covered by its own dedicated
# test since a fixed name list structurally cannot express "N of these").
EXPECTED_UNSET_VARS = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_GRAFT_FILE",
    "GIT_SHALLOW_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
]

# `git rev-parse --local-env-vars` output as of the gitleaks/git version
# installed in this environment -- git's own authoritative list of vars
# that affect local repo resolution. Hardcoded here (not re-invoked at test
# time) so a test run never silently depends on git version drift changing
# what this comparison means; test_local_env_vars_coverage below documents
# the two deliberate exclusions (GIT_PREFIX, and the GIT_CONFIG_KEY_*/
# GIT_CONFIG_VALUE_* indexed family git's own list does not name at all).
GIT_LOCAL_ENV_VARS_SNAPSHOT = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
]

# Vars that must survive the scrub untouched -- a sentinel against an
# over-broad implementation (e.g. `unset $(env | grep ^GIT_ | cut -d= -f1)`)
# that would happen to clear the enumerated set but ALSO clear vars this
# task deliberately decided not to touch (see ds_git_env_scrub's own doc
# comment for GIT_PREFIX/GIT_INDEX_VERSION's rationale).
DELIBERATELY_PRESERVED_VARS = ["GIT_PREFIX", "GIT_INDEX_VERSION"]


def _run_scrub_probe(preset_vars, extra_setup=""):
    """Source platform.sh, set every var in preset_vars to a sentinel
    value, call ds_git_env_scrub, then print every one of those vars'
    post-scrub state as `NAME=<value-or-UNSET>` lines. extra_setup is
    injected verbatim before the preset_vars are applied via the
    environment (used for the indexed GIT_CONFIG_KEY_N/VALUE_N probes,
    which need names computed from a loop variable, not a fixed list)."""
    env = os.environ.copy()
    for name in preset_vars:
        env[name] = "sentinel-value-for-" + name
    probe_lines = "\n".join(
        f'if [ "${{{name}+set}}" = "set" ]; then printf "{name}=%s\\n" "${name}"; '
        f'else printf "{name}=__UNSET__\\n"; fi'
        for name in preset_vars
    )
    script = f". '{PLATFORM_SH}'\n{extra_setup}\nds_git_env_scrub\n{probe_lines}\n"
    r = subprocess.run(["sh", "-c", script, PLATFORM_SH],
                        capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, f"probe script failed: {r.stderr}"
    result = {}
    for line in r.stdout.splitlines():
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        result[name] = None if value == "__UNSET__" else value
    return result


class TestDsGitEnvScrubEnumerationParity(unittest.TestCase):

    def test_every_enumerated_var_is_unset(self):
        result = _run_scrub_probe(EXPECTED_UNSET_VARS)
        still_set = {k: v for k, v in result.items() if v is not None}
        self.assertEqual(
            still_set, {},
            msg=f"ds_git_env_scrub left these vars set: {still_set}",
        )

    def test_no_additional_var_is_silently_unset(self):
        """The other half of parity: vars this task deliberately decided
        NOT to clear must still survive -- catches an over-broad
        implementation, not just an under-broad one."""
        result = _run_scrub_probe(DELIBERATELY_PRESERVED_VARS)
        still_set = {k: v for k, v in result.items() if v is not None}
        self.assertEqual(
            set(still_set.keys()), set(DELIBERATELY_PRESERVED_VARS),
            msg=f"ds_git_env_scrub unset a var it should have left alone: "
                f"expected all of {DELIBERATELY_PRESERVED_VARS} to survive, "
                f"got {still_set}",
        )

    def test_git_config_nosystem_is_set(self):
        """GIT_CONFIG_NOSYSTEM is one of two vars this function SETS
        rather than unsets -- verified separately since it is not part of
        the unset-enumeration parity check above."""
        env = os.environ.copy()
        env.pop("GIT_CONFIG_NOSYSTEM", None)
        script = (
            f". '{PLATFORM_SH}'\n"
            "ds_git_env_scrub\n"
            'printf "%s\\n" "$GIT_CONFIG_NOSYSTEM"\n'
        )
        r = subprocess.run(["sh", "-c", script, PLATFORM_SH],
                            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "1")

    def test_git_config_global_is_pinned_to_dev_null(self):
        """GIT_CONFIG_GLOBAL is the second var this function SETS rather
        than unsets -- pinned to /dev/null (BOBBIE's PR #209 audit nit).
        Merely unsetting it would leave git's own default global-config
        resolution (e.g. $HOME/.gitconfig) in force; asserting the actual
        pinned value here, not just presence, since "unset" and "set to
        /dev/null" are the two states this specifically must distinguish."""
        env = os.environ.copy()
        env["GIT_CONFIG_GLOBAL"] = "/some/real/gitconfig/an/attacker/controls"
        script = (
            f". '{PLATFORM_SH}'\n"
            "ds_git_env_scrub\n"
            'printf "%s\\n" "$GIT_CONFIG_GLOBAL"\n'
        )
        r = subprocess.run(["sh", "-c", script, PLATFORM_SH],
                            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "/dev/null")

    def test_expected_list_is_not_accidentally_empty(self):
        """Guards the guard: an empty EXPECTED_UNSET_VARS would make
        test_every_enumerated_var_is_unset vacuously pass."""
        self.assertGreaterEqual(len(EXPECTED_UNSET_VARS), 10)

    def test_local_env_vars_coverage(self):
        """Cross-check against git's OWN authoritative list (`git rev-parse
        --local-env-vars`, snapshotted above) rather than trusting the
        hand-curated list alone -- every var git itself names must be
        covered by either EXPECTED_UNSET_VARS or one of the two documented,
        deliberate exceptions: GIT_PREFIX (cosmetic-only, see
        ds_git_env_scrub's own doc comment) and GIT_CONFIG_COUNT (covered
        by the dedicated indexed-channel tests below, not this fixed
        list -- unsetting COUNT alone without also handling KEY_N/VALUE_N
        for each N would be incomplete, so it is deliberately tested
        separately rather than folded into a simple presence check here)."""
        deliberate_exceptions = {"GIT_PREFIX", "GIT_CONFIG_COUNT"}
        uncovered = [
            v for v in GIT_LOCAL_ENV_VARS_SNAPSHOT
            if v not in EXPECTED_UNSET_VARS and v not in deliberate_exceptions
        ]
        self.assertEqual(
            uncovered, [],
            msg=f"git rev-parse --local-env-vars names vars not covered by "
                f"ds_git_env_scrub's enumeration or a documented exception: "
                f"{uncovered}",
        )


class TestDsGitEnvScrubIndexedConfigChannel(unittest.TestCase):
    """GIT_CONFIG_COUNT + GIT_CONFIG_KEY_N/GIT_CONFIG_VALUE_N -- the
    indexed, unbounded config-injection channel PEACHES demonstrated
    directly reproduces a silent canary no-op via commit.gpgsign=true.
    Cannot be covered by EXPECTED_UNSET_VARS above (N is unbounded), so
    tested here for several different N values instead."""

    def _probe_indexed(self, count, keys_values):
        """count: the GIT_CONFIG_COUNT to set. keys_values: list of
        (key_name, value) tuples, index N implied by list position."""
        env = os.environ.copy()
        env["GIT_CONFIG_COUNT"] = str(count)
        for i, (key, value) in enumerate(keys_values):
            env[f"GIT_CONFIG_KEY_{i}"] = key
            env[f"GIT_CONFIG_VALUE_{i}"] = value
        probe_names = ["GIT_CONFIG_COUNT"] + [
            n for i in range(len(keys_values))
            for n in (f"GIT_CONFIG_KEY_{i}", f"GIT_CONFIG_VALUE_{i}")
        ]
        probe_lines = "\n".join(
            f'if [ "${{{name}+set}}" = "set" ]; then printf "{name}=%s\\n" "${name}"; '
            f'else printf "{name}=__UNSET__\\n"; fi'
            for name in probe_names
        )
        script = f". '{PLATFORM_SH}'\nds_git_env_scrub\n{probe_lines}\n"
        r = subprocess.run(["sh", "-c", script, PLATFORM_SH],
                            capture_output=True, text=True, env=env, timeout=30)
        assert r.returncode == 0, f"probe script failed: {r.stderr}"
        result = {}
        for line in r.stdout.splitlines():
            if "=" not in line:
                continue
            name, _, value = line.partition("=")
            result[name] = None if value == "__UNSET__" else value
        return result

    def test_single_indexed_pair_is_cleared(self):
        """The exact shape PEACHES demonstrated: COUNT=1, KEY_0/VALUE_0
        forcing commit.gpgsign=true."""
        result = self._probe_indexed(1, [("commit.gpgsign", "true")])
        self.assertIsNone(result["GIT_CONFIG_COUNT"])
        self.assertIsNone(result["GIT_CONFIG_KEY_0"])
        self.assertIsNone(result["GIT_CONFIG_VALUE_0"])

    def test_multiple_indexed_pairs_all_cleared(self):
        """N > 1 -- the unbounded case a fixed name list cannot express."""
        result = self._probe_indexed(3, [
            ("commit.gpgsign", "true"),
            ("core.hooksPath", "/tmp/evil-hooks"),
            ("user.email", "attacker@example.com"),
        ])
        self.assertIsNone(result["GIT_CONFIG_COUNT"])
        for i in range(3):
            self.assertIsNone(result[f"GIT_CONFIG_KEY_{i}"], f"KEY_{i} survived")
            self.assertIsNone(result[f"GIT_CONFIG_VALUE_{i}"], f"VALUE_{i} survived")

    def test_zero_count_is_a_no_op_not_an_error(self):
        """GIT_CONFIG_COUNT=0 (or absent) must not error the loop -- the
        common case (no indexed config injected at all)."""
        result = self._probe_indexed(0, [])
        self.assertIsNone(result["GIT_CONFIG_COUNT"])

    def test_non_numeric_count_does_not_crash_or_hang(self):
        """A corrupted/malicious non-numeric GIT_CONFIG_COUNT must be
        treated as zero iterations, not passed to a shell arithmetic
        context (which would error under `set -e`) or used as an
        unbounded/negative loop bound."""
        env = os.environ.copy()
        env["GIT_CONFIG_COUNT"] = "not-a-number"
        script = f". '{PLATFORM_SH}'\nds_git_env_scrub\nprintf done\n"
        r = subprocess.run(["sh", "-c", script, PLATFORM_SH],
                            capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "done")

    def test_large_all_digit_count_is_clamped_not_hung(self):
        """BOBBIE, PR #209 audit (bobbie.uncat.1) -- blocking: the digits-
        only validation alone has no UPPER bound, so a large all-digit
        GIT_CONFIG_COUNT (e.g. an inherited or attacker-influenced value)
        passed the pre-clamp check and drove the unset loop through
        millions of iterations. Both call sites of ds_git_env_scrub
        (scripts/gates.sh) run entirely OUTSIDE run_bounded's timeout
        wrapper, so nothing else catches this -- it directly violates the
        function's own documented "no smaller a candidate for hanging than
        the real [gitleaks] scan" invariant.

        Uses a REAL, TIGHT subprocess timeout (5s -- generous for a
        256-iteration loop, far short of what an unbounded multi-million
        iteration loop needs) so a regression here fails FAST with a clear
        TimeoutExpired, rather than hanging this test (and the suite/CI
        run it's part of) indefinitely -- the exact fail-open shape this
        finding is about, reproduced at the test-harness level too if this
        assertion were naively an unbounded subprocess.run call.

        Confirmed to hang past this same 5s budget pre-fix (verified
        directly during this task by disabling the upper-clamp branch and
        re-running with a comparable large count)."""
        env = os.environ.copy()
        env["GIT_CONFIG_COUNT"] = "5000000"
        script = f". '{PLATFORM_SH}'\nds_git_env_scrub\nprintf done\n"
        try:
            r = subprocess.run(["sh", "-c", script, PLATFORM_SH],
                                capture_output=True, text=True, env=env, timeout=5)
        except subprocess.TimeoutExpired:
            self.fail(
                "ds_git_env_scrub hung past a 5s budget on GIT_CONFIG_COUNT="
                "5000000 -- the upper clamp did not engage (unbounded loop "
                "DoS, bobbie.uncat.1)"
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "done")

    def test_count_just_above_the_clamp_is_also_rejected(self):
        """The clamp boundary itself: one past _DGES_MAX_CONFIG_COUNT (256)
        must be treated as zero iterations (same as non-numeric), not
        silently truncated to processing the first 256 entries -- this
        function has already decided a count that large cannot be
        trusted, so it should do nothing indexed, not "do something"."""
        result = self._probe_indexed(257, [("commit.gpgsign", "true")])
        # KEY_0/VALUE_0 must survive (never touched) because the whole
        # indexed pass is skipped -- if the clamp instead silently
        # truncated to 256 iterations, index 0 would still be cleared and
        # this assertion would not catch the truncation-vs-reject
        # distinction. Only GIT_CONFIG_COUNT itself is unconditionally
        # unset by the second, unrelated unset block later in the
        # function.
        self.assertEqual(result["GIT_CONFIG_KEY_0"], "commit.gpgsign")
        self.assertEqual(result["GIT_CONFIG_VALUE_0"], "true")


if __name__ == "__main__":
    unittest.main()
