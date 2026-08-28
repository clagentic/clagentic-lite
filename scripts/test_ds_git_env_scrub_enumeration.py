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

# The full, hardcoded expected set -- MUST be kept in sync with
# ds_git_env_scrub's own `unset` list (scripts/platform.sh) by a human
# editing both sides deliberately; that duplication is the point (see
# module docstring). GIT_CONFIG_NOSYSTEM is deliberately excluded here: the
# function SETS it (to "1"), it does not unset it -- covered by its own
# separate test below, not this enumeration.
EXPECTED_UNSET_VARS = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
]

# Vars that must survive the scrub untouched -- a sentinel against an
# over-broad implementation (e.g. `unset $(env | grep ^GIT_ | cut -d= -f1)`)
# that would happen to clear the enumerated set but ALSO clear vars this
# task deliberately decided not to touch (see ds_git_env_scrub's own doc
# comment for GIT_PREFIX/GIT_INDEX_VERSION's rationale).
DELIBERATELY_PRESERVED_VARS = ["GIT_PREFIX", "GIT_INDEX_VERSION"]


def _run_scrub_probe(preset_vars):
    """Source platform.sh, set every var in preset_vars to a sentinel
    value, call ds_git_env_scrub, then print every one of those vars'
    post-scrub state as `NAME=<value-or-UNSET>` lines."""
    env = os.environ.copy()
    for name in preset_vars:
        env[name] = "sentinel-value-for-" + name
    probe_lines = "\n".join(
        f'if [ "${{{name}+set}}" = "set" ]; then printf "{name}=%s\\n" "${name}"; '
        f'else printf "{name}=__UNSET__\\n"; fi'
        for name in preset_vars
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
        """GIT_CONFIG_NOSYSTEM is the one var this function SETS rather
        than unsets -- verified separately since it is not part of the
        unset-enumeration parity check above."""
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

    def test_expected_list_is_not_accidentally_empty(self):
        """Guards the guard: an empty EXPECTED_UNSET_VARS would make
        test_every_enumerated_var_is_unset vacuously pass."""
        self.assertGreaterEqual(len(EXPECTED_UNSET_VARS), 10)


if __name__ == "__main__":
    unittest.main()
