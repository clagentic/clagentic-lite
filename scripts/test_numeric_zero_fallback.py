"""
Numeric CLAGENTIC_* keys: where 0 would be fail-open or destructive, code must
match the documented behavior (0 or invalid falls back to the default, with a
WARN), via the one shared helper ds_positive_int_or_warn (scripts/platform.sh).

Three parts:
  1. the helper itself,
  2. behavior at the call sites that used to let 0 through (a disabled
     timeout, a tight poll loop, every finding dropped, every memory row
     pruned, a 0-byte chunk threshold),
  3. a classification sweep: every numeric-looking key in share/config.example
     must be listed below as either guarded or deliberately zero-meaningful,
     so a new numeric key cannot ship without someone deciding what 0 means.

Run with: python3 -m unittest scripts.test_numeric_zero_fallback -v
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts.test_config_key_drift import _ROLES, _code_files

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
MEMORY_SH = os.path.join(TOOL_HOME, "scripts", "memory.sh")
CONFIG_EXAMPLE = os.path.join(TOOL_HOME, "share", "config.example")

# 0 or invalid falls back to the default with a WARN: every read site goes
# through ds_positive_int_or_warn (TestEveryReadSiteUsesTheHelper).
ZERO_FALLS_BACK = {
    "CLAGENTIC_LLM_TIMEOUT_SEC",
    "CLAGENTIC_REVIEWER_TIMEOUT_SEC",
    "CLAGENTIC_LLM_TIMEOUT_BYTES_PER_SEC",
    "CLAGENTIC_SECRETS_FETCH_TIMEOUT_SEC",
    "CLAGENTIC_SAST_FETCH_TIMEOUT_SEC",
    "CLAGENTIC_SQLITE_BUSY_TIMEOUT_MS",
    "CLAGENTIC_PLUGIN_TIMEOUT_SEC",
    "CLAGENTIC_EXTERNAL_TIMEOUT_SEC",
    "CLAGENTIC_SECRETS_TIMEOUT_SEC",
    "CLAGENTIC_OSV_TIMEOUT_SEC",
    "CLAGENTIC_SAST_TIMEOUT_SEC",
    "CLAGENTIC_SHIP_TIMEOUT_SEC",
    "CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC",
    "CLAGENTIC_BLEED_FETCH_TIMEOUT_SEC",
    "CLAGENTIC_MERGE_GATE_FETCH_TIMEOUT_SEC",
    "CLAGENTIC_ADVERSARIAL_FINDINGS_MAX",
    "CLAGENTIC_TAIL_INTERVAL_SEC",
    "CLAGENTIC_MEMORY_MAX_ROWS",
    "CLAGENTIC_INVARIANT_FEED_MAX",
    "CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS",
    "CLAGENTIC_REVIEW_CHUNK_BYTES",
    "CLAGENTIC_REVIEWER_MAX_DIFF_KB",
    "CLAGENTIC_TOOL_VERSION_TIMEOUT_SEC",
    "CLAGENTIC_TOOL_UPGRADE_TIMEOUT_SEC",
    "CLAGENTIC_REMOTE_CHECK_TIMEOUT_SEC",
    "CLAGENTIC_SHIP_COMMITS_MAX_CHARS",
}

# 0 has a deliberate, documented meaning, so it is NOT rewritten.
ZERO_IS_MEANINGFUL = {
    "CLAGENTIC_LLM_TIMEOUT_MAX_SEC": "0 = no cap",
    "CLAGENTIC_REVIEWER_TIMEOUT_MAX_SEC": "0 = no cap",
    "CLAGENTIC_LEDGER_MAX_PER_BRANCH": "0 = unlimited",
    "CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC": "0 = no debounce",
    "CLAGENTIC_RECALL_MIN_KEYWORDS": "0 = never gate on keyword count",
    "CLAGENTIC_RECALL_LIMIT": "0 = return no rows",
    "CLAGENTIC_RECALL_MAX_CHARS": "0 = inject no text",
    "CLAGENTIC_RESULT_TOKEN_WARN": "0 = warn on every result",
    "CLAGENTIC_SESSION_TOKEN_WARN": "0 = warn on every result",
    "CLAGENTIC_AUTOSUMMARIZE_BYTES": "0 = summarize every result",
}

_NUMERIC_SUFFIX = re.compile(
    r"_(SEC|MS|MAX|MAX_SEC|BYTES|KB|LIMIT|ROWS|THRESHOLD|CHARS|WARN|KEYWORDS|PER_SEC|PER_BRANCH)$"
)


def _numeric_keys_in_config_example():
    keys = set()
    with open(CONFIG_EXAMPLE) as f:
        for line in f:
            m = re.match(r"#?\s*(CLAGENTIC_[A-Z0-9_]+)=", line)
            if m and _NUMERIC_SUFFIX.search(m.group(1)):
                keys.add(m.group(1))
    return keys


def _sh(script, env=None):
    full_env = os.environ.copy()
    for key in [k for k in full_env if k.startswith("CLAGENTIC_")]:
        del full_env[key]
    # The finding pipeline is found only under the tool home.
    full_env["TOOL_HOME"] = os.path.abspath(TOOL_HOME)
    if env:
        full_env.update(env)
    return subprocess.run(
        ["sh", "-c", script], capture_output=True, text=True, env=full_env, cwd=TOOL_HOME
    )


class TestHelper(unittest.TestCase):
    def _call(self, name, value, default):
        return _sh(f". '{PLATFORM_SH}'\nds_positive_int_or_warn '{name}' '{value}' '{default}'\n")

    def test_zero_and_invalid_fall_back_with_warn(self):
        for value in ("0", "00", "abc", "-5", "1.5"):
            with self.subTest(value=value):
                r = self._call("CLAGENTIC_X", value, 30)
                self.assertEqual(r.stdout, "30")
                self.assertIn("CLAGENTIC_X=" + value, r.stderr)
                self.assertIn("WARN", r.stderr)

    def test_valid_and_empty_pass_through_silently(self):
        for value, expected in (("7", "7"), ("", "30")):
            with self.subTest(value=value):
                r = self._call("CLAGENTIC_X", value, 30)
                self.assertEqual(r.stdout, expected)
                self.assertEqual(r.stderr, "")

    def test_leading_zeros_are_normalized_not_octal_and_not_warned(self):
        # "08" and "09" are octal parse errors in $(( )); the helper hands
        # callers a plain decimal.
        for value, expected in (("08", "8"), ("09", "9"), ("010", "10"), ("007", "7"), ("0100", "100")):
            with self.subTest(value=value):
                r = self._call("CLAGENTIC_X", value, 30)
                self.assertEqual(r.stdout, expected, msg=r.stderr)
                self.assertEqual(r.stderr, "")
                arith = _sh(f"echo $(( {r.stdout} + 1 ))")
                self.assertEqual(arith.stdout.strip(), str(int(expected) + 1))


class TestCallSites(unittest.TestCase):
    def test_json_array_cap_zero_keeps_the_findings(self):
        script = f". '{PLATFORM_SH}'\n_llm_json_array_cap '[1,2,3]' 0\n"
        r = _sh(script)
        self.assertEqual(r.stdout.strip(), "[1,2,3]", msg=r.stderr)

    def test_json_array_cap_env_zero_keeps_the_findings(self):
        script = f". '{PLATFORM_SH}'\n_llm_json_array_cap '[1,2,3]'\n"
        r = _sh(script, env={"CLAGENTIC_ADVERSARIAL_FINDINGS_MAX": "0"})
        self.assertEqual(r.stdout.strip(), "[1,2,3]", msg=r.stderr)

    def test_json_array_cap_still_caps_a_positive_max(self):
        script = f". '{PLATFORM_SH}'\n_llm_json_array_cap '[1,2,3]' 2\n"
        self.assertEqual(_sh(script).stdout.strip(), "[1,2]")

    def test_field_chars_zero_falls_back(self):
        script = f". '{PLATFORM_SH}'\n_invariant_feed_max_field_chars\n"
        r = _sh(script, env={"CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS": "0"})
        self.assertEqual(r.stdout, "500")
        self.assertIn("WARN", r.stderr)

    def _gates_text(self):
        with open(GATES_SH) as f:
            return f.read()

    def test_gates_sites_use_the_shared_helper(self):
        text = self._gates_text()
        for key in (
            "CLAGENTIC_MERGE_GATE_FETCH_TIMEOUT_SEC",
            "CLAGENTIC_TAIL_INTERVAL_SEC",
            "CLAGENTIC_ADVERSARIAL_FINDINGS_MAX",
            "CLAGENTIC_INVARIANT_FEED_MAX",
            "CLAGENTIC_REVIEW_CHUNK_BYTES",
            "CLAGENTIC_REVIEWER_MAX_DIFF_KB",
        ):
            with self.subTest(key=key):
                self.assertRegex(text, r"ds_positive_int_or_warn " + key + r"\b")

    def test_gates_sites_no_longer_pass_a_raw_zero_to_the_consumer(self):
        text = self._gates_text()
        # Each of these was the raw-read form that let 0 through.
        for stale in (
            '_bgs_fetch_timeout="${CLAGENTIC_MERGE_GATE_FETCH_TIMEOUT_SEC:-30}"',
            'INTERVAL="${CLAGENTIC_TAIL_INTERVAL_SEC:-1}"',
            '_llm_json_array_cap "$_adv_findings_json_sorted" "${CLAGENTIC_ADVERSARIAL_FINDINGS_MAX:-200}"',
        ):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, text)

    def test_memory_max_rows_zero_cannot_reach_the_delete(self):
        with open(MEMORY_SH) as f:
            text = f.read()
        self.assertRegex(text, r"ds_positive_int_or_warn CLAGENTIC_MEMORY_MAX_ROWS\b")


_HELPER = "ds_positive_int_or_warn"


def _read_site_regex(key):
    """Matches a line that READS `key`: a parameter expansion of the name, or,
    for a per-role key, a `role_env <role> <SUFFIX>` call (how llm-client.sh
    builds CLAGENTIC_<ROLE>_<SUFFIX> at run time)."""
    pats = [r"\$\{?" + re.escape(key) + r"\b"]
    m = re.match(r"CLAGENTIC_(" + "|".join(_ROLES) + r")_(.+)$", key)
    if m:
        pats.append(r"\brole_env\s+\S+\s+" + re.escape(m.group(2)) + r"\b")
    return re.compile("|".join(pats))


def read_sites(key, files):
    """[(path, lineno, line)] of every non-comment line reading `key`."""
    rx = _read_site_regex(key)
    sites = []
    for path in files:
        with open(path, errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                if line.lstrip().startswith("#"):
                    continue
                if rx.search(line):
                    sites.append((path, lineno, line.strip()))
    return sites


def unguarded_read_sites(keys, files):
    """Read sites of `keys` whose own line does not go through the helper."""
    bad = []
    for key in sorted(keys):
        for path, lineno, line in read_sites(key, files):
            if _HELPER not in line:
                bad.append(f"{os.path.relpath(path, TOOL_HOME)}:{lineno}: {key}: {line}")
    return bad


class TestEveryReadSiteUsesTheHelper(unittest.TestCase):
    maxDiff = None

    def _guarded_keys(self):
        return _numeric_keys_in_config_example() - set(ZERO_IS_MEANINGFUL)

    def test_every_read_site_of_every_zero_falls_back_key_uses_the_helper(self):
        bad = unguarded_read_sites(self._guarded_keys(), _code_files())
        self.assertEqual(
            bad, [],
            "numeric key read without ds_positive_int_or_warn on the same line "
            "(a 0 would reach a timeout/cap/loop unchecked): route it through the "
            "helper, or classify the key in ZERO_IS_MEANINGFUL",
        )

    def test_every_guarded_key_has_at_least_one_read_site(self):
        # A regex that stopped matching would make the sweep pass vacuously.
        files = _code_files()
        for key in sorted(self._guarded_keys()):
            with self.subTest(key=key):
                self.assertTrue(read_sites(key, files), f"no read site found for {key}")

    def _fixture(self, text):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        path = os.path.join(d, "fixture.sh")
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_a_new_timeout_read_without_the_helper_fails(self):
        path = self._fixture('T="${CLAGENTIC_NEW_THING_TIMEOUT_SEC:-30}"\n')
        bad = unguarded_read_sites({"CLAGENTIC_NEW_THING_TIMEOUT_SEC"}, [path])
        self.assertEqual(len(bad), 1, bad)

    def test_a_read_through_the_helper_passes(self):
        path = self._fixture(
            'T=$(ds_positive_int_or_warn CLAGENTIC_NEW_THING_TIMEOUT_SEC '
            '"${CLAGENTIC_NEW_THING_TIMEOUT_SEC:-}" 30)\n'
        )
        self.assertEqual(unguarded_read_sites({"CLAGENTIC_NEW_THING_TIMEOUT_SEC"}, [path]), [])

    def test_a_per_role_role_env_read_without_the_helper_fails(self):
        path = self._fixture('B=$(role_env "$ROLE_U" TIMEOUT_SEC 180)\n')
        self.assertEqual(len(unguarded_read_sites({"CLAGENTIC_REVIEWER_TIMEOUT_SEC"}, [path])), 1)

    def test_comments_and_message_text_are_not_read_sites(self):
        path = self._fixture(
            '# T="${CLAGENTIC_NEW_THING_TIMEOUT_SEC:-30}"\n'
            'echo "raise CLAGENTIC_NEW_THING_TIMEOUT_SEC"\n'
        )
        self.assertEqual(unguarded_read_sites({"CLAGENTIC_NEW_THING_TIMEOUT_SEC"}, [path]), [])

    def test_reviewer_max_diff_kb_zero_warns(self):
        r = _sh(
            f". '{PLATFORM_SH}'\n"
            'ds_positive_int_or_warn CLAGENTIC_REVIEWER_MAX_DIFF_KB "${CLAGENTIC_REVIEWER_MAX_DIFF_KB:-}" 0\n',
            env={"CLAGENTIC_REVIEWER_MAX_DIFF_KB": "0"},
        )
        self.assertIn("CLAGENTIC_REVIEWER_MAX_DIFF_KB=0", r.stderr)

    def test_reviewer_max_diff_kb_unset_is_silent(self):
        r = _sh(
            f". '{PLATFORM_SH}'\n"
            'ds_positive_int_or_warn CLAGENTIC_REVIEWER_MAX_DIFF_KB "${CLAGENTIC_REVIEWER_MAX_DIFF_KB:-}" 0\n'
        )
        self.assertEqual((r.stdout, r.stderr), ("0", ""))


class TestEveryNumericKeyIsClassified(unittest.TestCase):
    def test_no_key_is_in_both_sets(self):
        self.assertEqual(ZERO_FALLS_BACK & set(ZERO_IS_MEANINGFUL), set())

    def test_every_numeric_key_in_config_example_is_classified(self):
        classified = ZERO_FALLS_BACK | set(ZERO_IS_MEANINGFUL)
        unclassified = sorted(_numeric_keys_in_config_example() - classified)
        self.assertEqual(
            unclassified,
            [],
            "numeric key(s) in share/config.example with no decision on what 0 means; "
            "add each to ZERO_FALLS_BACK (and guard it with ds_positive_int_or_warn) or "
            "to ZERO_IS_MEANINGFUL (and document the meaning): " + ", ".join(unclassified),
        )

    def test_classification_names_only_real_keys(self):
        stale = sorted((ZERO_FALLS_BACK | set(ZERO_IS_MEANINGFUL)) - _numeric_keys_in_config_example())
        self.assertEqual(stale, [], "classified key(s) no longer in share/config.example")

    def test_classification_catches_an_unclassified_key(self):
        # Drifted fixture: a new numeric key nobody classified.
        drifted = _numeric_keys_in_config_example() | {"CLAGENTIC_NEW_THING_TIMEOUT_SEC"}
        classified = ZERO_FALLS_BACK | set(ZERO_IS_MEANINGFUL)
        self.assertEqual(sorted(drifted - classified), ["CLAGENTIC_NEW_THING_TIMEOUT_SEC"])


if __name__ == "__main__":
    unittest.main()
