"""
Structural guard: share/config.example and the code must name the same
CLAGENTIC_* keys.

Two directions, both mechanical:
  1. every CLAGENTIC_* name that appears in shipped code (bin/, scripts/*.sh,
     share/hook-shims/) must be documented in share/config.example, or be in
     INTERNAL_ONLY below with a reason;
  2. every key config.example documents must still be referenced by the code
     (directly, or through a dynamic CLAGENTIC_${ROLE}_<SUFFIX> construction),
     or be in DOCUMENT_ONLY below with a reason.

Both allowlists are explicit and commented on purpose: weakening the check to
make it pass is the failure this test exists to prevent. Adding a key to the
code without documenting it (or deleting code while leaving its key in the
example) fails here, at the point of the change.

A second check cross-checks the CLI dispatcher's subcommand list against the
README and the usage header.

Run with: python3 -m unittest scripts.test_config_key_drift -v
"""
import os
import re
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_EXAMPLE = os.path.join(TOOL_HOME, "share", "config.example")

# Names that end a shell identifier: alnum only, so a dangling prefix such as
# "CLAGENTIC_" or "CLAGENTIC_MODEL_" followed by ${...} is handled by the
# dynamic-construction pass below, not counted as a key.
_KEY_RE = re.compile(r"\bCLAGENTIC_[A-Z][A-Z0-9_]*[A-Z0-9]\b")
# CLAGENTIC_${ROLE}_SUFFIX / CLAGENTIC_$ROLE... style dynamic reads.
_DYNAMIC_RE = re.compile(r"CLAGENTIC_\$\{?[A-Za-z_][A-Za-z0-9_]*[^}\s'\"]*\}?_([A-Z][A-Z0-9_]*[A-Z0-9])\b")
# The role prefixes the dynamic constructions expand over.
_ROLES = ("BUILDER", "REVIEWER", "AUDITOR", "GATE", "SUMMARIZER", "TROUBLESHOOTER")

# Names that appear in code but are deliberately NOT operator-settable config
# keys. Each entry states why. Anything not here must be in config.example.
INTERNAL_ONLY = {
    # Once-per-process idempotence latches set by the env loaders in platform.sh.
    "CLAGENTIC_ENV_LOADED": "loader idempotence latch",
    "CLAGENTIC_GLOBAL_ENV_LOADED": "loader idempotence latch",
    "CLAGENTIC_REPO_ENV_LOADED": "loader idempotence latch",
    "CLAGENTIC_GLOBAL_CONFIG_OLD_PATH_WARNED": "once-per-process warning latch",
    "CLAGENTIC_LITE_HOME_SET": "once-per-process warning latch",
    # Shell constants inside bin/clagentic-lite, not read from the environment.
    "CLAGENTIC_HOOK_SCRIPTS": "internal constant: hook scripts to stamp",
    "CLAGENTIC_SECURITY_TOOLS": "internal constant: scanner list init/doctor iterate",
    # Snapshot ids of shipped glob tables in gates.sh; config.example documents
    # the EXTRA_GLOBS keys that extend them and names these in prose.
    "CLAGENTIC_DEPS_DOMAIN_VERSION": "internal snapshot id, named in prose next to EXTRA_GLOBS",
    "CLAGENTIC_SAST_DOMAIN_VERSION": "internal snapshot id, named in prose next to EXTRA_GLOBS",
    # Source-guard pair: set by test harnesses that dot-source gates.sh /
    # llm-client.sh on purpose; the hook shims and the CLI unset them.
    "CLAGENTIC_GATES_SOURCE_ONLY": "test-harness sourcing guard, not operator config",
    "CLAGENTIC_GATES_DELIBERATE_SOURCE": "test-harness sourcing guard, not operator config",
    "CLAGENTIC_LLM_CLIENT_SOURCE_ONLY": "test-harness sourcing guard, not operator config",
    "CLAGENTIC_LLM_CLIENT_DELIBERATE_SOURCE": "test-harness sourcing guard, not operator config",
    # Process-to-process channels between our own scripts.
    "CLAGENTIC_LLM_CLIENT_TOOL_ROLE": "walk_chain -> invoke_claude channel, set per call",
    "CLAGENTIC_GATE_REFS_FILE": "exported by `gates pre-push` for the deps/sast gates",
    "CLAGENTIC_TAIL_WATERMARK": "start id smoke.sh passes to `gates tail`; test hook",
    # Must be in the process environment BEFORE any config file is located
    # (it selects the repo), so it cannot live in a config file.
    "CLAGENTIC_PROJECT_ROOT": "scripted/test override of repo-root resolution; env-only by construction",
    # Deprecated alias, still honored with a warning; config.example describes
    # it in prose beside CLAGENTIC_LITE_HOME and must not offer it as a key.
    "CLAGENTIC_HOME": "deprecated alias of CLAGENTIC_LITE_HOME, documented in prose only",
}

# Keys config.example documents that the code does not reference by name.
# Each entry states why the example still carries it.
DOCUMENT_ONLY = {
}

# Key families the code builds at run time (so no literal name exists to
# find). Each entry: a regex over documented keys, the file, and a substring of
# the construction site. The substring is asserted present, so deleting the
# code that reads the family makes its documented keys "unread" again.
_ROLE_ALT = "|".join(_ROLES)
DYNAMIC_FAMILIES = (
    (
        re.compile(rf"^CLAGENTIC_({_ROLE_ALT})_REQUIRED$"),
        "scripts/llm-client.sh",
        "_REQUIRED\"",
    ),
    (
        re.compile(rf"^CLAGENTIC_({_ROLE_ALT})_TIMEOUT(_MAX)?_SEC$"),
        "scripts/llm-client.sh",
        'role_env "$ROLE_U" TIMEOUT_SEC',
    ),
    (
        re.compile(r"^CLAGENTIC_MODEL_[A-Z]+_[A-Z]+$"),
        "scripts/llm-client.sh",
        'CLAGENTIC_MODEL_${CLI_U}_${TIER_U}',
    ),
)


def _family_evidence_missing():
    missing = []
    for _, rel, needle in DYNAMIC_FAMILIES:
        with open(os.path.join(TOOL_HOME, rel), errors="replace") as f:
            if needle not in f.read():
                missing.append((rel, needle))
    return missing


def _code_files():
    out = subprocess.run(
        ["git", "-C", TOOL_HOME, "ls-files", "bin", "scripts", "share/hook-shims"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    files = []
    for rel in out:
        base = os.path.basename(rel)
        if base.startswith("test_") or rel.endswith(".py"):
            continue
        files.append(os.path.join(TOOL_HOME, rel))
    return files


def keys_read_in_code(files=None):
    """(literal names, dynamic suffixes) found in shipped code."""
    literal, suffixes = set(), set()
    for path in files if files is not None else _code_files():
        with open(path, errors="replace") as f:
            # Whole-line comments are dropped: a name that only a comment
            # mentions is not read by anything, and counting it would let a key
            # whose code was deleted stay "read" forever. (Trailing comments on
            # a code line are kept; that residual is accepted.)
            text = "".join(
                line for line in f if not line.lstrip().startswith("#")
            )
        literal.update(_KEY_RE.findall(text))
        suffixes.update(_DYNAMIC_RE.findall(text))
    return literal, suffixes


def keys_in_config_example(path=CONFIG_EXAMPLE):
    """Same extraction bin/clagentic-lite's _config_key_set uses: an active or
    single-'#'-commented KEY= line, variable name only."""
    keys = set()
    with open(path) as f:
        for line in f:
            m = re.match(r"^#?\s*(CLAGENTIC_[A-Za-z0-9_]*)=", line)
            if m:
                keys.add(m.group(1))
    return keys


def drift(literal, suffixes, documented, internal_only, document_only, families=()):
    """Returns (undocumented_in_code, documented_but_unread)."""
    undocumented = sorted(
        k for k in literal if k not in documented and k not in internal_only
    )
    dynamic_reads = {f"CLAGENTIC_{r}_{s}" for r in _ROLES for s in suffixes}
    unread = sorted(
        k for k in documented
        if k not in literal and k not in dynamic_reads and k not in document_only
        and not any(pattern.match(k) for pattern, _, _ in families)
    )
    return undocumented, unread


class TestConfigKeyDrift(unittest.TestCase):
    maxDiff = None  # the drift lists ARE the failure message

    def test_every_key_read_in_code_is_documented_and_vice_versa(self):
        literal, suffixes = keys_read_in_code()
        documented = keys_in_config_example()
        undocumented, unread = drift(
            literal, suffixes, documented, INTERNAL_ONLY, DOCUMENT_ONLY, DYNAMIC_FAMILIES
        )
        self.assertEqual(
            undocumented, [],
            "CLAGENTIC_* names in shipped code but missing from share/config.example "
            "(document them there, or add to INTERNAL_ONLY with a reason)",
        )
        self.assertEqual(
            unread, [],
            "keys in share/config.example that no shipped code references "
            "(delete the stale key, or add to DOCUMENT_ONLY with a reason)",
        )

    def test_dynamic_family_construction_sites_still_exist(self):
        self.assertEqual(_family_evidence_missing(), [])

    def test_allowlists_carry_no_dead_entries(self):
        literal, suffixes = keys_read_in_code()
        documented = keys_in_config_example()
        for key in INTERNAL_ONLY:
            self.assertIn(key, literal, f"INTERNAL_ONLY entry {key} is no longer in code")
            self.assertNotIn(key, documented, f"INTERNAL_ONLY entry {key} is documented; drop the entry")
        for key in DOCUMENT_ONLY:
            self.assertIn(key, documented, f"DOCUMENT_ONLY entry {key} is not in config.example")

    def test_guard_fails_on_a_drifted_fixture(self):
        # A key read in code but absent from the example, and a documented key
        # nothing reads: both directions must be reported.
        undocumented, unread = drift(
            literal={"CLAGENTIC_REAL_KEY", "CLAGENTIC_NEW_UNDOCUMENTED_KEY"},
            suffixes=set(),
            documented={"CLAGENTIC_REAL_KEY", "CLAGENTIC_STALE_DOCUMENTED_KEY"},
            internal_only={},
            document_only={},
        )
        self.assertEqual(undocumented, ["CLAGENTIC_NEW_UNDOCUMENTED_KEY"])
        self.assertEqual(unread, ["CLAGENTIC_STALE_DOCUMENTED_KEY"])

    def test_dynamic_role_reads_count_as_reading_the_documented_key(self):
        undocumented, unread = drift(
            literal=set(),
            suffixes={"CMD"},
            documented={"CLAGENTIC_BUILDER_CMD", "CLAGENTIC_BUILDER_TIER"},
            internal_only={},
            document_only={},
        )
        self.assertEqual(unread, ["CLAGENTIC_BUILDER_TIER"])
        self.assertEqual(undocumented, [])

    def test_extraction_matches_the_installed_drift_checks_key_shape(self):
        # bin/clagentic-lite's _config_key_set treats "KEY=" and "# KEY=" as
        # keys and ignores prose; this test's extractor must agree, or the
        # guard and `doctor` would disagree about what config.example says.
        keys = keys_in_config_example()
        self.assertIn("CLAGENTIC_BUILDER_CMD", keys)
        self.assertIn("CLAGENTIC_REVIEWER_REQUIRED", keys)

    def test_guard_fails_end_to_end_on_drifted_files(self):
        # Same pipeline as the real check, pointed at throwaway files: a code
        # file that reads an undocumented key (and only mentions another in a
        # comment) against an example that documents a key nothing reads.
        with tempfile.TemporaryDirectory() as tmp:
            code = os.path.join(tmp, "fixture.sh")
            example = os.path.join(tmp, "config.example")
            with open(code, "w") as f:
                f.write('x="${CLAGENTIC_FIXTURE_READ_KEY:-0}"\n')
                f.write("# CLAGENTIC_FIXTURE_COMMENT_ONLY_KEY is mentioned here only\n")
            with open(example, "w") as f:
                f.write("# CLAGENTIC_FIXTURE_COMMENT_ONLY_KEY=1\n")
            literal, suffixes = keys_read_in_code([code])
            documented = keys_in_config_example(example)
        undocumented, unread = drift(literal, suffixes, documented, {}, {})
        self.assertEqual(undocumented, ["CLAGENTIC_FIXTURE_READ_KEY"])
        self.assertEqual(unread, ["CLAGENTIC_FIXTURE_COMMENT_ONLY_KEY"])


DOC_FILES = ("README.md", "AGENTS.md", "docs/DESIGN.md", "docs/GATES.md",
             "docs/LLM-USAGE.md", "docs/PORTABILITY.md", "docs/ROUTER.md",
             "docs/DEMO-SCRIPT.md")

# Names the docs may mention although no shipped code reads them. Each states
# why; a doc naming a key that does not exist is otherwise a stale claim.
DOC_MENTION_ALLOWED = {
}


class TestDocKeyMentions(unittest.TestCase):
    maxDiff = None

    def test_docs_only_name_keys_that_exist(self):
        literal, suffixes = keys_read_in_code()
        documented = keys_in_config_example()
        dynamic = {f"CLAGENTIC_{r}_{s}" for r in _ROLES for s in suffixes}
        known = literal | documented | dynamic
        stale = []
        for rel in DOC_FILES:
            with open(os.path.join(TOOL_HOME, rel)) as f:
                for lineno, line in enumerate(f, 1):
                    for key in _KEY_RE.findall(line):
                        if key in known or key in DOC_MENTION_ALLOWED:
                            continue
                        if any(p.match(key) for p, _, _ in DYNAMIC_FAMILIES):
                            continue
                        stale.append(f"{rel}:{lineno}: {key}")
        self.assertEqual(stale, [], "docs name CLAGENTIC_* keys that no code or config.example has")


# Names of the crew agents that build and review this repo. They belong in
# git history and PR threads, never in shipped prose (a public repo's docs are
# read by people who have no idea what they refer to).
_CREW_NAME_RE = re.compile(
    r"\b(PEACHES|BOBBIE|HOLDEN|NAOMI|AMOS|MILLER|ASHFORD|AVASARALA|DRUMMER|TIAMUT|PRAX)\b"
)


def crew_names_in(text):
    return sorted(set(_CREW_NAME_RE.findall(text)))


class TestShippedProseHygiene(unittest.TestCase):
    def _shipped_prose_files(self):
        out = subprocess.run(
            ["git", "-C", TOOL_HOME, "ls-files", "plugins", "share/config.example"],
            capture_output=True, text=True, check=True,
        ).stdout.split()
        return list(DOC_FILES) + [p for p in out if p.endswith((".md", ".example"))]

    def test_no_crew_agent_names_in_shipped_prose(self):
        found = []
        for rel in self._shipped_prose_files():
            with open(os.path.join(TOOL_HOME, rel)) as f:
                for lineno, line in enumerate(f, 1):
                    for name in crew_names_in(line):
                        found.append(f"{rel}:{lineno}: {name}")
        self.assertEqual(found, [], "crew agent names in shipped prose")

    def test_detector_fails_on_a_drifted_fixture(self):
        self.assertEqual(crew_names_in("accepted after PEACHES review"), ["PEACHES"])
        self.assertEqual(crew_names_in("Miller and Holden are people's names"), [])


def _cli_text():
    with open(os.path.join(TOOL_HOME, "bin", "clagentic-lite")) as f:
        return f.read()


def dispatcher_labels(text, marker):
    """Case labels of the top-level dispatch `case` that follows MARKER."""
    tail = text[text.index(marker):]
    labels = re.findall(r"^\s{2,4}([a-z][a-z-]*(?:\|[a-z][a-z-]*)*)\)", tail, re.M)
    return {name for group in labels for name in group.split("|")}


def fenced_code_lines(text):
    """Lines inside ``` fences, so prose that merely starts with the product
    name is not mistaken for a command."""
    inside = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
        elif inside:
            yield line


class TestSubcommandDrift(unittest.TestCase):
    """The CLI's dispatcher, its usage text, and the docs must name the same
    subcommands. Docs are checked in the direction that matters to a reader:
    a documented `clagentic-lite <sub>` must exist."""

    DOCS = DOC_FILES

    @classmethod
    def setUpClass(cls):
        cls.cli = _cli_text()
        cls.subcommands = dispatcher_labels(
            cls.cli, "# ---------------------------------------------------------------- dispatch"
        )
        with open(os.path.join(TOOL_HOME, "scripts", "gates.sh")) as f:
            gates = f.read()
        cls.gate_subcommands = dispatcher_labels(gates, 'case "${1:-}" in\n    init)')

    def test_dispatcher_was_parsed(self):
        self.assertTrue({"init", "enroll", "doctor", "update", "gates"} <= self.subcommands, self.subcommands)
        self.assertTrue({"review", "ship", "merge-gate"} <= self.gate_subcommands, self.gate_subcommands)

    def test_usage_lines_list_exactly_the_dispatched_subcommands(self):
        usage = re.findall(r"^\s*printf 'subcommands: ([^\\]*)\\n'", self.cli, re.M)
        self.assertTrue(usage)
        for line in usage:
            named = {re.sub(r"\s*\[.*", "", part).strip() for part in line.split(", ")}
            self.assertEqual(named, self.subcommands - {""})

    def test_header_comment_lists_exactly_the_dispatched_subcommands(self):
        header = self.cli.split("# Subcommands:\n", 1)[1].split("\n#\n", 1)[0]
        named = set(re.findall(r"^#   ([a-z][a-z-]*)", header, re.M))
        self.assertEqual(named, self.subcommands)

    def test_documented_subcommands_exist(self):
        bad = []
        for rel in self.DOCS:
            with open(os.path.join(TOOL_HOME, rel)) as f:
                text = f.read()
            for sub in re.findall(r"`clagentic-lite ([a-z][a-z-]*)", text):
                if sub not in self.subcommands:
                    bad.append((rel, sub))
            for line in fenced_code_lines(text):
                m = re.match(r"^\s*(?:\$ )?clagentic-lite ([a-z][a-z-]*)", line)
                if m and m.group(1) not in self.subcommands:
                    bad.append((rel, m.group(1)))
        self.assertEqual(bad, [], "docs name a clagentic-lite subcommand the dispatcher does not have")

    def test_documented_gates_subcommands_exist(self):
        bad = []
        for rel in self.DOCS:
            with open(os.path.join(TOOL_HOME, rel)) as f:
                text = f.read()
            for sub in re.findall(r"clagentic-lite gates ([a-z][a-z-]*)", text):
                if sub not in self.gate_subcommands:
                    bad.append((rel, sub))
        self.assertEqual(bad, [], "docs name a gates subcommand gates.sh does not dispatch")

    def test_subcommand_check_fails_on_a_drifted_fixture(self):
        fixture = "case \"${1:-}\" in\n  init)     x ;;\n  real-one) x ;;\n"
        self.assertEqual(dispatcher_labels(fixture, "case"), {"init", "real-one"})
        self.assertNotIn("imaginary", dispatcher_labels(fixture, "case"))


if __name__ == "__main__":
    unittest.main()
