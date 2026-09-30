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
import shutil
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
# `role_env <ROLE> <SUFFIX> ...` (scripts/llm-client.sh) reads
# CLAGENTIC_<ROLE>_<SUFFIX>; the suffix is a literal word in the call.
_ROLE_ENV_RE = re.compile(r"\brole_env\s+\"?\$?\{?\w+\}?\"?\s+([A-Z][A-Z0-9_]*[A-Z0-9])\b")
# CLAGENTIC_$(<command substitution>)_SUFFIX: a name built by a pipeline.
_CONSTRUCTED_RE = re.compile(r"CLAGENTIC_\$\([^)]*\)_([A-Z][A-Z0-9_]*[A-Z0-9])\b")
# The role prefixes the dynamic constructions expand over. Must cover every
# prefix in bin/clagentic-lite's _AGENT_ROLE_TABLE (asserted below) plus the
# CLI-only SUMMARIZER role.
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
#
# Per-role families (_REQUIRED, _TIMEOUT_SEC, _TIMEOUT_MAX_SEC) are NOT listed
# here: they are extracted from the code itself (_ROLE_ENV_RE, _CONSTRUCTED_RE),
# so deleting one read makes its documented keys "unread" again instead of being
# masked by a blanket pattern. Only the CLI x tier table, which has no literal
# suffix to extract, stays evidence-based.
DYNAMIC_FAMILIES = (
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
        suffixes.update(_ROLE_ENV_RE.findall(text))
        suffixes.update(_CONSTRUCTED_RE.findall(text))
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
    # A per-role suffix the code reads must be documented for at least one role.
    undocumented += sorted(
        f"CLAGENTIC_<ROLE>_{s}" for s in suffixes
        if not any(f"CLAGENTIC_{r}_{s}" in documented or f"CLAGENTIC_{r}_{s}" in internal_only
                   for r in _ROLES)
    )
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

    def _fixture_drift(self, code_text, example_text):
        with tempfile.TemporaryDirectory() as tmp:
            code = os.path.join(tmp, "fixture.sh")
            example = os.path.join(tmp, "config.example")
            with open(code, "w") as f:
                f.write(code_text)
            with open(example, "w") as f:
                f.write(example_text)
            literal, suffixes = keys_read_in_code([code])
            documented = keys_in_config_example(example)
        return drift(literal, suffixes, documented, {}, {})

    def test_role_env_reads_are_extracted_as_role_suffixes(self):
        _, suffixes = keys_read_in_code(
            [self._write_tmp('x=$(role_env "$ROLE_U" TIMEOUT_MAX_SEC "300")\n')]
        )
        self.assertEqual(suffixes, {"TIMEOUT_MAX_SEC"})

    def test_constructed_names_are_extracted(self):
        _, suffixes = keys_read_in_code(
            [self._write_tmp("K=\"CLAGENTIC_$(printf '%s' \"$R\" | tr a-z A-Z)_REQUIRED\"\n")]
        )
        self.assertEqual(suffixes, {"REQUIRED"})

    def test_deleted_per_role_timeout_max_read_is_reported_unread(self):
        # Both documented; only the base read remains in code. The old blanket
        # family pattern hid this.
        example = (
            "# CLAGENTIC_REVIEWER_TIMEOUT_SEC=1\n"
            "# CLAGENTIC_REVIEWER_TIMEOUT_MAX_SEC=1\n"
        )
        code_before = 'a=$(role_env "$R" TIMEOUT_SEC 1)\nb=$(role_env "$R" TIMEOUT_MAX_SEC 1)\n'
        code_after = 'a=$(role_env "$R" TIMEOUT_SEC 1)\n'
        self.assertEqual(self._fixture_drift(code_before, example), ([], []))
        undocumented, unread = self._fixture_drift(code_after, example)
        self.assertEqual(undocumented, [])
        self.assertIn("CLAGENTIC_REVIEWER_TIMEOUT_MAX_SEC", unread)

    def test_deleted_constructed_required_read_is_reported_unread(self):
        example = "# CLAGENTIC_GATE_REQUIRED=0\n"
        code = "K=\"CLAGENTIC_$(printf x)_REQUIRED\"\n"
        self.assertEqual(self._fixture_drift(code, example), ([], []))
        _, unread = self._fixture_drift("echo nothing\n", example)
        self.assertEqual(unread, ["CLAGENTIC_GATE_REQUIRED"])

    def test_undocumented_per_role_suffix_is_reported(self):
        undocumented, _ = self._fixture_drift('a=$(role_env "$R" BRAND_NEW 1)\n', "")
        self.assertEqual(undocumented, ["CLAGENTIC_<ROLE>_BRAND_NEW"])

    def test_role_list_covers_the_cli_role_table(self):
        with open(os.path.join(TOOL_HOME, "bin", "clagentic-lite")) as f:
            m = re.search(r'^_AGENT_ROLE_TABLE="([^"]*)"', f.read(), re.M)
        self.assertIsNotNone(m)
        prefixes = {entry.split(":")[0] for entry in m.group(1).split()}
        self.assertEqual(prefixes - set(_ROLES), set(), "role table has a role _ROLES does not enumerate")

    def _write_tmp(self, text):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "fixture.sh")
        with open(path, "w") as f:
            f.write(text)
        return path


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
    r"\b(PEACHES|BOBBIE|HOLDEN|NAOMI|AMOS|MILLER|ASHFORD|AVASARALA|DRUMMER|TIAMUT|PRAX)\b",
    re.IGNORECASE,
)


def crew_names_in(text):
    return sorted({m.upper() for m in _CREW_NAME_RE.findall(text)})


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

    def test_detector_is_case_insensitive(self):
        # The mixed-case product spelling is the one an upper-case-only
        # pattern missed.
        self.assertEqual(crew_names_in("built by AMoS"), ["AMOS"])
        self.assertEqual(crew_names_in("Amos and holden"), ["AMOS", "HOLDEN"])

    def test_detector_respects_word_boundaries(self):
        self.assertEqual(crew_names_in("Tiamutant, Praxis, Damos, Millerite"), [])


# Shipped manifests are read by every installer; a personal address in one is
# an identity leak. Org-level name/url only.
SHIPPED_MANIFESTS = (
    ".claude-plugin/marketplace.json",
    "plugins/clagentic-lite/.claude-plugin/plugin.json",
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def emails_in(text):
    return sorted(set(_EMAIL_RE.findall(text)))


class TestShippedManifestsCarryNoEmail(unittest.TestCase):
    def test_no_email_address_in_shipped_manifests(self):
        found = []
        for rel in SHIPPED_MANIFESTS:
            with open(os.path.join(TOOL_HOME, rel)) as f:
                for lineno, line in enumerate(f, 1):
                    for addr in emails_in(line):
                        found.append(f"{rel}:{lineno}: {addr}")
        self.assertEqual(found, [], "email address in a shipped manifest")

    def test_detector_fails_on_a_drifted_fixture(self):
        drifted = '{"author": {"name": "x", "email": "someone@example.com"}}'
        self.assertEqual(emails_in(drifted), ["someone@example.com"])
        self.assertEqual(emails_in('{"author": {"name": "clagentic"}}'), [])


# Pointers in shipped code that send a reader to a doc section: either
# `FILE.md#anchor`, or a doc name followed by a quoted section title
# (`see README "Some heading"`, `docs/ROUTER.md § 2 "Some heading"`). Each must
# resolve to a real heading in the named file, or the pointer is a dead end (the
# README section a comment named had moved to docs/ROUTER.md).
_DOC_NAME = r"(README|AGENTS|(?:docs/)?(?:DESIGN|GATES|LLM-USAGE|PORTABILITY|ROUTER|DEMO-SCRIPT))"
_POINTER_TITLE_RE = re.compile(
    _DOC_NAME + r"(?:\.md)?\s+(?:§\s*[\d.]+\s+)?[\"'“]([^\"'”]{4,})[\"'”]"
)
_POINTER_ANCHOR_RE = re.compile(_DOC_NAME + r"\.md#([A-Za-z0-9_-]+)")


def _doc_path(name):
    if name in ("README", "AGENTS"):
        return f"{name}.md"
    return f"{name}.md" if name.startswith("docs/") else f"docs/{name}.md"


def _flatten_comment_wraps(text):
    """Join a pointer a comment wrapped across lines back into one line."""
    text = re.sub(r"-\n[ \t]*#[ \t]*", "-", text)
    text = re.sub(r"\n[ \t]*#[ \t]*", " ", text)
    return re.sub(r"[ \t]{2,}", " ", text)


def doc_headings(text):
    """Heading texts of a markdown file, backticks and trailing #s removed."""
    heads = []
    inside = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        m = None if inside else re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            heads.append(m.group(1).replace("`", ""))
    return heads


def heading_slug(heading):
    slug = re.sub(r"[^a-z0-9 _-]", "", heading.lower())
    return slug.replace(" ", "-")


def unresolved_pointers(code_text, headings_by_file):
    """(pointer, reason) for every doc pointer in CODE_TEXT that does not
    resolve. headings_by_file maps a doc path to its heading list."""
    bad = []
    code_text = _flatten_comment_wraps(code_text)
    for name, title in _POINTER_TITLE_RE.findall(code_text):
        heads = headings_by_file.get(_doc_path(name))
        if heads is None:
            bad.append((f"{name} \"{title}\"", "no such doc file"))
        elif not any(title.lower() in h.lower() for h in heads):
            bad.append((f"{name} \"{title}\"", f"no heading contains it in {_doc_path(name)}"))
    for name, anchor in _POINTER_ANCHOR_RE.findall(code_text):
        heads = headings_by_file.get(_doc_path(name))
        if heads is None:
            bad.append((f"{name}.md#{anchor}", "no such doc file"))
        elif anchor not in {heading_slug(h) for h in heads}:
            bad.append((f"{name}.md#{anchor}", f"no heading slug matches in {_doc_path(name)}"))
    return bad


def _headings_by_file():
    out = {}
    for rel in DOC_FILES:
        with open(os.path.join(TOOL_HOME, rel)) as f:
            out[rel] = doc_headings(f.read())
    return out


class TestCodeDocPointersResolve(unittest.TestCase):
    maxDiff = None

    def test_every_doc_pointer_in_shipped_code_resolves_to_a_heading(self):
        heads = _headings_by_file()
        found = []
        for path in _code_files():
            with open(path, errors="replace") as f:
                text = f.read()
            for pointer, reason in unresolved_pointers(text, heads):
                found.append(f"{os.path.relpath(path, TOOL_HOME)}: {pointer}: {reason}")
        self.assertEqual(found, [], "doc pointer(s) in shipped code that do not resolve")

    def test_a_pointer_at_a_moved_section_is_flagged(self):
        # The exact stale shapes bin/clagentic-lite carried: the section now
        # lives in docs/ROUTER.md, not README.
        heads = _headings_by_file()
        for stale in (
            "see README.md \"Verifying on your machine\" and",
            "see README 'Verifying on your machine'",
            "See README \"Verifying on your machine\".",
        ):
            with self.subTest(stale=stale):
                self.assertTrue(unresolved_pointers(stale, heads), stale)

    def test_the_corrected_pointer_resolves(self):
        heads = _headings_by_file()
        self.assertEqual(
            unresolved_pointers("see docs/ROUTER.md \"Verifying on your machine\"", heads), []
        )

    def test_a_dead_anchor_is_flagged(self):
        heads = _headings_by_file()
        self.assertTrue(unresolved_pointers("see docs/ROUTER.md#no-such-section", heads))
        self.assertEqual(
            unresolved_pointers("see docs/ROUTER.md#verifying-on-your-machine", heads), []
        )


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
