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
# Every role prefix that exists anywhere. Used only to recognize a per-role key
# by its shape; WHICH roles actually read a given dynamic suffix comes from
# roles_for_suffix() below, never from this union.
_ROLES = ("BUILDER", "REVIEWER", "AUDITOR", "GATE", "SUMMARIZER", "TROUBLESHOOTER")


def _read(rel):
    with open(os.path.join(TOOL_HOME, rel), errors="replace") as f:
        return f.read()


def agent_roles():
    """Roles the plugin render loops over: the prefixes in bin/clagentic-lite's
    _AGENT_ROLE_TABLE. These are the roles that read CLAGENTIC_<ROLE>_AGENT_MODEL."""
    m = re.search(r'^_AGENT_ROLE_TABLE="([^"]*)"', _read("bin/clagentic-lite"), re.M)
    assert m, "bin/clagentic-lite no longer defines _AGENT_ROLE_TABLE"
    return {entry.split(":")[0] for entry in m.group(1).split()}


def cli_roles():
    """Roles the gate/CLI path resolves through role_chain/walk_chain: the loop
    in doctor's auth probe that enumerates them, in bin/clagentic-lite."""
    m = re.search(r"for _role_pfx in ([A-Z ]+); do", _read("bin/clagentic-lite"))
    assert m, "bin/clagentic-lite no longer enumerates the CLI roles in doctor's auth probe"
    return set(m.group(1).split())


def routable_roles():
    """Roles _llm_role_routable (scripts/llm-client.sh) lets through to the
    router; the only roles whose CLAGENTIC_<ROLE>_VIA_ROUTER the code reads
    dynamically."""
    m = re.search(
        r"_llm_role_routable\(\) \{\s*case \"\$1\" in\s*([a-z|]+\)) return 0",
        _read("scripts/llm-client.sh"),
    )
    assert m, "scripts/llm-client.sh no longer defines _llm_role_routable as a case list"
    return {r.upper() for r in m.group(1).rstrip(")").split("|")}


def roles_for_suffix(suffix):
    """The roles that actually read CLAGENTIC_<ROLE>_<suffix>. A suffix read
    by SOME role does not make it read by every role: the fixtures in this
    file (a summarizer AGENT_MODEL, a troubleshooter REQUIRED, a builder
    VIA_ROUTER) document keys no code reads."""
    if suffix == "AGENT_MODEL":
        return agent_roles()
    if suffix == "VIA_ROUTER":
        return routable_roles()
    return cli_roles()

# Names that appear in code but are deliberately NOT operator-settable config
# keys. Each entry states why. Anything not here must be in config.example.
INTERNAL_ONLY = {
    # Once-per-process idempotence latches set by the env loaders in platform.sh.
    "CLAGENTIC_ENV_LOADED": "loader idempotence latch",
    "CLAGENTIC_GLOBAL_ENV_LOADED": "loader idempotence latch",
    "CLAGENTIC_REPO_ENV_LOADED": "loader idempotence latch",
    "CLAGENTIC_GLOBAL_CONFIG_OLD_PATH_WARNED": "once-per-process warning latch",
    "CLAGENTIC_LITE_HOME_SET": "once-per-process warning latch",
    # Per-call handoff gates.sh sets for one llm-client.sh invocation to receive
    # the accepted step's model and prompt hash; never an operator setting.
    "CLAGENTIC_LLM_RUN_META_FILE": "internal gates.sh -> llm-client.sh per-call handoff file",
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


def dynamic_key_reads(suffixes, roles_for=roles_for_suffix):
    """Every CLAGENTIC_<ROLE>_<SUFFIX> the code reads, expanded over only the
    roles that read that suffix."""
    return {f"CLAGENTIC_{r}_{s}" for s in suffixes for r in roles_for(s)}


def drift(literal, suffixes, documented, internal_only, document_only, families=(),
          roles_for=roles_for_suffix):
    """Returns (undocumented_in_code, documented_but_unread)."""
    undocumented = sorted(
        k for k in literal if k not in documented and k not in internal_only
    )
    dynamic_reads = dynamic_key_reads(suffixes, roles_for)
    # A per-role suffix the code reads must be documented for at least one of
    # the roles that read it.
    undocumented += sorted(
        f"CLAGENTIC_<ROLE>_{s}" for s in suffixes
        if not any(f"CLAGENTIC_{r}_{s}" in documented or f"CLAGENTIC_{r}_{s}" in internal_only
                   for r in roles_for(s))
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

    def test_role_sets_are_derived_from_the_code(self):
        self.assertEqual(agent_roles(), {"BUILDER", "REVIEWER", "AUDITOR", "GATE", "TROUBLESHOOTER"})
        self.assertEqual(cli_roles(), {"BUILDER", "REVIEWER", "AUDITOR", "GATE", "SUMMARIZER"})
        self.assertEqual(routable_roles(), {"REVIEWER", "AUDITOR"})

    def _unread_for(self, key, suffix):
        """Drift of a fixture config documenting `key` while the code reads
        only role-suffix `suffix` (through the real role sets)."""
        _, unread = drift(set(), {suffix}, {key}, {}, {})
        return unread

    def test_a_suffix_read_by_some_roles_is_not_read_by_all(self):
        # Each fixture documents a key no role's code reads: the suffix IS read
        # (by other roles), which the old any-role-reads-so-all-roles
        # expansion mistook for a read of every role's key.
        for key, suffix in (
            ("CLAGENTIC_SUMMARIZER_AGENT_MODEL", "AGENT_MODEL"),
            ("CLAGENTIC_TROUBLESHOOTER_REQUIRED", "REQUIRED"),
            ("CLAGENTIC_BUILDER_VIA_ROUTER", "VIA_ROUTER"),
        ):
            with self.subTest(key=key):
                self.assertEqual(self._unread_for(key, suffix), [key])

    def test_the_roles_that_do_read_a_suffix_are_not_flagged(self):
        for key, suffix in (
            ("CLAGENTIC_GATE_AGENT_MODEL", "AGENT_MODEL"),
            ("CLAGENTIC_TROUBLESHOOTER_AGENT_MODEL", "AGENT_MODEL"),
            ("CLAGENTIC_SUMMARIZER_REQUIRED", "REQUIRED"),
            ("CLAGENTIC_REVIEWER_VIA_ROUTER", "VIA_ROUTER"),
            ("CLAGENTIC_AUDITOR_VIA_ROUTER", "VIA_ROUTER"),
        ):
            with self.subTest(key=key):
                self.assertEqual(self._unread_for(key, suffix), [])

    def test_a_fixture_role_map_that_omits_a_role_reports_it(self):
        # The mapping is a parameter, so a fixture proves the check consults it.
        _, unread = drift(set(), {"X"}, {"CLAGENTIC_A_X", "CLAGENTIC_B_X"}, {}, {},
                          roles_for=lambda s: {"A"})
        self.assertEqual(unread, ["CLAGENTIC_B_X"])

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
        known = literal | documented | dynamic_key_reads(suffixes)
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
# A title is delimited by a matching pair of quotes, so an apostrophe INSIDE a
# heading ("What's new") does not end it: double and curly quotes take
# anything but their closer; single quotes let an apostrophe through when it
# is followed by a word character.
_POINTER_TITLE_RE = re.compile(
    _DOC_NAME
    + r"(?:\.md)?\s+(?:§\s*[\d.]+\s+)?"
    + r"(?:\"([^\"]{4,})\"|“([^”]{4,})”|'((?:[^']|'(?=\w)){4,})')"
)
_POINTER_ANCHOR_RE = re.compile(_DOC_NAME + r"\.md#([A-Za-z0-9_-]+)")


def _doc_path(name):
    if name in ("README", "AGENTS"):
        return f"{name}.md"
    return f"{name}.md" if name.startswith("docs/") else f"docs/{name}.md"


def _flatten_comment_wraps(text):
    """Join a pointer a comment wrapped across lines back into one line."""
    # A shell string split across two quoted fragments ("... 'Title "<newline>
    # "rest' ...") is one string: drop the join.
    text = re.sub(r'"[ \t]*\n[ \t]*"', "", text)
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
    for name, *quoted in _POINTER_TITLE_RE.findall(code_text):
        title = next(t for t in quoted if t)
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

    def test_an_apostrophe_inside_a_heading_does_not_end_the_title(self):
        heads = {"README.md": ["Intro", "What's new in v2"]}
        for pointer in (
            'see README "What\'s new in v2"',
            "see README 'What's new in v2'",
            "see README “What's new in v2”",
        ):
            with self.subTest(pointer=pointer):
                self.assertEqual(unresolved_pointers(pointer, heads), [])
        # And a title with an apostrophe that names no heading is still flagged.
        for pointer in ('see README "Don\'t panic"', "see README 'Don't panic'"):
            with self.subTest(pointer=pointer):
                bad = unresolved_pointers(pointer, heads)
                self.assertEqual(len(bad), 1, pointer)
                self.assertIn("Don't panic", bad[0][0])

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


# One invocation: optional `$ `, optional `env`, any number of VAR=value
# assignments, an optional shell, an optional path prefix, then the tool and its
# first (and, for `clagentic-lite gates`, second) word. Anchored at the start of
# a fenced line or a backtick span, so prose that merely mentions the product
# name is never mistaken for a command. Exactly one space separates the tool
# from its subcommand: a file-tree listing pads that gap with runs of spaces
# (`~/.local/bin/clagentic-lite    symlink to ...`) and is not an invocation. A
# word ending in `_...` (`gates.sh cmd_review`, a function name) is not a
# subcommand either.
_INVOCATION_RE = re.compile(
    r"^\s*(?:\$\s+)?(?:env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
    r"(?:(?:sh|bash)\s+)?(?:\S*/)?(clagentic-lite|gates\.sh) "
    r"([a-z][a-z-]*)(?!\w)(?: ([a-z][a-z-]*)(?!\w))?"
)
_PROSE_GATES_RE = re.compile(r"clagentic-lite gates ([a-z][a-z-]*)")


def invocation_candidates(text):
    """Fenced code lines plus every single-backtick span."""
    yield from fenced_code_lines(text)
    for span in re.findall(r"`([^`\n]+)`", text):
        yield span


def unknown_subcommands(text, subcommands, gate_subcommands):
    """(tool, subcommand) for every documented invocation in TEXT that names a
    subcommand the dispatcher (or gates.sh) does not have. Covers the plain
    form, path-prefixed and shell-prefixed invocations, env-prefixed ones,
    `gates.sh <sub>` called directly, and `clagentic-lite gates <sub>`."""
    bad = []
    for cand in invocation_candidates(text):
        m = _INVOCATION_RE.match(cand)
        if not m:
            continue
        tool, sub, sub2 = m.groups()
        if tool == "gates.sh":
            if sub not in gate_subcommands:
                bad.append(("gates.sh", sub))
        elif sub not in subcommands:
            bad.append(("clagentic-lite", sub))
        elif sub == "gates" and sub2 and sub2 not in gate_subcommands:
            bad.append(("clagentic-lite gates", sub2))
    for sub in _PROSE_GATES_RE.findall(text):
        if sub not in gate_subcommands and ("clagentic-lite gates", sub) not in bad:
            bad.append(("clagentic-lite gates", sub))
    return bad


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
            for tool, sub in unknown_subcommands(text, self.subcommands, self.gate_subcommands):
                bad.append((rel, tool, sub))
        self.assertEqual(
            bad, [],
            "docs name a subcommand the dispatcher (or gates.sh) does not have",
        )

    def test_dispatcher_label_parser_reads_a_fixture(self):
        fixture = "case \"${1:-}\" in\n  init)     x ;;\n  real-one) x ;;\n"
        self.assertEqual(dispatcher_labels(fixture, "case"), {"init", "real-one"})

    def _scan(self, doc_text):
        return unknown_subcommands(doc_text, self.subcommands, self.gate_subcommands)

    def test_the_real_doc_scan_fails_on_a_doc_naming_a_nonexistent_subcommand(self):
        drifted = "Run `clagentic-lite imaginary-sub` to do the thing.\n"
        self.assertEqual(self._scan(drifted), [("clagentic-lite", "imaginary-sub")])
        # The same scan on a doc naming a real one is clean.
        self.assertEqual(self._scan("Run `clagentic-lite doctor` first.\n"), [])

    def test_the_scan_covers_every_invocation_form(self):
        cases = {
            "plain, backticked": "`clagentic-lite nosuch`",
            "plain, fenced": "```\nclagentic-lite nosuch\n```",
            "prompt-prefixed, fenced": "```\n$ clagentic-lite nosuch\n```",
            "relative path prefix": "`bin/clagentic-lite nosuch`",
            "dot-slash prefix": "```\n./bin/clagentic-lite nosuch\n```",
            "home path prefix": "`~/.local/bin/clagentic-lite nosuch`",
            "variable path prefix": "`$CLAGENTIC_LITE_HOME/bin/clagentic-lite nosuch`",
            "shell-prefixed": "```\nsh bin/clagentic-lite nosuch\n```",
            "env-assignment prefix": "`CLAGENTIC_FOO=1 clagentic-lite nosuch`",
            "env command prefix": "```\nenv CLAGENTIC_FOO=1 CLAGENTIC_BAR=2 clagentic-lite nosuch\n```",
            "env prefix with path": "`CLAGENTIC_FOO=1 ~/.local/bin/clagentic-lite nosuch`",
        }
        for label, doc in cases.items():
            with self.subTest(form=label):
                self.assertEqual(self._scan(doc), [("clagentic-lite", "nosuch")], doc)

    def test_the_scan_covers_gates_forms(self):
        cases = {
            "gates.sh direct": ("`gates.sh nosuch`", ("gates.sh", "nosuch")),
            "gates.sh with script path": ("```\nscripts/gates.sh nosuch\n```", ("gates.sh", "nosuch")),
            "sh scripts/gates.sh": ("```\nsh scripts/gates.sh nosuch\n```", ("gates.sh", "nosuch")),
            "env-prefixed gates.sh": ("`CLAGENTIC_FOO=1 gates.sh nosuch`", ("gates.sh", "nosuch")),
            "clagentic-lite gates, backticked": (
                "`clagentic-lite gates nosuch`", ("clagentic-lite gates", "nosuch")),
            "clagentic-lite gates, prose": (
                "then clagentic-lite gates nosuch runs", ("clagentic-lite gates", "nosuch")),
            "env-prefixed clagentic-lite gates": (
                "```\nCLAGENTIC_FOO=1 clagentic-lite gates nosuch --x\n```",
                ("clagentic-lite gates", "nosuch")),
        }
        for label, (doc, expected) in cases.items():
            with self.subTest(form=label):
                self.assertEqual(self._scan(doc), [expected], doc)

    def test_the_scan_accepts_real_subcommands_in_every_form(self):
        real = sorted(self.gate_subcommands)[0]
        doc = (
            "`clagentic-lite doctor`\n```\nCLAGENTIC_FOO=1 ~/.local/bin/clagentic-lite update\n```\n"
            f"`gates.sh {real}`\n`clagentic-lite gates {real}`\n"
            "Prose: clagentic-lite is a tool, `clagentic-lite` alone is fine.\n"
        )
        self.assertEqual(self._scan(doc), [])


if __name__ == "__main__":
    unittest.main()
