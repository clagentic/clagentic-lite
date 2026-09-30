"""
Class guard: the command word given to run_bounded, or to $DS_TIMEOUT_CMD /
$DS_TIMEOUT_FOREGROUND_CMD, must be an executable, never a shell function.

timeout/gtimeout exec a program. A shell function passed as the command word
fails with "failed to run command" before the wrapped work starts, and the
caller sees a plain nonzero exit that reads like the work itself failed. This
once made `gates ship` log a fully green run as "push failed or timed out"
without ever invoking git push.

The guard collects every name defined as a function across scripts/*.sh and
bin/*, then checks each timeout-wrapped call site's command word against that
set. A deliberately bad fixture proves the guard catches the mistake.

Run with: python3 -m unittest scripts.test_run_bounded_command_word -v
"""
import glob
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import SCRIPTS_DIR, TOOL_HOME  # noqa: E402

_FUNC_DEF_RE = re.compile(
    r'^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{?', re.M)
_FUNC_KEYWORD_RE = re.compile(
    r'^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\b', re.M)

# run_bounded [TIMEOUT] -- CMD ...  (TIMEOUT optional; "--" separates)
_RUN_BOUNDED_RE = re.compile(
    r'\brun_bounded\s+(?:"[^"]*"\s+|[^\s-][^\s]*\s+)?--\s+("?)([A-Za-z_][A-Za-z0-9_.-]*)\1(?=\s|$|;|\))'
)
# $DS_TIMEOUT_CMD DURATION CMD ...   (also the _FOREGROUND variant)
_DS_TIMEOUT_RE = re.compile(
    r'\$\{?DS_TIMEOUT(?:_FOREGROUND)?_CMD\}?\s+(?:"[^"]*"|\$\{?\w+\}?|\S+)\s+("?)([A-Za-z_][A-Za-z0-9_.-]*)\1(?=\s|$|;|\))'
)


def shell_sources():
    paths = sorted(glob.glob(os.path.join(SCRIPTS_DIR, "*.sh")))
    bin_dir = os.path.join(TOOL_HOME, "bin")
    paths += sorted(
        p for p in glob.glob(os.path.join(bin_dir, "*"))
        if os.path.isfile(p)
    )
    return paths


def read_text(path):
    with open(path) as f:
        return f.read()


def defined_functions(text):
    names = set(_FUNC_DEF_RE.findall(text))
    names |= set(_FUNC_KEYWORD_RE.findall(text))
    return names


def find_function_command_words(text, functions):
    """Return [(line_no, command_word, line)] for every timeout-wrapped call
    whose command word is in `functions`. Comment lines are skipped."""
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for rx in (_RUN_BOUNDED_RE, _DS_TIMEOUT_RE):
            for m in rx.finditer(line):
                word = m.group(2)
                if word in functions:
                    hits.append((i, word, line.strip()))
    return hits


class TestNoShellFunctionUnderTimeout(unittest.TestCase):

    def test_no_timeout_wrapped_command_word_is_a_shell_function(self):
        sources = {p: read_text(p) for p in shell_sources()}
        self.assertGreater(len(sources), 3, "discovery found too few scripts")
        functions = set()
        for text in sources.values():
            functions |= defined_functions(text)
        self.assertIn("_git", functions, "function discovery is broken")

        violations = []
        for path, text in sources.items():
            for line_no, word, line in find_function_command_words(text, functions):
                violations.append(f"{os.path.relpath(path, TOOL_HOME)}:{line_no}: "
                                  f"`{word}` is a shell function: {line}")
        self.assertEqual(
            violations, [],
            "a shell function was passed as the command word of a timeout "
            "wrapper; timeout execs a program and cannot run it. Spell out the "
            "real command (for git: `git -C \"$REPO_ROOT\" ...`):\n"
            + "\n".join(violations),
        )

    def test_call_site_discovery_finds_real_wrapped_calls(self):
        """Guards the guard: if the regexes stop matching real sites, the
        check above passes vacuously."""
        found = 0
        for path in shell_sources():
            text = read_text(path)
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                if _RUN_BOUNDED_RE.search(line) or _DS_TIMEOUT_RE.search(line):
                    found += 1
        self.assertGreaterEqual(found, 10)


class TestGuardCatchesABadFixture(unittest.TestCase):

    BAD_RUN_BOUNDED = (
        '_git() { git -C "$REPO_ROOT" "$@"; }\n'
        'run_bounded "$_SHIP_TIMEOUT" -- _git push -u origin "$BRANCH" || exit 1\n'
    )
    BAD_DS_TIMEOUT = (
        '_helper() { :; }\n'
        '$DS_TIMEOUT_CMD "$T" _helper arg\n'
    )
    BAD_NO_TIMEOUT_ARG = (
        '_git() { :; }\n'
        'run_bounded -- _git push\n'
    )
    GOOD = (
        '_git() { git -C "$REPO_ROOT" "$@"; }\n'
        'run_bounded "$_SHIP_TIMEOUT" -- git -C "$REPO_ROOT" push -u origin "$BRANCH"\n'
        '# run_bounded 5 -- _git commented out\n'
        '$DS_TIMEOUT_CMD "$T" git -C "$REPO_ROOT" fetch origin\n'
    )

    def _hits(self, text):
        return find_function_command_words(text, defined_functions(text))

    def test_run_bounded_with_a_function_is_caught(self):
        hits = self._hits(self.BAD_RUN_BOUNDED)
        self.assertEqual([h[1] for h in hits], ["_git"])

    def test_ds_timeout_cmd_with_a_function_is_caught(self):
        hits = self._hits(self.BAD_DS_TIMEOUT)
        self.assertEqual([h[1] for h in hits], ["_helper"])

    def test_run_bounded_without_a_timeout_argument_is_caught(self):
        hits = self._hits(self.BAD_NO_TIMEOUT_ARG)
        self.assertEqual([h[1] for h in hits], ["_git"])

    def test_real_executable_command_words_pass(self):
        self.assertEqual(self._hits(self.GOOD), [])


if __name__ == "__main__":
    unittest.main()
