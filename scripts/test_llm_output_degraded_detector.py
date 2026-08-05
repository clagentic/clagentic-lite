"""
Regression coverage for lr-7047bf (PR-B): _llm_output_is_degraded, the
mode-complete degraded detector (scripts/gates.sh).

Root cause: review_is_degraded (gates.sh) only ever understood the JSON
envelope shape emit_degraded (llm-client.sh) can write. The MARKDOWN shape
(cmd_adversarial's output) and the LINE shape (cmd_summarize's output) had
NO detector anywhere in the repo -- that absence is exactly why
cmd_adversarial had no degraded check at all: there was nothing to call.
_llm_output_is_degraded covers all three modes emit_degraded can produce.

Also covers the fail-closed requirement for json mode specifically: with
neither jq nor python3 available, the OLD review_is_degraded assumed "not
degraded" (fail-open), relying on severity_blockers' own fail-closed as a
backstop that does not exist for every consumer (cmd_adversarial has no
equivalent numeric-count backstop). _llm_output_is_degraded's json branch
assumes "degraded" instead -- a caller that cannot verify JSON content is
real must not treat it as real. markdown/line modes are grep-based and
never depended on a JSON validator to begin with, so their coverage below
asserts the narrower "still detects correctly with no JSON tool present"
property rather than a fail-closed branch that does not exist for them.

UNFORGEABLE PREFIX (BOBBIE finding 1, lr-7047bf fold-in): line/markdown
mode detection now requires a leading DEGRADED_MARKER control byte (a
literal ASCII SOH, 0x01, prepended by emit_degraded -- llm-client.sh)
before it will treat the banner text as a real degraded envelope. Before
this, plain text alone ("[clagentic-lite degraded] " / "# Degraded
output") was sufficient -- a prompt-injected model response opening with
that exact text could misclassify a real, clean audit as degraded. The
"forged banner without marker byte" tests below prove that attack no
longer works: identical banner text with no leading marker byte is
correctly NOT flagged. All positive fixtures in this file were updated to
prepend \x01, matching real emit_degraded output.

Sources the REAL sh function from gates.sh (not a Python mirror), mirroring
test_adversarial_findings_sanitize.py's established functions-only-source
technique.

Run with: python3 -m unittest scripts.test_llm_output_degraded_detector -v
"""
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

# Coreutils gates.sh's own sourcing preamble and _llm_output_is_degraded's
# own body need on PATH (dirname for the `. "$(dirname "$0")/platform.sh"`
# self-source at the top of gates.sh; git for _git; head/grep for the
# detector itself; sh/cat/mkdir for general script plumbing) -- deliberately
# NOT jq or python3/python, which is the exact condition this test class
# exercises. An empty PATH would break sourcing before the function under
# test is ever reached; this builds a minimal-but-sufficient PATH instead.
_REQUIRED_NON_JSON_TOOLS = (
    "sh", "dirname", "cat", "head", "grep", "git", "mkdir", "sed", "date",
    "sqlite3", "mktemp", "printf", "rm", "cut", "tr", "uname", "basename",
    "stat", "find", "id", "wc",
)


def _build_no_json_tool_path(dest_bin_dir):
    """Symlink every tool in _REQUIRED_NON_JSON_TOOLS (if found on the real
    PATH) into dest_bin_dir, deliberately excluding jq/python3/python.
    Returns dest_bin_dir for use as a standalone PATH."""
    for name in _REQUIRED_NON_JSON_TOOLS:
        real = shutil.which(name)
        if real:
            os.symlink(real, os.path.join(dest_bin_dir, name))
    return dest_bin_dir


def _functions_only_source(dest_dir):
    """Same truncation/symlink pattern as test_adversarial_findings_sanitize.py."""
    with open(GATES_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in gates.sh"
    dest = os.path.join(dest_dir, "gates.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
    for fname in ("platform.sh", "review-merge.sh"):
        os.symlink(os.path.join(real_scripts_dir, fname), os.path.join(dest_dir, fname))
    return dest


def _run_sh_function(call_line, extra_script="", extra_env=None):
    """Source gates.sh (functions only) and run an arbitrary call line
    against it, returning (stdout, stderr, returncode)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-degraded-detector-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)

        script = textwrap.dedent(f"""\
            . '{sourced_gates}'
            {extra_script}
            {call_line}
        """)
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True,
            text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"),
            env=env,
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def _write_tmp_file(content):
    fd, path = tempfile.mkstemp(prefix="clagentic-test-degraded-content-")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class TestJsonModeDetection(unittest.TestCase):
    def test_degraded_true_is_detected(self):
        path = _write_tmp_file('{"degraded": true, "summary": "x", "checked": [], "findings": []}\n')
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded json '{path}'")
            self.assertEqual(rc, 0, f"expected degraded (rc=0). stderr={err!r}")
        finally:
            os.unlink(path)

    def test_degraded_false_is_not_detected(self):
        path = _write_tmp_file('{"summary": "clean", "checked": [], "findings": []}\n')
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded json '{path}'")
            self.assertEqual(rc, 1, f"expected not-degraded (rc=1). stderr={err!r}")
        finally:
            os.unlink(path)

    def test_review_is_degraded_wrapper_still_works(self):
        """review_is_degraded's many existing gates.sh call sites must be
        unaffected by becoming a thin wrapper."""
        path = _write_tmp_file('{"degraded": true, "findings": []}\n')
        try:
            out, err, rc = _run_sh_function(f"review_is_degraded '{path}'")
            self.assertEqual(rc, 0, f"stderr={err!r}")
        finally:
            os.unlink(path)


class TestMarkdownModeDetection(unittest.TestCase):
    """The shape emit_degraded's markdown branch writes (llm-client.sh) --
    this mode had NO detector anywhere before this task."""

    def test_degraded_markdown_header_is_detected(self):
        # Leading DEGRADED_MARKER byte (\x01) -- BOBBIE finding 1 hardening,
        # lr-7047bf fold-in: real emit_degraded output (llm-client.sh)
        # always prepends this byte; the fixture must match the real shape.
        content = (
            "\x01# Degraded output\n\n"
            "clagentic-lite role-call wrapper could not produce a real response: "
            "all chain steps failed for role auditor.\n"
        )
        path = _write_tmp_file(content)
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded markdown '{path}'")
            self.assertEqual(rc, 0, f"expected degraded (rc=0). stderr={err!r}")
        finally:
            os.unlink(path)

    def test_real_adversarial_markdown_is_not_flagged(self):
        """A real (non-degraded) Auditor pass must not be mistaken for
        degraded output -- proves the detector is specific to the actual
        emit_degraded header, not any markdown starting with '#'."""
        content = (
            "# Adversarial findings\n\n"
            "[FINDING] CWE-89 | app.py:12 | severity: high | reachable: yes | "
            "tier: blocking | class: durable | title: SQL injection\n\n"
            "Prose explanation.\n"
        )
        path = _write_tmp_file(content)
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded markdown '{path}'")
            self.assertEqual(rc, 1, f"expected NOT degraded (rc=1). stderr={err!r}")
        finally:
            os.unlink(path)

    def test_forged_markdown_banner_without_marker_byte_is_not_flagged(self):
        """BOBBIE finding 1 (lr-7047bf fold-in): a prompt-injected model
        response that opens with the EXACT banner text ("# Degraded
        output") but lacks the leading DEGRADED_MARKER control byte -- the
        byte only emit_degraded (never model-generated text) can produce --
        must NOT be classified as degraded. This is the attack the
        unforgeable-prefix hardening closes: before this fix, plain text
        alone was sufficient to trigger a false degraded classification,
        misclassifying a real, clean audit."""
        content = (
            "# Degraded output\n\n"
            "clagentic-lite role-call wrapper could not produce a real response: "
            "all chain steps failed for role auditor.\n"
        )
        path = _write_tmp_file(content)
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded markdown '{path}'")
            self.assertEqual(
                rc, 1,
                f"a forged banner with no leading marker byte must NOT be "
                f"classified as degraded -- text alone is forgeable, the "
                f"marker byte is not. stderr={err!r}",
            )
        finally:
            os.unlink(path)


class TestLineModeDetection(unittest.TestCase):
    """The shape emit_degraded's line branch writes -- also had no detector
    before this task."""

    def test_degraded_line_prefix_is_detected(self):
        # Leading DEGRADED_MARKER byte (\x01) -- see markdown-mode test
        # above for the rationale; real emit_degraded output always
        # prepends it.
        path = _write_tmp_file("\x01[clagentic-lite degraded] no chain configured for role summarizer\n")
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded line '{path}'")
            self.assertEqual(rc, 0, f"expected degraded (rc=0). stderr={err!r}")
        finally:
            os.unlink(path)

    def test_real_summary_line_is_not_flagged(self):
        path = _write_tmp_file("session summary: refactored the widget loader\n")
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded line '{path}'")
            self.assertEqual(rc, 1, f"expected NOT degraded (rc=1). stderr={err!r}")
        finally:
            os.unlink(path)

    def test_forged_line_banner_without_marker_byte_is_not_flagged(self):
        """BOBBIE finding 1 (lr-7047bf fold-in): the line-mode equivalent
        of the markdown forgery test above -- a summarizer response that
        happens to start with the exact "[clagentic-lite degraded] " text
        but lacks the marker byte must not be classified as degraded."""
        path = _write_tmp_file("[clagentic-lite degraded] no chain configured for role summarizer\n")
        try:
            out, err, rc = _run_sh_function(f"_llm_output_is_degraded line '{path}'")
            self.assertEqual(
                rc, 1,
                f"a forged line banner with no leading marker byte must NOT "
                f"be classified as degraded. stderr={err!r}",
            )
        finally:
            os.unlink(path)


class TestFailClosedOnNoValidator(unittest.TestCase):
    """FAIL CLOSED requirement: with neither jq nor python3 on PATH, json
    mode's detector must assume degraded rather than the old
    review_is_degraded's fail-open ('assume not degraded'). Only json mode
    has a genuine "no validator available" branch (it needs a JSON parser
    to read the .degraded field); markdown/line modes are grep-based and
    never depended on jq/python3 at all -- their tests below assert the
    narrower, still-important property that detection keeps working
    correctly with no JSON tool on PATH, not that they "fail closed" from a
    branch that does not exist for them. Achieved by stubbing PATH to a
    directory with every tool gates.sh sourcing needs EXCEPT jq/python3."""

    def _run_call_with_no_json_tools(self, call_line):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-no-json-tools-")
        try:
            no_json_bin = os.path.join(tmpdir, "no-json-bin")
            os.makedirs(no_json_bin)
            _build_no_json_tool_path(no_json_bin)
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            sourced_gates = _functions_only_source(src_dir)
            script = textwrap.dedent(f"""\
                export PATH='{no_json_bin}'
                . '{sourced_gates}'
                {call_line}
            """)
            r = subprocess.run(
                ["sh", "-c", script, sourced_gates],
                capture_output=True, text=True, cwd=os.path.join(TOOL_HOME, "scripts"),
            )
            return r.stdout, r.stderr, r.returncode
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _run_with_no_json_tools(self, mode, path):
        return self._run_call_with_no_json_tools(f"_llm_output_is_degraded {mode} '{path}'")

    def test_json_mode_fails_closed_with_no_validator(self):
        """This is the polarity flip on the detector itself (site 1.13):
        the old review_is_degraded returned 1 (not degraded) here. A
        caller that cannot verify JSON content must not trust it."""
        path = _write_tmp_file('{"degraded": false, "findings": []}\n')
        try:
            out, err, rc = self._run_with_no_json_tools("json", path)
            self.assertEqual(
                rc, 0,
                f"json mode must fail CLOSED (assume degraded, rc=0) with "
                f"no jq/python3 available, even though the file content "
                f"itself says degraded:false. stderr={err!r}",
            )
        finally:
            os.unlink(path)

    def test_review_is_degraded_wrapper_also_fails_closed(self):
        path = _write_tmp_file('{"degraded": false, "findings": []}\n')
        try:
            out, err, rc = self._run_call_with_no_json_tools(f"review_is_degraded '{path}'")
            self.assertEqual(
                rc, 0,
                f"review_is_degraded must also fail closed (previously "
                f"fail-OPEN -- this is the review_is_degraded-specific "
                f"regression, site 1.13). stderr={err!r}",
            )
        finally:
            os.unlink(path)

    def test_markdown_mode_needs_no_json_validator_at_all(self):
        """markdown/line modes are grep-based (head -1 | grep -qF), not
        JSON-parsed -- unlike json mode, there is no "no validator
        available" branch to fail closed FROM, because these two modes
        never depend on jq/python3 in the first place. This is the correct,
        narrower claim: detection still works correctly (real content is
        still correctly NOT flagged) with no JSON tool on PATH at all,
        which is a stronger property than "fails closed" would imply."""
        content = "# Adversarial findings\n\nreal content\n"
        path = _write_tmp_file(content)
        try:
            out, err, rc = self._run_with_no_json_tools("markdown", path)
            self.assertEqual(
                rc, 1,
                f"markdown mode must still correctly detect non-degraded "
                f"content with no jq/python3 on PATH -- it never needed a "
                f"JSON validator. stderr={err!r}",
            )
        finally:
            os.unlink(path)

    def test_line_mode_needs_no_json_validator_at_all(self):
        path = _write_tmp_file("a real summary line\n")
        try:
            out, err, rc = self._run_with_no_json_tools("line", path)
            self.assertEqual(rc, 1, f"stderr={err!r}")
        finally:
            os.unlink(path)

    def test_missing_file_fails_closed_in_markdown_and_line_modes(self):
        """A file that was never written at all (e.g. the LLM call crashed
        before any output redirection completed) must also read as
        degraded, not silently pass a `[ -f ... ] || return 1` style
        fail-open."""
        missing_path = os.path.join(tempfile.gettempdir(), "clagentic-test-does-not-exist-7047bf")
        self.assertFalse(os.path.exists(missing_path))
        out, err, rc = _run_sh_function(f"_llm_output_is_degraded markdown '{missing_path}'")
        self.assertEqual(rc, 0, f"missing file must read as degraded. stderr={err!r}")
        out, err, rc = _run_sh_function(f"_llm_output_is_degraded line '{missing_path}'")
        self.assertEqual(rc, 0, f"missing file must read as degraded. stderr={err!r}")


if __name__ == "__main__":
    unittest.main()
