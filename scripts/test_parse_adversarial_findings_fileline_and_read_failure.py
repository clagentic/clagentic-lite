"""
Regression tests for lr-33958f (PR-C fold-in, BOBBIE PR #142 review 2),
Classes 2.5 and 2.7 in _parse_adversarial_findings (scripts/gates.sh).

Class 2.7 -- READ FAILURE MUST SIGNAL, NOT SILENTLY EMPTY: an unreadable
adversarial markdown file used to fall back to `lines = []`, which then
yields the SAME zero-findings JSON array a genuinely clean audit produces
-- indistinguishable from a clean pass. This is the identical fail-open
class BOBBIE blocked on twice in PR-B (lr-7047bf): a failure signalled by
writing empty data rather than returning status. The fix: a genuine read
failure now exits nonzero with nothing on stdout, distinguishable from a
readable-but-empty file (exit 0, stdout "[]").

Class 2.5 -- FILE:LINE EXTRACTION MUST LOCATE-AND-VALIDATE, NOT
SPLIT-AND-HOPE: the prior `if ":" in fileline: fileline.rpartition(":")`
form was unanchored -- any colon anywhere in the field routed down the
"has a line number" branch. The fix: an anchored `^(.+):(\\d+)$` regex that
only recognizes a genuine trailing line number.

Sources the ACTUAL sh function from gates.sh (not a Python reimplementation),
same sourcing pattern as test_adversarial_tier_parsing.py.

Run with: python3 -m unittest scripts.test_parse_adversarial_findings_fileline_and_read_failure -v
"""
import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")


def _functions_only_source(dest_dir):
    """Same truncation/symlink pattern as test_adversarial_tier_parsing.py."""
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
    for fname in ("platform.sh", "review-merge.sh", "host-adapter.sh"):
        os.symlink(os.path.join(real_scripts_dir, fname), os.path.join(dest_dir, fname))
    return dest


def _run_parse_adversarial_findings(md_path):
    """Source gates.sh (functions only) and call _parse_adversarial_findings
    directly against md_path. Returns (stdout, stderr, returncode)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-paf-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)

        script = textwrap.dedent(f"""\
            . '{sourced_gates}'
            _parse_adversarial_findings '{md_path}'
        """)
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True, text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def _write_markdown(tmpdir, text):
    path = os.path.join(tmpdir, "adversarial.md")
    with open(path, "w") as f:
        f.write(text)
    return path


class TestFilelineAnchoredExtraction(unittest.TestCase):
    """Class 2.5: file:line extraction must LOCATE and VALIDATE, not
    split-and-hope on the first/last colon."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-paf-fileline-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_ordinary_file_colon_line_parses_correctly(self):
        md = _write_markdown(self._tmpdir, (
            "[FINDING] CWE-89 | scripts/app.py:42 | severity: high | "
            "reachable: yes | tier: blocking | class: durable | title: sqli\n\n"
            "body text\n"
        ))
        out, err, rc = _run_parse_adversarial_findings(md)
        self.assertEqual(rc, 0, f"stderr={err!r}")
        findings = json.loads(out)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file"], "scripts/app.py")
        self.assertEqual(findings[0]["line"], 42)

    def test_general_with_no_colon_falls_back_to_line_zero(self):
        md = _write_markdown(self._tmpdir, (
            "[FINDING] CWE-unknown | general | severity: low | "
            "reachable: no | tier: advisory | class: durable | title: design concern\n\n"
            "body text\n"
        ))
        out, err, rc = _run_parse_adversarial_findings(md)
        self.assertEqual(rc, 0, f"stderr={err!r}")
        findings = json.loads(out)
        self.assertEqual(findings[0]["file"], "general")
        self.assertEqual(findings[0]["line"], 0)

    def test_path_with_a_colon_and_no_trailing_digits_does_not_corrupt_the_path(self):
        """A file path containing a colon with NO trailing line number (e.g.
        a Windows drive-letter-style path, or any path with a colon that
        isn't a line-number separator) must not have its trailing segment
        misread as a line number by an unanchored split -- the anchored
        regex requires the trailing segment to be digits-only, so this
        shape simply does not match and falls back to (fileline, 0)
        rather than corrupting fname."""
        md = _write_markdown(self._tmpdir, (
            "[FINDING] CWE-22 | C:/weird/path:notanumber | severity: medium | "
            "reachable: no | tier: advisory | class: durable | title: odd path\n\n"
            "body text\n"
        ))
        out, err, rc = _run_parse_adversarial_findings(md)
        self.assertEqual(rc, 0, f"stderr={err!r}")
        findings = json.loads(out)
        self.assertEqual(findings[0]["file"], "C:/weird/path:notanumber")
        self.assertEqual(findings[0]["line"], 0)

    def test_trailing_colon_with_empty_segment_falls_back_safely(self):
        md = _write_markdown(self._tmpdir, (
            "[FINDING] CWE-22 | scripts/app.py: | severity: medium | "
            "reachable: no | tier: advisory | class: durable | title: trailing colon\n\n"
            "body text\n"
        ))
        out, err, rc = _run_parse_adversarial_findings(md)
        self.assertEqual(rc, 0, f"stderr={err!r}")
        findings = json.loads(out)
        self.assertEqual(findings[0]["file"], "scripts/app.py:")
        self.assertEqual(findings[0]["line"], 0)

    def test_multiple_colons_last_segment_is_the_line_number(self):
        """A path containing an earlier colon (unusual, but the regex's
        greedy `.+` for the file group must still capture the WHOLE prefix,
        not stop at the first colon) with a genuine trailing line number."""
        md = _write_markdown(self._tmpdir, (
            "[FINDING] CWE-22 | weird:path/app.py:99 | severity: medium | "
            "reachable: no | tier: advisory | class: durable | title: multi colon\n\n"
            "body text\n"
        ))
        out, err, rc = _run_parse_adversarial_findings(md)
        self.assertEqual(rc, 0, f"stderr={err!r}")
        findings = json.loads(out)
        self.assertEqual(findings[0]["file"], "weird:path/app.py")
        self.assertEqual(findings[0]["line"], 99)


class TestReadFailureSignalsOnReturnChannel(unittest.TestCase):
    """Class 2.7: a genuine read failure must signal on the return channel
    (nonzero exit, empty stdout), never silently produce the same "[]" a
    clean audit produces."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-paf-readfail-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_missing_file_exits_nonzero_with_empty_stdout(self):
        missing_path = os.path.join(self._tmpdir, "does-not-exist.md")
        out, err, rc = _run_parse_adversarial_findings(missing_path)
        self.assertNotEqual(
            rc, 0,
            f"a missing/unreadable file must exit NONZERO, distinguishable "
            f"from a readable-but-empty file (exit 0, stdout '[]') -- "
            f"stdout={out!r} stderr={err!r}",
        )
        self.assertEqual(
            out.strip(), "",
            f"stdout must be empty on a read failure, never the SAME '[]' "
            f"a genuinely clean audit produces -- out={out!r}",
        )

    def test_unreadable_file_permissions_exits_nonzero_with_empty_stdout(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores file permission bits")
        path = _write_markdown(self._tmpdir, "irrelevant content\n")
        os.chmod(path, 0)
        try:
            out, err, rc = _run_parse_adversarial_findings(path)
            self.assertNotEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
            self.assertEqual(out.strip(), "", f"out={out!r}")
        finally:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def test_readable_file_with_zero_findings_is_still_a_clean_exit_zero(self):
        """The positive control: a genuinely clean audit (readable file, no
        [FINDING] headers at all) must NOT be affected by the read-failure
        fix -- exit 0, stdout '[]', exactly as before."""
        path = _write_markdown(self._tmpdir, "Nothing exploitable found.\n")
        out, err, rc = _run_parse_adversarial_findings(path)
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertEqual(json.loads(out), [])


if __name__ == "__main__":
    unittest.main()
