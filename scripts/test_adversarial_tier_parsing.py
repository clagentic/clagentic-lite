"""
Regression tests for lr-e2b975: reachability + advisory/blocking split.

_parse_adversarial_findings (scripts/gates.sh) gained two new fields,
`reachable` and `tier`, parsed from the [FINDING] header emitted by
ds_adversarial_prompt (scripts/llm-client.sh). This is the mechanical gate
plumbing the merge-gate LLM relies on to know which adversarial findings are
refusal-eligible: only reachable, high/critical findings can ever be
`tier: blocking`; everything else is `tier: advisory` and must never gate
`/ship` on its own, though it must remain fully visible in the parsed output
(never suppressed).

These tests source the ACTUAL sh function from gates.sh (not a Python
reimplementation) so a regression in the real parser is caught here, not
just in a mirror of its intended behavior.

Run with: python3 -m unittest scripts.test_adversarial_tier_parsing -v
"""
import json
import os
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")


def _functions_only_source(dest_dir):
    """Copy gates.sh into dest_dir with its trailing subcommand dispatch
    (`case "${1:-}" in init) ... esac`) stripped off, mirroring the pattern
    test_llm_client_sh.py uses for llm-client.sh. Sourcing the real file
    unmodified would execute cmd_init/cmd_review/etc based on whatever $1
    happens to be in the sourcing shell and call `exit`.

    gates.sh unconditionally self-sources platform.sh and review-merge.sh
    relative to its own `dirname "$0")` at the top of the file (before any
    function definitions), so both real files are symlinked alongside the
    truncated copy — otherwise sourcing fails before _parse_adversarial_findings
    is even defined.
    """
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


def _parse_findings(markdown_text):
    """Source gates.sh (functions only) and call _parse_adversarial_findings
    directly against a markdown fixture. Returns the parsed findings list.

    gates.sh sources platform.sh and review-merge.sh unconditionally at the
    top (before any function definitions), so both must be reachable at
    their real relative path — running from TOOL_HOME/scripts satisfies
    `. "$(dirname "$0")/platform.sh"` without needing to symlink a whole
    fake tool tree (unlike the merge-gate --recheck tests, which fake
    TOOL_HOME to substitute a stub llm-client.sh; this test never invokes
    an LLM at all).
    """
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-tier-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)

        md_file = os.path.join(tmpdir, "adversarial.md")
        with open(md_file, "w") as f:
            f.write(markdown_text)

        out_file = os.path.join(tmpdir, "out.json")
        script = textwrap.dedent(f"""\
            . '{sourced_gates}'
            _parse_adversarial_findings '{md_file}' > '{out_file}'
        """)
        # Pass sourced_gates as $0 so gates.sh's own
        # `. "$(dirname "$0")/platform.sh"` self-source resolves — under
        # plain `sh -c script`, $0 would be "sh".
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True,
            text=True,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        assert r.returncode == 0, f"sourcing/parsing failed: {r.stderr}"
        with open(out_file) as f:
            raw = f.read()
        return json.loads(raw)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestReachableTierParsing(unittest.TestCase):
    """New-format headers: reachable/tier fields parse as stated."""

    def test_reachable_yes_high_severity_is_blocking(self):
        md = (
            "[FINDING] CWE-78 | scripts/x.sh:10 | severity: high | "
            "reachable: yes | tier: blocking | title: Command injection via unsanitized arg\n\n"
            "Prose body.\n"
        )
        findings = _parse_findings(md)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["reachable"], "yes")
        self.assertEqual(f["tier"], "blocking")
        self.assertEqual(f["category"], "CWE-78")
        self.assertEqual(f["file"], "scripts/x.sh")
        self.assertEqual(f["line"], 10)

    def test_reachable_no_forces_advisory_even_if_model_said_blocking(self):
        """Reachability is the mechanical precondition for blocking — the
        parser must not trust a model that states tier: blocking without
        reachable: yes (miscalibration, not malice, is the expected failure
        mode this guards)."""
        md = (
            "[FINDING] CWE-89 | app/db.py:42 | severity: critical | "
            "reachable: no | tier: blocking | title: SQL injection in dead helper\n\n"
            "Prose body.\n"
        )
        findings = _parse_findings(md)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["reachable"], "no")
        self.assertEqual(f["tier"], "advisory",
                          "reachable: no must force tier: advisory regardless of the model's stated tier")

    def test_low_severity_with_blocking_tier_field_still_parses_as_stated(self):
        """The parser does not re-derive severity-vs-tier consistency beyond
        the reachability force-correction — a low-severity reachable finding
        that a (miscalibrated) model tagged blocking is parsed as given. The
        prompt-level instruction (not the parser) is what constrains severity
        eligibility; the parser's only mechanical override is reachability."""
        md = (
            "[FINDING] CWE-1004 | app/cookie.py:5 | severity: low | "
            "reachable: yes | tier: blocking | title: Missing cookie flag\n\n"
            "Prose body.\n"
        )
        findings = _parse_findings(md)
        self.assertEqual(findings[0]["tier"], "blocking")

    def test_advisory_finding_still_present_in_output_never_dropped(self):
        """Threshold, not suppression: an advisory finding must appear in the
        parsed output exactly like a blocking one — only the tier differs."""
        md = (
            "[FINDING] CWE-770 | scripts/y.sh:3 | severity: medium | "
            "reachable: no | tier: advisory | title: Unbounded read in fixture loader\n\n"
            "Prose body.\n"
        )
        findings = _parse_findings(md)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tier"], "advisory")
        self.assertEqual(findings[0]["message"], "Unbounded read in fixture loader")


class TestBackwardCompatibleOldHeaderFormat(unittest.TestCase):
    """Pre-lr-e2b975 headers (no reachable/tier fields) must still parse —
    a model that has not picked up the new prompt instructions, or an old
    cached prompt in a chain fallback step, must not break the pipeline."""

    def test_old_four_field_header_defaults_to_advisory(self):
        md = (
            "[FINDING] CWE-798 | scripts/z.sh:7 | severity: high | "
            "title: Hardcoded credential\n\n"
            "Prose body.\n"
        )
        findings = _parse_findings(md)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["reachable"], "no",
                          "absent reachable field must default to 'no', not be left unset")
        self.assertEqual(f["tier"], "advisory",
                          "absent tier field must default to advisory — a parser gap can only under-block")
        self.assertEqual(f["message"], "Hardcoded credential")


class TestMixedFindingsAndOrdering(unittest.TestCase):
    def test_multiple_findings_mixed_tiers_all_present(self):
        md = (
            "[FINDING] CWE-78 | a.sh:1 | severity: critical | reachable: yes | tier: blocking | title: RCE\n\n"
            "Body one.\n\n"
            "[FINDING] CWE-330 | b.py:2 | severity: low | reachable: no | tier: advisory | title: Weak randomness\n\n"
            "Body two.\n"
        )
        findings = _parse_findings(md)
        self.assertEqual(len(findings), 2)
        tiers = sorted(f["tier"] for f in findings)
        self.assertEqual(tiers, ["advisory", "blocking"])

    def test_no_findings_in_clean_pass_is_empty_list(self):
        md = "No exploitable surfaces found. Considered: input parsing, auth checks.\n"
        findings = _parse_findings(md)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
