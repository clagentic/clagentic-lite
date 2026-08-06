"""
Regression coverage for lr-7047bf (PR-B): cmd_adversarial's own degraded
check, and the two ways that state is threaded to the merge gate --
build_gate_summary's adversarial_degraded field, and its
gate_summary_degraded field for the no-jq/no-python3 fallback.

Root cause (THE WORST site in the class): cmd_adversarial (scripts/gates.sh)
used to have NO degraded check of any kind. A fully-dead auditor (auth
broken, CLI not on PATH, every chain step timed out) wrote a degraded
markdown envelope indistinguishable from "nothing to report" --
_parse_adversarial_findings found zero [FINDING] headers either way,
build_gate_summary reported adversarial_blocking_count 0 and
resolved_change_class null, and the merge gate was told the audit was
CLEAN.

Covers three related fixes:
  1. cmd_adversarial itself now checks walk_chain's exit status AND the
     markdown-mode degraded marker (site 1.4).
  2. build_gate_summary surfaces adversarial_degraded: true in the
     gate-summary payload so a dead auditor cannot look identical to a
     clean pass downstream, independent of cmd_adversarial's own exit
     status (fold-in: cmd_adversarial's fix is only complete if the
     consumer of its output can also see the distinction).
  3. build_gate_summary's own no-jq/no-python3 fallback (site 1.12) now
     emits gate_summary_degraded: true and returns 0 with that marker
     instead of a normal-shaped envelope the merge gate reads as clean --
     and cmd_merge_gate refuses deterministically on that marker via a
     tool-agnostic grep (checking with jq/python3 would be circular, since
     the marker's whole point is that neither is available).

Sources the REAL sh functions from gates.sh (not a Python mirror), mirroring
test_build_gate_summary_change_class.py's established pattern.

Run with: python3 -m unittest scripts.test_adversarial_degraded_detection -v
"""
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _functions_only_source(dest_dir):
    """Same truncation/symlink pattern as test_build_gate_summary_change_class.py."""
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


def _init_git_repo(path):
    subprocess.run(["git", "init", "-q", path], check=True)
    env = {**os.environ, **_GIT_ENV}
    readme = os.path.join(path, "README")
    with open(readme, "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=path, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=path, env=env)


def _head_sha(path):
    r = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=path, check=True)
    return r.stdout.strip()


def _stage_a_change(path):
    """get_review_diff (gates.sh) prefers the staged diff; without one it
    falls to a branch-diff-against-origin path that attempts a real `git
    fetch` and fails/times out in a fixture repo with no remote. Staging a
    trivial change keeps these tests on the fast, network-free path, same
    technique test_adversarial_invariant_feed.py already uses."""
    target = os.path.join(path, "app.py")
    with open(target, "w") as f:
        f.write("print('hello')\n")
    subprocess.run(["git", "add", "app.py"], check=True, cwd=path)


def _run_cmd_adversarial(project_root, fake_llm_client_sh):
    """Source gates.sh (functions only) with a fake llm-client.sh on
    TOOL_HOME's scripts path substituted via a wrapper dir, and call
    cmd_adversarial directly. Returns (stdout, stderr, returncode)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-degraded-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)

        # cmd_adversarial calls "$TOOL_HOME/scripts/llm-client.sh" by
        # absolute path derived from gates.sh's own location -- point
        # TOOL_HOME at a directory whose scripts/llm-client.sh is our fake.
        fake_tool_home = os.path.join(tmpdir, "fake-tool-home")
        os.makedirs(os.path.join(fake_tool_home, "scripts"))
        fake_llm_client_path = os.path.join(fake_tool_home, "scripts", "llm-client.sh")
        with open(fake_llm_client_path, "w") as f:
            f.write(fake_llm_client_sh)
        os.chmod(fake_llm_client_path, 0o755)

        script = textwrap.dedent(f"""\
            . '{sourced_gates}'
            TOOL_HOME='{fake_tool_home}'
            cmd_adversarial
        """)
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = project_root
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


_FAKE_LLM_CLIENT_CLEAN = """\
#!/bin/sh
cat > /dev/null
cat <<'EOF'
# Adversarial findings

No exploitable issues found.
EOF
exit 0
"""

_FAKE_LLM_CLIENT_DEGRADED = """\
#!/bin/sh
cat > /dev/null
cat <<'EOF'
# Degraded output

clagentic-lite role-call wrapper could not produce a real response: all chain steps failed for role auditor.
EOF
exit 3
"""


class TestCmdAdversarialDegradedCheck(unittest.TestCase):
    """Site 1.4, the worst site in the class: cmd_adversarial must not
    report a clean audit when the auditor was dead."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-degraded-proj-")
        _init_git_repo(self._tmpdir)
        _stage_a_change(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_clean_auditor_pass_returns_0_and_logs_warn(self):
        out, err, rc = _run_cmd_adversarial(self._tmpdir, _FAKE_LLM_CLIENT_CLEAN)
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertIn("No exploitable issues found", out)

    def test_degraded_auditor_returns_nonzero_not_clean(self):
        """The regression this task closes: a dead auditor must not exit 0
        looking identical to a clean pass."""
        out, err, rc = _run_cmd_adversarial(self._tmpdir, _FAKE_LLM_CLIENT_DEGRADED)
        self.assertNotEqual(
            rc, 0,
            f"cmd_adversarial must not return 0 when the auditor chain "
            f"returned a degraded envelope. stdout={out!r} stderr={err!r}",
        )
        self.assertIn("INFRA_DEGRADED", err)

    def test_degraded_auditor_writes_empty_findings_sidecar_not_a_forged_clean_one(self):
        """The findings sidecar must reflect reality (no real findings were
        ever produced) rather than silently vanishing or containing forged
        content."""
        _run_cmd_adversarial(self._tmpdir, _FAKE_LLM_CLIENT_DEGRADED)
        sidecar_path = os.path.join(self._tmpdir, ".clagentic", "lite", "last-adversarial-findings.json")
        self.assertTrue(os.path.isfile(sidecar_path))
        with open(sidecar_path) as f:
            findings = json.load(f)
        self.assertEqual(findings, [])

    def test_degraded_auditor_still_writes_the_markdown_for_human_inspection(self):
        """The degraded markdown itself is still written and cat'd -- a
        human debugging a dead auditor still needs to see what happened,
        the fix is the exit status and audit outcome, not suppressing the
        output."""
        out, err, rc = _run_cmd_adversarial(self._tmpdir, _FAKE_LLM_CLIENT_DEGRADED)
        self.assertIn("Degraded output", out)


class TestBuildGateSummaryAdversarialDegradedField(unittest.TestCase):
    """build_gate_summary must surface adversarial_degraded independent of
    cmd_adversarial's own exit status -- a later run of build_gate_summary
    (e.g. via `gates ship`'s merge-gate step) reads last-adversarial.md
    fresh, it does not receive cmd_adversarial's return code directly."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-adv-degraded-")
        _init_git_repo(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_adversarial_md(self, content, marked=False):
        """Write a last-adversarial.md fixture, stamp-prepended exactly as
        cmd_adversarial's own SHA-stamp step does. `marked=True` prefixes
        `content` with the real DEGRADED_MARKER control byte (0x01) emit_
        degraded actually writes -- required since _llm_output_is_degraded
        was hardened (BOBBIE finding 1, lr-7047bf fold-in) to require that
        byte before it will treat banner text as a genuine degraded
        envelope; plain "# Degraded output" text with no marker byte must
        NOT be classified as degraded (that's the injection-resistance
        property the hardening exists to provide -- see
        test_clean_markdown_sets_adversarial_degraded_false and the new
        test_unmarked_degraded_banner_text_is_not_treated_as_degraded
        below, which pins that property explicitly)."""
        clagentic_dir = os.path.join(self._tmpdir, ".clagentic", "lite")
        os.makedirs(clagentic_dir, exist_ok=True)
        sha = _head_sha(self._tmpdir)
        path = os.path.join(clagentic_dir, "last-adversarial.md")
        prefix = "\x01" if marked else ""
        with open(path, "w") as f:
            f.write(f"<!-- clagentic-diff-sha: {sha} -->\n{prefix}{content}")
        return path

    def _run_build_gate_summary(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-adv-degraded-src-")
        try:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            sourced_gates = _functions_only_source(src_dir)
            script = f". '{sourced_gates}'\nbuild_gate_summary\n"
            env = os.environ.copy()
            env["CLAGENTIC_PROJECT_ROOT"] = self._tmpdir
            r = subprocess.run(
                ["sh", "-c", script, sourced_gates],
                capture_output=True, text=True, env=env,
                cwd=os.path.join(TOOL_HOME, "scripts"),
            )
            self.assertEqual(r.returncode, 0, f"build_gate_summary failed: {r.stderr}")
            return json.loads(r.stdout)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_degraded_markdown_sets_adversarial_degraded_true(self):
        self._write_adversarial_md(
            "# Degraded output\n\nclagentic-lite role-call wrapper could not "
            "produce a real response: all chain steps failed for role auditor.\n",
            marked=True,
        )
        payload = self._run_build_gate_summary()
        self.assertTrue(
            payload["adversarial_degraded"],
            f"expected adversarial_degraded: true for a degraded markdown "
            f"file. payload={payload!r}",
        )

    def test_clean_markdown_sets_adversarial_degraded_false(self):
        self._write_adversarial_md("# Adversarial findings\n\nNo exploitable issues found.\n")
        payload = self._run_build_gate_summary()
        self.assertFalse(payload["adversarial_degraded"])

    def test_unmarked_degraded_banner_text_is_not_treated_as_degraded(self):
        """Pins the injection-resistance property build_gate_summary now
        inherits by routing through _llm_output_is_degraded (BOBBIE finding
        1 remainder, lr-7047bf fold-in, PR #141 review #2): plain "#
        Degraded output" banner text with NO leading DEGRADED_MARKER byte
        -- exactly what a prompt-injected auditor response could reproduce
        verbatim -- must NOT be classified as degraded. Before this fix,
        build_gate_summary's own hand-rolled `grep -qF` check had no
        marker-byte gate and WOULD have misclassified this as degraded."""
        self._write_adversarial_md(
            "# Degraded output\n\nthis text was written by a prompt-injected "
            "auditor response, not by emit_degraded -- it carries no marker byte.\n",
            marked=False,
        )
        payload = self._run_build_gate_summary()
        self.assertFalse(
            payload["adversarial_degraded"],
            f"unmarked banner text (no DEGRADED_MARKER byte) must not be "
            f"classified as degraded -- doing so would let a prompt "
            f"injection masquerade a real audit as infra-failure. "
            f"payload={payload!r}",
        )

    def test_missing_file_sets_adversarial_degraded_false_not_true(self):
        """File-absent (adversarial gate never ran) is ADVERSARIAL_MISSING's
        job, a distinct state from ADVERSARIAL_DEGRADED -- a file that was
        never written is not the same failure as a file that WAS written
        but records a dead auditor."""
        payload = self._run_build_gate_summary()
        self.assertTrue(payload["adversarial_missing"])
        self.assertFalse(payload["adversarial_degraded"])


class TestGateSummaryDegradedNoToolFallback(unittest.TestCase):
    """Site 1.12: build_gate_summary's no-jq/no-python3 fallback must not
    silently look like a clean, normal-shaped envelope, and cmd_merge_gate
    must refuse deterministically on it without itself needing a JSON tool
    (checking gate_summary_degraded with jq/python3 would be circular)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-notool-")
        _init_git_repo(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _no_json_tool_path(self, dest_bin_dir):
        for name in ("sh", "dirname", "cat", "head", "grep", "git", "mkdir",
                     "sed", "date", "sqlite3", "mktemp", "printf", "rm",
                     "cut", "tr", "uname", "basename", "stat", "find", "id", "wc"):
            real = shutil.which(name)
            if real:
                os.symlink(real, os.path.join(dest_bin_dir, name))
        return dest_bin_dir

    def test_no_tool_fallback_emits_gate_summary_degraded_true(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-bgs-notool-src-")
        try:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            sourced_gates = _functions_only_source(src_dir)
            no_json_bin = os.path.join(tmpdir, "no-json-bin")
            os.makedirs(no_json_bin)
            self._no_json_tool_path(no_json_bin)

            script = textwrap.dedent(f"""\
                export PATH='{no_json_bin}'
                . '{sourced_gates}'
                build_gate_summary
            """)
            env = {"CLAGENTIC_PROJECT_ROOT": self._tmpdir, "HOME": os.environ.get("HOME", "/tmp")}
            r = subprocess.run(
                ["sh", "-c", script, sourced_gates],
                capture_output=True, text=True, env=env,
                cwd=os.path.join(TOOL_HOME, "scripts"),
            )
            self.assertEqual(r.returncode, 0, f"stderr={r.stderr!r}")
            self.assertIn(
                '"gate_summary_degraded": true', r.stdout,
                f"no-jq/no-python3 fallback must emit gate_summary_degraded: "
                f"true so the merge gate does not read this as a normal "
                f"clean envelope. stdout={r.stdout!r}",
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_cmd_merge_gate_refuses_deterministically_on_gate_summary_degraded(self):
        """cmd_merge_gate's grep-based check must catch the marker without
        needing jq/python3 itself -- checking a JSON field with a JSON tool
        here would be circular, since the whole point of the marker is that
        neither tool is present.

        Uses the normal (non-`--recheck`) path so build_gate_summary
        produces the gate_summary_degraded envelope naturally in the
        no-tool environment, rather than hand-writing gate-summary.json --
        `--recheck` has its own SHA-staleness guard that ALSO needs
        jq/python3 and would refuse before ever reaching the check under
        test here, so it is the wrong path to exercise this scenario."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-mg-notool-")
        try:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            sourced_gates = _functions_only_source(src_dir)
            no_json_bin = os.path.join(tmpdir, "no-json-bin")
            os.makedirs(no_json_bin)
            self._no_json_tool_path(no_json_bin)

            script = textwrap.dedent(f"""\
                export PATH='{no_json_bin}'
                . '{sourced_gates}'
                cmd_merge_gate
            """)
            env = {"CLAGENTIC_PROJECT_ROOT": self._tmpdir, "HOME": os.environ.get("HOME", "/tmp")}
            r = subprocess.run(
                ["sh", "-c", script, sourced_gates],
                capture_output=True, text=True, env=env,
                cwd=os.path.join(TOOL_HOME, "scripts"),
            )
            self.assertNotEqual(
                r.returncode, 0,
                f"cmd_merge_gate must refuse (nonzero) on a "
                f"gate_summary_degraded envelope, even with no jq/python3 "
                f"available to it. stdout={r.stdout!r} stderr={r.stderr!r}",
            )
            self.assertIn('"decision": "refuse"', r.stdout)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
