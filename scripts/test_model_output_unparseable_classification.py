"""
Regression coverage for lr-33958f (PR-C): the distinct MODEL_OUTPUT_UNPARSEABLE
classification, separate from INFRA_DEGRADED, for cmd_review, cmd_adversarial,
and cmd_merge_gate (scripts/gates.sh).

THE MISDIRECTION THIS CLOSES (the fix the foundry insisted on hardest):
before this task, ANY degraded chain -- whether the CLI never even ran
(misconfigured/auth-broken/network-out) or the model ran successfully and
returned unparseable output -- collapsed to the identical INFRA_DEGRADED
message: "Check LLM CLI config/auth." A model that ran, spent tokens, and
returned prose is not an infrastructure problem; sending the operator to
check CLI config/auth for a problem in neither is the exact misdirection
the foundry named as a plausible contributor to two real misdiagnoses in
the original investigation. Fail-closed either way (an unparseable review
still never passes the gate) -- but the message must now name itself
correctly and its remediation hint must point at reviewer OUTPUT SHAPE.

Sources the REAL sh functions from gates.sh via a fake llm-client.sh
substituted at TOOL_HOME, mirroring test_adversarial_degraded_detection.py's
established pattern (same helpers, reused not reimplemented).

Run with: python3 -m unittest scripts.test_model_output_unparseable_classification -v
"""
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
    """Identical truncation/symlink pattern to
    test_adversarial_degraded_detection.py -- reused, not reimplemented."""
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


def _init_git_repo(path):
    subprocess.run(["git", "init", "-q", path], check=True)
    env = {**os.environ, **_GIT_ENV}
    readme = os.path.join(path, "README")
    with open(readme, "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "add", "README"], check=True, cwd=path, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], check=True, cwd=path, env=env)


def _stage_a_change(path):
    target = os.path.join(path, "app.py")
    with open(target, "w") as f:
        f.write("print('hello')\n")
    subprocess.run(["git", "add", "app.py"], check=True, cwd=path)


def _run_gates_cmd(project_root, fake_llm_client_sh, cmd):
    """Source gates.sh (functions only) with a fake llm-client.sh
    substituted at TOOL_HOME, and invoke CMD directly. Returns
    (stdout, stderr, returncode)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-unparseable-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)

        fake_tool_home = os.path.join(tmpdir, "fake-tool-home")
        os.makedirs(os.path.join(fake_tool_home, "scripts"))
        fake_llm_client_path = os.path.join(fake_tool_home, "scripts", "llm-client.sh")
        with open(fake_llm_client_path, "w") as f:
            f.write(fake_llm_client_sh)
        os.chmod(fake_llm_client_path, 0o755)

        script = textwrap.dedent(f"""\
            . '{sourced_gates}'
            TOOL_HOME='{fake_tool_home}'
            {cmd}
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


# Fake llm-client.sh that models a chain whose model ran successfully
# (auth/network fine, tokens spent) but returned no parseable output --
# walk_chain's own status-4/cause-"unwrap" degraded envelope.
_FAKE_LLM_CLIENT_UNWRAP_DEGRADED_JSON = """\
#!/bin/sh
cat > /dev/null
cat <<'EOF'
{
  "degraded": true,
  "cause": "unwrap",
  "summary": "[clagentic-lite degraded] model output could not be reduced to parseable role-shaped JSON for role reviewer (auth/invocation succeeded on every attempt \\u2014 see reviewer output shape, not CLI config)",
  "checked": [],
  "findings": []
}
EOF
exit 4
"""

# Fake llm-client.sh that models the pre-existing infra-cause failure (no
# chain configured / every invocation failed) -- the negative control.
_FAKE_LLM_CLIENT_INFRA_DEGRADED_JSON = """\
#!/bin/sh
cat > /dev/null
cat <<'EOF'
{
  "degraded": true,
  "cause": "infra",
  "summary": "[clagentic-lite degraded] all chain steps failed for role reviewer",
  "checked": [],
  "findings": []
}
EOF
exit 3
"""

_FAKE_LLM_CLIENT_UNWRAP_DEGRADED_MARKDOWN = """\
#!/bin/sh
cat > /dev/null
printf '\\001# Degraded output\\n\\nclagentic-lite role-call wrapper could not produce a real response: model output could not be reduced to parseable role-shaped JSON for role auditor.\\n(cause: unwrap)\\n'
exit 4
"""

_FAKE_LLM_CLIENT_INFRA_DEGRADED_MARKDOWN = """\
#!/bin/sh
cat > /dev/null
printf '\\001# Degraded output\\n\\nclagentic-lite role-call wrapper could not produce a real response: all chain steps failed for role auditor.\\n(cause: infra)\\n'
exit 3
"""


class TestCmdReviewDistinguishesModelOutputUnparseableFromInfraDegraded(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-unparseable-review-")
        _init_git_repo(self._tmpdir)
        _stage_a_change(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_unwrap_cause_reports_model_output_unparseable_not_infra_degraded(self):
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_UNWRAP_DEGRADED_JSON, "cmd_review")
        self.assertEqual(rc, 2, f"still exit 2 (fail-closed either way). stderr={err!r}")
        self.assertIn(
            "MODEL_OUTPUT_UNPARSEABLE", err,
            f"an unwrap-cause degraded reviewer chain must report "
            f"MODEL_OUTPUT_UNPARSEABLE, not the generic INFRA_DEGRADED "
            f"label. stderr={err!r}",
        )
        self.assertNotIn(
            "INFRA_DEGRADED", err,
            f"must NOT also claim INFRA_DEGRADED -- the two are mutually "
            f"exclusive classifications for the same event. stderr={err!r}",
        )

    def test_unwrap_cause_remediation_hint_points_at_output_shape_not_cli_config(self):
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_UNWRAP_DEGRADED_JSON, "cmd_review")
        self.assertIn(
            "OUTPUT SHAPE", err,
            f"remediation hint must point at reviewer output shape for the "
            f"unwrap cause. stderr={err!r}",
        )
        self.assertNotIn(
            "Check LLM CLI config/auth.", err,
            f"the unwrap cause must NOT carry the CLI-config/auth "
            f"remediation hint -- that is exactly the misdirection the "
            f"foundry named. stderr={err!r}",
        )

    def test_infra_cause_still_reports_infra_degraded_unaffected(self):
        """Negative control: the pre-existing infra-cause path is
        unaffected by this task and must still say INFRA_DEGRADED with the
        CLI-config/auth hint."""
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_INFRA_DEGRADED_JSON, "cmd_review")
        self.assertEqual(rc, 2, f"stderr={err!r}")
        self.assertIn("INFRA_DEGRADED", err)
        self.assertIn("Check LLM CLI config/auth.", err)
        self.assertNotIn("MODEL_OUTPUT_UNPARSEABLE", err)

    def test_unwrap_cause_still_fails_closed_never_passes_the_gate(self):
        """Fail-closed either way -- an unparseable review must never pass
        the gate, regardless of which cause it is."""
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_UNWRAP_DEGRADED_JSON, "cmd_review")
        self.assertNotEqual(rc, 0, f"must never return 0 (pass). stdout={out!r} stderr={err!r}")


class TestCmdAdversarialDistinguishesModelOutputUnparseableFromInfraDegraded(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-unparseable-adv-")
        _init_git_repo(self._tmpdir)
        _stage_a_change(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_unwrap_cause_reports_model_output_unparseable(self):
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_UNWRAP_DEGRADED_MARKDOWN, "cmd_adversarial")
        self.assertNotEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("MODEL_OUTPUT_UNPARSEABLE", err)
        self.assertNotIn("INFRA_DEGRADED", err)

    def test_infra_cause_still_reports_infra_degraded(self):
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_INFRA_DEGRADED_MARKDOWN, "cmd_adversarial")
        self.assertNotEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("INFRA_DEGRADED", err)
        self.assertNotIn("MODEL_OUTPUT_UNPARSEABLE", err)


_FAKE_LLM_CLIENT_CLEAN_REVIEW = """\
#!/bin/sh
cat > /dev/null
cat <<'EOF'
{"summary": "clean", "checked": ["security"], "findings": []}
EOF
exit 0
"""


class TestCmdMergeGateDistinguishesModelOutputUnparseableFromInfraDegraded(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-unparseable-mg-")
        _init_git_repo(self._tmpdir)
        _stage_a_change(self._tmpdir)
        # cmd_merge_gate calls build_gate_summary first, which requires an
        # ANCHORED ledger pass (lr-01ae73) as well as a fresh last-review.json
        # stamp to avoid the stale/absent-review short circuits swallowing
        # this test's fake merge-gate call. Seeds via a REAL cmd_review run
        # (PEACHES/coordinator finding on PR #162, comment 5260223912) rather
        # than hand-writing last-review.json directly -- since lr-01ae73
        # removed the merge-gate's ledger bootstrap exemption, a hand-written
        # last-review.json with no ledger entry no longer passes at all.
        self._seed_anchored_review_pass()

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _seed_anchored_review_pass(self):
        """Run the real cmd_review (clean stub envelope) against
        self._tmpdir via the full gates.sh subcommand dispatcher so
        build_gate_summary's ledger-anchored check finds a genuine passing
        verdict at current HEAD. The staged change from setUp (_stage_a_change)
        is what cmd_review reviews; it is left staged afterward (uncommitted),
        matching this class's own fake-merge-gate calls, which never commit
        either -- HEAD stays exactly the SHA the ledger entry is anchored to."""
        fake_tool_home = tempfile.mkdtemp(prefix="clagentic-test-unparseable-mg-review-home-")
        try:
            scripts_dir = os.path.join(fake_tool_home, "scripts")
            os.makedirs(scripts_dir)
            real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
            for fname in os.listdir(real_scripts_dir):
                if fname.endswith(".sh") and fname != "llm-client.sh":
                    os.symlink(os.path.join(real_scripts_dir, fname), os.path.join(scripts_dir, fname))
            real_share = os.path.join(TOOL_HOME, "share")
            if os.path.isdir(real_share):
                os.symlink(real_share, os.path.join(fake_tool_home, "share"))
            stub_path = os.path.join(scripts_dir, "llm-client.sh")
            with open(stub_path, "w") as f:
                f.write(_FAKE_LLM_CLIENT_CLEAN_REVIEW)
            os.chmod(stub_path, 0o755)

            env = os.environ.copy()
            env["CLAGENTIC_PROJECT_ROOT"] = self._tmpdir
            env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
            env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
            env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
            r = subprocess.run(
                ["sh", os.path.join(scripts_dir, "gates.sh"), "review"],
                capture_output=True, text=True, env=env, cwd=self._tmpdir,
            )
            self.assertEqual(r.returncode, 0, f"seed cmd_review failed: {r.stderr}")
        finally:
            shutil.rmtree(fake_tool_home, ignore_errors=True)

    def test_unwrap_cause_reports_model_output_unparseable(self):
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_UNWRAP_DEGRADED_JSON, "cmd_merge_gate")
        self.assertNotEqual(
            rc, 0,
            f"a degraded merge-gate decision must block by default. "
            f"stdout={out!r} stderr={err!r}",
        )
        self.assertIn("MODEL_OUTPUT_UNPARSEABLE", err)
        self.assertNotIn("INFRA_DEGRADED", err)

    def test_infra_cause_still_reports_infra_degraded(self):
        out, err, rc = _run_gates_cmd(self._tmpdir, _FAKE_LLM_CLIENT_INFRA_DEGRADED_JSON, "cmd_merge_gate")
        self.assertNotEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("INFRA_DEGRADED", err)
        self.assertNotIn("MODEL_OUTPUT_UNPARSEABLE", err)


if __name__ == "__main__":
    unittest.main()
