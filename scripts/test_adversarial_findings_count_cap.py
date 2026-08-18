"""
Regression coverage for lr-33958f (PR-C): _parse_adversarial_findings'
output is COUNT-BOUNDED AT EMISSION, closing the gap the foundry ranked as
the most likely source of the next unreported bug.

ROOT CAUSE: _parse_adversarial_findings (scripts/gates.sh) built its
findings array with no count bound of its own, and that array is embedded
TWICE into the merge-gate system prompt (adversarial_findings and
adversarial_findings_fenced, build_gate_summary) -- an unusually chatty (or
prompt-injected) Auditor could grow that prompt without limit. This is the
sibling repo's seven-occurrence verdict-fence class, restated as an
EMISSION-side cap (_llm_json_array_cap, scripts/platform.sh) rather than a
parse-time presence check -- constraining the COUNT, not merely the
presence, per INV-2 clause (ii).

Two layers tested here:
  1. _llm_json_array_cap directly (platform.sh) -- the generic, reusable
     truncate-to-first-N helper.
  2. cmd_adversarial's own emission site (gates.sh) -- the sidecar file
     (last-adversarial-findings.json) actually written to disk must never
     exceed the configured cap, end to end through the real function.

Sources the REAL sh functions (not a Python mirror), mirroring
test_adversarial_findings_sanitize.py's established pattern.

Run with: python3 -m unittest scripts.test_adversarial_findings_count_cap -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, PLATFORM_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _run_platform_function(call_line):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-cap-")
    try:
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            {call_line}
        """)
        r = subprocess.run(
            ["sh", "-c", script, PLATFORM_SH],
            capture_output=True, text=True, cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestLlmJsonArrayCapDirect(unittest.TestCase):
    """_llm_json_array_cap (platform.sh) -- the generic truncate-to-first-N
    helper, exercised directly."""

    def test_truncates_to_max(self):
        arr = json.dumps([{"n": i} for i in range(10)])
        out, err, rc = _run_platform_function(
            f"""_llm_json_array_cap '{arr}' 3"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        capped = json.loads(out)
        self.assertEqual(len(capped), 3, f"out={out!r}")
        self.assertEqual([x["n"] for x in capped], [0, 1, 2],
                          "truncation must keep the FIRST N entries, stable "
                          "and deterministic, not an arbitrary subset")

    def test_array_under_max_is_unchanged(self):
        arr = json.dumps([{"n": 1}, {"n": 2}])
        out, err, rc = _run_platform_function(f"""_llm_json_array_cap '{arr}' 200""")
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertEqual(json.loads(out), [{"n": 1}, {"n": 2}])

    def test_default_max_is_200_when_arg_omitted(self):
        arr = json.dumps([{"n": i} for i in range(250)])
        out, err, rc = _run_platform_function(f"""_llm_json_array_cap '{arr}'""")
        self.assertEqual(rc, 0, f"stderr={err!r}")
        capped = json.loads(out)
        self.assertEqual(len(capped), 200, f"len={len(capped)}")

    def test_non_array_fails_open_unchanged(self):
        out, err, rc = _run_platform_function(
            """_llm_json_array_cap '{"not":"an array"}' 5"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertEqual(json.loads(out), {"not": "an array"})

    def test_malformed_json_fails_open_unchanged(self):
        out, err, rc = _run_platform_function(
            """_llm_json_array_cap 'not json at all' 5"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertEqual(out, "not json at all")


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


def _run_cmd_adversarial(project_root, fake_llm_client_sh, extra_env=None):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-cap-")
    try:
        sourced_gates = GATES_SH

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
        if extra_env:
            env.update(extra_env)
        env.update(source_env(gates=True))
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _many_findings_markdown(n):
    """Build a fake adversarial markdown response with N distinct
    [FINDING] headers, one per line/CWE so each is a genuinely distinct
    finding (not deduped by any downstream logic keyed on content)."""
    lines = ["#!/bin/sh", "cat > /dev/null", "cat <<'EOF'"]
    for i in range(n):
        lines.append(
            f"[FINDING] CWE-{100+i} | app/x.py:{i+1} | severity: low | "
            f"reachable: no | tier: advisory | class: durable | title: finding {i}"
        )
        lines.append("")
        lines.append(f"finding number {i}")
        lines.append("")
    lines.append("EOF")
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


class TestCmdAdversarialFindingsSidecarCountBoundedAtEmission(unittest.TestCase):
    """cmd_adversarial's own emission site: the on-disk sidecar
    (last-adversarial-findings.json), the exact array embedded TWICE into
    the merge-gate prompt, must never exceed the configured cap."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-adv-cap-proj-")
        _init_git_repo(self._tmpdir)
        _stage_a_change(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_sidecar_capped_at_configured_max(self):
        fake = _many_findings_markdown(30)
        out, err, rc = _run_cmd_adversarial(
            self._tmpdir, fake,
            extra_env={"CLAGENTIC_ADVERSARIAL_FINDINGS_MAX": "5"},
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        sidecar_path = os.path.join(self._tmpdir, ".clagentic", "lite", "last-adversarial-findings.json")
        with open(sidecar_path) as f:
            findings = json.load(f)
        self.assertEqual(
            len(findings), 5,
            f"the auditor emitted 30 [FINDING] headers but the sidecar "
            f"must be capped at the configured max (5) -- this is the "
            f"array embedded TWICE, uncapped, into the merge-gate prompt "
            f"before this fix. findings={findings!r}",
        )

    def test_sidecar_under_cap_unaffected(self):
        fake = _many_findings_markdown(3)
        out, err, rc = _run_cmd_adversarial(
            self._tmpdir, fake,
            extra_env={"CLAGENTIC_ADVERSARIAL_FINDINGS_MAX": "200"},
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        sidecar_path = os.path.join(self._tmpdir, ".clagentic", "lite", "last-adversarial-findings.json")
        with open(sidecar_path) as f:
            findings = json.load(f)
        self.assertEqual(len(findings), 3, f"findings={findings!r}")

    def test_default_cap_is_200_when_env_var_unset(self):
        fake = _many_findings_markdown(3)
        out, err, rc = _run_cmd_adversarial(self._tmpdir, fake)
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        sidecar_path = os.path.join(self._tmpdir, ".clagentic", "lite", "last-adversarial-findings.json")
        with open(sidecar_path) as f:
            findings = json.load(f)
        # 3 findings, well under the default 200 cap -- all must survive.
        self.assertEqual(len(findings), 3, f"findings={findings!r}")


if __name__ == "__main__":
    unittest.main()
