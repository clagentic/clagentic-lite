"""
Regression coverage for lr-33958f (PR-C fold-in, BOBBIE PR #142 review 2:
bobbie.sast.unbounded-truncation-drops-severity).

ROOT CAUSE: cmd_adversarial's count cap (_llm_json_array_cap, platform.sh)
truncated _parse_adversarial_findings' array to the first N entries IN PARSE
ORDER, with no severity/tier-aware sort before the cut.
_parse_adversarial_findings emits findings in the order the Auditor's
markdown lists them -- ATTACKER-INFLUENCEABLE via prompt injection in the
diff under review. A late-emitted tier:"blocking" finding could be silently
dropped while earlier tier:"advisory" findings survive into the merge-gate
prompt (which embeds the array twice) -- a hole the count cap itself
introduced.

THE FIX: _adversarial_findings_sort_blocking_first (platform.sh) sorts
tier:"blocking" findings first, severity descending within each tier,
BEFORE _llm_json_array_cap ever runs (cmd_adversarial, gates.sh) -- so the
cap can only ever drop the least-severe, non-blocking tail. Additionally, a
truncated audit must never be silently presented as complete: cmd_adversarial
now persists a dropped-count sidecar (last-adversarial-findings-meta.json)
that build_gate_summary reads back and surfaces as
"adversarial_findings_dropped_count" in the merge-gate payload.

Two layers tested here, mirroring test_adversarial_findings_count_cap.py's
established pattern:
  1. _adversarial_findings_sort_blocking_first directly (platform.sh).
  2. cmd_adversarial's end-to-end emission: a chatty auditor whose LATE
     finding is the only tier:"blocking" one must still have that finding
     survive the cap, and the dropped-count sidecar must record how many
     findings were truncated.

Run with: python3 -m unittest scripts.test_adversarial_findings_severity_sort_before_cap -v
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
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def _functions_only_source_gates(dest_dir):
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


def _run_platform_function(call_line):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-sort-")
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


class TestSortBlockingFirstDirect(unittest.TestCase):
    """_adversarial_findings_sort_blocking_first (platform.sh), exercised
    directly against synthetic finding objects."""

    def test_blocking_sorts_before_advisory_regardless_of_original_position(self):
        arr = json.dumps([
            {"id": "advisory-1", "severity": "low", "tier": "advisory"},
            {"id": "advisory-2", "severity": "medium", "tier": "advisory"},
            {"id": "late-blocking", "severity": "critical", "tier": "blocking"},
        ])
        out, err, rc = _run_platform_function(
            f"""_adversarial_findings_sort_blocking_first '{arr}'"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        sorted_arr = json.loads(out)
        self.assertEqual(
            sorted_arr[0]["id"], "late-blocking",
            f"the tier:blocking finding must sort FIRST even though it was "
            f"emitted last in parse order -- this is what stops the count "
            f"cap from dropping it while earlier advisory findings survive. "
            f"sorted_arr={sorted_arr!r}",
        )

    def test_severity_descends_within_the_same_tier(self):
        arr = json.dumps([
            {"id": "low", "severity": "low", "tier": "advisory"},
            {"id": "critical", "severity": "critical", "tier": "advisory"},
            {"id": "medium", "severity": "medium", "tier": "advisory"},
            {"id": "high", "severity": "high", "tier": "advisory"},
        ])
        out, err, rc = _run_platform_function(
            f"""_adversarial_findings_sort_blocking_first '{arr}'"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        ids = [x["id"] for x in json.loads(out)]
        self.assertEqual(ids, ["critical", "high", "medium", "low"], f"ids={ids!r}")

    def test_stable_within_identical_tier_and_severity(self):
        arr = json.dumps([
            {"id": "first", "severity": "low", "tier": "advisory"},
            {"id": "second", "severity": "low", "tier": "advisory"},
            {"id": "third", "severity": "low", "tier": "advisory"},
        ])
        out, err, rc = _run_platform_function(
            f"""_adversarial_findings_sort_blocking_first '{arr}'"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        ids = [x["id"] for x in json.loads(out)]
        self.assertEqual(
            ids, ["first", "second", "third"],
            "identically-ranked findings must keep their original relative "
            "(parse) order -- stable sort, matching _llm_json_array_cap's "
            "own stable-truncation contract one step downstream",
        )

    def test_non_array_fails_open_unchanged(self):
        out, err, rc = _run_platform_function(
            """_adversarial_findings_sort_blocking_first '{"not":"an array"}'"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertEqual(json.loads(out), {"not": "an array"})

    def test_malformed_json_fails_open_unchanged(self):
        out, err, rc = _run_platform_function(
            """_adversarial_findings_sort_blocking_first 'not json at all'"""
        )
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertEqual(out, "not json at all")


def _init_git_repo(path):
    subprocess.run(["git", "init", "-q", path], check=True)
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
           "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com"}
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
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-sort-cap-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source_gates(src_dir)

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
        r = subprocess.run(
            ["sh", "-c", script, sourced_gates],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(TOOL_HOME, "scripts"),
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _markdown_with_late_blocking_finding(n_advisory):
    """N low-severity advisory findings, followed by ONE late,
    high-severity, reachable:yes finding that mechanically resolves to
    tier:blocking (the security-floor clamp in _parse_adversarial_findings)
    -- simulating a chatty/prompt-injected auditor whose one real finding
    is buried after many low-value ones."""
    lines = ["#!/bin/sh", "cat > /dev/null", "cat <<'EOF'"]
    for i in range(n_advisory):
        lines.append(
            f"[FINDING] CWE-{100+i} | app/x.py:{i+1} | severity: low | "
            f"reachable: no | tier: advisory | class: durable | title: noise finding {i}"
        )
        lines.append("")
        lines.append(f"low-value finding number {i}")
        lines.append("")
    lines.append(
        "[FINDING] CWE-89 | app/db.py:99 | severity: critical | "
        "reachable: yes | tier: blocking | class: durable | title: SQL injection"
    )
    lines.append("")
    lines.append("the one finding that actually matters, emitted last")
    lines.append("")
    lines.append("EOF")
    lines.append("exit 0")
    return "\n".join(lines) + "\n"


class TestLateBlockingFindingSurvivesTheCap(unittest.TestCase):
    """End-to-end: cmd_adversarial's real emission path, with a chatty
    auditor whose only tier:blocking finding is emitted LAST in parse
    order. Before the fix, a low CLAGENTIC_ADVERSARIAL_FINDINGS_MAX would
    silently drop it while keeping earlier low-value advisory findings."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-sort-cap-proj-")
        _init_git_repo(self._tmpdir)
        _stage_a_change(self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_blocking_finding_survives_a_cap_smaller_than_the_noise(self):
        # 20 low-value advisory findings + 1 late blocking finding, capped
        # to 5 -- pre-fix, all 5 survivors would have been the 5 earliest
        # (noise) findings and the real blocking finding would be dropped.
        fake = _markdown_with_late_blocking_finding(20)
        out, err, rc = _run_cmd_adversarial(
            self._tmpdir, fake,
            extra_env={"CLAGENTIC_ADVERSARIAL_FINDINGS_MAX": "5"},
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        sidecar_path = os.path.join(self._tmpdir, ".clagentic", "lite", "last-adversarial-findings.json")
        with open(sidecar_path) as f:
            findings = json.load(f)
        self.assertEqual(len(findings), 5, f"findings={findings!r}")
        blocking = [f for f in findings if f.get("tier") == "blocking"]
        self.assertEqual(
            len(blocking), 1,
            f"the one tier:blocking finding must survive the cap even "
            f"though it was emitted last in parse order -- pre-fix this "
            f"would have been silently dropped. findings={findings!r}",
        )
        self.assertEqual(blocking[0]["category"], "CWE-89")

    def test_dropped_count_sidecar_reports_the_truncated_tail(self):
        fake = _markdown_with_late_blocking_finding(20)
        out, err, rc = _run_cmd_adversarial(
            self._tmpdir, fake,
            extra_env={"CLAGENTIC_ADVERSARIAL_FINDINGS_MAX": "5"},
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        meta_path = os.path.join(
            self._tmpdir, ".clagentic", "lite", "last-adversarial-findings-meta.json"
        )
        self.assertTrue(os.path.isfile(meta_path), "dropped-count sidecar must be written every run")
        with open(meta_path) as f:
            meta = json.load(f)
        # 21 total findings (20 advisory + 1 blocking), capped to 5 -> 16 dropped.
        self.assertEqual(meta["dropped_count"], 16, f"meta={meta!r}")
        self.assertEqual(meta["total_before_cap"], 21, f"meta={meta!r}")
        # A truncated audit must never be silently presented as complete --
        # the dropped-count fact must also be visible on stderr.
        self.assertIn("16 finding(s) dropped by the count cap", err, f"stderr={err!r}")

    def test_dropped_count_is_zero_when_nothing_is_truncated(self):
        fake = _markdown_with_late_blocking_finding(2)
        out, err, rc = _run_cmd_adversarial(
            self._tmpdir, fake,
            extra_env={"CLAGENTIC_ADVERSARIAL_FINDINGS_MAX": "200"},
        )
        self.assertEqual(rc, 0, f"stdout={out!r} stderr={err!r}")
        meta_path = os.path.join(
            self._tmpdir, ".clagentic", "lite", "last-adversarial-findings-meta.json"
        )
        with open(meta_path) as f:
            meta = json.load(f)
        self.assertEqual(meta["dropped_count"], 0, f"meta={meta!r}")
        self.assertNotIn("dropped by the count cap", err, f"stderr={err!r}")


if __name__ == "__main__":
    unittest.main()
