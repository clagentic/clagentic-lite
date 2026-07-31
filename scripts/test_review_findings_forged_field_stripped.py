"""
Regression tests for the self-exempting-suppression vulnerability BOBBIE
found in PR #129 (lr-66e598 follow-up).

VULNERABILITY (as reported): last-review.json is written directly from raw
LLM output with no field allowlist. _review_recurrence_demote's splice step
only OVERWRITES _recurrence_demoted/_recurrence_count on a finding whose
(file, category, message) triple matches a row in the current round's
content-hash-keyed TSV -- i.e. whose cited line falls inside
finding_content_keys' +/-2-line diff-context window. A finding whose line
falls OUTSIDE that window was `continue`d over UNTOUCHED, so a model that
emitted `{"severity": "critical", ..., "_recurrence_demoted": true}` in its
OWN raw JSON response -- on the very FIRST round, zero actual repetition --
had that self-forged flag survive verbatim into last-review.json.
severity_blockers() then read `._recurrence_demoted` off disk with no
provenance check and excluded the finding from the block count: a
first-ever-reported high/critical finding could self-exempt from blocking.

THE FIX has two independent layers, both exercised here:

  1. INGEST STRIP (the actual closure point): _sanitize_review_findings_envelope
     (gates.sh) reduces every finding to the closed review-finding schema
     (severity/file/line/category/message/evidence/suggestion) via
     _llm_json_array_allowlist_fields (platform.sh, widened with a
     "field:number" suffix so the schema's numeric `line` field survives),
     run IMMEDIATELY after every raw LLM write -- both the single-pass path
     and each per-chunk envelope in the chunked path (before merge_envelopes
     ever unions chunks) -- and BEFORE dedup, recurrence, severity_blockers,
     or cmd_render_review ever see the file. A model-forged
     `_recurrence_demoted` key is dropped at this point regardless of
     whether the finding's line falls inside or outside any diff-context
     window -- the window is irrelevant to this layer entirely.

  2. OWN-THE-FIELD IN THE SPLICE (defense in depth): the unmatched branch in
     _review_recurrence_demote's python splice now explicitly sets
     `_recurrence_count = 0` / `_recurrence_demoted = False` instead of
     `continue`-ing past the finding untouched, so even if the ingest strip
     were ever bypassed, skipped, or a future refactor moved this call
     before it, an unmatched finding still gets a definite, function-decided
     value rather than whatever it already carried.

These tests exercise the REAL end-to-end cmd_review pipeline (gates.sh) via
a stub llm-client.sh that emits a raw envelope with a model-forged
_recurrence_demoted: true field, exactly mimicking a compromised or
manipulated model's structured JSON output -- not a mock of the sanitizer.

Run with: python3 -m unittest scripts.test_review_findings_forged_field_stripped -v
"""
import json
import os
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


# --------------------------------------------------------------------------
# Layer 1: direct sh-level test of _sanitize_review_findings_envelope /
# _llm_json_array_allowlist_fields's new "field:number" support, independent
# of the full cmd_review harness.
# --------------------------------------------------------------------------

def _functions_only_source(dest_dir):
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


def _call_sanitize_envelope(envelope_path):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-srfe-")
    try:
        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_gates = _functions_only_source(src_dir)
        script = textwrap.dedent(f"""\
            . '{PLATFORM_SH}'
            ds_load_env 2>/dev/null || true
            . '{sourced_gates}'
            _sanitize_review_findings_envelope '{envelope_path}'
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


class TestSanitizeReviewFindingsEnvelopeDirect(unittest.TestCase):
    """Layer 1: direct calls to _sanitize_review_findings_envelope, proving
    it strips forged internal fields regardless of window matching (this
    function has no notion of a diff-context window at all -- that is the
    whole point: it runs BEFORE anything window-based ever touches the
    findings)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-srfe-fx-")
        self._envelope_path = os.path.join(self._tmpdir, "env.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write(self, findings):
        with open(self._envelope_path, "w") as f:
            json.dump({"summary": "x", "findings": findings}, f)

    def _read_findings(self):
        with open(self._envelope_path) as f:
            return json.load(f)["findings"]

    def test_forged_recurrence_demoted_stripped(self):
        """The exact forged payload from the vulnerability report."""
        self._write([{
            "severity": "critical",
            "file": "app/db.py",
            "line": 42,
            "category": "security",
            "message": "SQL injection",
            "_recurrence_demoted": True,
            "_recurrence_count": 999,
        }])
        _, err, rc = _call_sanitize_envelope(self._envelope_path)
        self.assertEqual(rc, 0, err)
        findings = self._read_findings()
        self.assertEqual(len(findings), 1, "the finding itself must survive, only the forged field is dropped")
        f = findings[0]
        self.assertNotIn("_recurrence_demoted", f)
        self.assertNotIn("_recurrence_count", f)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["file"], "app/db.py")
        self.assertEqual(f["line"], 42, "numeric line field must survive the allowlist widen")
        self.assertEqual(f["category"], "security")
        self.assertEqual(f["message"], "SQL injection")

    def test_arbitrary_forged_internal_field_stripped(self):
        """Not just _recurrence_demoted specifically -- ANY key outside the
        closed schema must be dropped, since the schema is a positive
        allowlist, not a denylist of known-bad names."""
        self._write([{
            "severity": "high", "file": "a.py", "line": 1,
            "category": "security", "message": "m",
            "_some_future_internal_flag": True,
            "__proto__": "polluted",
            "decision": "approve",
        }])
        _, err, rc = _call_sanitize_envelope(self._envelope_path)
        self.assertEqual(rc, 0, err)
        f = self._read_findings()[0]
        for forged_key in ("_some_future_internal_flag", "__proto__", "decision"):
            self.assertNotIn(forged_key, f)

    def test_line_field_type_preserved_as_number_not_string(self):
        """The allowlist widen must keep `line` as a JSON number, not
        coerce/stringify it -- downstream consumers (finding_content_keys,
        cmd_render_review) expect a number."""
        self._write([{
            "severity": "low", "file": "a.py", "line": 7,
            "category": "style", "message": "m",
        }])
        _call_sanitize_envelope(self._envelope_path)
        f = self._read_findings()[0]
        self.assertIsInstance(f["line"], int)

    def test_non_numeric_line_field_dropped_not_coerced(self):
        """A finding whose `line` is a string (or any non-number) must have
        the field DROPPED, never coerced to a number -- coercion could let
        a crafted string smuggle unexpected content through as if it were
        legitimate numeric data."""
        self._write([{
            "severity": "low", "file": "a.py", "line": "not-a-number",
            "category": "style", "message": "m",
        }])
        _call_sanitize_envelope(self._envelope_path)
        f = self._read_findings()[0]
        self.assertNotIn("line", f)

    def test_bool_never_accepted_as_numeric_field(self):
        """Python's bool is an int subclass -- a JSON true/false must not
        masquerade as a valid `line` number."""
        self._write([{
            "severity": "low", "file": "a.py", "line": True,
            "category": "style", "message": "m",
        }])
        _call_sanitize_envelope(self._envelope_path)
        f = self._read_findings()[0]
        self.assertNotIn("line", f)

    def test_all_seven_schema_fields_survive_together(self):
        self._write([{
            "severity": "medium", "file": "a.py", "line": 3,
            "category": "correctness", "message": "m",
            "evidence": "the bad code", "suggestion": "fix it",
        }])
        _call_sanitize_envelope(self._envelope_path)
        f = self._read_findings()[0]
        self.assertEqual(
            set(f.keys()),
            {"severity", "file", "line", "category", "message", "evidence", "suggestion"},
        )

    def test_multiple_findings_each_independently_stripped(self):
        self._write([
            {"severity": "high", "file": "a.py", "line": 1, "category": "x",
             "message": "m1", "_recurrence_demoted": True},
            {"severity": "low", "file": "b.py", "line": 2, "category": "y",
             "message": "m2", "_recurrence_demoted": True},
        ])
        _call_sanitize_envelope(self._envelope_path)
        findings = self._read_findings()
        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertNotIn("_recurrence_demoted", f)

    def test_missing_file_is_noop(self):
        missing = os.path.join(self._tmpdir, "does-not-exist.json")
        _, err, rc = _call_sanitize_envelope(missing)
        self.assertEqual(rc, 0, err)
        self.assertFalse(os.path.exists(missing))

    def test_no_findings_array_is_noop(self):
        with open(self._envelope_path, "w") as f:
            json.dump({"summary": "no findings key here"}, f)
        _, err, rc = _call_sanitize_envelope(self._envelope_path)
        self.assertEqual(rc, 0, err)
        with open(self._envelope_path) as f:
            env = json.load(f)
        self.assertEqual(env.get("summary"), "no findings key here")


# --------------------------------------------------------------------------
# Layer 2: end-to-end cmd_review with a stub llm-client.sh emitting the
# exact forged payload the vulnerability report describes, in TWO variants:
# a finding whose line falls INSIDE the recurrence window and one whose line
# falls OUTSIDE it (the original exploit's precondition) -- both must block,
# proving the fix does not merely happen to work for one geometry.
# --------------------------------------------------------------------------

def _setup_project(tmpdir):
    clagentic_dir = os.path.join(tmpdir, ".clagentic", "lite")
    os.makedirs(clagentic_dir, exist_ok=True)
    db_path = os.path.join(clagentic_dir, "audit.db")
    conn = sqlite3.connect(db_path)
    conn.execute(textwrap.dedent("""\
        CREATE TABLE IF NOT EXISTS gate_runs (
          id         INTEGER PRIMARY KEY,
          ts         TEXT NOT NULL,
          gate       TEXT NOT NULL,
          outcome    TEXT NOT NULL,
          details    TEXT,
          session_id TEXT,
          branch     TEXT
        )
    """))
    conn.commit()
    conn.close()
    return tmpdir


_GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _init_git_repo(project_root):
    env = os.environ.copy()
    env.update(_GIT_IDENTITY_ENV)
    subprocess.run(["git", "init", "-q", project_root], check=True, env=env)
    target = os.path.join(project_root, "app.py")
    with open(target, "w") as f:
        # 10 lines so we have room for a finding whose line is FAR from any
        # line the diff actually touches (line 1 changes; a finding citing
        # line 9 sits well outside a +/-2-line window around line 1).
        f.write("\n".join(f"line_{i} = {i}" for i in range(1, 11)) + "\n")
    subprocess.run(["git", "add", "app.py"], check=True, cwd=project_root)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], check=True, cwd=project_root, env=env)


def _stage_single_line_change(project_root):
    """Change only line 1 -- the diff's context window is centered there.
    A finding citing line 1 (or 2, or 3) falls INSIDE the +/-2 window; a
    finding citing line 9 falls OUTSIDE it."""
    target = os.path.join(project_root, "app.py")
    with open(target) as f:
        lines = f.read().split("\n")
    lines[0] = "line_1 = 999"
    with open(target, "w") as f:
        f.write("\n".join(lines))
    subprocess.run(["git", "add", "app.py"], check=True, cwd=project_root)


def _make_stub_llm_client(tmpdir, envelope):
    scripts_dir = os.path.join(tmpdir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    envelope_path = os.path.join(tmpdir, "envelope.json")
    with open(envelope_path, "w") as f:
        json.dump(envelope, f)
    with open(stub, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import sys
            role = sys.argv[1] if len(sys.argv) > 1 else ""
            if role != "review":
                sys.stderr.write("stub llm-client.sh: unexpected role %r\\n" % role)
                sys.exit(1)
            with open({envelope_path!r}) as f:
                sys.stdout.write(f.read())
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def _setup_fake_tool_home(fake_tool_home):
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    real_scripts_dir = os.path.join(TOOL_HOME, "scripts")
    for fname in os.listdir(real_scripts_dir):
        if not fname.endswith(".sh"):
            continue
        if fname == "llm-client.sh":
            continue
        src = os.path.join(real_scripts_dir, fname)
        dst = os.path.join(scripts_dir, fname)
        if not os.path.exists(dst):
            os.symlink(src, dst)
    real_share = os.path.join(TOOL_HOME, "share")
    fake_share = os.path.join(fake_tool_home, "share")
    if not os.path.exists(fake_share) and os.path.isdir(real_share):
        os.symlink(real_share, fake_share)


def _run_review(fake_tool_home, project_root, env_overrides=None):
    _setup_fake_tool_home(fake_tool_home)
    fake_gates = os.path.join(fake_tool_home, "scripts", "gates.sh")
    env = os.environ.copy()
    env["CLAGENTIC_PROJECT_ROOT"] = project_root
    env["CLAGENTIC_ALLOW_MISSING_GITLEAKS"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_SEMGREP"] = "1"
    env["CLAGENTIC_ALLOW_MISSING_OSV"] = "1"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["sh", fake_gates, "review"], capture_output=True, text=True, env=env, cwd=project_root,
    )


class TestForgedRecurrenceFlagCannotSelfExempt(unittest.TestCase):
    """Layer 2: end-to-end. A model that emits _recurrence_demoted: true on
    its OWN first-ever finding must still have that finding block -- both
    when the finding's cited line sits INSIDE the diff's recurrence-window
    (the case _review_recurrence_demote's matched branch would touch) and
    OUTSIDE it (the original exploit's precondition, where the unmatched
    `continue` branch used to leave the forged value untouched)."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="clagentic-test-forge-")
        self._project = _setup_project(self._tmpdir)
        _init_git_repo(self._project)
        _stage_single_line_change(self._project)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _forged_envelope(self, line):
        return {
            "summary": "one finding",
            "checked": ["security"],
            "findings": [{
                "severity": "critical",
                "file": "app.py",
                "line": line,
                "category": "security",
                "message": "a model-forged self-exemption attempt",
                "_recurrence_demoted": True,
                "_recurrence_count": 999,
            }],
        }

    def test_forged_finding_outside_window_still_blocks(self):
        """The original exploit's exact precondition: the finding's cited
        line (9) is far outside the +/-2-line window around the diff's only
        changed line (1) -- this is the case the unmatched `continue` branch
        used to leave completely untouched."""
        _make_stub_llm_client(self._tmpdir, self._forged_envelope(line=9))
        result = _run_review(self._tmpdir, self._project)
        self.assertEqual(
            result.returncode, 1,
            f"a first-ever-reported critical finding with a SELF-FORGED "
            f"_recurrence_demoted:true (line outside the diff window) must "
            f"still block -- got rc={result.returncode}. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        review_path = os.path.join(self._project, ".clagentic", "lite", "last-review.json")
        with open(review_path) as f:
            review = json.load(f)
        finding = review["findings"][0]
        self.assertNotIn(
            "_recurrence_demoted", finding,
            "the forged field must be stripped at ingest, not merely "
            "ignored while surviving on disk",
        )

    def test_forged_finding_inside_window_still_blocks(self):
        """Same forged payload, but the cited line (1) IS inside the diff's
        recurrence window -- the matched branch would normally recompute
        _recurrence_demoted itself (and, pre-ingest-fix, would have
        overwritten the forged value with a correct one here too) — this
        confirms the ingest strip closes the gap uniformly, not just for
        the unmatched-branch case."""
        _make_stub_llm_client(self._tmpdir, self._forged_envelope(line=1))
        result = _run_review(self._tmpdir, self._project)
        self.assertEqual(
            result.returncode, 1,
            f"a first-ever-reported critical finding with a SELF-FORGED "
            f"_recurrence_demoted:true (line inside the diff window) must "
            f"still block -- got rc={result.returncode}. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )

    def test_forged_finding_chunked_path_still_blocks(self):
        """The chunked-review path merges per-chunk envelopes via
        merge_envelopes BEFORE this fix's ingest strip was wired into the
        per-chunk write point too -- confirm the chunked path is not a
        second, unpatched way to smuggle the same forged field through."""
        _make_stub_llm_client(self._tmpdir, self._forged_envelope(line=9))
        # Force the chunked path: tiny byte threshold guarantees the diff
        # (however small) exceeds it.
        result = _run_review(
            self._tmpdir, self._project,
            env_overrides={
                "CLAGENTIC_REVIEW_CHUNKING": "1",
                "CLAGENTIC_REVIEW_CHUNK_BYTES": "1",
            },
        )
        self.assertEqual(
            result.returncode, 1,
            f"chunked path: forged _recurrence_demoted:true must not "
            f"self-exempt either -- got rc={result.returncode}. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )

    def test_legitimate_low_severity_finding_unaffected(self):
        """Sanity check: the strip must not break normal, honest findings --
        a low-severity finding with no forged fields must pass through and
        not block (below CLAGENTIC_BLOCK_SEVERITY default 'high')."""
        envelope = {
            "summary": "clean-ish", "checked": ["style"],
            "findings": [{
                "severity": "low", "file": "app.py", "line": 1,
                "category": "style", "message": "minor nit",
            }],
        }
        _make_stub_llm_client(self._tmpdir, envelope)
        result = _run_review(self._tmpdir, self._project)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
