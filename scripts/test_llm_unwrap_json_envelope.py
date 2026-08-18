"""
Regression coverage for lr-33958f (PR-C, INV-2): the shared unwrap helper
(_llm_unwrap_json_envelope, scripts/llm-client.sh), called once from
walk_chain immediately after invoke_step returns, replacing the old inline
unwrap that lived only inside invoke_claude.

THE OPERATOR'S ORIGINAL REPRODUCTION (the acceptance criterion this file
exists to encode): 15:55 passed and 16:02 failed on the SAME commit, SAME
diff, SAME auth, seven minutes apart -- the only difference was whether the
model led with the fence or with a sentence of prose. The 16:02 run
produced a COMPLETE, VALID review and the harness discarded it because the
old regex was `re.match` anchored to the WHOLE .result string. This file's
TestOperatorReproductionTable class encodes that table directly: fence-only
MUST pass, prose+fence MUST pass, two fences MUST fail (ambiguous, never
silently picked), zero fences MUST fail as unwrap-failed.

Three foundry rulings this file also proves, not just the parse fix alone:
  1. On unwrap failure the function LEAVES THE ENVELOPE FILE UNTOUCHED --
     never writes back the inner prose (which would destroy num_turns/
     duration_ms). Failure travels on the return channel (exit code),
     never the data channel (file content).
  2. EXACTLY ONE survivor, not first-or-last: zero candidates is a
     distinct failure (exit 10); more than one candidate is a SEPARATE,
     distinct failure (exit 11), never a silent pick of either.
  3. Uppercase and json5/jsonc fence info-strings are accepted (the fixed
     character class), not just lowercase "json".

These tests source the ACTUAL sh function via `sh -c`, mirroring the
established fake-binary-on-PATH-free technique other llm-client.sh tests
use (this function needs no CLI stub at all -- it operates purely on a
file already on disk, exactly as walk_chain calls it after invoke_step
returns).

Run with: python3 -m unittest scripts.test_llm_unwrap_json_envelope -v
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run_unwrap(result_value, mode="json", role="reviewer"):
    """Write RESULT_VALUE (a python string) as the .result field of a
    synthetic --output-format json envelope, call
    _llm_unwrap_json_envelope on it, and return
    (exit_code, final_file_content_str).

    The envelope's other fields (num_turns, duration_ms) are populated
    with recognizable sentinel values so a test can assert they survive
    (or are destroyed) depending on the unwrap outcome -- this is the
    concrete shape of "preserve the envelope for diagnostics."
    """
    envelope = {
        "type": "result",
        "result": result_value,
        "num_turns": 17,
        "duration_ms": 42000,
    }
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-unwrap-")
    try:
        sourced = LLM_CLIENT_SH

        target_file = os.path.join(tmpdir, "output.json")
        with open(target_file, "w") as f:
            json.dump(envelope, f)

        script = textwrap.dedent(f"""\
            . '{sourced}'
            RC=0
            _llm_unwrap_json_envelope '{mode}' '{target_file}' '{role}' || RC=$?
            exit "$RC"
        """)
        env = os.environ.copy()
        env.update(source_env(llm_client=True))
        r = subprocess.run(
            ["sh", "-c", script, sourced],
            capture_output=True,
            text=True,
            cwd=TOOL_HOME,
            env=env,
        )
        with open(target_file) as f:
            final_content = f.read()
        return r.returncode, final_content, r.stderr
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


_REVIEWER_JSON = json.dumps({
    "summary": "clean",
    "checked": ["security"],
    "findings": [],
})


class TestOperatorReproductionTable(unittest.TestCase):
    """The exact reproduction table the operator diagnosed himself: fence-
    only PASSES, prose+fence PASSES, two fences FAILS (ambiguous, not
    silently picked), zero fences FAILS as unwrap-failed. This is the
    acceptance criterion, encoded directly rather than inferred from unit
    tests of sub-pieces."""

    def test_fence_only_passes(self):
        """15:55's shape: the ENTIRE .result is a fenced JSON block, no
        preamble. Must unwrap successfully -- this already worked under the
        old anchored regex, and must keep working under the new one."""
        result_value = "```json\n" + _REVIEWER_JSON + "\n```"
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(rc, 0, f"fence-only must pass. stderr={stderr!r}")
        self.assertEqual(json.loads(content), json.loads(_REVIEWER_JSON))

    def test_prose_plus_fence_passes(self):
        """16:02's shape -- THE REPORTED BUG: one sentence of preamble
        before the SAME fenced JSON. The old start-and-end-anchored regex
        (`re.match` against the whole string) failed here; re.search must
        find it anywhere in the text."""
        result_value = (
            "Sure, here is my review of the diff:\n\n"
            "```json\n" + _REVIEWER_JSON + "\n```\n"
        )
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(
            rc, 0,
            f"prose+fence (THE REPORTED BUG) must pass. stderr={stderr!r}",
        )
        self.assertEqual(json.loads(content), json.loads(_REVIEWER_JSON))

    def test_two_fences_fails_ambiguous_not_silently_picked(self):
        """MORE THAN ONE candidate fenced block, both parsing as valid
        role-shaped JSON -- foundry ruling 2: never silently pick first or
        last. Must be its OWN reported outcome (exit 11), distinct from the
        zero-candidate case (exit 10)."""
        other_json = json.dumps({
            "summary": "different review",
            "checked": ["performance"],
            "findings": [{"severity": "low", "file": "a.py", "line": 1,
                           "category": "style", "message": "x",
                           "evidence": "y", "suggestion": "z"}],
        })
        result_value = (
            "```json\n" + _REVIEWER_JSON + "\n```\n\n"
            "Actually, here is a better version:\n\n"
            "```json\n" + other_json + "\n```\n"
        )
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(
            rc, 11,
            f"two role-shaped fenced candidates must fail as ambiguous "
            f"(exit 11), never silently pick one. stderr={stderr!r}",
        )
        # FILE UNTOUCHED: the envelope (with num_turns/duration_ms) survives.
        on_disk = json.loads(content)
        self.assertEqual(on_disk.get("num_turns"), 17)
        self.assertEqual(on_disk.get("duration_ms"), 42000)

    def test_zero_fences_prose_only_fails_unwrap_failed(self):
        """The RESIDUAL case the foundry insisted on hardest: the model
        returns prose and NO JSON at all -- not just a narrower trigger of
        the same bug, a distinct failure class. Must fail as unwrap-failed
        (exit 10), and the envelope must be PRESERVED on disk (num_turns/
        duration_ms survive) for diagnostics -- writing back the raw prose
        was the alternative the foundry explicitly REJECTED."""
        result_value = "I looked at the diff and it seems fine, no issues found."
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(
            rc, 10,
            f"prose-only, zero JSON candidates, must fail as unwrap-failed "
            f"(exit 10). stderr={stderr!r}",
        )
        on_disk = json.loads(content)
        self.assertEqual(
            on_disk.get("num_turns"), 17,
            "FILE MUST BE UNTOUCHED on unwrap failure -- num_turns is "
            "exactly the diagnostic field the foundry said writing back "
            "the inner prose would destroy.",
        )
        self.assertEqual(on_disk.get("duration_ms"), 42000)
        self.assertEqual(
            on_disk.get("result"), result_value,
            "the raw prose must still be present as .result inside the "
            "UNCHANGED envelope -- not promoted to top-level, not erased.",
        )


class TestFenceInfoStringCharacterClass(unittest.TestCase):
    """Foundry-required fix 4: the info-string character class must accept
    uppercase and json5/jsonc variants, not just lowercase 'json'."""

    def test_uppercase_json_info_string_accepted(self):
        result_value = "```JSON\n" + _REVIEWER_JSON + "\n```"
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(rc, 0, f"uppercase JSON fence must unwrap. stderr={stderr!r}")
        self.assertEqual(json.loads(content), json.loads(_REVIEWER_JSON))

    def test_json5_info_string_accepted(self):
        result_value = "```json5\n" + _REVIEWER_JSON + "\n```"
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(rc, 0, f"json5 fence must unwrap. stderr={stderr!r}")

    def test_jsonc_info_string_accepted(self):
        result_value = "```jsonc\n" + _REVIEWER_JSON + "\n```"
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(rc, 0, f"jsonc fence must unwrap. stderr={stderr!r}")

    def test_no_info_string_still_accepted(self):
        """Bare ``` with no language tag at all -- the pre-existing case
        that must not regress."""
        result_value = "```\n" + _REVIEWER_JSON + "\n```"
        rc, content, stderr = _run_unwrap(result_value)
        self.assertEqual(rc, 0, f"bare fence (no info string) must unwrap. stderr={stderr!r}")


class TestRoleShapeFiltering(unittest.TestCase):
    """A fenced candidate that parses as JSON but does NOT match the
    role's expected shape must not count as a survivor -- this is what
    lets the parser distinguish 'the model's own worked example, fenced
    incidentally' from the actual answer, per the task's INV-2 clause (ii)
    guidance ('a model's intermediate fenced example is far more likely to
    be arbitrary JSON than a well-formed findings envelope')."""

    def test_arbitrary_json_fence_not_reviewer_shaped_is_zero_candidates(self):
        arbitrary = json.dumps({"foo": "bar", "baz": [1, 2, 3]})
        result_value = "Here's an example of the input format:\n```json\n" + arbitrary + "\n```"
        rc, content, stderr = _run_unwrap(result_value, role="reviewer")
        self.assertEqual(
            rc, 10,
            f"a fenced JSON block with no .findings array must not count "
            f"as a reviewer-shaped candidate. stderr={stderr!r}",
        )

    def test_one_role_shaped_and_one_arbitrary_fence_picks_the_shaped_one(self):
        """This is NOT 'pick the last one' -- it is 'filter to role-shaped
        candidates, then require exactly one survivor.' With one arbitrary
        JSON fence and one genuinely role-shaped fence, exactly one
        candidate SURVIVES THE FILTER, so this is the ordinary
        len(candidates)==1 success path, not an ambiguous pick."""
        arbitrary = json.dumps({"foo": "bar"})
        result_value = (
            "```json\n" + arbitrary + "\n```\n\n"
            "```json\n" + _REVIEWER_JSON + "\n```\n"
        )
        rc, content, stderr = _run_unwrap(result_value, role="reviewer")
        self.assertEqual(rc, 0, f"exactly one role-shaped survivor must pass. stderr={stderr!r}")
        self.assertEqual(json.loads(content), json.loads(_REVIEWER_JSON))

    def test_gate_role_shape_requires_decision_field(self):
        gate_json = json.dumps({"decision": "approve", "reason": "clean"})
        result_value = "Decision:\n```json\n" + gate_json + "\n```"
        rc, content, stderr = _run_unwrap(result_value, role="gate")
        self.assertEqual(rc, 0, f"gate-shaped JSON must unwrap for role=gate. stderr={stderr!r}")
        self.assertEqual(json.loads(content), json.loads(gate_json))

    def test_gate_role_rejects_findings_shaped_json(self):
        """A reviewer-shaped candidate is not gate-shaped -- cross-role
        confusion must not accidentally count as a survivor."""
        result_value = "```json\n" + _REVIEWER_JSON + "\n```"
        rc, content, stderr = _run_unwrap(result_value, role="gate")
        self.assertEqual(
            rc, 10,
            f"a .findings-shaped candidate must not satisfy role=gate's "
            f".decision requirement. stderr={stderr!r}",
        )


class TestNonEnvelopeAndNonJsonModePassthrough(unittest.TestCase):
    """'Nothing to unwrap' cases: mode is not json, or the file is not a
    --output-format json envelope at all (bare CLI output, e.g. codex's
    -o file). Both must return 0 with the file COMPLETELY untouched."""

    def test_non_json_mode_is_a_no_op(self):
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-unwrap-nomode-")
        try:
            sourced = LLM_CLIENT_SH
            target_file = os.path.join(tmpdir, "output.md")
            original = "# Some markdown\n\nNot JSON at all."
            with open(target_file, "w") as f:
                f.write(original)
            script = textwrap.dedent(f"""\
                . '{sourced}'
                RC=0
                _llm_unwrap_json_envelope 'markdown' '{target_file}' 'auditor' || RC=$?
                exit "$RC"
            """)
            env = os.environ.copy()
            env.update(source_env(llm_client=True))
            r = subprocess.run(["sh", "-c", script, sourced], capture_output=True, text=True, cwd=TOOL_HOME, env=env)
            self.assertEqual(r.returncode, 0, f"markdown mode must be a no-op. stderr={r.stderr!r}")
            with open(target_file) as f:
                self.assertEqual(f.read(), original)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_bare_json_no_envelope_is_untouched_and_returns_0(self):
        """codex's -o file (or any bare-JSON CLI output with no
        --output-format json envelope) is not this function's shape --
        validate_output handles it directly."""
        tmpdir = tempfile.mkdtemp(prefix="clagentic-test-unwrap-bare-")
        try:
            sourced = LLM_CLIENT_SH
            target_file = os.path.join(tmpdir, "output.json")
            with open(target_file, "w") as f:
                f.write(_REVIEWER_JSON)
            script = textwrap.dedent(f"""\
                . '{sourced}'
                RC=0
                _llm_unwrap_json_envelope 'json' '{target_file}' 'reviewer' || RC=$?
                exit "$RC"
            """)
            env = os.environ.copy()
            env.update(source_env(llm_client=True))
            r = subprocess.run(["sh", "-c", script, sourced], capture_output=True, text=True, cwd=TOOL_HOME, env=env)
            self.assertEqual(r.returncode, 0, f"bare JSON (no envelope) must be a no-op. stderr={r.stderr!r}")
            with open(target_file) as f:
                self.assertEqual(json.loads(f.read()), json.loads(_REVIEWER_JSON))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_structured_result_dict_is_written_back_bare(self):
        """.result already a dict (not a string) -- some CLI shapes may
        hand back structured JSON directly. Must write it back bare and
        succeed, matching the original inline behavior for this sub-case."""
        rc, content, stderr = _run_unwrap({"summary": "x", "checked": [], "findings": []})
        self.assertEqual(rc, 0, f"structured .result dict must succeed. stderr={stderr!r}")
        self.assertEqual(json.loads(content), {"summary": "x", "checked": [], "findings": []})


if __name__ == "__main__":
    unittest.main()
