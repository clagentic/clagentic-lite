"""
Regression coverage for lr-33958f (PR-C, required foundry fix 6): the
Reviewer and Merge Gate prompts (ds_review_prompt, ds_merge_gate_prompt,
scripts/llm-client.sh) must explicitly instruct the model to emit exactly
one fenced JSON block or none -- not just "strict JSON, no prose before or
after" as before.

WHY THIS IS REQUIRED, NOT COSMETIC: the parser fix (_llm_unwrap_json_
envelope) is enforcement; the prompt is what reduces how often enforcement
fires. Tightening only the consuming end repeats the sibling repo's error
(five prior fixes there each guaranteed presence at the parser without
ever tightening emission, and the class only closed when both ends were
addressed). This file proves the STRENGTHENED instruction text actually
ships in both JSON-mode prompts, not just that the parser was fixed.

Run with: python3 -m unittest scripts.test_reviewer_prompt_fence_discipline -v
"""
import os
import subprocess
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LLM_CLIENT_SH = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")


def _run_prompt_func(func_name):
    """Source llm-client.sh (functions only, same truncation technique
    every other llm-client.sh test in this suite uses) and print the named
    prompt function's stdout."""
    with open(LLM_CLIENT_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in llm-client.sh"
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-prompt-fence-")
    try:
        dest = os.path.join(tmpdir, "llm-client.sh")
        with open(dest, "w") as f:
            f.writelines(lines[:cut])
        platform_dest = os.path.join(tmpdir, "platform.sh")
        with open(os.path.join(TOOL_HOME, "scripts", "platform.sh")) as src, open(platform_dest, "w") as dst:
            dst.write(src.read())
        script = f". '{dest}'\n{func_name}\n"
        r = subprocess.run(["sh", "-c", script, dest], capture_output=True, text=True, cwd=TOOL_HOME)
        return r.stdout, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestReviewerPromptDemandsExactlyOneFencedBlockOrNone(unittest.TestCase):
    def test_prompt_mentions_exactly_one_fenced_block(self):
        out, err, rc = _run_prompt_func("ds_review_prompt")
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertIn(
            "exactly ONE fenced code block", out,
            f"the Reviewer prompt must explicitly demand exactly one "
            f"fenced block or none -- tightening only the parser repeats "
            f"the sibling repo's error. prompt={out!r}",
        )

    def test_prompt_states_no_other_fenced_block(self):
        out, err, rc = _run_prompt_func("ds_review_prompt")
        self.assertIn("no other fenced block", out)

    def test_prompt_names_more_than_one_block_as_unparseable(self):
        out, err, rc = _run_prompt_func("ds_review_prompt")
        normalized = " ".join(out.lower().split())
        self.assertIn("more than one fenced block", normalized)


class TestMergeGatePromptDemandsExactlyOneFencedBlockOrNone(unittest.TestCase):
    def test_prompt_mentions_exactly_one_fenced_block(self):
        out, err, rc = _run_prompt_func("ds_merge_gate_prompt")
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertIn("exactly ONE fenced code block", out)

    def test_prompt_states_no_other_fenced_block(self):
        out, err, rc = _run_prompt_func("ds_merge_gate_prompt")
        self.assertIn("no other fenced block", out)


class TestReviewerPromptRequiresIssueClass(unittest.TestCase):
    """lr-3eb18c: every finding in the schema block must carry issue_class/
    class_fix, the honest 'none — isolated' answer must be named explicitly
    (confabulation mitigation -- the cheap answer must also be the
    documented one, not something the model has to infer is acceptable),
    and the anti-vagueness Pre-Report Gate rule (item 1: 'vague findings ...
    must be dropped') must be explicitly scoped so it does not eat the new
    class-level fields, per the task's own hard constraint."""

    def test_schema_block_carries_issue_class_field(self):
        out, err, rc = _run_prompt_func("ds_review_prompt")
        self.assertEqual(rc, 0, f"stderr={err!r}")
        self.assertIn("issue_class", out)

    def test_schema_block_carries_class_fix_field(self):
        out, err, rc = _run_prompt_func("ds_review_prompt")
        self.assertIn("class_fix", out)

    def test_none_isolated_named_as_the_honest_answer(self):
        out, err, rc = _run_prompt_func("ds_review_prompt")
        self.assertIn("none — isolated", out)

    def test_vagueness_rule_scoped_away_from_class_fields(self):
        """The per-finding citation requirement (item 1 of the Pre-Report
        Gate) must stay intact, AND the prompt must say explicitly that it
        does not apply to issue_class/class_fix -- otherwise 'vague findings
        ... must be dropped' reads as license to drop the class answer for
        being non-specific, exactly the failure mode the task names."""
        out, err, rc = _run_prompt_func("ds_review_prompt")
        self.assertIn(
            "must be dropped", out,
            "the original per-finding vagueness rule must survive verbatim",
        )
        self.assertIn(
            "does not apply to issue_class", out,
            "the vagueness rule must be explicitly scoped away from "
            "issue_class/class_fix, or a model will read it as license to "
            "drop the class answer for not being a cited line",
        )


if __name__ == "__main__":
    unittest.main()
