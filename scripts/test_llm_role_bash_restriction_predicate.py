"""
Regression coverage for ds_llm_role_is_bash_unrestricted (scripts/platform.sh),
the single source of truth for the LLM-role tool-restriction opt-out
enumeration (lr-49df97 fold-in, HOLDEN-authorized correction, PR #143;
UPDATED lr-8a28e0 -- auditor moved OFF this enumeration).

This predicate is the SECOND, INDEPENDENT layer the coordinator's
adjudication required: invoke_claude AND invoke_codex (scripts/llm-client.sh)
both consume it to decide their own tool-restriction flags, and walk_chain
independently calls it at the point a role is about to be exported to
CLAGENTIC_LLM_CLIENT_TOOL_ROLE, so no call site can silently drift onto a
different enumeration.

AUDITOR REMOVED (lr-8a28e0 adjudication, CORRECTING an accident, not
narrowing a considered contract): the original "auditor reads security-tool
output" rationale for exempting auditor describes
plugins/clagentic-lite/agents/auditor.md, the interactive Claude Code
subagent a human/session invokes directly to run gitleaks/semgrep/
osv-scanner itself -- a structurally DIFFERENT mechanism (Claude Code's
native subagent tools: frontmatter) from the one this predicate governs.
The invocation this predicate ACTUALLY governs is the non-interactive
TOOL_ROLE=auditor chain-step call (gates.sh cmd_adversarial ->
llm-client.sh adversarial -> invoke_claude/invoke_codex): read
ds_adversarial_prompt (scripts/llm-client.sh) and cmd_adversarial
(scripts/gates.sh) directly -- that invocation's ONLY input is a diff on
stdin, and cmd_adversarial never shells out to gitleaks/semgrep/osv-scanner
itself (those run as separate, deterministic gates driven by gates.sh's own
shell code, per AGENTS.md §4: "Do not add LLM calls to the blocking path of
any security check"). This invocation has no genuine Bash need, so it is
now restricted identically to the reviewer.

Run with: python3 -m unittest scripts.test_llm_role_bash_restriction_predicate -v
"""
import os
import subprocess
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def _run_predicate(role):
    """Source platform.sh in a real subshell and call the predicate
    directly, asserting on its exit status (0 = unrestricted, 1 =
    restricted) -- not a Python mirror of the case statement."""
    script = f'. "{PLATFORM_SH}"\nds_llm_role_is_bash_unrestricted "{role}"\n'
    r = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    return r.returncode


class TestEnumeratedOptOutRolesReturnUnrestricted(unittest.TestCase):
    """The three names locked by test_other_roles_get_no_tool_restriction_flags
    (test_reviewer_tool_restriction.py) must return 0 (unrestricted) --
    this predicate is what that test's real call path now depends on.
    auditor is deliberately ABSENT from this class (see module docstring
    and TestAuditorIsNowRestricted below) -- it moved to the restricted
    side under lr-8a28e0."""

    def test_gate_is_unrestricted(self):
        self.assertEqual(_run_predicate("gate"), 0)

    def test_builder_is_unrestricted(self):
        self.assertEqual(_run_predicate("builder"), 0)

    def test_summarizer_is_unrestricted(self):
        self.assertEqual(_run_predicate("summarizer"), 0)


class TestAuditorIsNowRestricted(unittest.TestCase):
    """lr-8a28e0 adjudication: auditor moved OFF the opt-out enumeration.
    The TOOL_ROLE=auditor chain-step invocation has no genuine Bash need
    (see module docstring for the full reasoning) and is now restricted
    identically to the reviewer -- this is the corrected, adjudicated
    contract, not merely a narrowing of the prior one."""

    def test_auditor_is_restricted(self):
        self.assertEqual(_run_predicate("auditor"), 1)


class TestEverythingElseFailsTowardRestricted(unittest.TestCase):
    """The fail-safe property this whole fold-in exists to establish:
    anything not explicitly enumerated returns 1 (restricted) -- including
    the reviewer role itself, the auditor role (as of lr-8a28e0), an empty
    string, a misspelling, and a completely unknown role."""

    def test_reviewer_is_restricted(self):
        self.assertEqual(_run_predicate("reviewer"), 1)

    def test_empty_string_is_restricted(self):
        self.assertEqual(_run_predicate(""), 1)

    def test_misspelled_role_is_restricted(self):
        self.assertEqual(_run_predicate("reviewr"), 1)

    def test_unknown_role_is_restricted(self):
        self.assertEqual(_run_predicate("not-a-real-role"), 1)

    def test_misspelled_optout_role_is_restricted(self):
        """A near-miss on a real opt-out name (e.g. a typo'd 'gate')
        must NOT fuzzy-match -- exact string comparison only, matching the
        case statement's own exact-match semantics."""
        self.assertEqual(_run_predicate("gatee"), 1)


if __name__ == "__main__":
    unittest.main()
