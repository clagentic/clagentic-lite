"""
Regression coverage for lr-964f7f: doctor's cross-vendor (step 9) and
reviewer tool-restriction (step 9b) checks were router-blind -- both
branched on CLAGENTIC_REVIEWER_CMD (the direct-CLI FALLBACK name) even when
CLAGENTIC_REVIEWER_VIA_ROUTER=1 routes the live reviewer through
scripts/llm-client.sh's router path instead, where the effective vendor is
governed by CLAGENTIC_REVIEWER_CHAIN.

Two defects this closes:
  (9)  FALSE NEGATIVE -- a routed setup with the same fallback CLI as the
       builder printed the cross-vendor WARN even when the live (routed)
       reviewer is genuinely a different vendor.
  (9b) WRONG-VENDOR OK -- the tool-restriction check asserted a posture
       (--allowedTools/--disallowedTools or --disable shell_tool) about the
       fallback CLI, not the live routed reviewer, whose restriction
       posture is delegated to the router adapter and unknowable from here.

FIX SHAPE: router-CONDITIONAL, vendor-AGNOSTIC. When
CLAGENTIC_REVIEWER_VIA_ROUTER=1 and CLAGENTIC_ROUTER_URL is set, both checks
suppress their *_CMD-keyed assertion and print an INFO naming
CLAGENTIC_REVIEWER_CHAIN as the variable that actually governs the live
vendor/posture -- never asserting an OK doctor cannot back from here. The
non-routed path (VIA_ROUTER unset/!=1, or ROUTER_URL unset) must remain
BYTE-IDENTICAL to the pre-fix behavior: this suite's "unrouted" tests pin
the exact pre-existing WARN/OK text so a future edit cannot silently widen
the routed branch to also fire when it should not.

These tests invoke the ACTUAL bin/clagentic-lite `doctor` command via
subprocess (same technique as scripts/test_router_settings_stamp.py) -- a
Python reimplementation of the shell branching would not catch a regression
in the real shell code.

Run with: python3 -m unittest scripts.test_doctor_router_blind_checks -v
"""
import os
import shutil
import subprocess
import tempfile
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


def _init_git_repo(path):
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", path], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Test"],
                    check=True, capture_output=True)
    fpath = os.path.join(path, "init.txt")
    with open(fpath, "w") as f:
        f.write("initial\n")
    subprocess.run(["git", "-C", path, "add", "init.txt"], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "commit", "-m", "initial"], check=True, capture_output=True)


def _run_doctor(cwd, home, env_extra=None):
    env = dict(os.environ)
    env["HOME"] = home
    env["CLAGENTIC_LITE_HOME"] = TOOL_HOME
    env["CLAGENTIC_SKIP_UPDATE_ALERT"] = "1"
    env.pop("CLAGENTIC_HOME", None)
    env.pop("CLAGENTIC_ROUTER_URL", None)
    env.pop("CLAGENTIC_ROUTER_TOKEN", None)
    env.pop("CLAGENTIC_REVIEWER_VIA_ROUTER", None)
    env.pop("CLAGENTIC_REVIEWER_CMD", None)
    env.pop("CLAGENTIC_BUILDER_CMD", None)
    env.pop("CLAGENTIC_REVIEWER_CHAIN", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [CLI, "doctor"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr


class _DoctorTestBase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-doctor-router-blind-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.home = os.path.join(self.tmpdir, "home")
        os.makedirs(self.home)
        self.repo = os.path.join(self.tmpdir, "repo")
        _init_git_repo(self.repo)


class TestUnroutedPathIsByteIdenticalToToday(_DoctorTestBase):
    """Primary design requirement: no router configured (CLAGENTIC_ROUTER_URL
    unset, or VIA_ROUTER != 1) must produce the exact pre-existing WARN/OK
    text -- this is a narrowing/conditional-branch change, not a rewrite."""

    def test_same_vendor_fallback_still_warns_with_original_text_when_unrouted(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_BUILDER_CMD": "claude",
                "CLAGENTIC_REVIEWER_CMD": "claude",
            },
        )
        self.assertIn(
            'WARN Builder and Reviewer both use "claude" — cross-vendor review is disabled.',
            out, msg=out,
        )
        self.assertIn("Set CLAGENTIC_REVIEWER_CMD to a different CLI", out, msg=out)

    def test_cross_vendor_ok_text_unchanged_when_unrouted(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_BUILDER_CMD": "claude",
                "CLAGENTIC_REVIEWER_CMD": "codex",
            },
        )
        self.assertIn("OK   Builder=claude / Reviewer=codex (cross-vendor OK)", out, msg=out)

    def test_reviewer_tool_restriction_ok_text_unchanged_when_unrouted(self):
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={"CLAGENTIC_REVIEWER_CMD": "claude"},
        )
        self.assertIn(
            "OK   Reviewer=claude (tool-restriction enforced: --allowedTools Read,Grep,Glob --disallowedTools Bash)",
            out, msg=out,
        )

    def test_router_url_set_but_via_router_unset_stays_unrouted(self):
        """CLAGENTIC_ROUTER_URL alone (no per-role opt-in) must not flip
        either check into the routed branch -- VIA_ROUTER is the gate,
        exactly mirroring scripts/llm-client.sh's own two-condition guard."""
        rc, out, err = _run_doctor(
            cwd=self.repo, home=self.home,
            env_extra={
                "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
                "CLAGENTIC_BUILDER_CMD": "claude",
                "CLAGENTIC_REVIEWER_CMD": "claude",
            },
        )
        self.assertIn(
            'WARN Builder and Reviewer both use "claude" — cross-vendor review is disabled.',
            out, msg=out,
        )
        self.assertIn(
            "OK   Reviewer=claude (tool-restriction enforced: --allowedTools Read,Grep,Glob --disallowedTools Bash)",
            out, msg=out,
        )


class TestRoutedPathRemovesFalseNegativeAndWrongVendorOk(_DoctorTestBase):
    """CLAGENTIC_REVIEWER_VIA_ROUTER=1 + CLAGENTIC_ROUTER_URL set: the live
    reviewer vendor is governed by CLAGENTIC_REVIEWER_CHAIN, not
    CLAGENTIC_REVIEWER_CMD. Neither check may assert same-vendor WARN,
    cross-vendor OK, or a tool-restriction OK keyed on *_CMD in this case --
    under-claiming (an INFO naming the governing variable) is required."""

    def _routed_env(self, chain="codex:flagship"):
        return {
            "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:8765",
            "CLAGENTIC_REVIEWER_VIA_ROUTER": "1",
            "CLAGENTIC_BUILDER_CMD": "claude",
            "CLAGENTIC_REVIEWER_CMD": "claude",
            "CLAGENTIC_REVIEWER_CHAIN": chain,
        }

    def test_cross_vendor_false_negative_removed(self):
        """The exact scenario from the task: builder=claude,
        reviewer fallback=claude, but reviewer routes to codex over the
        router. The false 'both use claude' WARN must not appear."""
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, env_extra=self._routed_env())
        self.assertNotIn(
            'WARN Builder and Reviewer both use "claude"',
            out, msg=out,
        )

    def test_cross_vendor_wrong_vendor_ok_not_asserted(self):
        """Doctor must not assert cross-vendor OK either -- it cannot prove
        vendor separation from *_CMD alone on a routed role."""
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, env_extra=self._routed_env())
        self.assertNotIn("cross-vendor OK", out, msg=out)

    def test_cross_vendor_info_names_the_chain_variable(self):
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, env_extra=self._routed_env())
        self.assertIn("CLAGENTIC_REVIEWER_VIA_ROUTER=1", out, msg=out)
        self.assertIn("CLAGENTIC_REVIEWER_CHAIN", out, msg=out)
        self.assertIn("codex:flagship", out, msg=out)

    def test_tool_restriction_wrong_vendor_ok_not_asserted(self):
        """The security-relevant half: doctor must not print an OK naming
        claude's tool-restriction posture when the live reviewer is routed
        to a different backend entirely."""
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, env_extra=self._routed_env())
        self.assertNotIn(
            "OK   Reviewer=claude (tool-restriction enforced",
            out, msg=out,
        )

    def test_tool_restriction_info_delegates_to_router_adapter(self):
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, env_extra=self._routed_env())
        self.assertIn("delegated to the clagentic-router adapter", out, msg=out)
        self.assertIn("CLAGENTIC_REVIEWER_CHAIN=codex:flagship", out, msg=out)

    def test_tool_restriction_still_names_the_direct_cli_fallback(self):
        """Under-claiming, not silence: the fallback CLI's own posture is
        still worth surfacing, clearly labeled as fallback-only."""
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, env_extra=self._routed_env())
        self.assertIn("Direct-CLI FALLBACK", out, msg=out)
        self.assertIn("Reviewer=claude", out, msg=out)

    def test_routed_with_unset_chain_still_suppresses_wrong_assertions(self):
        """Even with no CLAGENTIC_REVIEWER_CHAIN configured (chain resolves
        empty, e.g. relying on some other default), the routed branch must
        still suppress the *_CMD-keyed assertion rather than fall through
        to it silently."""
        env = self._routed_env()
        env.pop("CLAGENTIC_REVIEWER_CHAIN")
        rc, out, err = _run_doctor(cwd=self.repo, home=self.home, env_extra=env)
        self.assertNotIn('WARN Builder and Reviewer both use "claude"', out, msg=out)
        self.assertNotIn("OK   Reviewer=claude (tool-restriction enforced", out, msg=out)
        self.assertIn("(unset)", out, msg=out)


if __name__ == "__main__":
    unittest.main()
