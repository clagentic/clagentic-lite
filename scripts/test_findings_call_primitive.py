"""
Tests for ds_findings_call (scripts/platform.sh), the one primitive gate code
uses to run a finding-pipeline stage, and for the wrappers built on it.

Two properties are pinned here:

  1. The pipeline file is located only under the tool's own install. A
     findings.py inside the repository under review is never executed, even
     when the working directory is that repository and no home variable is set.

  2. A stage that fails, including one that prints part of its answer first,
     never leaves partial output behind and never reads as an empty or clean
     result: the primitive prints nothing and returns nonzero, and every wrapper
     takes its own fail-closed branch.

Every path is under a temp dir; nothing here writes this checkout's .clagentic.

Run with: python3 -m unittest scripts/test_findings_call_primitive.py -v
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import (  # noqa: E402
    GATES_SH, PLATFORM_SH, REVIEW_MERGE_SH, TOOL_HOME, init_git_repo, path_without,
    setup_project, source_env,
)

HOME_VARS = ("TOOL_HOME", "_DS_REAL_HOME", "CLAGENTIC_LITE_HOME", "CLAUDE_PLUGIN_ROOT")
FAIL_AFTER_PARTIAL = "import sys\nsys.stdout.write('PARTIAL-OUTPUT')\nsys.stdout.flush()\nsys.exit(3)\n"
ECHO_STDIN = "import sys\nsys.stdout.write(sys.stdin.read())\n"


def base_env(**extra):
    env = {k: v for k, v in os.environ.items()
           if k not in HOME_VARS and not k.startswith("CLAGENTIC_")}
    env.update(extra)
    return env


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-fcall-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.scratch = os.path.join(self.tmp, "scratch")
        os.mkdir(self.scratch)

    def make_home(self, findings_source, name="home"):
        home = os.path.join(self.tmp, name)
        bin_dir = os.path.join(home, "plugins", "clagentic-lite", "bin")
        os.makedirs(bin_dir)
        with open(os.path.join(bin_dir, "findings.py"), "w") as handle:
            handle.write(findings_source)
        return home

    def sh(self, script, home=None, path=None, cwd=None, stdin=None, env_extra=None):
        env = base_env(TMPDIR=self.scratch)
        if home:
            env["TOOL_HOME"] = home
        if path:
            env["PATH"] = path
        env.update(env_extra or {})
        return subprocess.run(["sh", "-c", script], input=stdin, capture_output=True, text=True,
                              cwd=cwd or TOOL_HOME, env=env, timeout=120)

    def platform(self, body, **kw):
        return self.sh(". '%s'\n%s\n" % (PLATFORM_SH, body), **kw)

    def with_review_merge(self, body, **kw):
        return self.sh(". '%s'\n. '%s'\n%s\n" % (PLATFORM_SH, REVIEW_MERGE_SH, body), **kw)


class TestPipelineIsLocatedOnlyUnderTheToolHome(Base):
    def hostile_repo(self):
        repo = os.path.join(self.tmp, "reviewed-repo")
        subprocess.run(["git", "init", "-q", repo], check=True, timeout=60)
        bin_dir = os.path.join(repo, "plugins", "clagentic-lite", "bin")
        os.makedirs(bin_dir)
        self.marker = os.path.join(self.tmp, "HOSTILE-RAN")
        with open(os.path.join(bin_dir, "findings.py"), "w") as handle:
            handle.write("open(%r, 'w').write('ran')\nprint('[]')\n" % self.marker)
        sub = os.path.join(repo, "src", "deep")
        os.makedirs(sub)
        return repo, sub

    def test_a_findings_py_in_the_reviewed_repo_is_not_executed(self):
        repo, sub = self.hostile_repo()
        for cwd in (repo, sub):
            with self.subTest(cwd=cwd):
                result = self.platform("ds_findings_call -t '[1]' -e any ingest length", cwd=cwd)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(os.path.exists(self.marker), "the repo's findings.py was executed")
                self.assertEqual(result.stdout, "")
                self.assertIn("not found", result.stderr)

    def test_every_caller_fails_closed_with_the_hostile_file_present(self):
        repo, _ = self.hostile_repo()
        # The sentinel the gates fall back to is exercised through gates.sh in
        # the class below; here the shell wrappers must refuse, not print "[]".
        result = self.platform(
            "out=$(_llm_json_array_sanitize_fields_strict '[{\"m\":\"x\"}]' m) && echo ACCEPTED\n"
            "printf '<%s>' \"$out\"", cwd=repo)
        self.assertNotIn("ACCEPTED", result.stdout)
        self.assertIn("<>", result.stdout)
        self.assertFalse(os.path.exists(self.marker))

    def test_the_tools_own_checkout_is_not_found_by_working_directory_alone(self):
        result = self.platform("ds_findings_call -t '[1]' -e any ingest length", cwd=TOOL_HOME)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_the_tool_home_resolves_it(self):
        result = self.platform("ds_findings_call -t '[1,2,3]' -e int ingest length",
                               home=TOOL_HOME, cwd=self.scratch)
        self.assertEqual((result.returncode, result.stdout), (0, "3"), result.stderr)

    def test_a_plugin_root_resolves_it_for_an_agent_running_from_the_rendered_plugin(self):
        root = os.path.join(self.tmp, "plugin-root")
        os.makedirs(os.path.join(root, "bin"))
        with open(os.path.join(root, "bin", "findings.py"), "w") as handle:
            handle.write("print('FROM-PLUGIN-ROOT')\n")
        result = self.platform("ds_findings_call ingest length",
                               env_extra={"CLAUDE_PLUGIN_ROOT": root}, cwd=self.scratch)
        self.assertEqual((result.returncode, result.stdout), (0, "FROM-PLUGIN-ROOT\n"), result.stderr)


class TestPrimitiveContract(Base):
    def test_a_stage_failing_after_partial_output_prints_nothing(self):
        home = self.make_home(FAIL_AFTER_PARTIAL)
        result = self.platform("ds_findings_call -e any ingest cap --max 1", home=home)
        self.assertEqual((result.returncode, result.stdout), (3, ""))
        self.assertIn("rc=3", result.stderr)
        self.assertIn("ingest cap", result.stderr)

    def test_exit_zero_with_no_output_is_a_failure_unless_empty_is_allowed(self):
        home = self.make_home("pass\n")
        refused = self.platform("ds_findings_call ingest cap", home=home)
        self.assertEqual((refused.returncode, refused.stdout), (1, ""))
        allowed = self.platform("ds_findings_call -e any ingest cap", home=home)
        self.assertEqual((allowed.returncode, allowed.stdout), (0, ""))

    def test_output_that_is_not_well_formed_for_its_kind_is_discarded(self):
        cases = {"array": "[1", "object": "[1]", "string": "abc", "int": "12x",
                 "ints3": "1 2", "array_or_null": "nul"}
        for kind, printed in cases.items():
            with self.subTest(kind=kind):
                home = self.make_home("import sys\nsys.stdout.write(%r)\n" % printed, name="h-" + kind)
                result = self.platform("ds_findings_call -e %s ingest cap" % kind, home=home)
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                self.assertIn("not a well-formed %s" % kind, result.stderr)

    def test_well_formed_output_of_each_kind_passes(self):
        cases = {"array": "[1]", "object": "{}", "string": '"s"', "int": "7", "ints3": "1 2 3",
                 "array_or_null": "null", "nonempty": "x", "any": ""}
        for kind, printed in cases.items():
            with self.subTest(kind=kind):
                home = self.make_home("import sys\nsys.stdout.write(%r)\n" % printed, name="ok-" + kind)
                result = self.platform("ds_findings_call -e %s ingest cap" % kind, home=home)
                self.assertEqual((result.returncode, result.stdout), (0, printed), result.stderr)

    def test_listed_statuses_are_answers_and_keep_their_output(self):
        home = self.make_home("import sys\nsys.stdout.write('ANSWER')\nsys.exit(1)\n")
        listed = self.platform("ds_findings_call -e any -o 1 verdict ledger-pass", home=home)
        self.assertEqual((listed.returncode, listed.stdout), (1, "ANSWER"))
        unlisted = self.platform("ds_findings_call -e any verdict ledger-pass", home=home)
        self.assertEqual((unlisted.returncode, unlisted.stdout), (1, ""))

    def test_a_stage_crash_is_not_accepted_as_a_listed_answer(self):
        # Python's own uncaught-exception status is 1, the status predicate
        # stages use for "no"; the real file must exit differently on a crash.
        real = os.path.join(TOOL_HOME, "plugins", "clagentic-lite", "bin", "findings.py")
        with open(real) as handle:
            source = handle.read()
        marker = "def main(argv=None):\n"
        self.assertIn(marker, source)
        crashing = source.replace(marker, marker + "    raise RuntimeError('boom')\n", 1)
        home = self.make_home(crashing)
        result = self.platform("ds_findings_call -t '[]' -e any -o 1 verdict ledger-pass", home=home)
        self.assertEqual((result.returncode, result.stdout), (70, ""))
        self.assertIn("rc=70", result.stderr)

    def test_input_reaches_the_stage_from_text_stdin_or_a_file(self):
        home = self.make_home(ECHO_STDIN)
        by_text = self.platform("ds_findings_call -t 'a b\nc' -e any x y", home=home)
        by_stdin = self.platform("ds_findings_call -s -e any x y", home=home, stdin="from stdin")
        path = os.path.join(self.tmp, "in.txt")
        with open(path, "w") as handle:
            handle.write("from file")
        by_file = self.platform("ds_findings_call -i '%s' -e any x y" % path, home=home)
        self.assertEqual(by_text.stdout, "a b\nc")
        self.assertEqual(by_stdin.stdout, "from stdin")
        self.assertEqual(by_file.stdout, "from file")
        self.assertTrue(os.path.exists(path), "a caller's input file must never be removed")

    def test_a_large_payload_never_rides_argv(self):
        home = self.make_home(ECHO_STDIN)
        big = "x" * (400 * 1024)
        result = self.platform("ds_findings_call -s -e any x y", home=home, stdin=big)
        self.assertEqual((result.returncode, len(result.stdout)), (0, len(big)), result.stderr[:200])

    def test_no_temp_files_are_left_behind(self):
        for source in (ECHO_STDIN, FAIL_AFTER_PARTIAL):
            home = self.make_home(source, name="h%d" % len(source))
            self.platform("ds_findings_call -t data -e any x y", home=home)
        self.assertEqual(os.listdir(self.scratch), [])

    def test_python3_missing_is_named_and_returns_127(self):
        shadow = path_without("python3")
        self.addCleanup(shutil.rmtree, shadow, True)
        result = self.platform("ds_findings_call -t '[1]' ingest length", home=TOOL_HOME, path=shadow)
        self.assertEqual((result.returncode, result.stdout), (127, ""))
        self.assertIn("python3 is not installed", result.stderr)

    def test_a_missing_pipeline_file_is_named_and_returns_126(self):
        result = self.platform("ds_findings_call -t '[1]' ingest length", home=self.tmp)
        self.assertEqual((result.returncode, result.stdout), (126, ""))
        self.assertIn("findings.py was not found", result.stderr)

    def test_an_unusable_temp_dir_fails_closed(self):
        home = self.make_home(ECHO_STDIN)
        result = self.platform("ds_findings_call -t x -e any x y", home=home,
                               env_extra={"TMPDIR": os.path.join(self.tmp, "does-not-exist")})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


class TestWrappersNeverConcatenatePartialOutput(Base):
    """The failing stage prints PARTIAL-OUTPUT and exits 3. No wrapper may emit
    that text, with or without its own fallback appended."""

    def setUp(self):
        super().setUp()
        self.home = self.make_home(FAIL_AFTER_PARTIAL)

    def assertClean(self, result, text=""):
        self.assertNotIn("PARTIAL-OUTPUT", result.stdout)
        self.assertEqual(result.stdout, text, result.stderr)

    def test_dedup_findings_passes_its_input_through_unchanged(self):
        payload = '[{"file": "a.py", "severity": "high"}]'
        result = self.with_review_merge("dedup_findings location /dev/null", home=self.home, stdin=payload)
        self.assertEqual(result.returncode, 0)
        self.assertClean(result, payload + "\n")

    def test_dedup_findings_fallback_survives_a_consumed_pipe(self):
        # The stage never reads stdin; a pipe consumed by the failed call used
        # to leave the fallback with nothing to print.
        payload = '[{"file": "a.py"}, {"file": "b.py"}]'
        result = self.with_review_merge("dedup_findings content-hash /dev/null /dev/null annotate",
                                        home=self.home, stdin=payload)
        self.assertClean(result, payload + "\n")

    def test_finding_recurrence_bump_falls_back_to_count_one_per_row(self):
        rows = "k1\tf\tc\tm\n\tf\tc\tm\n"
        result = self.with_review_merge("finding_recurrence_bump /dev/null", home=self.home, stdin=rows)
        self.assertEqual(result.returncode, 0)
        self.assertClean(result, "k1\tf\tc\tm\t1\n\tf\tc\tm\t1\n")

    def test_finding_content_keys_yields_no_rows(self):
        result = self.with_review_merge("finding_content_keys /dev/null", home=self.home, stdin="[]")
        self.assertEqual(result.returncode, 0)
        self.assertClean(result)

    def test_merge_envelopes_returns_the_degraded_envelope_alone(self):
        env_dir = os.path.join(self.tmp, "envs")
        os.mkdir(env_dir)
        result = self.with_review_merge("merge_envelopes '%s' location" % env_dir, home=self.home)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("PARTIAL-OUTPUT", result.stdout)
        envelope = json.loads(result.stdout)
        self.assertTrue(envelope["degraded"])
        self.assertIn("failed or is unavailable", envelope["summary"])

    def test_ledger_reads_yield_nothing_and_say_why(self):
        ledger = os.path.join(self.tmp, "ledger.jsonl")
        with open(ledger, "w") as handle:
            handle.write('{"branch": "b"}\n')
        result = self.with_review_merge("ledger_entries_for_branch '%s' b" % ledger, home=self.home)
        self.assertClean(result)
        self.assertIn("rc=3", result.stderr)
        self.assertEqual(self.with_review_merge("ledger_latest_for_branch '%s' b" % ledger,
                                                home=self.home).stdout, "")

    def test_cap_and_sort_return_the_original_array_alone(self):
        for call in ("_llm_json_array_cap '[3,2,1]' 2", "_adversarial_findings_sort_blocking_first '[3,2,1]'"):
            with self.subTest(call=call):
                result = self.platform(call, home=self.home)
                self.assertClean(result, "[3,2,1]")

    def test_sanitize_helpers_fail_closed_with_no_output(self):
        for call in ("_llm_json_array_sanitize_fields_strict '[{\"m\": \"x\"}]' m",
                     "_llm_json_array_allowlist_fields '[{\"m\": \"x\"}]' m",
                     "_llm_field_sanitize 'some text'"):
            with self.subTest(call=call):
                result = self.platform(call, home=self.home)
                self.assertNotEqual(result.returncode, 0)
                self.assertClean(result)


class TestGateFunctionsFailClosedOnAMidRunFailure(Base):
    """gates.sh functions with the real pipeline replaced, for one stage, by a
    python3 that prints a fragment and fails."""

    def setUp(self):
        super().setUp()
        self.project = os.path.join(self.tmp, "project")
        os.mkdir(self.project)
        setup_project(self.project)
        init_git_repo(self.project)
        self.stub_dir = os.path.join(self.tmp, "stub")
        os.mkdir(self.stub_dir)

    def stub_python(self, stage_op, printed="PARTIAL-OUTPUT", exit_code=3):
        path = os.path.join(self.stub_dir, "python3")
        real = shutil.which("python3")
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\ncase \"$*\" in *'%s'*) printf '%s'; exit %d;; esac\nexec '%s' \"$@\"\n"
                         % (stage_op, printed, exit_code, real))
        os.chmod(path, stat.S_IRWXU)

    def gates(self, body, path=None):
        env = base_env(TMPDIR=self.scratch, CLAGENTIC_PROJECT_ROOT=self.project,
                       PATH=path or (self.stub_dir + os.pathsep + os.environ.get("PATH", "")))
        env.update(source_env(gates=True))
        return subprocess.run(["sh", "-c", ". '%s'\n%s\n" % (GATES_SH, body), GATES_SH],
                              capture_output=True, text=True, cwd=self.project,
                              env=env, timeout=120)

    def test_severity_blockers_prints_the_sentinel_not_the_fragment(self):
        self.stub_python("verdict blockers", printed="0")
        review = os.path.join(self.tmp, "review.json")
        with open(review, "w") as handle:
            json.dump({"findings": []}, handle)
        result = self.gates("severity_blockers '%s' high" % review)
        self.assertEqual(result.stdout.strip(), "99", result.stderr)

    def test_a_stale_report_failure_names_the_real_cause(self):
        self.stub_python("stale-report")
        result = self.gates("_mg_stale_report /nonexistent\nprintf '%s' \"$_MG_STALE_TEXT\"")
        self.assertIn("failed with status 3", result.stdout)
        self.assertNotIn("not installed", result.stdout)
        self.assertNotIn("PARTIAL-OUTPUT", result.stdout)

        shadow = path_without("python3")
        self.addCleanup(shutil.rmtree, shadow, True)
        missing = self.gates("_mg_stale_report /nonexistent\nprintf '%s' \"$_MG_STALE_TEXT\"", path=shadow)
        self.assertIn("python3 is not installed", missing.stdout)

    def test_fence_findings_renders_nothing_on_failure(self):
        self.stub_python("fence-findings", printed='"PARTIAL')
        result = self.gates("rc=0\nout=$(_fence_adversarial_findings '[1]') || rc=$?\nprintf '%s|%s' \"$rc\" \"$out\"")
        self.assertEqual(result.stdout, "3|")

    def test_cross_round_counts_are_validated_before_arithmetic(self):
        # Exit 0 with output that is not three integers used to reach $((...))
        # and the -gt test unvalidated.
        self.stub_python("cross-round", printed="oops", exit_code=0)
        envelope = os.path.join(self.tmp, "env.json")
        with open(envelope, "w") as handle:
            json.dump({"findings": []}, handle)
        result = self.gates("_cross_round_dedup '%s' /dev/null '%s/seen'" % (envelope, self.tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("key computation failed", result.stderr)
        self.assertNotIn("syntax error", result.stderr)
        self.assertNotIn("integer expression", result.stderr)


if __name__ == "__main__":
    unittest.main()
