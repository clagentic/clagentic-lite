"""
Tests for pre-push gate input domains (scripts/gate-domain.sh, cmd_pre_push).

A push whose diff cannot reach a gate's input domain must not be blocked by
that gate's pre-existing findings, and that skip must be a distinct
`skipped_out_of_domain` outcome, never a pass. Every uncertainty must run the
gate; secrets is never eligible; touching any gate's config runs everything.

End-to-end cases drive the real `gates.sh pre-push` against real git repos
(bare origin + clone) with fake semgrep/osv-scanner binaries that record
whether they were invoked, feeding the git pre-push stdin contract directly.

Run with: python3 -m unittest scripts.test_gate_domain -v
"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")
ZERO = "0" * 40

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _write_exe(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def _install_fake_scanners(bin_dir):
    os.makedirs(bin_dir, exist_ok=True)
    _write_exe(os.path.join(bin_dir, "semgrep"), textwrap.dedent("""\
        #!/bin/sh
        if [ "$1" = "scan" ] && [ "$2" = "--help" ]; then
          echo "--baseline-commit TEXT"
          exit 0
        fi
        echo semgrep >> "$SCANNER_LOG"
        exit 0
    """))
    _write_exe(os.path.join(bin_dir, "osv-scanner"), textwrap.dedent("""\
        #!/bin/sh
        if [ "$1" = "--version" ]; then
          echo "osv-scanner version: 2.2.0"
          exit 0
        fi
        echo osv-scanner >> "$SCANNER_LOG"
        echo '{"results": []}'
        exit 0
    """))


class _PushRepoTestCase(unittest.TestCase):
    """Bare origin + clone with main pushed and a `feature` branch checked out."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-gate-domain-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.bin = os.path.join(self.tmp, "bin")
        _install_fake_scanners(self.bin)
        self.log = os.path.join(self.tmp, "scanner.log")
        open(self.log, "w").close()
        self.origin = os.path.join(self.tmp, "origin.git")
        self.work = os.path.join(self.tmp, "work")
        self._git_bare("init", "-q", "--bare", self.origin)
        self._g(self.tmp, "clone", "-q", self.origin, self.work)
        self.write("README.md", "hello\n")
        with open(os.path.join(self.work, ".git", "info", "exclude"), "a") as f:
            f.write(".clagentic/lite/\n")
        self.commit("initial")
        self._g(self.work, "branch", "-M", "main")
        self._g(self.work, "push", "-q", "origin", "HEAD:main")
        self._g(self.work, "checkout", "-q", "-b", "feature")

    def _git_bare(self, *args):
        subprocess.run(["git", *args], check=True, env={**os.environ, **_GIT_ENV})

    def _g(self, cwd, *args):
        return subprocess.run(["git", *args], check=True, cwd=cwd, capture_output=True,
                              text=True, env={**os.environ, **_GIT_ENV}).stdout.strip()

    def write(self, rel, content="x\n"):
        path = os.path.join(self.work, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def commit(self, msg="change"):
        self._g(self.work, "add", "--all")
        self._g(self.work, "commit", "-q", "-m", msg)
        return self.head()

    def head(self):
        return self._g(self.work, "rev-parse", "HEAD")

    def new_branch_line(self, sha=None, ref="refs/heads/feature"):
        return f"{ref} {sha or self.head()} {ref} {ZERO}\n"

    def run_sh(self, snippet, extra_env=None):
        env = {**os.environ, "HOME": self.home, "CLAGENTIC_PROJECT_ROOT": self.work,
               "CLAGENTIC_GATES_SOURCE_ONLY": "1", "CLAGENTIC_GATES_DELIBERATE_SOURCE": "1",
               "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        env.update(extra_env or {})
        return subprocess.run(["sh", "-c", f'. "{GATES_SH}"; {snippet}', GATES_SH], cwd=self.work,
                              capture_output=True, text=True, env=env)

    def pre_push(self, stdin_text, extra_env=None):
        env = {**os.environ, "HOME": self.home, "CLAGENTIC_PROJECT_ROOT": self.work,
               "SCANNER_LOG": self.log, "PATH": self.bin + os.pathsep + os.environ["PATH"]}
        for k in ("CLAGENTIC_GATES_SOURCE_ONLY", "CLAGENTIC_GATES_DELIBERATE_SOURCE",
                  "CLAGENTIC_ALWAYS_RUN_ALL_GATES", "CLAGENTIC_SEMGREP_CONFIG"):
            env.pop(k, None)
        env.update(extra_env or {})
        return subprocess.run(["sh", GATES_SH, "pre-push"], cwd=self.work, input=stdin_text,
                              capture_output=True, text=True, env=env, timeout=120)

    def scanners_run(self):
        with open(self.log) as f:
            return sorted(set(f.read().split()))

    def rows(self, gate):
        conn = sqlite3.connect(os.path.join(self.work, ".clagentic", "lite", "audit.db"))
        try:
            return conn.execute(
                "SELECT outcome, details FROM gate_runs WHERE gate=? ORDER BY id", (gate,)
            ).fetchall()
        finally:
            conn.close()

    def assert_everything_ran(self, result, reason=None):
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        if reason is not None:
            # Proves the gates ran for the intended fail-closed reason rather
            # than by accident of some other inconclusive path.
            self.assertIn(reason, result.stderr)
        self.assertEqual(self.scanners_run(), ["osv-scanner", "semgrep"], msg=result.stderr)
        for gate in ("deps", "sast"):
            self.assertNotIn("skipped_out_of_domain", [r[0] for r in self.rows(gate)])


class TestOutOfDomainSkip(_PushRepoTestCase):
    def test_docs_only_push_skips_both_and_logs_distinct_outcome(self):
        self.write("docs/guide.md", "prose\n")
        self.commit()
        result = self.pre_push(self.new_branch_line())
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.scanners_run(), [])
        for gate in ("deps", "sast"):
            outcome, details = self.rows(gate)[-1]
            self.assertEqual(outcome, "skipped_out_of_domain")
            self.assertNotEqual(outcome, "pass")
            self.assertIn("domain=", details)
            self.assertIn("docs/guide.md", details)
            self.assertIn("derived=new ref refs/heads/feature", details)
            self.assertIn("NOT a pass", details)

    def test_lockfile_change_runs_deps_but_skips_sast(self):
        self.write("go.sum", "h1:abc\n")
        self.commit()
        result = self.pre_push(self.new_branch_line())
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.scanners_run(), ["osv-scanner"])
        self.assertEqual(self.rows("deps")[-1][0], "pass")
        self.assertEqual(self.rows("sast")[-1][0], "skipped_out_of_domain")

    def test_source_change_runs_sast_but_skips_deps(self):
        self.write("app.py", "print(1)\n")
        self.commit()
        result = self.pre_push(self.new_branch_line())
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.scanners_run(), ["semgrep"])
        self.assertEqual(self.rows("deps")[-1][0], "skipped_out_of_domain")
        self.assertEqual(self.rows("sast")[-1][0], "pass")

    def test_update_of_existing_remote_branch_uses_remote_tip_as_base(self):
        self.write("docs/a.md")
        first = self.commit("first")
        self._g(self.work, "push", "-q", "origin", "feature")
        self.write("docs/b.md")
        second = self.commit("second")
        line = f"refs/heads/feature {second} refs/heads/feature {first}\n"
        result = self.pre_push(line)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.scanners_run(), [])
        details = self.rows("deps")[-1][1]
        self.assertIn("docs/b.md", details)
        self.assertNotIn("docs/a.md", details)
        self.assertIn(f"{first}..{second}", details)

    def test_multiple_refs_use_the_union(self):
        self.write("docs/a.md")
        docs_sha = self.commit("docs")
        self.write("app.py", "print(1)\n")
        src_sha = self.commit("src")
        stdin = (f"refs/heads/docs {docs_sha} refs/heads/docs {ZERO}\n"
                 f"refs/heads/feature {src_sha} refs/heads/feature {ZERO}\n")
        result = self.pre_push(stdin)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.scanners_run(), ["semgrep"])


class TestFailClosed(_PushRepoTestCase):
    """Each way of not knowing the changed-path set must run every gate."""

    def setUp(self):
        super().setUp()
        self.write("docs/guide.md", "prose\n")
        self.docs_sha = self.commit("docs only")

    def test_no_stdin_ref_list(self):
        self.assert_everything_ran(self.pre_push(""), "no pre-push ref list")

    def test_ref_deletion(self):
        self.assert_everything_ran(
            self.pre_push(f"(delete) {ZERO} refs/heads/feature {self.docs_sha}\n"),
            "ref deletion")

    def test_remote_tip_not_present_locally(self):
        line = f"refs/heads/feature {self.docs_sha} refs/heads/feature {'1' * 40}\n"
        self.assert_everything_ran(self.pre_push(line), "not present locally")

    def test_non_fast_forward_push(self):
        self._g(self.work, "checkout", "-q", "main")
        self.write("other.txt")
        other = self.commit("diverge")
        self._g(self.work, "checkout", "-q", "feature")
        line = f"refs/heads/feature {self.docs_sha} refs/heads/feature {other}\n"
        self.assert_everything_ran(self.pre_push(line), "non-fast-forward")

    def test_merge_commit_in_range(self):
        self._g(self.work, "checkout", "-q", "-b", "side", "main")
        self.write("side.md")
        self.commit("side")
        self._g(self.work, "checkout", "-q", "feature")
        self._g(self.work, "merge", "-q", "--no-ff", "-m", "merge", "side")
        self.assert_everything_ran(self.pre_push(self.new_branch_line()), "merge commit")

    def test_symlink_change(self):
        os.symlink("README.md", os.path.join(self.work, "link.md"))
        self.commit("symlink")
        self.assert_everything_ran(self.pre_push(self.new_branch_line()), "symlink or submodule")

    def test_newly_executable_prose_file(self):
        os.chmod(self.write("run.md"), 0o755)
        self.commit("exec")
        self.assert_everything_ran(self.pre_push(self.new_branch_line()), "executable file")

    def test_mode_change_of_existing_file(self):
        os.chmod(os.path.join(self.work, "README.md"), 0o755)
        self.commit("chmod")
        self.assert_everything_ran(self.pre_push(self.new_branch_line()), "executable file")

    def test_empty_changed_path_set(self):
        self._g(self.work, "checkout", "-q", "-b", "same", "main")
        main_sha = self.head()
        line = f"refs/heads/same {main_sha} refs/heads/same {ZERO}\n"
        self.assert_everything_ran(self.pre_push(line), "changed-path set is empty")

    def test_shallow_clone(self):
        self._g(self.work, "push", "-q", "origin", "feature")
        shallow = os.path.join(self.tmp, "shallow")
        self._g(self.tmp, "clone", "-q", "--depth", "1", "--branch", "feature",
                "file://" + self.origin, shallow)
        self.assertEqual(
            subprocess.run(["git", "-C", shallow, "rev-parse", "--is-shallow-repository"],
                           capture_output=True, text=True).stdout.strip(), "true")
        self.work = shallow
        self.assert_everything_ran(self.pre_push(self.new_branch_line(
            sha=self._g(shallow, "rev-parse", "origin/feature"))), "shallow clone")

    def test_always_run_all_gates_switch(self):
        self.assert_everything_ran(self.pre_push(
            self.new_branch_line(), {"CLAGENTIC_ALWAYS_RUN_ALL_GATES": "1"}))

    def test_typoed_switch_value_errs_toward_running(self):
        self.assert_everything_ran(self.pre_push(
            self.new_branch_line(), {"CLAGENTIC_ALWAYS_RUN_ALL_GATES": "true"}))

    def test_pinned_semgrep_ruleset_keeps_sast_running(self):
        ruleset = os.path.join(self.tmp, "rules.yml")
        open(ruleset, "w").close()
        result = self.pre_push(self.new_branch_line(), {"CLAGENTIC_SEMGREP_CONFIG": ruleset})
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.scanners_run(), ["semgrep"])
        self.assertEqual(self.rows("deps")[-1][0], "skipped_out_of_domain")


class TestGateConfigIsInEveryDomain(_PushRepoTestCase):
    def _assert_config_path_runs_everything(self, rel):
        self.write(rel, "x\n")
        self.commit("config")
        self.assert_everything_ran(self.pre_push(self.new_branch_line()))

    def test_repo_clagentic_dir(self):
        self._assert_config_path_runs_everything(".clagentic/osv-ignore")

    def test_reason_is_reported(self):
        self.write(".clagentic/osv-ignore", "GHSA-x\n")
        self.commit("config")
        self.assert_everything_ran(self.pre_push(self.new_branch_line()),
                                   "push touches gate configuration")

    def test_gitleaks_config(self):
        self._assert_config_path_runs_everything(".gitleaks.toml")

    def test_semgrepignore(self):
        self._assert_config_path_runs_everything(".semgrepignore")

    def test_osv_scanner_toml(self):
        self._assert_config_path_runs_everything("osv-scanner.toml")

    def test_config_change_bundled_with_prose_still_runs_everything(self):
        self.write("docs/a.md")
        self.write(".clagentic/semgrep-exclude", "some.rule\n")
        self.commit("both")
        self.assert_everything_ran(self.pre_push(self.new_branch_line()))


class TestDomainPredicates(_PushRepoTestCase):
    def _in(self, gate, path):
        out = self.run_sh(f'_gd_path_in_gate_domain {gate} "{path}" && echo yes || echo no')
        self.assertEqual(out.returncode, 0, msg=out.stderr)
        return out.stdout.strip() == "yes"

    def test_markdown_is_in_neither_scanner_domain(self):
        for path in ("README.md", "docs/a/b.md", "NOTES.txt", "logo.png"):
            self.assertFalse(self._in("deps", path), path)
            self.assertFalse(self._in("sast", path), path)

    def test_manifests_and_lockfiles_are_in_deps_domain(self):
        for path in ("package-lock.json", "a/b/Cargo.lock", "requirements-dev.txt",
                     "go.mod", "app.csproj", "x.cdx.json", "lib/app.jar"):
            self.assertTrue(self._in("deps", path), path)

    def test_code_and_extensionless_files_are_in_sast_domain(self):
        for path in ("a.py", "a/b.TS", "Dockerfile", "bin/tool", ".env", "x.ipynb", "ci.yml"):
            self.assertTrue(self._in("sast", path), path)

    def test_vendored_tree_under_docs_is_in_both_domains(self):
        self.assertTrue(self._in("deps", "docs/vendor/lib/readme.md"))
        self.assertTrue(self._in("sast", "docs/node_modules/x/readme.md"))

    def test_gate_without_declared_domain_takes_every_path(self):
        self.assertTrue(self._in("secrets", "README.md"))
        self.assertTrue(self._in("some-future-gate", "README.md"))

    def test_only_deps_and_sast_are_eligible_to_skip(self):
        for gate, eligible in (("deps", True), ("sast", True), ("secrets", False),
                               ("review", False), ("adversarial", False),
                               ("merge-gate", False), ("bleed", False)):
            out = self.run_sh(f"_gd_gate_eligible_for_skip {gate} && echo yes || echo no")
            self.assertEqual(out.stdout.strip() == "yes", eligible, gate)

    def test_version_compare(self):
        for a, b, expected in (("2.3.0", "2.2.0", "yes"), ("2.2.0", "2.2.0", "no"),
                               ("2.10.0", "2.9.9", "yes"), ("1.130", "1.130.1", "no")):
            out = self.run_sh(f'_gd_version_gt {a} {b} && echo yes || echo no')
            self.assertEqual(out.stdout.strip(), expected, (a, b))


class TestSkipReachesMergeGatePayload(_PushRepoTestCase):
    def test_payload_carries_the_distinct_outcome_not_a_pass(self):
        self.write("docs/guide.md")
        self.commit()
        self.assertEqual(self.pre_push(self.new_branch_line()).returncode, 0)
        out = self.run_sh("_read_deterministic_gates")
        self.assertEqual(out.returncode, 0, msg=out.stderr)
        payload = json.loads(out.stdout)
        for gate in ("deps", "sast"):
            self.assertEqual(payload[gate]["outcome"], "skipped_out_of_domain")
        self.assertIsNone(payload["secrets"])

    def test_merge_gate_prompt_names_the_third_state(self):
        with open(os.path.join(TOOL_HOME, "scripts", "llm-client.sh")) as f:
            prompt = f.read()
        self.assertIn('"skipped_out_of_domain" is a distinct third state', prompt)
        self.assertIn("NOT a pass", prompt)


if __name__ == "__main__":
    unittest.main()
