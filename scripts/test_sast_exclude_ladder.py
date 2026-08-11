"""
Regression coverage for the semgrep SAST rule-exclude ladder and pinned-
config override (lr-321e18).

cmd_sast (scripts/gates.sh) had zero repo-side override surface for a single
unsatisfiable registry rule -- one false-positive finding (e.g.
python.sqlalchemy.security.sqlalchemy-execute-raw-query, which rejects even
injection-safe parameterized/sql.Identifier composition) forced multi-round
review churn with no sanctioned escape.

The task's five acceptance criteria are framed as runtime assertions ("when
gates.sh sast runs..."). Per task correction, this suite verifies the
factored, testable units instead of executing gates.sh's `sast` subcommand
(which never runs on this host by design -- clagentic-lite is developed
here, not run here): `_sast_exclude_rule_flags` (the two-level ladder
parser, mirroring cmd_deps' osv-ignore mechanism exactly) and
`_sast_config_flag` (the --config=auto/CLAGENTIC_SEMGREP_CONFIG switch).
Both are sourced directly from gates.sh and exercised as real shell
functions, same technique test_ds_sqlite3.py established for ds_sqlite3:
prove the actual argv shape, not merely that the code "looks like" it
should produce one.

Run with: python3 -m unittest scripts.test_sast_exclude_ladder -v
"""
import os
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")
GATES_SH = os.path.join(TOOL_HOME, "scripts", "gates.sh")

# _sast_exclude_rule_flags and _sast_config_flag are plain functions with no
# REPO_ROOT/AUDIT_DB dependency, but gates.sh itself requires a resolvable
# git repo at source time (REPO_ROOT resolution, :42-47) and `set -e`. Source
# platform.sh (the real dependency both functions need: none, in fact -- they
# use no platform.sh helper) is not required either; we extract and source
# ONLY the two function definitions via a tiny wrapper script, so this suite
# never needs a git repo, a fake semgrep binary, or gates.sh's own top-level
# dispatch -- exactly the "factor so it's testable without executing the
# gate" instruction.
_HELPER_MARKER_START = "_sast_exclude_rule_flags() {"
_HELPER_MARKER_END = "\ncmd_sast() {"


def _extract_helpers():
    with open(GATES_SH) as f:
        content = f.read()
    start = content.index("# _sast_exclude_rule_flags")
    end = content.index(_HELPER_MARKER_END)
    assert _HELPER_MARKER_START in content[start:end], (
        "extraction marker drifted -- _sast_exclude_rule_flags definition "
        "not found between the expected markers; update this test's anchors"
    )
    return content[start:end]


class _HelperTestBase(unittest.TestCase):
    """Shared sourcing/exec plumbing for both helper functions."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-sast-excl-")
        self._helpers_sh = os.path.join(self._tmp, "sast-helpers.sh")
        with open(self._helpers_sh, "w") as f:
            f.write("#!/bin/sh\n")
            f.write(_extract_helpers())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, script_body, extra_env=None):
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        script = textwrap.dedent(f"""\
            . '{self._helpers_sh}'
            {script_body}
        """)
        return subprocess.run(
            ["sh", "-c", script, "sast-helpers-test"],
            capture_output=True, text=True, env=env,
        )

    def _write_exclude_file(self, path, lines):
        with open(path, "w") as f:
            f.write(lines)


class TestExcludeRuleFlags(_HelperTestBase):
    """_sast_exclude_rule_flags GLOBAL_FILE REPO_FILE -- the ladder parser."""

    def test_rule_id_in_exclude_file_produces_exclude_rule_flag(self):
        repo_file = os.path.join(self._tmp, "repo-exclude")
        self._write_exclude_file(repo_file, "python.sqlalchemy.security.sqlalchemy-execute-raw-query\n")
        result = self._run(
            f"_sast_exclude_rule_flags /nonexistent-global '{repo_file}'"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertIn("--exclude-rule", lines)
        self.assertIn("python.sqlalchemy.security.sqlalchemy-execute-raw-query", lines)

    def test_no_exclude_files_produces_no_flags(self):
        """Critical no-regression precondition: absent ladder files must
        produce zero output, so cmd_sast's reconstructed argv gets no
        --exclude-rule tokens at all in the default case."""
        result = self._run(
            "_sast_exclude_rule_flags /nonexistent-global /nonexistent-repo"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "", f"expected empty output, got {result.stdout!r}")

    def test_malformed_comment_blank_whitespace_lines_skipped(self):
        """Same tolerance as osv-ignore's parser: '' and '#'-prefixed lines
        are skipped outright; a trailing comment and trailing whitespace are
        stripped from an otherwise-valid line."""
        repo_file = os.path.join(self._tmp, "repo-exclude")
        self._write_exclude_file(repo_file, textwrap.dedent("""\
            # a full-line comment


            real.rule.id   # trailing comment
            another.rule.id
        """))
        result = self._run(
            f"_sast_exclude_rule_flags /nonexistent-global '{repo_file}'"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(
            lines,
            ["--exclude-rule", "real.rule.id", "--exclude-rule", "another.rule.id"],
            f"unexpected parse of malformed/comment/blank/whitespace lines: {lines!r}",
        )

    def test_global_and_repo_both_present_produce_union(self):
        global_file = os.path.join(self._tmp, "global-exclude")
        repo_file = os.path.join(self._tmp, "repo-exclude")
        self._write_exclude_file(global_file, "global.rule.one\n")
        self._write_exclude_file(repo_file, "repo.rule.two\n")
        result = self._run(
            f"_sast_exclude_rule_flags '{global_file}' '{repo_file}'"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(
            lines,
            ["--exclude-rule", "global.rule.one", "--exclude-rule", "repo.rule.two"],
            f"expected union of both ladder levels, got {lines!r}",
        )


class TestConfigFlag(_HelperTestBase):
    """_sast_config_flag -- the --config=auto / CLAGENTIC_SEMGREP_CONFIG switch."""

    def test_default_is_config_auto(self):
        result = self._run("_sast_config_flag", extra_env={"CLAGENTIC_SEMGREP_CONFIG": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "--config=auto\n")

    def test_unset_env_var_is_config_auto(self):
        env = os.environ.copy()
        env.pop("CLAGENTIC_SEMGREP_CONFIG", None)
        result = subprocess.run(
            ["sh", "-c", f". '{self._helpers_sh}'\n_sast_config_flag", "sast-helpers-test"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "--config=auto\n")

    def test_configured_path_replaces_auto(self):
        result = self._run(
            "_sast_config_flag",
            extra_env={"CLAGENTIC_SEMGREP_CONFIG": "/repo/.clagentic/semgrep-policy.yml"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "--config\n/repo/.clagentic/semgrep-policy.yml\n")
        self.assertNotIn("auto", result.stdout)


class TestNoRegressionArgvReconstruction(_HelperTestBase):
    """Reconstructs cmd_sast's own `set -- $(_sast_config_flag); ... while
    read _sast_exclude_rule_flags` argv-building sequence (mirroring
    scripts/gates.sh's cmd_sast body) to prove the CRITICAL no-regression
    property: no exclude files and no CLAGENTIC_SEMGREP_CONFIG produces an
    argv byte-identical to the pre-lr-321e18 invocation
    (`semgrep --config=auto --error --severity=ERROR`)."""

    def test_no_excludes_no_config_env_reconstructs_prior_argv_exactly(self):
        script = textwrap.dedent("""\
            set --
            while IFS= read -r tok; do
              [ -n "$tok" ] || continue
              set -- "$@" "$tok"
            done <<EOF_CFG
$(_sast_config_flag)
EOF_CFG
            while IFS= read -r tok; do
              [ -n "$tok" ] || continue
              set -- "$@" "$tok"
            done <<EOF_EXCL
$(_sast_exclude_rule_flags /nonexistent-global /nonexistent-repo)
EOF_EXCL
            printf 'semgrep %s --error --severity=ERROR\\n' "$*"
        """)
        result = self._run(script, extra_env={"CLAGENTIC_SEMGREP_CONFIG": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "semgrep --config=auto --error --severity=ERROR",
            f"argv regressed from the pre-lr-321e18 invocation: {result.stdout!r}",
        )

    def test_exclude_and_config_both_active_produce_expected_argv(self):
        repo_file = os.path.join(self._tmp, "repo-exclude")
        self._write_exclude_file(repo_file, "python.sqlalchemy.security.sqlalchemy-execute-raw-query\n")
        script = textwrap.dedent(f"""\
            set --
            while IFS= read -r tok; do
              [ -n "$tok" ] || continue
              set -- "$@" "$tok"
            done <<EOF_CFG
$(_sast_config_flag)
EOF_CFG
            while IFS= read -r tok; do
              [ -n "$tok" ] || continue
              set -- "$@" "$tok"
            done <<EOF_EXCL
$(_sast_exclude_rule_flags /nonexistent-global '{repo_file}')
EOF_EXCL
            printf 'semgrep %s --error --severity=ERROR\\n' "$*"
        """)
        result = self._run(
            script,
            extra_env={"CLAGENTIC_SEMGREP_CONFIG": "/repo/.clagentic/policy.yml"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            "semgrep --config /repo/.clagentic/policy.yml --exclude-rule "
            "python.sqlalchemy.security.sqlalchemy-execute-raw-query "
            "--error --severity=ERROR",
        )


if __name__ == "__main__":
    unittest.main()
