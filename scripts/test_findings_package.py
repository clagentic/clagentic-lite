"""
Structure and trust tests for the finding pipeline's package layout
(plugins/clagentic-lite/bin/findings.py and clagentic_findings/).

  * the manifest, module sizes and import graph keep the one-module-per-concern
    shape (no module over 800 lines, no import cycle, no reach into a peer's
    private names);
  * the entrypoint loads the package only from its own directory, so a
    hostile checkout in the working directory, or one named by PYTHONPATH, is
    never imported;
  * a copy of the plugin that lost a module fails loudly and closed;
  * the entrypoint works from any directory against an unenrolled repository.

Run with: python3 -m unittest scripts/test_findings_package.py -v
"""
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.findings_test_support import (
    FINDINGS_PY, PIPELINE_PACKAGE_DIR, clean_env, copy_pipeline, make_repo, manifest)

MAX_MODULE_LINES = 800


def module_files():
    return sorted(name for name in os.listdir(PIPELINE_PACKAGE_DIR)
                  if name.endswith(".py") and name != "__init__.py")


def relative_imports(path):
    """(imported sibling module names, imported names that are private)."""
    with open(path) as handle:
        tree = ast.parse(handle.read())
    siblings, private = set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
            siblings.add(node.module)
            private.extend((node.module, alias.name) for alias in node.names
                           if alias.name.startswith("_"))
    return siblings, private


def run_entrypoint(args, cwd=None, env=None, entry=FINDINGS_PY, stdin=None):
    base = clean_env()
    base.update(env or {})
    return subprocess.run([sys.executable, entry] + list(args), input=stdin, capture_output=True,
                          text=True, cwd=cwd, env=base, timeout=120)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-findings-package-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)


class TestPackageShape(unittest.TestCase):
    def test_the_manifest_lists_exactly_the_module_files(self):
        listed = list(manifest())
        self.assertEqual(len(listed), len(set(listed)), "a module is listed twice")
        self.assertEqual(sorted(listed), [name[:-3] for name in module_files()])

    def test_no_module_is_larger_than_the_limit(self):
        for name in module_files():
            with open(os.path.join(PIPELINE_PACKAGE_DIR, name)) as handle:
                lines = sum(1 for _ in handle)
            self.assertLessEqual(lines, MAX_MODULE_LINES, "%s has %d lines" % (name, lines))

    def test_every_module_states_its_one_concern(self):
        for name in module_files():
            with open(os.path.join(PIPELINE_PACKAGE_DIR, name)) as handle:
                self.assertTrue(ast.get_docstring(ast.parse(handle.read())), name)

    def test_there_is_no_import_cycle(self):
        graph = {name[:-3]: relative_imports(os.path.join(PIPELINE_PACKAGE_DIR, name))[0]
                 for name in module_files()}
        for name, targets in graph.items():
            self.assertTrue(targets <= set(graph), (name, targets - set(graph)))
        done, visiting = set(), []

        def visit(node):
            if node in visiting:
                self.fail("import cycle: " + " -> ".join(visiting[visiting.index(node):] + [node]))
            if node in done:
                return
            visiting.append(node)
            for target in sorted(graph[node]):
                visit(target)
            visiting.pop()
            done.add(node)

        for node in sorted(graph):
            visit(node)

    def test_no_module_imports_a_peers_private_name(self):
        for name in module_files():
            _, private = relative_imports(os.path.join(PIPELINE_PACKAGE_DIR, name))
            self.assertEqual(private, [], name)

    def test_no_module_imports_the_package_by_absolute_name(self):
        for name in module_files():
            with open(os.path.join(PIPELINE_PACKAGE_DIR, name)) as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0:
                    self.assertNotEqual((node.module or "").split(".")[0], "clagentic_findings", name)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(alias.name.split(".")[0], "clagentic_findings", name)


class TestEntrypointLoadsOnlyItsOwnPackage(Tmp):
    """The directory the entrypoint runs in is the repository under review."""

    def hostile_tree(self):
        marker = self.path("HOSTILE-IMPORTED")
        evil = self.path("evil")
        os.makedirs(os.path.join(evil, "clagentic_findings"))
        plant = "open(%r, 'a').write('imported %%s\\n' %% __name__)\n" % marker
        with open(os.path.join(evil, "clagentic_findings", "__init__.py"), "w") as handle:
            handle.write(plant + "MODULES = ()\n")
        with open(os.path.join(evil, "clagentic_findings", "cli.py"), "w") as handle:
            handle.write(plant + "def run(argv=None):\n    print('HOSTILE')\n    return 0\n")
        # A same-named top-level module, and a stand-in for the standard library.
        evil_module = self.path("evil-module")
        os.makedirs(evil_module)
        for name in ("clagentic_findings.py", "json.py", "argparse.py"):
            with open(os.path.join(evil_module, name), "w") as handle:
                handle.write(plant + "raise SystemExit(99)\n")
        return marker, evil, evil_module

    def assert_untouched(self, result, marker):
        self.assertEqual((result.returncode, result.stdout), (0, "3\n"), result.stderr)
        self.assertFalse(os.path.exists(marker), "a planted module was imported")

    def test_a_package_in_the_working_directory_is_never_imported(self):
        marker, evil, _ = self.hostile_tree()
        self.assert_untouched(run_entrypoint(["verdict", "rank", "high"], cwd=evil), marker)

    def test_pythonpath_naming_a_hostile_tree_is_never_imported(self):
        marker, evil, evil_module = self.hostile_tree()
        env = {"PYTHONPATH": os.pathsep.join((evil, evil_module))}
        self.assert_untouched(run_entrypoint(["verdict", "rank", "high"], cwd=self.tmp, env=env),
                              marker)

    def test_a_relative_pythonpath_entry_resolved_against_the_hostile_cwd(self):
        marker, evil, _ = self.hostile_tree()
        for entry in (".", "", "clagentic_findings"):
            with self.subTest(entry=entry):
                self.assert_untouched(run_entrypoint(["verdict", "rank", "high"], cwd=evil,
                                                     env={"PYTHONPATH": entry}), marker)

    def test_working_directory_and_pythonpath_together_against_a_real_stage(self):
        marker, evil, evil_module = self.hostile_tree()
        report = self.path("report.md")
        with open(report, "w") as handle:
            handle.write("[FINDING] CWE-78 | a.sh:3 | severity: high | title: shell injection\n")
        result = run_entrypoint(["ingest", "adversarial-parse", report], cwd=evil,
                                env={"PYTHONPATH": os.pathsep.join((evil, evil_module))})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"tier":"blocking"', result.stdout)
        self.assertFalse(os.path.exists(marker), "a planted module was imported")

    def test_a_symlinked_entrypoint_loads_the_package_beside_the_real_file(self):
        link_dir = self.path("elsewhere")
        os.makedirs(link_dir)
        link = os.path.join(link_dir, "findings.py")
        os.symlink(FINDINGS_PY, link)
        result = run_entrypoint(["verdict", "rank", "critical"], cwd=link_dir, entry=link)
        self.assertEqual((result.returncode, result.stdout), (0, "4\n"), result.stderr)

    def test_a_copy_of_the_plugin_runs_from_anywhere(self):
        bin_dir = self.path("plugin", "bin")
        copy_pipeline(bin_dir)
        result = run_entrypoint(["verdict", "rank", "medium"], cwd=self.tmp,
                                entry=os.path.join(bin_dir, "findings.py"))
        self.assertEqual((result.returncode, result.stdout), (0, "2\n"), result.stderr)


class TestAPartialCopyFailsLoudlyAndClosed(Tmp):
    def copy(self):
        bin_dir = self.path("plugin", "bin")
        copy_pipeline(bin_dir)
        return bin_dir, os.path.join(bin_dir, "findings.py")

    def assert_refused(self, result, *needles):
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertEqual(result.stdout, "")
        for needle in needles:
            self.assertIn(needle, result.stderr)

    def test_a_missing_module_is_named(self):
        bin_dir, entry = self.copy()
        os.unlink(os.path.join(bin_dir, "clagentic_findings", "rubric.py"))
        self.assert_refused(run_entrypoint(["verdict", "rank", "high"], entry=entry),
                            "rubric", "incomplete")

    def test_every_listed_module_is_required(self):
        for name in manifest():
            with self.subTest(module=name):
                bin_dir, entry = self.copy()
                os.unlink(os.path.join(bin_dir, "clagentic_findings", name + ".py"))
                self.assert_refused(run_entrypoint(["verdict", "rank", "high"], entry=entry), name)
                shutil.rmtree(self.path("plugin"))

    def test_a_missing_package_directory_is_refused(self):
        bin_dir, entry = self.copy()
        shutil.rmtree(os.path.join(bin_dir, "clagentic_findings"))
        self.assert_refused(run_entrypoint(["verdict", "rank", "high"], entry=entry),
                            "cannot be loaded")

    def test_a_missing_package_marker_is_refused(self):
        bin_dir, entry = self.copy()
        os.unlink(os.path.join(bin_dir, "clagentic_findings", "__init__.py"))
        self.assert_refused(run_entrypoint(["verdict", "rank", "high"], entry=entry),
                            "cannot be loaded")

    def test_a_damaged_module_is_refused(self):
        bin_dir, entry = self.copy()
        with open(os.path.join(bin_dir, "clagentic_findings", "severity.py"), "w") as handle:
            handle.write("def broken(:\n")
        self.assert_refused(run_entrypoint(["verdict", "rank", "high"], entry=entry),
                            "SyntaxError")

    def test_a_crash_inside_a_stage_keeps_status_70(self):
        bin_dir, entry = self.copy()
        cli_path = os.path.join(bin_dir, "clagentic_findings", "cli.py")
        with open(cli_path) as handle:
            source = handle.read()
        marker = "def main(argv=None):\n"
        self.assertIn(marker, source)
        with open(cli_path, "w") as handle:
            handle.write(source.replace(marker, marker + "    raise RuntimeError('boom')\n", 1))
        result = run_entrypoint(["verdict", "rank", "high"], entry=entry)
        self.assertEqual((result.returncode, result.stdout), (70, ""))
        self.assertIn("RuntimeError: boom", result.stderr)

    def test_a_crash_in_the_entrypoint_handler_path_exits_70_not_1(self):
        bin_dir, entry = self.copy()
        cli_path = os.path.join(bin_dir, "clagentic_findings", "cli.py")
        with open(cli_path, "a") as handle:
            handle.write("\n\ndef run(argv=None):\n    raise RuntimeError('boom-run')\n")
        result = run_entrypoint(["verdict", "rank", "high"], entry=entry)
        self.assertEqual((result.returncode, result.stdout), (70, ""))
        self.assertIn("RuntimeError: boom-run", result.stderr)

    def test_a_system_exit_from_run_passes_through_unchanged(self):
        bin_dir, entry = self.copy()
        cli_path = os.path.join(bin_dir, "clagentic_findings", "cli.py")
        with open(cli_path, "a") as handle:
            handle.write("\n\ndef run(argv=None):\n    raise SystemExit(2)\n")
        result = run_entrypoint(["verdict", "rank", "high"], entry=entry)
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_any_exception_type_raised_while_loading_is_refused_with_70(self):
        for exc in ("RuntimeError('boom-load')", "ValueError('bad')", "ZeroDivisionError()"):
            with self.subTest(exc=exc):
                bin_dir, entry = self.copy()
                with open(os.path.join(bin_dir, "clagentic_findings", "severity.py"), "a") as handle:
                    handle.write("\nraise %s\n" % exc)
                self.assert_refused(run_entrypoint(["verdict", "rank", "high"], entry=entry),
                                    "cannot be loaded", exc.split("(")[0])
                shutil.rmtree(self.path("plugin"))


class TestStandaloneInAnUnenrolledRepository(Tmp):
    def test_the_entrypoint_gives_a_verdict_from_a_copy_far_from_any_install(self):
        bin_dir = self.path("plugin", "bin")
        copy_pipeline(bin_dir)
        repo = make_repo(self.path("repo"))
        before = sorted(os.listdir(repo))
        result = run_entrypoint(["evaluate", "--gate", "review", "--no-input"], cwd=repo,
                                entry=os.path.join(bin_dir, "findings.py"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("VERDICT: PASS"), result.stdout)
        # A read-only stage leaves the repository's top level exactly as it was.
        self.assertEqual([n for n in sorted(os.listdir(repo)) if n not in before], [])

    def test_a_blocking_finding_blocks_and_exits_1(self):
        repo = make_repo(self.path("repo"))
        envelope = '[{"severity_claimed": "low", "file": "app.py", "line": 1, "category": "security", ' \
                   '"message": "m", "reachable": "yes", "attacker_precondition": "none", ' \
                   '"impact": "code_exec", "class": "durable"}]'
        result = run_entrypoint(["evaluate", "--gate", "review", "--caller", "standalone"],
                                cwd=repo, stdin=envelope)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(result.stdout.startswith("VERDICT: BLOCKED"), result.stdout)


if __name__ == "__main__":
    unittest.main()
