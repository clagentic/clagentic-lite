"""
The isolation fixture (scripts/isolated_env.py) really isolates, and no test
file reintroduces the pattern it replaces.

Run with: python3 -m unittest scripts.test_isolated_env -v
"""
import ast
import glob
import importlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from isolated_env import (  # noqa: E402
    IsolatedEnv, points_at_live_checkout, shared_cli, shared_env, shared_home,
    shared_project, shared_tool_home)
from test_support import TOOL_HOME  # noqa: E402

AMBIENT = {
    "GIT_DIR": "/nonexistent-git-dir",
    "GIT_INDEX_FILE": "/nonexistent-index",
    "CLAGENTIC_PROJECT_ROOT": TOOL_HOME,
    "CLAGENTIC_LITE_HOME": TOOL_HOME,
    "CLAGENTIC_ROUTER_URL": "http://127.0.0.1:1",
    "XDG_CONFIG_HOME": "/nonexistent-xdg",
}


class TestIsolatedEnv(unittest.TestCase):
    def test_env_points_all_three_locations_at_temp_dirs(self):
        iso = IsolatedEnv.for_test(self)
        with mock.patch.dict(os.environ, AMBIENT):
            env = iso.env()
        self.assertFalse(points_at_live_checkout(env))
        for key in ("HOME", "CLAGENTIC_PROJECT_ROOT", "CLAGENTIC_LITE_HOME"):
            self.assertTrue(env[key].startswith(iso.root), (key, env[key]))

    def test_env_drops_variables_that_redirect_git_or_the_tool(self):
        iso = IsolatedEnv.for_test(self)
        with mock.patch.dict(os.environ, AMBIENT):
            env = iso.env()
        for key in ("GIT_DIR", "GIT_INDEX_FILE", "CLAGENTIC_ROUTER_URL", "XDG_CONFIG_HOME"):
            self.assertNotIn(key, env)

    def test_extra_wins_and_project_can_be_replaced(self):
        iso = IsolatedEnv.for_test(self)
        env = iso.env(project="/elsewhere", CLAGENTIC_FOO="1")
        self.assertEqual(env["CLAGENTIC_PROJECT_ROOT"], "/elsewhere")
        self.assertEqual(env["CLAGENTIC_FOO"], "1")

    def test_project_is_a_git_repository(self):
        iso = IsolatedEnv.for_test(self)
        self.assertTrue(os.path.isdir(os.path.join(iso.project, ".git")))

    def test_cloned_tool_home_is_a_distinct_runnable_copy(self):
        iso = IsolatedEnv.for_test(self, clone_tool_home=True)
        self.assertTrue(os.access(iso.cli, os.X_OK), iso.cli)
        self.assertNotEqual(os.path.realpath(iso.tool_home), os.path.realpath(TOOL_HOME))

    def test_cleanup_removes_what_it_created(self):
        iso = IsolatedEnv()
        iso.cleanup()
        self.assertFalse(os.path.exists(iso.root))


class TestSharedEnv(unittest.TestCase):
    def test_shared_pair_is_not_the_live_checkout(self):
        with mock.patch.dict(os.environ, AMBIENT):
            env = shared_env(project=shared_project())
        self.assertFalse(points_at_live_checkout(env))
        self.assertEqual(env["HOME"], shared_home())
        self.assertEqual(env["CLAGENTIC_LITE_HOME"], shared_tool_home())
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("CLAGENTIC_ROUTER_URL", env)

    def test_project_root_is_left_unset_unless_given(self):
        with mock.patch.dict(os.environ, AMBIENT):
            self.assertNotIn("CLAGENTIC_PROJECT_ROOT", shared_env())

    def test_the_shared_cli_runs_from_the_clone_not_the_live_tree(self):
        self.assertTrue(shared_cli().startswith(shared_tool_home()))
        self.assertTrue(os.access(shared_cli(), os.X_OK))

    def test_shared_clone_carries_uncommitted_tracked_edits(self):
        # The overlay is what makes a test exercise the change under review.
        live = os.path.join(TOOL_HOME, "scripts", "gates.sh")
        copy = os.path.join(shared_tool_home(), "scripts", "gates.sh")
        with open(live) as a, open(copy) as b:
            self.assertEqual(a.read(), b.read())


class TestOneModuleObjectPerSpelling(unittest.TestCase):
    """`isolated_env` and `scripts.isolated_env` must be one module, or the
    shared-clone cache is built once per spelling."""

    MODULES = ("isolated_env", "test_support", "findings_test_support")

    def test_both_spellings_resolve_to_one_object(self):
        if TOOL_HOME not in sys.path:
            sys.path.insert(0, TOOL_HOME)
        for name in self.MODULES:
            bare = importlib.import_module(name)
            qualified = importlib.import_module("scripts." + name)
            self.assertIs(bare, qualified, name)

    def test_the_shared_clone_is_built_once_across_spellings(self):
        if TOOL_HOME not in sys.path:
            sys.path.insert(0, TOOL_HOME)
        bare = importlib.import_module("isolated_env")
        qualified = importlib.import_module("scripts.isolated_env")
        self.assertEqual(bare.shared_tool_home(), qualified.shared_tool_home())
        self.assertIs(bare._shared_clone, qualified._shared_clone)


# --------------------------------------------------------------------------
# Sweep detector. AST-based: it sees through quoting, spacing, keyword
# arguments and simple aliases (X = TOOL_HOME), none of which a line regex does.
# It is still a HEURISTIC: it follows names within one file and does not follow
# a live path through a function argument or another module. The hard backstop
# is scripts/live_tree_guard.py, which fails the run on any actual write.
# --------------------------------------------------------------------------
LIVE_SEEDS = {"TOOL_HOME", "_TOOL_HOME", "REPO_ROOT", "REPO"}
HOME_KEY = "CLAGENTIC_LITE_HOME"
_PATH_WRAPPERS = {"abspath", "realpath", "normpath"}


def _strip_wrappers(node):
    while (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
           and node.func.attr in _PATH_WRAPPERS and len(node.args) == 1):
        node = node.args[0]
    return node


def _is_repo_root_expr(node):
    """os.path.join(os.path.dirname(__file__), "..") and dirname(dirname(...))."""
    node = _strip_wrappers(node)
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr == "join" and len(node.args) == 2:
        last = node.args[1]
        return (isinstance(last, ast.Constant) and last.value == ".."
                and "__file__" in ast.unparse(node.args[0]))
    if node.func.attr == "dirname" and len(node.args) == 1:
        inner = _strip_wrappers(node.args[0])
        return (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "dirname" and "__file__" in ast.unparse(inner))
    return False


def _is_live(node, live):
    node = _strip_wrappers(node)
    return isinstance(node, ast.Name) and node.id in live


def _live_names(tree):
    live = set(LIVE_SEEDS)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in LIVE_SEEDS:
                    live.add(alias.asname or alias.name)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not (_is_live(node.value, live) or _is_repo_root_expr(node.value)):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in live:
                    live.add(target.id)
                    changed = True
    return live


def _is_home_key(node):
    return isinstance(node, ast.Constant) and node.value == HOME_KEY


def _is_live_cwd(node, live):
    if _is_live(node, live):
        return True
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join" and bool(node.args) and _is_live(node.args[0], live))


def live_tree_uses(source):
    """[(kind, lineno)] for each place SOURCE hands the live checkout to a child:
    kind "tool-home" (CLAGENTIC_LITE_HOME = live path) or "cwd" (cwd = live path)."""
    tree = ast.parse(source)
    live = _live_names(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is not None and _is_home_key(key) and _is_live(value, live):
                    found.append(("tool-home", value.lineno))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Subscript) and _is_home_key(target.slice)
                        and _is_live(node.value, live)):
                    found.append(("tool-home", node.lineno))
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == HOME_KEY and _is_live(kw.value, live):
                    found.append(("tool-home", kw.value.lineno))
                if kw.arg == "cwd" and _is_live_cwd(kw.value, live):
                    found.append(("cwd", kw.value.lineno))
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "setdefault"
                    and len(node.args) == 2 and _is_home_key(node.args[0])
                    and _is_live(node.args[1], live)):
                found.append(("tool-home", node.lineno))
    return found


class TestLiveTreeDetector(unittest.TestCase):
    """The detector flags every spelling the old line regexes missed."""

    def kinds(self, source):
        return sorted(kind for kind, _ in live_tree_uses(source))

    def test_flags_subscript_assignment_in_either_quote_style(self):
        self.assertEqual(self.kinds('env["CLAGENTIC_LITE_HOME"] = TOOL_HOME'), ["tool-home"])
        self.assertEqual(self.kinds("env['CLAGENTIC_LITE_HOME'] = TOOL_HOME"), ["tool-home"])

    def test_flags_dict_literals_and_keyword_arguments(self):
        self.assertEqual(self.kinds("e = {'CLAGENTIC_LITE_HOME': TOOL_HOME}"), ["tool-home"])
        self.assertEqual(self.kinds("e.update(CLAGENTIC_LITE_HOME=TOOL_HOME)"), ["tool-home"])
        self.assertEqual(self.kinds("dict(os.environ, CLAGENTIC_LITE_HOME=TOOL_HOME)"),
                         ["tool-home"])
        self.assertEqual(self.kinds("e.setdefault('CLAGENTIC_LITE_HOME', TOOL_HOME)"),
                         ["tool-home"])

    def test_follows_aliases_and_a_locally_defined_repo_root(self):
        self.assertEqual(self.kinds("R = TOOL_HOME\nenv['CLAGENTIC_LITE_HOME'] = R"),
                         ["tool-home"])
        self.assertEqual(self.kinds("R = os.path.realpath(TOOL_HOME)\nf(cwd=R)"), ["cwd"])
        self.assertEqual(
            self.kinds("ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))\n"
                       "f(cwd = ROOT)"), ["cwd"])
        self.assertEqual(self.kinds("from test_support import TOOL_HOME as T\nf(cwd=T)"), ["cwd"])

    def test_flags_cwd_in_any_spacing_and_under_a_join(self):
        self.assertEqual(self.kinds("f(cwd = TOOL_HOME)"), ["cwd"])
        self.assertEqual(self.kinds("f(cwd=os.path.join(TOOL_HOME, 'x'))"), ["cwd"])

    def test_ignores_temp_paths_and_unrelated_joins(self):
        self.assertEqual(self.kinds("env['CLAGENTIC_LITE_HOME'] = iso.tool_home"), [])
        self.assertEqual(self.kinds("f(cwd=tmp)\nG = os.path.join(TOOL_HOME, 'x')\nf(cwd=G)"), [])
        self.assertEqual(self.kinds("S = os.path.join(os.path.dirname(__file__), 'fixtures')\n"
                                    "f(cwd=S)"), [])


class TestNoTestAimsTheCliAtTheLiveTree(unittest.TestCase):
    """Sweep: discovery is by glob, not a list. A test that hands the live
    checkout to the CLI as its tool home runs init/enroll/update/render against
    it (CLAUDE.local.md fact 2)."""

    # A child run with the live checkout as its cwd resolves the project root,
    # the repository config it then sources, and audit.db from it. These files
    # use that cwd on purpose: read-only `git` history queries about this
    # repository, a file listing, and one test that asserts the tool is NOT
    # located through the working directory.
    LIVE_CWD_ALLOWED = {
        "test_findings_call_primitive.py",
        "test_llm_client_consumer_sweep.py",
        "test_secrets_positive_control.py",
    }

    def offenders(self, kind, allowed=()):
        found = []
        for path in sorted(glob.glob(os.path.join(TOOL_HOME, "scripts", "test_*.py"))):
            if os.path.samefile(path, __file__) or os.path.basename(path) in allowed:
                continue
            with open(path) as handle:
                source = handle.read()
            lines = source.splitlines()
            for found_kind, number in live_tree_uses(source):
                if found_kind == kind:
                    found.append("%s:%d: %s" % (os.path.relpath(path, TOOL_HOME), number,
                                                lines[number - 1].strip()))
        return found

    def test_no_test_sets_the_tool_home_to_the_live_checkout(self):
        self.assertEqual(self.offenders("tool-home"), [])

    def test_no_test_runs_a_child_with_the_live_checkout_as_its_cwd(self):
        self.assertEqual(self.offenders("cwd", self.LIVE_CWD_ALLOWED), [])


if __name__ == "__main__":
    unittest.main()
