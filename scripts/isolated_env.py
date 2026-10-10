"""
The one fixture for tests that source gates.sh / llm-client.sh / platform.sh,
run findings.py, or run bin/clagentic-lite (including init/enroll/update/render).

Each of those reads three locations from its environment and WRITES under them:
the project root (audit.db, ledgers), CLAGENTIC_LITE_HOME (rendered plugin,
materialized hook scripts, `update`'s stash/checkout) and HOME (global config,
registry, plugin cache). Left unset they resolve to THIS checkout, so a test
that forgets one litters the live tree or, for init/enroll/update, runs the
destructive hazard CLAUDE.local.md describes. IsolatedEnv provisions all three
under a temp directory and strips the variables that redirect git or the tool
(GIT_*, CLAGENTIC_*) out of the child environment.

    iso = IsolatedEnv.for_test(self)                 # sourcing a script
    env = iso.env(); env.update(source_env(gates=True))
    subprocess.run([...], env=env, cwd=iso.project)

    iso = IsolatedEnv.for_test(self, clone_tool_home=True)   # running the CLI
    subprocess.run([iso.cli, "init"], env=iso.env(), cwd=iso.project)

clone_tool_home=True makes CLAGENTIC_LITE_HOME a throwaway clone of this
checkout with the on-disk (possibly uncommitted) tracked files overlaid, so the
CLI under test is the code under review and `update` can only ever discard
inside the clone (set CLAGENTIC_UPDATE_ALLOW_DISCARD=1 for that, see
test_support.py). Without it CLAGENTIC_LITE_HOME is an empty temp directory:
enough for sourcing tests, since platform.sh finds the install from the
sourced script's own location first.

scripts/live_tree_guard.py is the net that fails the run if a test still
writes to the live checkout.
"""
import atexit
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from findings_test_support import clean_env, make_repo  # noqa: E402
from test_support import TOOL_HOME, clone_this_tool_home_with_overlay  # noqa: E402

# Variables that point a child at a config or state location outside HOME.
_REDIRECTS = ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")


class IsolatedEnv:
    def __init__(self, root=None, clone_tool_home=False, git_project=True):
        self._owns_root = root is None
        self.root = root if root is not None else tempfile.mkdtemp(prefix="clagentic-test-iso-")
        self.home = self._mkdir("iso-home")
        self.project = os.path.join(self.root, "iso-project")
        if git_project:
            make_repo(self.project)
        else:
            os.makedirs(self.project, exist_ok=True)
        self.tool_home = os.path.join(self.root, "iso-tool-home")
        if clone_tool_home:
            clone_this_tool_home_with_overlay(self.tool_home)
        else:
            os.makedirs(self.tool_home, exist_ok=True)

    @classmethod
    def for_test(cls, case, **kwargs):
        """An IsolatedEnv under a fresh temp dir, removed when CASE finishes."""
        iso = cls(**kwargs)
        case.addCleanup(iso.cleanup)
        return iso

    @property
    def cli(self):
        return os.path.join(self.tool_home, "bin", "clagentic-lite")

    def _mkdir(self, name):
        path = os.path.join(self.root, name)
        os.makedirs(path, exist_ok=True)
        return path

    def env(self, project=None, **extra):
        """Child environment: the caller's minus GIT_* and CLAGENTIC_*, with the
        project root, tool home and HOME pointed at this fixture. PROJECT picks a
        different project root (a repo the test built itself); EXTRA wins over
        everything."""
        env = clean_env()
        for name in _REDIRECTS:
            env.pop(name, None)
        env["HOME"] = self.home
        env["CLAGENTIC_PROJECT_ROOT"] = project if project is not None else self.project
        env["CLAGENTIC_LITE_HOME"] = self.tool_home
        env.update(extra)
        return env

    def cleanup(self):
        if self._owns_root:
            shutil.rmtree(self.root, ignore_errors=True)


_shared_clone = []


def shared_tool_home():
    """A per-process throwaway clone of this checkout (with the on-disk tracked
    files overlaid), built on first use and removed at interpreter exit.

    For modules whose tests run the CLI at module level (a `_run_cli` helper with
    no per-test setup): point CLAGENTIC_LITE_HOME at it and run
    shared_cli(), never bin/clagentic-lite from the live tree (an invocation by
    its own path is how the CLI resolves its home). It is shared, so a test that
    runs `update`, or needs a pristine tree, builds its own with
    IsolatedEnv(clone_tool_home=True)."""
    if not _shared_clone:
        root = tempfile.mkdtemp(prefix="clagentic-test-shared-home-")
        atexit.register(shutil.rmtree, root, True)
        dest = os.path.join(root, "tool-home")
        clone_this_tool_home_with_overlay(dest)
        _shared_clone.append(dest)
    return _shared_clone[0]


def shared_cli():
    return os.path.join(shared_tool_home(), "bin", "clagentic-lite")


def shared_home():
    """A per-process HOME that sits beside shared_tool_home(). Shared, so for
    tests that only read from it or tolerate leftovers; a test that writes the
    global config or registry builds its own HOME."""
    path = os.path.join(os.path.dirname(shared_tool_home()), "home")
    os.makedirs(path, exist_ok=True)
    return path


def shared_project():
    """A per-process throwaway git repository, for sourcing tests that need a
    project root and cwd but keep their own fixtures elsewhere. Shared, so a
    test that asserts on state under the project (audit.db, ledgers) must use
    its own directory instead."""
    path = os.path.join(os.path.dirname(shared_tool_home()), "project")
    if not os.path.isdir(os.path.join(path, ".git")):
        make_repo(path)
    return path


def shared_env(project=None, **extra):
    """Child environment for module-level helpers that have no per-test fixture:
    the caller's minus GIT_* and CLAGENTIC_*, HOME and CLAGENTIC_LITE_HOME at the
    shared throwaway pair, and CLAGENTIC_PROJECT_ROOT at PROJECT when given
    (otherwise unset, so the child resolves the project from its cwd, which the
    caller must have pointed at a temp repo)."""
    env = clean_env()
    for name in _REDIRECTS:
        env.pop(name, None)
    env["HOME"] = shared_home()
    env["CLAGENTIC_LITE_HOME"] = shared_tool_home()
    if project is not None:
        env["CLAGENTIC_PROJECT_ROOT"] = project
    env.update(extra)
    return env


def points_at_live_checkout(env):
    """True when ENV would aim any of the three locations at this checkout."""
    live = os.path.realpath(TOOL_HOME)
    for key in ("HOME", "CLAGENTIC_PROJECT_ROOT", "CLAGENTIC_LITE_HOME"):
        value = env.get(key)
        if value and os.path.realpath(value) == live:
            return True
    return False
