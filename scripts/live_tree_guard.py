"""
Suite-level guard: a test run must not create or modify anything under the live
checkout's .clagentic/ or .claude/ directories (tracked, untracked or ignored).

Those trees hold the checkout's own audit.db, rendered plugin and hook scripts.
A test that sources gates.sh / llm-client.sh or runs bin/clagentic-lite with the
project root, tool home or HOME pointing at this checkout writes into them, and
an `init`/`enroll`/`update` aimed at the live tree is the destructive hazard
class CLAUDE.local.md describes. scripts/isolated_env.py is the sanctioned way
to avoid it; this guard is the net that catches a test that did not use it.

The comparison keys on (size, mtime_ns) of every file. Directories count only
by presence, because a directory's mtime moves whenever a child is touched and
the child is already reported. Deletions are not reported: a run that cleans
up pre-existing litter has not polluted the tree.

Attribution: each test's wall-clock window is recorded and a changed file is
blamed on the test whose window could hold the write that stamped its mtime.
Under pytest-xdist the writer may be a test on another worker; that worker's
own report names it, and this one says so.

make_guard_fixtures() builds the pytest fixture pair so scripts/conftest.py and
the proof-it-fires test share one implementation.
"""
import os
import time

import pytest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GUARDED_DIRS = (".clagentic", ".claude")
# The filesystem stamps mtimes from a coarse clock that lags time_ns() by up to
# a few milliseconds (a scheduler tick); the margin keeps a write at a window
# edge attributable to its window.
MTIME_LAG_NS = 20_000_000


def snapshot(root, guarded=GUARDED_DIRS):
    """{absolute path: ("dir",) or ("file", size, mtime_ns)} for everything under
    the guarded directories of ROOT, ignored files included."""
    state = {}
    for name in guarded:
        top = os.path.join(root, name)
        if not os.path.isdir(top):
            continue
        state[top] = ("dir",)
        for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
            for entry in dirnames:
                state[os.path.join(dirpath, entry)] = ("dir",)
            for entry in filenames:
                path = os.path.join(dirpath, entry)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                state[path] = ("file", info.st_size, info.st_mtime_ns)
    return state


def changes(before, after):
    """Sorted [(path, "created" | "modified")] between two snapshots."""
    found = []
    for path, now in after.items():
        was = before.get(path)
        if was is None:
            found.append((path, "created"))
        elif was != now:
            found.append((path, "modified"))
    return sorted(found)


def attribute(after, path, windows):
    """Node ids of the tests whose window could hold the write that gave PATH
    its mtime: the stamp lags the write by up to MTIME_LAG_NS, so the write fell
    in [mtime, mtime + lag]. Usually one; adjacent sub-lag tests all appear."""
    entry = after.get(path)
    if entry is None or entry[0] != "file":
        return []
    mtime = entry[2]
    return [nodeid for start, end, nodeid in windows
            if start <= mtime + MTIME_LAG_NS and end >= mtime]


def describe(found, after, windows, root):
    lines = ["the test run changed the live checkout (%s):" % root]
    for path, kind in found:
        culprits = attribute(after, path, windows)
        culprit = " | ".join(culprits) if culprits else (
            "not on this worker (another xdist worker, or between tests)")
        lines.append("  %s: %s (written during: %s)" % (kind, os.path.relpath(path, root), culprit))
    lines.append("Route the test through scripts/isolated_env.py so CLAGENTIC_PROJECT_ROOT, "
                 "CLAGENTIC_LITE_HOME and HOME point at temp dirs.")
    return "\n".join(lines)


def make_guard_fixtures(root=TOOL_HOME, guarded=GUARDED_DIRS):
    """(session_fixture, per_test_fixture), both autouse. The session fixture
    snapshots before the first test and owns the failure; the per-test fixture
    only records each test's time window for attribution."""
    windows = []

    @pytest.fixture(scope="session", autouse=True)
    def live_tree_guard():
        before = snapshot(root, guarded)
        yield
        after = snapshot(root, guarded)
        found = changes(before, after)
        if found:
            pytest.fail(describe(found, after, windows, root), pytrace=False)

    @pytest.fixture(autouse=True)
    def live_tree_window(request, live_tree_guard):
        start = time.time_ns()
        yield
        windows.append((start, time.time_ns(), request.node.nodeid))

    return live_tree_guard, live_tree_window
