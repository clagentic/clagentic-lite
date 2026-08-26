"""
Shared throwaway-clone helper for tests that run a real subprocess (CLI or
gates.sh) against a git clone of this checkout, never the live tree itself
(TEST HAZARD: no test may point CLAGENTIC_LITE_HOME/HOME at this checkout).

`git clone` of a local path only ever picks up COMMITTED history -- it is
blind to an uncommitted edit to a file under test. Without an overlay step,
every one of these throwaway-clone tests would silently validate the last
commit rather than the diff actually under review, for as long as the
relevant file stayed uncommitted (PEACHES finding, PR #207).

`clone_tool_home_with_overlay` closes that gap: clone first (some callers
need real git log/rev-parse/pull plumbing against the clone), then overlay
the CURRENT on-disk content of every tracked file from TOOL_HOME on top --
so a test run always exercises what is actually on disk in this checkout,
committed or not.

Extracted from scripts/test_gates_bleed_patterns_brand_migration.py's
_clone_tool_home (PR #207), the reference implementation, and applied to
every other throwaway-clone call site (lr-bca2ee) rather than leaving ten
near-identical copies to drift apart -- the same shape that let this defect
class survive nine sites unnoticed in the first place.

CALLER HAZARD if the clone is later used to invoke `clagentic-lite update`
(directly or via `update --restamp`): the overlay leaves the clone
unstaged-dirty against its own HEAD whenever THIS checkout has uncommitted
tracked-file changes (the overlay copies working-tree content over
committed history) -- `git diff --quiet` inside the clone then reports
dirty, which trips cmd_update's non-tty discard guard (lr-55a27a,
bin/clagentic-lite) even though the clone itself is a genuinely disposable
tempdir. A caller that runs `update`/`update --restamp` against a clone
from this module must set CLAGENTIC_UPDATE_ALLOW_DISCARD=1 in that
subprocess's env -- never against the real dev checkout, only against the
disposable clone this module produces. `init` (and any other
CLAGENTIC_LITE_HOME-pointed subcommand that never calls cmd_update) is
unaffected.
"""
import os
import shutil
import subprocess

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def clone_tool_home_with_overlay(tool_home, dest):
    """Throwaway copy of `tool_home` for running a real CLI/gates.sh
    subprocess against -- never the live checkout itself (test hazard).

    Clones committed history first (git rev-parse/log/pull-dependent code
    paths some callers exercise need a real repo shape), then overlays the
    CURRENT on-disk content of every tracked file over the clone. Without
    the overlay, an uncommitted edit to e.g. scripts/gates.sh or
    bin/clagentic-lite is invisible to a test that only clones -- it would
    silently validate the last commit instead of the change under review.
    """
    subprocess.run(["git", "clone", "-q", tool_home, dest], check=True, capture_output=True)
    tracked = subprocess.run(
        ["git", "-C", tool_home, "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout
    for rel_raw in tracked.split(b"\0"):
        if not rel_raw:
            continue
        rel = rel_raw.decode()
        src = os.path.join(tool_home, rel)
        dst = os.path.join(dest, rel)
        # A tracked file can be deleted-but-uncommitted on disk; skip it
        # rather than fail the overlay -- ls-files still lists it (index
        # entry unchanged), but there is nothing to copy.
        if os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    subprocess.run(["git", "-C", dest, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.name", "Test"],
                    check=True, capture_output=True)


def clone_this_tool_home_with_overlay(dest):
    """Convenience wrapper for the overwhelmingly common case: overlaying
    THIS checkout (scripts/test_support.py's own TOOL_HOME) onto a
    throwaway clone at `dest`. Callers that need to clone some other tree
    should use clone_tool_home_with_overlay directly."""
    clone_tool_home_with_overlay(TOOL_HOME, dest)
