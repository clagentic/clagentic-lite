"""
Remove the variables that redirect git from the test process's own environment.

A hook or a wrapping `git` invocation exports GIT_DIR, GIT_INDEX_FILE and
friends; every child a test spawns inherits them, and they override an explicit
`git -C <dir>` or cwd, so a fixture's `git init`/`commit` lands in the REAL
repository instead of its temp one. Several hundred test call sites spawn git;
scrubbing the process environment once, before any test runs, closes them all
(including ones that pass env=os.environ), where routing each through a helper
would leave the next new call site open.

The author and committer identity variables are kept: they do not redirect git
and a few fixtures commit relying on them. A test that needs a redirecting
variable sets it explicitly in the child's env (see test_canary_git_dir_scoping).
"""
import os

_KEEP_PREFIXES = ("GIT_AUTHOR_", "GIT_COMMITTER_")


def redirecting_git_vars(environ=None):
    environ = os.environ if environ is None else environ
    return sorted(k for k in environ
                  if k.startswith("GIT_") and not k.startswith(_KEEP_PREFIXES))


def scrub_git_env(environ=None):
    """Delete the redirecting GIT_* variables from ENVIRON (default os.environ);
    return the names removed."""
    environ = os.environ if environ is None else environ
    removed = redirecting_git_vars(environ)
    for name in removed:
        del environ[name]
    return removed
