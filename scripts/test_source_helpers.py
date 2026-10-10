"""
Shared helper for tests that need to `.`-source the REAL scripts/gates.sh or
scripts/llm-client.sh to call an internal sh function directly, without
triggering either file's trailing subcommand dispatch.

BACKGROUND (lr-bdddcf): both gate-path files used to run an unguarded
subcommand dispatch at EOF under `set -e` -- simply sourcing the real file
executed that dispatch against the sourcing shell's own "$1" and called
`exit`, aborting any test harness that tried. ~30 test files independently
worked around this by writing a dispatch-truncated COPY of the target script
into a throwaway tempdir before sourcing it. Several of those copies were not
byte-identical (some symlinked platform.sh/review-merge.sh/host-adapter.sh
alongside the truncated copy, some copied platform.sh's content instead, one
stubbed review-merge.sh/host-adapter.sh rather than symlinking) -- three
distinct truncation-helper shapes across the ~30 sites, not one.

Both files now carry an explicit source guard
(CLAGENTIC_LLM_CLIENT_SOURCE_ONLY / CLAGENTIC_GATES_SOURCE_ONLY) around their
dispatch block -- see the guard comment at the tail of each .sh file for why
an env sentinel was chosen over a `main()`-invoked-when-not-sourced form.
That guard makes the truncate-a-copy workaround unnecessary: a caller can
source the REAL file directly (no copy, no symlink/stub juggling) as long as
the sentinel is set in the environment BEFORE the `.` line runs. This module
is the one place that env-sentinel contract is expressed, so a future rename
or relocation of either file only needs to change it here.

FAIL-CLOSED AMENDMENT (lr-bdddcf PR #177 fold-in): each guard now also
requires a second, purpose-specific signal --
CLAGENTIC_GATES_DELIBERATE_SOURCE / CLAGENTIC_LLM_CLIENT_DELIBERATE_SOURCE
-- asserting that the *_SOURCE_ONLY suppress-sentinel is set because this
file is being dot-sourced on purpose, not because it leaked in ambiently
from a shell profile or inherited environment. Without the deliberate
signal, the guarded .sh file treats a set suppress-sentinel as an ambient
leak and fails loudly (non-zero exit, stderr naming both variables) instead
of silently no-op'ing. `source_env()` below emits BOTH variables for every
flag it's asked for, so every real sourcing call site in this test suite
continues to work with no per-call-site changes -- this module is still the
only place either contract is expressed.

Usage (mirrors the pattern every test in this suite already uses to build a
`sh -c` script string and hand it to subprocess.run):

    from isolated_env import shared_env
    from test_source_helpers import GATES_SH, LLM_CLIENT_SH, source_env

    env = shared_env(project=tmpdir)   # temp project root, HOME and tool home
    env.update(source_env(gates=True))
    script = f". '{GATES_SH}'\\n_some_internal_function ...\\n"
    subprocess.run(["sh", "-c", script, GATES_SH], env=env, cwd=tmpdir, ...)

Never source from, or run in, this checkout with the inherited environment:
the sourced scripts resolve the project root, tool home and HOME from it and
write there (scripts/isolated_env.py, scripts/live_tree_guard.py).

`source_env` returns ONLY the sentinel(s) to merge into the subprocess's
environment (never mutates os.environ itself) -- callers already build their
own env dict for other reasons (PATH prepends for fake binaries,
CLAGENTIC_PROJECT_ROOT, etc.) and merge this in alongside those, the same
shape every existing call site already used for its other env keys.
"""
import os

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(TOOL_HOME, "scripts")
GATES_SH = os.path.join(SCRIPTS_DIR, "gates.sh")
LLM_CLIENT_SH = os.path.join(SCRIPTS_DIR, "llm-client.sh")
PLATFORM_SH = os.path.join(SCRIPTS_DIR, "platform.sh")
REVIEW_MERGE_SH = os.path.join(SCRIPTS_DIR, "review-merge.sh")
HOST_ADAPTER_SH = os.path.join(SCRIPTS_DIR, "host-adapter.sh")


def source_env(gates=False, llm_client=False):
    """Return the source-guard sentinel env vars to merge into a subprocess
    environment before dot-sourcing the requested real script(s).

    gates=True adds CLAGENTIC_GATES_SOURCE_ONLY=1 and
    CLAGENTIC_GATES_DELIBERATE_SOURCE=1 (guards scripts/gates.sh's trailing
    ds_load_env-branch + subcommand dispatch, and asserts the suppression is
    deliberate rather than an ambient leak -- see the fail-closed amendment
    in this module's docstring).
    llm_client=True adds CLAGENTIC_LLM_CLIENT_SOURCE_ONLY=1 and
    CLAGENTIC_LLM_CLIENT_DELIBERATE_SOURCE=1 (same pair, for
    scripts/llm-client.sh's trailing subcommand dispatch).

    Neither flag alone implies the other -- gates.sh sources llm-client.sh
    nowhere, and a caller that sources both real files in the same subshell
    (rare; most tests need only one) passes both flags.
    """
    env = {}
    if gates:
        env["CLAGENTIC_GATES_SOURCE_ONLY"] = "1"
        env["CLAGENTIC_GATES_DELIBERATE_SOURCE"] = "1"
    if llm_client:
        env["CLAGENTIC_LLM_CLIENT_SOURCE_ONLY"] = "1"
        env["CLAGENTIC_LLM_CLIENT_DELIBERATE_SOURCE"] = "1"
    return env


# --------------------------------------------------------------------------
# Shared fixtures for tests that drive `gates.sh review` end to end against a
# throwaway project dir (real git repo, SQLite audit table, symlinked tool
# home). Every path they write is under the caller-supplied temp dir.
# --------------------------------------------------------------------------
import sqlite3
import subprocess
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# One identity and one GIT_*-stripping rule for every throwaway repository in
# the suite, shared with scripts/findings_test_support.py (a GIT_DIR or
# GIT_INDEX_FILE inherited from a hook would otherwise redirect a fixture's git
# call off its temp repository).
from findings_test_support import GIT_IDENTITY as GIT_IDENTITY_ENV, clean_env  # noqa: E402

RECURRING_FINDING = {
    "severity": "high",
    "file": "app.py",
    "line": 2,
    "category": "security",
    "message": "unsanitized input reaches a sink",
    # The facts the rubric reads high from, off the security floor; without
    # them the finding is the worst case.
    "attacker_precondition": "authenticated_user",
    "impact": "code_exec",
}


def git_env():
    """The caller's environment minus GIT_*, plus the fixture identity."""
    env = clean_env(drop=("GIT_",))
    env.update(GIT_IDENTITY_ENV)
    return env


def setup_project(tmpdir):
    clagentic_dir = os.path.join(tmpdir, ".clagentic", "lite")
    os.makedirs(clagentic_dir, exist_ok=True)
    db_path = os.path.join(clagentic_dir, "audit.db")
    conn = sqlite3.connect(db_path)
    conn.execute(textwrap.dedent("""\
        CREATE TABLE IF NOT EXISTS gate_runs (
          id         INTEGER PRIMARY KEY,
          ts         TEXT NOT NULL,
          gate       TEXT NOT NULL,
          outcome    TEXT NOT NULL,
          details    TEXT,
          session_id TEXT,
          branch     TEXT
        )
    """))
    conn.commit()
    conn.close()
    return tmpdir


def init_git_repo(project_root):
    env = git_env()
    subprocess.run(["git", "init", "-q", project_root], check=True, env=env)
    target = os.path.join(project_root, "app.py")
    with open(target, "w") as f:
        f.write("def handle(x):\n    return x\n")
    subprocess.run(["git", "add", "app.py"], check=True, cwd=project_root, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "seed"], check=True, cwd=project_root, env=env)


def stage_identical_recreation(project_root, round_n):
    """Commit the current state as a clean baseline, delete app.py, commit the
    deletion, then recreate it byte-identically and stage (not commit) it.
    Every round's staged diff then shows the same lines as freshly ADDED, so
    the flagged line's content-hash key is stable regardless of git's
    diff-minimization (which would otherwise emit an unchanged line only as
    context). The gate under test sees a staged, uncommitted diff."""
    env = git_env()
    # A prior call leaves its recreation staged but uncommitted; without this
    # checkpoint the deletion commit below would find nothing to commit.
    subprocess.run(
        ["git", "commit", "-q", "-m", "checkpoint", "--allow-empty"],
        check=True, cwd=project_root, env=env,
    )
    target = os.path.join(project_root, "app.py")
    if os.path.exists(target):
        os.remove(target)
        subprocess.run(["git", "add", "app.py"], check=True, cwd=project_root, env=env)
        subprocess.run(
            ["git", "commit", "-q", "-m", "delete"], check=True, cwd=project_root, env=env,
        )
    with open(target, "w") as f:
        f.write("def handle(x):\n    return x\n")
    subprocess.run(["git", "add", "app.py"], check=True, cwd=project_root, env=env)


def setup_fake_tool_home(fake_tool_home):
    scripts_dir = os.path.join(fake_tool_home, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    for fname in os.listdir(SCRIPTS_DIR):
        if not fname.endswith(".sh") or fname == "llm-client.sh":
            continue
        dst = os.path.join(scripts_dir, fname)
        if not os.path.exists(dst):
            os.symlink(os.path.join(SCRIPTS_DIR, fname), dst)
    real_share = os.path.join(TOOL_HOME, "share")
    fake_share = os.path.join(fake_tool_home, "share")
    if not os.path.exists(fake_share) and os.path.isdir(real_share):
        os.symlink(real_share, fake_share)


def path_without(tool):
    """A PATH like the current one with `tool` hidden, built from symlinks so
    the python3 fallback branches of the gate run for real. The caller removes
    the returned directory."""
    import tempfile
    shadow = tempfile.mkdtemp(prefix="clagentic-test-nopath-")
    seen = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name == tool or name in seen:
                continue
            seen.add(name)
            try:
                os.symlink(os.path.join(d, name), os.path.join(shadow, name))
            except OSError:
                continue
    return shadow


def stub_review_llm(tmpdir, envelope, record_meta=True):
    """Stub llm-client.sh returning `envelope`. When asked it appends the same
    TSV provenance line the real walk_chain writes, so the gates.sh side is
    exercised end to end."""
    import stat
    scripts_dir = os.path.join(tmpdir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    stub = os.path.join(scripts_dir, "llm-client.sh")
    with open(stub, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import json, os, sys
            data = sys.stdin.read()
            meta = os.environ.get("CLAGENTIC_LLM_RUN_META_FILE")
            if {record_meta!r} and meta:
                with open(meta, "a") as m:
                    m.write("\\t".join(["stub-model-1", "claude", "high", "ab" * 32,
                                         "111", str(len(data.encode()))]) + "\\n")
            sys.stdout.write(json.dumps({envelope!r}))
        """))
    os.chmod(stub, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
