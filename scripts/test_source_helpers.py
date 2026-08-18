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

Usage (mirrors the pattern every test in this suite already uses to build a
`sh -c` script string and hand it to subprocess.run):

    from test_source_helpers import GATES_SH, LLM_CLIENT_SH, source_env

    env = os.environ.copy()
    env.update(source_env(gates=True))
    script = f". '{GATES_SH}'\\n_some_internal_function ...\\n"
    subprocess.run(["sh", "-c", script, GATES_SH], env=env, ...)

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

    gates=True adds CLAGENTIC_GATES_SOURCE_ONLY=1 (guards scripts/gates.sh's
    trailing ds_load_env-branch + subcommand dispatch).
    llm_client=True adds CLAGENTIC_LLM_CLIENT_SOURCE_ONLY=1 (guards
    scripts/llm-client.sh's trailing subcommand dispatch).

    Neither flag alone implies the other -- gates.sh sources llm-client.sh
    nowhere, and a caller that sources both real files in the same subshell
    (rare; most tests need only one) passes both flags.
    """
    env = {}
    if gates:
        env["CLAGENTIC_GATES_SOURCE_ONLY"] = "1"
    if llm_client:
        env["CLAGENTIC_LLM_CLIENT_SOURCE_ONLY"] = "1"
    return env
