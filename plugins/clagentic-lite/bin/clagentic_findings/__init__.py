"""The clagentic-lite finding pipeline, one module per concern.

Loaded only by bin/findings.py, from this directory (see that file for why the
import never goes through sys.path). MODULES is the manifest of every module
file the pipeline needs: the entrypoint refuses to run on a copy that is
missing one, and a test keeps this list equal to the files on disk.
"""

MODULES = (
    "cli", "dates", "digest", "dispositions", "errors", "evaluate", "fileio",
    "fingerprint", "gitstate", "globs", "infer", "ingest", "ledger", "paths",
    "policy", "profile", "render", "rounds", "rubric", "samples", "sanitize",
    "severity", "stakes", "state", "summary", "unify", "verdict",
)
