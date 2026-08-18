"""
Regression coverage for lr-d5b322: walk_chain's (scripts/llm-client.sh)
step-failed ERR_HINT extraction from $TMP_ERR must never surface codex's
version banner in place of the real error.

ROOT CAUSE: invoke_codex intentionally merges codex's stdout+stderr into
ERR_FILE (the real answer goes to -o TMP_RAW; see invoke_codex's own header
comment ~line 1376 -- this merge is documented and unchanged by this fix).
codex unconditionally prints a fixed version banner ("OpenAI Codex vX.Y.Z
...") as the FIRST lines of that stream on every invocation, success or
failure. The pre-fix ERR_HINT extraction took the first ANSI-stripped
non-blank line of TMP_ERR -- which is structurally always the banner, never
the real error further down the stream.

FIX: prefer the LAST line matching ^ERROR: when one exists (codex emits
repeated "ERROR: Reconnecting... N/5" retry noise BEFORE the substantive
final ERROR: line, so tail-not-head matters); fall back to the existing
first-non-blank-line behavior when no ^ERROR: line is present at all
(claude's error path, which never had the banner problem, is unchanged).

Three cases proven here, exercised through the real walk_chain function end
to end via a stubbed `codex` binary on PATH -- mirroring the established
fake-binary-on-PATH technique test_walk_chain_stderr_notice.py and
test_walk_chain_unwrap_cause.py already use. No real codex binary, no
network, no pinned codex version string in any assertion (the stub always
reports "99.0.0" as codex_version_check's probed version, matching the
existing test_invoke_exit_status_sweep.py convention) -- fully
environment-agnostic, portable across every machine this repo runs on.

  1. banner + single ERROR: line -> ERR_HINT is the ERROR: text, not the
     banner.
  2. banner + multiple ERROR: lines (incl. "Reconnecting... N/5" retry
     noise) -> ERR_HINT is the LAST ERROR: line, not the first.
  3. banner, no ERROR: line at all -> falls back to the first-non-blank-line
     behavior (still not the banner, since the banner IS the first
     non-blank line in that case by construction of the fixture below --
     proven by using a non-banner-only stub instead, see
     test_no_error_line_falls_back_to_first_non_blank_line).

Run with: python3 -m unittest scripts.test_walk_chain_codex_err_hint -v
"""
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

# IMPORT-PATH ROBUSTNESS: see test_llm_client_source_guard.py's identical
# comment -- this repo has no scripts/__init__.py, so a bare sibling import
# only resolves reliably once this file's own directory is on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import LLM_CLIENT_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_BANNER = "OpenAI Codex v0.146.1\n--------\nworkdir: / model: / provider: openai\n--------\n"


def _write_codex_stub(bin_dir, stderr_body):
    """A `codex` stub that answers `--version` (codex_version_check's probe,
    same convention test_invoke_exit_status_sweep.py's _write_stub_binary
    uses) with a fixed, modern, never-asserted-on version string so the
    full-flag-set invocation path is used, then on the real `exec` call
    drains stdin, writes stderr_body to its own stdout+stderr (mirroring
    codex's real behavior and invoke_codex's intentional merge of both into
    ERR_FILE), and exits 1 -- an invocation-level failure (step-failed)."""
    path = os.path.join(bin_dir, "codex")
    with open(path, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1" = "--version" ]; then
              echo "codex-cli 99.0.0"
              exit 0
            fi
            cat > /dev/null 2>&1
            printf '%s' '{stderr_body}'
            exit 1
        """))
    os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return path


def _run_walk_chain(role_lower, mode, stderr_body):
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-walkchain-codex-errhint-")
    try:
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        _write_codex_stub(bin_dir, stderr_body)

        sourced = LLM_CLIENT_SH

        role_upper = role_lower.upper()
        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            export CLAGENTIC_{role_upper}_CMD=codex
            _fixture_prompt() {{ printf 'test prompt'; }}
            . '{sourced}'
            printf 'stdin diff content' | walk_chain '{role_lower}' '{mode}' _fixture_prompt
        """)
        env = os.environ.copy()
        env.update(source_env(llm_client=True))
        r = subprocess.run(
            ["sh", "-c", script, sourced],
            capture_output=True,
            text=True,
            cwd=TOOL_HOME,
            env=env,
        )
        return r.stdout, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestWalkChainCodexErrHintPrefersErrorLine(unittest.TestCase):
    """The core lr-d5b322 fix: ERR_HINT must never be the codex version
    banner when a real ^ERROR: line exists further down the merged
    stdout+stderr stream."""

    def test_banner_plus_single_error_line_surfaces_error_not_banner(self):
        body = (
            _BANNER
            + "ERROR: unexpected status 404 Not Found: the model does not exist\n"
        )
        stdout, stderr, rc = _run_walk_chain("auditor", "json", body)
        self.assertIn(
            "ERROR: unexpected status 404 Not Found", stderr,
            f"ERR_HINT must surface the real ERROR: line, not the version "
            f"banner. stderr={stderr!r}",
        )
        self.assertNotIn(
            "OpenAI Codex v", stderr,
            f"ERR_HINT must never be the codex version banner. stderr={stderr!r}",
        )

    def test_banner_plus_retry_noise_surfaces_last_error_line_not_first(self):
        body = (
            _BANNER
            + "ERROR: Reconnecting... 1/5\n"
            + "ERROR: Reconnecting... 2/5\n"
            + "ERROR: Reconnecting... 3/5\n"
            + "ERROR: Reconnecting... 4/5\n"
            + "ERROR: Reconnecting... 5/5\n"
            + "ERROR: unexpected status 404 Not Found: the model does not exist\n"
        )
        stdout, stderr, rc = _run_walk_chain("auditor", "json", body)
        self.assertIn(
            "ERROR: unexpected status 404 Not Found", stderr,
            f"ERR_HINT must pick the LAST ^ERROR: line (tail, not head) so "
            f"retry noise never masks the substantive final error. "
            f"stderr={stderr!r}",
        )
        self.assertNotIn(
            "Reconnecting", stderr,
            f"ERR_HINT must not be one of the retry-noise ERROR: lines. "
            f"stderr={stderr!r}",
        )
        self.assertNotIn("OpenAI Codex v", stderr)

    def test_no_error_line_falls_back_to_first_non_blank_line(self):
        """No ^ERROR: line anywhere in the stream: falls back to the
        pre-existing first-non-blank-line behavior unchanged. Uses a
        non-banner stub body so the assertion pins the FALLBACK behavior
        itself, not merely 'the banner happens to also be first'."""
        body = "auth expired, please re-run codex login\nsome other detail\n"
        stdout, stderr, rc = _run_walk_chain("auditor", "json", body)
        self.assertIn(
            "auth expired, please re-run codex login", stderr,
            f"with no ^ERROR: line present, ERR_HINT must fall back to the "
            f"first non-blank line (pre-existing behavior, unchanged). "
            f"stderr={stderr!r}",
        )
        self.assertNotIn("some other detail", stderr)


if __name__ == "__main__":
    unittest.main()
