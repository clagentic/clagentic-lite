"""
Regression tests for the claude carrier in llm-client.sh (lr-082f).

Root cause: invoke_claude() hardcoded TEMP_FLAG="--temperature 0" for the
auditor role and passed it to `claude --print`. The installed claude CLI
(2.1.197) does not support --temperature, so every auditor/adversarial call
failed and the merge-gate refused on a degraded result.

These tests source the ACTUAL sh function (invoke_claude) from llm-client.sh
via `sh -c`, with a fake `claude` binary on PATH that records its argv
instead of calling the real CLI. This proves the real invocation never emits
an unsupported flag — a change to the CLAGENTIC_*_CMD config or a Python
mirror of the logic would not catch a regression here; only exercising the
real function does.

Run with: python3 -m unittest scripts/test_llm_client_sh.py -v
"""
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest

TOOL_HOME = os.path.join(os.path.dirname(__file__), "..")
LLM_CLIENT_SH = os.path.join(TOOL_HOME, "scripts", "llm-client.sh")
PLATFORM_SH = os.path.join(TOOL_HOME, "scripts", "platform.sh")


def _write_fake_claude(bin_dir, argv_file):
    """Write a fake `claude` binary that records its argv and exits 0.

    Emits a minimal valid response on stdout so callers that also check
    the output shape (not exercised by these tests) would not choke.
    """
    fake = os.path.join(bin_dir, "claude")
    with open(fake, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/bin/sh
            printf '%s\\n' "$*" >> '{argv_file}'
            cat > /dev/null  # drain stdin (the diff/prompt input)
            printf 'ok\\n'
        """))
    os.chmod(fake, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return fake


def _functions_only_source(dest_dir):
    """Copy llm-client.sh into dest_dir with its trailing subcommand dispatch
    (`case "${1:-}" in build) ... esac`) stripped off.

    That dispatch runs unconditionally at source time (it is not guarded by
    a function or `[ "$0" = ... ]` check), so simply `. llm-client.sh`-ing the
    real file from a test harness executes cmd_build/cmd_review/etc based on
    whatever $1 happens to be in the sourcing shell and calls `exit`, which
    would abort the harness before invoke_claude can be called directly.
    Truncating at the dispatch line preserves every real function body
    byte-for-byte (this is still the actual invoke_claude implementation,
    not a copy) while making the file safe to source for targeted function
    tests. platform.sh is copied alongside unchanged so the relative
    `. "$(dirname "$0")/platform.sh"` self-source at the top still resolves.
    """
    with open(LLM_CLIENT_SH) as f:
        lines = f.readlines()
    cut = None
    for i, line in enumerate(lines):
        if line.startswith('case "${1:-}" in'):
            cut = i
            break
    assert cut is not None, "could not locate subcommand dispatch in llm-client.sh"
    dest = os.path.join(dest_dir, "llm-client.sh")
    with open(dest, "w") as f:
        f.writelines(lines[:cut])
    platform_dest = os.path.join(dest_dir, "platform.sh")
    with open(PLATFORM_SH) as src, open(platform_dest, "w") as dst:
        dst.write(src.read())
    return dest


def _run_invoke_claude(call_role, call_mode="markdown", model=""):
    """Source llm-client.sh (functions only) and call invoke_claude directly
    with a fake claude on PATH. Returns (recorded_argv_lines, stderr, rc)."""
    tmpdir = tempfile.mkdtemp(prefix="clagentic-test-llm-client-")
    try:
        argv_file = os.path.join(tmpdir, "argv.log")
        open(argv_file, "w").close()
        bin_dir = os.path.join(tmpdir, "bin")
        os.makedirs(bin_dir)
        _write_fake_claude(bin_dir, argv_file)

        src_dir = os.path.join(tmpdir, "src")
        os.makedirs(src_dir)
        sourced_llm_client = _functions_only_source(src_dir)

        prompt_file = os.path.join(tmpdir, "prompt.txt")
        input_file = os.path.join(tmpdir, "input.txt")
        output_file = os.path.join(tmpdir, "output.txt")
        err_file = os.path.join(tmpdir, "err.txt")
        with open(prompt_file, "w") as f:
            f.write("test prompt")
        with open(input_file, "w") as f:
            f.write("test diff")

        script = textwrap.dedent(f"""\
            export PATH='{bin_dir}':"$PATH"
            . '{sourced_llm_client}'
            invoke_claude '{model}' '{prompt_file}' '{input_file}' '{output_file}' '{err_file}' 60 '{call_mode}' '{call_role}'
        """)
        # Pass sourced_llm_client as $0 (sh -c's second arg) so its own
        # `. "$(dirname "$0")/platform.sh"` resolves correctly — under plain
        # `sh -c script`, $0 is "sh" and that self-source would fail.
        r = subprocess.run(
            ["sh", "-c", script, sourced_llm_client],
            capture_output=True,
            text=True,
            cwd=TOOL_HOME,
        )
        with open(argv_file) as f:
            recorded = [line.rstrip("\n") for line in f if line.strip()]
        return recorded, r.stderr, r.returncode
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestInvokeClaudeNoUnsupportedFlags(unittest.TestCase):
    """Regression guard for lr-082f: the claude carrier must never pass
    --temperature (or any flag `claude --help` does not list) on the
    `claude --print` invocation, for any role."""

    def test_auditor_role_no_temperature_flag(self):
        """The role that previously hardcoded --temperature 0 must not emit it."""
        recorded, err, rc = _run_invoke_claude("auditor", call_mode="markdown")
        self.assertEqual(rc, 0, f"invoke_claude exited non-zero: {err}")
        self.assertEqual(len(recorded), 1, f"expected exactly one claude invocation, got: {recorded}")
        self.assertNotIn("--temperature", recorded[0],
                          f"claude carrier must not pass --temperature: {recorded[0]!r}")

    def test_auditor_role_no_temperature_flag_with_model(self):
        """Same guard on the model-specified branch of invoke_claude (separate code path)."""
        recorded, err, rc = _run_invoke_claude("auditor", call_mode="markdown", model="sonnet")
        self.assertEqual(rc, 0, f"invoke_claude exited non-zero: {err}")
        self.assertEqual(len(recorded), 1, f"expected exactly one claude invocation, got: {recorded}")
        self.assertNotIn("--temperature", recorded[0],
                          f"claude carrier must not pass --temperature: {recorded[0]!r}")

    def test_other_roles_also_no_temperature_flag(self):
        """No role should ever pass --temperature — it was never supported for
        reviewer/gate either; this locks the invariant in for all roles."""
        for role in ("reviewer", "gate", "builder", "summarizer"):
            with self.subTest(role=role):
                recorded, err, rc = _run_invoke_claude(role, call_mode="markdown")
                self.assertEqual(rc, 0, f"invoke_claude exited non-zero for role={role}: {err}")
                self.assertNotIn("--temperature", recorded[0] if recorded else "",
                                  f"role={role} must not pass --temperature: {recorded}")


if __name__ == "__main__":
    unittest.main()
