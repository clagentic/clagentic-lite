"""
Fold-in regression tests for the PR #195 review round (lr-25e73e), folding
in BOBBIE (task thread comment #3, bobbie.secret.7) and PEACHES (comment #4,
amos.code-craft.1 + amos.code-craft.12) findings into this same task/branch
per operator-directed fold-in discipline.

Covers the two defects neither reviewer's own scanner class could catch
alone, plus the coverage gap PEACHES named explicitly as required, not
optional:

  (a) INTERACTIVE PRECEDENCE (PEACHES amos.code-craft.1): `init
      --reconfigure`'s interactive prompt answers were silently discarded by
      the preservation merge that ran after them. Fixed by factoring the
      merge/precedence logic into `_merge_preserved_config_values`
      (bin/clagentic-lite), callable directly without a TTY -- PEACHES's own
      preferred fix over PTY plumbing. This file drives that function
      DIRECTLY (extracted from the real bin/clagentic-lite source, never a
      hand-reimplemented copy -- see `_extract_shell_function` below) with a
      synthetic ANSWERS_FILE, so the precedence rule (interactive > preserved
      > template) is exercised without any `read`/TTY involvement, while
      still being the exact code the interactive prompt flow calls for real.

  (b) THE !found BRANCH (BOBBIE bobbie.secret.7 + PEACHES amos.code-craft.12,
      site 1811/1819 pre-fold-in line numbers): a preserved ACTIVE credential
      key with NO counterpart anywhere in the fresh template used to write
      the raw KEY=VALUE line to a never-chmod'd file
      (`$_wgc_merged.notfound`, landing 0644 -- BOBBIE sandbox-confirmed).
      The existing leak test in test_init_reconfigure_merge.py activates a
      key that IS present (commented) in the template, so `found=1` and this
      branch never fired -- it looked like coverage and was not. This file
      drives the !found branch specifically: an active credential-shaped key
      with no template counterpart at all.

  (c) PERMISSIONS DURING THE WINDOW, not only final state (both reviewers'
      explicit requirement): a final-state-only permission check passes even
      while the exposure window existed. This file polls file mode WHILE the
      merge subprocess is still running, not only after it exits.

HAZARD, read before editing this file: every test here points
CLAGENTIC_LITE_HOME at a throwaway `git clone` of the real checkout, never
the live dev checkout -- follows _clone_tool_home from
test_init_reconfigure_merge.py / test_update_nontty_discard_guard.py
exactly, with check=True and no fallback to the live tree.

Run with: python3 -m unittest scripts.test_merge_preserved_config_values -v
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import unittest

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN_PATH = os.path.join(TOOL_HOME, "bin", "clagentic-lite")


def _clone_tool_home(dest):
    subprocess.run(["git", "clone", "-q", TOOL_HOME, dest], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.email", "test@example.com"],
                    check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "config", "user.name", "Test"],
                    check=True, capture_output=True)


def _extract_shell_function(source_path, name):
    """Extract one `name() { ... }` function body verbatim from a POSIX sh
    file, by scanning for the literal `name() {` line at column 0 through
    the next `}` line at column 0. Returns the function TEXT, never a
    hand-reimplemented copy -- so a test built on this always exercises the
    real, current bin/clagentic-lite logic, not a stale or drifted stand-in.
    Raises AssertionError if the function cannot be found, so a rename in
    bin/clagentic-lite fails this test loudly instead of silently testing
    nothing."""
    start_pat = re.compile(r'^' + re.escape(name) + r'\(\) \{\s*$')
    with open(source_path) as f:
        lines = f.readlines()
    start = None
    for i, line in enumerate(lines):
        if start_pat.match(line):
            start = i
            break
    if start is None:
        raise AssertionError("function %r not found in %s" % (name, source_path))
    depth = 0
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if j > start and depth == 0:
            return "".join(lines[start:j + 1])
    raise AssertionError("closing brace for %r not found in %s" % (name, source_path))


class _MergePreservedConfigValuesTestBase(unittest.TestCase):
    """Builds a throwaway sh harness sourcing ONLY the two real functions
    under test (_secret_tmp_create, _merge_preserved_config_values) --
    extracted verbatim from a throwaway clone of bin/clagentic-lite, never
    hand-copied -- plus a thin driver that calls
    _merge_preserved_config_values with caller-supplied fixture files and
    prints the resulting merged file's path. No TTY, no `read`, no full CLI
    dispatch (the real file's own top-level `case` dispatch is never
    sourced -- only the two function bodies are extracted and concatenated
    into a fresh script)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="clagentic-test-merge-preserved-")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.fake_tool_home = os.path.join(self.tmpdir, "fake-tool-home")
        _clone_tool_home(self.fake_tool_home)
        cloned_bin = os.path.join(self.fake_tool_home, "bin", "clagentic-lite")

        secret_tmp_create = _extract_shell_function(cloned_bin, "_secret_tmp_create")
        merge_fn = _extract_shell_function(cloned_bin, "_merge_preserved_config_values")

        self.harness_path = os.path.join(self.tmpdir, "harness.sh")
        with open(self.harness_path, "w") as f:
            f.write("#!/bin/sh\nset -e\n\n")
            f.write(secret_tmp_create)
            f.write("\n\n")
            f.write(merge_fn)
            f.write("\n\n")
            # Driver: TARGET PRESERVE [ANSWERS] as argv, prints merged path.
            f.write(
                '_merge_preserved_config_values "$1" "$2" "${3:-}"\n'
            )
        os.chmod(self.harness_path, 0o700)

    def _write_fixture(self, name, body):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            f.write(body)
        return path

    def _run_harness(self, target, preserve, answers=None, forbidden_value=None):
        argv = ["sh", self.harness_path, target, preserve]
        if answers is not None:
            argv.append(answers)
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=True)
        if forbidden_value is not None:
            self.assertNotIn(forbidden_value, proc.stdout,
                              msg="a configured VALUE must never appear on stdout")
            self.assertNotIn(forbidden_value, proc.stderr,
                              msg="a configured VALUE must never appear on stderr")
        merged_path = proc.stdout.strip()
        self.assertTrue(merged_path, msg="harness produced no merged-file path: %r" % proc.stdout)
        return merged_path


class TestInteractivePrecedence(_MergePreservedConfigValuesTestBase):
    """(a) Drives the merge/precedence logic directly with a synthetic
    ANSWERS_FILE -- no TTY, no PTY plumbing -- proving the precedence rule:
    interactive answer (this run) > preserved existing value > template
    default."""

    def test_interactive_answer_wins_over_preserved_value(self):
        target = self._write_fixture(
            "target",
            "CLAGENTIC_DEFAULT_BRANCH=main\n"
            "CLAGENTIC_BUILDER_CMD=claude\n",
        )
        preserve = self._write_fixture(
            "preserve",
            "CLAGENTIC_DEFAULT_BRANCH=old-preserved-branch\n",
        )
        answers = self._write_fixture(
            "answers",
            "CLAGENTIC_DEFAULT_BRANCH=operator-typed-this-run\n",
        )
        merged_path = self._run_harness(target, preserve, answers)
        with open(merged_path) as f:
            merged = f.read()
        self.assertIn("CLAGENTIC_DEFAULT_BRANCH=operator-typed-this-run", merged, msg=merged)
        self.assertNotIn("old-preserved-branch", merged, msg=merged)

    def test_preserved_value_still_wins_when_no_interactive_answer_for_that_key(self):
        target = self._write_fixture(
            "target",
            "CLAGENTIC_DEFAULT_BRANCH=main\n"
            "CLAGENTIC_REPO_HOST=github\n",
        )
        preserve = self._write_fixture(
            "preserve",
            "CLAGENTIC_REPO_HOST=gitlab\n",
        )
        answers = self._write_fixture(
            "answers",
            "CLAGENTIC_DEFAULT_BRANCH=operator-typed-this-run\n",
        )
        merged_path = self._run_harness(target, preserve, answers)
        with open(merged_path) as f:
            merged = f.read()
        self.assertIn("CLAGENTIC_DEFAULT_BRANCH=operator-typed-this-run", merged, msg=merged)
        self.assertIn("CLAGENTIC_REPO_HOST=gitlab", merged, msg=merged)

    def test_no_answers_file_falls_back_to_preserved_value(self):
        """The pre-fold-in behavior (preserved value applied, nothing else)
        must still hold when there is no interactive input at all -- e.g. a
        non-tty `--reconfigure` run."""
        target = self._write_fixture("target", "CLAGENTIC_BUILDER_CMD=claude\n")
        preserve = self._write_fixture("preserve", "CLAGENTIC_BUILDER_CMD=my-custom\n")
        merged_path = self._run_harness(target, preserve, answers=None)
        with open(merged_path) as f:
            merged = f.read()
        self.assertIn("CLAGENTIC_BUILDER_CMD=my-custom", merged, msg=merged)


class TestNotFoundBranchNeverWorldReadable(_MergePreservedConfigValuesTestBase):
    """(b) + (c): drives the !found branch -- a preserved ACTIVE
    credential-shaped key with NO counterpart anywhere in the target file --
    and asserts permissions DURING the window the merge runs, not only on
    final state (final-state-only would have passed under the pre-fold-in
    defect too, since the vulnerable file was rm -f'd before the process
    exited in the common case)."""

    def test_retired_credential_key_appended_never_world_readable_final_state(self):
        target = self._write_fixture(
            "target",
            "CLAGENTIC_BUILDER_CMD=claude\n",
        )
        secret = "sk-retired-key-must-never-leak"
        preserve = self._write_fixture(
            "preserve",
            # CLAGENTIC_RETIRED_ROUTER_TOKEN has NO counterpart in `target`
            # at all -- this is the exact !found branch BOBBIE and PEACHES
            # both found unguarded.
            "CLAGENTIC_RETIRED_ROUTER_TOKEN=%s\n" % secret,
        )
        merged_path = self._run_harness(target, preserve, forbidden_value=secret)
        with open(merged_path) as f:
            merged = f.read()
        self.assertIn(secret, merged, msg="retired key's value must still be appended, not dropped")

        mode = stat.S_IMODE(os.stat(merged_path).st_mode)
        self.assertEqual(mode, 0o600, msg="final merged file must be 600")

        # No sibling temp file left behind at 0644 or wider -- the merge
        # function's own intermediate .merge-body/.merge-step/.merge-notfound
        # files must all have been either 600 throughout or removed.
        for entry in os.listdir(self.tmpdir):
            full = os.path.join(self.tmpdir, entry)
            if not os.path.isfile(full) or full == merged_path:
                continue
            if "merge-" not in entry:
                continue
            leftover_mode = stat.S_IMODE(os.stat(full).st_mode)
            self.assertEqual(
                leftover_mode, 0o600,
                msg="leftover intermediate file %s must never be wider than 600 (got %o)"
                % (entry, leftover_mode),
            )

    def test_permissions_during_the_window_not_only_after(self):
        """(c), the explicit requirement: assert mode WHILE the merge
        subprocess is still running, polling for any secrets-bearing
        `.merge-*` temp file and asserting it is 600 the instant it is
        observed -- never 0644 at any sampled instant, not merely at exit."""
        target = self._write_fixture("target", "CLAGENTIC_BUILDER_CMD=claude\n")
        secret = "sk-during-window-must-never-be-0644"
        # Large preserve file (many keys, several !found) to widen the
        # window the harness subprocess spends inside the merge loop, so a
        # polling thread has a realistic chance to observe intermediate
        # files while they exist.
        preserve_lines = ["CLAGENTIC_RETIRED_KEY_%d=%s\n" % (i, secret) for i in range(40)]
        preserve = self._write_fixture("preserve", "".join(preserve_lines))

        violations = []
        stop = threading.Event()

        def _poll():
            while not stop.is_set():
                try:
                    for entry in os.listdir(self.tmpdir):
                        if "merge-" not in entry:
                            continue
                        full = os.path.join(self.tmpdir, entry)
                        try:
                            mode = stat.S_IMODE(os.stat(full).st_mode)
                        except FileNotFoundError:
                            continue  # removed between listdir and stat -- fine, not a violation
                        if mode != 0o600:
                            violations.append((entry, oct(mode)))
                except FileNotFoundError:
                    pass
                time.sleep(0.001)

        poller = threading.Thread(target=_poll, daemon=True)
        poller.start()
        try:
            merged_path = self._run_harness(target, preserve)
        finally:
            stop.set()
            poller.join(timeout=5)

        self.assertEqual(
            violations, [],
            msg="observed a merge-* temp file at a mode other than 600 DURING the run: %r" % violations,
        )
        with open(merged_path) as f:
            merged = f.read()
        self.assertEqual(merged.count(secret), 40, msg="all 40 retired keys must round-trip")


if __name__ == "__main__":
    unittest.main()
