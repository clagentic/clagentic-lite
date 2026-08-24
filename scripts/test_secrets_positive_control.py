"""
Regression tests for lr-170808: the secrets gate's config preflight (scope
item 1) and positive-control canary (scope item 2).

BACKGROUND: gitleaks' --config REPLACES the embedded ruleset rather than
merging with it. A repo-supplied .gitleaks.toml consisting solely of an
[allowlist]/[[allowlists]] block -- the most natural file to write when the
intent is "suppress these known false positives" -- silently loads ZERO
detection rules. cmd_secrets (scripts/gates.sh) used to hand any existing
.gitleaks.toml straight to gitleaks with no check that it actually declares
usable rules, so a rules-less config produced a permanent, convincing "no
leaks found" pass.

This file covers:
  1. _gitleaks_config_declares_rules -- text-level preflight over a
     .gitleaks.toml: true only when it declares [[rules]] or
     [extend] useDefault = true.
  2. _gitleaks_positive_control -- runs the REAL installed gitleaks against
     a scratch git repo seeded with realistic, non-example planted
     credentials, and asserts on finding COUNT and RULE IDS (never merely a
     non-zero exit). Proven sensitive in BOTH directions: findings with
     rules loaded, zero with a deliberately rules-less config.
  3. cmd_secrets' own wiring: the preflight and the canary both block with
     the documented message/vocabulary, and that vocabulary is what
     _read_deterministic_gates' no_coverage predicate keys on (item 3).

These tests invoke the REAL scripts/gates.sh functions (sourced via `sh -c`,
CLAGENTIC_GATES_SOURCE_ONLY-guarded, same pattern as test_run_bounded.py /
test_gate_manifest.py) against the REAL installed gitleaks binary -- a
canary that only proves itself against a stub would not catch the exact
defect this task is about (a fully functional scanner that still reports
clean because of what it was fed).

Run with: python3 -m unittest scripts.test_secrets_positive_control -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, source_env  # noqa: E402

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def _gitleaks_available():
    return shutil.which("gitleaks") is not None


def _run_gates_sh(script_body, env_extra=None, cwd=None):
    env = os.environ.copy()
    env.update(source_env(gates=True))
    if env_extra:
        env.update(env_extra)
    script = f". '{GATES_SH}'\n{script_body}\n"
    return subprocess.run(
        ["sh", "-c", script, GATES_SH],
        capture_output=True, text=True, env=env,
        cwd=cwd or os.path.join(TOOL_HOME, "scripts"),
        timeout=120,
    )


def _write_toml(tmpdir, name, content):
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestGitleaksConfigDeclaresRules(unittest.TestCase):
    """_gitleaks_config_declares_rules -- text-level preflight."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-gl-cfg-")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_allowlist_only_config_declares_no_rules(self):
        """The exact reported defect shape: an [[allowlists]] block with no
        [[rules]] and no [extend] useDefault = true."""
        path = _write_toml(self._tmp, ".gitleaks.toml", textwrap.dedent("""\
            [[allowlists]]
            description = "known fixtures"
            paths = ['''^examples/.*''']
        """))
        r = _run_gates_sh(f"_gitleaks_config_declares_rules '{path}'")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_extend_use_default_true_declares_rules(self):
        path = _write_toml(self._tmp, ".gitleaks.toml", textwrap.dedent("""\
            [extend]
            useDefault = true

            [[allowlists]]
            description = "known fixtures"
            paths = ['''^examples/.*''']
        """))
        r = _run_gates_sh(f"_gitleaks_config_declares_rules '{path}'")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_explicit_rules_block_declares_rules(self):
        path = _write_toml(self._tmp, ".gitleaks.toml", textwrap.dedent("""\
            [[rules]]
            id = "custom-rule"
            regex = '''secret-[0-9]+'''
        """))
        r = _run_gates_sh(f"_gitleaks_config_declares_rules '{path}'")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_use_default_true_under_a_different_table_does_not_count(self):
        """useDefault = true appearing under some OTHER table header must
        not be mistaken for [extend]'s own declaration -- this is the
        table-scoping property that distinguishes this from a bare
        substring grep for 'useDefault = true'."""
        path = _write_toml(self._tmp, ".gitleaks.toml", textwrap.dedent("""\
            [[allowlists]]
            description = "not the extend table"
            useDefault = true
        """))
        r = _run_gates_sh(f"_gitleaks_config_declares_rules '{path}'")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_extend_use_default_false_does_not_declare_rules(self):
        path = _write_toml(self._tmp, ".gitleaks.toml", textwrap.dedent("""\
            [extend]
            useDefault = false
        """))
        r = _run_gates_sh(f"_gitleaks_config_declares_rules '{path}'")
        self.assertNotEqual(r.returncode, 0, r.stderr)

    def test_repo_own_gitleaks_toml_declares_rules(self):
        """This repo's own .gitleaks.toml must pass -- it is the documented
        correct shape ([extend] useDefault = true plus a narrow allowlist)."""
        own_toml = os.path.join(TOOL_HOME, ".gitleaks.toml")
        r = _run_gates_sh(f"_gitleaks_config_declares_rules '{own_toml}'")
        self.assertEqual(r.returncode, 0, r.stderr)


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestGitleaksPositiveControl(unittest.TestCase):
    """_gitleaks_positive_control -- proven sensitive in BOTH directions
    against the REAL installed gitleaks binary."""

    def test_canary_detects_with_default_rules_loaded(self):
        """No --config at all (gitleaks' own full built-in ruleset) must
        detect the planted fixtures and report a real, non-zero count plus
        at least one rule id -- assert on count/rule-ids, not merely exit
        status, per the task's own explicit instruction."""
        r = _run_gates_sh("_gitleaks_positive_control ''")
        self.assertEqual(r.returncode, 0, r.stderr)
        count_str, rule_ids = r.stdout.rstrip("\n").split("\t")
        count = int(count_str)
        self.assertGreaterEqual(count, 1)
        self.assertNotEqual(rule_ids, "")

    def test_canary_still_spans_multiple_rule_families_after_runtime_reassembly(self):
        """PEACHES, PR #188 follow-up: the fix to build fixtures from
        run-time fragments must not have silently narrowed the canary down
        to a single rule family -- still plant multiple rule types (task's
        own explicit constraint), verified here by rule-id count, not just
        finding count."""
        r = _run_gates_sh("_gitleaks_positive_control ''")
        self.assertEqual(r.returncode, 0, r.stderr)
        _count_str, rule_ids_str = r.stdout.rstrip("\n").split("\t")
        rule_ids = set(rule_ids_str.split(",")) if rule_ids_str else set()
        self.assertGreaterEqual(
            len(rule_ids), 3,
            msg=f"expected several distinct rule families, got: {rule_ids}",
        )

    def test_canary_reports_zero_with_a_deliberately_rules_less_config(self):
        """The canary's own negative case (task requirement): a
        deliberately rules-less config (an [[allowlists]]-only file, the
        exact reported defect shape) must make the SAME canary fixture
        report ZERO findings -- proving the canary is actually sensitive to
        the defect this task closes, not just to gitleaks being present."""
        tmp = tempfile.mkdtemp(prefix="clagentic-test-gl-canary-nocfg-")
        try:
            cfg_path = _write_toml(tmp, "rules-less.toml", textwrap.dedent("""\
                [[allowlists]]
                description = "rules-less config -- the reported defect shape"
                paths = ['''^.*$''']
            """))
            r = _run_gates_sh(f"_gitleaks_positive_control '--config={cfg_path}'")
            self.assertNotEqual(r.returncode, 0, r.stderr)
            self.assertTrue(r.stdout.startswith("0\t"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_canary_does_not_use_the_aws_doc_example_key(self):
        """Regression guard for the task's own IMPLEMENTATION WARNING:
        gitleaks stopwords AWS's own published doc-example access key in
        most contexts, so a canary built from it would report clean
        against a fully functional scanner. Read the actual function
        source and assert the doc-example literal never appears in it.

        The literals themselves are deliberately assembled here rather
        than written as whole strings -- a same-file PROSE MENTION of
        either published doc-example literal is itself gitleaks-detectable
        (confirmed against the real binary during this task, see
        docs/GATES.md's identical fix), so this test file must not
        reproduce them as complete literals any more than gates.sh may."""
        with open(GATES_SH) as f:
            src = f.read()
        start = src.index("_gitleaks_positive_control() {")
        end = src.index("\n}\n", start)
        body = src[start:end]
        # Short (4-char) fragments joined at runtime, same discipline as
        # gates.sh's own _gpc_join -- two adjacent literals on one line
        # still leave the full contiguous run for gitleaks to match (this
        # was tried first and confirmed detectable against the real
        # binary), so this needs the same fragment-count granularity, not
        # merely a two-way split.
        aws_doc_example_key = "".join(["AKIA", "IOSF", "ODNN", "7EXA", "MPLE"])
        aws_doc_example_secret = "".join([
            "wJal", "rXUt", "nFEM", "I/K7", "MDEN", "G/bP", "xRfi", "CYEX", "AMPL", "EKEY",
        ])
        self.assertNotIn(aws_doc_example_key, body)
        self.assertNotIn(aws_doc_example_secret, body)


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestCanaryFixturesAreNotSourceLiterals(unittest.TestCase):
    """PEACHES, PR #188 review: the FIRST shipped canary embedded each
    fixture as one complete literal in a heredoc -- gitleaks itself then
    flagged those exact lines in gates.sh's OWN committed source/history (18
    findings: aws-access-token, generic-api-key, github-pat,
    slack-access-token, stripe-access-token), so `gates.sh secrets` blocked
    on branch history scanning this very file once shipped.

    Fix: every fixture is assembled at RUN TIME from fragments, never
    written to source as one complete credential-shaped literal. This class
    proves BOTH halves of that fix directly against the REAL installed
    gitleaks binary -- not by re-deriving gitleaks' own rule regexes:

      1. scripts/gates.sh's own WORKING-TREE content (the actual shipped
         function body, scanned exactly as gitleaks would scan it) reports
         ZERO findings.
      2. `gitleaks git` branch-history scanning (the exact mode PEACHES
         asked to be verified) against a REAL scratch repo seeded with this
         repo's current gates.sh, on a clean index, also reports ZERO
         findings -- confirming the reassembled-at-runtime fixtures are not
         merely absent from THIS file's current text but genuinely
         undetectable as committed history content.

    A regression here (someone reintroducing a complete literal) is exactly
    the self-defeating-canary shape PEACHES caught -- this test exists so
    it is caught mechanically, not only by a future human reviewer.
    """

    def test_gates_sh_working_tree_content_is_clean(self):
        report = tempfile.mktemp(prefix="clagentic-test-selfscan-", suffix=".json")
        try:
            r = subprocess.run(
                ["gitleaks", "detect", "--no-banner", "--no-git",
                 "--source", os.path.dirname(GATES_SH),
                 "--report-format", "json", "--report-path", report],
                capture_output=True, text=True, timeout=120,
            )
            findings = []
            if os.path.isfile(report):
                with open(report) as f:
                    content = f.read().strip()
                if content:
                    findings = json.loads(content)
            offending = [
                f for f in findings
                if os.path.basename(f.get("File", "")) == "gates.sh"
            ]
            self.assertEqual(
                offending, [],
                msg=f"gitleaks flagged scripts/gates.sh's own working-tree "
                    f"content (rc={r.returncode}): {offending}",
            )
        finally:
            if os.path.isfile(report):
                os.remove(report)

    def test_no_reachable_commit_in_this_branchs_history_carries_the_literals(self):
        """BOBBIE, PR #188 follow-up (bobbie.secret.1): the tip-tree fix
        alone is not sufficient -- an EARLIER commit on this branch can
        still carry the complete literals even after a LATER commit
        supersedes them in the working tree, because branch history remains
        scannable (`gitleaks git`, the exact path cmd_secrets takes on a
        clean index) regardless of what the tip looks like. This checks
        every commit reachable from the current branch tip back to its
        merge-base with origin/main (or HEAD itself if no such base is
        resolvable) for the literal patterns this task's own canary must
        never leave as committed, complete, credential-shaped text.

        Deliberately does NOT depend on `gitleaks git` being supported by
        the installed binary (older gitleaks lacks that subcommand, as this
        environment demonstrated during this task) -- instead checks out
        each historical commit's scripts/gates.sh blob directly via `git
        show` and greps for the exact literal substrings BOBBIE's
        gitleaks/trufflehog runs both attributed to commit 89be47b. This is
        a narrower, deliberately mechanical check (exact substrings, not a
        re-derivation of gitleaks' rule regexes) -- sufficient to catch a
        REGRESSION of this exact defect class without needing gitleaks'
        history-scan subcommand to be present in every environment this
        test runs in.
        """
        try:
            merge_base = subprocess.run(
                ["git", "merge-base", "HEAD", "origin/main"],
                capture_output=True, text=True, cwd=TOOL_HOME, timeout=30,
            ).stdout.strip()
        except Exception:
            merge_base = ""
        if not merge_base:
            self.skipTest("no origin/main merge-base resolvable in this checkout")

        rev_list = subprocess.run(
            ["git", "rev-list", f"{merge_base}..HEAD"],
            capture_output=True, text=True, cwd=TOOL_HOME, timeout=30,
        )
        commits = [c for c in rev_list.stdout.splitlines() if c]
        self.assertGreater(len(commits), 0, "expected at least one commit in range")

        # The exact literal substrings BOBBIE's independent gitleaks/
        # trufflehog runs attributed to commit 89be47b, scripts/gates.sh
        # lines 511-515 -- assembled at RUN TIME from short (4-char)
        # fragments, same discipline as scripts/gates.sh's own _gpc_join
        # and this file's own test_canary_does_not_use_the_aws_doc_example_key
        # above. A THIS test file is exactly what a base..head gitleaks scan
        # also covers (see the companion test below), so writing these as
        # complete literals here would reintroduce the identical defect
        # class this whole test class exists to catch, one level up.
        forbidden = [
            "".join(["AKIA", "47QM", "DLXN", "ZP2K", "6R3T"]),
            "".join(["ghp_", "9fK3", "mQ7x", "R2vN", "5jL8", "wT4y", "B6cH", "1sD0", "pA3g", "U9iX", "2eZ7", "f"]),
            "".join(["xoxb", "-847", "3629", "5104", "7-82", "9104", "6573", "821-"]),
            "".join(["sk_l", "ive_", "9fK3", "mQ7x", "R2vN", "5jL8", "wT4y", "B6cH", "1sD0", "pA3g"]),
        ]
        offenders = []
        for commit in commits:
            show = subprocess.run(
                ["git", "show", f"{commit}:scripts/gates.sh"],
                capture_output=True, text=True, cwd=TOOL_HOME, timeout=30,
            )
            if show.returncode != 0:
                continue  # file didn't exist at this commit -- nothing to check
            for literal in forbidden:
                if literal in show.stdout:
                    offenders.append((commit, literal))
        self.assertEqual(
            offenders, [],
            msg=f"found forbidden credential-shaped literal(s) still "
                f"reachable in branch history: {offenders}",
        )

    def test_real_gitleaks_binary_reports_zero_findings_across_the_full_range(self):
        """BOBBIE, PR #188 follow-up (bobbie.secret.1) -- explicit ask:
        "Scan the full new base..head range with the real gitleaks binary --
        must be zero findings, not just the tip tree." Checks out EVERY
        commit reachable from HEAD back to its origin/main merge-base into
        an isolated scratch clone (never the shared working checkout) and
        runs the real installed gitleaks against each one with --no-git
        (this installed binary predates the `gitleaks git` subcommand, as
        this task's own doctor version-floor check documents) --
        equivalent coverage to a history scan without depending on that
        subcommand's presence.

        Scoped to the files THIS PR touches (bin/clagentic-lite,
        docs/GATES.md, scripts/gates.sh, scripts/test_*.py), matching
        test_gates_sh_working_tree_content_is_clean's own scoping
        precedent above -- a whole-repo scan would also re-flag this
        repo's own pre-existing, .gitleaks.toml-allowlisted public demo
        fixtures (examples/*/.env.example, docs/DEMO-SCRIPT.md,
        examples/README.md), which are a pre-existing, already-reviewed
        state this task did not touch and is not responsible for
        re-litigating."""
        try:
            merge_base = subprocess.run(
                ["git", "merge-base", "HEAD", "origin/main"],
                capture_output=True, text=True, cwd=TOOL_HOME, timeout=30,
            ).stdout.strip()
        except Exception:
            merge_base = ""
        if not merge_base:
            self.skipTest("no origin/main merge-base resolvable in this checkout")

        rev_list = subprocess.run(
            ["git", "rev-list", f"{merge_base}..HEAD"],
            capture_output=True, text=True, cwd=TOOL_HOME, timeout=30,
        )
        commits = [c for c in rev_list.stdout.splitlines() if c]
        self.assertGreater(len(commits), 0, "expected at least one commit in range")

        touched_files = {
            "bin/clagentic-lite", "docs/GATES.md", "scripts/gates.sh",
            "scripts/test_doctor_gitleaks_version_floor.py",
            "scripts/test_secrets_positive_control.py",
        }

        scratch = tempfile.mkdtemp(prefix="clagentic-test-fullrange-scan-")
        try:
            scan_dir = os.path.join(scratch, "scan")
            os.makedirs(scan_dir)
            for commit in commits:
                for rel_path in touched_files:
                    show = subprocess.run(
                        ["git", "show", f"{commit}:{rel_path}"],
                        capture_output=True, text=True, cwd=TOOL_HOME, timeout=30,
                    )
                    if show.returncode != 0:
                        continue  # file didn't exist yet at this commit
                    dest = os.path.join(scan_dir, f"{commit}--{rel_path.replace('/', '_')}")
                    with open(dest, "w") as f:
                        f.write(show.stdout)

            report = os.path.join(scratch, "report.json")
            subprocess.run(
                ["gitleaks", "detect", "--no-banner", "--no-git",
                 "--source", scan_dir,
                 "--report-format", "json", "--report-path", report],
                capture_output=True, text=True, timeout=120,
            )
            findings = []
            if os.path.isfile(report):
                with open(report) as f:
                    content = f.read().strip()
                if content:
                    findings = json.loads(content)
            self.assertEqual(
                findings, [],
                msg=f"real gitleaks binary flagged findings across the "
                    f"{merge_base[:12]}..HEAD range's touched-file content: {findings}",
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def test_docs_gates_md_is_clean(self):
        """docs/GATES.md prose (this task's own documentation, lr-170808)
        mentions AWS's published doc-example access key literally, by name,
        to explain the stopword behavior -- verify gitleaks' stopword list
        actually suppresses it rather than assuming so, the same
        verify-don't-assume discipline this task's own IMPLEMENTATION
        WARNING is about."""
        report = tempfile.mktemp(prefix="clagentic-test-selfscan-docs-", suffix=".json")
        docs_dir = os.path.join(TOOL_HOME, "docs")
        try:
            subprocess.run(
                ["gitleaks", "detect", "--no-banner", "--no-git",
                 "--source", docs_dir,
                 "--report-format", "json", "--report-path", report],
                capture_output=True, text=True, timeout=120,
            )
            findings = []
            if os.path.isfile(report):
                with open(report) as f:
                    content = f.read().strip()
                if content:
                    findings = json.loads(content)
            offending = [
                f for f in findings
                if os.path.basename(f.get("File", "")) == "GATES.md"
            ]
            self.assertEqual(
                offending, [],
                msg=f"gitleaks flagged docs/GATES.md: {offending}",
            )
        finally:
            if os.path.isfile(report):
                os.remove(report)

    def test_branch_history_scan_on_clean_index_does_not_block_on_gates_sh(self):
        """The exact scenario PEACHES asked to be verified: the secrets
        gate run against branch history on a clean index must not block
        because it finds the planted canary credentials in its own source.
        Builds a REAL scratch git repo containing this repo's CURRENT
        scripts/gates.sh, commits it (clean index, mirroring the feature-
        branch/no-staged-changes path cmd_secrets takes), then runs the
        SAME capability-probed invocation cmd_secrets itself uses
        (`gitleaks git --help` -> `gitleaks git`, else `gitleaks protect`)
        -- and asserts it exits 0 with zero findings against the committed
        content."""
        tmp = tempfile.mkdtemp(prefix="clagentic-test-branch-history-")
        try:
            subprocess.run(["git", "init", "-q", "-b", "feature", tmp], check=True)
            env = {**os.environ, **_GIT_ENV}
            scripts_dir = os.path.join(tmp, "scripts")
            os.makedirs(scripts_dir)
            shutil.copy(GATES_SH, os.path.join(scripts_dir, "gates.sh"))
            subprocess.run(["git", "add", "scripts/gates.sh"], check=True, cwd=tmp, env=env)
            subprocess.run(["git", "commit", "-q", "-m", "seed gates.sh"],
                            check=True, cwd=tmp, env=env)
            # Clean index at this point -- nothing staged, mirroring the
            # exact precondition cmd_secrets checks before choosing the
            # branch-history scan path (_SECRETS_ON_FEATURE=1 branch).
            status = subprocess.run(["git", "status", "--porcelain"],
                                     capture_output=True, text=True, cwd=tmp, env=env)
            self.assertEqual(status.stdout, "", "index must be clean for this scenario")

            # Same capability probe cmd_secrets uses (scripts/gates.sh:669):
            # `gitleaks git --help` -> history-scan-capable `gitleaks git`;
            # otherwise the older `gitleaks protect --staged` surface, which
            # on a clean index scans nothing directly -- fall back further
            # to `gitleaks detect --no-git` against the committed tree so
            # this test still exercises "committed content, clean index" on
            # an installation with neither newer subcommand.
            probe = subprocess.run(["gitleaks", "git", "--help"],
                                    capture_output=True, text=True, timeout=30)
            if probe.returncode == 0:
                r = subprocess.run(
                    ["gitleaks", "git", "--no-banner", "--redact"],
                    capture_output=True, text=True, cwd=tmp, timeout=120,
                )
            else:
                report = tempfile.mktemp(prefix="clagentic-test-branch-history-", suffix=".json")
                r = subprocess.run(
                    ["gitleaks", "detect", "--no-banner", "--no-git",
                     "--source", tmp, "--report-format", "json", "--report-path", report],
                    capture_output=True, text=True, timeout=120,
                )
                if os.path.isfile(report):
                    os.remove(report)
            self.assertEqual(
                r.returncode, 0,
                msg=f"branch/committed-content scan blocked on gates.sh's own "
                    f"committed content -- stdout={r.stdout!r} stderr={r.stderr!r}",
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestCmdSecretsConfigPreflight(unittest.TestCase):
    """cmd_secrets' own wiring: a rules-less .gitleaks.toml blocks with the
    documented message, before gitleaks is ever invoked against real repo
    content."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-cmdsecrets-")
        subprocess.run(["git", "init", "-q", "-b", "main", self._tmp], check=True)
        env = {**os.environ, **_GIT_ENV}
        with open(os.path.join(self._tmp, "app.py"), "w") as f:
            f.write("def handle(x):\n    return x\n")
        subprocess.run(["git", "add", "app.py"], check=True, cwd=self._tmp, env=env)
        subprocess.run(["git", "commit", "-q", "-m", "seed"], check=True, cwd=self._tmp, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_rules_less_gitleaks_toml_blocks_before_scanning(self):
        _write_toml(self._tmp, ".gitleaks.toml", textwrap.dedent("""\
            [[allowlists]]
            description = "rules-less -- the reported defect"
            paths = ['''^.*$''']
        """))
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = self._tmp
        r = _run_gates_sh("cmd_secrets", env_extra=env, cwd=self._tmp)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("defines no rules", r.stderr)
        self.assertIn("useDefault = true", r.stderr)

    def test_valid_extend_config_does_not_hit_the_preflight_block(self):
        """A correctly-shaped config (useDefault = true) must not trip the
        preflight -- it proceeds to the canary/real scan instead. This repo
        has no planted secret in app.py, so the run should pass cleanly
        (or block on the canary if gitleaks itself cannot detect the
        fixture in this environment -- either way, never the preflight
        message)."""
        _write_toml(self._tmp, ".gitleaks.toml", textwrap.dedent("""\
            [extend]
            useDefault = true
        """))
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = self._tmp
        r = _run_gates_sh("cmd_secrets", env_extra=env, cwd=self._tmp)
        self.assertNotIn("defines no rules", r.stderr)


@unittest.skipUnless(_gitleaks_available(), "gitleaks not installed")
class TestReadDeterministicGatesNoCoverage(unittest.TestCase):
    """_read_deterministic_gates' no_coverage predicate (scope item 3) --
    keyed on the same fixed vocabulary cmd_secrets' preflight/canary block
    paths and the pre-existing older-gitleaks warn path already write."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="clagentic-test-nocoverage-")
        subprocess.run(["git", "init", "-q", self._tmp], check=True)
        env = {**os.environ, **_GIT_ENV}
        subprocess.run(["git", "-C", self._tmp, "commit", "-q", "--allow-empty", "-m", "seed"],
                        check=True, env=env)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _seed_and_read(self, gate, outcome, details):
        env = os.environ.copy()
        env["CLAGENTIC_PROJECT_ROOT"] = self._tmp
        r = subprocess.run(
            [GATES_SH, "log-run", gate, outcome, details],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(TOOL_HOME, "scripts"), timeout=30,
        )
        assert r.returncode == 0, r.stderr
        r2 = _run_gates_sh("_read_deterministic_gates", env_extra={"CLAGENTIC_PROJECT_ROOT": self._tmp})
        self.assertEqual(r2.returncode, 0, r2.stderr)
        return json.loads(r2.stdout)

    def test_canary_block_is_flagged_no_coverage(self):
        dg = self._seed_and_read(
            "secrets", "block",
            "positive-control canary failed: gitleaks did not detect a planted credential — scan result cannot be trusted (no coverage)",
        )
        self.assertTrue(dg["secrets"]["no_coverage"])

    def test_config_preflight_block_is_flagged_no_coverage(self):
        dg = self._seed_and_read(
            "secrets", "block",
            ".gitleaks.toml defines no rules and does not set [extend] useDefault = true. gitleaks --config replaces the built-in ruleset, so this configuration detects nothing. Add [extend] useDefault = true or declare rules.",
        )
        self.assertTrue(dg["secrets"]["no_coverage"])

    def test_older_gitleaks_history_scan_unavailable_warn_is_flagged_no_coverage(self):
        dg = self._seed_and_read(
            "secrets", "warn",
            "older gitleaks; no staged changes on feature branch (history scan unavailable)",
        )
        self.assertTrue(dg["secrets"]["no_coverage"])

    def test_ordinary_pass_is_not_flagged_no_coverage(self):
        dg = self._seed_and_read("secrets", "pass", "branch history scan (no staged changes)")
        self.assertFalse(dg["secrets"]["no_coverage"])

    def test_ordinary_missing_tool_block_is_not_flagged_no_coverage(self):
        """A different block cause (tool missing) must not be swept up by
        this predicate -- it is a distinct, pre-existing fail-closed path,
        not the "scanner ran but proved nothing" class this flag names."""
        dg = self._seed_and_read("secrets", "block", "gitleaks not installed (fail-closed)")
        self.assertFalse(dg["secrets"]["no_coverage"])


if __name__ == "__main__":
    unittest.main()
