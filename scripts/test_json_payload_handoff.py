"""
A JSON or text payload with no fixed size bound must never be an exec
argument. One argv string over the kernel's MAX_ARG_STRLEN (~128 KiB) fails
exec with E2BIG, and the caller then degrades a real result into a false "no
review recorded" or drops the ledger entry. Payloads reach jq or python3 by
file (_stage_payload_file) or on stdin.

Covers: the ledger-record and render paths with a payload over the limit, in
both the jq and the python3 branch; and a static sweep of gates.sh and
host-adapter.sh that flags any new argv-passed payload of that shape.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_source_helpers import GATES_SH, HOST_ADAPTER_SH, source_env  # noqa: E402

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}

# Comfortably past MAX_ARG_STRLEN (131072) once serialized.
_OVER_LIMIT_BYTES = 300 * 1024


def _big_findings():
    message = "x" * 1000
    count = _OVER_LIMIT_BYTES // 1000 + 1
    return [
        {"severity": "high", "file": "a%d.py" % i, "line": 1, "category": "c", "message": message}
        for i in range(count)
    ]


def _repo(tmp):
    repo = os.path.join(tmp, "repo")
    subprocess.run(["git", "init", "-q", "-b", "main", repo], check=True, timeout=60)
    with open(os.path.join(repo, "seed.txt"), "w") as f:
        f.write("seed\n")
    env = {**os.environ, **_GIT_ENV}
    subprocess.run(["git", "-C", repo, "add", "seed.txt"], check=True, env=env, timeout=60)
    subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "seed"], check=True, env=env, timeout=60)
    return repo


def _path_without_jq(tmp):
    """A bin dir of symlinks to every executable on PATH except jq, so the
    python3 branch of a jq-or-python3 helper is the one that runs."""
    farm = os.path.join(tmp, "nojq-bin")
    os.makedirs(farm)
    seen = set()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            full = os.path.join(d, name)
            if name == "jq" or name in seen or not os.access(full, os.X_OK) or os.path.isdir(full):
                continue
            seen.add(name)
            os.symlink(full, os.path.join(farm, name))
    return farm


def _run(repo, script, hide_jq_in=None):
    env = os.environ.copy()
    env.update(source_env(gates=True))
    env["CLAGENTIC_PROJECT_ROOT"] = repo
    if hide_jq_in:
        env["PATH"] = hide_jq_in
    full = ". '%s'\n%s\n" % (GATES_SH, script)
    return subprocess.run(["sh", "-c", full, GATES_SH], capture_output=True, text=True,
                          env=env, cwd=repo, timeout=120)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="clagentic-test-handoff-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = _repo(self.tmp)
        self.findings = _big_findings()
        self.assertGreater(len(json.dumps(self.findings)), 131072)

    def _branches(self):
        yield "jq", None
        yield "python3", _path_without_jq(self.tmp)


class TestOverLimitPayloads(_Base):
    def test_ledger_record_writes_an_over_limit_findings_list(self):
        envelope = os.path.join(self.tmp, "out.json")
        with open(envelope, "w") as f:
            json.dump({"summary": "s", "checked": [], "findings": self.findings}, f)
        for label, path in self._branches():
            with self.subTest(branch=label):
                ledger = os.path.join(self.repo, ".clagentic", "lite", "review-ledger.jsonl")
                if os.path.exists(ledger):
                    os.unlink(ledger)
                res = _run(self.repo,
                           "_ledger_record_review_verdict adversarial '%s' '' block base1 head1" % envelope,
                           hide_jq_in=path)
                self.assertEqual(res.returncode, 0, res.stderr[-500:])
                with open(ledger) as f:
                    lines = [json.loads(line) for line in f if line.strip()]
                self.assertEqual(len(lines), 1, "the entry must be recorded, not dropped")
                self.assertEqual(len(lines[0]["findings"]), len(self.findings))
                self.assertEqual(lines[0]["verdict"], "block")

    def test_render_reports_an_over_limit_findings_list(self):
        listing = os.path.join(self.tmp, "findings.json")
        with open(listing, "w") as f:
            json.dump(self.findings, f)
        res = _run(self.repo, "_render_review_verdict_lines head1 \"$(cat '%s')\"" % listing)
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        self.assertIn("Findings: %d total" % len(self.findings), res.stdout)

    def test_recurrence_marking_keeps_an_over_limit_findings_list(self):
        listing = os.path.join(self.tmp, "findings.json")
        with open(listing, "w") as f:
            json.dump(self.findings, f)
        res = _run(self.repo,
                   "_ledger_mark_recurrence \"$(cat '%s')\" '' '%s/none.jsonl' main" % (listing, self.tmp))
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        marked = json.loads(res.stdout)
        self.assertEqual(len(marked), len(self.findings))
        self.assertTrue(all(f["_ledger_recurring"] is False for f in marked))

    def test_adversarial_findings_fence_accepts_an_over_limit_array_without_jq(self):
        listing = os.path.join(self.tmp, "findings.json")
        with open(listing, "w") as f:
            json.dump(self.findings, f)
        res = _run(self.repo, "_fence_adversarial_findings \"$(cat '%s')\"" % listing,
                   hide_jq_in=_path_without_jq(self.tmp))
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        text = json.loads(res.stdout)
        self.assertIn("===BEGIN ADVERSARIAL FINDINGS DATA===", text)
        self.assertIn("a%d.py" % (len(self.findings) - 1), text)

    def test_stage_payload_file_round_trips_an_over_limit_payload(self):
        res = _run(self.repo,
                   "p=$(python3 -c \"print('y' * %d)\")\n"
                   "f=$(_stage_payload_file clagentic-test \"$p\") || exit 3\n"
                   "wc -c < \"$f\"\nrm -f \"$f\"" % _OVER_LIMIT_BYTES)
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        self.assertEqual(int(res.stdout.strip()), _OVER_LIMIT_BYTES)


# Variable names that carry an unbounded payload when handed to jq or python3.
_PAYLOAD_NAME = re.compile(r"findings|payload|json|body|report|text|entries|deferrals|summary", re.I)
# A path, count or fixed value is not a payload even when its name says "json".
_NOT_A_PAYLOAD = re.compile(r"(file|path|tmp|dir|sha|count|label|keys|unavailable|fenced_arg)$", re.I)

# Argv-passed on purpose, each with the bound that makes it safe.
_BOUNDED_BY_DESIGN = {
    # Each field is cut to the shared _llm_field_sanitize cap and the object
    # holds three gates.
    "DETERMINISTIC_GATES_PAYLOAD": "three sanitized details fields",
    "DETERMINISTIC_GATES_FENCED_PAYLOAD": "the same object, fenced",
    # One sanitized summary string, cut to the same cap.
    "_srp_summary": "one sanitized field",
    # Named like a payload, but each holds a path or a flag.
    "_gpc_report": "path to the scanner report",
    "_lmr_prior_entries": "path to the prior-entries temp file",
    "_srp_has_summary": "the literal 0 or 1",
}

_VAR = re.compile(r"\"\$\{?([A-Za-z_][A-Za-z0-9_]*)")


def _logical_lines(lines):
    out, buf, start = [], "", 0
    for n, raw in enumerate(lines, 1):
        if not buf and raw.strip().startswith("#"):
            continue
        if not buf:
            start = n
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        out.append((start, buf + raw))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def _argv_segments(text):
    """Yield (line_no, argv_text) for every place a jq or python3 command line
    receives arguments. A multi-line python3 -c script's arguments follow its
    closing quote on a later line."""
    lines = text.splitlines()
    in_script = False
    for n, logical in _logical_lines(lines):
        if in_script:
            stripped = logical.lstrip()
            if stripped.startswith("'"):
                in_script = False
                yield n, stripped[1:]
            continue
        for m in re.finditer(r"\bjq\b|\bpython3\b", logical):
            rest = logical[m.end():]
            if m.group(0) == "jq":
                yield n, rest
            elif " -c '" in rest and rest.count("'") % 2 == 1:
                in_script = True
            elif " -c '" in rest:
                yield n, rest[rest.rindex("'") + 1:]
            else:
                yield n, rest


def find_argv_payloads(text):
    """(line_no, variable) for each argv-passed variable that looks like an
    unbounded payload and is not allowlisted."""
    hits = []
    for n, argv in _argv_segments(text):
        # A pipe feeds stdin; only the part of a line up to the next shell
        # operator belongs to this command.
        argv = re.split(r"\s(?:\||&&|\|\|)\s|<<|>", argv)[0]
        for name in _VAR.findall(argv):
            if _PAYLOAD_NAME.search(name) and not _NOT_A_PAYLOAD.search(name) \
                    and name not in _BOUNDED_BY_DESIGN:
                hits.append((n, name))
    return hits


class TestNoArgvPayloads(unittest.TestCase):
    def test_gates_and_host_adapter_pass_no_unbounded_payload_by_argv(self):
        for path in (GATES_SH, HOST_ADAPTER_SH):
            with open(path, encoding="utf-8") as f:
                hits = find_argv_payloads(f.read())
            self.assertEqual(hits, [], "%s passes a payload as an exec argument; stage it with "
                             "_stage_payload_file or send it on stdin" % os.path.basename(path))

    def test_sweep_flags_each_argv_shape(self):
        shapes = [
            "jq -nc --argjson findings \"$_x_findings\" '.'\n",
            "jq --arg body \"$_x_body\" '.'\n",
            "python3 - \"$_x_findings_json\" <<'PYEOF'\nimport sys\nPYEOF\n",
            "python3 -c 'import sys' \"$_x_payload\"\n",
            "python3 -c '\nimport sys\nprint(1)\n' \"$_x_report\"\n",
            "jq -c --argjson df \"$_x_deduped_json\" \\\n  '.findings = $df' env.json\n",
        ]
        for shape in shapes:
            with self.subTest(shape=shape):
                self.assertTrue(find_argv_payloads(shape), shape)

    def test_sweep_ignores_paths_stdin_and_bounded_values(self):
        shapes = [
            "jq -nc --slurpfile findings \"$_x_findings_file\" '.'\n",
            "printf '%s' \"$_x_findings\" | python3 -c 'import sys' \n",
            "printf '%s' \"$_x_json\" | jq --arg k \"$_x_key\" '.'\n",
            "python3 - \"$_x_findings_file\" \"$_x_ts\" <<'PYEOF'\nimport sys\nPYEOF\n",
            "python3 -c '\nimport sys\n' \"$_srp_file\"\n",
            "jq -n --arg d \"$_x_details\" '.'\n",
        ]
        for shape in shapes:
            with self.subTest(shape=shape):
                self.assertEqual(find_argv_payloads(shape), [], shape)


if __name__ == "__main__":
    unittest.main()
