# clagentic-lite — Gates reference

Each gate is documented here: what it does, where it fires, what blocks, how to override.

> **Scope:** All gates described here are per-project. They activate only in enrolled repos. If a gate is not firing, confirm the project is enrolled: run `clagentic-lite list` to see enrolled repos, or `clagentic-lite enroll` to enroll the current directory.

## Gate 1 — Memory inject

| | |
|---|---|
| **Fires** | `UserPromptSubmit` (every prompt) |
| **Tool** | `scripts/memory.sh recall` |
| **Blocks?** | No (read-only context injection) |
| **Output** | Up to `CLAGENTIC_RECALL_LIMIT` (default 5) prior session summaries prepended, capped at `CLAGENTIC_RECALL_MAX_CHARS` (default 1500) total chars. Memory DB at `.clagentic/lite/memory.db`. |
| **Disable** | `CLAGENTIC_DISABLE_RECALL=1` |

Keyword extraction is the simplest thing that works: strip stopwords from the prompt, take tokens ≥4 chars, `LIKE %token%` against the `tags` and `summary` columns. Top N by recency. If nothing matches, inject nothing.

## Gate 2 — Safe Bash + writes

| | |
|---|---|
| **Fires** | `PreToolUse` for `Bash`, `Write`, `Edit` |
| **Tool** | `.claude/hooks/pre-bash-guard.sh`, `pre-write-guard.sh` |
| **Blocks?** | Yes (exit 2). Also blocks if neither `jq` nor `python3` is on PATH — hooks need a JSON validator to parse tool input safely, and a hook that can't parse fails closed. |
| **JSON parsing** | `ds_json_field` (in `scripts/platform.sh`) routes through `jq` if present, `python3` as fallback. The previous `sed`-based parser truncated on escaped quotes and was a known R-005 bypass surface. |
| **Path normalization** | `pre-write-guard.sh` resolves relative paths against the repo root via `python3 os.path.realpath` before the W-002 "inside repo" check, so `../outside.txt` traversal blocks. |
| **Override** | `CLAGENTIC_ALLOW_BASH_RULES=R-XXX` (comma-separated) in `.clagentic/config` or `~/.config/clagentic/config`. Document the reason in your commit or PR body. Never edit `pre-bash-guard.sh` to remove a rule. |

Bash rules (R-001 through R-020) implemented inline in `pre-bash-guard.sh`:

| ID | Pattern | Reason |
|---|---|---|
| R-001 | `rm -rf /` (any variant) | catastrophic |
| R-002 | `rm -rf $HOME` | catastrophic |
| R-003 | `curl ... | sh` / `wget ... | bash` | remote-code-execution antipattern |
| R-004 | `chmod -R 777` | overpermissive |
| R-005 | `git reset --hard` (without explicit confirm) | destroys uncommitted work |
| R-006 | `git checkout .` / `git restore .` (no path) | destroys uncommitted work |
| R-007 | `git push --force` / `-f` / `--force-with-lease` targeting `${CLAGENTIC_DEFAULT_BRANCH}` — either by name in the command, or by current branch being the default | history rewrite on protected branch |
| R-008 | `git clean -fdx` | nukes ignored files including `.env` |
| R-009 | `git commit --no-verify` | bypasses our gates |
| R-010 | `npm publish` / `pip upload` / `cargo publish` (unguarded) | publishes to a registry |
| R-011 | `sudo` (any) | elevates outside the harness |
| R-012 | `eval $(...)` / `eval "$..."` | indirect execution |
| R-013 | `aws s3 rm --recursive` | catastrophic cloud delete |
| R-014 | `terraform destroy` (unguarded) | catastrophic cloud delete |
| R-015 | `docker system prune -a` | nukes local images/volumes |
| R-016 | `git config --global` | mutates global state |
| R-017 | `chsh` / `passwd` | account modification |
| R-018 | `> /dev/sda*` / `dd of=/dev/...` | disk-level write |
| R-019 | `find ... -delete` without a literal (non-wildcard) `-path` constraint | unbounded delete |
| R-020 | `: > <large path>` / truncation of `.env`/credentials | credential destruction |

Write rules:

| ID | Rule | Bypass |
|---|---|---|
| W-001 | No writes to `${CLAGENTIC_DEFAULT_BRANCH}` — must be on a feature branch | `CLAGENTIC_ALLOW_DEFAULT_BRANCH_WRITE=1` in `.clagentic/config` |
| W-002 | No writes outside `git rev-parse --show-toplevel` | none — path traversal is never legitimate |
| W-003 | No writes to `.git/`, `.clagentic/`, `.env` | none |
| W-004 | No writes to files matching `**/*.pem`, `**/id_rsa*`, `**/*.key` | none |

## Gate 3 — Cross-CLI review

| | |
|---|---|
| **Fires** | `/review` slash command (which routes through `scripts/gates.sh review` — never bypassed); optional pre-push hook (`CLAGENTIC_REVIEW_ON_PUSH=1`) |
| **Tool** | `scripts/gates.sh review` → `scripts/llm-client.sh review` |
| **Blocks?** | (a) Findings ≥ `${CLAGENTIC_BLOCK_SEVERITY}` block `/ship`; (b) degraded envelopes (every Reviewer chain step failed) block; (c) unparseable JSON blocks (sentinel value 99). |
| **Default severity** | `high` |
| **Per-call timeout** | `${CLAGENTIC_LLM_TIMEOUT_SEC}` seconds (default 180). Hung CLI → step failure → chain advances. |
| **Required-role enforcement** | `CLAGENTIC_REVIEWER_REQUIRED=1` makes a full-chain failure a hard gate error (non-zero exit) instead of a degraded envelope. Use when the cross-vendor property is non-negotiable and a same-vendor fallback must be a visible failure rather than a silent degradation. Applies to any role: `CLAGENTIC_<ROLE>_REQUIRED=1`. |

### Reviewer-consulted deferrals

When an operator has reviewed a finding and decided to defer it — because it is
a known fixture, an intentional design choice, or a false positive they have
accepted — they can record that decision in `.clagentic/deferrals.json`. The
file is read at review time and injected into the reviewer system prompt as
context before the diff is reviewed.

**File location:** `.clagentic/deferrals.json` in the enrolled repo. The
`.clagentic/` directory is gitignored by the gate orchestrator, so this file is
local state — it is not committed. Do not commit deferrals to version control;
use `.clagentic/adversarial-acks.json` or `.clagentic/accepted-risks.md` for
committed, audited suppression.

**Schema (JSON array):**

```json
[
  {
    "id": "def-001",
    "category": "sql",
    "file": "scripts/seed-demo.sh",
    "description": "Planted demo credential — intentional fixture, not production code.",
    "expires": "2026-12-31",
    "acknowledged_by": "akuehner"
  }
]
```

Fields:

| Field | Required | Description |
|---|---|---|
| `id` | yes | Stable identifier for the deferral |
| `category` | no | Finding category this deferral applies to |
| `file` | no | Exact path or path glob this deferral applies to |
| `description` | yes | Human-readable reason for the deferral |
| `expires` | no | ISO date after which the deferral should be reconsidered |
| `acknowledged_by` | no | Who approved the deferral |

**Suppression is inside model judgment, not gate code.** The deferrals file is
injected verbatim into the reviewer system prompt. The gate does NOT parse
finding output to post-filter based on deferrals. If the LLM still emits a
finding despite a deferral entry, the finding stands. This is intentional:
the LLM is better placed to reason about whether a deferral is still applicable
than a regex or equality match in shell code.

**`expires` field semantics:** the gate does not parse or compute expiry dates.
The expiry text is passed to the LLM verbatim so the model can reason about
whether the deferral is still valid given the current context. The gate has no
date arithmetic.

**Fail-open:** if `.clagentic/deferrals.json` is absent, empty, or unreadable,
the review runs as if no deferrals exist. The gate never blocks on a missing
deferrals file. A malformed file (non-JSON) is treated the same as an absent
file — the content is injected as-is and the LLM will ignore text it cannot
interpret as a deferral list.

**Deferrals vs. `accepted-risks.md`:**

| Mechanism | Location | Read by | Suppression path |
|---|---|---|---|
| `deferrals.json` | `.clagentic/deferrals.json` (gitignored) | Gate 3 reviewer prompt | LLM judgment |
| `accepted-risks.md` | `.clagentic/accepted-risks.md` (committed) | Gate 6 merge-gate | Gate plumbing reads the doc; merge-gate LLM classifies covered findings as acknowledged |

Use deferrals for local, ephemeral, or per-session suppression guidance. Use
`accepted-risks.md` for committed, audited architectural decisions that persist
in the repo history.

### Cross-round finding dedup (opt-in)

| | |
|---|---|
| **Feature flag** | `CLAGENTIC_CROSS_ROUND_DEDUP` (default: `1` — on; set `=0` to opt out) |
| **Seen-keys file** | `.clagentic/lite/review-seen-keys` (gitignored, local gate state) |
| **Key strategy** | `content-hash`: sha256 of a 5-line `+`-line context window around the finding from the diff. Survives line shifts (a line that moves without changing its content has the same key). If the window cannot be computed (no sha256 tool, no diff file), the finding is retained conservatively — wrong suppressions are worse than missed dedups. |
| **Effect** | Findings reported in a prior round on lines the diff shows unchanged since are suppressed. Suppression is annotated: a `gate_runs` audit row (`gate=review-dedup`) records `suppressed:N/total:M` and the operator sees a stderr notice (`[dedup] suppressed N finding(s) seen in prior run(s)`). Silently dropped findings are not possible — every suppression is logged. |
| **Reset** | `clagentic-lite gates review --reset-dedup` deletes `.clagentic/lite/review-seen-keys`. The next review run re-seeds the file from scratch. |
| **Conservative bias** | Bias is toward showing. A finding on changed lines will always re-show (the diff window changes → different hash → not suppressed). A finding where the key cannot be computed (parse error, no diff file, no sha256) is retained. |
| **First run** | Seen-keys file absent → no-op: all findings pass through; keys for this run's findings are appended for use by the next round. |

Configure in `.clagentic/config` (per-repo) or `~/.config/clagentic/config` (global). See `share/config.example` for the full entry.

### Exit-code contract for `gates.sh review` and `gates.sh ship`

`gates.sh review` distinguishes two failure classes with separate exit codes. CI and operator scripts should branch on these:

| Exit code | Constant | Meaning | Action |
|---|---|---|---|
| `0` | — | Clean review, no findings at or above severity threshold | Proceed |
| `1` | `REVIEW_BLOCKED` | Reviewer returned real findings at or above `${CLAGENTIC_BLOCK_SEVERITY}` | Fix the code, re-run review |
| `2` | `INFRA_DEGRADED` | Every Reviewer chain step failed; degraded envelope returned; no real review occurred | Check LLM CLI config/auth and retry; do not ship |

`gates.sh ship` propagates these codes at the ship level when the review gate fires:

- Ship exits `2` when the review gate returns `INFRA_DEGRADED`.
- Ship exits `1` for all other blocking gate failures (secrets, deps, sast, review-blocked, merge-gate).

**Audit trail:** the `gate_runs` table records the failure class in the `details` column:

- `infra-degraded: all reviewer chain steps failed` — for degraded envelope path
- `review-blocked: N finding(s) at >= THRESHOLD` — for real findings path

Example query to distinguish failure classes:

```sh
sqlite3 .clagentic/lite/audit.db \
  "SELECT ts, outcome, details FROM gate_runs WHERE gate='review' ORDER BY ts DESC LIMIT 5;"
```

Reviewer prompt and JSON schema are pinned in `.claude/agents/reviewer.md` (Pre-Report Gate + Common False Positives list). Output is persisted at `.clagentic/lite/last-review.json` and into `audit.db.gate_runs`. Per-step LLM-call attempts are logged separately (`gate=llm-call`) with a one-line error hint from stderr.

The Reviewer never has write tools. The Builder never sees its own review pre-graded. The Reviewer prompt forbids "looks good to me" outputs without specific evidence.

## Gate 4 — Local security scan

Three independent sub-gates run as standard git hooks:

### 4a. Secrets (pre-commit)

| | |
|---|---|
| **Tool** | `gitleaks git --staged --pre-commit --redact --no-banner` (8.18+) or `gitleaks protect --staged --redact --no-banner` (older). The orchestrator capability-probes via `gitleaks git --help` and picks the right surface. |
| **Blocks?** | Yes. Also blocks if gitleaks is missing entirely — set `CLAGENTIC_ALLOW_MISSING_GITLEAKS=1` to skip explicitly. |
| **Override** | None for findings — secrets cannot be committed. Rotate, then re-stage. |
| **Augment** | `.gitleaks.toml` in repo root extends the default ruleset. Path-scoped allowlists only (see `.gitleaks.toml` comment for why regex allowlists on token literals are dangerous). |

### 4b. Dependencies (pre-push)

| | |
|---|---|
| **Tool** | `osv-scanner scan --recursive --format=json --config=<tmpfile> .` (newer releases) or `osv-scanner --recursive --severity=<S> .` (older releases). Version probed by subcommand availability, not version string. |
| **Blocks?** | Yes, on vulnerabilities at or above the configured severity. Default is `CRITICAL`. |
| **Severity** | Set `CLAGENTIC_OSV_SEVERITY` in `~/.config/clagentic/config` or `.clagentic/config`. Values: `CRITICAL` (default), `HIGH`, `MEDIUM`, `LOW`. Set `LOW` to restore block-on-any-finding behavior. Newer releases no longer expose a scan-time severity filter, so clagentic-lite captures JSON and applies the threshold to osv-scanner's computed `max_severity` values. Missing or malformed severity data blocks fail-closed. |
| **Ignore list** | Add CVE/GHSA IDs one-per-line to `~/.config/clagentic/osv-ignore` (global) or `.clagentic/osv-ignore` (repo). Lines starting with `#` and blank lines are ignored. For newer releases, these become `[[IgnoredVulns]]` blocks in the generated temp config; for older releases, they are passed as `--ignore-vulns=<id>`. |
| **Missing tool** | Set `CLAGENTIC_ALLOW_MISSING_OSV=1` to skip if osv-scanner is not installed. |

### 4c. SAST (pre-push)

| | |
|---|---|
| **Tool** | `semgrep --config=auto --error --severity=ERROR` |
| **Blocks?** | Yes, on ERROR. `--error` makes semgrep exit non-zero only on ERROR-severity findings; WARNING-and-below findings still print but don't block. |
| **Override** | `.semgrepignore` at the repo root (natively honored by semgrep — add file paths or rule IDs to suppress); `# nosemgrep: <rule-id> — <reason>` inline in source. |
| **Missing tool** | Set `CLAGENTIC_ALLOW_MISSING_SEMGREP=1` if semgrep is not installed locally. |

Rationale: deterministic tools, well-understood, no LLM in the security path. The LLM-driven `adversarial` layer (Gate 5) is separate and non-blocking by design.

## Gate 5 — Adversarial pass

| | |
|---|---|
| **Fires** | `/review --adversarial`; `scripts/gates.sh adversarial` |
| **Tool** | Auditor role via `scripts/llm-client.sh adversarial` |
| **Blocks?** | No — commentary only |
| **Output** | Markdown attack scenarios saved to `.clagentic/lite/last-adversarial.md`; attach to PR if interesting |

The Auditor argues, in concrete terms, how a hostile user could exploit each new or modified input surface. Cites file:line. Names threats with CWE if obvious. If nothing is exploitable, says so in one sentence and lists the surfaces considered.

### Finding format (prose-primary with structured header)

Each finding in the adversarial output begins with a compact header line, followed by a prose explanation:

```
[FINDING] CWE-XXX | file.ext:line | severity: high | title: Short description phrase

Prose explanation (1-3 paragraphs): what the vulnerability is, how an
attacker exploits it, and what a minimal fix looks like.
```

Header fields:

| Field | Values |
|---|---|
| `[FINDING]` | Literal tag; always the first token on the header line |
| CWE | Most specific CWE Base-level ID (e.g. `CWE-78`); `CWE-unknown` if not applicable |
| file:line | Specific file and line number (e.g. `scripts/gates.sh:42`); `general` if not file-specific |
| severity | `critical` / `high` / `medium` / `low` |
| title | One short phrase, eight words or fewer |

This is a "prose-primary with structured header" format: the header makes the output scannable at a glance; the prose below it preserves the full adversarial explanation. If the model does not emit `[FINDING]` headers (format mismatch, older model), the prose output is still valid and usable — the format is additive, not a schema enforcement.

For a heavier, structured threat-model pass, use the `/infosec-rt` skill instead — multi-persona chained attack scenarios with hardening priority list.

### Invariant-feed (opt-in) — forward-invariant memory across rounds

| | |
|---|---|
| **Feature flag** | `CLAGENTIC_ADVERSARIAL_INVARIANTS` (default: `0` — off; set `=1` to opt in) |
| **File location** | `.clagentic/lite/invariants.json` (gitignored, local gate state — same convention as `last-review.json` and `review-seen-keys`) |
| **Effect** | When present and the flag is set, the file is injected verbatim into the adversarial system prompt with an inverted instruction relative to reviewer deferrals: "these invariants must still hold — verify the diff against each" instead of "these findings are deferred, do not re-report." |
| **Fail-open** | Absent, empty, or unreadable file → the pass proceeds with no invariants. Never blocks — Gate 5 is non-blocking regardless. |
| **Population** | Manual/operator-maintained. When a finding resolves, distill its message + category into an invariant statement and append it to the file. |

**Why this exists:** the adversarial gate is context-free by construction — each round re-derives threats from scratch off the diff alone, with no memory of what a prior round already found and fixed. Cross-round dedup (`CLAGENTIC_CROSS_ROUND_DEDUP`, above) is *suppression* memory: it hushes a finding already reported. The invariant-feed is the opposite polarity — *assertion* memory: it actively re-checks the diff against previously-resolved issues, including reintroduction at a wider scope than where the issue was originally fixed (e.g. a fail-open sentinel fixed at item scope recurring at fleet scope two rounds later). The two mechanisms are independent and can be used together.

**Schema (JSON array):**

```json
[
  {
    "id": "inv-001",
    "category": "security",
    "file": "scripts/example.sh",
    "statement": "Dedup-key derivation must not trust client-settable input."
  }
]
```

| Field | Required | Description |
|---|---|---|
| `id` | yes | Stable identifier for the invariant |
| `category` | no | Finding category this invariant applies to |
| `file` | no | Exact path or path glob this invariant applies to |
| `statement` | yes | The property that must still hold, stated as a check the Auditor can verify against the diff |

## Gate 6 — Merge Gate

| | |
|---|---|
| **Fires** | `scripts/gates.sh ship` (the `/ship` slash command), after all other gates have passed |
| **Tool** | LLM "gate" role via `scripts/llm-client.sh merge-gate` |
| **Input** | A JSON gate-summary payload (`.clagentic/lite/gate-summary.json`) built from `last-review.json` + `last-adversarial.md` + threshold |
| **Output** | `{decision: "approve" | "refuse", reason: "<one sentence>"}` JSON at `.clagentic/lite/last-merge-gate.json` |
| **Blocks?** | **Yes by default** (`CLAGENTIC_MERGE_GATE_BLOCKING=1`). Set to `0` to make advisory. |
| **Unparseable decision** | Also blocks — schema-invalid merge-gate output is treated as a gate failure, not a pass. |

The Merge Gate is the last LLM check before the PR is opened. It never overrides the deterministic security gates (those already gated upstream) and never adds its own findings — it reads the structured outputs of every prior gate and returns a single approve/refuse decision.

If an adversarial finding describes inherent product behavior (e.g., a security dashboard that exposes CVE data to authenticated analysts), commit `.clagentic/accepted-risks.md` to the repo documenting the decision. The merge-gate reads that file and classifies covered findings as acknowledged rather than refusing. Copy `share/accepted-risks.example.md` from the clagentic-lite install tree as a starting template. For per-CWE structured acknowledgments with path-glob scoping, `.clagentic/adversarial-acks.json` remains the more precise mechanism and takes precedence when both apply.

## Gate 7 — Session summarize

| | |
|---|---|
| **Fires** | `Stop` (async, debounced) |
| **Tool** | `scripts/memory.sh summarize-turn` |
| **Blocks?** | No |
| **Debounce** | `CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC=20` |

Reads the last assistant turn from the Claude Code transcript path, passes it through the Summarizer (`CLAGENTIC_SUMMARIZER_CMD` at cheap tier), inserts one row into `.clagentic/lite/memory.db.turns` with `source='stop-hook'`. Best-effort: if the summarizer fails, the session continues uninterrupted and the row is skipped. `python3` is required for transcript JSONL parsing — without it, the hook logs `summarize skip` to audit.db and exits cleanly.

## Auditing what happened

```sh
# every gate run today
sqlite3 .clagentic/lite/audit.db \
  "SELECT ts, gate, outcome, substr(details,1,80) FROM gate_runs WHERE ts > date('now','-1 day') ORDER BY ts"

# digest (human-readable; time-ordered, last 24h)
scripts/gates.sh digest

# status (last N runs per gate, color-coded; defaults to N=10)
scripts/gates.sh status
scripts/gates.sh status 25

# tail (follow audit.db live; new rows render as they land — Ctrl-C to quit)
scripts/gates.sh tail
CLAGENTIC_TAIL_INTERVAL_SEC=2 scripts/gates.sh tail   # adjust poll interval
```

`status` and `tail` honor `NO_COLOR=1` and emit plain text when stdout is not a TTY (safe to pipe to a file). Both are read-only — neither writes to `audit.db`, neither runs a gate, neither spawns a daemon.

## Working around gates — use config, not code edits

**Do not edit hook source files or gate scripts to bypass a blocking rule.** The right path is always a config variable, an ignore file, or a native tool mechanism. The table below covers every supported bypass. All bypasses are visible in the audit trail.

| Gate | Situation | How to handle it |
|---|---|---|
| Gate 4a — secrets | False-positive token | Add a path-scoped allowlist entry to `.gitleaks.toml`. Do not use regex allowlists on token literals. |
| Gate 4b — deps | Pre-existing CVE you accept | Add the ID to `.clagentic/osv-ignore` (repo) or `~/.config/clagentic/osv-ignore` (global). One ID per line. |
| Gate 4b — deps | Want to ignore below CRITICAL | Set `CLAGENTIC_OSV_SEVERITY=HIGH` (or `MEDIUM`) in `.clagentic/config`. |
| Gate 4c — SAST | False-positive semgrep rule | Add the file path to `.semgrepignore`, or add `# nosemgrep: <rule-id> — <reason>` inline. |
| Gate 2 — bash guard | Legitimate command blocked by a rule | Set `CLAGENTIC_ALLOW_BASH_RULES=R-XXX` in `.clagentic/config`. Multiple rules: comma-separated. Add a comment explaining why in the commit. |
| Gate 2 — write guard (W-001) | Intentional work on default branch | Set `CLAGENTIC_ALLOW_DEFAULT_BRANCH_WRITE=1` in `.clagentic/config`. This is unusual — default-branch protection exists for good reason. |
| Gate 3 — review | Cross-vendor fallback silently taken | Set `CLAGENTIC_REVIEWER_REQUIRED=1` to make chain failure a hard error. Chain fallback becomes visible in audit trail and the gate blocks rather than emitting a degraded envelope. |
| Gate 6 — adversarial (via merge-gate) | By-design behavior flagged as a CWE finding (per-CWE, path-scoped) | Commit `.clagentic/adversarial-acks.json` to the repo. See "adversarial-acks.json" below. |
| Gate 6 — adversarial (via merge-gate) | Finding is inherent product behavior (architectural, not per-CWE) | Commit `.clagentic/accepted-risks.md` documenting the decision. Copy `share/accepted-risks.example.md` as template. See "accepted-risks.md" below. |
| Any gate | Tool not installed | Set `CLAGENTIC_ALLOW_MISSING_<TOOL>=1`. Prefer installing the tool. |

### adversarial-acks.json — per-finding acknowledgment for the merge gate

When an adversarial finding reflects intentional design (e.g., a service that reads untrusted input by contract), you can acknowledge it rather than suppress the adversarial pass entirely. The acknowledgment is committed to the repo so it is visible in code review and audit.

**File location:** `.clagentic/adversarial-acks.json` in the enrolled repo root.

**Schema:** a JSON array of ack objects. Copy `adversarial-acks.json.example` from the clagentic-lite install tree root as a starting point.

```json
[
  {
    "cwe": "CWE-807",
    "path_glob": "src/reachability/**",
    "rationale": "Deployment-discovery reads K8s workload specs by design; security analysts viewing CVEs is the product surface.",
    "acknowledged_by": "andy",
    "acknowledged_at": "2026-06-04"
  }
]
```

Fields:

| Field | Required | Description |
|---|---|---|
| `cwe` | yes | CWE identifier string, e.g. `"CWE-807"` |
| `path_glob` | no | If present, the ack only applies when the cited file matches this glob. If absent, the ack covers all paths for that CWE. |
| `rationale` | yes | Human-readable explanation of why the finding is intentional |
| `acknowledged_by` | yes | Who made the call |
| `acknowledged_at` | yes | ISO date string |

**Coverage rule:** a finding is covered when (a) its CWE matches `acks[].cwe`, and (b) either `path_glob` is absent or the cited file matches `path_glob`.

**Effect:** when all blocking adversarial findings are covered, the merge gate approves and writes a `gate_runs` row to `audit.db` with the full per-finding detail (CWE, cited file:line, rationale) in the `details` column. Uncovered findings still refuse. The gate output also includes an `acknowledged` array for inspection via `clagentic-lite show gates`.

**Important:** the acks file must be committed deliberately. A missing file means no acks are in effect — the merge gate sees an empty list and refuses on any unmitigated CWE finding.

**Trust model:** `adversarial-acks.json` is repo-controlled. It is a workflow convenience for trusted internal contributors, not a security control. `acknowledged_by` is a plain string — it is not verified or authenticated. A contributor can add both a regression and a covering ack entry in the same diff; the gate has no way to detect this. `path_glob` entries should be as narrow as the real affected scope — overly broad globs (e.g., `**`) allow future regressions in covered files to be silently acknowledged. The structural fix is CODEOWNERS protection on `.clagentic/adversarial-acks.json` so adding or editing an entry requires review from someone outside the submitter. Until that is in place, treat the ack mechanism as convenience, not enforcement.

**Bootstrap sequence — first ack in a repo:** the first time you commit `.clagentic/adversarial-acks.json` (or `accepted-risks.md`), the merge-gate adversarial pass may flag the file itself ("repo-controlled suppression", "unauthenticated acknowledged_by"). The gate-summary payload includes a deterministic `introduces_ack_file` boolean (set by `build_gate_summary` via `git diff --name-status`). When `true` — meaning the ack file is being **added** in this exact diff, not modified — the merge-gate applies a bootstrap exemption and does not block on findings whose only cited file is the ack file itself. Findings on other files in the same diff are still evaluated normally. Recommended practice: add `.clagentic/adversarial-acks.json` and `.clagentic/accepted-risks.md` to `.github/CODEOWNERS` (or your host's equivalent) so all future edits require explicit human approval. Once the ack file is on the default branch, subsequent diffs that the ack covers pass normally.

### accepted-risks.md — architectural risk documentation for the merge gate

When an adversarial finding describes behavior that is inherent to the product's stated purpose — not a bug or an oversight, but a deliberate architectural decision — commit `.clagentic/accepted-risks.md` to the repo documenting that decision. The merge-gate reads this file and uses it to classify covered findings as acknowledged rather than refused.

**File location:** `.clagentic/accepted-risks.md` in the enrolled repo root.

**Template:** copy `share/accepted-risks.example.md` from the clagentic-lite install tree. It shows the recommended format with example entries.

**Format:** freetext markdown. Each entry should state the CWE(s) it covers, the specific behavior that triggers the finding, why that behavior is intentional, and who accepted it and when.

**Effect:** the merge-gate reads the document and, for each adversarial finding that would otherwise block, checks whether the finding describes behavior that is inherent to the stated product purpose as documented in `accepted_risks`. Covered findings are approved with `"source": "accepted-risks"` in the `acknowledged` array. Uncovered findings still refuse.

**When to use this vs. adversarial-acks.json:** use `adversarial-acks.json` for precise per-CWE, path-glob-scoped acknowledgments. Use `accepted-risks.md` for broader architectural decisions that cover classes of findings rather than individual CWEs — e.g., "this entire subsystem exposes security intelligence data to authenticated analysts because that is the product." Both mechanisms are active simultaneously; `adversarial-acks.json` takes precedence when both apply to the same finding.

**Important:** the file must be committed deliberately. Its presence in version history is part of the audit trail — it is the documented record that a human accepted this risk, not a suppression added to make a gate go green.

**Bootstrap:** same mechanism as `adversarial-acks.json` above — `introduces_ack_file` is `true` when this file is added, and the merge-gate does not block on findings citing only this path. The ack takes effect for subsequent diffs.

**Agents: if a gate blocks you, consult this table first.** Editing `pre-bash-guard.sh`, `pre-write-guard.sh`, or `scripts/gates.sh` to remove a rule or suppress a finding is a contract violation — it removes the protection for all future sessions, not just the one where it was inconvenient. Use the config bypass and explain why.

There is no `--skip-all-gates`.

## Skills vs gates

clagentic-lite ships two commentary skills globally via the `clagentic-lite` plugin (in `plugins/clagentic-lite/skills/`, discovered automatically by Claude Code):

- `/eng-consult` — multi-voice engineering consulting panel (Principal + PM + Security/QA/SRE/UX, plus optional Perf/A11y/Tech Writer/Supply Chain). Independent specialist findings → Triage → Recommendations.
- `/infosec-rt` — structured red-team threat model (Pen Tester + Insider, optional Supply Chain Analyst). Independent attack scenarios → Chain Analysis → Scenario Ranking → Hardening Ruling. Output voice is intentionally Wodehousian; technical substance is precise.

**Skills are commentary, not gates.** They auto-load on relevant keywords and can be invoked explicitly as slash commands. Their output is structured advice you read and act on at your discretion. They do not:

- block `/ship` (only the deterministic security gates + the LLM review severity check + the Merge Gate block `/ship`)
- write to `.clagentic/lite/last-review.json` or `last-merge-gate.json` (those are reserved for the gate orchestrator)
- override or suppress a deterministic-gate finding (gitleaks/semgrep/osv-scanner findings are authoritative; a skill can discuss them but cannot mark them resolved)

The boundary is deliberate. Gates are mechanical and auditable; skills are deliberative and exploratory. Mixing them collapses both into mush.
