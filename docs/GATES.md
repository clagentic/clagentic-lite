# clagentic-lite — Gates reference

Each gate is documented here: what it does, where it fires, what blocks, how to override.

## Gate 1 — Memory inject

| | |
|---|---|
| **Fires** | `UserPromptSubmit` (every prompt) |
| **Tool** | `scripts/memory.sh recall` |
| **Blocks?** | No (read-only context injection) |
| **Output** | Up to 3 prior session summaries prepended to the prompt as additional context |
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

Reviewer prompt and JSON schema are pinned in `.claude/agents/reviewer.md` (Pre-Report Gate + Common False Positives list). Output is persisted at `.clagentic/last-review.json` and into `audit.db.gate_runs`. Per-step LLM-call attempts are logged separately (`gate=llm-call`) with a one-line error hint from stderr.

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
| **Tool** | `osv-scanner scan --recursive --config=<tmpfile> .` (v1.9+) or `osv-scanner --recursive --severity=<S> .` (v1.8 and earlier). Version probed by subcommand availability, not version string. |
| **Blocks?** | Yes, on vulnerabilities at or above the configured severity. Default is `CRITICAL`. |
| **Severity** | Set `CLAGENTIC_OSV_SEVERITY` in `~/.config/clagentic/config` or `.clagentic/config`. Values: `CRITICAL` (default), `HIGH`, `MEDIUM`, `LOW`. Set `LOW` to restore block-on-any-finding behavior. For v1.9+, this becomes `MinimumSeverity` in a generated temp config passed via `--config`. |
| **Ignore list** | Add CVE/GHSA IDs one-per-line to `~/.config/clagentic/osv-ignore` (global) or `.clagentic/osv-ignore` (repo). Lines starting with `#` and blank lines are ignored. For v1.9+, these become `[[IgnoredVulns]]` blocks in the generated temp config; for v1.8 and earlier, they are passed as `--ignore-vulns=<id>`. |
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
| **Output** | Markdown attack scenarios saved to `.clagentic/last-adversarial.md`; attach to PR if interesting |

The Auditor argues, in concrete terms, how a hostile user could exploit each new or modified input surface. Cites file:line. Names threats with CWE if obvious. If nothing is exploitable, says so in one sentence and lists the surfaces considered.

For a heavier, structured threat-model pass, use the `/infosec-rt` skill instead — multi-persona chained attack scenarios with hardening priority list.

## Gate 6 — Merge Gate

| | |
|---|---|
| **Fires** | `scripts/gates.sh ship` (the `/ship` slash command), after all other gates have passed |
| **Tool** | LLM "gate" role via `scripts/llm-client.sh merge-gate` |
| **Input** | A JSON gate-summary payload (`.clagentic/gate-summary.json`) built from `last-review.json` + `last-adversarial.md` + threshold |
| **Output** | `{decision: "approve" | "refuse", reason: "<one sentence>"}` JSON at `.clagentic/last-merge-gate.json` |
| **Blocks?** | **Yes by default** (`CLAGENTIC_MERGE_GATE_BLOCKING=1`). Set to `0` to make advisory. |
| **Unparseable decision** | Also blocks — schema-invalid merge-gate output is treated as a gate failure, not a pass. |

The Merge Gate is the last LLM check before the PR is opened. It never overrides the deterministic security gates (those already gated upstream) and never adds its own findings — it reads the structured outputs of every prior gate and returns a single approve/refuse decision.

## Gate 7 — Session summarize

| | |
|---|---|
| **Fires** | `Stop` (async, debounced) |
| **Tool** | `scripts/memory.sh summarize-turn` |
| **Blocks?** | No |
| **Debounce** | `CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC=20` |

Reads the last assistant turn from the Claude Code transcript path, passes it through the Summarizer (`CLAGENTIC_SUMMARIZER_CMD` at cheap tier), inserts one row into `.clagentic/memory.db.turns` with `source='stop-hook'`. Best-effort: if the summarizer fails, the session continues uninterrupted and the row is skipped. `python3` is required for transcript JSONL parsing — without it, the hook logs `summarize skip` to audit.db and exits cleanly.

## Auditing what happened

```sh
# every gate run today
sqlite3 .clagentic/audit.db \
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
| Any gate | Tool not installed | Set `CLAGENTIC_ALLOW_MISSING_<TOOL>=1`. Prefer installing the tool. |

**Agents: if a gate blocks you, consult this table first.** Editing `pre-bash-guard.sh`, `pre-write-guard.sh`, or `scripts/gates.sh` to remove a rule or suppress a finding is a contract violation — it removes the protection for all future sessions, not just the one where it was inconvenient. Use the config bypass and explain why.

There is no `--skip-all-gates`.

## Skills vs gates

clagentic-lite ships two commentary skills under `.claude/skills/`:

- `/eng-consult` — multi-voice engineering consulting panel (Principal + PM + Security/QA/SRE/UX, plus optional Perf/A11y/Tech Writer/Supply Chain). Independent specialist findings → Triage → Recommendations.
- `/infosec-rt` — structured red-team threat model (Pen Tester + Insider, optional Supply Chain Analyst). Independent attack scenarios → Chain Analysis → Scenario Ranking → Hardening Ruling. Output voice is intentionally Wodehousian; technical substance is precise.

**Skills are commentary, not gates.** They auto-load on relevant keywords and can be invoked explicitly as slash commands. Their output is structured advice you read and act on at your discretion. They do not:

- block `/ship` (only the deterministic security gates + the LLM review severity check + the Merge Gate block `/ship`)
- write to `.clagentic/last-review.json` or `last-merge-gate.json` (those are reserved for the gate orchestrator)
- override or suppress a deterministic-gate finding (gitleaks/semgrep/osv-scanner findings are authoritative; a skill can discuss them but cannot mark them resolved)

The boundary is deliberate. Gates are mechanical and auditable; skills are deliberative and exploratory. Mixing them collapses both into mush.
