# AGENTS.md — instructions for AI coding assistants working in this repo

This file is the canonical agent-instruction file for any AI coding assistant operating in this repository: Codex, Claude Code (via the `CLAUDE.md` pointer), Cursor, Aider, Copilot CLI, Gemini CLI, and any other tool that respects the [AGENTS.md convention](https://agents.md/).

The repo is **clagentic-lite** — a small, deliberate solo-dev coding harness with five gates and two AI roles. Read `README.md` for the product narrative and `docs/DESIGN.md` for architecture.

---

## How to behave in this repo

### 1. Stay inside the contract

clagentic-lite is intentionally small. New features must justify themselves against the existing five gates (`docs/GATES.md`) and five roles (`docs/DESIGN.md` § "The five roles"). If a proposed change does not strengthen, simplify, or document one of those, push back before writing code.

The non-goals list in `docs/DESIGN.md` is binding. Do not add: a server, a daemon, a vector database, an embedding model, a web UI, a plugin marketplace, multi-agent orchestration, or multi-repo state. Propose those as separate projects.

#### Memory feature bright-line test

"Lite may DISPLAY any number the user could verify by eye; lite may not let a number it COMPUTED DECIDE what you see. Ordering is permitted only on facts the user authored directly — recency (ts) and intent (source='manual') — never on a score derived from the corpus. If a user could ever reasonably ask 'why did recall return that and not this?' and the only honest answer involves a number the tool computed (a score, weight, decay, or index rank), the feature belongs in LORE, not lite."

Mechanical form: a computed number is lite-legal only if the result set the user sees would be byte-identical with the number deleted. Ranking, gating, weighting, or decay that changes which rows appear — out. Counts, last-seen timestamps, or tags that annotate a set produced by the user's own words or pins — in. (Ratified in hc-2026-06-01-litemem, tome #552.)

### 2. Portability is a hard constraint

All shell code is **POSIX sh**. No bash-4 features (associative arrays, `${var^^}`, `mapfile`, `[[ =~ ]]` capture groups). All `sed`/`date`/`stat`/`find` invocations go through `scripts/platform.sh` shims. See `docs/PORTABILITY.md` for the GNU/BSD differences table.

If you add a new shell tool dependency, add a detection block to `bin/clagentic-lite doctor` (via `ds_check_tool` in `scripts/platform.sh`) and document it in `docs/PORTABILITY.md`.

### 3. Parameterization is non-negotiable

Nothing personal, nothing org-specific, nothing host-specific is hardcoded. Everything user-supplied goes through `.env` (gitignored) with `.env.example` as the committed template. Branch names, model commands, org slugs, repo hosts — all variables.

If you find a hardcoded value, fix it. If you can't fix it without breaking flow, file it as a TODO comment with `# clagentic-lite:hardcoded` so it shows up in grep.

### 4. The security gate is local-tool-owned

`gitleaks`, `semgrep`, and `osv-scanner` are the blocking security gates. **Do not add LLM calls to the blocking path of any security check.** LLM-driven security commentary is fine and welcome, but only as the non-blocking adversarial layer (Gate 3 extension).

This isn't a technical preference. It's the product story. "The harness does not trust AI for security decisions" is the line that makes the cross-vendor LLM review *more* credible, not less.

### 4a. Never edit gate source to bypass a block

**If a gate is blocking you, use the config bypass — do not modify `pre-bash-guard.sh`, `pre-write-guard.sh`, or `scripts/gates.sh` to suppress or remove a rule.** Editing source removes the protection for all future sessions. The supported bypass paths are:

- `CLAGENTIC_ALLOW_BASH_RULES=R-XXX` — skip specific bash-guard rules (comma-separated)
- `CLAGENTIC_ALLOW_DEFAULT_BRANCH_WRITE=1` — skip W-001 write-guard
- `CLAGENTIC_OSV_SEVERITY=HIGH` — raise osv-scanner threshold
- `.clagentic/osv-ignore` — per-CVE/GHSA ignore list for osv-scanner
- `.semgrepignore` or `# nosemgrep:` — semgrep native suppression
- `.gitleaks.toml` path-scoped allowlist — gitleaks false-positive suppression
- `.clagentic/adversarial-acks.json` — per-CWE structured acknowledgment for adversarial/merge-gate false positives (path-glob scoped, committed, audited). This is a workflow convenience for trusted internal contributors, not a security control — `acknowledged_by` is unverified plain text and a contributor can add both a regression and a covering ack in the same diff. Path-glob should be scoped as narrowly as possible; overly broad globs allow future regressions in covered files to be silently acknowledged. Protect this path with CODEOWNERS so edits require reviewer sign-off outside the submitter.
- `.clagentic/accepted-risks.md` — freetext markdown documenting architectural risk decisions where an adversarial finding describes inherent product behavior; the merge-gate reads this file and classifies covered findings as acknowledged rather than refused. Copy `share/accepted-risks.example.md` from the install tree as a template.
- `CLAGENTIC_SKIP_UPDATE_ALERT=1` — suppress the session-start update-available notice (air-gapped or manually managed installs)
- `CLAGENTIC_ALLOW_STALE_PAYLOAD=1` — skip the staleness check on gate output files (`.clagentic/lite/last-review.json`, `.clagentic/lite/last-adversarial.md`); use when artifacts were written in a prior CI step or air-gapped environment where the files are known-fresh despite the SHA mismatch

Set these in `.clagentic/config` (repo-level) or `~/.config/clagentic/config` (global). Document the reason in the commit or PR body. See `docs/GATES.md` § "Working around gates" for the full table.

### 5. Cross-vendor is the point

Builder and Reviewer must default to different vendors. The Reviewer role's whole job is to surface what the Builder couldn't see, and a same-vendor reviewer shares the Builder's blind spots. If the user configures both roles to the same vendor, the install script warns; don't suppress the warning.

### 6. Audit-first

Every gate decision lands in `.clagentic/lite/audit.db`. If you add a gate, add a `gate_runs` insert. If you bypass a gate, log the bypass. The audit trail is the artifact — it is what a code review or InfoSec conversation reads.

### 7. Read before edit

This is a project rule and a habit. Read the file in full before modifying it. Read every file the change touches, including hooks and config. Partial reads followed by edits that assume unseen content are forbidden.

### 8. No emojis, no fluff

Commit messages, PR descriptions, code comments, log lines — no emojis, no exclamation points, no "Successfully!" Be terse, technical, and accurate. Match the existing tone.

---

## Build / test / run

```sh
# First-time setup (run from the clagentic-lite checkout):
bin/clagentic-lite init            # prereq detection, global config, symlink, plugin install

# Per-project enrollment (run from inside the project you want gated):
clagentic-lite enroll              # init DBs, stamp hooks, register

# Ongoing use:
clagentic-lite gates review        # run cross-model review on staged diff
clagentic-lite gates ship          # run all gates in sequence
clagentic-lite gates digest        # summarize today's audit-db rows
clagentic-lite recall <kw>          # search session summaries
sqlite3 .clagentic/lite/audit.db   # inspect the audit trail directly
sqlite3 .clagentic/lite/memory.db  # inspect session memory directly
clagentic-lite doctor              # verify all prereqs and enrolled-repo hook health
clagentic-lite list                # show enrolled repos with last-gate-run and status
clagentic-lite show memory [N]     # pretty-print last N session memory rows (default 10)
clagentic-lite show gates [N]      # pretty-print last N gate run rows (default 10)
clagentic-lite export              # write self-contained HTML report to .clagentic/lite/report.html
```

There is intentionally no CI. The gates run on the user's machine via git hooks (pre-commit, pre-push) and Claude Code lifecycle hooks. Re-running the same gates in a hosted CI surface would contradict the no-server contract — and the gates exist to block bad changes locally, not to gate PRs against the upstream repo.

---

## File map (load-bearing)

| Path | Purpose |
|---|---|
| `AGENTS.md` (this file) | canonical agent instructions, cross-tool |
| `CLAUDE.md` | thin pointer to `AGENTS.md` for Claude Code compatibility |
| `README.md` | product narrative + 5-minute demo |
| `bin/clagentic-lite` | CLI entry point: init, enroll, unenroll, list, doctor, update, recall, remember, show, export, gates |
| `share/config.example` | all configurable parameters, no secrets (written to ~/.config/clagentic/config by init) |
| `share/hook-shims/pre-commit.template` | hook shim template stamped into enrolled repos at enroll time |
| `share/hook-shims/pre-push.template` | hook shim template stamped into enrolled repos at enroll time |
| `share/hook-shims/claude-settings.template` | settings.json template stamped into enrolled repos — hook paths substituted with absolute `$CLAGENTIC_HOME` paths |
| `share/hook-shims/CLAUDE.md.template` | CLAUDE.md template stamped into enrolled repo root — thin enrollment notice, unconditionally true for any teammate |
| `share/hook-shims/builder-contract.template` | builder-contract.md template stamped into `.clagentic/lite/` (gitignored) — full builder rules, agent table, commands, hooks, gate reference; injected at session start |
| `.claude/settings.json` | hook wiring (tool's own repo; enrolled repos get a generated copy in their `.claude/`) |
| `.claude-plugin/marketplace.json` | plugin marketplace manifest — declares the `clagentic-lite` plugin |
| `plugins/clagentic-lite/.claude-plugin/plugin.json` | per-plugin manifest; version bumped by maintainer PRs that change agent or skill files — never by `clagentic-lite update` |
| `plugins/clagentic-lite/agents/{builder,reviewer,auditor,merge-gate,troubleshooter}.md` | role contracts installed globally via `claude plugin install` at `clagentic-lite init` time |
| `plugins/clagentic-lite/skills/infosec-rt/SKILL.md` | infosec red-team commentary skill — installed globally via the plugin |
| `plugins/clagentic-lite/skills/eng-consult/SKILL.md` | engineering consulting panel skill — installed globally via the plugin |
| `.claude/commands/recall.md` | `/recall` slash command — session memory search |
| `.claude/hooks/*.sh` | five lifecycle hooks |
| `.codex/config.toml` | Codex sandbox + role config |
| `.gitleaks.toml` | gitleaks config — extends defaults, narrow path+token allowlist |
| `scripts/platform.sh` | GNU/BSD shims + shared helpers (`ds_load_env`, `ds_sql_escape`, `ds_audit_log`, `ds_json_field`, `ds_check_tool`, `ds_offer_install`, `$DS_TIMEOUT_CMD`) |
| `scripts/memory.sh` | SQLite session memory CRUD |
| `scripts/llm-client.sh` | role-aware LLM wrapper with model_chain fallback |
| `scripts/gates.sh` | gate orchestrator + digest + ship + merge-gate |
| `scripts/smoke.sh` | non-interactive end-to-end (local sanity check) |
| `docs/` | DESIGN, GATES, DEMO-SCRIPT, PORTABILITY |
| `examples/{python,node,go}/` | demo projects with planted issues |
| `media/logo/` | brand assets (lockup, icon) |
| `LICENSE` | FSL-1.1-MIT (free personal/internal; commercial licensing at clagentic.ai) |

---

## Template version-bump protocol

Four generated artifacts are stamped into enrolled repos at enroll time and kept in sync by `clagentic-lite update`:

- `CLAUDE.md` — thin enrollment notice (committed, user-extensible)
- `.clagentic/lite/builder-contract.md` — full builder rules (gitignored, local only)
- `.claude/settings.json` — hook wiring (gitignored)
- `.git/hooks/{pre-commit,pre-push}` — gate shims

**Hard rule: the committed `CLAUDE.md` contains only the thin notice — never builder rules, agent tables, or gate commands.** Those belong in `.clagentic/lite/builder-contract.md` (gitignored, injected at session start) or `CLAUDE.md.wrapper.template` (local-only, non-git directories). The notice's own language is "if not enrolled, follow normal project workflow" — any rules framed as unconditional mandates in the committed file contradict that and mislead non-clagentic contributors. Do not add rule content to `CLAUDE.md.template`.

Each has a version constant in `bin/clagentic-lite`. `clagentic-lite update` compares the installed version against the constant and restamps only when they differ.

**Rule: any change to a template file requires a version bump to its corresponding constant.** Without the bump, `update` sees matching versions and skips the restamp — enrolled repos never receive the change.

| Template file | Version constant | When to bump |
|---|---|---|
| `share/hook-shims/CLAUDE.md.template` | `CLAUDE_NOTICE_VERSION` in `bin/clagentic-lite` | Any content change to the thin notice |
| `share/hook-shims/builder-contract.template` | `CLAUDE_CONTRACT_VERSION` in `bin/clagentic-lite` | Any change to builder rules, agents, commands, hooks, gate reference, or `.clagentic/lite/` path references |
| `share/hook-shims/CLAUDE.md.wrapper.template` | `CLAUDE_WRAPPER_VERSION` in `bin/clagentic-lite` | Any content change to the wrapper template |
| `share/hook-shims/claude-settings.template` | `CLAUDE_SETTINGS_VERSION` in `bin/clagentic-lite` | Any content change to the settings template |
| `share/hook-shims/pre-commit.template` | `SHIM_VERSION` in `bin/clagentic-lite` | Any content change to the hook shim |
| `share/hook-shims/pre-push.template` | `SHIM_VERSION` (same constant) | Any content change to the hook shim |

`CLAUDE_MD_VERSION` is retired — replaced by the three narrower constants above. During the transition period it remains in `bin/clagentic-lite` as a tombstone so old installed files continue to compare correctly. Doctor will warn on any repo still carrying the old `clagentic-claude-md-version` marker; `update` will migrate them to the thin notice with a full replace (no old rule content preserved). If a repo's committed `CLAUDE.md` still contains a "How to work in this repo" rules block after updating, run `clagentic-lite update --restamp` to force a clean restamp.

The version strings are arbitrary (`v1`, `v2`, ...) — increment by one each time. The template file itself should also carry the updated version in its managed-by comment (e.g. `clagentic-notice-version: v2`) so the installed copy is self-describing.

**After bumping:** run `clagentic-lite update` (or `clagentic-lite update --restamp` to force all enrolled repos regardless of version). Users on older installs get the restamp automatically on their next `update` run.

**`.claude/commands/` is different.** Those files are symlinked directly from `$CLAGENTIC_HOME/.claude/commands` into enrolled repos — no stamping, no version tracking. Changes take effect immediately for all enrolled repos. No version bump needed.

## Plugin rename protocol

If a plugin is renamed, `cmd_update`'s installed-check uses an exact-token grep — `grep -qE '(^|[[:space:]])<name>(@|[[:space:]]|$)'` — so the old name will not match the new one. This means the update will fall through to `plugin install`, which is correct for a fresh install but will leave the old plugin installed alongside the new one.

**Rule: any plugin rename requires an explicit migration step in both `cmd_init` and `cmd_update`.** Pattern:

1. Before the installed-check, detect the old name with the same exact-token grep.
2. If found, uninstall it: `claude plugin uninstall "<old-name>@clagentic-lite"` with a fallback to bare `claude plugin uninstall "<old-name>"`.
3. Then proceed with the normal install/update path.

The migration block stays in the code permanently — it is a no-op once the old name is gone, and removing it breaks users who skipped intermediate versions.

**Plugin manifest `skills` field**: Claude Code discovers skills from a plugin's `skills/` subdirectory automatically (same convention as `agents/`). Do not add a `skills` array to `plugin.json` — the field is not in the supported manifest schema and will cause `plugin install` to fail entirely, blocking agent delivery too.

---

## What to ask the user before doing

- Adding any new external tool dependency
- Changing the default `BLOCK_SEVERITY` threshold
- Changing the default Builder, Reviewer, Auditor, Merge Gate, or Summarizer CLI
- Modifying the rule list in `pre-bash-guard.sh` or `pre-write-guard.sh`
- Adding anything to the non-goals list in `docs/DESIGN.md`
- Flipping any fail-closed default to fail-open (the `CLAGENTIC_ALLOW_MISSING_*` opt-ins, `CLAGENTIC_MERGE_GATE_BLOCKING`, the hook fail-closed-without-jq behavior)
- Loosening the gitleaks allowlist beyond the path + fixture-token intersection

Otherwise, fix what's in front of you and ship it.
