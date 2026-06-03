<p align="center">
  <img src="media/logo/lite-lockup-256.png" alt="Clagentic:Lite" width="260" />
</p>

<h4 align="center">Cross-vendor AI coding harness with deterministic security gates. Gated Builder+Reviewer roles, full SQLite audit trail. No server, no cloud.</h4>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-FSL--1.1--MIT-blue.svg" alt="License: FSL-1.1-MIT" /></a>
  <img src="https://img.shields.io/badge/shell-POSIX-blue.svg" alt="POSIX shell" />
  <img src="https://img.shields.io/badge/OS-WSL2%20%7C%20macOS-lightgrey.svg" alt="WSL2 | macOS" />
  <a href="https://ko-fi.com/clagentic"><img src="https://img.shields.io/badge/Support-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white" alt="Support on Ko-fi" /></a>
</p>

---

# Clagentic:Lite

Five roles (Builder, Reviewer, Auditor, Merge Gate, Troubleshooter) with per-role model chains. Five gates (memory recall, safe bash/writes, cross-vendor review, local security scans, session summarize) that fire on Claude Code or Codex events. One SQLite file for session memory, one for the audit trail. POSIX shell. No server. Nothing global. Runs the same on WSL2 Ubuntu and macOS.

It is not a platform. It is what you install on your machine so the coding session you have there is visibly more careful than the default.

---

## Two steps: install once, enroll per project

clagentic-lite has two distinct steps.

**`clagentic-lite init`** — runs once per machine. Installs the tool, wires the symlink, detects prereqs, and writes global config. After this, `clagentic-lite` is on your PATH.

**`clagentic-lite enroll`** — runs once per project (inside each git repo you want gated). This is the activation step. Without it, nothing gates your code: no hooks fire, no session memory writes, Claude Code sees no agents or slash commands, and no audit trail exists for that repo.

If you only run `init` and skip `enroll`, the tool is installed but inert.

---

## What you get

All capabilities below are per-project and activate only in enrolled repos (`clagentic-lite enroll`).

| Capability | How it works |
|---|---|
| **Per-role model chain** | Each role declares an ordered list of `(cli, tier)` pairs. Primary fails → next entry → next → degraded envelope. Every attempt logged. |
| **Cross-CLI review** | Builder writes; Reviewer (configured to a different CLI by default) reads the staged diff and returns JSON findings. |
| **Local-tool security gates** | gitleaks pre-commit, osv-scanner + semgrep pre-push. Deterministic. Blocking. No LLM in the security path. |
| **LLM adversarial pass** | Auditor role plays attacker on the diff. Non-blocking. Logged. Attach to PR if interesting. |
| **Merge gate** | Final LLM check reads every prior gate's structured output and returns `approve|refuse`. Never opens PRs, never pushes. |
| **Troubleshooter** | Read-only failure diagnosis agent. Receives one artifact (gate error, hook trace, wrong output), applies structured Tier 0→2 diagnosis, emits root cause and bounce target. Never writes, never dispatches. |
| **Session memory** | Stop-hook pipes the last assistant turn through the Summarizer, writes one row to `.clagentic/memory.db`. UserPromptSubmit hook recalls relevant rows into the next prompt's context. |
| **Safe-by-default tool use** | PreToolUse hooks (`pre-bash-guard.sh`, `pre-write-guard.sh`) block 20 dangerous patterns and writes to the default branch / outside repo / to credential-shaped paths. |
| **Audit trail** | Every gate decision, every LLM call attempt, every block — one row in `.clagentic/audit.db`. `scripts/gates.sh digest` is the readout. |
| **Commentary skills** | `/eng-consult` (multi-voice consulting panel: Principal + PM + Security/QA/SRE/UX) and `/infosec-rt` (structured red-team threat model with chained attack scenarios). User-invocable any time; Claude Code may also auto-select on relevant prompts. Commentary only — neither blocks `/ship`. |

---

## Why per-role model chains

A reviewer that shares the builder's training distribution shares its blind spots. So the Reviewer role defaults to a different CLI than the Builder. But "different CLI" should not be hard-coded: each role declares an ordered chain, drawn from whatever CLIs you actually have on this laptop. If your primary fails (rate limit, auth expired, model deprecated), the wrapper walks the chain and logs which entry succeeded.

Concrete example from `share/config.example`:

```sh
CLAGENTIC_BUILDER_CMD=claude
CLAGENTIC_BUILDER_TIER=default
CLAGENTIC_BUILDER_CHAIN=codex:default,claude:flagship

CLAGENTIC_REVIEWER_CMD=codex
CLAGENTIC_REVIEWER_TIER=default
CLAGENTIC_REVIEWER_CHAIN=claude:default,codex:flagship
```

Tier names (`flagship`, `default`, `cheap`) resolve to concrete model strings via the `CLAGENTIC_MODEL_<CLI>_<TIER>` table in `.env`. That table is the only place model version literals live. Agent files and scripts reference tier names only — when a model deprecates, you edit one row in `.env` and everything else still works.

---

## Install

Clone once, enroll per project. The snippet below is safe to re-run — on a fresh machine it clones, on a machine that already has clagentic-lite it pulls and re-runs `init` (which is also what `clagentic-lite update` does):

```sh
# First install OR re-run after pulling new commits.
HOME_DIR="${CLAGENTIC_HOME:-$HOME/.clagentic-lite}"
if [ -d "$HOME_DIR/.git" ]; then
  git -C "$HOME_DIR" pull --ff-only
else
  git clone https://github.com/clagentic/clagentic-lite.git "$HOME_DIR"
fi
"$HOME_DIR/bin/clagentic-lite" init

# Step 2 — per-project activation (REQUIRED for each repo you want gated):
# Without this, no hooks fire and Claude Code sees no agents.
cd /path/to/your/project && clagentic-lite enroll
```

If you stop after `init` without running `enroll` in at least one project, the harness is installed but dormant — no gates are active anywhere.

After the first install, the steady-state upgrade is just `clagentic-lite update` — it does the `git pull --ff-only`, re-checks prereqs, and re-stamps hook shims, `.claude/settings.json`, and `CLAUDE.md` in every enrolled repo when their template versions change.

If `init` warns that `~/.local/bin` is not on `$PATH`, add this to your shell rc and reopen your shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

There is no package manager. Distribution is the git repo itself at <https://github.com/clagentic/clagentic-lite>. Updates are `clagentic-lite update` — pulls `--ff-only`, re-checks prereqs, re-stamps all versioned artifacts in enrolled repos when their template versions change.

The tool is cloned once to `~/.clagentic-lite` (or `$CLAGENTIC_HOME` if set). Your projects never contain a copy of the scripts or agent files — they hold only `.clagentic/{audit.db,memory.db}`, thin hook shims, and a `CLAUDE.md` that call back to `$CLAGENTIC_HOME`. Update the tool once and every enrolled repo picks it up.

### Prerequisites

clagentic-lite is small in *code* (~1,500 lines of POSIX shell + agent/skill markdown) but it leans on real tools to do real work. The security gates are deterministic local scanners — gitleaks, semgrep, osv-scanner — not LLM judgment. If you don't have them, you don't have the gates. The harness ships with explicit opt-ins to skip each one (see "Minimal install" below) so you can run a stripped-down version while you decide which gates you want.

`clagentic-lite init` detects missing tools and offers to run the install command for you. If you decline, it prints the exact command and exits non-zero.

Required:

| Tool         | Purpose                                | Linux/WSL                   | macOS                       |
|--------------|----------------------------------------|-----------------------------|-----------------------------|
| `sqlite3`    | session memory + audit DB              | `apt install sqlite3`       | `brew install sqlite`       |
| `git`        | hooks, diffs                           | `apt install git`           | `xcode-select --install`    |
| `jq` or `python3` | hook JSON parsing — hooks fail closed without either | `apt install jq` | `brew install jq` (python3 ships with macOS) |
| **one LLM CLI** | for Builder + Reviewer roles. `claude` or `codex`; both is the cross-CLI pattern. | see vendor docs | see vendor docs |

Required for the security gates (you can install these later and opt-in per gate):

| Tool                | Gate     | Linux/WSL                   | macOS                       | Skip with                              |
|---------------------|----------|-----------------------------|-----------------------------|----------------------------------------|
| `gitleaks` ≥ 8.18   | secrets  | see [releases][gl]          | `brew install gitleaks`     | `CLAGENTIC_ALLOW_MISSING_GITLEAKS=1`   |
| `semgrep`           | sast     | `pipx install semgrep`      | `brew install semgrep`      | `CLAGENTIC_ALLOW_MISSING_SEMGREP=1`    |
| `osv-scanner`       | deps     | [osv-scanner releases][osv] | `brew install osv-scanner`  | `CLAGENTIC_ALLOW_MISSING_OSV=1`        |

Nice-to-have:

| Tool      | Why                                                     |
|-----------|---------------------------------------------------------|
| `gh`      | `/ship` opens the PR for you; falls back to a URL template |
| `timeout` / `gtimeout` | per-call LLM timeout; auto-detected. macOS users: `brew install coreutils` for `gtimeout` |

### Minimal install (just the harness, no security gates)

Want to try the role/review/memory layer without installing gitleaks/semgrep/osv-scanner? Set the three `ALLOW_MISSING` opt-ins to `1` in `~/.config/clagentic/config` after `clagentic-lite init`:

```sh
CLAGENTIC_ALLOW_MISSING_GITLEAKS=1
CLAGENTIC_ALLOW_MISSING_SEMGREP=1
CLAGENTIC_ALLOW_MISSING_OSV=1
```

That gives you the cross-CLI review, the dumb-thing-blocking hooks, session memory, and the audit trail — but no deterministic secret/dep/sast scanning. Add the tools when you want the gates. The audit DB will record `skip` rows so you have a paper trail of which gates ran and which didn't.

### What `clagentic-lite init` and `clagentic-lite enroll` do

**`clagentic-lite init`** (run once, in $CLAGENTIC_HOME or anywhere after the symlink is on PATH):

1. Verifies `$CLAGENTIC_HOME` is a valid clagentic-lite checkout.
2. Detects WSL vs macOS, picks portable tool variants (`scripts/platform.sh`).
3. For each REQUIRED missing tool: prints `MISSING: X — install with: <cmd>` and prompts `Run it now? [y/N]:`. On y, runs the install command. On N, exits non-zero with the manual command.
4. Two-question front door: accept all defaults (Y/n) + vendor mode ([1] Claude only / [2] Claude+Codex). On Y+mode-2: writes global config and done. On n: up to 6 granular prompts.
5. Writes `~/.config/clagentic/config` (chmod 600).
6. Ensures `~/.local/bin/` exists; warns with the exact shell-profile line if not on `$PATH`.
7. Symlinks `~/.local/bin/clagentic-lite` to `$CLAGENTIC_HOME/bin/clagentic-lite`.

**`clagentic-lite enroll [PATH]`** (run inside each project you want gates on, default `$PWD`):

1. Verifies the path is a git repo.
2. Refuses if the path is `$CLAGENTIC_HOME` (use `--self` for dogfood).
3. Refuses if already enrolled (use `--force` to re-enroll).
4. Initializes `.clagentic/audit.db` and `.clagentic/memory.db` in that repo.
5. Stamps `.git/hooks/pre-commit` and `.git/hooks/pre-push` from `share/hook-shims/*.template`, substituting `$CLAGENTIC_HOME` at stamp time. Refuses to overwrite non-clagentic hooks unless `--force`.
6. Generates `.claude/settings.json` (absolute hook paths → `$CLAGENTIC_HOME`), symlinks `.claude/commands`, and adds `.claude/` to `.gitignore`. These are local-only artifacts. Role agents are installed globally via the `clagentic-lite-agents` plugin at `init` time — no per-repo copies.
7. Stamps `CLAUDE.md` at the repo root — activates the Builder contract and exposes agents for Claude Code auto-dispatch. Refuses to overwrite a non-clagentic `CLAUDE.md` unless `--force`.
8. Registers the repo path in `~/.local/state/clagentic/registry`.

### Solo vs. shared repos

**Solo / private repo**: `CLAUDE.md` is generated and ready to use. If you'd rather not commit it, add it to `.gitignore` yourself — clagentic won't do that automatically because the file is safe to commit.

**Shared repo**: `CLAUDE.md` is committable as-is and is the only clagentic artifact that is meant to be shared. It contains no machine-specific paths. Teammates without clagentic-lite installed will see a normal project CLAUDE.md. Teammates with clagentic-lite installed will get full agent auto-dispatch.

`.claude/` (hook wiring, command symlinks, `settings.json`) is **local-only** — it is added to `.gitignore` automatically at enroll time and is never committed. Each teammate who wants clagentic-lite active must run `clagentic-lite enroll` in the repo on their own machine. This is by design: hook paths are absolute and machine-specific; sharing them would break the harness on every machine but the original.

If you extend `CLAUDE.md` with project-specific rules, `clagentic-lite enroll --force` will refuse to overwrite until you remove the `managed-by: clagentic` marker.

### Verify the install

Two layers — the shell harness, then Claude Code's view of it.

**Shell harness:**

```sh
# Run from inside $CLAGENTIC_HOME (default: ~/.clagentic-lite):
"$CLAGENTIC_HOME/scripts/smoke.sh" --quick   # non-interactive end-to-end without LLM calls

# Run from inside an enrolled project repo:
"$CLAGENTIC_HOME/scripts/gates.sh" digest    # show what gates ran today
"$CLAGENTIC_HOME/scripts/gates.sh" status    # last 10 runs per gate, color-coded
"$CLAGENTIC_HOME/scripts/gates.sh" tail      # follow audit.db live (Ctrl-C to quit)

# Run from anywhere:
clagentic-lite doctor      # diagnostics: symlink, prereqs, every enrolled repo's hook status
```

Note: `scripts/` lives in `$CLAGENTIC_HOME`, not in your enrolled project. Always use the absolute path form (`"$CLAGENTIC_HOME/scripts/gates.sh"`) when running gate scripts directly from inside a project. The `clagentic-lite` CLI and `/ship`, `/review` slash commands use the correct path automatically.

Smoke covers: DB init, seed + recall, gitleaks blocks a planted token, `llm-client.sh review` emits parseable JSON, audit-DB has fresh rows. If smoke passes, the harness is wired correctly.

**Claude Code sees the agents, commands, and skills:**

Open the repo in Claude Code and type each of these. If any are "command not found," Claude Code didn't pick up the file — usually a permissions issue (`chmod +x .claude/hooks/*.sh scripts/*.sh`) or a stale Claude Code session (restart it).

```text
/recall            → prints recent session summaries (empty on fresh install)
/review            → prints the review-gate doc (no diff staged yet, so it'll say so)
/ship              → prints the ship gate sequence (won't actually push on main)
/infosec-rt        → convenes the red-team threat model
/eng-consult       → convenes the multi-voice engineering consulting panel
```

If `/infosec-rt` or `/eng-consult` aren't recognized, Claude Code's project-skills discovery isn't finding `.claude/skills/`. Confirm the directory exists and that `SKILL.md` inside each has proper frontmatter (`name:`, `description:`, `user_invocable: true`).

[gl]: https://github.com/gitleaks/gitleaks/releases
[osv]: https://google.github.io/osv-scanner/installation/

---

## Setting up Codex (the default Reviewer)

clagentic-lite defaults to **Claude as Builder, Codex as Reviewer** — that's the point of the cross-CLI pattern. Codex is the OpenAI CLI (`@openai/codex`) backed by a ChatGPT Plus/Pro subscription. No API key needed.

```sh
# 1. Install Codex
npm install -g @openai/codex
# or on macOS: brew install codex

# 2. Authenticate once (device auth — opens browser, no API key)
codex login --device-auth

# 3. Verify
echo 'ok' | codex exec --skip-git-repo-check 'repeat back what you read on stdin'
```

### Model configuration

The recommended approach is `~/.codex/models.json` — a runtime tier map that clagentic-lite reads automatically. Update it when OpenAI renames models; no `clagentic-lite init` re-run needed.

```json
{
  "tiers": {
    "flagship": { "model": "<your-flagship-model>", "default_effort": "medium", "escalated_effort": "high" },
    "mini":     { "model": "<your-mini-model>",     "default_effort": "medium" },
    "spark":    { "model": "<your-spark-model>",    "default_effort": "low" }
  },
  "default_tier": "flagship",
  "fallback_policy": "surface_error_no_silent_retry"
}
```

Fill in the model IDs that are available on your account. clagentic-lite reads this file at runtime — update it when OpenAI releases new models or renames existing ones, with no `clagentic-lite init` re-run required. Model strings in `~/.config/clagentic/config` (`CLAGENTIC_MODEL_CODEX_*`) are intentionally left blank by default so this file is the sole source of truth.

Tier names map to clagentic-lite's chain vocabulary: `flagship`, `mini`, `spark`. The `default` tier alias resolves to `default_tier` in the file. Explicit env vars always win over models.json if both are set.

**Model availability matters.** The `-codex` suffixed names (`gpt-5-codex`, `gpt-5.5-codex`) are API-key-only and return a 400 error on ChatGPT-account logins. When a step fails, the reason appears in the audit row — run `"$CLAGENTIC_HOME/scripts/gates.sh" digest` to see it.

The wrapper invokes Codex as:

```sh
codex exec --skip-git-repo-check -m "$MODEL" --color never -o "$OUTPUT_FILE" "$PROMPT"
```

If Codex returns non-zero or its output fails to parse as the expected JSON (Reviewer / Merge Gate roles), the wrapper falls through to the next entry in the role's chain. The fallback is whatever you put in `CLAGENTIC_REVIEWER_CHAIN` — typically Claude with a comparable tier.

### Why not the official Claude Code Codex plugin

The marketplace plugin (`/codex:rescue`, etc.) gives you hardcoded slash commands with no tier selection, no session continuity, and opaque error handling. The `codex exec` path used here is pure shell, explicit tier, verbatim output, and composable with every other role in the harness.

### Setting up Claude

If you only use Claude Code, set every role's `CMD` to `claude` and put nothing in the chains. The wrapper invokes:

```sh
cat "$INPUT" | claude --print --model "$MODEL" --append-system-prompt "$PROMPT"
```

A same-CLI configuration is allowed — `clagentic-lite init` warns that you've lost the cross-CLI signal but does not refuse.

### Adding a third CLI

Any CLI that accepts a prompt and emits text works. Add a row to the model table:

```sh
CLAGENTIC_MODEL_OLLAMA_DEFAULT=llama3.1:8b
```

…then reference it in a chain (`CLAGENTIC_REVIEWER_CHAIN=claude:default,ollama:default`). The wrapper's generic invocation path is `<cli> -p -` with prompt+input on stdin; CLIs that need a different invocation surface need their own `invoke_<cli>` function in `scripts/llm-client.sh` (see `invoke_claude` and `invoke_codex` for the pattern).

---

## Layout

The tool lives in `$CLAGENTIC_HOME` (default `~/.clagentic-lite`). Your enrolled projects hold only the per-repo state — no copy of scripts, agents, or config.

```
~/.clagentic-lite/                              the tool — never gated by default
├── bin/clagentic-lite                          CLI entry point
├── AGENTS.md                                   canonical agent instructions, cross-tool
├── CLAUDE.md                                   pointer to AGENTS.md
├── README.md                                   this file
├── share/
│   ├── config.example                          global config template (written to ~/.config/clagentic/config)
│   └── hook-shims/
│       ├── pre-commit.template                 stamped into enrolled repos at enroll time
│       └── pre-push.template
├── docs/
│   ├── DESIGN.md                               architecture and non-goals
│   ├── GATES.md                                what each gate does, what it blocks
│   ├── DEMO-SCRIPT.md                          5-minute walkthrough
│   └── PORTABILITY.md                          GNU vs BSD tool table
├── .claude/
│   ├── settings.json                           hook wiring
│   ├── agents/{builder,reviewer,auditor,merge-gate}.md
│   ├── commands/{review,ship,recall}.md
│   └── hooks/{session-start,prompt-inject,stop-summarize,pre-bash-guard,pre-write-guard}.sh
├── .codex/
│   ├── config.toml                             Codex sandbox + role config
│   └── AGENTS.md → ../AGENTS.md               symlink so Codex reads the same rules
├── scripts/
│   ├── platform.sh                             GNU/BSD shims + ds_check_tool/ds_offer_install
│   ├── memory.sh                               SQLite session memory CRUD
│   ├── llm-client.sh                           role-aware LLM wrapper with model_chain fallback
│   ├── gates.sh                                gate orchestrator + digest + ship
│   └── smoke.sh                                non-interactive end-to-end
└── examples/{python,node,go}/                  demo projects with planted bugs + secrets

~/.config/clagentic/config                      global config (chmod 600; written by init)
~/.local/state/clagentic/registry               enrolled repos — one absolute path per line
~/.local/bin/clagentic-lite                     symlink to $CLAGENTIC_HOME/bin/clagentic-lite

<any enrolled repo>/
├── .clagentic/
│   ├── audit.db                                gate run log (written by gates.sh)
│   └── memory.db                               session memory (written by memory.sh)
└── .git/hooks/
    ├── pre-commit                              shim: calls $CLAGENTIC_HOME/scripts/gates.sh secrets
    └── pre-push                                shim: calls $CLAGENTIC_HOME/scripts/gates.sh pre-push
```

---

## Roles

| Role | Default CLI | Job | State-changing tools |
|---|---|---|---|
| **Builder** | claude | Write code on a feature branch. Never merges. | Read, Write, Edit, Bash (allowlisted) |
| **Reviewer** | codex | Read staged diff, return JSON findings. | Read, Bash (read-only) |
| **Auditor** | codex | LLM narration on top of deterministic security scans. Adversarial mode plays attacker. | Read, Bash (security tools) |
| **Merge Gate** | claude | Final approve/refuse decision over every prior gate's output. Never opens PRs. | Read |

Each role is a markdown file under `.claude/agents/` with the role contract in the body. Model selection for non-interactive invocations (via `llm-client.sh`) is controlled by `CLAGENTIC_<ROLE>_CMD` and `CLAGENTIC_<ROLE>_TIER` in config. The Reviewer file is the longest — it carries the Pre-Report Gate and the Common False Positives list, both load-bearing for output quality.

---

## Gates

| # | Gate | Trigger | Blocking? |
|---|------|---------|----------|
| 1 | Memory recall | UserPromptSubmit | no |
| 2 | Safe Bash + writes | PreToolUse (Bash, Write, Edit) | yes |
| 3 | Cross-CLI review | `/review` or pre-push (opt-in) | yes if findings ≥ `CLAGENTIC_BLOCK_SEVERITY` |
| 4 | Local security scan | pre-commit (gitleaks), pre-push (osv-scanner, semgrep) | yes |
| 5 | Session summarize | Stop | no (best-effort) |
| 6 | Adversarial pass | `/review --adversarial` | no |
| 7 | Merge Gate | `/ship` | yes by default, set `CLAGENTIC_MERGE_GATE_BLOCKING=0` to make advisory |

Details in `docs/GATES.md`.

---

## Daily commands

```sh
/review                  # cross-CLI review of staged diff (single Reviewer pass)
/review --adversarial    # plus an attacker-perspective markdown pass
/ship                    # run all gates; if green, push and open PR
/recall <keywords>       # grep session memory

/eng-consult             # multi-voice consulting panel (Principal + PM + specialists)
/infosec-rt              # structured red-team threat model

scripts/gates.sh digest  # what gates ran today
scripts/gates.sh status  # last N runs per gate (default 10), color-coded outcomes
scripts/gates.sh tail    # follow audit.db live; new gate rows render as they land
scripts/memory.sh recall <keyword>   # raw recall
sqlite3 .clagentic/audit.db          # inspect the audit trail
sqlite3 .clagentic/memory.db         # inspect session memory
clagentic-lite show memory [N]       # pretty-print last N session memory rows (default 10)
clagentic-lite show gates [N]        # pretty-print last N gate run rows (default 10)
clagentic-lite export                # write self-contained HTML report to .clagentic/report.html
clagentic-lite export --output PATH  # write report to a specific path
```

`/eng-consult` and `/infosec-rt` are **skills**, not gates — they return structured commentary you read and act on at your own discretion. Both are user-invocable as slash commands at any time. Claude Code may *also* auto-select them on relevant prompts (`/infosec-rt` is scoped to threat-modeling vocabulary; `/eng-consult` is scoped to multi-discipline review vocabulary), but skill auto-selection is heuristic-not-deterministic — when you want the panel, invoke it explicitly. See `.claude/skills/{infosec-rt,eng-consult}/SKILL.md` for the full protocol.

---

## When you've outgrown lite

Signals: you want a server; you want multi-repo memory; you want ranked or embedding-based retrieval; you want multi-agent orchestration; you want memory that learns, decays, and promotes itself automatically.

If you're hitting these limits, the tool did its job — you've grown into needing a heavier harness that provides those capabilities explicitly.

No `eject` subcommand, no schema bridge. `.clagentic/memory.db` is plain SQLite — query it directly with `sqlite3`, or run `clagentic-lite export` to generate a self-contained HTML report. No migration tooling or schema bridge is planned. See `docs/DESIGN.md` § "When you've outgrown lite" for the full rationale.

---

## License

**FSL-1.1-MIT** — [Functional Source License 1.1, MIT Future License](https://fsl.software/).

- **Free** for personal use, internal-business use, evaluation, education, research, and contributing back.
- **Not free** for offering clagentic-lite (or a substantial fork) as a competing commercial product or service.
- Each release **auto-converts to MIT** on its second anniversary — fully open source, no restrictions, on a rolling 2-year window.

Commercial licensing inquiries: [clagentic.ai](https://clagentic.ai). See `LICENSE` for the full text and the plain-English summary.
