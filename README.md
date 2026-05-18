<p align="center">
  <img src="media/logo/lite-lockup-256.png" alt="Clagentic:Lite" width="260" />
</p>

<h4 align="center">A personal coding harness with serious gates. POSIX shell, two SQLite files, no server.</h4>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-FSL--1.1--MIT-blue.svg" alt="License: FSL-1.1-MIT" /></a>
  <img src="https://img.shields.io/badge/shell-POSIX-blue.svg" alt="POSIX shell" />
  <img src="https://img.shields.io/badge/OS-WSL2%20%7C%20macOS-lightgrey.svg" alt="WSL2 | macOS" />
  <a href="https://ko-fi.com/clagentic"><img src="https://img.shields.io/badge/Support-Ko--fi-FF5E5B?logo=ko-fi&logoColor=white" alt="Support on Ko-fi" /></a>
</p>

---

# Clagentic:Lite

Four roles (Builder, Reviewer, Auditor, Merge Gate) with per-role model chains. Five gates (memory recall, safe bash/writes, cross-vendor review, local security scans, session summarize) that fire on Claude Code or Codex events. One SQLite file for session memory, one for the audit trail. POSIX shell. No server. Nothing global. Runs the same on WSL2 Ubuntu and macOS.

It is not a platform. It is what you install on your machine so the coding session you have there is visibly more careful than the default.

---

## What you get

| Capability | How it works |
|---|---|
| **Per-role model chain** | Each role declares an ordered list of `(cli, tier)` pairs. Primary fails → next entry → next → degraded envelope. Every attempt logged. |
| **Cross-CLI review** | Builder writes; Reviewer (configured to a different CLI by default) reads the staged diff and returns JSON findings. |
| **Local-tool security gates** | gitleaks pre-commit, osv-scanner + semgrep pre-push. Deterministic. Blocking. No LLM in the security path. |
| **LLM adversarial pass** | Auditor role plays attacker on the diff. Non-blocking. Logged. Attach to PR if interesting. |
| **Merge gate** | Final LLM check reads every prior gate's structured output and returns `approve|refuse`. Never opens PRs, never pushes. |
| **Session memory** | Stop-hook pipes the last assistant turn through the Summarizer, writes one row to `.clagentic/memory.db`. UserPromptSubmit hook recalls relevant rows into the next prompt's context. |
| **Safe-by-default tool use** | PreToolUse hooks (`pre-bash-guard.sh`, `pre-write-guard.sh`) block 20 dangerous patterns and writes to the default branch / outside repo / to credential-shaped paths. |
| **Audit trail** | Every gate decision, every LLM call attempt, every block — one row in `.clagentic/audit.db`. `scripts/gates.sh digest` is the readout. |
| **Commentary skills** | `/eng-consult` (multi-voice consulting panel: Principal + PM + Security/QA/SRE/UX) and `/infosec-rt` (structured red-team threat model with chained attack scenarios). User-invocable any time; Claude Code may also auto-select on relevant prompts. Commentary only — neither blocks `/ship`. |

---

## Why per-role model chains

A reviewer that shares the builder's training distribution shares its blind spots. So the Reviewer role defaults to a different CLI than the Builder. But "different CLI" should not be hard-coded: each role declares an ordered chain, drawn from whatever CLIs you actually have on this laptop. If your primary fails (rate limit, auth expired, model deprecated), the wrapper walks the chain and logs which entry succeeded.

Concrete example from `.env.example`:

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

Three lines from a clean checkout:

```sh
git clone https://github.com/clagentic/clagentic-lite.git
cd clagentic-lite
./install.sh
```

There is no package manager. Distribution is the git repo itself at <https://github.com/clagentic/clagentic-lite>. Updates are `git pull && ./install.sh` — re-running is idempotent.

### Prerequisites

clagentic-lite is small in *code* (~1,500 lines of POSIX shell + agent/skill markdown) but it leans on real tools to do real work. The security gates are deterministic local scanners — gitleaks, semgrep, osv-scanner — not LLM judgment. If you don't have them, you don't have the gates. The harness ships with explicit opt-ins to skip each one (see "Minimal install" below) so you can run a stripped-down version while you decide which gates you want.

Required on PATH before `./install.sh`:

| Tool         | Purpose                                | Linux/WSL                   | macOS                       |
|--------------|----------------------------------------|-----------------------------|-----------------------------|
| `sqlite3`    | session memory + audit DB              | `apt install sqlite3`       | `brew install sqlite`       |
| `git`        | hooks, diffs                           | `apt install git`           | `xcode-select --install`    |
| `jq` or `python3` | hook JSON parsing — hooks fail closed without either | `apt install jq` | `brew install jq` (python3 ships with macOS) |
| **one LLM CLI** | for Builder + Reviewer roles. `claude` or `codex`; both is the cross-CLI pattern. | see vendor docs | see vendor docs |

Required for the security gates (you can install these later and opt-in per gate):

| Tool                | Gate     | Linux/WSL                   | macOS                       | Skip with                              |
|---------------------|----------|-----------------------------|-----------------------------|----------------------------------------|
| `gitleaks` ≥ 8.25   | secrets  | [gitleaks releases][gl]     | `brew install gitleaks`     | `CLAGENTIC_ALLOW_MISSING_GITLEAKS=1`   |
| `semgrep`           | sast     | `pipx install semgrep`      | `brew install semgrep`      | `CLAGENTIC_ALLOW_MISSING_SEMGREP=1`    |
| `osv-scanner`       | deps     | [osv-scanner releases][osv] | `brew install osv-scanner`  | `CLAGENTIC_ALLOW_MISSING_OSV=1`        |

Nice-to-have:

| Tool      | Why                                                     |
|-----------|---------------------------------------------------------|
| `gh`      | `/ship` opens the PR for you; falls back to a URL template |
| `timeout` / `gtimeout` | per-call LLM timeout; auto-detected. macOS users: `brew install coreutils` for `gtimeout` |

### Minimal install (just the harness, no security gates)

Want to try the role/review/memory layer without installing gitleaks/semgrep/osv-scanner? Set the three `ALLOW_MISSING` opt-ins to `1` in `.env` after `./install.sh`:

```sh
CLAGENTIC_ALLOW_MISSING_GITLEAKS=1
CLAGENTIC_ALLOW_MISSING_SEMGREP=1
CLAGENTIC_ALLOW_MISSING_OSV=1
```

That gives you the cross-CLI review, the dumb-thing-blocking hooks, session memory, and the audit trail — but no deterministic secret/dep/sast scanning. Add the tools when you want the gates. The audit DB will record `skip` rows so you have a paper trail of which gates ran and which didn't.

### What `./install.sh` does

1. Detects WSL vs macOS, picks portable tool variants (`scripts/platform.sh`).
2. If `.env` is missing, prompts interactively for each `CLAGENTIC_*` variable (defaults from `.env.example`). Non-TTY runs (CI) skip prompts and use defaults.
3. Writes `.env` (chmod 600).
4. Initializes `.clagentic/memory.db` and `.clagentic/audit.db`.
5. Wires `.git/hooks/pre-commit` and `.git/hooks/pre-push`.
6. `chmod +x` on every hook and script.
7. Warns if the repo's current branch doesn't match `CLAGENTIC_DEFAULT_BRANCH` (e.g. you're on `master` but configured `main`) — the `pre-write-guard` rule W-001 needs that to match.

Re-running is safe. An existing `.env` is left alone (delete it to re-prompt).

```sh
./install.sh --check       # verify dependencies, print install hints, no changes
./install.sh --no-prompt   # use .env.example defaults verbatim (for CI)
CLAGENTIC_STRICT_PREFLIGHT=1 ./install.sh --check    # exit non-zero on missing required tools
```

### Verify the install

Two layers — the shell harness, then Claude Code's view of it.

**Shell harness:**

```sh
scripts/smoke.sh --quick   # non-interactive end-to-end without LLM calls
scripts/gates.sh digest    # show what gates ran today
```

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

clagentic-lite defaults to **Claude as Builder, Codex as Reviewer** — that's the point of the cross-CLI pattern. Codex is the OpenAI CLI shipping with ChatGPT Plus / Pro. You need to log in once.

```sh
# 1. Install Codex
#    macOS:   brew install codex
#    Linux:   see https://github.com/openai/codex#installation

# 2. Authenticate (opens a browser to the OpenAI login flow)
codex login

# 3. Verify it works
echo 'print "ok"' | codex exec --skip-git-repo-check 'echo this verbatim'

# 4. Tell clagentic-lite which model tier to call
#    Edit .env (the installer writes the table; you only change the values).
#    Models available on a ChatGPT account (Plus/Pro/Free) — what most users have:
#    CLAGENTIC_MODEL_CODEX_FLAGSHIP=gpt-5.5
#    CLAGENTIC_MODEL_CODEX_DEFAULT=gpt-5.5
#    CLAGENTIC_MODEL_CODEX_CHEAP=gpt-5.5-mini
```

**Model availability matters.** The `-codex` suffixed model names (`gpt-5-codex`, `gpt-5.5-codex`) are gated to API-key accounts only and will fail with a 400 error on ChatGPT-account logins. clagentic-lite's wrapper surfaces that error in the audit row (`gate=llm-call, outcome=step-failed, details=… — the 'gpt-5-codex' model is not supported when using Codex with a ChatGPT account.`) and falls through to the next chain entry. If every step in the chain hits the same wall, you get the degraded envelope with no review — check `scripts/gates.sh digest` to see why.

The wrapper invokes Codex as:

```sh
codex exec --skip-git-repo-check -m "$MODEL" -o "$OUTPUT_FILE" "$PROMPT"
```

If Codex returns non-zero or its output fails to parse as the expected JSON (Reviewer / Merge Gate roles), the wrapper falls through to the next entry in the role's chain. The fallback is whatever you put in `CLAGENTIC_REVIEWER_CHAIN` — typically Claude with a comparable tier.

### Setting up Claude

If you only use Claude Code, set every role's `CMD` to `claude` and put nothing in the chains. The wrapper invokes:

```sh
cat "$INPUT" | claude --print --model "$MODEL" --append-system-prompt "$PROMPT"
```

A same-CLI configuration is allowed — `install.sh --check` warns that you've lost the cross-CLI signal but does not refuse to install.

### Adding a third CLI

Any CLI that accepts a prompt and emits text works. Add a row to the model table:

```sh
CLAGENTIC_MODEL_OLLAMA_DEFAULT=llama3.1:8b
```

…then reference it in a chain (`CLAGENTIC_REVIEWER_CHAIN=claude:default,ollama:default`). The wrapper's generic invocation path is `<cli> -p -` with prompt+input on stdin; CLIs that need a different surface need a case in `invoke_step` in `scripts/llm-client.sh`.

---

## Layout

```
clagentic-lite/
├── AGENTS.md                       canonical agent instructions, cross-tool
├── CLAUDE.md                       pointer to AGENTS.md
├── README.md                       this file
├── install.sh                      POSIX installer, idempotent, prompts
├── .env.example                    every parameter, no secrets
├── docs/
│   ├── DESIGN.md                   architecture and non-goals
│   ├── GATES.md                    what each gate does, what it blocks
│   ├── DEMO-SCRIPT.md              5-minute walkthrough
│   └── PORTABILITY.md              GNU vs BSD tool table
├── .claude/
│   ├── settings.json               hook wiring
│   ├── agents/{builder,reviewer,auditor,merge-gate}.md
│   ├── commands/{review,ship,recall}.md
│   └── hooks/{session-start,prompt-inject,stop-summarize,pre-bash-guard,pre-write-guard}.sh
├── .codex/
│   ├── config.toml                 Codex sandbox + role config
│   └── AGENTS.md → ../AGENTS.md    symlink so Codex reads the same rules
├── scripts/
│   ├── platform.sh                 GNU/BSD shims
│   ├── memory.sh                   SQLite session memory CRUD
│   ├── llm-client.sh               role-aware LLM wrapper with model_chain fallback
│   ├── gates.sh                    gate orchestrator + digest + ship
│   └── smoke.sh                    non-interactive end-to-end
├── examples/{python,node,go}/      demo projects with planted bugs + secrets
└── .github/workflows/gates.yml     CI mirror of local gates (ubuntu + macos)
```

---

## Roles

| Role | Default CLI | Job | State-changing tools |
|---|---|---|---|
| **Builder** | claude | Write code on a feature branch. Never merges. | Read, Write, Edit, Bash (allowlisted) |
| **Reviewer** | codex | Read staged diff, return JSON findings. | Read, Bash (read-only) |
| **Auditor** | codex | LLM narration on top of deterministic security scans. Adversarial mode plays attacker. | Read, Bash (security tools) |
| **Merge Gate** | claude | Final approve/refuse decision over every prior gate's output. Never opens PRs. | Read |

Each role is a markdown file under `.claude/agents/` with the `model_chain` frontmatter and the role contract in the body. The Reviewer file is the longest — it carries the Pre-Report Gate and the Common False Positives list, both load-bearing for output quality.

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
scripts/memory.sh recall <keyword>   # raw recall
sqlite3 .clagentic/audit.db          # inspect the audit trail
sqlite3 .clagentic/memory.db         # inspect session memory
```

`/eng-consult` and `/infosec-rt` are **skills**, not gates — they return structured commentary you read and act on at your own discretion. Both are user-invocable as slash commands at any time. Claude Code may *also* auto-select them on relevant prompts (`/infosec-rt` is scoped to threat-modeling vocabulary; `/eng-consult` is scoped to multi-discipline review vocabulary), but skill auto-selection is heuristic-not-deterministic — when you want the panel, invoke it explicitly. See `.claude/skills/{infosec-rt,eng-consult}/SKILL.md` for the full protocol.

---

## License

**FSL-1.1-MIT** — [Functional Source License 1.1, MIT Future License](https://fsl.software/).

- **Free** for personal use, internal-business use, evaluation, education, research, and contributing back.
- **Not free** for offering clagentic-lite (or a substantial fork) as a competing commercial product or service.
- Each release **auto-converts to MIT** on its second anniversary — fully open source, no restrictions, on a rolling 2-year window.

Commercial licensing inquiries: [clagentic.ai](https://clagentic.ai). See `LICENSE` for the full text and the plain-English summary.
