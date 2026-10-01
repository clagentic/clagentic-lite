<p align="center">
  <img src="media/logo/lite-lockup-256.png" alt="clagentic:lite" width="260" />
</p>

<h4 align="center">Cross-vendor coding harness. Built for builders.</h4>

<p align="center">
  <a href="https://clagentic.ai"><img src="https://img.shields.io/badge/-clagentic.ai-00CFFF?style=flat&logoColor=white" alt="clagentic.ai" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-FSL--1.1--MIT-blue?style=flat" alt="License: FSL-1.1-MIT" /></a>
  <img src="https://img.shields.io/badge/shell-POSIX-4EAA25?style=flat&logo=gnubash&logoColor=white" alt="POSIX shell" />
  <img src="https://img.shields.io/badge/OS-WSL2%20%7C%20macOS-lightgrey?style=flat" alt="WSL2 | macOS" />
  <a href="https://ko-fi.com/clagentic"><img src="https://img.shields.io/badge/Ko--fi-FF5E5B?style=flat&logo=ko-fi&logoColor=white&label=support" alt="Support on Ko-fi" /></a>
</p>

---

# clagentic:lite

Cross-vendor AI coding harness with deterministic security gates and a full SQLite audit trail. Part of the [clagentic](https://clagentic.ai) suite.

Five roles (Builder, Reviewer, Auditor, Merge Gate, Troubleshooter) with per-role model chains. Seven gates (memory recall, safe bash/writes, cross-vendor review, local security scans, adversarial pass, merge gate, session summarize) that fire from Claude Code lifecycle hooks, git hooks, and `clagentic-lite gates` commands. One SQLite file for session memory, one for the audit trail. POSIX shell. No server. Runs the same on WSL2 Ubuntu and macOS.

It is not a platform. It is what you install on your machine so the coding session you have there is visibly more careful than the default.

---

## Two steps: install once, enroll per project

clagentic-lite has two distinct steps.

**`clagentic-lite init`** — runs once per machine. Installs the tool, wires the symlink, detects prereqs, and writes global config. After this, `clagentic-lite` is on your PATH.

**`clagentic-lite enroll`** — runs once per project (inside each git repo you want gated). This is the activation step. Without it, nothing gates your code: no hooks fire, no session memory writes, Claude Code sees no agents or slash commands, and no audit trail exists for that repo.

If you only run `init` and skip `enroll`, the tool is installed but inert.

**Setting this up on someone else's behalf via an AI coding assistant?** See
[`docs/LLM-USAGE.md`](docs/LLM-USAGE.md) — a checklist written for an LLM/agent
session, not a human, covering exactly this two-step sequence plus the checks
to run before assuming either step already happened.

---

## What you get

All capabilities below are per-project and activate only in enrolled repos (`clagentic-lite enroll`).

| Capability | How it works |
|---|---|
| **Per-role model chain** | On the gate/hook path, each role declares an ordered list of `(cli, tier)` pairs. Primary fails → next entry → next → degraded envelope. Every attempt logged. Agents dispatched from Claude Code use a separate setting, see below. |
| **Cross-CLI review** | Builder writes; Reviewer (configured to a different CLI by default) reads the staged diff and returns JSON findings. |
| **Local-tool security gates** | gitleaks pre-commit, osv-scanner + semgrep pre-push. Deterministic. Blocking. No LLM in the security path. |
| **LLM adversarial pass** | Auditor role plays attacker on the diff. Non-blocking. Logged. Attach to PR if interesting. |
| **Merge gate** | Final LLM check reads every prior gate's structured output and returns `approve|refuse`. Never opens PRs, never pushes. |
| **Troubleshooter** | Read-only failure diagnosis agent. Receives one artifact (gate error, hook trace, wrong output), applies structured Tier 0→2 diagnosis, emits root cause and bounce target. Never writes, never dispatches. |
| **Session memory** | Stop-hook pipes the last assistant turn through the Summarizer, writes one row to `.clagentic/lite/memory.db`. UserPromptSubmit hook recalls relevant rows into the next prompt's context. |
| **Safe-by-default tool use** | PreToolUse hooks (`pre-bash-guard.sh`, `pre-write-guard.sh`) block 20 dangerous patterns and writes to the default branch / outside repo / to credential-shaped paths. |
| **Audit trail** | Every gate decision, every LLM call attempt, every block — one row in `.clagentic/lite/audit.db`. `scripts/gates.sh digest` is the readout. |
| **Commentary skills** | `/eng-consult` (multi-voice consulting panel: Principal + PM + Security/QA/SRE/UX) and `/infosec-rt` (structured red-team threat model with chained attack scenarios). User-invocable any time; Claude Code may also auto-select on relevant prompts. Commentary only — neither blocks `clagentic-lite gates ship`. |

---

## Why per-role model chains

A reviewer that shares the builder's training distribution shares its blind spots. So the Reviewer role defaults to a different CLI than the Builder. But "different CLI" should not be hard-coded: each role declares an ordered chain, drawn from whatever CLIs you actually have on this laptop. If your primary fails (rate limit, auth expired, model deprecated), the wrapper walks the chain and logs which entry succeeded.

Concrete example from `share/config.example`:

```sh
CLAGENTIC_BUILDER_CMD=claude
CLAGENTIC_BUILDER_TIER=default
CLAGENTIC_BUILDER_CHAIN=codex:default,claude:flagship

CLAGENTIC_REVIEWER_CMD=codex
CLAGENTIC_REVIEWER_TIER=flagship
CLAGENTIC_REVIEWER_CHAIN=claude:default,codex:flagship
```

Tier names (`flagship`, `default`, `cheap`) resolve to concrete model strings via the `CLAGENTIC_MODEL_<CLI>_<TIER>` table in `~/.config/clagentic/lite/config`. That table feeds `scripts/llm-client.sh`, so it decides the model for the **gate/hook path**: `gates review|ship`, git hooks, Claude Code lifecycle hooks. When a model deprecates, you edit that one table row and every role that uses the tier follows.

**Agents dispatched from Claude Code are a different path.** When Claude Code's Agent tool dispatches `clagentic-lite:builder` (or any other role), `_CMD`/`_TIER`/`_CHAIN` are not consulted; the agent runs on the session model. To pin a model for that dispatch, set `CLAGENTIC_<ROLE>_AGENT_MODEL` (a Claude Code alias, a full model ID, or `inherit`), for example `CLAGENTIC_BUILDER_AGENT_MODEL=<model-id-or-alias>`. It exists for all five roles, applies to Claude Code only, and takes effect after `clagentic-lite update`. Set it in the global config (`~/.config/clagentic/lite/config`): the rendered plugin is one per user, so a repo's `.clagentic/config` or an exported shell value is never applied to it (`doctor` says so). `clagentic-lite doctor` shows the effective value per role. On Bedrock or Vertex, prefer a full model ID over a bare alias: an alias resolves to Claude Code's default for the active backend, which can lag the newest model. See [`docs/LLM-USAGE.md`](docs/LLM-USAGE.md#two-model-paths--which-keys-control-which-model) for the full two-path table.

---

## Install

Clone once, enroll per project. The snippet below is safe to re-run — on a fresh machine it clones, on a machine that already has clagentic-lite it pulls and re-runs `init` (which is also what `clagentic-lite update` does):

```sh
# First install OR re-run after pulling new commits.
HOME_DIR="${CLAGENTIC_LITE_HOME:-$HOME/.clagentic/lite}"
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

After the first install, the steady-state upgrade is just `clagentic-lite update` — it does the `git pull --ff-only`, re-checks prereqs, re-materializes the hook scripts, re-renders and re-installs the plugin, and re-stamps hook shims, `.claude/settings.json`, and `CLAUDE.md` in every enrolled repo when their template versions change. **It does not add new keys to `~/.config/clagentic/lite/config`** unless you ask: your global config is written once by `init`, so a key shipped after your install is simply absent. `clagentic-lite doctor` lists the keys in `share/config.example` your config is missing ("global config drift"). `clagentic-lite update --refresh-config` appends them as commented-out lines (nothing is activated, nothing you set is touched), or you can add the ones you want by hand. (`init --reconfigure` also merges: it re-prompts but keeps every value you already set.) The one automatic change is a one-time, additive move of an old config from `~/.config/clagentic/config` — see "Config file location" below.

**Upgrading and the secrets gate.** If any enrolled repo's `.gitleaks.toml` declares no `[[rules]]` table and has no `[extend]` / `useDefault = true`, the secrets gate previously reported a permanent, silent pass — `gitleaks --config` replaces the built-in ruleset rather than merging with it, so a rules-less config detects nothing. Since the fix for this, that same config now **blocks** the `secrets` gate outright, naming the cause, instead of passing. That is the correct behavior, but if your gate has been green for a while, it can look like the upgrade broke something. Run `clagentic-lite doctor` after updating — it now warns on exactly this condition for every enrolled repo, before you hit the block, and names the fix (`[extend]` / `useDefault = true`, or declare your own `[[rules]]`). See [`docs/GATES.md`, "4a. Secrets"](docs/GATES.md#4a-secrets-pre-commit) for the full mechanism.

If `init` warns that `~/.local/bin` is not on `$PATH`, add this to your shell rc and reopen your shell:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

There is no package manager. Distribution is the git repo itself at <https://github.com/clagentic/clagentic-lite>. `update --restamp` forces every enrolled repo's versioned artifacts to be re-stamped regardless of template version. Your global config (`~/.config/clagentic/lite/config`) is not one of those artifacts — see above.

The tool is cloned once to `~/.clagentic/lite` (or `$CLAGENTIC_LITE_HOME` if set). Your projects never contain a copy of the scripts or agent files — they hold only `.clagentic/lite/{audit.db,memory.db}`, thin hook shims, and a `CLAUDE.md` that call back to `$CLAGENTIC_LITE_HOME`. Update the tool once and every enrolled repo picks it up.

### Prerequisites

clagentic-lite is POSIX shell plus agent/skill markdown, and it leans on real tools to do real work. The security gates are deterministic local scanners — gitleaks, semgrep, osv-scanner — not LLM judgment. If you don't have them, you don't have the gates. The harness ships with explicit opt-ins to skip each one (see "Minimal install" below) so you can run a stripped-down version while you decide which gates you want.

`clagentic-lite init` detects missing tools and offers to run the install command for you. If you decline, it prints the exact command and reports how many required tools are still missing. It exits non-zero on a missing required tool only when `CLAGENTIC_STRICT_PREFLIGHT=1`.

Required:

| Tool         | Purpose                                | Linux/WSL                   | macOS                       |
|--------------|----------------------------------------|-----------------------------|-----------------------------|
| `sqlite3`    | session memory + audit DB              | `apt install sqlite3`       | `brew install sqlite`       |
| `git`        | hooks, diffs                           | `apt install git`           | `xcode-select --install`    |
| `jq` or `python3` | hook JSON parsing — hooks fail closed without either | `apt install jq` | `brew install jq` (python3 ships with macOS) |
| **one LLM CLI** | for Builder + Reviewer roles. `claude` or `codex`; both is the cross-CLI pattern. Not checked by `init` or `doctor`; a missing CLI shows up as a failed chain step in the audit trail. | see vendor docs | see vendor docs |

Required for the security gates (you can install these later and opt-in per gate):

| Tool                | Gate     | Linux/WSL                   | macOS                       | Skip with                              |
|---------------------|----------|-----------------------------|-----------------------------|----------------------------------------|
| `gitleaks` ≥ 8.19   | secrets  | see [releases][gl]          | `brew install gitleaks`     | `CLAGENTIC_ALLOW_MISSING_GITLEAKS=1`   |
| `semgrep`           | sast     | `pipx install semgrep`      | `brew install semgrep`      | `CLAGENTIC_ALLOW_MISSING_SEMGREP=1`    |
| `osv-scanner`       | deps     | [osv-scanner releases][osv] | `brew install osv-scanner`  | `CLAGENTIC_ALLOW_MISSING_OSV=1`        |

Nice-to-have:

| Tool      | Why                                                     |
|-----------|---------------------------------------------------------|
| `gh`      | `clagentic-lite gates ship` opens the PR for you (the GitHub adapter is the only one shipped); without it, `ship` prints the base/head/remote to open a PR manually |
| `timeout` / `gtimeout` | per-call LLM timeout; auto-detected. macOS users: `brew install coreutils` for `gtimeout` |

### Minimal install (just the harness, no security gates)

Want to try the role/review/memory layer without installing gitleaks/semgrep/osv-scanner? Set the three `ALLOW_MISSING` opt-ins to `1` in `~/.config/clagentic/lite/config` after `clagentic-lite init`:

```sh
CLAGENTIC_ALLOW_MISSING_GITLEAKS=1
CLAGENTIC_ALLOW_MISSING_SEMGREP=1
CLAGENTIC_ALLOW_MISSING_OSV=1
```

That gives you the cross-CLI review, the dumb-thing-blocking hooks, session memory, and the audit trail — but no deterministic secret/dep/sast scanning. Add the tools when you want the gates. The audit DB will record `skip` rows so you have a paper trail of which gates ran and which didn't.

### What `clagentic-lite init` and `clagentic-lite enroll` do

**`clagentic-lite init`** (run once, in $CLAGENTIC_LITE_HOME or anywhere after the symlink is on PATH):

1. Verifies `$CLAGENTIC_LITE_HOME` is a valid clagentic-lite checkout, and warns if it is behind its upstream (skip that check with `CLAGENTIC_SKIP_FETCH=1`).
2. Materializes the Claude Code lifecycle hook scripts into `$CLAGENTIC_LITE_HOME/.claude/hooks/` from `share/hook-shims/*.sh.template` — the one copy every enrolled repo calls back into.
3. Detects WSL vs macOS, picks portable tool variants (`scripts/platform.sh`), and checks prerequisites. For each missing tool it prints the install command and prompts `Run it now? [y/N]`. On decline it reports the missing count and continues (exits non-zero only with `CLAGENTIC_STRICT_PREFLIGHT=1`).
4. Two-question front door: accept all defaults (Y/n) + vendor mode ([1] Claude only / [2] Claude+Codex). On Y+mode-2: writes global config and done. On n: up to 6 granular prompts. Skipped when a config already exists, unless you pass `--reconfigure`.
5. Writes `~/.config/clagentic/lite/config` (chmod 600). If a config still exists at the old brand-root path `~/.config/clagentic/config`, it is migrated in place first (see "Config file location" below) rather than re-prompted from scratch.
6. Ensures `~/.local/bin/` exists; warns with the exact shell-profile line if not on `$PATH`.
7. Symlinks `~/.local/bin/clagentic-lite` to `$CLAGENTIC_LITE_HOME/bin/clagentic-lite`.
8. Renders and installs the `clagentic-lite` Claude Code plugin (the five agents plus the two skills) globally via `claude plugin`, if `claude` is on `PATH`.

**`clagentic-lite enroll [PATH]`** (run inside each project you want gates on, default `$PWD`):

1. Verifies the path is a git repo.
2. Refuses if the path is `$CLAGENTIC_LITE_HOME` (use `--self` for dogfood).
3. Refuses if already enrolled (use `--force` to re-enroll).
4. Initializes `.clagentic/lite/audit.db` and `.clagentic/lite/memory.db` in that repo.
5. Stamps `.git/hooks/pre-commit` and `.git/hooks/pre-push` from `share/hook-shims/*.template`, substituting `$CLAGENTIC_LITE_HOME` at stamp time. Refuses to overwrite non-clagentic hooks unless `--force`.
6. Generates `.claude/settings.json` (absolute hook paths → `$CLAGENTIC_LITE_HOME`), symlinks `.claude/commands`, and ignores `.claude/` and `.clagentic/lite/` (see "Which project files enroll and update write" below for where). These are local-only artifacts. Role agents and commentary skills are installed globally via the `clagentic-lite` plugin at `init` time — no per-repo copies.
7. Stamps `CLAUDE.md` at the repo root when none exists — activates the Builder contract and exposes agents for Claude Code auto-dispatch. A `CLAUDE.md` without the `managed-by: clagentic` marker is project-owned and is never overwritten, not even with `--force`.
8. Registers the repo path in `~/.local/state/clagentic/registry`.

#### Which project files enroll and update write

Everything else enroll and update write lives under `.git/` or `.clagentic/lite/` (and `.claude/`, which is ignored). The only files that can be tracked by your project are these two:

| Layout | `.gitignore` | `CLAUDE.md` | Ignore patterns go to |
|---|---|---|---|
| Regular repo (default) | appended with `.claude/` and `.clagentic/lite/` if absent (created if missing); nothing else in it is touched | stamped when missing; the notice block is refreshed when the file is clagentic-managed; an unmanaged file is never touched | the repo's `.gitignore` |
| Regular repo, `CLAGENTIC_IGNORE_TARGET=exclude` | never touched | same as above | `.git/info/exclude` |
| Wrapper layout (enrolled through a wrapper directory) | never touched | not created (the wrapper `CLAUDE.md` already carries the rules and Claude Code loads it as an ancestor file); a clagentic-managed one keeps its notice refreshed | `.git/info/exclude` |

`CLAGENTIC_IGNORE_TARGET` (`gitignore` or `exclude`, in the global config) overrides the per-layout default. To keep a project's tracked files untouched, set it to `exclude`, or enroll through the wrapper layout. A pattern already present in either `.gitignore` or `.git/info/exclude` counts as satisfied, so a pattern you moved to `info/exclude` is never added back to `.gitignore`. The exclude path is resolved with `git rev-parse --git-path`, so linked worktrees and submodules (where `.git` is a file) work. Governance files at the top of `.clagentic/` (`adversarial-acks.json`, `osv-ignore`, `accepted-risks.md`, `config`) stay trackable in every mode.

Lines an earlier enrollment already added to a tracked `.gitignore` are not removed automatically; for a wrapper-enrolled repo `doctor` prints an INFO line saying they can be moved to `.git/info/exclude`. `update`'s one-time migration of old per-file `.clagentic/*` patterns removes only those exact legacy lines and keeps every other line, blank lines included.

**A repo-local `.clagentic/config` does not apply on this very first `enroll` call** — the CLI will not execute a repo's own config before that repo is registered as enrolled. It takes effect starting with the next command you run against the repo (`doctor`, `update`, a re-`enroll`, or any hook that fires from your next commit). The global config (`~/.config/clagentic/lite/config`) is unaffected and applies at enroll time as normal.

#### Config file location

The global config lives at `~/.config/clagentic/lite/config` — `~/.config/clagentic/` is a brand root shared with other tools (`clagentic-loadout` uses `~/.config/clagentic/loadout/` alongside it), so clagentic-lite's own config lives one segment deeper, under `lite/`, never at the bare brand root.

If you installed an older version, your config may still be at `~/.config/clagentic/config`. `clagentic-lite update` (and a fresh `init` on an un-migrated machine) moves it automatically: byte-identical content, `chmod 600` preserved throughout, with a one-time warning. Until you run `update`, the old path is still read as a fallback — nothing is silently lost. If both paths somehow end up populated with different content, neither is touched automatically; `doctor` names both paths and tells you to reconcile by hand.

### Solo vs. shared repos

**Solo / private repo**: `CLAUDE.md` is generated and ready to use. If you'd rather not commit it, add it to `.gitignore` yourself — clagentic-lite won't do that automatically because the file is safe to commit.

**Shared repo**: `CLAUDE.md` is committable as-is and is the only clagentic artifact that is meant to be shared. It contains no machine-specific paths. Teammates without clagentic-lite installed will see a normal project CLAUDE.md. Teammates with clagentic-lite installed will get full agent auto-dispatch.

`.claude/` (hook wiring, command symlinks, `settings.json`) is **local-only** — it is added to `.gitignore` (or `.git/info/exclude`, see above) automatically at enroll time and is never committed. Each teammate who wants clagentic-lite active must run `clagentic-lite enroll` in the repo on their own machine. This is by design: hook paths are absolute and machine-specific; sharing them would break the harness on every machine but the original.

A `CLAUDE.md` that lacks the `managed-by: clagentic` marker is yours: `clagentic-lite enroll --force` leaves it byte-identical and says so. To have enroll stamp the notice instead, delete or rename the file and enroll again.

### Verify the install

Two layers — the shell harness, then Claude Code's view of it.

**Shell harness:**

```sh
# Run from inside $CLAGENTIC_LITE_HOME (default: ~/.clagentic/lite):
"$CLAGENTIC_LITE_HOME/scripts/smoke.sh" --quick   # non-interactive end-to-end without LLM calls

# Run from inside an enrolled project repo:
"$CLAGENTIC_LITE_HOME/scripts/gates.sh" digest    # show what gates ran today
"$CLAGENTIC_LITE_HOME/scripts/gates.sh" status    # last 10 runs per gate, color-coded
"$CLAGENTIC_LITE_HOME/scripts/gates.sh" tail      # follow audit.db live (Ctrl-C to quit)

# Run from anywhere:
clagentic-lite doctor      # diagnostics: symlink, prereqs, every enrolled repo's hook status
```

Note: `scripts/` lives in `$CLAGENTIC_LITE_HOME`, not in your enrolled project. Always use the absolute path form (`"$CLAGENTIC_LITE_HOME/scripts/gates.sh"`) when running gate scripts directly from inside a project. The `clagentic-lite` CLI and its `gates review`/`gates ship` subcommands use the correct path automatically.

Smoke covers: DB init, seed + recall, gitleaks blocks a planted token, `llm-client.sh review` emits parseable JSON, audit-DB has fresh rows. If smoke passes, the harness is wired correctly.

**Claude Code sees the agents, commands, and skills:**

Open the repo in Claude Code and type each of these. If any are "command not found," Claude Code didn't pick up the file — usually a permissions issue (`chmod +x .claude/hooks/*.sh scripts/*.sh`) or a stale Claude Code session (restart it).

```text
/recall            → prints recent session summaries (empty on fresh install)
/infosec-rt        → convenes the red-team threat model
/eng-consult       → convenes the multi-voice engineering consulting panel
```

For review/ship, use the subagent or gates subcommands directly (no slash command exists for these anymore):

```sh
clagentic-lite gates review   # cross-CLI review of the staged diff (no diff staged yet, so it'll say so)
clagentic-lite gates ship     # runs the full gate sequence (won't actually push on main)
```

If `/infosec-rt` or `/eng-consult` aren't recognized, the `clagentic-lite` plugin may not be installed or may have failed to load. Run `claude plugin list` and check for `clagentic-lite` with status `✔ active`. If it shows failed, re-run `clagentic-lite init`. Skills are discovered by Claude Code from the plugin's `skills/` directory — no per-repo files are needed.

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

Fill in the model IDs that are available on your account. clagentic-lite reads this file at runtime — update it when OpenAI releases new models or renames existing ones, with no `clagentic-lite init` re-run required. Model strings in `~/.config/clagentic/lite/config` (`CLAGENTIC_MODEL_CODEX_*`) are intentionally left blank by default so this file is the sole source of truth.

Tier names map to clagentic-lite's chain vocabulary: `flagship`, `mini`, `spark`. The `default` tier alias resolves to `default_tier` in the file. Explicit env vars always win over models.json if both are set.

**Model availability matters.** The `-codex` suffixed names (`gpt-5-codex`, `gpt-5.5-codex`) are API-key-only and return a 400 error on ChatGPT-account logins. When a step fails, the reason appears in the audit row — run `"$CLAGENTIC_HOME/scripts/gates.sh" digest` to see it.

The wrapper invokes Codex roughly as below, with the prompt and input on stdin (extra read-only flags are added for the Reviewer and Auditor; see `invoke_codex` in `scripts/llm-client.sh` for the exact set, which depends on your installed Codex version):

```sh
codex exec --skip-git-repo-check -m "$MODEL" --color never -o "$OUTPUT_FILE" - < "$PROMPT_AND_INPUT"
```

If Codex returns non-zero or its output fails to parse as the expected JSON (Reviewer / Merge Gate roles), the wrapper falls through to the next entry in the role's chain. The fallback is whatever you put in `CLAGENTIC_REVIEWER_CHAIN` — typically Claude with a comparable tier.

### Why not the official Claude Code Codex plugin

The marketplace plugin (`/codex:rescue`, etc.) gives you hardcoded slash commands with no tier selection, no session continuity, and opaque error handling. The `codex exec` path used here is pure shell, explicit tier, verbatim output, and composable with every other role in the harness.

### Setting up Claude

If you only use Claude Code, set every role's `CMD` to `claude` and put nothing in the chains. The wrapper invokes, roughly (output-format and tool-restriction flags vary by role; see `invoke_claude`):

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

### Optional: clagentic-router integration

[clagentic-router](https://github.com/clagentic/clagentic-router) is a separate, optionally-run local proxy that lets Claude Code's *interactive* subagent dispatch (Reviewer, Auditor, … invoked mid-session via the Agent/Task tool) route through a chosen backend the same way the gate path (`CLAGENTIC_<ROLE>_CMD`/`_TIER`/`_CHAIN`, `scripts/llm-client.sh`) already does — a gap that exists because clagentic-lite is not Claude Code's parent process and has no interception point on that path otherwise. It is a separate repo, not installed or started by clagentic-lite — you run it yourself. If all you want is a different Claude model for a dispatched agent, you do not need it: use `CLAGENTIC_<ROLE>_AGENT_MODEL` (above).

There are **three independent opt-ins**, not one switch, and enabling one does not enable the others:

1. `CLAGENTIC_ROUTER_URL` — stamps the router into `.claude/settings.json` as a transparent proxy for the interactive session (passthrough by default; routed mode with a named chain if you configure one).
2. `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL` — additionally injects `model: role:<role>-chain` into the Reviewer/Auditor/Merge-Gate subagent frontmatter, and wins over `CLAGENTIC_<ROLE>_AGENT_MODEL` for those roles. **Unverified** — whether Claude Code actually honors this is unconfirmed ([claude-code GH#44385](https://github.com/anthropics/claude-code/issues/44385)).
3. `CLAGENTIC_<ROLE>_VIA_ROUTER` — the separate gate-path switch, scoped to `reviewer`/`auditor` only. See `docs/ROUTER.md` for why Builder and Merge-Gate are excluded.

Full detail — setup, the Bedrock-mode variable pair, the URL validation rules, the agent-model-injection verification procedure, and the gate-path routing switch — lives in **[`docs/ROUTER.md`](docs/ROUTER.md)**.

**`CLAGENTIC_ROUTER_URL` is validated before it is ever stamped.** This value redirects your entire Claude Code session and, in passthrough mode, forwards your real Anthropic credentials to whatever host it names — it is a traffic-interception primitive, not an ordinary config string. A malformed URL is refused outright. A well-formed but non-local host (anything other than `localhost`/`127.0.0.0/8`/`::1`) is allowed but warned loudly, at both stamp time and every `clagentic-lite doctor` run — an operator must not have to follow a link to learn their real Anthropic credentials may be forwarded to a remote host. See `docs/ROUTER.md` for the full classification rules.

---

## Layout

The tool lives in `$CLAGENTIC_LITE_HOME` (default `~/.clagentic/lite`). Your enrolled projects hold only the per-repo state — no copy of scripts, agents, or config.

```
~/.clagentic/lite/                              the tool — never gated by default
├── bin/clagentic-lite                          CLI entry point
├── AGENTS.md                                   canonical agent instructions, cross-tool
├── CLAUDE.md                                   pointer to AGENTS.md
├── README.md                                   this file
├── install.sh                                  stub that only prints a redirect to the steps above
├── adversarial-acks.json.example               template for a repo's .clagentic/adversarial-acks.json
├── share/
│   ├── config.example                          global config template (written to ~/.config/clagentic/lite/config)
│   ├── accepted-risks.example.md               template for a repo's .clagentic/accepted-risks.md
│   ├── bleed-patterns.example                  template for the internal-bleed gate's pattern file
│   └── hook-shims/                             templates stamped or materialized by init/enroll/update:
│       ├── pre-commit.template, pre-push.template          git hook shims, stamped into enrolled repos
│       ├── CLAUDE.md.template, builder-contract.template   enrolled-repo notice and local builder contract
│       ├── claude-settings.template                        .claude/settings.json for enrolled repos
│       └── {session-start,prompt-inject,pre-bash-guard,pre-write-guard,post-tool-nudge,stop-summarize}.sh.template
├── docs/
│   ├── DESIGN.md                               architecture and non-goals
│   ├── GATES.md                                what each gate does, what it blocks
│   ├── ROUTER.md                               clagentic-router integration: all three opt-ins, operator-facing
│   ├── DEMO-SCRIPT.md                          5-minute walkthrough
│   ├── PORTABILITY.md                          GNU vs BSD tool table
│   └── LLM-USAGE.md                            checklist for an LLM/agent setting this up or operating it for a user
├── .claude/
│   ├── commands/recall.md                      symlinked into enrolled repos
│   └── hooks/{session-start,prompt-inject,pre-bash-guard,pre-write-guard,post-tool-nudge,stop-summarize}.sh
│                                               materialized by init/update from share/hook-shims/*.sh.template
├── .clagentic/rendered-plugin/                 generated by init/update: the config-aware plugin copy that is actually installed
├── plugins/
│   └── clagentic-lite/
│       ├── .claude-plugin/plugin.json          plugin manifest (name, version)
│       ├── agents/{builder,reviewer,auditor,merge-gate,troubleshooter}.md  role contracts
│       └── skills/{infosec-rt,eng-consult}/SKILL.md  commentary skills
├── .codex/
│   ├── config.toml                             Codex sandbox + role config (operator-facing docs; not auto-loaded — see AGENTS.md)
│   └── AGENTS.md → ../AGENTS.md               symlink so Codex reads the same rules
├── scripts/
│   ├── platform.sh                             GNU/BSD shims + ds_check_tool/ds_offer_install
│   ├── memory.sh                               SQLite session memory CRUD
│   ├── llm-client.sh                           role-aware LLM wrapper with model_chain fallback
│   ├── gates.sh                                gate orchestrator + digest + ship
│   ├── review-merge.sh                         diff chunking, envelope merge and cross-round finding tracking (sourced by gates.sh)
│   ├── host-adapter.sh                         the one place a git host (GitHub, via `gh`) is named: PR open and verdict comments
│   └── smoke.sh                                non-interactive end-to-end
└── examples/{python,node,go}/                  demo projects with planted bugs + secrets

~/.config/clagentic/lite/config                 global config (chmod 600; written by init). ~/.config/clagentic/
                                                 is the shared brand root (clagentic-loadout uses
                                                 ~/.config/clagentic/loadout/ alongside this) -- lite's own state
                                                 always lives one segment deeper, under lite/.
                                                 An old config at the bare ~/.config/clagentic/config path
                                                 (pre-lr-7939f8) is migrated here automatically by `update`,
                                                 with a one-time warning; still honored as a read fallback
                                                 until migrated.
~/.config/clagentic/lite/osv-ignore              global osv CVE ignore list (gates.sh deps, one ID per line).
                                                 An old list at the bare ~/.config/clagentic/osv-ignore path
                                                 (pre-lr-8ee2df) is migrated here automatically on the next
                                                 `deps` run, with a one-time warning; still honored as a read
                                                 fallback until migrated.
~/.config/clagentic/lite/semgrep-exclude         global semgrep rule-exclude ladder (gates.sh sast, one rule id
                                                 per line). Same migrate-and-warn as osv-ignore above, from the
                                                 bare ~/.config/clagentic/semgrep-exclude path (pre-lr-8ee2df).
~/.local/state/clagentic/registry               enrolled repos — one absolute path per line
~/.local/bin/clagentic-lite                     symlink to $CLAGENTIC_LITE_HOME/bin/clagentic-lite

<any enrolled repo>/
├── .clagentic/
│   ├── adversarial-acks.json                   per-CWE ack list (governance, committed)
│   ├── accepted-risks.md                       architectural risk docs (governance, committed)
│   ├── osv-ignore                              osv CVE ignore list (governance, committed)
│   ├── config                                  repo-level config overrides (governance, committed; not read on the first `enroll` — see "What init and enroll do" above)
│   └── lite/
│       ├── audit.db                            gate run log (written by gates.sh, gitignored)
│       └── memory.db                           session memory (written by memory.sh, gitignored)
└── .git/hooks/
    ├── pre-commit                              shim: calls $CLAGENTIC_LITE_HOME/scripts/gates.sh secrets
    └── pre-push                                shim: calls $CLAGENTIC_LITE_HOME/scripts/gates.sh pre-push
```

---

## Roles

| Role | Default CLI | Job | State-changing tools |
|---|---|---|---|
| **Builder** | claude | Write code on a feature branch. Never merges. | Read, Write, Edit, Bash (allowlisted) |
| **Reviewer** | codex | Read staged diff, return JSON findings. | Read, Bash (read-only) |
| **Auditor** | codex | LLM narration on top of deterministic security scans. Adversarial mode plays attacker. | Read, Bash (security tools) |
| **Merge Gate** | claude | Final approve/refuse decision over every prior gate's output. Never opens PRs. | Read, Bash (unrestricted on the CLI path) |
| **Troubleshooter** | (session model) | Read-only failure diagnosis: one artifact in, root cause and bounce target out. Never writes. | Read, Glob, Grep, Bash (read-only) |

(The default CLI column is the CLI/hook path default; the Troubleshooter runs only as a Claude Code agent.) Each role's contract is a markdown file at `plugins/clagentic-lite/agents/<role>.md`, delivered to Claude Code by the `clagentic-lite` plugin; nothing is copied into your project. There are two independent ways a role's model is chosen: `CLAGENTIC_<ROLE>_CMD`/`_TIER`/`_CHAIN` for non-interactive invocations through `llm-client.sh`, and `CLAGENTIC_<ROLE>_AGENT_MODEL` for agents dispatched from Claude Code (see "Why per-role model chains" above). The Reviewer file is the longest — it carries the Pre-Report Gate and the Common False Positives list, both load-bearing for output quality.

---

## Gates

| # | Gate | Trigger | Blocking? |
|---|------|---------|----------|
| 1 | Memory recall | UserPromptSubmit | no |
| 2 | Safe Bash + writes | PreToolUse (Bash, Write, Edit) | yes |
| 3 | Cross-CLI review | `clagentic-lite gates review`, or pre-push with `CLAGENTIC_REVIEW_ON_PUSH=1` | yes if findings ≥ `CLAGENTIC_BLOCK_SEVERITY` |
| 4 | Local security scan | pre-commit (gitleaks), pre-push (osv-scanner, semgrep), plus an opt-in internal-bleed pattern scan in `gates ship` | yes |
| 5 | Session summarize | Stop | no (best-effort) |
| 6 | Adversarial pass | `clagentic-lite gates adversarial` | no |
| 7 | Merge Gate | `clagentic-lite gates ship` | yes by default, set `CLAGENTIC_MERGE_GATE_BLOCKING=0` to make advisory |

Details in `docs/GATES.md`.

---

## Daily commands

```sh
clagentic-lite gates review        # cross-CLI review of the staged diff, or the branch diff (single Reviewer pass)
clagentic-lite gates adversarial   # attacker-perspective markdown pass
clagentic-lite gates ship          # run all gates; if green, push and open PR
/recall <keywords>                 # grep session memory (inside Claude Code)

/eng-consult             # multi-voice consulting panel (Principal + PM + specialists)
/infosec-rt              # structured red-team threat model

clagentic-lite gates digest          # what gates ran today
clagentic-lite gates status          # last N runs per gate (default 10), color-coded outcomes
clagentic-lite gates tail            # follow audit.db live; new gate rows render as they land
clagentic-lite recall <keywords>     # search session memory from the shell
clagentic-lite remember "<note>"     # store a pinned manual memory entry
sqlite3 .clagentic/lite/audit.db     # inspect the audit trail
sqlite3 .clagentic/lite/memory.db    # inspect session memory
clagentic-lite show memory [N]       # pretty-print last N session memory rows (default 10)
clagentic-lite show gates [N]        # pretty-print last N gate run rows (default 10)
clagentic-lite export                # write self-contained HTML report to .clagentic/lite/report.html
clagentic-lite export --output PATH  # write report to a specific path
clagentic-lite list                  # enrolled repos and last gate run
clagentic-lite doctor                # diagnostics
clagentic-lite update [--restamp] [--refresh-config]
clagentic-lite unenroll [--purge] [PATH]
clagentic-lite rotate                # re-stamp every enrolled repo's settings.json with the current router token
```

`/eng-consult` and `/infosec-rt` are **skills**, not gates — they return structured commentary you read and act on at your own discretion. Both are user-invocable as slash commands at any time. Claude Code may *also* auto-select them on relevant prompts (`/infosec-rt` is scoped to threat-modeling vocabulary; `/eng-consult` is scoped to multi-discipline review vocabulary), but skill auto-selection is heuristic-not-deterministic — when you want the panel, invoke it explicitly. See `plugins/clagentic-lite/skills/{infosec-rt,eng-consult}/SKILL.md` for the full protocol.

---

## When something fails

A gate returns non-zero, a hook errors, `clagentic-lite gates ship` prints `BLOCKED` or `INFRA_DEGRADED`, or `clagentic-lite doctor` reports a broken enrollment — the first move is the **Troubleshooter** agent, not fixing it inline. It is read-only, diagnoses in Tier 0→2, and hands back a root cause plus a `bounce_target` naming who should act (you, the Builder, or nobody — expected behavior). Invoke it by name in Claude Code, or describe the failure ("why did this fail", a pasted exit code, a gate error) — its description is written to match that vocabulary so Claude Code is more likely to select it, but agent selection is always a model judgment call, not a guaranteed trigger; if it doesn't pick the Troubleshooter up on its own, ask for it explicitly. See `plugins/clagentic-lite/agents/troubleshooter.md` for the full contract.

---

## When you've outgrown lite

Signals: you want a server; you want multi-repo memory; you want ranked or embedding-based retrieval; you want multi-agent orchestration; you want memory that learns, decays, and promotes itself automatically.

If you're hitting these limits, the tool did its job — you've grown into needing a heavier harness that provides those capabilities explicitly.

No `eject` subcommand, no schema bridge. `.clagentic/lite/memory.db` is plain SQLite — query it directly with `sqlite3`, or run `clagentic-lite export` to generate a self-contained HTML report. No migration tooling or schema bridge is planned. See `docs/DESIGN.md` § "When you've outgrown lite" for the full rationale.

---

## Support

If clagentic:lite is useful to you: [ko-fi.com/clagentic](https://ko-fi.com/clagentic)

## Disclaimer

Not affiliated with Anthropic or OpenAI. Claude is a trademark of Anthropic. Codex is a
trademark of OpenAI. Provided "as is" without warranty. Users are responsible for
complying with their AI provider's terms of service.

## License

[FSL-1.1-MIT](LICENSE) — Functional Source License 1.1, with MIT as the Change License.

Free for personal, internal-business, evaluation, research, and non-commercial use.
Not free for offering this tool (or a substantial fork) as a competing commercial product.
Each release auto-converts to MIT on its second anniversary.

Commercial licensing inquiries: [clagentic.ai](https://clagentic.ai).
