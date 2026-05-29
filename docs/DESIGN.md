# clagentic-lite — Design

## The thesis

A solo developer running a modern coding agent (Claude Code, Codex CLI, or both) can capture most of the benefit of a full multi-agent platform — cross-vendor review, durable session memory, deliberate gates between drafting and merging — with **nothing more than git hooks, a SQLite file, and two CLI invocations through a pipe**.

clagentic-lite is the smallest credible expression of that thesis. It is built to be read in one sitting, installed in one minute, and demonstrated in five.

## Constraints

1. **Zero servers.** No daemons, no central services, no embedding APIs, no message buses.
2. **Zero vendor lock.** Builder and Reviewer are environment variables. Swap freely.
3. **Two-OS portable.** Identical behavior on WSL2 Ubuntu and macOS. POSIX sh, no bash-4 features, GNU/BSD-tool shims behind one script.
4. **Parameterized.** Nothing hardcoded — no org names, hostnames, user identifiers, model names, or branch names.
5. **Auditable.** Every gate decision, model call, and block lands in one SQLite table. `sqlite3` is the debugger.
6. **Local-first security.** LLMs do not gate security. Deterministic tools do.

## The seven gates

| # | Gate | Trigger | Mechanism | Blocking |
|---|------|---------|-----------|----------|
| 1 | **Memory recall** | `UserPromptSubmit` | `scripts/memory.sh recall <keywords>` → top N summaries injected | no |
| 2 | **Safe Bash + writes** | `PreToolUse` (Bash, Write, Edit) | regex deny-list on dangerous commands; path-scope check; default-branch protection; hooks fail closed when no JSON validator (jq/python3) available | yes |
| 3 | **Cross-CLI review** | `/review` slash command, optional pre-push | Builder's staged diff piped to Reviewer; schema-validated JSON findings | findings ≥ `BLOCK_SEVERITY` block `/ship`; degraded envelopes also block |
| 4 | **Local security scan** | git `pre-commit` (secrets) and `pre-push` (deps, SAST) | gitleaks; osv-scanner; semgrep --error --severity=ERROR. Missing tool fails closed unless `CLAGENTIC_ALLOW_MISSING_*=1` | yes |
| 5 | **Adversarial pass** | `/review --adversarial` | Auditor role plays attacker on the diff | no (commentary) |
| 6 | **Merge Gate** | `/ship` | LLM reads every prior gate's structured output and returns `{decision, reason}` JSON | yes by default (`CLAGENTIC_MERGE_GATE_BLOCKING=1`) |
| 7 | **Session summarize** | `Stop` | async, debounced: Summarizer reads transcript → one-line summary → SQLite | no (best-effort) |

## The four roles

| Role | CLI (default) | Job | Tools allowed |
|---|---|---|---|
| **Builder** | `claude` | Write code on a feature branch. Never merges. | Read, Write, Edit, Bash (allowlisted) |
| **Reviewer** | `codex` | Read staged diff, return structured findings. Never writes code. | Read, Bash (read-only) |
| **Auditor** | `codex` | LLM narration on top of deterministic security scans. Adversarial mode plays attacker. | Read, Bash (security tools) |
| **Merge Gate** | `claude` | Final approve/refuse decision over every prior gate's output. Never opens PRs, never pushes. | Read |

Plus a non-role **Summarizer** (default `claude` at cheap tier) wired into the Stop hook for per-turn session memory.

Cross-CLI is the point — a Reviewer that shares the Builder's training distribution shares its blind spots. Each role declares its own `model_chain` (primary `(cmd, tier)` + ordered fallback list) in `.env` so the *vendor* is configurable per role, not hard-coded.

Two commentary skills live under `.claude/skills/` for deeper deliberation:

- `/eng-consult` — multi-voice consulting panel (Principal + PM + Security/QA/SRE/UX, plus optional Perf/A11y/Tech Writer/Supply Chain).
- `/infosec-rt` — structured red-team threat model (Pen Tester + Insider, optional Supply Chain Analyst).

Skills are commentary only — they do not gate `/ship`. See `docs/GATES.md` § "Skills vs gates" for the boundary.

## Memory — minimal viable recall

One SQLite file per project, at `.clagentic/memory.db`. One table:

```sql
CREATE TABLE turns (
  id          INTEGER PRIMARY KEY,
  ts          TEXT NOT NULL,            -- ISO-8601
  session_id  TEXT NOT NULL,            -- from hook env
  branch      TEXT,
  summary     TEXT NOT NULL,            -- one short paragraph
  tags        TEXT,                     -- space-separated keywords
  source      TEXT                      -- 'stop-hook' | 'manual' | 'seed' | 'summarize-turn'
);
CREATE INDEX idx_turns_ts   ON turns(ts);
CREATE INDEX idx_turns_tags ON turns(tags);
```

Recall is `SELECT summary FROM turns WHERE (summary LIKE ?) OR (tags LIKE ?) ORDER BY ts DESC LIMIT N` with prompt-keyword extraction in shell. No vector search. The SQLite `LIKE` over a few thousand rows is microseconds; if a project ever produces enough history that this becomes slow, that project has outgrown clagentic-lite.

## Cross-CLI review — concrete flow

`/review` slash command routes through `scripts/gates.sh review`:

1. `git diff --cached --unified=3` → stdin to `scripts/llm-client.sh review`.
2. The wrapper walks the Reviewer's model_chain — primary, then each fallback `(cmd, tier)` — and validates output against the reviewer schema (`.findings` must be an array). Schema-invalid output advances the chain; if every step fails, it returns a degraded envelope marked `"degraded": true`.
3. Findings written to `.clagentic/last-review.json`. The Reviewer prompt is fixed (`.claude/agents/reviewer.md`): role, JSON schema, severity scale, Pre-Report Gate, Common False Positives.
4. `gates.sh cmd_review` rejects degraded envelopes (block) and counts findings at `>= CLAGENTIC_BLOCK_SEVERITY` (block on any). Pass otherwise.
5. Outcome row inserted into `.clagentic/audit.db.gate_runs` (`gate=review`, `outcome=pass|block`).
6. `cmd_render_review` pretty-prints the JSON to the session.
7. Builder may revise in the same session. Each revision restarts the loop. Max 3 rounds (operator discipline; not enforced in code).

The Reviewer never edits files. The Builder never gates its own work. `/review` never calls `llm-client.sh` directly — always through `gates.sh` so the audit row, severity check, render, and persistence stay in one path.

## Adversarial layer — non-blocking, opt-in

`/review --adversarial` adds a second pass:

1. Reviewer is reprompted: "you are an attacker. What would you exploit in this diff?"
2. Builder is reprompted: "the reviewer suggests these attacks. Which are plausible? Which are overstated?"
3. Both outputs land in `.clagentic/last-adversarial.md`, attached to the PR as a comment.

This is the demo flourish. It's also genuinely useful, but it's not on the blocking path.

## LLM role-call wrapper

`scripts/llm-client.sh` exposes one interface:

```sh
llm-client.sh <subcmd>
# review       stdin = diff;       stdout = JSON findings (reviewer.md schema)
# summarize    stdin = transcript; stdout = one-line summary (<=200 chars)
# adversarial  stdin = diff;       stdout = markdown attack scenarios
# merge-gate   stdin = gate summary JSON; stdout = {decision,reason} JSON
```

Implementation is **one-shot per call**. Each subcommand resolves the configured chain for its role (`CLAGENTIC_<ROLE>_CMD/_TIER/_CHAIN`), tries each `(cmd, tier)` entry in order, validates the output's schema, and falls through on failure to a degraded envelope marked `"degraded": true`. The gate orchestrator (`scripts/gates.sh`) detects degraded envelopes and blocks rather than treats them as clean reviews.

Per-call timeout is `$CLAGENTIC_LLM_TIMEOUT_SEC` (default 180s) via `timeout` or `gtimeout` — exposed as `$DS_TIMEOUT_CMD` from `scripts/platform.sh`. If neither is available, the wrapper runs without a timeout and `clagentic-lite doctor` warns.

Persistent codex sessions and persistent claude sessions were both considered and deferred. The wall-clock difference between repeated one-shots and one persistent session is small on the cadence clagentic-lite is built for (a few `/review` calls per coding session, not hundreds), and the persistent path would require either codex's experimental `app-server` or a long-running daemon — both of which violate the no-server constraint.

## Portability strategy

`scripts/platform.sh` is sourced by every script and exports:

- `DS_SED_INPLACE` — `-i` on GNU sed, `-i ''` on BSD sed
- `DS_DATE_ISO` — `date -Iseconds` (GNU) or `date -u +%Y-%m-%dT%H:%M:%SZ` (BSD)
- `DS_STAT_MTIME` — `stat -c %Y` (GNU) or `stat -f %m` (BSD)
- `DS_OS` — `linux` (incl. WSL) or `darwin`

Hooks call only POSIX sh + the shims. No `bash-4` features (associative arrays, `${var^^}`, etc.). Verified by `sh -n` syntax check + `scripts/smoke.sh --quick` local run; not gated by hosted CI.

## What gets logged

Every gate run inserts one row into `.clagentic/audit.db`:

```sql
CREATE TABLE gate_runs (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  gate TEXT NOT NULL,        -- 'secrets' | 'sast' | 'deps' | 'review' | 'adversarial' | 'bash-guard' | 'write-guard'
  outcome TEXT NOT NULL,     -- 'pass' | 'block' | 'warn' | 'skip'
  details TEXT,              -- JSON
  session_id TEXT,
  branch TEXT
);
```

`scripts/gates.sh digest` produces a one-screen daily summary. This is the "show your work" surface for a code review or an InfoSec conversation.

## Install shape: clone once, enroll per repo

The tool is cloned once to `$CLAGENTIC_HOME` (default `~/.clagentic-lite`). The tool's own repo is never the thing under gates by default — `clagentic-lite enroll --self` is the dogfood escape hatch.

Per-repo footprint is `.clagentic/{audit.db,memory.db}`, thin shims in `.git/hooks/` that call back to `$CLAGENTIC_HOME/scripts/`, and a `.claude/` directory containing a generated `settings.json` (with absolute hook paths pointing to `$CLAGENTIC_HOME/.claude/hooks/`) plus symlinks to `$CLAGENTIC_HOME/.claude/{commands,agents}`. The `.claude/` directory is added to the project's `.gitignore` automatically. Update the tool once; every enrolled repo picks up the new version automatically because the hook scripts and the symlinked commands/agents resolve back to `$CLAGENTIC_HOME`.

`bin/clagentic-lite` is the CLI entry point. It dispatches `init` (setup + symlink), `enroll` (hook stamp + DB init + register), `unenroll` (remove clagentic-owned hooks + deregister), `list` (enrolled status table), `doctor` (diagnostics punch list), and `update` (ff-only pull + re-stamp).

Project root isolation: `gates.sh`, `memory.sh`, and `llm-client.sh` resolve the project root via `CLAGENTIC_PROJECT_ROOT` env var when set, falling back to `git rev-parse --show-toplevel` of cwd. Hook shims run from inside the enrolled repo's working tree, so git show-toplevel finds the enrolled project automatically without the shim needing to know the path at stamp time.

## Non-goals

- Multi-agent orchestration (no director, no relay).
- Multi-repo state (each enrolled repo has independent DBs; there is no cross-repo index).
- A web UI.
- A plugin marketplace.
- Anything that requires running our own server.

These are excellent things to build. They are not this project.

## Open design questions

- **Summarizer cost control:** spark-tier model is fine for one-paragraph summaries, but a chatty session could rack up calls. Add a debounce (`Stop` fires often) — only summarize after N seconds of quiet. Implementation deferred to weekend 2.
- **Adversarial loop budget:** how many rounds before declaring "the model isn't finding new issues"? Currently capped at 1. Revisit after first real use.
- **Cross-platform sqlite3:** macOS ships an old SQLite. Document `brew install sqlite` as a soft requirement; test on the macOS-default version anyway.
