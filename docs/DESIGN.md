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
| 1 | **Memory recall** | `UserPromptSubmit` | `scripts/memory.sh recall <keywords>` → top `CLAGENTIC_RECALL_LIMIT` (default 5) summaries injected, capped at `CLAGENTIC_RECALL_MAX_CHARS` (default 1500) chars | no |
| 2 | **Safe Bash + writes** | `PreToolUse` (Bash, Write, Edit) | regex deny-list on dangerous commands; path-scope check; default-branch protection; hooks fail closed when no JSON validator (jq/python3) available | yes |
| 3 | **Cross-CLI review** | `/review` slash command, optional pre-push | Builder's staged diff piped to Reviewer; schema-validated JSON findings | findings ≥ `BLOCK_SEVERITY` block `/ship`; degraded envelopes also block |
| 4 | **Local security scan** | git `pre-commit` (secrets) and `pre-push` (deps, SAST) | gitleaks; osv-scanner; semgrep --error --severity=ERROR. Missing tool fails closed unless `CLAGENTIC_ALLOW_MISSING_*=1` | yes |
| 5 | **Adversarial pass** | `/review --adversarial` | Auditor role plays attacker on the diff; each finding is tagged `reachable: yes/no`, `tier: blocking/advisory`, and `class: durable/ephemeral` | no on its own (commentary); `tier: blocking` findings are what Gate 6 can refuse on |
| 6 | **Merge Gate** | `/ship` | LLM reads every prior gate's structured output and returns `{decision, reason}` JSON | yes by default (`CLAGENTIC_MERGE_GATE_BLOCKING=1`); only `tier: blocking` adversarial findings are refusal-eligible, `tier: advisory` findings are never gating |
| 7 | **Session summarize** | `Stop` | async, debounced: Summarizer reads transcript → one-line summary → SQLite | no (best-effort) |

## The five roles

| Role | CLI (default) | Job | Tools allowed |
|---|---|---|---|
| **Builder** | `claude` | Write code on a feature branch. Never merges. | Read, Write, Edit, Bash (allowlisted) |
| **Reviewer** | `codex` | Read staged diff, return structured findings. Never writes code. | Read, Grep, Glob — no Bash. Enforced on `claude` via `--allowedTools`/`--disallowedTools` (see `scripts/llm-client.sh` `invoke_claude`) and on `codex` via `--disable shell_tool -s read-only` (`invoke_codex`) — both driven by the same `ds_llm_role_is_bash_unrestricted` predicate (`scripts/platform.sh`), AGENTS.md Invariants INV-2. codex's flags were verified empirically against the installed CLI (codex-cli 0.142.5): `--disable shell_tool` removes the model's shell-execution tool entirely (distinct from `-s`/`--sandbox`, which only scopes what an *available* shell tool may touch), and `-s read-only` additionally blocks codex's `apply_patch` file-write tool, which is not gated by `--disable shell_tool` alone. File reads still work under both flags. Only the version-gated minimal codex flag set (installed codex older than `CODEX_MIN_VERSION`, or a third CLI outside claude/codex) remains genuinely unrestrictable — `walk_chain` prints a loud stderr warning on that remaining case and `clagentic-lite doctor` reports it under "reviewer tool-restriction check." Changing the shipped default away from `codex` was considered and rejected — it would defeat cross-vendor review (§"Cross-vendor is the point" below) to work around a gap in one CLI's flag surface, and that gap is now closed for the shipped default anyway. |
| **Auditor** | `codex` | LLM narration on top of deterministic security scans. Adversarial mode plays attacker. | Two distinct surfaces, not one: (1) the non-interactive `TOOL_ROLE=auditor` chain-step invocation (`gates.sh cmd_adversarial` → `llm-client.sh adversarial` → `invoke_claude`/`invoke_codex`) reads ONLY a diff on stdin (`ds_adversarial_prompt`) and never shells out to gitleaks/semgrep/osv-scanner itself — those run as separate, deterministic gates invoked directly by `gates.sh`'s own shell code (AGENTS.md §4). This surface gets the SAME Read/Grep/Glob-no-Bash restriction as the Reviewer (lr-8a28e0 adjudication) since it has no genuine execution need. (2) `plugins/clagentic-lite/agents/auditor.md`, the interactive Claude Code subagent a human/session invokes directly, DOES run `gitleaks`/`semgrep`/`osv-scanner` itself, via its own scoped Bash allowlist (`tools: Read, Glob, Grep, Bash # security-tool allowlist only`) — a structurally different mechanism (Claude Code's native subagent tool list) untouched by `--allowedTools`/`--disallowedTools`/`ds_llm_role_is_bash_unrestricted` and unaffected by this restriction. |
| **Merge Gate** | `claude` | Final approve/refuse decision over every prior gate's output. Never opens PRs, never pushes. | Read |
| **Troubleshooter** | `claude` | Read-only failure diagnosis. Receives one artifact, emits root cause + bounce target. Never writes, never dispatches. | Read, Glob, Grep, Bash (read-only) |

Plus a non-role **Summarizer** (default `claude` at cheap tier) wired into the Stop hook for per-turn session memory.

Cross-CLI is the point — a Reviewer that shares the Builder's training distribution shares its blind spots. Each role declares its own `model_chain` (primary `(cmd, tier)` + ordered fallback list) in `.env` so the *vendor* is configurable per role, not hard-coded.

Two commentary skills are installed globally via the `clagentic-lite` plugin (discovered by Claude Code from `plugins/clagentic-lite/skills/`):

- `/eng-consult` — multi-voice consulting panel (Principal + PM + Security/QA/SRE/UX, plus optional Perf/A11y/Tech Writer/Supply Chain).
- `/infosec-rt` — structured red-team threat model (Pen Tester + Insider, optional Supply Chain Analyst).

Skills are commentary only — they do not gate `/ship`. See `docs/GATES.md` § "Skills vs gates" for the boundary.

## Memory — minimal viable recall

One SQLite file per project, at `.clagentic/lite/memory.db`. One table:

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

Recall is LIKE-based keyword search over `summary` and `tags` with prompt-keyword extraction in shell. No vector search. The SQLite `LIKE` over a few thousand rows is microseconds; if a project ever produces enough history that this becomes slow, that project has outgrown clagentic-lite.

### Recall ordering — pin-first

`ORDER BY (source='manual') DESC, ts DESC`

Rows where `source='manual'` sort above all auto-generated rows regardless of timestamp. Within each group (manual and non-manual) ordering is recency-descending. The `[pin]` prefix is prepended to the display text of every manual row so the user can see which entries are pinned.

Ordering is determined solely by `source` and `ts` — user-authored facts. Computed values such as the seen-N occurrence count (below) never appear in `ORDER BY` or `WHERE`.

### Display-only seen-N annotation

When two or more rows share the same summary prefix (first 60 characters), each occurrence in recall or digest output is annotated with `(seen N)` where N is the occurrence count. This is a display-only annotation:

- It is computed in a correlated subquery and appended to the rendered text.
- It never affects ordering, filtering, or the row set returned.
- It is omitted when N = 1 (no duplicates).

The goal is to let the user recognize repeated summaries without hiding any row. Both (or all) duplicate rows appear in the output; the annotation is additive text only.

### Tag-grouped digest

`memory.sh digest` groups recent entries by the first literal tag token in the `tags` column rather than showing a flat list. Entries with no tags appear under `(untagged)`. The grouping key is the raw string the user or summarizer wrote — not computed similarity. Ordering within and across groups is recency-descending (`ORDER BY ts DESC`); the seen-N annotation follows the same display-only rule.

### Defaults

| Variable | Default | Effect |
|---|---|---|
| `CLAGENTIC_RECALL_LIMIT` | `5` | Maximum rows returned by `recall` |
| `CLAGENTIC_RECALL_MAX_CHARS` | `1500` | Hard cap on total injected text; whole rows dropped from the tail |

Non-integer values for either variable fall back silently to the documented default.

Three env vars govern the recall and retention budget (code defaults; override in `~/.config/clagentic/config` or `.clagentic/config`):

| Var | Default | Effect |
|---|---|---|
| `CLAGENTIC_RECALL_LIMIT` | `5` | Max rows returned by `recall` (the SQL `LIMIT`). |
| `CLAGENTIC_RECALL_MAX_CHARS` | `1500` | Hard cap on total injected text per recall call. Whole rows are dropped from the tail — no mid-row splits that would corrupt the ` | ` separator parse contract. |
| `CLAGENTIC_MEMORY_MAX_ROWS` | `5000` | Row cap enforced opportunistically after each `log-turn` INSERT. One `DELETE` of the oldest rows beyond the cap; no scheduler, no daemon. |

## Cross-CLI review — concrete flow

`/review` slash command routes through `scripts/gates.sh review`:

1. `git diff --cached --unified=3` → stdin to `scripts/llm-client.sh review`.
2. The wrapper walks the Reviewer's model_chain — primary, then each fallback `(cmd, tier)` — and validates output against the reviewer schema (`.findings` must be an array). Schema-invalid output advances the chain; if every step fails, it returns a degraded envelope marked `"degraded": true`.
3. Findings written to `.clagentic/lite/last-review.json`. The Reviewer prompt is fixed and inlined in `ds_review_prompt` (`scripts/llm-client.sh`): role, JSON schema, severity scale, Pre-Report Gate, Common False Positives.
4. `gates.sh cmd_review` rejects degraded envelopes (block) and counts findings at `>= CLAGENTIC_BLOCK_SEVERITY` (block on any). Pass otherwise.
5. Outcome row inserted into `.clagentic/lite/audit.db.gate_runs` (`gate=review`, `outcome=pass|block`).
6. `cmd_render_review` pretty-prints the JSON to the session.
7. Builder may revise in the same session. Each revision restarts the loop. Max 3 rounds (operator discipline; not enforced in code).

The Reviewer never edits files. The Builder never gates its own work. `/review` never calls `llm-client.sh` directly — always through `gates.sh` so the audit row, severity check, render, and persistence stay in one path.

## Adversarial layer — non-blocking, opt-in

`/review --adversarial` adds a second pass:

1. Reviewer is reprompted: "you are an attacker. What would you exploit in this diff?"
2. Builder is reprompted: "the reviewer suggests these attacks. Which are plausible? Which are overstated?"
3. Both outputs land in `.clagentic/lite/last-adversarial.md`, attached to the PR as a comment.

This is the demo flourish. It's also genuinely useful, but it's not on the blocking path.

## Change class — durability-aware thresholds (lr-4f8316)

Gates review all code as if it ships forever by default. That is usually right, but it is a category error for a one-shot migration script or a k8s Job stood up for a single task and documented for decommission — an internal-only, run-once process does not carry the same durability risk a persistent service does, and holding it to the identical bar is a dominant cause of review bounce loops that fix nothing real.

**Vocabulary — two classes, chosen to be small and defensible:**

- `durable` (default) — ships and stays. Full bar applies.
- `ephemeral` — one-shot, time-boxed, or throwaway: a migration script, a k8s Job (not a Deployment) with a documented decommission path, a change confined to `tests/`/`migrations/`, a one-shot `main()` that exits.

**Inferred from the diff, not maintained in a file.** An operator-maintained context file was explicitly rejected: it is a second source of truth that goes stale the moment the thing it describes is decommissioned. The signal — path under `tests/`/`migrations/`, k8s Job vs Deployment, a one-shot `main()` that exits, a documented decommission date — is already in the diff, and the Reviewer and Auditor already read the diff for every other finding. They need a defined vocabulary and permission to reason about it, not a new input channel.

**Builder hint, diff wins.** The Builder may declare a class as a `Change-class: <value>` trailer in the tip commit message (see `plugins/clagentic-lite/agents/builder.md`), read by `_change_class_hint` (`scripts/llm-client.sh`) and surfaced to the Reviewer/Auditor ahead of the diff. It is a claim to weigh, never the source of truth: if the diff contradicts the declared class, the diff wins and the mismatch itself becomes a finding. Degradation is clean by construction — no declaration infers from the diff; a wrong declaration is overridden and the override is visible — so there is no path where a bad label silently buys a pass, and no separate enforcement mechanism is needed.

**Threshold only, never suppression.** Class shifts the Auditor's *blocking threshold*, nothing else, and only below the security floor (see next paragraph): it never suppresses a finding and never alters reported severity. An ephemeral `high` durability-only finding is still reported as `high`, fully visible in the markdown output, the JSON sidecar, and the audit trail — it simply rides `tier: advisory` instead of `tier: blocking`, with the reason stated in the finding's prose. One honest severity scale; the model never quietly decides something is fine.

**Security floor is absolute regardless of class — mechanically enforced, not LLM self-restraint.** A live credential, a reachable injection sink, or any real exploit path with a concrete attacker-controlled trigger is `tier: blocking` in every class, ephemeral included. This is not merely a prompt instruction: `_parse_adversarial_findings` applies an unconditional parser-level clamp (see "Mechanical plumbing" below) forcing `tier: "blocking"` whenever `reachable: "yes"` and severity is high/critical, regardless of `class` or of what tier value the model wrote — the same mechanical posture as the existing reachability clamp. Ephemeral does not mean unsafe — it means unbounded resource growth in a job that runs once and dies is not a defect the same way it would be in a long-lived service, and that distinction applies only below the floor.

**Mechanical plumbing.** `_parse_adversarial_findings` (`scripts/gates.sh`) enum-validates the Auditor's stated `class` field the same way it already validates `severity`/`reachable`/`tier` (unrecognized/absent → `durable`, the class that never relaxes anything — a parser gap can only ever leave the full bar in place). It then applies TWO mechanical clamps to `tier`, in order: `reachable != "yes"` forces `advisory`; `reachable == "yes"` AND severity high/critical forces `blocking`, regardless of class — this second clamp is the security floor made real, not aspirational. `build_gate_summary` derives `resolved_change_class` (the diff's resolved class, mechanically: `ephemeral` if any finding declares it, else `durable`, else `null` on a clean pass with no findings) and `adversarial_downgraded_by_class_count` (a defense-in-depth cross-check over whatever is on disk in the sidecar — see `docs/GATES.md` for why this should always read `0` given the parser's clamp) and threads both into the merge-gate payload and the `merge-gate`/`merge-gate recheck` audit row. See `docs/GATES.md` § "Change class" for the full per-field enumeration.

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

Per-call timeout is `$CLAGENTIC_LLM_TIMEOUT_SEC` (default 180s) via `timeout` or `gtimeout` — exposed as `$DS_TIMEOUT_CMD` from `scripts/platform.sh`. If neither is available, `$DS_TIMEOUT_CMD` resolves to `ds_timeout_missing`, which fails closed at the point of use: it refuses to run the wrapped command at all and returns a distinct exit status (99) rather than running it unbounded. `clagentic-lite doctor` should be run to install a real timeout binary before any gate or LLM call is attempted on such a host.

Persistent codex sessions and persistent claude sessions were both considered and deferred. The wall-clock difference between repeated one-shots and one persistent session is small on the cadence clagentic-lite is built for (a few `/review` calls per coding session, not hundreds), and the persistent path would require either codex's experimental `app-server` or a long-running daemon — both of which violate the no-server constraint.

### The interactive-path gap, and how clagentic-router closes it

Everything above describes the **gate path**: `clagentic-lite gates review`/`ship`/etc. invoking `scripts/llm-client.sh` directly, which resolves `CLAGENTIC_<ROLE>_CMD/_TIER/_CHAIN` and dispatches to the right CLI. That path honors per-role CLI selection correctly today.

There is a second, structurally different path: a Claude Code session dispatching a subagent (Reviewer, Auditor, …) mid-conversation via its own Agent/Task tool — e.g. the user asking "review this diff" inline, or a workflow that invokes the Reviewer agent directly rather than through `clagentic-lite gates review`. On that path, `CLAGENTIC_REVIEWER_CMD=codex` is silently **ignored**: Claude Code dispatches the subagent using its own session model, because clagentic-lite has no interception point on that request at all. clagentic-lite is not Claude Code's parent process — there is nothing to intercept a request Claude Code sends directly to `api.anthropic.com`. A startup-time `export CLAGENTIC_REVIEWER_CMD=codex` reaches the gate-path shell scripts; it never reaches Claude Code's own outbound HTTP client.

[clagentic-router](https://github.com/clagentic/clagentic-router) — a separate, optionally-run local proxy, not part of clagentic-lite itself — closes this gap through the one channel that *does* reach an interactive session: Claude Code's own `settings.json` `env` block, specifically `ANTHROPIC_BASE_URL` (and the credential variable Claude Code forwards as `Authorization: Bearer <token>`, `ANTHROPIC_AUTH_TOKEN`). When `CLAGENTIC_ROUTER_URL` is set, `clagentic-lite enroll`/`update` stamps that env block into the enrolled repo's `.claude/settings.json`, so every request from that session — gate-path and interactive-path alike — is transparently proxied through the router. In the router's passthrough mode this changes nothing observable; in routed mode (`model: role:<chain-name>`, resolved by the router's own scoring/fallback policy) it gives the interactive path the same per-role CLI selection the gate path already has.

This still cannot make Claude Code itself select a non-default model for a subagent dispatch on its own — the router only controls where the request is SENT once Claude Code decides to send one. Reaching per-subagent model selection additionally requires the subagent's own frontmatter to carry a `model:` value the router recognizes as a routed reference (`role:reviewer-chain`). Whether Claude Code's subagent dispatch machinery actually honors a non-standard `model:` string in frontmatter, rather than silently falling back to the parent session's model, is UNVERIFIED from this codebase — see README.md "Optional: clagentic-router integration" § "Verifying on your machine" for the exact steps to confirm or refute this on a machine that can drive a real interactive session, and § "Agent-model injection" for how `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL` is gated separately from the (verified-safe) settings.json passthrough so that turning on the router does not implicitly gamble on this open question.

A third key, `CLAGENTIC_ROUTER_BEDROCK_MODE=1`, additionally stamps `ANTHROPIC_BEDROCK_BASE_URL`/`AWS_BEARER_TOKEN_BEDROCK` alongside the direct-API pair — required because `CLAUDE_CODE_USE_BEDROCK=1` sessions ignore `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` entirely and speak the AWS Bedrock Runtime wire protocol instead, so `CLAGENTIC_ROUTER_URL` alone is silently inert for such a session (`lr-4af4c4`). Both pairs are stamped together, not one instead of the other, since a single `settings.json` may be opened by sessions in either auth mode.

All three halves are opt-in and byte-for-byte inert when their respective config keys are unset — see `share/config.example`'s router section for the full config surface.

Because `CLAGENTIC_ROUTER_URL` redirects the entire session's traffic (and, in passthrough mode, carries the operator's real Anthropic credentials to whatever host it names), `bin/clagentic-lite` validates it before stamping or probing: a malformed value is refused outright, a well-formed non-local host is allowed but warned loudly at both stamp time and every `doctor` run. The host check is structural — RFC 3986 userinfo is stripped before the host is read, and `127.0.0.0/8` membership is a real numeric-octet-range test, not a string-prefix match — because a string-shaped check over a fully attacker-controlled URL is a bypass waiting to be found (`_host_is_local_ip4`, `bin/clagentic-lite`); any host form the check does not confidently recognize is classified non-local rather than guessed at. `.claude/settings.json` writes also go through a single atomic-write choke point (`_stamp_claude_settings`): the URL is validated before any file is opened, and the render lands via a temp-file-then-`mv`, so a refused value never truncates a previously-working settings.json. See `_validate_router_url`/`_router_url_classify`/`_stamp_claude_settings` in `bin/clagentic-lite` for the full reasoning and README's "Optional: clagentic-router integration" section for the operator-facing behavior.

### Gate-path routing (`CLAGENTIC_<ROLE>_VIA_ROUTER`)

A third, distinct integration point from the two above (both of which affect an *interactive* Claude Code session). `CLAGENTIC_<ROLE>_VIA_ROUTER=1`, scoped to exactly `reviewer`/`auditor`/`gate` (merge-gate's internal role literal), makes `scripts/llm-client.sh`'s `walk_chain` POST to `${CLAGENTIC_ROUTER_URL}/v1/messages` (`invoke_router`, model `role:<role>-chain`) instead of shelling out to `CLAGENTIC_<ROLE>_CMD` for that role's gate-path calls. Unset (either the per-role key or `CLAGENTIC_ROUTER_URL`) leaves this path byte-for-byte inert — the pre-existing direct-CLI chain runs unmodified.

**Builder is deliberately excluded.** It holds unrestricted Bash and does real multi-turn agentic tool-calling; every clagentic-router adapter currently declares `SupportsTools=false` (`lr-be9454`), so a tool-bearing routed request gets refused (422), not silently degraded. Reviewer/Auditor/Merge-Gate are already tool-restricted and single-shot on both CLI carriers (`invoke_claude`'s `--allowedTools`/`--disallowedTools`, `invoke_codex`'s `--disable shell_tool -s read-only`) and never send a `tools` field either way, so routing them carries no tool-drop risk.

**Two-layer fallback, deliberately distinguishable.** The router itself may fall back internally between backends within a `role:<role>-chain` (its own scored/health-aware policy) — that is Layer 1, entirely internal to the router process and invisible to clagentic-lite by construction; the router's own `/logs` is the source of truth for it. Layer 2 is different: the router itself is unreachable or degraded at call time, so `walk_chain` falls back to the pre-existing direct-CLI chain instead of blocking. Layer 2 is logged to `audit.db` with outcome `router-fallback` — a label distinct from the direct-CLI loop's own `pass`/`fallback`/`step-failed`/`degraded` outcomes, so a query against `audit.db` can tell "the router advanced internally" (not represented here at all) apart from "this gate bypassed the router entirely" (a `router-fallback` row) apart from "the direct-CLI chain itself also failed" (the loop's own rows, unchanged). Layer 2 also prints a loud, explicitly-labeled stderr warning naming the difference, so collapsing the two into one ambiguous "fallback" notice — the exact failure mode a router-down-for-a-week scenario would hide behind — cannot happen silently.

**No self-healing.** `walk_chain`'s router path only ever makes one `invoke_router` attempt and reports the result; it never restarts, respawns, or retries a router process from inside the gate. The gate is on the critical path of a merge — adding restart-and-retry would turn a fast, clean failure into a slow, ambiguous one, and would require handing a restricted role the ability to start processes. Health-probe-and-loudly-report is the whole contract; process supervision belongs to the router's own deployment.

**Logging parity.** Router-path calls write to the same per-repo `audit.db` `gate_runs` table as every other `llm-client.sh` call (`log_attempt`), with `details` carrying `<role>:router:role:<role>-chain` on the happy path — distinguishable from a direct-CLI row's `<role>:<cli>:<tier>` shape by the literal `router` CLI field, so the existing audit trail (and `clagentic-lite show gates`) stays the complete picture for both paths without a second log destination.

`clagentic-lite doctor` warns when a role has both `CLAGENTIC_<ROLE>_VIA_ROUTER=1` and a `CLAGENTIC_<ROLE>_CHAIN`/`_TIER` configured — those become no-ops for the router path (only consulted by the Layer 2 fallback), so leaving them set is not wrong but is worth surfacing rather than silently ignoring.

## Portability strategy

`scripts/platform.sh` is sourced by every script and exports:

- `DS_SED_INPLACE` — `-i` on GNU sed, `-i ''` on BSD sed
- `DS_DATE_ISO` — `date -Iseconds` (GNU) or `date -u +%Y-%m-%dT%H:%M:%SZ` (BSD)
- `DS_STAT_MTIME` — `stat -c %Y` (GNU) or `stat -f %m` (BSD)
- `DS_OS` — `linux` (incl. WSL) or `darwin`

Hooks call only POSIX sh + the shims. No `bash-4` features (associative arrays, `${var^^}`, etc.). Verified by `sh -n` syntax check + `scripts/smoke.sh --quick` local run; not gated by hosted CI.

## What gets logged

Every gate run inserts one row into `.clagentic/lite/audit.db`:

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

The tool is cloned once to `$CLAGENTIC_LITE_HOME` (default `~/.clagentic/lite`). The tool's own repo is never the thing under gates by default — `clagentic-lite enroll --self` is the dogfood escape hatch.

Per-repo footprint is `.clagentic/lite/{audit.db,memory.db}`, thin shims in `.git/hooks/` that call back to `$CLAGENTIC_LITE_HOME/scripts/`, and a `.claude/` directory containing a generated `settings.json` (with absolute hook paths pointing to `$CLAGENTIC_LITE_HOME/.claude/hooks/`) plus symlinks to `$CLAGENTIC_LITE_HOME/.claude/{commands,agents}`. The `.claude/` directory is added to the project's `.gitignore` automatically. Update the tool once; every enrolled repo picks up the new version automatically because the hook scripts and the symlinked commands/agents resolve back to `$CLAGENTIC_LITE_HOME`.

`bin/clagentic-lite` is the CLI entry point. It dispatches `init` (setup + symlink), `enroll` (hook stamp + DB init + register), `unenroll` (remove clagentic-owned hooks + deregister), `list` (enrolled status table), `doctor` (diagnostics punch list), and `update` (ff-only pull + re-stamp).

Project root isolation: `gates.sh`, `memory.sh`, and `llm-client.sh` resolve the project root via `CLAGENTIC_PROJECT_ROOT` env var when set, falling back to `git rev-parse --show-toplevel` of cwd. Hook shims run from inside the enrolled repo's working tree, so git show-toplevel finds the enrolled project automatically without the shim needing to know the path at stamp time.

### Trust boundary: global config vs. per-repo config

Two config files feed into every clagentic-lite process: `~/.config/clagentic/config` (global, written by `init`, lives outside any repo) and `<repo>/.clagentic/config` (optional, sparse, lives inside the repo). Both are loaded the same way — sourced into the shell, each assignment auto-exported — which means loading either one *executes* it: it is a shell file, not a passive key-value format.

That distinction matters because the two files have very different provenance. The global config is something the operator wrote, on their own machine, before any of this runs. The per-repo config is *repo content* — it travels with `git clone` like everything else in the tree. A repo you have merely cloned, never enrolled, never reviewed, can carry a `.clagentic/config` an attacker planted. If the CLI sourced that file the moment it noticed cwd was inside a git repo, running something as innocuous as `clagentic-lite doctor` right after cloning an unfamiliar repo — out of curiosity, before deciding whether to trust it at all — would execute arbitrary shell on your machine.

The fix is to treat the two files differently rather than loading them through one unconditional call:

- **`ds_load_global_env`** (`scripts/platform.sh`) loads only the global config. Safe to call unconditionally, for every subcommand, because it never touches repo content.
- **`ds_load_repo_env`** (`scripts/platform.sh`) loads only the per-repo config (plus a legacy `.env` file, same idea). This one requires a trust decision first.
- **`ds_load_env`** composes both, in order, and remains what `gates.sh`, `llm-client.sh`, `memory.sh`, `smoke.sh`, and the Claude Code hook shims call — unconditionally, exactly as before this split existed. That is correct for them: every one of those only ever runs against a repo you have already deliberately enrolled (a hook fires from inside your own working tree; you invoked the script yourself while working in that repo). The precondition — "this repo is already trusted" — genuinely holds before any of them run.

`bin/clagentic-lite`'s own top-level dispatch is the one place that precondition does *not* automatically hold, because it is the thing deciding, moment to moment, which repo (if any) to trust. So it calls `ds_load_global_env` unconditionally, then a separate helper that loads the repo-local layer *only* when the repo's canonical path is already listed in `~/.local/state/clagentic/registry` — the file `enroll` appends to on success. Registry membership is the trust signal specifically because it lives outside the repo: nothing in a hostile clone can add itself to a file on the operator's machine that the operator never asked to write.

`enroll` and `init` are the two exceptions, and each is a real design decision, not an oversight:

- **`init`** has no per-repo context at all — it configures the tool installation, not a project.
- **`enroll` is how a repo becomes trusted.** It cannot require prior registry membership as a precondition for reading the repo it is in the middle of enrolling — that would make it impossible to ever enroll a first repo. But it must also not execute that repo's own config as the price of enrolling it; doing so would just move the same pre-trust execution problem one subcommand over. So `enroll` skips the repo-local layer entirely. The practical consequence: a repo-local override is not honored on the very first `enroll` call for a given repo — only from the next invocation onward (`doctor`, `update`, a re-`enroll`), once registry membership exists. The global config is unaffected and still applies at enroll time.

This same reasoning extends one layer down: `enroll` itself shells out to `gates.sh init` and `memory.sh init` to create each repo's local databases, before the registry entry is written. Those two scripts skip the repo-local config load specifically for their `init` subcommand (and only `init` — every other subcommand they support keeps the unconditional combined load, since those are only ever reached post-enrollment) for the identical reason: `init` in both scripts needs nothing from a config file, global or per-repo, so there is no cost to deferring the repo-local layer past that one call.

If you find yourself wanting to simplify this back into a single unconditional config load anywhere in the CLI's own dispatch path (as opposed to the hook-invoked runtime scripts, where it is correct): don't. That collapses the trust boundary this section exists to describe, and turns a passing `doctor`/`list`/`update` invocation against an unenrolled repo back into an arbitrary-code-execution surface.

## Non-goals

- Multi-agent orchestration (no director, no relay).
- Multi-repo state (each enrolled repo has independent DBs; there is no cross-repo index).
- A web UI.
- A plugin marketplace.
- Anything that requires running our own server.

These are excellent things to build. They are not this project.

## When you've outgrown lite

The signals that you have crossed the threshold:

- You want a server or a daemon — a persistent process that runs outside your editor session.
- You want multi-repo memory — a single recall surface that spans more than one enrolled project.
- You want ranked or embedding-based retrieval — surfacing rows by relevance scores or vector similarity rather than by your own keywords, recency, or explicit pins.
- You want multi-agent orchestration — a director that dispatches work to specialized agents, tracks inter-agent state, and retries on failure.
- You want memory that learns, decays, and promotes itself automatically — a system that decides what is important without your explicit marking.

If you are hitting these limits, the tool did its job. The right next step is a heavier harness that explicitly provides those capabilities — a persistent memory store with a real query engine, a multi-agent director, or an embedding-based retrieval layer.

No `eject` subcommand and no schema bridge are provided, and none are planned. The `.clagentic/lite/memory.db` file is a plain SQLite database. A user who outgrows lite has all their data already — open it with `sqlite3`, export with `.dump`, query it directly, or run `clagentic-lite export` to generate a self-contained HTML report. Building a schema bridge would couple lite to whichever platform's schema happened to be current at build time; that coupling is a thesis violation through the back door.

## Open design questions

- **Summarizer cost control:** spark-tier model is fine for one-paragraph summaries, but a chatty session could rack up calls. Add a debounce (`Stop` fires often) — only summarize after N seconds of quiet. Implementation deferred to weekend 2.
- **Adversarial loop budget:** how many rounds before declaring "the model isn't finding new issues"? Currently capped at 1. Revisit after first real use.
- **Cross-platform sqlite3:** macOS ships an old SQLite. Document `brew install sqlite` as a soft requirement; test on the macOS-default version anyway.
