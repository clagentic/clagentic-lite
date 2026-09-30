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
| 3 | **Cross-CLI review** | `clagentic-lite gates review` (or subagent), optional pre-push | Builder's staged diff piped to Reviewer; schema-validated JSON findings | findings ≥ `BLOCK_SEVERITY` block `gates ship`; degraded envelopes also block |
| 4 | **Local security scan** | git `pre-commit` (secrets) and `pre-push` (deps, SAST); `gates ship` also runs an opt-in internal-bleed pattern scan | gitleaks; osv-scanner; semgrep --error --severity=ERROR; `grep` against a pattern file you supply. Missing tool fails closed unless `CLAGENTIC_ALLOW_MISSING_*=1` | yes |
| 5 | **Adversarial pass** | `clagentic-lite gates adversarial` (or subagent) | Auditor role plays attacker on the diff; each finding is tagged `reachable: yes/no`, `tier: blocking/advisory`, and `class: durable/ephemeral` | no on its own (commentary); `tier: blocking` findings are what Gate 6 can refuse on |
| 6 | **Merge Gate** | `clagentic-lite gates ship` (or subagent) | LLM reads every prior gate's structured output and returns `{decision, reason}` JSON | yes by default (`CLAGENTIC_MERGE_GATE_BLOCKING=1`); only `tier: blocking` adversarial findings are refusal-eligible, `tier: advisory` findings are never gating |
| 7 | **Session summarize** | `Stop` | async, debounced: Summarizer reads transcript → one-line summary → SQLite | no (best-effort) |

## The five roles

| Role | CLI (default) | Job | Tools allowed |
|---|---|---|---|
| **Builder** | `claude` | Write code on a feature branch. Never merges. | Read, Write, Edit, Bash (allowlisted) |
| **Reviewer** | `codex` | Read staged diff, return structured findings. Never writes code. | Read, Grep, Glob — no Bash. Enforced on `claude` via `--allowedTools`/`--disallowedTools` (see `scripts/llm-client.sh` `invoke_claude`) and on `codex` via `--disable shell_tool -s read-only` (`invoke_codex`) — both driven by the same `ds_llm_role_is_bash_unrestricted` predicate (`scripts/platform.sh`), AGENTS.md Invariants INV-2. codex's flags were verified empirically against the installed CLI (codex-cli 0.142.5): `--disable shell_tool` removes the model's shell-execution tool entirely (distinct from `-s`/`--sandbox`, which only scopes what an *available* shell tool may touch), and `-s read-only` additionally blocks codex's `apply_patch` file-write tool, which is not gated by `--disable shell_tool` alone. File reads still work under both flags. Only the version-gated minimal codex flag set (installed codex older than `CODEX_MIN_VERSION`, or a third CLI outside claude/codex) remains genuinely unrestrictable — `walk_chain` prints a loud stderr warning on that remaining case and `clagentic-lite doctor` reports it under "reviewer tool-restriction check." Changing the shipped default away from `codex` was considered and rejected — it would defeat cross-vendor review (see the cross-CLI paragraph after this table) to work around a gap in one CLI's flag surface, and that gap is now closed for the shipped default anyway. |
| **Auditor** | `codex` | LLM narration on top of deterministic security scans. Adversarial mode plays attacker. | Two distinct surfaces, not one: (1) the non-interactive `TOOL_ROLE=auditor` chain-step invocation (`gates.sh cmd_adversarial` → `llm-client.sh adversarial` → `invoke_claude`/`invoke_codex`) reads ONLY a diff on stdin (`ds_adversarial_prompt`) and never shells out to gitleaks/semgrep/osv-scanner itself — those run as separate, deterministic gates invoked directly by `gates.sh`'s own shell code (AGENTS.md §4). This surface gets the SAME Read/Grep/Glob-no-Bash restriction as the Reviewer (lr-8a28e0 adjudication) since it has no genuine execution need. (2) `plugins/clagentic-lite/agents/auditor.md`, the interactive Claude Code subagent a human/session invokes directly, DOES run `gitleaks`/`semgrep`/`osv-scanner` itself, via its own scoped Bash allowlist (`tools: Read, Glob, Grep, Bash # security-tool allowlist only`) — a structurally different mechanism (Claude Code's native subagent tool list) untouched by `--allowedTools`/`--disallowedTools`/`ds_llm_role_is_bash_unrestricted` and unaffected by this restriction. |
| **Merge Gate** | `claude` | Final approve/refuse decision over every prior gate's output. Never opens PRs, never pushes. | Read, Bash — unrestricted. `TOOL_ROLE=gate` is one of the three roles `ds_llm_role_is_bash_unrestricted` (`scripts/platform.sh`) returns true for, so `invoke_claude`/`invoke_codex` skip the `--allowedTools`/`--disallowedTools`/`--disable shell_tool -s read-only` restriction entirely on this role's non-interactive chain-step invocation (`gates.sh cmd_merge_gate` → `walk_chain` → `invoke_claude`/`invoke_codex`) — the gate reads a real diff and prior gates' output and needs to inspect the tree to do that job (`invoke_claude`'s own comment states explicitly that the merge-gate must not lose Bash). This is exactly why `_llm_role_routable` (`scripts/llm-client.sh`) excludes gate from routing through clagentic-router (lr-250d9d): routing would silently trade this unrestricted Bash for a one-shot, tool-free router call. |
| **Troubleshooter** | `claude` | Read-only failure diagnosis. Receives one artifact, emits root cause + bounce target. Never writes, never dispatches. | Read, Glob, Grep, Bash (read-only) |

Plus a non-role **Summarizer** (default `claude` at cheap tier) wired into the Stop hook for per-turn session memory.

Cross-CLI is the point — a Reviewer that shares the Builder's training distribution shares its blind spots. Each role declares its own `model_chain` (primary `(cmd, tier)` + ordered fallback list) in `~/.config/clagentic/lite/config` (or a repo's `.clagentic/config`) so the *vendor* is configurable per role, not hard-coded.

**Two model paths.** That chain configuration drives the gate/CLI path only (`llm-client.sh`: `gates review|ship`, git hooks, Claude Code lifecycle hooks). A role dispatched from Claude Code through its Agent tool is a second path, on which the model is the session model unless the rendered agent file carries a `model:` line. `CLAGENTIC_<ROLE>_AGENT_MODEL` (all five roles, Claude Code only) or router injection (reviewer/auditor/merge-gate) sets that line; `CLAGENTIC_<ROLE>_CMD`/`_TIER`/`_CHAIN` never does. The two paths are deliberately configured by different keys: reusing `_TIER` at render time would give one key two meanings and silently change behavior for existing installs, and Claude Code's own subagent-model environment override pins every subagent at once with no per-role control. See `docs/LLM-USAGE.md` § "Two model paths" for the table.

Two commentary skills are installed globally via the `clagentic-lite` plugin (discovered by Claude Code from `plugins/clagentic-lite/skills/`):

- `/eng-consult` — multi-voice consulting panel (Principal + PM + Security/QA/SRE/UX, plus optional Perf/A11y/Tech Writer/Supply Chain).
- `/infosec-rt` — structured red-team threat model (Pen Tester + Insider, optional Supply Chain Analyst).

Skills are commentary only — they do not gate `gates ship`. See `docs/GATES.md` § "Skills vs gates" for the boundary.

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

Recall is keyword search over `summary` and `tags` with prompt-keyword extraction in shell. When SQLite was built with FTS5, candidate rows are filtered with an FTS5 `MATCH`; otherwise, or with `CLAGENTIC_DISABLE_FTS=1`, it falls back to `LIKE`. Either way the filter only decides which rows are candidates; ordering and display are unchanged. No vector search. If a project ever produces enough history that this becomes slow, that project has outgrown clagentic-lite.

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

Three variables govern the recall and retention budget (code defaults; override in `~/.config/clagentic/lite/config` or `.clagentic/config`). Non-integer values fall back to the documented default. For `CLAGENTIC_MEMORY_MAX_ROWS` a zero falls back too (a cap of 0 would prune every row on each write), and both cases print a WARN; `CLAGENTIC_RECALL_LIMIT=0` returns no rows and `CLAGENTIC_RECALL_MAX_CHARS=0` injects no text.

| Var | Default | Effect |
|---|---|---|
| `CLAGENTIC_RECALL_LIMIT` | `5` | Max rows returned by `recall` (the SQL `LIMIT`). |
| `CLAGENTIC_RECALL_MAX_CHARS` | `1500` | Hard cap on total injected text per recall call. Whole rows are dropped from the tail — no mid-row splits that would corrupt the ` | ` separator parse contract. |
| `CLAGENTIC_MEMORY_MAX_ROWS` | `5000` | Row cap enforced opportunistically after each `log-turn` INSERT. One `DELETE` of the oldest rows beyond the cap; no scheduler, no daemon. |

## Cross-CLI review — concrete flow

`clagentic-lite gates review` (or the subagent) routes through `scripts/gates.sh review`:

1. `git diff --cached --unified=3` → stdin to `scripts/llm-client.sh review`.
2. The wrapper walks the Reviewer's model_chain — primary, then each fallback `(cmd, tier)` — and validates output against the reviewer schema (`.findings` must be an array). Schema-invalid output advances the chain; if every step fails, it returns a degraded envelope marked `"degraded": true`.
3. Findings written to `.clagentic/lite/last-review.json`. The Reviewer prompt is fixed and inlined in `ds_review_prompt` (`scripts/llm-client.sh`): role, JSON schema, severity scale, Pre-Report Gate, Common False Positives.
4. `gates.sh cmd_review` rejects degraded envelopes (block) and counts findings at `>= CLAGENTIC_BLOCK_SEVERITY` (block on any). Pass otherwise.
5. Outcome row inserted into `.clagentic/lite/audit.db.gate_runs` (`gate=review`, `outcome=pass|block`).
6. `cmd_render_review` pretty-prints the JSON to the session.
7. Builder may revise in the same session. Each revision restarts the loop. Max 3 rounds (operator discipline; not enforced in code).

The Reviewer never edits files. The Builder never gates its own work. `gates review` never calls `llm-client.sh` directly — always through `gates.sh` so the audit row, severity check, render, and persistence stay in one path.

## Adversarial layer — non-blocking, opt-in

`clagentic-lite gates adversarial` (or the subagent) adds a second pass:

1. The Auditor role is prompted, on the same diff the review gate reads: "you are an attacker. What would you exploit in this diff?"
2. Its output lands in `.clagentic/lite/last-adversarial.md`, and each `[FINDING]` is parsed into `.clagentic/lite/last-adversarial-findings.json` with a `reachable`, `tier` and `class` field (see `docs/GATES.md` Gate 5).
3. The Merge Gate reads that sidecar; only `tier: blocking` findings can make it refuse. There is no Builder rebuttal step.

The pass itself is not on the blocking path. Loop budget: one round.

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
# build        stdin = instruction; stdout = builder output (diff or prose)
# review       stdin = diff;       stdout = JSON findings (reviewer.md schema)
# summarize    stdin = transcript; stdout = one-line summary (<=200 chars)
# adversarial  stdin = diff;       stdout = markdown attack scenarios
# merge-gate   stdin = gate summary JSON; stdout = {decision,reason} JSON
```

Implementation is **one-shot per call**. Each subcommand resolves the configured chain for its role (`CLAGENTIC_<ROLE>_CMD/_TIER/_CHAIN`), tries each `(cmd, tier)` entry in order, validates the output's schema, and falls through on failure to a degraded envelope marked `"degraded": true`. The gate orchestrator (`scripts/gates.sh`) detects degraded envelopes and blocks rather than treats them as clean reviews.

Per-call timeout is `$CLAGENTIC_LLM_TIMEOUT_SEC` (default 180s) via `timeout` or `gtimeout` — exposed as `$DS_TIMEOUT_CMD` from `scripts/platform.sh`. If neither is available, `$DS_TIMEOUT_CMD` resolves to `ds_timeout_missing`, which fails closed at the point of use: it refuses to run the wrapped command at all and returns a distinct exit status (99) rather than running it unbounded. `clagentic-lite init`/`update` warn about the missing binary in their prerequisite sweep; install one before any gate or LLM call is attempted on such a host.

Persistent codex sessions and persistent claude sessions were both considered and deferred. The wall-clock difference between repeated one-shots and one persistent session is small on the cadence clagentic-lite is built for (a few `gates review` calls per coding session, not hundreds), and the persistent path would require either codex's experimental `app-server` or a long-running daemon — both of which violate the no-server constraint.

### The interactive-path gap, and how clagentic-router closes it

This section and "Gate-path routing" below are the architecture-level
account of clagentic-router's three integration points — why each exists,
how they compose. For the operator-facing account (what to set, what each
opt-in turns on/off, verification status, setup walkthroughs), see
`docs/ROUTER.md`; the two documents are companions, not duplicates.

Everything above describes the **gate path**: `clagentic-lite gates review`/`ship`/etc. invoking `scripts/llm-client.sh` directly, which resolves `CLAGENTIC_<ROLE>_CMD/_TIER/_CHAIN` and dispatches to the right CLI. That path honors per-role CLI selection correctly today.

There is a second, structurally different path (the "Agent path"; see "Two model paths" above): a Claude Code session dispatching a subagent (Reviewer, Auditor, …) mid-conversation via its own Agent/Task tool — e.g. the user asking "review this diff" inline, or a workflow that invokes the Reviewer agent directly rather than through `clagentic-lite gates review`. On that path, `CLAGENTIC_REVIEWER_CMD=codex` is silently **ignored**: Claude Code dispatches the subagent using its own session model unless the agent file names one, because clagentic-lite has no interception point on that request at all. Pinning a plain Claude model for that dispatch needs no router: `CLAGENTIC_<ROLE>_AGENT_MODEL` writes a `model:` line into the rendered agent file. The router is for the different goal of sending a dispatched agent to a non-default backend or chain. clagentic-lite is not Claude Code's parent process — there is nothing to intercept a request Claude Code sends directly to `api.anthropic.com`. A startup-time `export CLAGENTIC_REVIEWER_CMD=codex` reaches the gate-path shell scripts; it never reaches Claude Code's own outbound HTTP client.

[clagentic-router](https://github.com/clagentic/clagentic-router) — a separate, optionally-run local proxy, not part of clagentic-lite itself — closes this gap through the one channel that *does* reach an interactive session: Claude Code's own `settings.json` `env` block, specifically `ANTHROPIC_BASE_URL` (and the credential variable Claude Code forwards as `Authorization: Bearer <token>`, `ANTHROPIC_AUTH_TOKEN`). When `CLAGENTIC_ROUTER_URL` is set, `clagentic-lite enroll`/`update` stamps that env block into the enrolled repo's `.claude/settings.json`, so every request from that session — gate-path and interactive-path alike — is transparently proxied through the router. In the router's passthrough mode this changes nothing observable; in routed mode (`model: role:<chain-name>`, resolved by the router's own scoring/fallback policy) it gives the interactive path the same per-role CLI selection the gate path already has.

This still cannot make Claude Code itself select a non-default model for a subagent dispatch on its own — the router only controls where the request is SENT once Claude Code decides to send one. Reaching per-subagent model selection additionally requires the subagent's own frontmatter to carry a `model:` value the router recognizes as a routed reference (`role:reviewer-chain`). Whether Claude Code's subagent dispatch machinery actually honors a non-standard `model:` string in frontmatter, rather than silently falling back to the parent session's model, is UNVERIFIED from this codebase — see `docs/ROUTER.md` § 2 ("agent-model injection (UNVERIFIED)"), "Verifying on your machine", for the exact steps to confirm or refute this on a machine that can drive a real interactive session, and for how `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL` is gated separately from the (verified-safe) settings.json passthrough so that turning on the router does not implicitly gamble on this open question.

A third key, `CLAGENTIC_ROUTER_BEDROCK_MODE=1`, additionally stamps `ANTHROPIC_BEDROCK_BASE_URL`/`AWS_BEARER_TOKEN_BEDROCK` alongside the direct-API pair — required because `CLAUDE_CODE_USE_BEDROCK=1` sessions ignore `ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` entirely and speak the AWS Bedrock Runtime wire protocol instead, so `CLAGENTIC_ROUTER_URL` alone is silently inert for such a session (`lr-4af4c4`). Both pairs are stamped together, not one instead of the other, since a single `settings.json` may be opened by sessions in either auth mode.

All three halves are opt-in and byte-for-byte inert when their respective config keys are unset — see `share/config.example`'s router section for the full config surface.

Because `CLAGENTIC_ROUTER_URL` redirects the entire session's traffic (and, in passthrough mode, carries the operator's real Anthropic credentials to whatever host it names), it is validated by EVERY consumer that builds a network target from it — `bin/clagentic-lite` (stamping/probing) and `scripts/llm-client.sh`'s `invoke_router` (the gate-path POST, lr-02f048) alike — before stamping, probing, or connecting: a malformed value is refused outright, a well-formed non-local host is allowed but warned loudly. The classifier itself (`ds_router_url_classify`, `scripts/platform.sh`) is the ONE shared implementation both files source; there is no second copy to drift. The host check is structural — RFC 3986 userinfo is stripped before the host is read, and `127.0.0.0/8` membership is a real numeric-octet-range test, not a string-prefix match — because a string-shaped check over a fully attacker-controlled URL is a bypass waiting to be found (`ds_host_is_local_ip4`, `scripts/platform.sh`); any host form the check does not confidently recognize is classified non-local rather than guessed at. `.claude/settings.json` writes also go through a single atomic-write choke point (`_stamp_claude_settings`): the URL is validated before any file is opened, and the render lands via a temp-file-then-`mv`, so a refused value never truncates a previously-working settings.json. `invoke_router` validates before ever placing the bearer token in a curl argument or POSTing the prompt+diff — a malformed/nonlocal URL is refused as a distinct, loudly-labeled `router-refused` outcome, never silently folded into the "router unreachable" Layer-2 fallback path (see "Gate-path routing" § "Layer 0 — URL validation" below). See `_validate_router_url`/`ds_router_url_classify`/`_stamp_claude_settings` (`bin/clagentic-lite`, `scripts/platform.sh`) for the full reasoning and README's "Optional: clagentic-router integration" section for the operator-facing behavior.

### Gate-path routing (`CLAGENTIC_<ROLE>_VIA_ROUTER`)

A third, distinct integration point from the two above (both of which affect an *interactive* Claude Code session). `CLAGENTIC_<ROLE>_VIA_ROUTER=1`, scoped to exactly `reviewer`/`auditor`, makes `scripts/llm-client.sh`'s `walk_chain` POST to `${CLAGENTIC_ROUTER_URL}/v1/messages` (`invoke_router`, model `role:<role>-chain`) instead of shelling out to `CLAGENTIC_<ROLE>_CMD` for that role's gate-path calls. Unset (either the per-role key or `CLAGENTIC_ROUTER_URL`) leaves this path byte-for-byte inert — the pre-existing direct-CLI chain runs unmodified.

**Builder and Merge-Gate are both deliberately excluded, for the same reason (`lr-250d9d` for Merge-Gate, correcting `lr-02f048`).** Both hold unrestricted Bash and do real multi-turn agentic tool-calling on the direct-CLI path. The router refuses a tool-bearing routed request (422 `no_tool_capable_backend`) unless the chain resolves to a tool-capable backend, and its CLI-subprocess adapters (`claude_cli`, `codex_cli`, `codex_subagent`, `gemini_cli`) declare no tool support, so a chain built from them cannot carry either role. That is a defense Builder/Merge-Gate never reach here, since `_llm_role_routable` never routes them in the first place, and clagentic-lite does not define or verify a tool-capable chain for them. `lr-02f048` originally included Merge-Gate in the routable set on the claim that all three roles were "already tool-restricted and single-shot" on both CLI carriers — true for Reviewer/Auditor, false for Merge-Gate: `ds_llm_role_is_bash_unrestricted` (`scripts/platform.sh`) returns `true` for `gate`, meaning its direct-CLI invocation holds full, unrestricted Bash (the same predicate `invoke_claude` consults to skip the `--allowedTools`/`--disallowedTools` restriction for it). Routing it would have silently converted a Bash-capable, multi-turn merge-authorization step into a one-shot, tool-free text completion, logged as an ordinary `pass` row indistinguishable from a full-capability run — `invoke_router` never sends a `tools` key on the wire (see "Repo-scoping" below), so nothing in the response would have surfaced the loss either. A loud-but-still-routable fix (a stderr warning, a distinct audit outcome on the capability loss) was considered and rejected: it would tell an operator, after the fact, that a merge had already been authorized by a gate that could not run Bash — on the one gate whose entire job is the final authorization before code lands on the default branch. Fail-closed wins here for the identical reason it already won for Builder: exclusion from the routable set, not a label on the degradation. Reviewer/Auditor are already tool-restricted and single-shot on both CLI carriers (`invoke_claude`'s `--allowedTools`/`--disallowedTools`, `invoke_codex`'s `--disable shell_tool -s read-only`) and never send a `tools` field either way, so routing them carries no tool-drop risk.

**Repo-scoping via `working_dir` (lr-4a6268).** `invoke_router`'s request body carries `working_dir: <REPO_ROOT>` (this file's own module-level `REPO_ROOT`, the same value every other repo-scoped read in `scripts/llm-client.sh` uses) — the consumer-side fix for a measured silent quality regression where a routed Reviewer/Auditor call reached the model with the diff text only and no filesystem access to the repo under review (upstream cause: clagentic-router's `codex_cli` adapter never set the spawned subprocess's cwd, fixed as `lr-009423`). A router that rejects `working_dir` (4xx, per its own fail-loud `ResolveWorkingDir` validator) is surfaced with a distinctly labeled diagnostic, never silently folded into a generic non-200 hint — but remains non-blocking for the gate, falling through to Layer 2 like any other `invoke_router` failure. Routed mode is still one-shot text-in/text-out with no tool loop, so this is not equivalent to the direct-CLI path's real multi-turn filesystem access. See `docs/ROUTER.md` § "Repo-scoping via `working_dir`" for the full operator-facing account, including the measured before/after impact.

**Layer 0 — URL validation, never conflated with Layer 2 unreachability.** Before `invoke_router` ever opens a connection, it runs `CLAGENTIC_ROUTER_URL` through `ds_router_url_classify` (`scripts/platform.sh`, lr-02f048) — the same classifier `bin/clagentic-lite` uses at stamp/probe time. A **malformed** URL is refused outright: no curl invocation is made at all, so the bearer token is never even placed in a curl argument. A **nonlocal** URL (well-formed, but not localhost/127.0.0.0/8/::1) is also refused for the gate path specifically — this is a deliberate, stricter posture than the interactive-session stamp (which allows nonlocal with a warning, since an operator running clagentic-router on another LAN box is a legitimate interactive setup they explicitly configured into `settings.json`). The gate path has no equivalent human-in-the-loop moment: `walk_chain` runs unattended inside a merge gate, so a nonlocal target here is treated as indistinguishable from misconfiguration-or-attack rather than a judgment call to warn-and-proceed on. Both cases write a distinct `router-refused` outcome to `audit.db` and print a loud stderr line naming the refusal reason (malformed vs. nonlocal) — **never** the `router-fallback` label Layer 2 uses, because "this URL looks like exfiltration, refusing to send credentials" and "the router process is down" are different conditions an operator must be able to tell apart from the log alone. Refusal at Layer 0 is non-blocking for the gate itself: exactly like a Layer-2 event, it falls through to the pre-existing direct-CLI chain rather than failing the whole gate — a malformed/misconfigured router integration must not be able to block every merge, but it also must never be silently indistinguishable from "router happened to be offline right now."

**Layer 1/Layer 2 fallback, deliberately distinguishable.** The router itself may fall back internally between backends within a `role:<role>-chain` (its own scored/health-aware policy) — that is Layer 1, entirely internal to the router process and invisible to clagentic-lite by construction; the router's own `/logs` is the source of truth for it. Layer 2 is different: the router itself is unreachable or degraded at call time, so `walk_chain` falls back to the pre-existing direct-CLI chain instead of blocking. Layer 2 is logged to `audit.db` with outcome `router-fallback` — a label distinct from the direct-CLI loop's own `pass`/`fallback`/`step-failed`/`degraded` outcomes, so a query against `audit.db` can tell "the router advanced internally" (not represented here at all) apart from "this gate bypassed the router entirely" (a `router-fallback` row) apart from "the direct-CLI chain itself also failed" (the loop's own rows, unchanged). Layer 2 also prints a loud, explicitly-labeled stderr warning naming the difference, so collapsing the two into one ambiguous "fallback" notice — the exact failure mode a router-down-for-a-week scenario would hide behind — cannot happen silently.

**No self-healing.** `walk_chain`'s router path only ever makes one `invoke_router` attempt and reports the result; it never restarts, respawns, or retries a router process from inside the gate. The gate is on the critical path of a merge — adding restart-and-retry would turn a fast, clean failure into a slow, ambiguous one, and would require handing a restricted role the ability to start processes. Health-probe-and-loudly-report is the whole contract; process supervision belongs to the router's own deployment.

**Logging parity.** Router-path calls write to the same per-repo `audit.db` `gate_runs` table as every other `llm-client.sh` call (`log_attempt`), with `details` carrying `<role>:router:role:<role>-chain` on the happy path — distinguishable from a direct-CLI row's `<role>:<cli>:<tier>` shape by the literal `router` CLI field, so the existing audit trail (and `clagentic-lite show gates`) stays the complete picture for both paths without a second log destination.

`clagentic-lite doctor` warns when a role has both `CLAGENTIC_<ROLE>_VIA_ROUTER=1` and a `CLAGENTIC_<ROLE>_CHAIN`/`_TIER` configured — those become no-ops for the router path (only consulted by the Layer 2 fallback), so leaving them set is not wrong but is worth surfacing rather than silently ignoring.

## Portability strategy

`scripts/platform.sh` is sourced by every script and exports:

- `DS_SED_INPLACE` — `-i` on GNU sed, `-i ''` on BSD sed
- `ds_date_iso` — `date -Iseconds` (GNU) or `date -u +%Y-%m-%dT%H:%M:%SZ` (BSD)
- `ds_stat_mtime` — `stat -c %Y` (GNU) or `stat -f %m` (BSD)
- `DS_OS` — `linux`, `darwin` or `unknown`; `DS_WSL` — `1` under WSL
- `$DS_TIMEOUT_CMD` — `timeout`/`gtimeout`, failing closed when neither exists (see `docs/PORTABILITY.md`)

Hooks call only POSIX sh + the shims. No `bash-4` features (associative arrays, `${var^^}`, etc.). Verified by `sh -n` syntax check + `scripts/smoke.sh --quick` local run; not gated by hosted CI.

## What gets logged

Every gate run inserts one row into `.clagentic/lite/audit.db`:

```sql
CREATE TABLE gate_runs (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  gate TEXT NOT NULL,        -- e.g. 'secrets' | 'sast' | 'deps' | 'bleed' | 'review' | 'adversarial' | 'merge-gate' | 'bash-guard' | 'write-guard' | 'llm-call' (open-ended)
  outcome TEXT NOT NULL,     -- e.g. 'pass' | 'block' | 'warn' | 'skip' | 'degraded' (open-ended)
  details TEXT,              -- free text, not JSON
  session_id TEXT,
  branch TEXT
);
```

`scripts/gates.sh digest` produces a one-screen daily summary. This is the "show your work" surface for a code review or an InfoSec conversation.

## Install shape: clone once, enroll per repo

The tool is cloned once to `$CLAGENTIC_LITE_HOME` (default `~/.clagentic/lite`). The tool's own repo is never the thing under gates by default — `clagentic-lite enroll --self` is the dogfood escape hatch.

Per-repo footprint is `.clagentic/lite/{audit.db,memory.db}`, thin shims in `.git/hooks/` that call back to `$CLAGENTIC_LITE_HOME/scripts/`, and a `.claude/` directory containing a generated `settings.json` (with absolute hook paths pointing to `$CLAGENTIC_LITE_HOME/.claude/hooks/`) plus a symlink to `$CLAGENTIC_LITE_HOME/.claude/commands`. The `.claude/` directory is added to the project's `.gitignore` automatically. The role agents and the two skills are not copied into repos: they are installed once, globally, as the `clagentic-lite` Claude Code plugin. Update the tool once; every enrolled repo picks up the new version automatically because the hook scripts and the symlinked commands resolve back to `$CLAGENTIC_LITE_HOME`, and the plugin is re-rendered by `update`.

`bin/clagentic-lite` is the CLI entry point. It dispatches `init` (setup, hook materialization, symlink, plugin install), `enroll` (hook stamp + DB init + register), `unenroll` (remove clagentic-owned hooks + deregister), `list` (enrolled status table), `doctor` (diagnostics), `rotate` (re-stamp router tokens), `update` (ff-only pull, prereqs, re-stamp, plugin re-render; `--restamp`, `--refresh-config`), `recall`/`remember` (session memory), `show` (recent memory or gate rows), `export` (HTML report), and `gates` (a proxy to `scripts/gates.sh`).

Project root isolation: `gates.sh`, `memory.sh`, and `llm-client.sh` resolve the project root via `CLAGENTIC_PROJECT_ROOT` env var when set, falling back to `git rev-parse --show-toplevel` of cwd. Hook shims run from inside the enrolled repo's working tree, so git show-toplevel finds the enrolled project automatically without the shim needing to know the path at stamp time.

### Trust boundary: global config vs. per-repo config

Two config files feed into every clagentic-lite process: `~/.config/clagentic/lite/config` (global, written by `init`, lives outside any repo) and `<repo>/.clagentic/config` (optional, sparse, lives inside the repo). Both are loaded the same way — sourced into the shell, each assignment auto-exported — which means loading either one *executes* it: it is a shell file, not a passive key-value format.

That distinction matters because the two files have very different provenance. The global config is something the operator wrote, on their own machine, before any of this runs. The per-repo config is *repo content* — it travels with `git clone` like everything else in the tree. A repo you have merely cloned, never enrolled, never reviewed, can carry a `.clagentic/config` an attacker planted. If the CLI sourced that file the moment it noticed cwd was inside a git repo, running something as innocuous as `clagentic-lite doctor` right after cloning an unfamiliar repo — out of curiosity, before deciding whether to trust it at all — would execute arbitrary shell on your machine.

The fix is to treat the two files differently rather than loading them through one unconditional call:

- **`ds_load_global_env`** (`scripts/platform.sh`) loads only the global config. Safe to call unconditionally, for every subcommand, because it never touches repo content.
- **`ds_load_repo_env`** (`scripts/platform.sh`) loads only the per-repo config: `<repo>/.clagentic/config`, then the legacy `<repo>/.env` if present (a v0.1 leftover, still honored, never created; loaded last, so it wins over `.clagentic/config`). This one requires a trust decision first.
- **`ds_load_env`** composes both, in order (global config, `.clagentic/config`, legacy `.env`; later wins), and remains what `gates.sh`, `llm-client.sh`, `memory.sh`, `smoke.sh`, and the Claude Code hook shims call — unconditionally, exactly as before this split existed. That is correct for them: every one of those only ever runs against a repo you have already deliberately enrolled (a hook fires from inside your own working tree; you invoked the script yourself while working in that repo). The precondition — "this repo is already trusted" — genuinely holds before any of them run.

`bin/clagentic-lite`'s own top-level dispatch is the one place that precondition does *not* automatically hold, because it is the thing deciding, moment to moment, which repo (if any) to trust. So it calls `ds_load_global_env` unconditionally, then a separate helper that loads the repo-local layer *only* when the repo's canonical path is already listed in `~/.local/state/clagentic/registry` — the file `enroll` appends to on success. Registry membership is the trust signal specifically because it lives outside the repo: nothing in a hostile clone can add itself to a file on the operator's machine that the operator never asked to write.

`enroll` and `init` are the two exceptions, and each is a real design decision, not an oversight:

- **`init`** has no per-repo context at all — it configures the tool installation, not a project.
- **`enroll` is how a repo becomes trusted.** It cannot require prior registry membership as a precondition for reading the repo it is in the middle of enrolling — that would make it impossible to ever enroll a first repo. But it must also not execute that repo's own config as the price of enrolling it; doing so would just move the same pre-trust execution problem one subcommand over. So `enroll` skips the repo-local layer entirely. The practical consequence: a repo-local override is not honored on the very first `enroll` call for a given repo — only from the next invocation onward (`doctor`, `update`, a re-`enroll`), once registry membership exists. The global config is unaffected and still applies at enroll time.

This same reasoning extends one layer down: `enroll` itself shells out to `gates.sh init` and `memory.sh init` to create each repo's local databases, before the registry entry is written. Those two scripts skip the repo-local config load specifically for their `init` subcommand (and only `init` — every other subcommand they support keeps the unconditional combined load, since those are only ever reached post-enrollment) for the identical reason: `init` in both scripts needs nothing from a config file, global or per-repo, so there is no cost to deferring the repo-local layer past that one call.

One consumer deliberately does not use this layering at all. The rendered Claude Code plugin is one per user, not one per repo, so its inputs (the `CLAGENTIC_<ROLE>_AGENT_MODEL` keys, `CLAGENTIC_ROUTER_URL`, `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL`, and the reviewer, auditor and gate `_CMD` keys while router injection is on) are read from the global config file alone, by sourcing it in a subshell with every `CLAGENTIC_*` variable unset. A repo's `.clagentic/config` would otherwise make the shared plugin depend on which repo `update` last ran from, and the process environment is no safer, because the loaders export what they source and `update` re-execs itself after a pull. `doctor` names any such key it finds in a repo's config or exported with a different value. The gate/CLI path keeps the layered behaviour above.

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

- **Summarizer cost control:** the Stop hook is debounced (`CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC`), but a very chatty session can still rack up cheap-tier calls. Revisit if it shows up in the audit trail.
- **Adversarial loop budget:** how many rounds before declaring "the model isn't finding new issues"? Currently capped at 1. Revisit after first real use.
- **Cross-platform sqlite3:** macOS ships an old SQLite. Document `brew install sqlite` as a soft requirement; test on the macOS-default version anyway.
