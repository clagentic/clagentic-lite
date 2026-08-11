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

### 9. Definition of done: local gate reproduction, not an approximation

Before reporting a fix or feature complete, you **MUST** run every locally-runnable blocking gate against your branch using the exact invocation the gate uses — `gates.sh sast`, `gates.sh secrets`, `gates.sh deps`, `gates.sh bleed` (each is already an individually invocable subcommand; see Gate 4 in `docs/GATES.md`) — not a hand-rolled approximation of what you think semgrep/gitleaks/osv-scanner/the bleed scan would do. A red local gate means the work is **not done**: do not report completion, and do not commit-and-hope that CI or a later `ship` run will catch it — this codebase has no CI (see "Build / test / run" below), so a local gate is the only check that will ever run.

Your completion report **MUST** include the per-gate local reproduction results (pass/fail for each of `sast`/`secrets`/`deps`/`bleed` you ran). Omitting the results is the same failure as not running the gates at all — the report exists so a reviewer doesn't have to re-derive whether you actually checked.

### 10. Class-over-instance: fix the pattern, not the line

When a review finding or bug is an instance of a pattern — the same defect shape is possible at other call sites, not just the one flagged — a silent point-patch of the flagged line alone is a **contract violation, not a style choice**. The Invariants section below exists because this codebase has hit this failure mode repeatedly: a single reported defect turned out to be one instance of a class, and a line-level fix left every sibling site exposed.

The required fix, in order:

1. **A shared primitive / single sanctioned path** — the one place the corrected behavior lives, so every call site can route through it instead of re-implementing it.
2. **A sweep of existing sites** — find every other place the same defect shape appears (e.g. via `git ls-files`-driven discovery, matching the convention in "Sweeping-test discovery convention" below) and fix them in the same change.
3. **Where feasible, a guard that fails the class going forward** — a sweeping test in `scripts/test_invariants.py` (see below) or an equivalent mechanical check, so a future reintroduction of the same shape is caught automatically rather than discovered as a fresh incident.

The only sanctioned alternative to doing all three is an **explicit written deferral**, recorded in the task or roadmap, with rationale for why the class-level fix is out of scope for this change. A deferral must be written down where the next person will find it — silence is not a deferral.

---

## Invariants

Class-level properties of this codebase, not per-instance bugfixes. Each one exists because a single reported defect turned out to be one instance of a class that could recur anywhere the same shape appears — the fix is the class-level property below, not the individual site. Each invariant states a mechanical check a reviewer or a sweeping test can run without judgment calls.

Before this section existed, there was nowhere to STATE a class-level property in this file — `_gate_resolve_fresh_default_branch_ref` (scripts/gates.sh) ended up with a docstring demanding callers check its exit status, and both of its own callers still wrote `|| true` around it, because there was no place in AGENTS.md an author could point to and say "this MUST hold." A numbered rule below is exactly that place.

- **INV-1a — a degraded/failed LLM chain outcome is NEVER silently reported as a clean pass, and the timeout mechanism that bounds every external call can never itself resolve to a silent no-op.**
  Two halves of the same property (a degraded outcome must be visible, and the very thing meant to bound a call must not silently vanish):
  - `$DS_TIMEOUT_CMD` (`scripts/platform.sh`) MUST NEVER resolve to a stub that discards its duration argument and runs the wrapped command unbounded. On a host missing both `timeout` and `gtimeout`, it resolves to `ds_timeout_missing`, which refuses to run the command at all (exit 99) rather than degrading silently.
  - Mechanical check: `scripts/platform.sh` must not define or reference a `DS_TIMEOUT_CMD` fallback function whose body executes `"$@"` (or an equivalent exec) without first invoking a real timeout binary.

- **INV-1b — every direct `llm-client.sh` invocation, anywhere in this repository, captures the real exit status AND performs a mode-appropriate degraded check before trusting the output.**
  (lr-7047bf, PR-B.) `walk_chain` communicates failure through a captured non-zero exit status (3 = infra, 4 = unwrap, 5 = turns-exhausted — see INV-4) as well as through the emitted envelope's own degraded marker; a caller that checks only one channel can miss a real failure the other channel would have caught.
  Mechanical check: `scripts/test_llm_client_consumer_sweep.py` — discovers every call site by `git ls-files`, not a hardcoded directory list, and asserts each one captures `|| VAR=$?` on the call line and performs a degraded check (`_llm_output_is_degraded` / `review_is_degraded` / an exit-status comparison / the line-mode text marker) downstream in the same function, or carries an explicit, reasoned `llm-client-sweep-exempt:` marker.

- **INV-2 — constrain the COUNT (or exactly-which) of a matched shape, never merely its PRESENCE.**
  (lr-33958f, PR-C.) A fix that only guarantees "at least one match exists" is not the same property as "exactly the expected number of matches exist, and I have proven it" — the former silently accepts an ambiguous or unbounded result as if it were the single correct one. Applies to: `_llm_unwrap_json_envelope` (locate every fenced-JSON candidate, not just the first; zero is a failure, more than one is a *different*, equally-reported failure, never a silent pick); `_llm_json_array_cap` / `_invariant_feed_max_field_chars` (a count bound at the point of emission, not merely "at least one finding is captured"); the reviewer/auditor tool restriction this task adds (`--allowedTools`/`--disallowedTools` constrain WHICH tools are available, not merely note in prose that Bash "shouldn't" be used).
  Mechanical check: any new decompose-and-match routine over LLM output must report a distinguishable outcome for zero, exactly-one, and more-than-one candidates — never collapse the latter two into "found one, proceed."

- **INV-3 — a function parameter that is accepted but never read by the function body is a defect, not a compatibility affordance. Fix it by removing the parameter or by actually reading it for a real purpose — never by leaving it accepted-but-silent.**
  (lr-33958f, PR-C.) An accepted-but-unread parameter looks like it does something; it does not, and the next reader has no way to tell without reading the whole function body. `invoke_step`'s (and `invoke_claude`'s) ROLE positional was removed once for exactly this reason. This task's reviewer tool-restriction feature needed role to reach `invoke_claude` again — satisfied WITHOUT reopening `invoke_step`'s signature (an existing test, `test_invoke_step_no_dead_role_positional.py`, locks it at 8 params permanently): `walk_chain` instead exports `CLAGENTIC_LLM_CLIENT_TOOL_ROLE` immediately before calling `invoke_step`, and `invoke_claude` reads it from either its own (renamed, `TOOL_ROLE`, not the retired `CALL_ROLE`) 8th positional or that env var. The principle generalizes: when a genuine, actually-read need for a previously-retired parameter reappears, prefer a channel that does not collide with an existing locked-in absence over reusing the same name/position.
  Mechanical check: for every POSIX-sh function signature reachable from `scripts/gates.sh` / `scripts/llm-client.sh`, every declared positional (`"$1"`, `"$2"`, …) must appear at least once more in the function body after its assignment.

- **INV-4 — every external-process invocation carries an explicit wall-clock bound, and every LLM invocation additionally carries an explicit bound on agentic tool use.**
  (This task, class 4.) Mechanically: no line invoking `gitleaks`/`osv-scanner`/`semgrep`/`gh`/`git push`/`claude`/`codex` in `scripts/gates.sh` may lack a `run_bounded`/`$DS_TIMEOUT_CMD` prefix (see `run_bounded`, `scripts/gates.sh`, the sole entry point for these); every `claude --print` reviewer call carries an explicit tool-restriction flag pair (`--allowedTools`/`--disallowedTools`); `$DS_TIMEOUT_CMD` NEVER resolves to a no-op (INV-1a is load-bearing here — without it, every bound this invariant requires is decorative on a host missing coreutils).
  KNOWN LIMITATION, recorded rather than faked: this codebase CANNOT set a hard cap on the number of agentic tool-use turns a `claude --print` call makes. `--max-turns` does not exist on the installed CLI (`@anthropic-ai/claude-code` 2.1.113, `claude --help` checked directly) — it is an SDK-only concept (`maxTurns` in the TypeScript `query()` options), never exposed through the `claude --print` flag surface. The invariant is satisfied via the timeout clause (`llm_timeout_for`'s byte-scaled wall-clock budget) and the tool-restriction pair alone for the turn-count half; turn-limit EXHAUSTION (Claude Code's own internal default ceiling, not one this codebase sets) is detected after the fact via `subtype=="error_max_turns"` on the raw `--output-format json` envelope (confirmed against the installed `@anthropic-ai/claude-agent-sdk`'s `SDKResultError` type) and classified as a distinct, non-passing outcome (`walk_chain` exit 5, cause `"turns-exhausted"` — see `_llm_degraded_cause`, `scripts/gates.sh`) rather than silently shipping as a clean pass. `num_turns` is logged into every `llm-call` audit row (`log_attempt`, `scripts/llm-client.sh`) so a reviewer riding close to its ceiling is visible in `gates.sh digest`/`gates.sh status` before it tips over into a turns-exhausted failure, not only after.
  Mechanical check: `scripts/test_invariants.py`'s external-invocation sweep reads `scripts/gates.sh` (the tracked file directly, not a hardcoded line-number list) and discovers every gitleaks/osv-scanner/semgrep/gh/git-push invocation by its statement-start token, asserting each one carries a `run_bounded`/`$DS_TIMEOUT_CMD` prefix; a companion sweep in the same file confirms `$DS_TIMEOUT_CMD` never resolves to the pre-fix no-op stub shape.

- **INV-5 — a Bash-restricted LLM role's restriction must be enforced identically across EVERY carrier CLI this codebase ships an `invoke_*` function for, never on only the CLI the original fix happened to verify against; AND the loud-warning mechanism covering a CLI/version this restriction cannot actually reach must be driven by the SAME predicate as the restriction itself, never a hardcoded per-role literal — a control and its disclosure are a pair, and updating one half without the other silently reopens the gap the pair exists to close.**
  (lr-37282a/lr-8a28e0, mirroring PR-A's finding that `invoke_codex` had correct exit-status handling eleven lines below an `invoke_claude` that did not — same two functions, same failure to propagate a property across the pair, opposite direction. Second half added same-PR, PEACHES fold-in, PR #144 review comment 5207862165 — the tenth instance of this exact propagate-across-the-pair failure shape in this sequence.) `ds_llm_role_is_bash_unrestricted` (`scripts/platform.sh`) is the SOLE source of truth for which roles keep Bash (currently `gate`/`builder`/`summarizer` only — `reviewer` and the `TOOL_ROLE=auditor` chain-step invocation are both restricted); both `invoke_claude` (`--allowedTools Read,Grep,Glob --disallowedTools Bash`) and `invoke_codex` (`--disable shell_tool -s read-only`, verified against the installed CLI per that function's own doc comment) consult this SAME predicate, so the two carriers cannot drift onto two different opt-out enumerations. A third `invoke_*` carrier added later (or `invoke_generic`, which restricts nothing today) must be added to this invariant's sweep the day it is written, not discovered as a gap in a future audit.
  THE WARNING HALF: `walk_chain` warns loudly, per call, whenever the resolved chain step is a CLI/version combination this predicate's restriction cannot actually reach (a codex version older than `CODEX_MIN_VERSION`, or any CLI outside claude/codex) — restriction is either real or loudly disclosed, never silently assumed. This warning's OWN guarding condition consults `ds_llm_role_is_bash_unrestricted` too, not a hardcoded `[ "$ROLE_L" = "reviewer" ]`-shaped literal comparison — the original class-4 fix (lr-49df97) wrote the warning when "reviewer" was the only restricted role and it was a correct, complete check at the time; when lr-8a28e0 (same PR) moved `auditor` onto the restricted side, the RESTRICTION propagated automatically (both `invoke_claude`/`invoke_codex` already consulted the shared predicate) but the hardcoded WARNING gate did not, leaving an auditor chain step on an old/unversioned codex genuinely unrestricted with zero diagnostic — silently reopening exactly the hole lr-8a28e0's restriction existed to close. Driving the warning off the same predicate as the restriction means any FUTURE role moved onto the restricted side is covered by construction.
  NOT restricted by this invariant, and deliberately so: `plugins/clagentic-lite/agents/auditor.md`, the interactive Claude Code subagent a human/session invokes directly to run `gitleaks`/`semgrep`/`osv-scanner` itself. That subagent's Bash access is Claude Code's own subagent `tools:` frontmatter (a security-tool-scoped allowlist) — a structurally separate mechanism from `--allowedTools`/`--disallowedTools`/`ds_llm_role_is_bash_unrestricted`, and outside this invariant's reach entirely. Conflating that subagent's genuine execution need with the `TOOL_ROLE=auditor` chain-step invocation's lack of one was the original defect this invariant closes.
  Mechanical check: `scripts/test_invariants.py`'s `TestEveryInvokeCarrierConsultsTheSharedBashRestrictionPredicate` discovers every `invoke_*` function in `scripts/llm-client.sh` by `git ls-files`-driven regex over the tracked file (not a hardcoded function-name list) and asserts each one that accepts a role — currently `invoke_claude`, `invoke_codex` — either consults `ds_llm_role_is_bash_unrestricted` to decide its own flags, or is an explicitly-enumerated known exemption (`invoke_generic`: no CLI-specific flag surface at all; `invoke_step`: the dispatcher, not a carrier) — never silently absent. `TestUnrestrictedCliWarningIsDrivenByTheSharedPredicate` (same file) extracts `walk_chain`'s warning-condition block by its anchor comment and asserts it consults the same predicate and carries no hardcoded per-role literal equality guard — a synthetic-sibling fixture in the same class proves the sweep actually catches the pre-fix hardcoded shape.

- **INV-6 — a `git` invocation that reads REPO STATE (a staged diff, a branch name, a commit SHA, a merge-base, an `ls-files`/`ls-remote`/`fetch` result) must never resolve as a bare `git ...` call, and `git -C "$DIR" ...` alone is not sufficient either — every such call must be proven to operate on the intended repo, not an ancestor one, before its result is trusted for a security- or correctness-relevant decision.**
  (lr-da1f28 sweep, generalizing lr-4a3f88's single-site fix — that task found and fixed one bare-`git` call, `gates.sh`'s `--recheck` SHA-staleness guard; this is the class-level closure.) `git -C <dir> <cmd>` only changes cwd BEFORE git's own repo-discovery walk-up runs — it still climbs the filesystem from `<dir>` looking for a `.git` directory. When `<dir>` (typically `$REPO_ROOT`, but also `$CLAGENTIC_LITE_HOME`/enrollment-registry paths in `bin/clagentic-lite`) is not itself a git repo but an ancestor of it is — the wrapper/`.clagentic-project` layout this codebase supports permits exactly this — every repo-state read silently resolves against that UNRELATED ancestor repo instead. This is a wrong-repo RESULT, not a git error: nothing about the call itself signals the mistake. The highest-stakes instance found in this sweep: `_gate_resolve_fresh_default_branch_ref` (`scripts/gates.sh`) feeds `cmd_sast`'s semgrep `--baseline-commit` and `cmd_bleed`'s branch-diff scope — a wrong-repo merge-base there would silently NARROW a blocking security gate's scan window while reporting a normal-looking clean pass, rather than producing a visibly-red test (the same silently-narrows-a-gate failure class BOBBIE caught during PR #137's own review at the stale-ref site). Other real instances closed in the same sweep: `get_review_diff` could leak an ancestor repo's staged diff to the LLM review/adversarial gates; `cmd_ship`'s push-target branch resolution could borrow a branch name from an unrelated repo; `.claude/hooks/pre-write-guard.sh`'s W-001 default-branch write-block could silently resolve the wrong repo's branch.
  `scripts/gates.sh` defines `_git_repo_root_is_scoped` (requires `git rev-parse --show-toplevel`, canonicalized via `cd DIR && pwd -P`, to literally equal REPO_ROOT's own canonicalized path) and `_git_repo_scoped_head_sha` (HEAD SHA, but only when scoped) as the shared mechanism; every repo-state-reading call site in that file either routes through `_git` after gating on `_git_repo_root_is_scoped`, or — the two `$DS_TIMEOUT_CMD`-bound fetch/ls-remote calls inside `_gate_resolve_fresh_default_branch_ref`, which cannot route through the `_git` shell function at all since `$DS_TIMEOUT_CMD` execs a literal command, not a function — the whole function gates its entire body on the same predicate up front instead. `scripts/llm-client.sh` and `scripts/memory.sh` (which source `platform.sh` but not `gates.sh`, and have no shared `_git` wrapper of their own) each carry a local mirror of the same predicate (`_llm_repo_root_is_scoped`, `_mem_repo_root_is_scoped`) rather than a hand-rolled inline check per call site. `bin/clagentic-lite`'s `_enroll_one` — the ROOT CAUSE of the same defect reappearing at every registry consumer (`list`/`doctor`/`update --restamp` all re-check a `$_rpath` that traces back to this function's `_canon` assignment) — gates its own "is this a git repo" check on the same toplevel-equality test, not presence alone, so a mis-scoped enrollment can no longer poison the registry at the source.
  Mechanical check: `scripts/test_invariants.py`'s `TestNoBareOrUnscopedGitRepoStateCallInGatesSh` discovers every `_git`/`git -C "$VAR"` repo-state invocation in `scripts/gates.sh` by `git ls-files`-driven regex over the tracked file (not a hardcoded line-number list), asserts no bare `git <repo-state-subcommand>` call exists and no `git -C "$VAR" <repo-state-subcommand>` call exists outside the two documented, function-guarded `$DS_TIMEOUT_CMD` exemptions, and separately asserts `_gate_resolve_fresh_default_branch_ref` still gates its body on `_git_repo_root_is_scoped` — synthetic-sibling fixtures (a bare-git call, an ungated `-C` call, a properly-`_git`-routed call, and a `git init` call, which is correctly NOT flagged since `init` creates a repo directly at `<dir>` with no discovery/walk-up involved) prove the sweep actually catches the pre-fix shapes rather than vacuously passing.

- **INV-7 — no tracked, live Claude Code lifecycle hook script or `settings.json` may exist under this repo's own `.claude/` again; the source of truth for both is `share/hook-shims/{*.sh,claude-settings}.template`, installer-materialized into `$CLAGENTIC_LITE_HOME/.claude/` at `init`/`update` time, never a file this repo commits and Claude Code auto-executes against its own dev sessions.**
  (lr-57db23.) Before this migration, `.claude/hooks/*.sh` and `.claude/settings.json` were tracked at this repo's own root — any Claude Code session run from this checkout could not help but load and execute this repo's own product against itself (tolerable only because the hooks were warn/non-blocking; a future hard-block would foot-gun the very repo where the tool is developed), and the executed copy could silently drift from the installer's own template inputs (the `share/hook-shims/*.template` files already existed for the other stamped artifacts but not, until this task, for the hook scripts themselves). `_stamp_claude_hooks` (`bin/clagentic-lite`) materializes the six hook scripts from their templates into `$CLAGENTIC_LITE_HOME/.claude/hooks/` at `init`/`update`, validated-then-temp-then-atomic-`mv`'d per script (mirrors `_stamp_claude_settings`'s own fix for the PR #146-diagnosed truncation defect — `sed ... > target` truncates the target before a failed render can refuse). `.claude/commands/recall.md` is a DELIBERATE, DOCUMENTED exception, not a gap in this invariant's scope: it is symlinked directly (no template, no stamping, no version marker) and is not something Claude Code auto-executes the way a lifecycle hook or `settings.json` is — see "Template version-bump protocol" above.
  Mechanical check: `scripts/test_invariants.py`'s `TestNoTrackedLiveHookScriptUnderClaudeDir` discovers every tracked file under `.claude/` via `git ls-files .claude/` (not a hardcoded file list) and asserts none is a lifecycle hook script (by path prefix `.claude/hooks/` OR basename match against the known six hook script names, so a renamed or relocated single script still trips it) or a `settings.json` by basename anywhere under `.claude/`. `test_sweep_anchor_still_finds_the_known_tracked_claude_file` asserts `.claude/commands/recall.md` is still present in the `git ls-files` output BEFORE trusting an empty violation list as meaningful — if that file is ever relocated without updating the anchor, the sweep would otherwise pass vacuously with zero tracked files actually swept, exactly the silent-no-op failure mode the "fail loudly if the anchor is renamed" bar requires.

## Sweeping-test discovery convention

`scripts/` contains roughly forty test files, most named after the incident or task that motivated them (`test_bleed_scope.py`, `test_merge_gate_recheck.py`, `test_review_deferral_match.py`). A suite organized purely by incident name cannot catch a REPLICATED defect: a test named after the one reported site never visits its sibling, so the same defect class can ship again at a different call site and pass every existing test.

`scripts/test_invariants.py` is the home for sweeping tests that discover call sites by grepping `git ls-files` — not a hardcoded directory or file list — and assert an invariant holds at every discovered site, the same discovery discipline `test_freshness_helper_sweep.py` and `test_llm_client_consumer_sweep.py` already established (`git ls-files`-driven scope needed three rounds in one prior PR because a directory-list-based scope kept being narrower than reality — do not regress that). New class-level invariants belong here first; a test named after one incident site belongs in its own file only when the property genuinely cannot recur elsewhere.

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

## When a gate or hook fails

Do not debug a failed gate, hook, or command inline as your own problem. Dispatch the **Troubleshooter** agent (`plugins/clagentic-lite/agents/troubleshooter.md`) first — it is read-only, applies a tiered diagnosis (Tier 0 fast triage → Tier 2 deep diagnosis), and returns a root cause plus a `bounce_target` (you, the Builder, or none — expected behavior). This applies to: a gate exit code that isn't 0, a hook producing an unexpected error, `clagentic-lite gates ship` reporting `BLOCKED`/`INFRA_DEGRADED`, or `clagentic-lite doctor`/`enroll` reporting broken state. The Troubleshooter never fixes — it names the cause and stops; act on its finding yourself.

### Iterate the single gate, never the whole chain

`gates.sh ship` runs the full blocking sequence (secrets, deps, sast, review, merge-gate) in order. When the ship chain goes red on one gate — say `sast` — **iterate that gate standalone** (`gates.sh sast`, re-run after each fix attempt) until it is green, then run `ship` once to confirm the full chain. Never loop the full `ship` chain to debug a single failing gate: re-running secrets/deps/review on every iteration wastes the time those gates take (a network-bound osv-scanner call, an LLM review round) on gates that already passed and tells you nothing new about the one that didn't.

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
| `share/hook-shims/claude-settings.template` | settings.json template stamped into enrolled repos — hook paths substituted with absolute `$CLAGENTIC_LITE_HOME` paths |
| `share/hook-shims/CLAUDE.md.template` | CLAUDE.md template stamped into enrolled repo root — thin enrollment notice, unconditionally true for any teammate |
| `share/hook-shims/builder-contract.template` | builder-contract.md template stamped into `.clagentic/lite/` (gitignored) — full builder rules, agent table, commands, hooks, gate reference; injected at session start |
| `share/hook-shims/{session-start,prompt-inject,pre-bash-guard,pre-write-guard,post-tool-nudge,stop-summarize}.sh.template` | source of truth for the six Claude Code lifecycle hook scripts (lr-57db23 — relocated out of the live, tracked `.claude/hooks/` so this repo's own dev sessions no longer self-execute its own product). Materialized into `$CLAGENTIC_LITE_HOME/.claude/hooks/` at `init`/`update` time via `__CLAGENTIC_LITE_HOME__` substitution (`_stamp_claude_hooks`, `bin/clagentic-lite`) — the ONE copy every enrolled repo's generated `.claude/settings.json` calls back into by absolute path. This checkout's own `.claude/` no longer carries a tracked, executed copy — see "Developing clagentic-lite itself" below for the opt-in dogfood path. |
| `.claude-plugin/marketplace.json` | plugin marketplace manifest — declares the `clagentic-lite` plugin |
| `plugins/clagentic-lite/.claude-plugin/plugin.json` | per-plugin manifest; version bumped by maintainer PRs that change agent or skill files — never by `clagentic-lite update` |
| `plugins/clagentic-lite/agents/{builder,reviewer,auditor,merge-gate,troubleshooter}.md` | role contracts installed globally via `claude plugin install` at `clagentic-lite init` time |
| `plugins/clagentic-lite/skills/infosec-rt/SKILL.md` | infosec red-team commentary skill — installed globally via the plugin |
| `plugins/clagentic-lite/skills/eng-consult/SKILL.md` | engineering consulting panel skill — installed globally via the plugin |
| `.claude/commands/recall.md` | `/recall` slash command — session memory search. Different from the hooks above: this file IS the source of truth at this exact path — enrolled repos symlink `$CLAGENTIC_LITE_HOME/.claude/commands` directly, no template/materialization step (see "Template version-bump protocol" below). |
| `.codex/config.toml` | Codex sandbox + role config — operator-facing documentation only; NOT auto-loaded by the codex binary (confirmed against codex-cli 0.142.5, lr-ae403d) and never read by this repo's own `invoke_codex` invocation path. See the file's own header comment. |
| `.gitleaks.toml` | gitleaks config — extends defaults, narrow path+token allowlist |
| `scripts/platform.sh` | GNU/BSD shims + shared helpers (`ds_load_env`, `ds_sql_escape`, `ds_audit_log`, `ds_json_field`, `ds_check_tool`, `ds_offer_install`, `$DS_TIMEOUT_CMD`) |
| `scripts/memory.sh` | SQLite session memory CRUD |
| `scripts/llm-client.sh` | role-aware LLM wrapper with model_chain fallback |
| `scripts/gates.sh` | gate orchestrator + digest + ship + merge-gate |
| `scripts/smoke.sh` | non-interactive end-to-end (local sanity check) |
| `docs/` | DESIGN, GATES, DEMO-SCRIPT, PORTABILITY, LLM-USAGE (checklist for an LLM/agent setting up or operating clagentic-lite on a user's behalf) |
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
| `share/hook-shims/{session-start,prompt-inject,pre-bash-guard,pre-write-guard,post-tool-nudge,stop-summarize}.sh.template` | `CLAUDE_HOOKS_VERSION` in `bin/clagentic-lite` | Any content change to any one of the six hook script templates (lr-57db23) — these are materialized into `$CLAGENTIC_LITE_HOME/.claude/hooks/`, not per-enrolled-repo, so a bump re-stamps the tool's own install, not each enrolled repo directly |

`CLAUDE_MD_VERSION` is retired — replaced by the three narrower constants above. During the transition period it remains in `bin/clagentic-lite` as a tombstone so old installed files continue to compare correctly. Doctor will warn on any repo still carrying the old `clagentic-claude-md-version` marker; `update` will migrate them to the thin notice with a full replace (no old rule content preserved). If a repo's committed `CLAUDE.md` still contains a "How to work in this repo" rules block after updating, run `clagentic-lite update --restamp` to force a clean restamp.

The version strings are arbitrary (`v1`, `v2`, ...) — increment by one each time. The template file itself should also carry the updated version in its managed-by comment (e.g. `clagentic-notice-version: v2`) so the installed copy is self-describing.

**After bumping:** run `clagentic-lite update` (or `clagentic-lite update --restamp` to force all enrolled repos regardless of version). Users on older installs get the restamp automatically on their next `update` run.

**`.claude/commands/` is different.** Those files are symlinked directly from `$CLAGENTIC_LITE_HOME/.claude/commands` into enrolled repos — no stamping, no version tracking. Changes take effect immediately for all enrolled repos. No version bump needed.

### Developing clagentic-lite itself

This checkout does not ship a tracked, live `.claude/hooks/*.sh` + `.claude/settings.json` at its own repo root (lr-57db23). Chosen trade-off: a Claude Code session run from this repo no longer self-executes this repo's own hooks/settings by default — editing a hook script here does not self-enforce against the very session editing it, unlike before. This was a deliberate STOP-dogfooding decision, not an oversight: the prior tracked-and-live shape meant the source-of-truth for hook behavior and the executed copy were the same file, and a future hard-block hook could foot-gun the repo where the tool is developed.

Verification is now via install + test, not ambient self-execution:

- Run `clagentic-lite init` (or `enroll --self`) against `CLAGENTIC_LITE_HOME=$(pwd)` once to materialize `.claude/hooks/*.sh` from `share/hook-shims/*.sh.template` into this checkout's own `$CLAGENTIC_LITE_HOME/.claude/hooks/` and opt this checkout into dogfooding its own hooks for the current session onward — same command any other machine runs, no special-cased dev path.
- `scripts/test_claude_hooks_materialization.py` is the fast, non-interactive way to prove a hook template change is byte-correct without touching the live checkout at all — it runs `init`/`update`/`doctor` against a throwaway copy under `tempfile.mkdtemp()` with `CLAGENTIC_LITE_HOME`/`CLAGENTIC_HOME` forced, never inherited from the ambient environment — mirroring `test_enroll_reenroll_no_force.py` and `test_router_settings_stamp.py`, which establish the same isolation discipline for their own install-affecting tests.

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
