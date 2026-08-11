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

**Three distinct degraded causes.** A degraded chain reports one of three
mutually exclusive causes, all fail-closed but with different remediation:

- **`INFRA_DEGRADED`** (`walk_chain` exit 3, envelope `"cause": "infra"`) —
  no chain configured, or every step's own CLI invocation failed (nonzero
  exit, timeout, not on PATH). This is genuinely a misconfigured/
  auth-broken/network-out chain; remediation is "check LLM CLI config/auth."
- **`MODEL_OUTPUT_UNPARSEABLE`** (`walk_chain` exit 4, envelope
  `"cause": "unwrap"`) — every step's model invocation *succeeded* (auth
  worked, tokens were spent) but its output could never be reduced to
  exactly one role-shaped JSON candidate — the model returned prose, no
  JSON at all, or more than one competing JSON block. This is NOT an
  infrastructure problem; remediation points at reviewer/auditor output
  shape, never CLI config. Before lr-33958f this collapsed into the
  identical `INFRA_DEGRADED` message, which sent operators to check CLI
  config/auth for a problem in neither — see the shared unwrap helper,
  `_llm_unwrap_json_envelope` in `scripts/llm-client.sh`, called once from
  `walk_chain` for every role/CLI uniformly.
- **`TURNS_EXHAUSTED`** (`walk_chain` exit 5, envelope
  `"cause": "turns-exhausted"`) — the model exhausted its agentic tool-use
  turn ceiling (`subtype=="error_max_turns"` on the raw
  `--output-format json` envelope) before completing. Distinct from BOTH of
  the above: the model ran (not infra), and its output may be
  well-formed, role-shaped JSON — e.g. `findings: []` emitted before being
  cut off — which is exactly what makes this the most dangerous of the
  three. A truncated run must never pass as a clean review; this cause is
  checked, and rejected, BEFORE `walk_chain`'s own pass branch, regardless
  of how parseable the partial output looks. `num_turns` is logged into the
  `llm-call` audit row for every claude json-mode call (not only a failing
  one), so a reviewer riding close to its ceiling is visible in
  `gates.sh digest`/`gates.sh status` before it tips over into this state.
  See AGENTS.md § Invariants, INV-4, for the full rationale and the
  no-settable-turn-cap limitation this detection does NOT close on its own.

Unwrap itself requires **exactly one** JSON candidate — located via
`re.search`/`finditer` over the model's full response (never an
anchored whole-string match), filtered to candidates that both parse as
JSON and match the calling role's expected shape. Zero candidates and more
than one candidate are both failures, reported distinctly (never a silent
first-or-last pick) — see that function's own doc comment for the full
contract.

**Reviewer tool restriction.** The Reviewer's LLM invocation loses shell
execution on both shipped CLIs. When the resolved chain step is `claude`,
`claude --print` carries `--allowedTools Read,Grep,Glob --disallowedTools
Bash` — it keeps Read/Grep/Glob (its prompt mandates caller-tracing and
import-checking) but loses Bash. When the resolved chain step is `codex`,
`codex exec` carries `--disable shell_tool -s read-only` — verified against
the installed CLI (codex-cli 0.142.5) to remove the model's shell-execution
tool while preserving file reads (`-s read-only` additionally closes
codex's separate `apply_patch` file-write tool, which `--disable shell_tool`
alone does not gate). Both closures exist for the same reason: nothing in
the Reviewer's prompt asks it to execute anything, and a `--print`/`exec`
reviewer holding unrestricted Bash while reading an attacker-influenceable
diff is a prompt-injection-to-execution path. Scoped to the Reviewer (and,
as of lr-8a28e0, the Auditor's chain-step invocation — see Gate 5 below) —
the Merge Gate, Builder, and Summarizer are unaffected. Still not
enforceable when the resolved chain step is a third CLI outside claude/
codex (`invoke_generic`, no restriction mechanism at all), or when the
installed codex predates `CODEX_MIN_VERSION` (the tool-restriction flags are
only applied on codex's version-gated, confirmed flag-surface path) —
`walk_chain` prints a loud stderr warning in either remaining case.

### Reviewer-consulted deferrals

When an operator has reviewed a finding and decided to defer it — because it is
a known fixture, an intentional design choice, or a false positive they have
accepted — they can record that decision in `.clagentic/deferrals.json`. The
file is read at review time and injected into the reviewer system prompt as
context before the diff is reviewed, AND (lr-2ebc41, see "Gate-code
enforcement" below) is mechanically re-checked in gate code after the
Reviewer responds, independent of whether the model chose to honor it.

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
    "message": "hardcoded credential in seed-demo.sh",
    "description": "Planted demo credential — intentional fixture, not production code.",
    "expires": "2026-12-31",
    "acknowledged_by": "akuehner",
    "scope": "stable-contract",
    "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
]
```

Fields:

| Field | Required | Description |
|---|---|---|
| `id` | yes | Stable identifier for the deferral |
| `category` | no | Finding category this deferral applies to |
| `file` | no (yes for gate-code matching) | Exact path this deferral applies to |
| `message` | no (yes for gate-code matching) | The Reviewer finding's own `message` text, VERBATIM — this is the gate-code match key, see below |
| `description` | yes | Human-readable reason for the deferral |
| `expires` | no | ISO date after which the deferral should be reconsidered |
| `acknowledged_by` | no | Who approved the deferral |
| `scope` | no (yes for gate-code matching) | Must be the literal string `"stable-contract"` to be gate-code-eligible at all — see "Gate-code enforcement" below. Any other value (or absent) means the entry is prompt-context-only, exactly as this feature behaved before lr-2ebc41. |
| `file_sha256` | no (yes when `scope` is `"stable-contract"`) | sha256 (64 lowercase hex chars) of `file`'s content at the moment the deferral was granted. Gate code recomputes this at match time; any difference lapses the match. |

lr-c567's original six fields (`id`/`category`/`file`/`description`/
`expires`/`acknowledged_by`) remain valid on their own — a deferral with only
those fields is a pure prompt-context hint, unchanged from before lr-2ebc41:
the model weighs it, nothing mechanically enforces it, and it is never
gate-code-matched. `message`/`scope`/`file_sha256` are additive fields that
opt a specific entry into the stricter, mechanically-enforced path described
next.

**Suppression is inside model judgment for entries without `scope:
"stable-contract"`; it is ALSO inside gate code for entries with it
(lr-2ebc41 — see "Gate-code enforcement" below, reversal of lr-c567's
original design).** All deferral fields still reach the reviewer system
prompt as claims to weigh regardless of scope (see "Round-trip sanitization
and fencing" below for how the transport is hardened — the round-trip
mechanics are unchanged). A finding the LLM still emits despite a
non-gate-code-eligible deferral entry stands, exactly as before. A finding
that mechanically matches a live `stable-contract` entry is excluded from
`severity_blockers()`'s count regardless of whether the model itself also
honored the deferral — see below.

**`expires` field semantics:** the gate does not parse or compute expiry dates.
The expiry text is passed to the LLM (sanitized, see below) so the model can
reason about whether the deferral is still valid given the current context.
The gate has no date arithmetic. This is unchanged by lr-2ebc41's gate-code
path — `expires` is not part of the mechanical match or lapse conditions;
`file_sha256` freshness is the sole gate-code lapse mechanism (see below).

### Gate-code deferral enforcement (lr-2ebc41)

**This reverses lr-c567's original "suppression happens inside the LLM's
judgment ... NOT in gate plumbing computing a score and dropping rows"
decision, on purpose, for one narrow class of deferral.** Field evidence: on
a real multi-round run, a single stage-contract finding, accepted with a
stable documented rationale in round 2, was re-raised by the stateless
Reviewer in rounds 3, 5, 6 (twice), and 7 — six identical rulings on the
same accepted finding, because nothing mechanically excluded it once
accepted; the Reviewer was only ever *asked* to honor the deferral, never
*required* to. This is the same move this repo has already made twice
elsewhere for the identical reason: `_parse_adversarial_findings`
force-corrects a finding's tier in the parser rather than trusting the
model to set it correctly, and the lr-66e598 close comment records the
general lesson — "overwrite-on-match is not own-the-field." Deterministic
enforcement of a model-visible hint is the pattern this codebase has
converged on twice before lr-2ebc41 made it three.

**What changed, precisely:** a review finding whose `(file, category,
message)` triple exactly matches a `.clagentic/deferrals.json` entry with
`scope: "stable-contract"`, AND whose named `file`'s current sha256 exactly
equals that entry's `file_sha256`, is annotated on the finding object with
`_deferral_matched: true` and `_deferral_id: "<id>"` by
`_review_deferral_match` (`scripts/gates.sh`), which runs immediately after
cross-round dedup and recurrence demotion in `cmd_review`. `severity_blockers()`
(`scripts/gates.sh`) excludes `_deferral_matched` findings from its block
count — **threshold only, never suppression**, the identical posture
`_recurrence_demoted` already established (lr-66e598): the finding remains
in `.findings`, fully visible in `last-review.json`, in
`cmd_render_review`'s terminal output (rendered with a `(matched deferral
<id>)` suffix), and in the audit trail (`gate_runs`, `gate=review-deferral-match`)
— only its eligibility to gate `/ship` changes. Model compliance with the
deferral (skipping the finding in its own output) is unaffected by, and
independent of, this mechanism; either or both can suppress the same
finding from blocking.

**Match key.** Deliberately NOT `finding_content_keys`' sha256-of-a-±2-line
diff-context-window key (`scripts/review-merge.sh`) — that key is
*computed from the lines surrounding the finding*, so an incidental,
unrelated edit two lines away changes the key and silently breaks the
match; this is precisely why the original recurrence-only mechanism did not
catch the six-re-raise case. The key here is the `(file, category,
message)` triple instead — the same triple `_review_recurrence_demote`
already uses internally to join a bumped recurrence count back to a
finding object. It survives incidental line-number drift by construction
(it never mentions a line number), which is the stability property this
needs. What it deliberately does **not** distinguish: two genuinely
different findings that happen to share `file`+`category`+`message` text —
extremely unlikely for anything but a fixed boilerplate lint message, and
even then `file` still disambiguates most cases. A finding whose message
text itself changes between rounds is treated as a NEW finding and
correctly fails to match — this key does not attempt fuzzy or semantic
sameness (explicitly out of scope; see "Explicitly out of scope" below).

**Lapse (freshness).** A `(file, category, message)` triple match alone is
NOT sensitive to the deferred logic changing — a deferral granted against
one round's behavior in a file would keep matching every later round even
after that file's logic was rewritten, if the triple were the only check.
`file_sha256`, pinned to the named file's content at grant time and
recomputed at match time, closes that gap for the case where the
deferral's own validity depends only on its own file: any edit anywhere in
that file, not just near the finding's own line, lapses the match back to
blocking. This correctly handles a *stable-contract* acceptance (one whose
rationale is "this holds as long as this file's own contract holds") but is
a **deliberate, documented restriction**, not a general mechanism: it
cannot detect a dependency living in a *different* file or region than the
one the deferral names.

**What this deliberately does not support, and why (the `:139`-class
problem).** Some accepted findings are not stable-contract acceptances at
all — they are reasoned *scope boundaries* whose validity depends on code
living *elsewhere*. Example (field evidence): a finding that a gate
intentionally does not scan a certain repo shape, accepted with the
rationale "including them would make an unrelated reset routine clobber
another scanner's findings, a data-loss bug — that clobber risk is why the
scope is deliberately narrow." That deferral's truth depends on the reset
routine staying narrow, and the reset routine lives in a *different file*
than the finding itself. A single-file content hash cannot see that
dependency: the named file could stay byte-identical while the real
dependency changes elsewhere, silently leaving a stale deferral in place
exactly when it would matter most. Rather than build a mechanism that
silently mishandles this class (or a general cross-file dependency-graph
mechanism, which is a materially larger and riskier feature than this task
scoped), lr-2ebc41 chose a **deliberate, documented restriction**: only
`scope: "stable-contract"` entries are gate-code-eligible; anything whose
acceptance rationale depends on code outside its own named file must NOT
declare that scope. `scripts/gates.sh deferrals-lint` (see below) refuses,
loudly, at capture time, any entry claiming `stable-contract` scope without
the fields gate-code matching requires — the goal is that a conditional
acceptance is either declared correctly (no `scope`, prompt-context-only,
unchanged from pre-lr-2ebc41 behavior) or rejected outright, never silently
accepted and mis-honored.

**Fail-closed (the property that matters most).** Any of the following
retains a finding as blocking, exactly as if no deferral existed at all: no
`.clagentic/deferrals.json`, or it is empty/malformed; a `deferrals.json`
entry missing `id`/`file`/`message`; a `stable-contract`-scoped entry
missing or with a malformed `file_sha256`; the named file missing from disk
or unreadable; no sha256 tool available; no `python3` available (the splice
step needs a real JSON encoder/decoder, matching `_review_recurrence_demote`'s
own python3-only posture); and — the ambiguous case — more than one live
(hash-matching) deferral entry independently claiming the same `(file,
category, message)` triple. Over-matching is the dangerous direction (a
deferral bug silencing a real high/critical finding); under-matching only
costs an operator a redundant re-report, never a missed real issue. "Wrong
suppressions are worse than missed dedups" (above) is the same governing
principle applied here.

**Capture-time linting: `clagentic-lite gates deferrals-lint [FILE]`.**
Validates `.clagentic/deferrals.json` (or `FILE`) against the stricter
gate-code schema and exits non-zero with one specific reason per problem on
stderr — most importantly, it refuses any entry that declares `scope:
"stable-contract"` without the fields required to make that scope
meaningful (`id`/`file`/`message`/`file_sha256`), which is the mechanical
half of "reject a conditional acceptance loudly at capture time" (the
prose half — recognizing that an acceptance's rationale is conditional on
code elsewhere — is not something shell code can verify and remains the
capturing agent's judgment call; see `plugins/clagentic-lite/agents/builder.md`
"Capturing an accepted review finding"). This is a **lint gate, not a
generator** — it does not write, create, or compute anything, including
`file_sha256` itself (the capturing agent computes that from the same file
it is deferring, in the same edit that adds the entry — see "Why there is
no `defer` writer subcommand" below). It is not wired into `gates ship`'s
blocking sequence; it is meant to be run by the capturing agent (or a
commit hook, at the operator's option) immediately after writing an entry,
so a malformed grant is caught in the same turn it was written rather than
discovered rounds later when it silently never matches.

**Why there is no `gates defer` (or similar) writer subcommand.** This was
evaluated and deliberately rejected. The task's own framing: "capture must
be a byproduct of the acceptance, not a separate act — if accepting a
finding is one step and recording it is another, the second step is the
one that gets skipped, and that is precisely the observed six-re-raise
failure. A `defer` subcommand the operator must remember to run is the same
failure mode with a shorter path, not a fix." There is also no interactive
prompt loop anywhere in this codebase's review path (`cmd_review` /
`cmd_render_review` are pure batch CLI — see their own code) for a
subcommand to hook into as a true byproduct of the act of accepting; the
actual acceptance happens in a Claude Code conversation between the
operator and the Builder (or the operator directly), entirely outside any
process boundary `gates.sh` can observe. The closest thing this codebase
already has to "capture a verbal acceptance as a byproduct of the same
turn" is the Builder's existing tech-debt-trailer convention (`builder.md`
§ "When these principles conflict with the user's request," step 3: "If
the user explicitly accepts the shortcut, note it in the commit message ...
so it is findable later") — lr-2ebc41 extends that exact pattern to review
findings: the Builder writes the deferral entry in the same turn it acts on
the operator's acceptance, not as a queued follow-up. This is honestly
still "ask an LLM to write something down," which is the thing the task
explicitly wants to move away from — but it is the most deterministic
capture point that exists given no mechanically-observable acceptance
event exists in this codebase's architecture. The mechanism this task
requires to be genuinely deterministic is Half 2 (gate-code matching,
above): whether or not capture happens reliably, a well-formed entry is
enforced by shell code, not by asking the Reviewer to comply.

**Fail-open:** if `.clagentic/deferrals.json` is absent or empty, the review
runs as if no deferrals exist. The gate never blocks on a missing deferrals
file. Non-empty content that is not a valid JSON array (malformed) is still
surfaced to the Reviewer — fail-open on *whether deferrals apply*, not on
*whether the file gets read* — but is no longer injected completely as-is
(see "Round-trip sanitization" below): it goes through a best-effort
text-level sanitize pass and the LLM will ignore text it cannot interpret
as a deferral list.

**Round-trip sanitization and fencing (lr-4f8316 follow-up, hardened in a
second follow-up pass).** `.clagentic/deferrals.json` is gitignored, but
gitignored means *untracked and unreviewed*, not *write-restricted* — it is
not an enforced property, it is an assumption. Any process with filesystem
write access to the working tree (a compromised dependency, a build step,
an agent with Write access) can populate this file, and because the
content never appears in a diff, it is never code-reviewed — weaker
provenance than the change-class commit-message hint (which at least
travels through git history), not stronger. Deferrals also carry the
highest payoff of any prompt-interpolation site in this codebase: a
deferral literally suppresses a finding, so a forged or injected entry
does not just confuse the Reviewer, it can silence it.

`ds_review_prompt` (`scripts/llm-client.sh`) runs a two-stage pipeline, in
this order:

1. **Allowlist** — `_llm_json_array_allowlist_fields` (`scripts/platform.sh`)
   reduces every deferral object to ONLY the nine documented schema fields
   (`id`/`category`/`file`/`message`/`description`/`expires`/`acknowledged_by`/
   `scope`/`file_sha256`, extended from the original six by lr-2ebc41).
   Any other key is DROPPED entirely, not sanitized-and-kept — an
   unrecognized key has no defined meaning to the Reviewer. A known field
   name holding a non-string value (a nested object or array) is also
   dropped, not stringified: the schema defines every field as plain
   text, so a nested structure under a real key name has no defined
   meaning either, and passing it through would smuggle attacker content
   one level deep past a sanitizer that inspects a field as flat text.
2. **Sanitize** — only after every surviving field is a known, schema-legal
   string does `_llm_json_array_sanitize_fields` (the same shared
   decompose/sanitize/rebuild machinery `_sanitize_adversarial_findings_json`,
   `scripts/gates.sh`, uses for the adversarial findings sidecar) run
   `_llm_field_sanitize` over each one.

**Why the allowlist step exists as a separate function, not a change to the
sanitize step's contract:** `_llm_json_array_sanitize_fields` sanitizes
only the fields it is told to and passes every other key through
unchanged — safe for the adversarial-findings caller (its field set is
fixed by `_parse_adversarial_findings`' own regex capture groups; an
attacker cannot introduce a key at all) but unsafe for deferrals, which
reads an arbitrary JSON object off disk. The first version of this fix
sanitized only the six original named fields without first reducing the
object to that schema — any extra key an attacker added rode through
byte-identical, undefanged, unstripped, uncapped. The allowlist step closes
that gap by running BEFORE sanitization, so there is no unlisted field left
for the sanitizer to have skipped, and the same discipline extends to the
three fields lr-2ebc41 added (`message`/`scope`/`file_sha256`) — they are
allowlisted and sanitized exactly like the original six, whether or not
they end up mechanically matched by gate code.

The result is wrapped in a `===BEGIN/END DEFERRED FINDINGS DATA===` fence
with the same treat-as-data framing the invariants and change-class-hint
blocks use. If the content is not valid JSON (so there is no object to
decompose), the whole blob still goes through one `_llm_field_sanitize`
pass — control bytes stripped, forged fence labels defanged — rather than
being interpolated completely raw. This non-JSON fallback path is not
weaker than the field-level path: both call the same sanitizer with the
same defang list, and the whole-blob cap (`CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS`,
default 500 chars) is stricter in aggregate than the field-level path's
per-field cap applied across up to six fields per entry. Deliberately
malforming the file to route onto this path trades structured deferral
data for shorter, opaquely-sanitized text — never a downgrade in defang
coverage.

**Deferrals vs. `accepted-risks.md`:**

| Mechanism | Location | Read by | Suppression path |
|---|---|---|---|
| `deferrals.json`, no `scope` or `scope` != `"stable-contract"` | `.clagentic/deferrals.json` (gitignored) | Gate 3 reviewer prompt | LLM judgment only |
| `deferrals.json`, `scope: "stable-contract"` | `.clagentic/deferrals.json` (gitignored) | Gate 3 reviewer prompt AND `severity_blockers()` gate code | LLM judgment (advisory) AND mechanical file-hash match (authoritative — see "Gate-code deferral enforcement" above) |
| `accepted-risks.md` | `.clagentic/accepted-risks.md` (committed) | Gate 6 merge-gate | Gate plumbing reads the doc; merge-gate LLM classifies covered findings as acknowledged |

Use deferrals for local, ephemeral, or per-session suppression guidance —
`scope: "stable-contract"` entries additionally get mechanical enforcement
independent of model compliance. Use `accepted-risks.md` for committed,
audited architectural decisions that persist in the repo history.

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

### Cross-round finding recurrence demotion (lr-66e598)

Backstop for the general case of "no loop state exists anywhere in
clagentic-lite" — round N+1's reviewer prompt has no record of round N's
findings, so the same class of concern can be reported, argued about, and
re-reported indefinitely with nothing counting the rounds. Recurrence
demotion is a second use of the same content-hash key space
`finding_content_keys` (`scripts/review-merge.sh`) cross-round dedup already
computes — where dedup only tests membership ("have we seen this key
before" → suppress), recurrence tracking counts occurrences ("how many
rounds has this key been reported in" → demote at a threshold).

**Relationship to cross-round dedup.** The two mechanisms compose, in this
order, every round: dedup runs first and can suppress a finding outright
(same content-hash key seen before → dropped from `.findings` entirely, per
"Cross-round finding dedup" above); recurrence demotion then runs only
against whatever survived dedup. This means a finding whose content-hash key
is byte-identical round to round is dedup's job — it is suppressed starting
round 2 and recurrence demotion never gets a second round to count. Where
recurrence demotion actually matters is when dedup is off
(`CLAGENTIC_CROSS_ROUND_DEDUP=0`, in which case a finding's own occurrence
count still accrues every round it is reported) — the mechanism inherits the
SAME "survives line shifts, not content edits" key-stability property dedup
has (see "Cross-round finding dedup" above); it does not invent a fuzzier
notion of sameness.

| | |
|---|---|
| **Feature flag** | Same as cross-round dedup — runs only when `CLAGENTIC_CROSS_ROUND_DEDUP=1` (default on). Recurrence tracking depends on the same per-round content-hash-keying pass dedup performs on the diff, so the two share one on/off switch. |
| **Threshold** | `CLAGENTIC_RECURRENCE_THRESHOLD` (default `2`, floored at `2` — a finding can only be demoted after being reported before AND reported again; a first-ever report is never demotable regardless of configuration). |
| **Counts file** | `.clagentic/lite/review-recurrence.json` (gitignored, local gate state — same directory convention as `review-seen-keys` and `invariants.json`). A JSON object mapping content-hash key → integer round-count, maintained by `finding_recurrence_bump` (`scripts/review-merge.sh`). |
| **Effect** | A review finding that survives cross-round dedup (i.e. is still reported this round) AND whose content-hash key has now recurred at or above the threshold is annotated `_recurrence_count` (integer) and `_recurrence_demoted: true` on the finding object. `severity_blockers()` (`scripts/gates.sh`) excludes `_recurrence_demoted` findings from its block count. **Threshold only, never suppression**: the finding remains in `.findings`, fully visible in `last-review.json`, `cmd_render_review`'s terminal output (rendered with a `(reported N rounds running — decide)` suffix), and the audit trail — only its eligibility to gate `/ship` changes. |
| **Audit trail** | Every recurrence pass logs a `gate_runs` row (`gate=review-recurrence`) recording `demoted:N threshold:T`, and the operator sees a stderr notice (`[recurrence] N finding(s) demoted to advisory ...`) when N > 0. |
| **Reset** | `clagentic-lite gates review --reset-dedup` deletes BOTH `.clagentic/lite/review-seen-keys` AND `.clagentic/lite/review-recurrence.json` — a reset means every finding is treated as fresh in both senses (not suppressed by dedup, and not recurrence-demoted). |
| **Conservative bias** | Identical posture to cross-round dedup, applied to demotion instead of suppression: empty key → retained, un-demoted. Splice failure → original findings retained untouched. No JSON tool at all → full passthrough, `last-review.json` unmodified. A finding is annotated only when its key was actually computable this round; an uncomputable key never accrues a count and can never be demoted. |
| **Scope** | Review findings only (Gate 3). Adversarial findings (Gate 5) already have their own two-tier `reachable`/`tier` mechanism (see "Blocking vs advisory" above) with its own mechanical security-floor clamp; recurrence demotion does not read or write adversarial findings and has no interaction with that clamp — a finding held `tier: blocking` by the security floor is a Gate 5 concept entirely outside this function's reach. |

Configure in `.clagentic/config` (per-repo) or `~/.config/clagentic/config` (global). See `share/config.example` for the full entry.

**Ingest sanitization — closing a self-exempting-suppression gap (BOBBIE-caught follow-up).** `last-review.json` is written directly from the LLM's raw structured JSON output; the pre-write validation (`validate_output`, `scripts/llm-client.sh`) checks that `.findings` is an array, that each `.severity`, if present, is a legal enum value, and (lr-3eb18c, reviewer role only — see "Class-level review findings" below) that every finding carries a non-empty `issue_class` and `class_fix` — it does not allowlist the rest of the object's field set. Before this fix, a model (compromised, manipulated by attacker-influenced code under review, or simply emitting whatever the prompt schema loosely tolerates) could include `_recurrence_demoted: true` directly in its own JSON response. `_review_recurrence_demote`'s splice only *overwrites* `_recurrence_count`/`_recurrence_demoted` on a finding whose `(file, category, message)` triple matches a row in the current round's content-hash-keyed TSV (i.e. whose cited line falls inside `finding_content_keys`' diff-context window); a finding outside that window was left untouched, so a self-forged `_recurrence_demoted: true` on a **first-ever-reported** finding survived verbatim into `last-review.json`, and `severity_blockers()` (which reads `._recurrence_demoted` with no provenance check) excluded it from the block count — a finding could self-exempt from blocking with zero actual repetition.

The fix has two independent layers:

1. **Ingest strip (the actual closure point).** `_sanitize_review_findings_envelope` (`scripts/gates.sh`) reduces every finding to the closed review-finding schema — `severity`, `file`, `line`, `category`, `message`, `evidence`, `suggestion`, `issue_class`, `class_fix` (the exact fields `ds_review_prompt`, `scripts/llm-client.sh`, documents — the last two added by lr-3eb18c, see "Class-level review findings" below) — via `_llm_json_array_allowlist_fields` (`scripts/platform.sh`), dropping every other key including any `_recurrence_demoted`/`_recurrence_count` the model itself supplied. It runs immediately after **every** raw LLM write to an envelope file: the single-pass path's `$OUT`, and each per-chunk envelope in the chunked path *before* `merge_envelopes` ever unions chunks (`merge_envelopes`/`dedup_findings` are pure concatenation/dedup with no field validation of their own, so an unsanitized chunk would have carried a forged field through the merge untouched). This mirrors the established choke-point pattern `_sanitize_adversarial_findings_json` and the deferrals allowlist already use elsewhere in this codebase — sanitize once at the one true ingest boundary, not at every reader.
2. **Own-the-field in the splice (defense in depth).** `_review_recurrence_demote`'s unmatched branch (a finding whose triple has no match in this round's bumped TSV) now sets `_recurrence_count: 0` / `_recurrence_demoted: false` explicitly rather than leaving the finding object untouched — so even if the ingest strip were ever bypassed, skipped, or reordered by a future change, this function still writes a definite, function-decided value for every finding it processes rather than trusting whatever the object already carried.

**`line` field type widening.** `_llm_json_array_allowlist_fields`'s base contract keeps only string-valued fields (correct for `deferrals.json`, an all-string schema). Review findings' `line` field is legitimately a JSON number, so the function now accepts a `"fieldname:number"` suffix that declares that ONE field's type as number instead of string (a type declaration, not an added alternative — a string value under a `:number` field is dropped, never coerced; a JSON boolean is explicitly excluded from the numeric type even though Python's `bool` is an `int` subclass). See `scripts/platform.sh`'s updated docstring for the full contract.

**Field-provenance enumeration (why this fix is sufficient and complete).** Every field that can influence a blocking decision across Gate 3 and Gate 5, enumerated with its origin and validation mechanism:

| Field | Object | Origin | Validation before a blocking read | Forgeable |
|---|---|---|---|---|
| `severity` | review finding | raw LLM JSON | Enum-checked in `validate_output` (`scripts/llm-client.sh`); re-normalized case-insensitively by `severity_rank`/`rank()` (`scripts/gates.sh`) | No (closed enum) |
| `_recurrence_demoted`, `_recurrence_count` | review finding | raw LLM JSON (before this fix) / gates.sh-only (after) | `_sanitize_review_findings_envelope` strips both unconditionally at ingest; `_review_recurrence_demote` additionally owns both explicitly for every finding it touches | No (closed by ingest strip + own-the-field) |
| `file`, `line`, `category`, `message`, `evidence`, `suggestion` | review finding | raw LLM JSON | Reduced to exactly these keys (closed schema, alongside `issue_class`/`class_fix` below) by `_sanitize_review_findings_envelope`; `line` type-restricted to number, the rest to string | Not a blocking lever on their own; free text is unsanitized on this path (no `_llm_field_sanitize` call — this schema is not currently interpolated into a later prompt the way invariants/deferrals are, so the round-trip-injection concern that motivates `_llm_field_sanitize` elsewhere does not apply here; if a future change ever feeds review findings back into a prompt, that call site must add sanitization at that point) |
| `issue_class`, `class_fix` | review finding | raw LLM JSON | (lr-3eb18c) PRESENCE required by `validate_output` (`scripts/llm-client.sh`, reviewer role only — non-empty string, no enum check) before a chain step counts as a pass at all; reduced to these two keys (string-only) by `_sanitize_review_findings_envelope` at ingest, same as the other free-text fields above | Content is unsanitized free text, same posture as `message`/`evidence`/`suggestion` above — **never read by `severity_blockers()`** (see that function's own comment, `scripts/gates.sh`): mandatory presence, never a blocking lever, by explicit design (see "Class-level review findings" below) |
| `severity`, `reachable`, `tier`, `class`, `line` | adversarial finding | constructed by `_parse_adversarial_findings` from named regex capture groups into a fixed Python dict literal with exactly 8 keys (`scripts/gates.sh`) | Each enum-validated and force-corrected at parse time; the security-floor clamp (`reachable=="yes"` and severity high/critical → `tier` forced `"blocking"`) runs unconditionally after `class` resolves | No — this object is never a decode of attacker-supplied JSON, so no extra key (forged or otherwise) can exist on it at all; see "Every field in the parsed finding record, enumerated" under Gate 6 for the field-by-field detail |
| `file`, `category`, `message` (title) | adversarial finding | same fixed dict literal (free text from regex capture) | `_llm_field_sanitize` via `_sanitize_adversarial_findings_json` | No (sanitized; and, per above, no extra key can exist regardless) |

**Class-level review findings (lr-3eb18c).** Prior to this task, the Reviewer had no field for stepping back from an individual finding to the CLASS of issue it belongs to — `ds_review_prompt`'s own anti-vagueness instruction ("vague findings ... must be dropped") structurally discouraged exactly this kind of generalization, and the closed finding schema had no field to carry it even if the model volunteered one. Every finding now carries two additional required fields:

- **`issue_class`** — the recurring class this finding is an instance of, in a few words (e.g. "unbounded external call", "missing input validation on trust boundary"), or the literal string `"none — isolated"` when the finding is genuinely a one-off with no recognizable recurring shape.
- **`class_fix`** — a higher-level, structural change that would eliminate every instance of the class at once (not a fix for this one line), or `"n/a — isolated"` when `issue_class` is `"none — isolated"`.

**Mandatory but never blocking (settled, not relitigated in this task's PR).** `validate_output` (`scripts/llm-client.sh`) requires both fields to be present, non-empty strings on every finding for the reviewer role — an envelope missing either is treated as a schema violation exactly like a missing `.findings` array or an invalid `.severity`, which fails that chain step the same way any malformed response always has. What this does **not** do: `severity_blockers()` (`scripts/gates.sh`) never reads `issue_class`/`class_fix` at all — an unresolved or freshly-named class can never gate `/ship`, by construction, not by convention. This is deliberately the same shape as `_recurrence_demoted`/`_deferral_matched`'s own "threshold, not suppression" posture (see "Cross-round finding recurrence demotion" and "Gate-code deferral enforcement" above), inverted: those two fields can only ever *reduce* the blocker count; `issue_class`/`class_fix` never enter the count in either direction. `cmd_render_review` surfaces a non-`"none — isolated"` class on its own indented line so the answer is legible to the operator without adding noise to the (expected, honest) majority of genuinely isolated findings.

**Confabulation mitigation.** A required field invites a model to fill it with something, and `ds_review_prompt` itself names manufactured findings as the primary LLM-reviewer failure mode. `"none — isolated"` / `"n/a — isolated"` are explicit, named, first-class enum values in the prompt — the honest, cheap answer for a genuinely isolated finding is also the one-token answer, removing the incentive to invent a class to fill the field. The prompt explicitly scopes the existing per-finding vagueness rule (`ds_review_prompt`, "Vague findings ... must be dropped") away from these two fields: they are an attribute *of* an already-cited, already-passing finding, never grounds for a new uncited finding of their own, and never a substitute for the citation the underlying finding still requires.

The structural reason the two gates needed different treatment: the adversarial-findings path never decodes attacker-supplied JSON — it builds each finding as a code-controlled dict literal with a fixed key set, so an extra key cannot exist on the object at all (the `_llm_json_array_sanitize_fields`-only treatment `_sanitize_adversarial_findings_json` uses is safe *because* of this). The review-findings path decodes the model's own raw JSON response directly — a field set an attacker (or a manipulated/miscalibrated model) can freely add to — which is exactly the shape `_llm_json_array_allowlist_fields` exists to close (the same reasoning `docs/GATES.md` "Reviewer-consulted deferrals" already documents for `deferrals.json`, a different attacker-influenced-field-set case). Before this fix, review findings were the one remaining consumer of externally-authored JSON with no allowlist step — a third state alongside "closed code-controlled field set" (adversarial findings) and "allowlist-then-sanitize" (deferrals) that the standing invariant does not permit.

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

Reviewer prompt and JSON schema are inlined in `ds_review_prompt` (`scripts/llm-client.sh`), including its own Pre-Report Gate and Common False Positives list — matching the pattern `ds_adversarial_prompt` already uses for the Auditor's gate in the same file. The authoritative subagent doc for interactive/Claude Code use is `plugins/clagentic-lite/agents/reviewer.md`; that file lands at `.claude/agents/reviewer.md` only inside an enrolled consumer repo via plugin install, never in clagentic-lite's own working tree, so it is not a valid reference from this repo's source. Output is persisted at `.clagentic/lite/last-review.json` and into `audit.db.gate_runs`. Per-step LLM-call attempts are logged separately (`gate=llm-call`) with a one-line error hint from stderr.

The Reviewer never has write tools. The Builder never sees its own review pre-graded. The Reviewer prompt forbids "looks good to me" outputs without specific evidence.

## Gate 4 — Local security scan

Three independent sub-gates run as standard git hooks, plus a fourth
change-scoped pattern scan (internal-bleed):

### 4a. Secrets (pre-commit)

| | |
|---|---|
| **Tool** | `gitleaks git --staged --pre-commit --redact --no-banner` (8.18+) or `gitleaks protect --staged --redact --no-banner` (older). The orchestrator capability-probes via `gitleaks git --help` and picks the right surface. |
| **Blocks?** | Yes. Also blocks if gitleaks is missing entirely — set `CLAGENTIC_ALLOW_MISSING_GITLEAKS=1` to skip explicitly. |
| **Override** | None for findings — secrets cannot be committed. Rotate, then re-stage. |
| **Augment** | `.gitleaks.toml` in repo root extends the default ruleset. Path-scoped allowlists only (see `.gitleaks.toml` comment for why regex allowlists on token literals are dangerous). |
| **Timeout** | Every gitleaks invocation runs under `run_bounded` (default 300s, configurable via `CLAGENTIC_SECRETS_TIMEOUT_SEC`) — a full branch-history scan can legitimately take longer than a staged-only scan. A timeout counts as a block, same as a real finding. |

### 4b. Dependencies (pre-push)

| | |
|---|---|
| **Tool** | `osv-scanner scan --recursive --format=json --config=<tmpfile> .` (newer releases) or `osv-scanner --recursive --severity=<S> .` (older releases). Version probed by subcommand availability, not version string. |
| **Blocks?** | Yes, on vulnerabilities at or above the configured severity. Default is `CRITICAL`. |
| **Severity** | Set `CLAGENTIC_OSV_SEVERITY` in `~/.config/clagentic/config` or `.clagentic/config`. Values: `CRITICAL` (default), `HIGH`, `MEDIUM`, `LOW`. Set `LOW` to restore block-on-any-finding behavior. Newer releases no longer expose a scan-time severity filter, so clagentic-lite captures JSON and applies the threshold to osv-scanner's computed `max_severity` values. Missing or malformed severity data blocks fail-closed. |
| **Ignore list** | Add CVE/GHSA IDs one-per-line to `~/.config/clagentic/osv-ignore` (global) or `.clagentic/osv-ignore` (repo). Lines starting with `#` and blank lines are ignored. For newer releases, these become `[[IgnoredVulns]]` blocks in the generated temp config; for older releases, they are passed as `--ignore-vulns=<id>`. |
| **Missing tool** | Set `CLAGENTIC_ALLOW_MISSING_OSV=1` to skip if osv-scanner is not installed. |
| **Timeout** | Every osv-scanner invocation runs under `run_bounded` (default 300s, configurable via `CLAGENTIC_OSV_TIMEOUT_SEC`) — the vulnerability-DB lookup is a network call. A timeout counts as a block. |

### 4c. SAST (pre-push)

| | |
|---|---|
| **Tool** | `semgrep --config=auto --error --severity=ERROR`, scoped with `--baseline-commit=<merge-base>` when a baseline can be resolved (see below) |
| **Blocks?** | Yes, on ERROR. `--error` makes semgrep exit non-zero only on ERROR-severity findings; WARNING-and-below findings still print but don't block. |
| **Override** | `.semgrepignore` at the repo root (natively honored by semgrep — add file paths or rule IDs to suppress); `# nosemgrep: <rule-id> — <reason>` inline in source; the rule-exclude ladder below. |
| **Missing tool** | Set `CLAGENTIC_ALLOW_MISSING_SEMGREP=1` if semgrep is not installed locally. |
| **Baseline fetch timeout** | `CLAGENTIC_SAST_FETCH_TIMEOUT_SEC` (default 30). Bounds both the `git fetch` and the `git ls-remote` freshness check used to resolve the baseline commit (see below) — expiry falls back to full-tree, same as any other resolution failure. |
| **Scan timeout** | Every semgrep invocation runs under `run_bounded` (default 300s, configurable via `CLAGENTIC_SAST_TIMEOUT_SEC`) — `--config=auto` downloads rules over the network on top of running the scan itself. A timeout counts as a block, same as an ERROR-severity finding. |

**Rule-exclude ladder (lr-321e18).** `cmd_sast` had zero repo-side override
surface for a single unsatisfiable registry rule — one false-positive
finding (e.g. `python.sqlalchemy.security.sqlalchemy-execute-raw-query`,
which rejects even injection-safe parameterized/`sql.Identifier`
composition) forced multi-round review churn with no sanctioned escape.
Fixed by mirroring `cmd_deps`' osv-ignore mechanism (above) exactly
(reuse-first): a two-level, one-rule-id-per-line exclude list, unioned
across both levels —

- `~/.config/clagentic/semgrep-exclude` (global)
- `.clagentic/semgrep-exclude` (repo, **committed** — unlike `.clagentic/`'s
  other contents, this one file is un-ignored in `.gitignore` the same way
  `.clagentic/adversarial-acks.json` is, because it is tracked policy, not
  local runtime state)

`#` comments and blank lines are stripped the same way osv-ignore's parser
tolerates them. Each active rule id becomes an `--exclude-rule <id>` flag on
**both** the baseline-commit and full-tree semgrep invocations —
`_sast_exclude_rule_flags` (`scripts/gates.sh`) builds the flag list once,
and both call sites reuse it.

**Visibility: a suppressed rule is never silent.** When the ladder resolves
at least one exclusion, `cmd_sast` echoes the excluded rule ids to stderr
(`[gates/sast] excluding N rule(s): <id1>,<id2>,...`) and folds the same
count/id list into the `gate_runs.details` audit column for both the pass
and block outcome branches.

**Pinned config (`CLAGENTIC_SEMGREP_CONFIG`).** Set this env var (or the
matching repo-config key) to a committed policy path to replace
`--config=auto` outright — `_sast_config_flag` (`scripts/gates.sh`) builds
`--config <path>` instead, and semgrep's registry (`auto`) is never
contacted. **The default remains `auto` when the var is unset or empty** —
`clagentic-lite` ships to other people; a specific repo's rule-tuning
preferences (like this repo's own exclude entry above) are a per-repo
opt-in, never a value hardcoded into `gates.sh` itself. With no exclude
files and no `CLAGENTIC_SEMGREP_CONFIG` set, `cmd_sast`'s semgrep argv is
byte-identical to the pre-lr-321e18 invocation — this is the load-bearing
no-regression property the ladder and the config override are both built
around.

**Baseline scoping (lr-06b87e).** A plain `semgrep --config=auto` with no path argument scans the entire working tree on every run, so pre-existing findings in files the current branch never touched get attributed to that branch and block the gate — a full-tree scan is punished the same as a real regression. `cmd_sast` (`scripts/gates.sh`) narrows this with semgrep's own `--baseline-commit=<ref>`, which reports only findings introduced relative to that commit (semgrep, not clagentic-lite, computes the diff — this correctly follows moved/changed-context findings the way a path-restricted or full-tree-plus-filter approach cannot).

The baseline is `git merge-base origin/<default-branch> HEAD`. Baseline scoping activates only when **every** one of these holds:

- The installed semgrep supports `--baseline-commit` (probed via `semgrep --help`, not a version-string parse).
- `HEAD` is not detached and not on `${CLAGENTIC_DEFAULT_BRANCH}` itself (nothing to baseline a default-branch run against).
- `git fetch origin <default-branch>` exits 0 within the configured timeout (see below) — a failed or timed-out fetch is never treated as harmless, because `origin/<default-branch>` may already exist locally from a prior run.
- The freshly-fetched `origin/<default-branch>` tip matches an independent `git ls-remote origin <default-branch>` read of the same remote, taken in this same run.
- `git merge-base` succeeds and returns a commit (fails on a shallow clone that never fetched the base, or unrelated histories).

**Freshness is a precondition, not an assumption.** An earlier version of this gate fetched `origin/<default-branch>` non-fatally (`|| true`) on the theory that a fetch failure would simply make the later `merge-base` fail too, falling back safely. That reasoning had a gap: if `origin/<default-branch>` already existed locally from a *prior* successful fetch, this run's fetch failure left that stale tracking ref in place, and `rev-parse`/`merge-base` both succeeded against it anyway. If the default branch had been force-pushed or rewritten upstream since that last successful fetch, the stale ref could resolve to a merge-base *closer to HEAD* than the true one — silently narrowing the diff-introduced window while the gate reported a normal-looking verdict with a plausible `baseline-commit=<sha>` and no visible error. This is a **successful-looking wrong resolution**, not a failure, so it slipped past every fallback keyed on "did the command error."

The fix treats a resolved `origin/<default-branch>` ref as trustworthy only when it is **provably current**: the fetch must exit 0 (not time out, not fail any other way) *and* the resulting local tip must match a fresh, independent `git ls-remote` read of the same remote taken in the same run. "We have some ref" is not sufficient on its own — a fetch can exit 0 against a stale mirror/cache, or race a concurrent upstream rewrite between the fetch and the later `merge-base` call. Comparing two independent reads of the remote tip is what establishes currency rather than mere presence.

**Fetch is time-bounded.** `git fetch` and `git ls-remote` both run under `$DS_TIMEOUT_CMD` (the same portable-timeout mechanism `scripts/llm-client.sh` uses for every LLM CLI call), so a stalled network operation — DNS timeout, TCP stall, an auth prompt hanging against a private remote — cannot hang this blocking security gate indefinitely; `set -e` alone does not bound execution time. The timeout defaults to 30 seconds and is configurable via `CLAGENTIC_SAST_FETCH_TIMEOUT_SEC`. A timed-out fetch is treated identically to a failed fetch — it is not a third case with its own behavior.

**Offline / air-gapped runs.** A repo with no reachable `origin` (or a fetch that consistently times out) falls back to full-tree on every run — this is the correct, intended consequence of the freshness requirement above, not a bug: a gate that cannot prove its baseline is current must not narrow the scan. A slower, full-tree gate is an acceptable outcome; a silently narrowed security gate is not.

**Fail-closed, not fail-narrow.** Any one of the above conditions failing — old semgrep, detached HEAD, on the default branch, a fetch that fails or times out, a resolved ref that disagrees with the independent `ls-remote` freshness check, or a failed merge-base (including shallow clones) — falls back to the exact prior full-tree `semgrep --config=auto --error --severity=ERROR` behavior, and blocks on whatever it finds. The gate never silently narrows to an empty or partial scan on a resolution failure; a scoping bug degrades to "noisier, but still safe," never to "quietly stops checking." The active mode and, when full-tree, the reason baseline scoping was unavailable are both logged to stderr and the `gate_runs.details` audit column.

Rationale: deterministic tools, well-understood, no LLM in the security path. The LLM-driven `adversarial` layer (Gate 5) is separate and non-blocking by design.

### Every external-process invocation is bounded (INV-4)

`scripts/gates.sh`'s `run_bounded` wrapper is the single entry point every gitleaks, osv-scanner, semgrep, `git push`, `gh pr view`, and `gh pr create` invocation runs through — a call site that bypasses it stands out as visibly different from every sibling. Each tool gets its own configurable default (`CLAGENTIC_SECRETS_TIMEOUT_SEC`, `CLAGENTIC_OSV_TIMEOUT_SEC`, `CLAGENTIC_SAST_TIMEOUT_SEC`, `CLAGENTIC_SHIP_TIMEOUT_SEC`; unnamed sites fall back to `CLAGENTIC_EXTERNAL_TIMEOUT_SEC`, default 120s) because a full branch-history gitleaks scan or a rule-downloading `semgrep --config=auto` legitimately needs more headroom than a quick `gh pr view` check.

**This bound is only as real as the timeout binary underneath it.** `$DS_TIMEOUT_CMD` (`scripts/platform.sh`) resolves to `timeout` or `gtimeout` when either is on PATH; when neither is present, it resolves to `ds_timeout_missing`, which refuses to run the wrapped command at all (distinct exit status 99) rather than silently running it unbounded. Every timeout in this codebase — this section's, Gate 4c's fetch timeout, and the LLM per-call timeout `scripts/llm-client.sh` uses — depends on this guarantee; see AGENTS.md § Invariants, INV-1a.

### 4d. Internal-bleed scan

| | |
|---|---|
| **Fires** | `scripts/gates.sh bleed`; part of `gates ship`'s blocking sequence |
| **Tool** | `grep -lIf` against a change-scoped file set, using a repo- or user-supplied pattern file |
| **Blocks?** | Yes, on any pattern match. Opt-in: skips non-blocking when no pattern file is configured. |
| **Pattern file** | `.clagentic/bleed-patterns` (repo-level, checked first) or `~/.config/clagentic/bleed-patterns` (global). BRE, one pattern per line; `#` comments and blank lines ignored. |
| **Exclusions** | `.clagentic-bleed-ignore` (repo root, one path-substring per line); `.git/` and `.clagentic/` are always excluded. |
| **Full-scan escape hatch** | `scripts/gates.sh bleed --full-scan`, or automatic whenever a change-scoped resolution can't be established (see below). |
| **Branch-diff fetch timeout** | `CLAGENTIC_BLEED_FETCH_TIMEOUT_SEC` (default 30). Bounds both the `git fetch` and the `git ls-remote` freshness check used to verify the branch-diff baseline (see "Branch-diff freshness" below) — expiry falls back to full-tree, same as any other unverifiable-baseline outcome. |

**Scoping (lr-caebc5).** This gate used to run `git ls-files` against the whole repo on every invocation — every tracked file, every run, with no relation to what changed. The three sibling gates already scope to the change under review (secrets: staged diff or branch history, above; SAST: merge-base baseline, above; merge-gate: staged diff or branch diff, below) — bleed was the outlier. It now follows this fallback ladder:

1. Staged files (`git diff --cached --name-only`), when the index is non-empty.
2. Otherwise, the current branch's diff against `origin/${CLAGENTIC_DEFAULT_BRANCH}` (default `main`), when a usable branch baseline exists (not detached HEAD, not on the default branch itself) **and** that ref can be shown to be provably current (see "Branch-diff freshness" below).
3. Otherwise (fresh repo, no staged changes, no usable branch baseline, or a branch baseline that could not be verified current), full tree — this is the fallback path, not the default.

**This is NOT the same fallback `cmd_secrets` uses.** `cmd_secrets`' feature-branch fallback (Gate 4a's `gitleaks git` history scan) runs over the current branch's local commit *history* — it never resolves or diffs against a remote ref at all. Step 2 above instead resolves `origin/<default-branch>` and diffs the file set against it, which is the same shape as `cmd_sast`'s `--baseline-commit`/merge-base mechanism above, not `cmd_secrets`' history scan.

**Branch-diff freshness.** Step 2's `origin/<default-branch>` resolution shares the exact freshness precondition `cmd_sast` uses (`_gate_resolve_fresh_default_branch_ref` in `scripts/gates.sh`, extracted as the common helper both gates call): a bare `git rev-parse --verify` proves only that a local tracking ref *exists*, not that it is *current*. A present-but-stale ref is a successful-looking wrong resolution — it exits 0 and produces a plausible file set — so on a long-lived clone fetched once and never refreshed, a bleed pattern committed to the default branch afterward would be invisible to a scope trusting that stale ref, and the gate would report an authoritative-looking clean pass. The fix: `git fetch origin <default-branch>` under a timeout (`CLAGENTIC_BLEED_FETCH_TIMEOUT_SEC`, default 30s, mirroring `CLAGENTIC_SAST_FETCH_TIMEOUT_SEC`), trusted only when it exits 0 *and* the resulting local tip matches an independent `git ls-remote origin <default-branch>` read taken in the same run. On a stale-or-unverifiable baseline the gate fails toward **more** coverage, never less — it falls back to the full-tree scan (step 3), exactly like `cmd_sast`. Narrowing to the branch diff requires a positively-verified fresh baseline; see "Freshness is a precondition, not an assumption" above for the full rationale (BOBBIE, lr-caebc5 follow-up to lr-06b87e).

A pattern-file change is also detected and forces a full scan regardless of the above: a newly added or edited pattern can match content in files the current diff never touches, so treating a pattern-file edit like any other narrow diff would risk silently missing an old, already-committed hit the new pattern is meant to catch. `--full-scan` is available as an explicit override for the same reason. Deletions in a diff-scoped file list are skipped (nothing left to grep); the active scope and the reason full-tree was used, when applicable, are both logged to stderr and the `gate_runs.details` audit column.

## Gate 5 — Adversarial pass

| | |
|---|---|
| **Fires** | `/review --adversarial`; `scripts/gates.sh adversarial` |
| **Tool** | Auditor role via `scripts/llm-client.sh adversarial` |
| **Blocks?** | No — Gate 5 itself is commentary only. A finding's `tier` field can make Gate 6 (Merge Gate) refuse — see "Reachability requirement" and "Blocking vs advisory" below. `gates.sh ship` runs it as `cmd_adversarial \|\| true` (an explicit, deliberate opt-out, not an accidental default — see "Exit codes" below). |
| **Output** | Markdown attack scenarios saved to `.clagentic/lite/last-adversarial.md`; structured findings (same data, machine-readable) saved to `.clagentic/lite/last-adversarial-findings.json`; attach to PR if interesting |

The Auditor argues, in concrete terms, how a hostile user could exploit each new or modified input surface. Cites file:line. Names threats with CWE if obvious. If nothing is exploitable, says so in one sentence and lists the surfaces considered.

The Auditor prompt (`plugins/clagentic-lite/agents/auditor.md`, and the `ds_adversarial_prompt` heredoc in `scripts/llm-client.sh` — both surfaces carry the same material, since a non-Claude CLI chain step never has the agent `.md` file in context) carries a Pre-Report Gate, severity calibration, and a false-positive list, mirroring the Reviewer's (Gate 3). This exists because an uncalibrated adversarial pass is the dominant cause of repeated review bounces: real-but-unexploitable findings — a vulnerable-looking function nothing calls, a CWE pattern-match with no named attacker input — carried the same blocking weight as a live exposure. See "Reachability requirement" below for the mechanism that fixes this.

**Auditor tool restriction (lr-8a28e0).** This gate's LLM invocation (the `TOOL_ROLE=auditor` chain step reached via `cmd_adversarial`, `scripts/gates.sh`) receives ONLY a diff on stdin (`ds_adversarial_prompt`) and never invokes `gitleaks`/`semgrep`/`osv-scanner` itself — those are Gate 4's deterministic sub-gates, run directly by `gates.sh`'s own shell code, independent of any LLM call (AGENTS.md §4: "Do not add LLM calls to the blocking path of any security check"). Because this specific invocation has no genuine execution need, it now carries the SAME Read/Grep/Glob-no-Bash restriction Gate 3 applies to the Reviewer — on `claude`, `--allowedTools Read,Grep,Glob --disallowedTools Bash`; on `codex`, `--disable shell_tool -s read-only` — via the same `ds_llm_role_is_bash_unrestricted` predicate (`scripts/platform.sh`) both roles now share.

**This does NOT restrict `plugins/clagentic-lite/agents/auditor.md`**, the separate interactive Claude Code subagent a human/session invokes directly to actually run `gitleaks protect`/`osv-scanner`/`semgrep` and narrate their output. That subagent's Bash access is governed by Claude Code's own subagent `tools:` frontmatter (a security-tool-scoped allowlist, not a blanket grant) — a structurally different mechanism from `--allowedTools`/`--disallowedTools` on `claude --print`/`codex exec`, untouched by `ds_llm_role_is_bash_unrestricted` or by this restriction. The two "Auditor" names in this repo cover genuinely different invocation surfaces with genuinely different execution needs; conflating them was the accident lr-8a28e0 corrects, not a reason to restrict the subagent too.

### Exit codes for `gates.sh adversarial`

`cmd_adversarial` (lr-7047bf) checks the Auditor chain's own outcome, not just whether it produced findings — a fully-dead auditor (auth broken, CLI not on PATH, every chain step timed out) used to write a degraded markdown envelope indistinguishable from "nothing to report," and the merge gate downstream read that as a clean audit.

| Exit code | Meaning | Action |
|---|---|---|
| `0` | Auditor ran; markdown + findings sidecar written (`gate_runs` outcome `warn`, non-blocking by design) | Review findings if any; attach interesting ones to the PR |
| `2` | `INFRA_DEGRADED` — every Auditor chain step failed; degraded envelope written; no real audit occurred (`gate_runs` outcome `degraded`) | Check LLM CLI config/auth and retry |

`build_gate_summary` independently surfaces this to the Merge Gate as `adversarial_degraded: true` in the gate-summary payload — a dead auditor is now distinguishable from a clean pass at every downstream consumer, not just at `cmd_adversarial`'s own exit status.

### Finding format (prose-primary with structured header)

Each finding in the adversarial output begins with a compact header line, followed by a prose explanation:

```
[FINDING] CWE-XXX | file.ext:line | severity: high | reachable: yes | tier: blocking | class: durable | title: Short description phrase

Prose explanation (1-3 paragraphs): what the vulnerability is, how an
attacker exploits it (or why it cannot currently be exploited, if
reachable: no), and what a minimal fix looks like.
```

Header fields:

| Field | Values |
|---|---|
| `[FINDING]` | Literal tag; always the first token on the header line |
| CWE | Most specific CWE Base-level ID (e.g. `CWE-78`); `CWE-unknown` if not applicable |
| file:line | Specific file and line number (e.g. `scripts/gates.sh:42`); `general` if not file-specific |
| severity | `critical` / `high` / `medium` / `low` |
| reachable | `yes` / `no` — see "Reachability requirement" below |
| tier | `blocking` / `advisory` — see "Blocking vs advisory" below |
| class | `durable` / `ephemeral` (lr-4f8316) — see "Change class" below |
| title | One short phrase, eight words or fewer |

This is a "prose-primary with structured header" format: the header makes the output scannable at a glance; the prose below it preserves the full adversarial explanation. If the model does not emit `[FINDING]` headers (format mismatch, older model), the prose output is still valid and usable — the format is additive, not a schema enforcement. `reachable`/`tier`/`class` are themselves optional at the parser level for the same reason (see "Parser default" below) — an older-format header without them still parses.

For a heavier, structured threat-model pass, use the `/infosec-rt` skill instead — multi-persona chained attack scenarios with hardening priority list.

### Reachability requirement

Every finding states whether the vulnerable code is actually reachable from an external or attacker-influenced surface:

- **`reachable: yes`** — the vulnerable code is in the live import/call graph from an external or attacker-influenced entry point, or the finding is a live credential/secret. The Auditor cites the concrete call path or trigger.
- **`reachable: no`** — the pattern exists in the diff, but nothing currently calls it with attacker-controlled input, it is gated behind a condition an attacker cannot reach, or it is example/test/fixture code. Real, but not exploitable today.

This is the mechanical precondition for blocking eligibility (see "Blocking vs advisory" next): a finding cannot be `tier: blocking` unless it is `reachable: yes`, regardless of the severity the Auditor assigns it. `_parse_adversarial_findings` (`scripts/gates.sh`) enforces this at the parser level, not just the prompt level — it force-corrects `tier` to `advisory` whenever the parsed `reachable` value is not exactly `yes`, so a miscalibrated model cannot cause a block by stating a high tier without reachability.

`severity` is enum-validated the same way: `_parse_adversarial_findings` accepts only `low`/`medium`/`high`/`critical` (case-normalized) and force-corrects any other captured text to the sentinel `unknown`. `severity_rank()` (`scripts/gates.sh`) ranks `unknown` at `0`, below every real severity level, so an unrecognized value can never inflate its own rank anywhere severity is later compared. This closes a gap a follow-up review caught: `severity` was originally captured as unvalidated free text bounded only by the next `|` in the header line — the identical round-trip exposure `_llm_field_sanitize` closes for `file`/`category`/`message` (see "Round-trip sanitization" under Gate 6), just left open on this one field until the fix.

### Blocking vs advisory — threshold, not suppression

**This is a threshold mechanism: every finding is reported at its honest severity and stays fully visible in the adversarial markdown output, the structured findings sidecar, and the audit trail, regardless of `tier`.** `tier` only decides whether Gate 6 (Merge Gate) treats a finding as gating `/ship`. Nothing is ever hidden, dropped, or omitted from output because of its tier.

A finding is `tier: blocking` only when reachability is `yes` (with a cited concrete exploit path) **and** severity is `high` or `critical` **and** it is not a durability-dependent concern excused by an `ephemeral` change class (see "Change class" below). Every other finding — `reachable: no`, or severity `medium`/`low`, or excused by class — is `tier: advisory`.

**Mechanical plumbing, not LLM judgment at gate time.** `cmd_adversarial` (`scripts/gates.sh`) unconditionally loose-parses the `[FINDING]` headers into `.clagentic/lite/last-adversarial-findings.json` (not gated behind `CLAGENTIC_ADVERSARIAL_INVARIANTS` — this sidecar is a base behavior). `build_gate_summary` reads that sidecar and adds fields to the gate-summary payload fed to the Merge Gate:

- `adversarial_findings` — the full structured array (file, line, category/CWE, message, severity, reachable, tier, class)
- `adversarial_blocking_count` — count of `tier: "blocking"` findings, computed mechanically (same pattern as `severity_blockers()` counting review findings by rank rather than asking an LLM to recount)
- `adversarial_advisory_count` — count of `tier: "advisory"` findings
- `resolved_change_class` (lr-4f8316) — `"ephemeral"` if any finding declares `class: "ephemeral"`, else `"durable"` if there is at least one finding, else `null` on a clean pass with no findings
- `adversarial_downgraded_by_class_count` (lr-4f8316) — see "Change class" below

The Merge Gate prompt (`ds_merge_gate_prompt`) is instructed to refuse only on `tier: "blocking"` findings not covered by `adversarial-acks.json`/`accepted-risks.md`, and to note advisory findings — including class-downgraded ones — in its `reason` text without gating on them. If `adversarial_findings` is empty or absent (e.g. a gate run predating this feature, or a model that emitted no parseable `[FINDING]` headers), the Merge Gate falls back to reasoning over the `adversarial` markdown prose directly, as it did before this change.

**Parser default (fail-open on the non-blocking side).** `reachable`/`tier`/`class` are optional at the parser level for backward compatibility with an older header (`severity | title`, no `reachable`/`tier`/`class`) or a model that omits them despite the prompt instruction. An unparseable or absent `tier` is classified `advisory`, never `blocking` — a parser gap can only ever under-block. An unparseable or absent `class` is classified `durable`, never `ephemeral` — the same fail-closed direction on the class axis, since `durable` is the class that never relaxes anything; a parser gap can only ever leave the full bar in place, never silently grant a downgrade. The finding is still fully visible in the markdown output and the sidecar; it simply cannot gate the merge on its own, or receive a class-based downgrade, if the classification is missing.

**Deterministic gates are untouched.** None of this changes `cmd_secrets`, `cmd_deps`, `cmd_sast`, or their fail-closed behavior (Gate 4). The advisory/blocking split applies only to LLM-driven adversarial findings, which were already, and remain, outside the security-gate path — AGENTS.md §4: no LLM in the security path.

### Change class — durability-aware blocking threshold (lr-4f8316)

Gates review all code as if it ships forever by default. That is usually right, but it is a category error for a one-shot migration script or a k8s Job stood up for a single task and documented for decommission — an internal-only, run-once process does not carry the same durability risk a persistent service does.

**Vocabulary:**

| Class | Meaning | Threshold effect |
|---|---|---|
| `durable` (default) | Ships and stays | None — full bar applies |
| `ephemeral` | One-shot, time-boxed, or throwaway: a migration script, a k8s Job (not a Deployment) with a documented decommission path, a change confined to `tests/`/`migrations/`, a one-shot `main()` that exits | Relaxes the blocking threshold for durability-dependent findings only (see below) |

**Inferred from the diff, not maintained in a file.** The Auditor (and Reviewer, for the mismatch case) infers the class from the diff itself — path, structure, lifecycle shape, any stated decommission date. There is deliberately no operator-maintained context file: it is a second source of truth that goes stale the moment the ephemeral thing is decommissioned, and the diff is already read for every other finding.

**Builder hint, diff wins.** The Builder may declare a class as a one-line `Change-class: <value>` trailer in the tip commit message (`plugins/clagentic-lite/agents/builder.md`). `_change_class_hint` (`scripts/llm-client.sh`) extracts it via `git log -1 --format=%B` and surfaces it to the Reviewer and Auditor as a `BUILDER-DECLARED CHANGE-CLASS HINT` note ahead of the diff — a claim to weigh, never the source of truth. If the diff contradicts the declared class, the diff wins and the mismatch itself becomes a reported finding (`CWE-unknown`, `maintainability`-shaped). Degradation is clean by construction: no declaration infers from the diff; a wrong declaration is overridden and the override is visible. There is no separate enforcement mechanism — the mismatch finding is the enforcement.

Why commit message and not PR body: clagentic-lite is zero-server by design (no GitHub/Forgejo API call anywhere in the review/adversarial pipeline — `get_review_diff` only ever produces `git diff` output). A commit-message trailer is git-native, requires no network call, and is visible to a local `gates review`/`gates adversarial` run exactly the way a PR-hosted trailer would be once that commit lands.

**Threshold only, never suppression.** A finding whose *sole* basis is a durability-dependent concern (unbounded resource growth in a process that runs once and exits, missing retry/backoff/observability hardening that only matters across a long service lifetime) rides `tier: advisory` instead of `tier: blocking` under an `ephemeral` resolved class — but only when it does NOT also meet the security-floor bar below (`reachable: yes` at severity high/critical). It is still reported at its honest severity, fully visible in the markdown, the sidecar, and the audit trail regardless of tier. Class never suppresses a finding and never alters reported severity.

**Security floor is absolute regardless of class — and this is mechanically enforced, not LLM self-restraint (lr-4f8316 follow-up).** `_parse_adversarial_findings` (`scripts/gates.sh`) applies a second, unconditional clamp after `class` is resolved: any finding with `reachable: "yes"` AND severity `high`/`critical` is force-corrected to `tier: "blocking"`, regardless of what tier value the model wrote and regardless of `class`. Mirrors the existing reachability clamp's structure (same function, same posture) — see "Every field in the parsed finding record" below for the exact predicate. This is the mechanically enforceable translation of "live credentials, reachable injection sinks, real exploit paths block in every class": the parser has no field that directly encodes "is a credential" or "is a real exploit path" — `reachable` (a cited concrete exploit path/trigger, per the Auditor's Pre-Report Gate) and severity high/critical (the Auditor's own judgment that this is a live, serious exposure) are the closed-form proxy for that intent, given the fields actually available. Ephemeral does not mean unsafe — it means unbounded resource growth in a job that runs once and dies is not a defect the same way it would be in a long-lived service, and that distinction lives entirely below the floor.

**`adversarial_downgraded_by_class_count`** (in `build_gate_summary`'s payload and the `merge-gate`/`merge-gate recheck` audit row as `[class=... downgraded=N]`) is a mechanical proxy: a count of findings with `class: "ephemeral"`, `tier: "advisory"`, `reachable: "yes"`, and severity `high`/`critical`. Because of the security-floor clamp above, a finding produced by the real parser can never actually have this exact combination (`reachable: "yes"` + high/critical would have been force-corrected to `tier: "blocking"`) — the count is computed independently by `build_gate_summary` reading whatever JSON is on disk in `last-adversarial-findings.json`, as a defense-in-depth cross-check that should always read `0` for any sidecar the real parser produced. A nonzero value here is itself a signal worth investigating: either the sidecar was populated by something other than `_parse_adversarial_findings`, or the clamp has regressed.

### Invariant-feed (opt-in) — forward-invariant memory across rounds

| | |
|---|---|
| **Feature flag** | `CLAGENTIC_ADVERSARIAL_INVARIANTS` (default: `0` — off; set `=1` to opt in) |
| **File location** | `.clagentic/lite/invariants.json` (gitignored, local gate state — same convention as `last-review.json` and `review-seen-keys`) |
| **Effect** | When present and the flag is set, the file is sanitized (see "Write-boundary sanitization" below) and injected into the adversarial system prompt inside a fenced `===BEGIN/END INVARIANTS DATA===` block with an inverted instruction relative to reviewer deferrals: "these invariants must still hold — verify the diff against each" instead of "these findings are deferred, do not re-report." |
| **Fail-open** | Absent, empty, or unreadable file → the pass proceeds with no invariants. Never blocks — Gate 5 is non-blocking regardless. |
| **Population** | Automatic. When a finding resolves — present in one round, absent from the next round's diff-covered findings — the writer distills its message + category into an invariant statement and appends it to the file. See "Invariant-feed writer" below. |

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

### Invariant-feed writer — auto-population (lr-63359e)

The writer is the counterpart to the read/injection half above: it populates `invariants.json` automatically as findings resolve, so the feed does not require operator hand-authoring to be useful end-to-end.

**Resolve signal — reused, not reinvented.** The writer does not maintain an independent notion of "this finding is fixed." It reuses the content-hash key space `dedup_findings`/`_cross_round_dedup` already persist (`.clagentic/lite/review-seen-keys` for the review gate; a new `.clagentic/lite/adversarial-seen-keys` for the adversarial gate, since adversarial did not otherwise participate in cross-round key tracking). Each round, the writer snapshots the seen-keys file *before* that round's `dedup_findings` call adds the round's own keys, runs the same content-hash key derivation (`finding_content_keys` in `scripts/review-merge.sh`) against this round's live findings, and treats any key present in the snapshot but absent from the live set as resolved. This does not change `_cross_round_dedup`'s suppression behavior — it is a read-only comparison that runs after dedup completes, against a separate snapshot, and the file it writes (`invariants.json`) is never read back by `dedup_findings`.

**Two input shapes, one key space:**

- **Review findings** — already structured JSON (`severity`/`file`/`line`/`category`/`message`); no parsing needed.
- **Adversarial findings** — unstructured markdown `[FINDING] CWE-XXX | file:line | severity: <level> | reachable: <yes|no> | tier: <blocking|advisory> | title: <phrase>` headers; loose-parsed into the same `{file,line,category,message}` shape (`category` becomes the CWE id) — plus `reachable`/`tier` (lr-e2b975), carried through for the advisory/blocking split but not part of the content-hash key itself — before running through the identical key derivation.

**Distillation is mechanical, not an LLM call.** The writer is gate plumbing, not a role — it prefixes the resolved finding's message with a fixed "must not recur, including at a wider scope" framing rather than asking a model to paraphrase. The Auditor's own prompt instructions (in `ds_adversarial_prompt`) already tell it how to use an invariant statement; the writer's job is just to get the original finding text into the file.

**Gating.** The writer only runs when `CLAGENTIC_ADVERSARIAL_INVARIANTS=1` — the same flag that gates the read half. Writing invariants nobody reads would be dead state.

**Unbounded-growth guard.** `invariants.json` dedupes on `(file, statement)` at append time — resolving the same finding class again in a later round is a no-op, not a duplicate entry — and is capped at `CLAGENTIC_INVARIANT_FEED_MAX` total entries (default 200), dropping the oldest entries first. This is a deliberate irony guard: the invariant-feed exists partly to catch unbounded-growth findings (see the round-4/round-6 fail-open-scope-widening case in the synthetic replay test), so its own storage must not grow without bound.

**Write-boundary sanitization (lr-cda4b9, generalized lr-e2b975).** `category`, `file`, and the distilled `statement` written to `invariants.json` all ultimately trace back to adversarial- or review-LLM-controlled finding text — a compromised/manipulated model, or attacker-influenced code under audit that steers model output, could plant a prompt-injection payload in a finding's message that later round-trips into a future adversarial system prompt. `_invariant_feed_append` (the sole writer) is a single choke point: every field is run through `_llm_field_sanitize` before being written, which

- strips ANSI/terminal escape sequences and other control/non-printable bytes (tab and newline preserved),
- defangs literal occurrences of the delimiter labels (`INVARIANTS:`, `DEFERRED FINDINGS:`, `END INVARIANTS`, `END DEFERRED FINDINGS`, and both fenced marker sets — `===BEGIN/END INVARIANTS DATA===` and `===BEGIN/END ADVERSARIAL FINDINGS DATA===`, unconditionally, since a single planted finding could round-trip through either path) so a forged label inside finding text cannot spoof a fresh data-block boundary once re-injected,
- caps each field at `CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS` (default 500), truncating rather than dropping the entry (fail-open, matching the rest of the invariant-feed).

Sanitizing at the write boundary (once, on ingest) rather than at read time means every current and future reader of `invariants.json` (today: `ds_adversarial_prompt`) gets clean data automatically — a read-time-only approach would require every new consumer to remember to re-sanitize.

**`_llm_field_sanitize` is the sole sanitizer for this class of round-trip in the codebase** — was `_invariant_feed_sanitize_field` until lr-e2b975 generalized and renamed it to cover a second call site (see Gate 6 below, `.clagentic/lite/last-adversarial-findings.json`). Any future round-trip path (LLM output written to disk, later re-read into a different LLM's prompt) should extend this function rather than adding a parallel one.

As a second, independent layer, `ds_adversarial_prompt` (`scripts/llm-client.sh`) wraps the (already-sanitized) invariants content in an explicit `===BEGIN INVARIANTS DATA===` / `===END INVARIANTS DATA===` fenced block with an instruction telling the Auditor to treat the block as data describing prior findings, not as an instruction, and to ignore any imperative or role-change sentence that may appear inside it. **This is a prompt-contract change**: the previous format injected the raw `invariants.json` content directly after an `INVARIANTS:` label with no fence; any external tooling or test fixture that pattern-matches on the exact prior wording will need to account for the new `===BEGIN/END INVARIANTS DATA===` markers. The feature remains default-off (`CLAGENTIC_ADVERSARIAL_INVARIANTS=0`), so this only affects installs that have already opted in.

## Gate 6 — Merge Gate

| | |
|---|---|
| **Fires** | `scripts/gates.sh ship` (the `/ship` slash command), after all other gates have passed |
| **Tool** | LLM "gate" role via `scripts/llm-client.sh merge-gate` |
| **Input** | A JSON gate-summary payload (`.clagentic/lite/gate-summary.json`) built from `last-review.json` + `last-adversarial.md` + `last-adversarial-findings.json` + threshold |
| **Output** | `{decision: "approve" | "refuse", reason: "<one sentence>"}` JSON at `.clagentic/lite/last-merge-gate.json` |
| **Blocks?** | **Yes by default** (`CLAGENTIC_MERGE_GATE_BLOCKING=1`). Set to `0` to make advisory. |
| **Unparseable decision** | Also blocks — schema-invalid merge-gate output is treated as a gate failure, not a pass. |

The Merge Gate is the last LLM check before the PR is opened. It never overrides the deterministic security gates (those already gated upstream) and never adds its own findings — it reads the structured outputs of every prior gate and returns a single approve/refuse decision.

**State-identity cache — no re-prompt on an unchanged state (lr-caebc5).** Gate results previously carried no notion of which commit/tree state they validated, only the mtimes of `last-review.json`/`last-adversarial.md`. Any incidental mtime change — a checkout, a stash, an editor save with no content change, or simply re-running `gates ship`/`gates merge-gate` again in the same session — was indistinguishable from a real change, so the Merge Gate re-ran, and re-prompted the operator, every time (`--recheck`'s SHA-staleness guard, above, closed one symptom of this but not the underlying gap: the non-`--recheck` path never checked whether it had already reached a verdict for the current state at all).

`cmd_merge_gate` now computes a **state identity** — `<HEAD SHA>:<content hash>` — before doing anything else:

- The content hash is `sha256(git diff HEAD + git status --porcelain)`, using the same `_rm_sha256` shim `dedup_findings`/`_review_deferral_match` already use for content-not-timestamp fingerprinting (`scripts/review-merge.sh`). `git diff HEAD` captures staged and unstaged changes to tracked files; `git status --porcelain` captures untracked files. Neither reads a file's mtime.
- A commit SHA alone would be insufficient: a dirty working tree is the normal state while iterating, not an edge case, and two dirty trees on the same commit can differ. The content hash makes a dirty tree representable as its own distinct, cacheable state.
- Every `pass` merge-gate audit row is stamped with `[state=<identity>]` in `gate_runs.details` (visible via `gates.sh status`/`gates.sh tail`, per Gate 6's own audit convention). Before doing any work, `cmd_merge_gate` looks up the most recent `merge-gate`/`merge-gate recheck` row; if its outcome is `pass` and its stamped state identity matches the current one, the invocation is a no-op — it reports the cached pass (from `last-merge-gate.json` if present) and returns without calling the LLM, without touching `gate-summary.json`, and without any new prompt to the operator.
- Only a stored **pass** short-circuits. A stored `refuse` never does — a real refusal always requires the operator to act (fix the code, or re-run after a real change), so it is never silently bypassed by invoking `gates merge-gate` again.
- mtime is never an input to this check anywhere in the codepath — only `git diff`/`git status --porcelain` content and `git rev-parse HEAD`.

This closes the operator-facing complaint directly: run the gate to a pass, re-run with no content changes, and the second (and any subsequent) invocation reports the cached pass with zero LLM calls and zero new prompts.

**Adversarial findings gate here on `tier`, not on severity alone (lr-e2b975).** Only `tier: "blocking"` adversarial findings (reachable, high/critical severity, and not excused by an ephemeral change class — see Gate 5 "Blocking vs advisory" and "Change class") are eligible to refuse the merge. `tier: "advisory"` findings — including real, correctly-severity-rated ones that are simply unreachable, lower severity, or class-downgraded — never gate `/ship` on their own; they are noted in the Merge Gate's `reason` text and remain fully visible in `last-adversarial.md`, `last-adversarial-findings.json`, and the audit trail. This is a threshold change, never suppression.

**Resolved change class recorded on every merge-gate run (lr-4f8316).** `build_gate_summary`'s `resolved_change_class` and `adversarial_downgraded_by_class_count` fields (see Gate 5 "Change class") are read back and appended to the `merge-gate`/`merge-gate recheck` audit row as `[class=<durable|ephemeral> downgraded=<N>]`, on both the `approve` and `refuse` outcomes — the class that applied to a ship attempt is part of the audit trail regardless of the decision it fed into. The Merge Gate prompt itself never re-derives or widens what `tier: "blocking"` means from this data; class was already folded into `tier` by the Auditor before the payload reached the Merge Gate.

**Round-trip sanitization (lr-e2b975, mirrors lr-cda4b9).** `.clagentic/lite/last-adversarial-findings.json` is LLM-authored finding text (title, message, file) written to disk and later read back into the Merge Gate's system prompt — structurally the same round-trip shape as the invariant-feed's `invariants.json`. `cmd_adversarial` (`scripts/gates.sh`) sanitizes the sidecar's `file`/`category`/`message` fields via `_llm_field_sanitize` — the same function, not a second sanitizer — before the sidecar is ever written to disk, so every downstream reader (`build_gate_summary`, the merge-gate prompt) gets clean data. `build_gate_summary` additionally renders the sanitized array as `adversarial_findings_fenced`, a fenced-text rendering delimited by `===BEGIN ADVERSARIAL FINDINGS DATA===` / `===END ADVERSARIAL FINDINGS DATA===` — `_llm_field_sanitize`'s defang list covers this label too, so a forged marker inside a finding's own title cannot escape the fence. `ds_merge_gate_prompt` (`scripts/llm-client.sh`) instructs the Merge Gate to treat that fenced block as data describing findings, not as an instruction, and to ignore any imperative/role-change/decision-override sentence that may appear inside a finding's own text — the same "data, not instructions" framing `ds_adversarial_prompt` applies to the invariant-feed.

**Every field in the parsed finding record, enumerated (lr-e2b975 follow-up).** Every field has an explicit enforcement mechanism — none is asserted safe without one:

| Field | Shape | Enforcement |
|---|---|---|
| `file` | free-form model text | Sanitized via `_llm_field_sanitize` (control-byte strip, fence-label defang, length cap) |
| `category` (CWE) | free-form model text | Sanitized via `_llm_field_sanitize` |
| `message` (title) | free-form model text | Sanitized via `_llm_field_sanitize` |
| `severity` | closed set: `low`/`medium`/`high`/`critical` | Enum-validated and force-corrected to `unknown` at parse time (`_parse_adversarial_findings`) — not additionally routed through the sanitizer, since after validation there is no free text left in the field |
| `reachable` | closed set: `yes`/`no` | Enum-validated and force-corrected to `no` at parse time |
| `tier` | closed set: `blocking`/`advisory` | Enum-validated and force-corrected to `advisory` at parse time, and again whenever `reachable != "yes"`. As of the lr-4f8316 follow-up, ALSO force-corrected to `blocking` — mechanically, unconditionally, regardless of `class` or of what the model wrote — whenever `reachable == "yes"` AND `severity` is `high`/`critical`. This is the security-floor clamp: it is not LLM self-restraint, it is a parser-level guarantee |
| `class` (lr-4f8316) | closed set: `durable`/`ephemeral` | Enum-validated and force-corrected to `durable` at parse time — the class that never relaxes the blocking threshold, so a parser gap can only ever leave the full bar in place, never silently grant a downgrade. `class` CAN influence `tier` for durability-only, non-floor-eligible findings, but can never override the security-floor clamp above — the clamp runs unconditionally after `class` is resolved |
| `line` | integer | Parsed via Python `int()`; a non-numeric suffix falls back to `0`. Never a pass-through of the raw captured string |

Every field lands in one of three buckets: free-text-and-sanitized, closed-set-and-force-corrected-at-parse-time, or non-text-by-construction. `severity` was the one field that fell through this classification for a period — captured as free text but never enum-checked, the identical fence-escape shape already closed for the other three text fields — until a follow-up review caught it.

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

**Concurrent writers and the busy timeout (lr-c71845).** Every `sqlite3` invocation against `.clagentic/lite/audit.db` inside `scripts/gates.sh` and `scripts/platform.sh` (`ds_audit_log`) routes through one shared wrapper, `ds_sqlite3` (`scripts/platform.sh`), which prepends `-cmd ".timeout N"` — SQLite's own busy-retry mechanism — so a writer that finds the database locked (e.g. two gate runs racing) retries for up to `N` milliseconds instead of failing immediately with `SQLITE_BUSY`. `N` is configurable via `CLAGENTIC_SQLITE_BUSY_TIMEOUT_MS` (default `5000`), validated through `ds_positive_int_or_default` — an unset, non-numeric, or zero value falls back to the default rather than silently disabling the busy wait. This mirrors `run_bounded`'s unwritable-bare-form pattern: every call site in this codebase goes through the named wrapper, so a future bare `sqlite3 "$AUDIT_DB" ...` call would be visibly different from every sibling. Out of scope for this fix, and a real follow-up worth filing separately: SQLite's default rollback-journal mode still serializes writers even with a busy timeout in place (only one writer proceeds at a time; the timeout just makes the second one wait instead of failing) — WAL mode (`PRAGMA journal_mode=WAL`) would let readers and a single writer proceed concurrently and is the more complete fix for write contention, but is a schema/mode migration with its own compatibility considerations (older SQLite versions, network filesystems) and was intentionally not bundled into this change.

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

### Audit-vocabulary lint — `scripts/gates.sh audit-vocab-lint [FILE]`

`cmd_log_run <gate> pass "<details>"` is a promise: this gate ran and found nothing wrong. Several gates historically logged `pass` with a details string that itself names a reason the underlying tool never actually scanned anything — `git ls-files failed`, `no package sources found`, an empty pattern file. That is a contradiction between the outcome label and its own explanation, and it is invisible to anyone reading the audit trail without also reading the gate's source.

`audit-vocab-lint` (default target: `scripts/gates.sh` itself) scans for `cmd_log_run <gate> pass "<details>"` calls whose details string contains a failure word (`failed` / `not found` / `empty` / `no package sources` / `skipped` / `unavailable`) and reports them. **Warn-only, non-blocking, never exits non-zero** — it does not rewrite any gate's behavior. Existing violations are enumerated in an explicit `_KNOWN_VIOLATIONS` allowlist inside `cmd_audit_vocab_lint`, keyed on the exact `(gate, details)` pair; a genuinely new violation (a different gate, or the same gate with reworded details) is reported separately from the known backlog rather than silently absorbed. `warn`-outcome rows are deliberately out of scope — a `warn` already signals "not fully clean" honestly (e.g. cross-round dedup's "splice failed; original findings retained"); the lie this lint targets is specifically a `pass` outcome contradicting itself.

Not wired into `gates ship`'s blocking sequence — it is diagnostic output, run manually or from a maintenance script.

## Working around gates — use config, not code edits

**Do not edit hook source files or gate scripts to bypass a blocking rule.** The right path is always a config variable, an ignore file, or a native tool mechanism. The table below covers every supported bypass. All bypasses are visible in the audit trail.

| Gate | Situation | How to handle it |
|---|---|---|
| Gate 4a — secrets | False-positive token | Add a path-scoped allowlist entry to `.gitleaks.toml`. Do not use regex allowlists on token literals. |
| Gate 4b — deps | Pre-existing CVE you accept | Add the ID to `.clagentic/osv-ignore` (repo) or `~/.config/clagentic/osv-ignore` (global). One ID per line. |
| Gate 4b — deps | Want to ignore below CRITICAL | Set `CLAGENTIC_OSV_SEVERITY=HIGH` (or `MEDIUM`) in `.clagentic/config`. |
| Gate 4c — SAST | False-positive semgrep rule | Add the file path to `.semgrepignore`, or add `# nosemgrep: <rule-id> — <reason>` inline. |
| Gate 4c — SAST | Slow/unreliable network makes the baseline fetch time out, forcing full-tree scans | Set `CLAGENTIC_SAST_FETCH_TIMEOUT_SEC=<seconds>` (default 30) in `.clagentic/config`. A longer timeout only helps if the fetch would otherwise succeed — an unreachable remote still falls back to full-tree regardless of the timeout value, by design. |
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
