# Optional: clagentic-router integration

Everything in the main README and `docs/GATES.md` describes the **gate
path**: `CLAGENTIC_<ROLE>_CMD`/`_TIER`/`_CHAIN`, `invoke_<cli>`, all of it
controlling `scripts/llm-client.sh`, invoked by `clagentic-lite gates
review`/`ship`/etc. It does not touch the **interactive path**: when you
dispatch a subagent (Reviewer, Auditor, …) via Claude Code's own Agent/Task
tool mid-session, that dispatch goes straight to Anthropic (or wherever
`ANTHROPIC_BASE_URL` points), never through `llm-client.sh`. clagentic-lite
is not Claude Code's parent process, so there is no interception point on
that path short of Claude Code's own `settings.json`.

[clagentic-router](https://github.com/clagentic/clagentic-router) is a
separate, optionally-run local proxy that closes this gap. **It is not
installed or started by clagentic-lite — you run it yourself**, and it is
not a single switch: there are **three independent opt-ins** below. Turning
one on does not turn on the others, and one of the three is currently
unverified while another is documented here specifically because enabling
it without reading this page has caused a measured, silent quality
regression (see "Gate-path routing" below).

Read this page top to bottom before enabling any of the three. Each section
states what it turns on, what it does **not** turn on, and its current
verification status.

---

## 1. `CLAGENTIC_ROUTER_URL` — interactive-session passthrough

**What it turns on.** When set, `clagentic-lite enroll`/`update` stamps an
`env` block into the enrolled repo's `.claude/settings.json`
(`ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN`) so Claude Code — including
interactive subagent dispatch — routes every request through the router. In
passthrough mode (the default, no per-role chain reference) this is a
transparent reverse proxy; your session behaves exactly as it does today.
clagentic-router also supports *routed* mode: reference a named chain
(`role:reviewer-chain`, matching `router.example.yaml` in the
clagentic-router repo) and the router picks a backend per its own
scoring/fallback policy instead of forwarding straight to Anthropic.

**What it does NOT turn on.** By itself, `CLAGENTIC_ROUTER_URL` only wires
the settings.json passthrough. It does not change gate-path behavior (see
§3) and it does not change subagent model selection (see §2) — those are
separate keys.

**Verification status.** Verified-safe. The passthrough itself carries no
open questions; only §2 (agent-model injection) is unverified.

**`CLAGENTIC_ROUTER_URL` is validated before it is ever stamped.** This
value redirects your entire Claude Code session and, in passthrough mode,
forwards your real Anthropic credentials to whatever host it names — it is
a traffic-interception primitive, not an ordinary config string.
`clagentic-lite enroll`/`update`/`doctor` all validate it the same way:

- **Malformed** (not a well-formed `http://` or `https://` URL) —
  **refused**. Enroll/update stop with an error rather than stamping a
  value that would silently break every session opened against the repo
  afterward.
- **Well-formed, non-local host** (anything other than exactly `localhost`,
  `0.0.0.0`, a real `127.0.0.0/8` address, or `::1`/`[::1]`) — **allowed,
  but warned loudly**, at both stamp time and every `clagentic-lite doctor`
  run, naming exactly what gets forwarded. The router is designed to run
  locally (this is why every example below uses `127.0.0.1`), but running
  it on another box on your own LAN is a legitimate setup, not a mistake —
  so this is a warning, not a refusal. A silent accept would be the wrong
  failure mode here: an operator should never discover after the fact that
  their credentials have been going to a remote host they forgot they
  configured.
- **Well-formed, local host** — silent, same as any other correctly-configured
  value.

The host check parses the URL structurally (strips RFC 3986 userinfo, e.g.
`user:pass@`, before ever looking at the host; matches `127.0.0.0/8` by
real numeric octet range, not a string prefix) rather than pattern-matching
the raw string — `http://127.0.0.1:x@evil.com/` and
`http://127.0.0.1.evil.com/` both correctly classify as non-local
(evil.com), not local. Any host form the check does not confidently
recognize (IPv4-mapped IPv6 like `[::ffff:127.0.0.1]`, non-decimal IP
encodings) is treated as non-local — a false "non-local" costs one warning
line, a false "local" would silently forward real credentials, so
ambiguity always resolves toward the warning. This classifier
(`ds_router_url_classify`, `scripts/platform.sh`) is the one shared
implementation both `bin/clagentic-lite` and `scripts/llm-client.sh` use —
see §3 for the gate path's stricter application of the same check.

**Setup:**

```sh
# 1. Run clagentic-router (see that repo's README for build/run instructions).
#    It listens on 127.0.0.1:8765 by default.

# 2. Set the two config keys (~/.config/clagentic/lite/config or .clagentic/config):
CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765
CLAGENTIC_ROUTER_TOKEN=<your router's proxy.token / CLAGENTIC_ROUTER_TOKEN>

# 3. Re-run enroll (or update) so settings.json picks up the env block:
clagentic-lite enroll --force    # per enrolled repo
# or: clagentic-lite update --restamp

# 4. Verify:
clagentic-lite doctor            # probes GET /version, reports reachable/unreachable
```

### Bedrock-mode sessions (worked example, not the assumed backend)

**Bedrock-mode sessions need a second variable pair — the direct-API pair
above does NOT work for them.** If you run Claude Code with
`CLAUDE_CODE_USE_BEDROCK=1` (e.g. an AWS SSO profile), it ignores
`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN` entirely and speaks the AWS
Bedrock Runtime `InvokeModel` wire protocol instead. Setting
`CLAGENTIC_ROUTER_URL` alone will look like it worked (`clagentic-lite
doctor` reports the router reachable) while every Bedrock-mode session
silently never talks to it — no error, no warning, nothing routed. Set a
third config key to fix this:

```sh
CLAGENTIC_ROUTER_BEDROCK_MODE=1
```

When set (alongside `CLAGENTIC_ROUTER_URL`), `enroll`/`update` additionally
stamp `ANTHROPIC_BEDROCK_BASE_URL` (the Bedrock-mode equivalent of
`ANTHROPIC_BASE_URL`) and `AWS_BEARER_TOKEN_BEDROCK` (a bearer-token
alternative to full AWS SigV4 signing — Claude Code's documented
["Option E: Amazon Bedrock API
keys"](https://code.claude.com/docs/en/amazon-bedrock)) into the same `env`
block, reusing `CLAGENTIC_ROUTER_TOKEN` verbatim as the Bedrock bearer
token. `AWS_BEARER_TOKEN_BEDROCK` is not optional: without it, Bedrock-mode
Claude Code signs requests with full SigV4 instead of a bearer token, which
fails the router's auth check and 401s even though
`ANTHROPIC_BEDROCK_BASE_URL` correctly pointed traffic at the router.

Both pairs are stamped together, not one instead of the other — a single
`settings.json` may be opened by sessions running in either auth mode
(direct API/OAuth vs. Bedrock), and each mode only reads the pair it
understands. `CLAGENTIC_ROUTER_BEDROCK_MODE` is validated through the exact
same `CLAGENTIC_ROUTER_URL` classifier and atomic settings-stamp writer as
the direct-API pair — it stamps the same URL value into a second variable
name, not a second independently-configured URL.

This is one worked example among however many backends and auth modes you
run in practice — clagentic-router itself is backend-agnostic; chains are
operator-defined in `router.example.yaml`. Bedrock gets a worked-through
example here only because the failure mode (`InvokeModel` silently
ignoring `ANTHROPIC_BASE_URL`) is a real trap, not because it's the
intended or default backend.

---

## 2. `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL` — agent-model injection (UNVERIFIED)

**What it turns on.** `CLAGENTIC_ROUTER_URL` alone gets you the
settings.json passthrough above with no further risk. This second,
independent key additionally causes `clagentic-lite init`/`update` to
render the Reviewer/Auditor/Merge-Gate subagent definitions with `model:
role:<role>-chain` injected into frontmatter (matching
`router.example.yaml`'s `reviewer-chain`/`auditor-chain` examples). There
is exactly one `clagentic-lite` plugin at all times — this key changes what
that ONE plugin's render looks like, it does not install a second plugin
alongside it (pre-lr-1b5a31 versions installed a separate
`clagentic-lite-router` overlay plugin; that design is retired — `update`
on an older install automatically detects and removes the stale overlay).
The checked-in `plugins/clagentic-lite/agents/*.md` files are never
modified on disk — only a generated copy under
`$CLAGENTIC_LITE_HOME/.clagentic/rendered-plugin/` is, and that generated
copy is what actually gets installed via `claude plugin install`.

**What it does NOT turn on.** It does not affect the gate path (§3) at
all — the gate path's model selection is controlled entirely by
`CLAGENTIC_<ROLE>_VIA_ROUTER`, independent of this key. It only changes
what frontmatter the interactive subagent definitions render with.

**Verification status: explicitly UNVERIFIED.** Whether Claude Code
actually honors a subagent frontmatter `model:` field set to a
non-standard string like `role:reviewer-chain` — versus silently ignoring
it and dispatching the subagent on the parent session's own model — has
not been confirmed against a live interactive session from this codebase.
This is [claude-code
GH#44385](https://github.com/anthropics/claude-code/issues/44385)
territory: that issue reports subagent frontmatter `model:` being ignored
in some contexts. **Leave `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL` unset until
you've run the verification below at least once.**

### Verifying on your machine

This is the one part of the router integration that could not be tested
from this development environment (no route to a fresh interactive Claude
Code session or a local HTTP capture listener from a crew-dispatched
build). Run this on a real machine with `claude` installed:

1. Stand up a minimal capture listener, e.g. `python3 -m http.server 8765`
   in a scratch directory, or any tool that logs the raw HTTP request it
   receives (headers + body).
2. In a scratch repo (or the wrapper CLAUDE.md dir), enroll with the
   router pointed at your capture listener and injection turned on:
   ```sh
   CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765 CLAGENTIC_ROUTER_TOKEN=test-token \
     CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1 CLAGENTIC_REVIEWER_CMD=codex \
     clagentic-lite enroll --force
   ```
3. Open a fresh interactive Claude Code session in that repo (a plain
   session — not something that itself intercepts the request).
4. Dispatch the Reviewer subagent (e.g. ask it to review a diff, or invoke
   it directly via the Task/Agent tool).
5. Inspect what your capture listener received:
   - **The `model` field in the request body, verbatim.** If it reads
     `role:reviewer-chain`, the injection point works as designed. If it
     reads a normal model alias/ID (e.g. `claude-sonnet-4-6`), Claude Code
     silently ignored the frontmatter field and fell back to the parent
     session's model — this is the GH#44385 failure mode. Either way,
     record what you saw as a comment on lr-49f25e (or the equivalent
     follow-up task) so the next person doesn't have to re-run this.
   - **Which auth header arrived**: `x-api-key` or `Authorization: Bearer
     <token>`. clagentic-router's routed-mode auth
     (`internal/server/messages.go` in that repo) accepts either, keyed off
     the same token value — but confirming which one Claude Code actually
     sends closes a documentation gap on the router side too, independent
     of the model-field outcome.
6. If the model field does NOT arrive verbatim: do not "fix" this by
   editing the router or the injection code to compensate — file a task
   naming the concrete alternative injection point (the Task/Agent tool's
   own `model` parameter, if callable with a custom string; or accept that
   this specific mechanism has no equivalent for interactive dispatch and
   scope it back to gate-path-only). Leave
   `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL` off in your own config either way
   until it's confirmed working.

---

## 3. `CLAGENTIC_<ROLE>_VIA_ROUTER` — gate-path routing

**What it turns on.** A third, distinct integration point from the two
above (both of which affect an *interactive* Claude Code session).
`CLAGENTIC_<ROLE>_VIA_ROUTER=1`, scoped to exactly two role literals —
`reviewer`, `auditor` — makes `scripts/llm-client.sh`'s `walk_chain` POST
to `${CLAGENTIC_ROUTER_URL}/v1/messages` (`invoke_router`, model
`role:<role>-chain`) instead of shelling out to `CLAGENTIC_<ROLE>_CMD` for
that role's gate-path calls (`clagentic-lite gates review`/`ship`/etc.).
Requires `CLAGENTIC_ROUTER_URL` to also be set — this key alone does
nothing.

**Merge-Gate is excluded (`lr-250d9d`, correcting `lr-02f048`).**
`CLAGENTIC_GATE_VIA_ROUTER` still exists as a config key so `doctor` can
warn on it, but setting it to `1` has **no effect** — `gate` was removed
from `_llm_role_routable`'s enumeration. The original `lr-02f048` task
justified routing reviewer/auditor/gate together on the claim that all
three are "already tool-restricted and single-shot" on both CLI carriers.
That is true for reviewer and auditor. It was **false for gate**: the
merge-gate's direct-CLI invocation holds **unrestricted Bash** and does
**real multi-turn tool-calling** (`ds_llm_role_is_bash_unrestricted`,
`scripts/platform.sh`, returns `true` for `gate` — the same predicate that
makes `invoke_claude` skip the `--allowedTools`/`--disallowedTools`
restriction for it). Routing gate would have silently converted a
Bash-capable, multi-turn merge-authorization step into a one-shot,
tool-free text completion, logged as an ordinary `pass` row
indistinguishable from a full-capability run — `invoke_router` never sends
a `tools` key at all (§ "Repo-scoping" below), so there was nothing in the
wire protocol that would have surfaced the loss. A loud warning at call
time was considered and rejected: it would tell an operator, after the
fact, that a merge had already been authorized by a gate that could not
run Bash — the one gate whose entire job is the final check before code
lands on the default branch. Gate now shares the same fail-closed answer
Builder already has: excluded from the routable set entirely, not merely
labeled when the capability loss occurs.

**What it does NOT turn on.** Unset (either the per-role key or
`CLAGENTIC_ROUTER_URL`), this path is **byte-for-byte inert** — the
pre-existing direct-CLI chain runs unmodified. It has no effect on the
interactive path (§1, §2) either way.

**Interaction with `CLAGENTIC_<ROLE>_CHAIN`/`_TIER`.** These become
**no-ops** for a routed role — they are only consulted by the Layer 2
fallback below, never by the router path itself while the router is
reachable. `clagentic-lite doctor` warns when a role has both
`CLAGENTIC_<ROLE>_VIA_ROUTER=1` and a `CLAGENTIC_<ROLE>_CHAIN`/`_TIER`
configured, since leaving them set is not wrong but is worth surfacing
rather than silently ignoring.

**Verification status.** Live in production use. This path was previously
implicated in a measured, silent quality regression — routed roles lost
filesystem access to the repo under review (Reviewer/Auditor calls made
via this path reached the model with no filesystem access; measured
review block rate fell 10-40% → ~0%). **This is now fixed** — see
"Repo-scoping via `working_dir`" below — but the regression class it
belongs to is worth understanding before you enable this switch for
`reviewer`/`auditor` on a repo whose reviews you rely on.

**Builder and Merge-Gate are both deliberately excluded, for the same
reason.** Both hold unrestricted Bash and do real multi-turn agentic
tool-calling; every clagentic-router adapter currently declares
`SupportsTools=false` (`lr-be9454`), so a tool-bearing routed request gets
refused (422), not silently degraded — a defense Builder/Merge-Gate never
reach because they never route in the first place. Reviewer/Auditor are
already tool-restricted and single-shot on both CLI carriers
(`invoke_claude`'s `--allowedTools`/`--disallowedTools`, `invoke_codex`'s
`--disable shell_tool -s read-only`) and never send a `tools` field either
way, so routing them carries no tool-drop risk.

### Repo-scoping via `working_dir` (lr-4a6268) — FIXED, read this before relying on it

**The regression, precisely.** `invoke_router` (`scripts/llm-client.sh`)
builds its POST body from only the prompt and the diff text. Combined with
a bug in clagentic-router itself (its `codex_cli` adapter never set the
spawned subprocess's cwd, so it inherited the router daemon's own cwd —
fixed upstream as `lr-009423`), every gate-path call made with
`CLAGENTIC_REVIEWER_VIA_ROUTER=1` / `CLAGENTIC_AUDITOR_VIA_ROUTER=1`
reached the model with the diff text only and **no filesystem access to
the repo under review**. This was silent: no error, no timeout, no gate
failure — reviews simply got worse. Measured impact on project-coldest-tea:
block rate on active days fell from a historical 10-40% to 0% (0/25) the
day router opt-in went live, ~4% the next day. Closest miss: a PR passed
review with zero findings and failed CI seven minutes later on a missing
transitive dependency — exactly the class of finding that requires reading
a caller and a CI config a diff-only reviewer cannot see.

**The fix.** `invoke_router` now sends `working_dir: <REPO_ROOT>` in every
routed request body, where `REPO_ROOT` is the same absolute, already
git-resolved path every other repo-scoped operation in `llm-client.sh`
uses (`CLAGENTIC_PROJECT_ROOT` if set, else `git rev-parse
--show-toplevel`). clagentic-router's `/v1/messages` endpoint honors
`working_dir` **in routed mode only** (the gate path's mode — passthrough
mode never decodes it) and sets it as the spawned CLI subprocess's cwd
across all four subprocess adapters, replacing the daemon-inherited/
hardcoded-`/` defaults the regression above depended on.

**Fail-loud, not silent, on rejection.** clagentic-router validates
`working_dir` server-side (must be absolute, must exist, must be a
directory) and responds 4xx on a bad value rather than silently ignoring
it or exec'ing elsewhere. `invoke_router` detects a 4xx response whose body
mentions `working_dir`/`WorkingDir` and writes a distinctly labeled
diagnostic line to the gate's error log naming the rejection explicitly —
never folded into the generic "router responded non-200" hint. This
remains **non-blocking for the gate itself**: exactly like every other
`invoke_router` failure mode, a rejected `working_dir` falls through to
Layer 2 (direct-CLI fallback, see below), logged and loud, never a silent
degrade back to the pre-fix behavior.

**Residual limitation, NOT solved by this field — do not document this
away.** Routed mode remains one-shot text-in/text-out with no tool loop
(clagentic-router's own documented non-goal). `working_dir` helps only
insofar as the CLI reads the filesystem during its single turn — this is
**not equivalent** to the direct-CLI path (`invoke_codex`), which runs
from a process whose cwd is already the enrolled repo across a real
multi-turn tool loop. A routed Reviewer/Auditor can now `cat` a caller or
a CI config in its one turn; it still cannot open a second file after
reading the first one and deciding it needs more context.

### Layer 0 — URL validation, never conflated with Layer 2 unreachability

Before `invoke_router` ever opens a connection, it runs
`CLAGENTIC_ROUTER_URL` through `ds_router_url_classify`
(`scripts/platform.sh`) — the same classifier `bin/clagentic-lite` uses at
stamp/probe time (§1). A **malformed** URL is refused outright: no curl
invocation is made at all, so the bearer token is never even placed in a
curl argument. A **nonlocal** URL (well-formed, but not
localhost/127.0.0.0/8/::1) is also refused for the gate path specifically —
this is a deliberate, stricter posture than the interactive-session stamp
check (§1, which allows nonlocal with a warning, since an operator running
clagentic-router on another LAN box is a legitimate interactive setup they
explicitly configured into `settings.json`). The gate path has no
equivalent human-in-the-loop moment: `walk_chain` runs unattended inside a
merge gate, so a nonlocal target here is treated as indistinguishable from
misconfiguration-or-attack rather than a judgment call to warn-and-proceed
on. Both cases write a distinct `router-refused` outcome to `audit.db` and
print a loud stderr line naming the refusal reason (malformed vs.
nonlocal) — **never** the `router-fallback` label Layer 2 uses, because
"this URL looks like exfiltration, refusing to send credentials" and "the
router process is down" are different conditions an operator must be able
to tell apart from the log alone. Refusal at Layer 0 is non-blocking for
the gate itself: exactly like a Layer-2 event, it falls through to the
pre-existing direct-CLI chain rather than failing the whole gate — a
malformed/misconfigured router integration must not be able to block every
merge, but it also must never be silently indistinguishable from "router
happened to be offline right now."

### Layer 1/Layer 2 fallback, deliberately distinguishable

The router itself may fall back internally between backends within a
`role:<role>-chain` (its own scored/health-aware policy) — that is Layer 1,
entirely internal to the router process and invisible to clagentic-lite by
construction; the router's own `/logs` is the source of truth for it.
Layer 2 is different: the router itself is unreachable or degraded at call
time, so `walk_chain` falls back to the pre-existing direct-CLI chain
instead of blocking. Layer 2 is logged to `audit.db` with outcome
`router-fallback` — a label distinct from the direct-CLI loop's own
`pass`/`fallback`/`step-failed`/`degraded` outcomes, so a query against
`audit.db` can tell "the router advanced internally" (not represented here
at all) apart from "this gate bypassed the router entirely" (a
`router-fallback` row) apart from "the direct-CLI chain itself also
failed" (the loop's own rows, unchanged). Layer 2 also prints a loud,
explicitly-labeled stderr warning naming the difference, so collapsing the
two into one ambiguous "fallback" notice — the exact failure mode a
router-down-for-a-week scenario would hide behind — cannot happen
silently.

### No self-healing

`walk_chain`'s router path only ever makes one `invoke_router` attempt and
reports the result; it never restarts, respawns, or retries a router
process from inside the gate. The gate is on the critical path of a merge —
adding restart-and-retry would turn a fast, clean failure into a slow,
ambiguous one, and would require handing a restricted role the ability to
start processes. Health-probe-and-loudly-report is the whole contract;
process supervision belongs to the router's own deployment.

### Logging parity

Router-path calls write to the same per-repo `audit.db` `gate_runs` table
as every other `llm-client.sh` call (`log_attempt`), with `details`
carrying `<role>:router:role:<role>-chain` on the happy path —
distinguishable from a direct-CLI row's `<role>:<cli>:<tier>` shape by the
literal `router` CLI field, so the existing audit trail (and `clagentic-lite
show gates`) stays the complete picture for both paths without a second
log destination.

### Config

```sh
CLAGENTIC_REVIEWER_VIA_ROUTER=0
CLAGENTIC_AUDITOR_VIA_ROUTER=0
CLAGENTIC_GATE_VIA_ROUTER=0   # kept for `doctor` to warn on; always a no-op — see "Merge-Gate is excluded" above
```

See `share/config.example`'s router section for the full commented config
surface (`$CLAGENTIC_LITE_HOME/share/config.example` once installed).

---

## Honest limitation across all three

Routed roles lose tool-calling and true streaming through
clagentic-router's CLI adapters — fine for a one-shot pass that only reads
a diff and returns text, wrong for a role that needs to read/write files
or run commands mid-conversation. Do not point the Builder role through
the router — this is why §2's frontmatter injection still touches
Reviewer/Auditor/Merge-Gate (it changes what model a subagent's
frontmatter *names*, not whether the gate path routes), but §3's gate-path
switch touches only Reviewer/Auditor: Merge-Gate needs the same
tool-calling Builder does on the direct-CLI path (§3 "Merge-Gate is
excluded"), so it stays off §3's routable set even though §2's injection
key still applies to it.

---

## See also

- `README.md` § "Optional: clagentic-router integration" — short operator
  blurb and pointer here.
- `docs/DESIGN.md` § "The interactive-path gap, and how clagentic-router
  closes it" and § "Gate-path routing (`CLAGENTIC_<ROLE>_VIA_ROUTER`)" —
  the same three integration points from an architecture-documentation
  angle: why they exist, why they're structured this way. This page is the
  operator-facing companion, not a replacement.
- `docs/LLM-USAGE.md` § "Optional: clagentic-router" — checklist form for
  an LLM/agent setting this up on someone else's behalf.
- `share/config.example` — canonical, commented list of every router
  config key.
