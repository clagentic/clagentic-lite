# LLM-USAGE.md — operating clagentic-lite on a user's behalf

This file is for an LLM (Claude, Codex, or any other coding-assistant CLI/agent)
that is setting up or operating clagentic-lite **for a user**, inside a chat or
agentic session. It assumes you can run shell commands and read their output,
and that the user does not know — and will not tell you — that any of this
setup is required. Do not ask the user "have you run `enroll`?" — check, and if
not, run it (steps 3 and 8 below tell you exactly how).

If you are a human reading this instead: it is still accurate, just written in
imperative/checklist form rather than narrative. `README.md` has the narrative
version with more "why."

Every command and file path below is verified against `bin/clagentic-lite`,
`install.sh`, `share/config.example`, and `share/hook-shims/` in this repo, not
inferred. If your local checkout's behavior disagrees with this file, trust the
source and file a docs bug.

---

## Preconditions — check these before doing anything else

1. **Is clagentic-lite installed at all?**

   ```sh
   command -v clagentic-lite
   ```

   Empty output or "not found" → not installed. Go to [Step 1](#step-1-install-the-tool-once-per-machine).
   A path printed → installed. Skip to [Step 2](#step-2-confirm-config-exists).

   Do not assume install because you see a `clagentic-lite` binary somewhere in
   the repo tree (e.g. `bin/clagentic-lite` inside a cloned checkout that isn't
   on `PATH`). The check above is the only one that reflects what the user's
   shell can actually invoke.

2. **What is `$CLAGENTIC_LITE_HOME`?**

   ```sh
   echo "${CLAGENTIC_LITE_HOME:-<unset>}"
   ```

   If unset, the effective value is `${CLAGENTIC_HOME:-$HOME/.clagentic/lite}`
   — `bin/clagentic-lite` resolves it that way at the top of the script. If the
   user has `CLAGENTIC_HOME` set (the old name), the tool still honors it but
   prints a one-time deprecation warning to stderr on every invocation until
   `CLAGENTIC_LITE_HOME` is set explicitly. If you see that warning in command
   output, tell the user to add `export CLAGENTIC_LITE_HOME=...` (or unset
   `CLAGENTIC_HOME` and let the default apply) to their shell rc — do not
   silently keep using the deprecated name across a session.

3. **Is the current project enrolled?**

   ```sh
   clagentic-lite list
   ```

   This prints every enrolled repo with its last-gate-run status. Compare
   against the current working directory's git toplevel
   (`git rev-parse --show-toplevel`). Not listed → not enrolled → nothing is
   gated here, no hooks fire, Claude Code sees no agents or slash commands for
   this repo, and there is no audit trail. This is the single most common gap:
   a user asks you to "run the security check" or "review this diff" in a repo
   that was never enrolled, and every clagentic-lite command either errors or
   silently no-ops. Check this before doing any gate-related work, every
   session, even if you enrolled this same repo in a previous session — a
   fresh clone of an already-clagentic-managed repo is NOT automatically
   enrolled; enrollment state lives in `~/.local/state/clagentic/registry` on
   this machine, not in the repo.

---

## Step 1 — Install the tool (once per machine)

There is no package manager and no standalone installer script —
`install.sh` at the repo root is a deliberate stub that only prints a redirect
message and exits 1 (it existed as a real installer in clagentic-lite v0.1;
the flow changed in v0.2 to clone-once + per-repo enroll). The **real**
install is a git clone plus running the CLI's own `init` subcommand:

```sh
HOME_DIR="${CLAGENTIC_LITE_HOME:-$HOME/.clagentic/lite}"
if [ -d "$HOME_DIR/.git" ]; then
  git -C "$HOME_DIR" pull --ff-only
else
  git clone https://github.com/clagentic/clagentic-lite.git "$HOME_DIR"
fi
"$HOME_DIR/bin/clagentic-lite" init
```

This one snippet is safe to re-run: fresh machine → clones; machine that
already has it → pulls and re-runs `init` (this is exactly what
`clagentic-lite update` also does under the hood).

`init` does, in order (verified against `cmd_init()`, `bin/clagentic-lite`):

1. Verifies `$CLAGENTIC_LITE_HOME` looks like a real checkout (checks for
   `scripts/gates.sh`) — refuses with a clear error if not.
2. Detects missing required tools (`sqlite3`, `git`, `jq`-or-`python3`, an LLM
   CLI) and offers to install each one for you (`y`/`N` prompt); on decline,
   prints the exact manual install command and exits non-zero.
3. Materializes the Claude Code lifecycle hook scripts into
   `$CLAGENTIC_LITE_HOME/.claude/hooks/` — this is the ONE shared copy every
   later-enrolled repo's hooks call back into.
4. Runs a two-question front door (accept defaults? which vendor mode?) and
   writes `~/.config/clagentic/config` (global config, `chmod 600`).
5. Symlinks `~/.local/bin/clagentic-lite` → `$CLAGENTIC_LITE_HOME/bin/clagentic-lite`
   and warns (with the exact shell-rc line to add) if `~/.local/bin` is not on
   `$PATH`.
6. Installs the `clagentic-lite` Claude Code plugin (agents + skills) globally
   via `claude plugin marketplace add` / `claude plugin install`.

**Verify:**

```sh
command -v clagentic-lite   # should print a path under ~/.local/bin
clagentic-lite doctor       # should report the checkout, symlink, and prereqs as OK
```

If `doctor` reports `~/.local/bin` missing from `$PATH`, add the line it
prints to the user's shell rc file and tell them to reopen their shell (or
`source` the rc file) before continuing — commands in the rest of this doc
will fail with "command not found" until that's done.

**Do not stop here and consider the tool "set up."** `init` installs the tool
on the machine. It does not gate any project. That is Step 3.

---

## Step 2 — Confirm config exists

```sh
test -f ~/.config/clagentic/config && echo "global config present" || echo "MISSING — re-run: clagentic-lite init"
```

If `init` completed successfully this file exists already (it's written in
step 4 of `init` above) — you do not need to hand-author it. `share/config.example`
in the checkout (`$CLAGENTIC_LITE_HOME/share/config.example`) is the canonical
reference for every setting, with defaults and purpose comments; it is not a
file you copy — `init` writes the real config from its own prompts/defaults.

The settings a user is most likely to need to change, and where they live:

| Setting | Default | What it controls |
|---|---|---|
| `CLAGENTIC_LITE_HOME` | `~/.clagentic/lite` | Where the tool itself lives. Set once by `init`; edit only if you move the install. |
| `CLAGENTIC_BUILDER_CMD` / `_TIER` / `_CHAIN` | `claude` / `default` / `codex:default,claude:flagship` | Which CLI writes code. |
| `CLAGENTIC_REVIEWER_CMD` / `_TIER` / `_CHAIN` | `codex` / `flagship` / `claude:default,codex:flagship` | Which CLI reviews the diff — deliberately a **different vendor** than the Builder by default (cross-vendor review is the point of the tool; same-CLI is allowed but `init` warns). |
| `CLAGENTIC_BLOCK_SEVERITY` | `high` | Review-finding severity that blocks `gates ship`. |
| `CLAGENTIC_ALLOW_MISSING_GITLEAKS` / `_OSV` / `_SEMGREP` | `0` (i.e. required) | Set to `1` to run without that specific security scanner installed — see "Minimal install" in README.md. |
| `CLAGENTIC_REPO_HOST` / `CLAGENTIC_DEFAULT_BRANCH` | `github` / `main` | Where `gates ship` opens PRs and what branch write-guard protects. |

Config is layered: `~/.config/clagentic/config` (global, applies everywhere)
then `<repo>/.clagentic/config` (per-repo override, optional, committed —
**note:** not read on the very first `enroll` call for a given repo, only
from the next command onward; see README.md "What init and enroll do").
Edit the file directly (it's plain `KEY=value` shell, `chmod 600`) — there is
no `clagentic-lite config set` subcommand.

**Verify a config change took effect:**

```sh
clagentic-lite doctor   # re-run after any global config edit; reports current CMD/TIER/CHAIN per role
```

---

## Step 3 — Enroll the project (once per repo, REQUIRED)

This is the step users forget exists, because nothing in "install the tool"
implies "and now do a second thing per project." Without it: no git hooks
fire, no `.claude/settings.json` is generated, Claude Code sees no
clagentic-lite agents or slash commands in this repo, and there is no audit
trail — the tool is installed but completely inert for this project.

**Precondition:** the target directory must be a git repository. If it is not
(`git rev-parse --show-toplevel` fails), either run `git init` first (ask the
user before doing this — it changes repo state) or `enroll` will prompt for
this interactively if run on a real terminal, and will just skip with a
warning in a non-interactive context.

```sh
cd /path/to/the/users/project
clagentic-lite enroll
```

Flags:

- `clagentic-lite enroll` — enrolls `$PWD`.
- `clagentic-lite enroll /some/other/path` — enrolls a specific path instead
  (accepts multiple paths at once).
- `clagentic-lite enroll --force` — re-stamps an already-enrolled repo, or
  overwrites a pre-existing non-clagentic `CLAUDE.md`/`.claude/settings.json`
  it would otherwise refuse to touch.
- `clagentic-lite enroll --self` — the ONLY way to enroll
  `$CLAGENTIC_LITE_HOME` itself (the tool's own checkout). Plain `enroll`
  refuses this on purpose — the tool does not gate itself by default.

**What `enroll` writes** (verified against `_enroll_one()`, `bin/clagentic-lite`):

1. `.clagentic/lite/audit.db` and `.clagentic/lite/memory.db` — created,
   empty, in the target repo.
2. `.git/hooks/pre-commit` and `.git/hooks/pre-push` — thin shims that call
   back into `$CLAGENTIC_LITE_HOME/scripts/gates.sh`. Refuses to overwrite an
   existing non-clagentic hook unless `--force`.
3. `.claude/settings.json` — hook wiring for Claude Code (absolute paths back
   to `$CLAGENTIC_LITE_HOME`), plus a symlink `.claude/commands` →
   `$CLAGENTIC_LITE_HOME/.claude/commands`. This file is machine-specific
   (absolute paths) and is added to `.gitignore` automatically — never commit
   it, and each teammate must run their own `enroll`.
4. `CLAUDE.md` at the repo root — a thin, committable notice that activates
   the Builder contract for Claude Code sessions opened in this repo. Refuses
   to overwrite a pre-existing non-clagentic `CLAUDE.md` unless `--force`.
5. `.clagentic/lite/builder-contract.md` — the full rules/agents/gates
   reference injected at session start. Gitignored, local-only, regenerated
   automatically by `doctor`/`update` when stale — you do not hand-edit it.
6. `.gitignore` — `.claude/` and `.clagentic/lite/` are appended if not
   already present.
7. The repo's canonical absolute path is appended to
   `~/.local/state/clagentic/registry` — this file is what `clagentic-lite
   list`/`doctor` read to know what's enrolled.

**Already enrolled?** `enroll` detects this (checks the registry) and refuses
with `already enrolled (use --force to re-enroll)` rather than erroring —
treat that as success, not a failure to fix.

**Verify:**

```sh
clagentic-lite list          # the repo's path should now appear
clagentic-lite doctor        # should report this repo's hooks/CLAUDE.md/settings.json as OK, current version
test -f .clagentic/lite/audit.db && echo "audit db present"
test -f .claude/settings.json && echo "claude settings present"
git check-ignore .claude/settings.json && echo "correctly gitignored"
```

If `doctor` reports a version mismatch for `CLAUDE.md`, `builder-contract.md`,
or the hook shims, that means the tool itself was updated
(`clagentic-lite update`) after this repo was enrolled — re-run `enroll
--force` or `clagentic-lite update --restamp` to bring the repo's stamped
artifacts current. This is expected maintenance, not a bug.

**Re-running enroll is safe.** `enroll --force` is idempotent — it re-stamps
generated files but does not touch anything user-authored (a `CLAUDE.md` that
still carries the `managed-by: clagentic` marker gets spliced/replaced; one
that doesn't is left alone and `enroll --force` still refuses it — remove the
marker check by hand if the user genuinely wants a full overwrite).

---

## Step 4 — Confirm the harness actually works end to end

```sh
"$CLAGENTIC_LITE_HOME/scripts/smoke.sh" --quick
```

Run this from anywhere (it's an absolute-path invocation of the tool's own
smoke test, not a per-repo command). It exercises DB init, memory seed/recall,
gitleaks blocking a planted token, and `llm-client.sh review` emitting
parseable JSON — no live LLM billing calls in `--quick` mode. A clean pass
means the shell harness is wired correctly, independent of Claude Code.

Then confirm Claude Code itself sees the enrolled repo's surface. Open the
enrolled repo in Claude Code and check:

```text
/recall            → should run (prints recent session summaries, may be empty on a fresh enroll)
/infosec-rt         → should convene the red-team skill
/eng-consult         → should convene the consulting-panel skill
```

"Command not found" for any of these means either a stale Claude Code session
(restart it) or the plugin failed to install — run `claude plugin list` and
look for `clagentic-lite` with an active status; if missing or failed, re-run
`clagentic-lite init`.

---

## Step 5 — Day-to-day commands (for after setup is confirmed)

```sh
clagentic-lite gates review        # cross-CLI review of the staged diff
clagentic-lite gates ship          # runs all gates in sequence; pushes + opens PR if green
clagentic-lite gates digest        # what gates ran today
clagentic-lite doctor              # re-run any time something seems off
clagentic-lite list                # enrolled repos + last-gate-run status
```

`gates review` and `gates ship` require a **staged** diff (`git add`) to have
anything to review — an empty `git diff --cached` means the Reviewer has
nothing to say, which is correct behavior, not a bug.

---

## Optional: clagentic-router (separate download, NOT bundled)

If the user asks about routing interactive Claude Code subagent dispatch
(Reviewer/Auditor/etc. invoked mid-session via the Task/Agent tool, as opposed
to via `clagentic-lite gates review`) through a specific CLI/vendor —
`CLAGENTIC_REVIEWER_CMD` alone does NOT reach that path; only the gate-path
commands honor it directly.

**clagentic-router is a separate GitHub repository
(<https://github.com/clagentic/clagentic-router>), not part of this repo, not
installed by `clagentic-lite init`, not started by anything in this tool.**
If it is not already running, it does not exist on this machine yet. Do not
assume it's available; check:

```sh
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/version 2>/dev/null || echo "not reachable"
```

Setup is a separate clone-and-run, outside this repo's scope — point the user
at that repo's own README for build/run instructions. Once it's running
locally, wiring clagentic-lite to it is two config keys plus a re-enroll:

```sh
# In ~/.config/clagentic/config or <repo>/.clagentic/config:
CLAGENTIC_ROUTER_URL=http://127.0.0.1:8765
CLAGENTIC_ROUTER_TOKEN=<the router's own proxy token>

# Re-stamp so .claude/settings.json picks up the env block:
clagentic-lite enroll --force
# or, for every enrolled repo at once:
clagentic-lite update --restamp
```

**Verify:**

```sh
clagentic-lite doctor   # probes GET /version on the configured router URL, reports reachable/unreachable
```

A non-local `CLAGENTIC_ROUTER_URL` (anything other than `localhost`,
`127.0.0.0/8`, or `::1`) is allowed but `doctor` and the stamp step both warn
loudly — this URL receives the user's real Anthropic credentials in
passthrough mode. Do not suppress or silently pass through that warning;
surface it to the user verbatim.

Do not enable `CLAGENTIC_ROUTER_INJECT_AGENT_MODEL=1` without reading
README.md's "Agent-model injection (separate opt-in, UNVERIFIED)" section
first — this feature's core mechanism (Claude Code honoring a non-standard
`model:` frontmatter value) is explicitly unverified upstream.

---

## Common failure modes and fixes

| Symptom | Cause | Fix |
|---|---|---|
| `clagentic-lite: command not found` | Not installed, or `~/.local/bin` not on `$PATH` | Run Step 1. If already installed, check `$PATH` per the `doctor` output. |
| A gate never fires; `clagentic-lite gates ship` says nothing changed | Repo not enrolled | Run Step 3 in that repo. |
| Claude Code shows no clagentic-lite agents/slash-commands in this repo | Repo not enrolled, or `.claude/settings.json` missing/stale | `clagentic-lite doctor`; re-run `enroll --force` if it flags a version mismatch. |
| `clagentic-lite init` warns "CLAGENTIC_HOME is deprecated" | User (or their shell rc) still sets the old env var name | Tell them to set `CLAGENTIC_LITE_HOME` explicitly and drop `CLAGENTIC_HOME`. Both still work — this is a warning, not a hard failure. |
| `enroll` refuses with "is already enrolled" | Not a failure — repo is enrolled | Nothing to do, or pass `--force` to re-stamp. |
| `enroll` refuses with "refusing to enroll $CLAGENTIC_LITE_HOME itself" | Tried to enroll the tool's own checkout without `--self` | Only pass `--self` if the user explicitly wants to dogfood the tool against its own repo. |
| `git pull --ff-only failed` during `clagentic-lite update` | Local checkout at `$CLAGENTIC_LITE_HOME` has diverged or has uncommitted changes | This is the tool's own checkout, not the user's project — `cd "$CLAGENTIC_LITE_HOME"` and resolve the git state there (stash or reset local edits) before retrying `update`. |
| Router configured but Claude Code traffic never routes | `CLAGENTIC_ROUTER_URL` set but repo not re-enrolled since, or Bedrock-mode session (`CLAUDE_CODE_USE_BEDROCK=1`) which ignores `ANTHROPIC_BASE_URL` entirely | Re-run `enroll --force`/`update --restamp`. For Bedrock-mode sessions, also set `CLAGENTIC_ROUTER_BEDROCK_MODE=1` — see README.md. |
| A security gate (gitleaks/semgrep/osv-scanner) blocks and the tool isn't installed | Missing required security tool, and no opt-out set | Either install the tool (`doctor` prints the exact command) or set the matching `CLAGENTIC_ALLOW_MISSING_*=1` to explicitly skip it — never silently work around a block by disabling the hook itself. |
| `doctor` reports a stale artifact version (`CLAUDE.md`, `builder-contract.md`, hook shims) | The tool was updated after this repo was enrolled | `clagentic-lite update --restamp`, or `enroll --force` for a single repo. |

---

## What NOT to do on the user's behalf

- Do not hand-write `.claude/settings.json`, `CLAUDE.md`, or any hook shim —
  these are always generated by `enroll`/`update` from templates in
  `share/hook-shims/`. A hand edit will be silently overwritten (or, worse,
  cause `enroll`/`update` to refuse the repo as "non-clagentic-managed").
- Do not commit `.claude/settings.json` or `.clagentic/lite/*.db` — both are
  gitignored automatically at enroll time; if you see either staged, that is
  a signal something upstream went wrong, not something to force-add.
- Do not bypass a blocking security gate by editing `scripts/gates.sh`,
  `pre-bash-guard.sh`, or `pre-write-guard.sh` — use the documented config
  bypasses (`CLAGENTIC_ALLOW_*`, `.clagentic/osv-ignore`, `.gitleaks.toml`,
  `.semgrepignore`) instead. See AGENTS.md § "Never edit gate source to
  bypass a block."
- Do not assume clagentic-router is running just because `CLAGENTIC_ROUTER_URL`
  is set in config — always probe it (`doctor`, or the `curl` check above)
  before telling the user routing is active.

---

## Cross-references

- `README.md` — product narrative, full install/enroll walkthrough, why
  cross-vendor review, layout diagram.
- `AGENTS.md` — canonical repo rules for anyone (human or LLM) contributing
  *to* clagentic-lite itself (as opposed to *using* it, which is this file).
- `docs/DESIGN.md` — architecture, non-goals, the config trust-boundary
  reasoning, the clagentic-router interactive-path gap in full.
- `docs/GATES.md` — every gate's trigger, blocking behavior, and override.
- `docs/PORTABILITY.md` — GNU/BSD differences, what's required per-platform.
- `share/config.example` — canonical, commented list of every configurable
  setting (`$CLAGENTIC_LITE_HOME/share/config.example` once installed).
