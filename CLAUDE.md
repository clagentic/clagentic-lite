# CLAUDE.md

Claude Code does not yet natively support the `AGENTS.md` cross-tool
convention. Until it does, this file exists so Claude Code reads the same
canonical agent instructions as every other tool operating in this repo.

**Read `CLAUDE.local.md` first, if it exists.** It carries host-specific
truth about how this checkout is actually developed (crew+loadout vs. the
shipped product) that must never be tracked. Its absence is not an error —
untracked and gitignored by design — but if present, read it before doing
anything else.

**Then read `AGENTS.md` in full.** It remains the single canonical,
cross-tool instruction file — this file does not replace it, only front-loads
the highest-cost rules so they aren't buried at line 94+ of a 295-line file.

## Top non-negotiables (see `AGENTS.md` Invariants / "What to ask the user" for full detail)

1. Read every file in full before editing it. No partial reads + blind edits.
2. Never add an LLM call to the blocking security path (gitleaks/semgrep/osv-scanner stay local-tool-owned).
3. Never flip a fail-closed default to fail-open without asking first.
4. Never edit gate source (`pre-bash-guard.sh`, `pre-write-guard.sh`, `scripts/gates.sh`) to suppress a block — use the documented config bypass instead.
5. All shell code is POSIX sh; route GNU/BSD differences through `scripts/platform.sh`.
6. Nothing personal, org-specific, or host-specific is hardcoded — everything user-supplied goes through `.env`.
7. A red local gate means the work is not done — no CI exists here, so the local gate is the only check that will ever run.
8. Fix the pattern, not the line — a defect that could recur elsewhere gets a shared primitive, a sweep, and a guard, not a point-patch.
9. No emojis, no fluff, in commits/PRs/comments/code.
10. Ask before: new external tool dependency, changing default severity/CLI roles, editing bash/write-guard rule lists, widening the non-goals list, or loosening the gitleaks allowlist.
11. No fix may require a flag, env var, redirect, or documented user action to be received — `update`/`doctor`/`init`/`enroll` must work bare, for a user who knows nothing (INV-8).

When this repo is opened by Claude Code:

1. Read `CLAUDE.local.md` if present.
2. Read `AGENTS.md` completely.
3. Read `README.md` for product context.
4. Skim `docs/DESIGN.md` and `docs/GATES.md` for architectural context.
5. Then begin work.

Do not infer Claude-specific behavior from this file. If you need
Claude-specific configuration, propose it in `AGENTS.md` under a
clearly-marked section so other tools can ignore it consistently.
