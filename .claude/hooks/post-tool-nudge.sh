#!/bin/sh
# clagentic-lite :: PostToolUse (Bash) hook
# Nudges the session to run /review after git commit or git add.
# NON-BLOCKING by design — always exits 0. A hook failure here must never
# interrupt the user's workflow; the nudge is advisory only.
#
# Claude Code passes a JSON payload on stdin with fields including
# tool_name and tool_input. We check tool_input.command for git commit/add
# patterns and emit an additionalContext nudge when matched.

# Fail-open wrapper: any unexpected error exits 0, not 2.
set +e

HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || HOOK_DIR=.

# Load platform shims for ds_json_field. If platform.sh is missing or broken,
# exit 0 — the nudge is skipped, not the user's work.
. "$HOOK_DIR/../../scripts/platform.sh" 2>/dev/null || exit 0
ds_load_env 2>/dev/null || exit 0

# Read tool payload from stdin.
PAYLOAD=$(cat 2>/dev/null) || exit 0
[ -z "$PAYLOAD" ] && exit 0

# Extract command field via real JSON parsing.
CMD=$(printf '%s' "$PAYLOAD" | ds_json_field command 2>/dev/null) || exit 0
[ -z "$CMD" ] && exit 0

# Match git commit or git add (but not git add -p, which is interactive).
# We only nudge after the write side — not after read-only git commands.
case "$CMD" in
  *"git commit"*)
    # After a commit: staged diff is now HEAD. Suggest /review for the
    # diff between HEAD and origin, or the most recent commit.
    cat <<'EOF'
{
  "additionalContext": "clagentic-lite: changes committed. Run /review to get a cross-vendor review of the staged diff before /ship, or run /ship to execute all gates in sequence."
}
EOF
    ;;
  *"git add"*)
    # Skip git add -p (interactive) and git add --patch.
    case "$CMD" in
      *"-p"*|*"--patch"*) exit 0 ;;
    esac
    cat <<'EOF'
{
  "additionalContext": "clagentic-lite: changes staged. When ready, run /review for cross-vendor review before committing, or /ship to run all gates."
}
EOF
    ;;
  *)
    exit 0
    ;;
esac

exit 0
