#!/bin/sh
# clagentic-lite :: SessionStart hook
# Injects the 3 most recent session summaries as additional context.
# Non-blocking — failures are silent.
#
# STATUS: stub. Real implementation lands in weekend-1 task #6.

set -e

# shellcheck source=../../scripts/platform.sh
. "$(dirname "$0")/../../scripts/platform.sh" 2>/dev/null || true

MEMORY_DB="${PWD}/.clagentic/memory.db"
[ -f "$MEMORY_DB" ] || exit 0

# Print up to 3 most recent summaries as additionalContext.
# Output JSON understood by Claude Code's hook protocol.
RECENT=$(sqlite3 "$MEMORY_DB" \
  "SELECT '[' || ts || '] ' || summary FROM turns ORDER BY ts DESC LIMIT 3;" 2>/dev/null || true)

[ -z "$RECENT" ] && exit 0

cat <<EOF
{
  "additionalContext": "CLAGENTIC RECALL · ${PWD##*/} · most recent session summaries:\n${RECENT}"
}
EOF
