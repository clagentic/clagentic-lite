#!/bin/sh
# clagentic-lite :: UserPromptSubmit hook
# Extracts keywords from the prompt, greps memory, injects top matches.
# Non-blocking.
#
# STATUS: stub. Real implementation lands in weekend-1 task #6.

set -e

[ "${CLAGENTIC_DISABLE_RECALL:-0}" = "1" ] && exit 0

MEMORY_DB="${PWD}/.clagentic/memory.db"
[ -f "$MEMORY_DB" ] || exit 0

# Read hook payload from stdin (Claude Code passes JSON).
# Stub: extract any quoted prompt field naively.
PROMPT=$(cat 2>/dev/null | sed -n 's/.*"prompt"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
[ -z "$PROMPT" ] && exit 0

# Strip short tokens and stopwords, take top 5 meaningful words.
KEYWORDS=$(printf '%s\n' "$PROMPT" | tr '[:upper:]' '[:lower:]' | \
  tr -c '[:alnum:]' ' ' | tr ' ' '\n' | \
  awk 'length($0) >= 4 && !/^(this|that|with|from|have|will|what|when|where|which|should|would|could|about|into|been|being|some)$/' | \
  sort -u | head -5)

[ -z "$KEYWORDS" ] && exit 0

# Build a SQL LIKE clause; bounded to 3 results.
WHERE=""
for kw in $KEYWORDS; do
  if [ -z "$WHERE" ]; then
    WHERE="(summary LIKE '%$kw%' OR tags LIKE '%$kw%')"
  else
    WHERE="$WHERE OR (summary LIKE '%$kw%' OR tags LIKE '%$kw%')"
  fi
done

MATCHES=$(sqlite3 "$MEMORY_DB" \
  "SELECT '[' || ts || '] ' || summary FROM turns WHERE $WHERE ORDER BY ts DESC LIMIT 3;" 2>/dev/null || true)

[ -z "$MATCHES" ] && exit 0

cat <<EOF
{
  "additionalContext": "CLAGENTIC RECALL · prior matches for [$KEYWORDS]:\n${MATCHES}"
}
EOF
