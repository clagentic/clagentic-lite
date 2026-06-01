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

# Source platform shims for ds_json_field — same real JSON parser used by
# pre-bash-guard.sh and pre-write-guard.sh. The sed-based extraction it
# replaced was vulnerable to prompt injection: a payload containing
# escaped quotes or embedded JSON would corrupt the extracted field.
HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || HOOK_DIR=.
. "$HOOK_DIR/../../scripts/platform.sh" 2>/dev/null || true

# Read hook payload from stdin (Claude Code passes JSON).
PAYLOAD=$(cat 2>/dev/null || true)
[ -z "$PAYLOAD" ] && exit 0

# Extract prompt via real JSON parsing. ds_json_field returns exit 1 on parse
# failure or exit 2 if no validator is available; both are silent exits here
# since recall injection is non-blocking and best-effort.
PROMPT=""
if command -v ds_json_field >/dev/null 2>&1; then
  PROMPT=$(printf '%s' "$PAYLOAD" | ds_json_field prompt 2>/dev/null) || PROMPT=""
else
  # ds_json_field unavailable (platform.sh load failed) — skip injection
  # rather than fall back to sed-based extraction. Non-blocking; hook exits
  # clean. The user sees no recall context for this turn only.
  exit 0
fi
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
