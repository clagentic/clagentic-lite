#!/bin/sh
# clagentic-lite :: UserPromptSubmit hook
# Extracts keywords from the user's prompt, searches .clagentic/lite/memory.db
# for matching prior session summaries, and injects the top 3 matches as
# additionalContext so the session can reference prior decisions without
# asking the user to recall them manually.
# Non-blocking — any failure exits 0 silently.

# set -e intentionally absent — this hook is non-blocking and must always
# exit 0 on unexpected failures.

[ "${CLAGENTIC_DISABLE_RECALL:-0}" = "1" ] && exit 0

MEMORY_DB="${PWD}/.clagentic/lite/memory.db"
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
# tr -c '[:alnum:]' reduces to alnum-only tokens, so no SQL metacharacters
# survive — but we still escape explicitly for defense-in-depth, matching the
# ds_sql_escape + LIKE-wildcard-escape pattern used in scripts/memory.sh recall.
KEYWORDS=$(printf '%s\n' "$PROMPT" | tr '[:upper:]' '[:lower:]' | \
  tr -c '[:alnum:]' ' ' | tr ' ' '\n' | \
  awk 'length($0) >= 4 && !/^(this|that|with|from|have|will|what|when|where|which|should|would|could|about|into|been|being|some)$/' | \
  sort -u | head -5)

[ -z "$KEYWORDS" ] && exit 0

# Gate: count surviving keywords and skip injection if below threshold.
# Bright-line compliance: the gate counts tokens from the user's own input
# (how many keywords were extracted from the prompt), never a number derived
# from the corpus. The SQL query, result set, and ORDER BY are unchanged —
# rows that appear are byte-identical to a no-gate run. Only the call/no-call
# decision differs, based solely on the user's own prompt structure.
KEYWORD_COUNT=$(printf '%s\n' "$KEYWORDS" | grep -c '.')
MIN_KW="${CLAGENTIC_RECALL_MIN_KEYWORDS:-2}"
[ "$KEYWORD_COUNT" -lt "$MIN_KW" ] && exit 0

# Escape a keyword for safe interpolation into a SQLite LIKE pattern.
# Escapes: single-quote (SQL injection), %, _ (LIKE wildcards), \ (escape char).
# Input is already alnum-only after tr filtering above, so in practice nothing
# escapes — but this makes the function the defence, not the filter.
_sql_like_escape() {
  printf '%s' "$1" | sed "s/'/\\''/g; s/\\\\/\\\\\\\\/g; s/%/\\\\%/g; s/_/\\\\_/g"
}

# Build a SQL LIKE clause; bounded to 3 results.
WHERE=""
for kw in $KEYWORDS; do
  _ekw=$(_sql_like_escape "$kw")
  _clause="(summary LIKE '%${_ekw}%' ESCAPE '\\' OR tags LIKE '%${_ekw}%' ESCAPE '\\')"
  if [ -z "$WHERE" ]; then
    WHERE="$_clause"
  else
    WHERE="$WHERE OR $_clause"
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
