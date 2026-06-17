#!/bin/sh
# clagentic-lite :: SessionStart hook
# 1. Injects up to 3 recent session summaries from .clagentic/lite/memory.db as
#    additionalContext so the session opens with recent decisions visible.
# 2. Checks whether the clagentic-lite tool itself is behind its upstream and,
#    if so, appends a terse one-line update notice.  Rate-limited to one
#    git fetch per 24 h via ~/.config/clagentic/update-check.  Non-blocking —
#    any failure exits 0 silently.  Suppress with CLAGENTIC_SKIP_UPDATE_ALERT=1.
#
# Non-blocking — any failure exits 0 silently.

# shellcheck source=../../scripts/platform.sh
. "$(dirname "$0")/../../scripts/platform.sh" 2>/dev/null || true

MEMORY_DB="${PWD}/.clagentic/lite/memory.db"
CONTRACT_MD="${PWD}/.clagentic/lite/builder-contract.md"

# Wrapper-CWD fallback: if the memory DB is absent and a .clagentic-project
# pointer exists in CWD, read the first enrolled repo path and redirect
# MEMORY_DB and CONTRACT_MD to that repo's .clagentic/lite/ paths.
# Only the first line is used — multi-repo wrappers use the primary project.
if [ ! -f "$MEMORY_DB" ] && [ -f "${PWD}/.clagentic-project" ]; then
  _ws_primary=$(head -n 1 "${PWD}/.clagentic-project" 2>/dev/null || true)
  if [ -n "$_ws_primary" ]; then
    MEMORY_DB="${_ws_primary}/.clagentic/lite/memory.db"
    CONTRACT_MD="${_ws_primary}/.clagentic/lite/builder-contract.md"
  fi
fi

# ---- 1. Recent session summaries ----------------------------------------

RECENT=""
if [ -f "$MEMORY_DB" ]; then
  RECENT=$(sqlite3 "$MEMORY_DB" \
    "SELECT '[' || ts || '] ' || summary FROM turns ORDER BY ts DESC LIMIT 3;" 2>/dev/null || true)
fi

# ---- 1b. Builder contract injection ----------------------------------------
# Inject .clagentic/lite/builder-contract.md so Claude Code receives the full
# builder rules, agent table, and gate reference at session open. The contract
# is gitignored (local machine only) — this is the delivery path that replaces
# the fat committed CLAUDE.md. Best-effort: missing contract is not an error.

CONTRACT_CONTENT=""
if [ -f "$CONTRACT_MD" ]; then
  CONTRACT_CONTENT=$(cat "$CONTRACT_MD" 2>/dev/null || true)
fi

# ---- 2. Update alert -------------------------------------------------------
# Resolve CLAGENTIC_LITE_HOME; fall back to the hook file's grandparent directory
# (mirrors the bin/clagentic-lite resolution logic).
: "${CLAGENTIC_LITE_HOME:=${CLAGENTIC_HOME:-$HOME/.clagentic/lite}}"

UPDATE_MSG=""

if [ "${CLAGENTIC_SKIP_UPDATE_ALERT:-0}" != "1" ] \
    && git -C "$CLAGENTIC_LITE_HOME" rev-parse --git-dir >/dev/null 2>&1; then

  # State file: track the last time we did a network fetch.
  _STATE_DIR="$HOME/.config/clagentic"
  _STATE_FILE="$_STATE_DIR/update-check"
  _FETCH_INTERVAL=86400   # 24 h in seconds
  _NOW=$(date +%s 2>/dev/null || echo 0)
  _LAST=0

  if [ -f "$_STATE_FILE" ]; then
    _LAST=$(ds_stat_mtime "$_STATE_FILE" 2>/dev/null || echo 0)
  fi

  _AGE=$(( _NOW - _LAST ))

  if [ "$_AGE" -ge "$_FETCH_INTERVAL" ]; then
    # Best-effort fetch; 5 s timeout; suppress all output.
    # Only stamp the state file when the fetch succeeds — a network failure must
    # not lock out update detection for 24 h.
    if $DS_TIMEOUT_CMD 5 git -C "$CLAGENTIC_LITE_HOME" fetch --quiet 2>/dev/null; then
      mkdir -p "$_STATE_DIR" 2>/dev/null || true
      printf '%s\n' "$_NOW" > "$_STATE_FILE" 2>/dev/null || true
    fi
  fi

  _UPSTREAM=$(git -C "$CLAGENTIC_LITE_HOME" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || echo "")
  if [ -z "$_UPSTREAM" ]; then
    # No tracking branch configured; fall back to origin/main so new installs
    # still receive the update notice after the initial fetch.
    git -C "$CLAGENTIC_LITE_HOME" rev-parse --verify origin/main >/dev/null 2>&1 && _UPSTREAM="origin/main" || true
  fi
  if [ -n "$_UPSTREAM" ]; then
    _BEHIND=$(git -C "$CLAGENTIC_LITE_HOME" rev-list --count "HEAD..$_UPSTREAM" 2>/dev/null || echo 0)
    if [ "${_BEHIND:-0}" -gt 0 ] 2>/dev/null; then
      UPDATE_MSG="UPDATE AVAILABLE · clagentic-lite is ${_BEHIND} commit(s) behind upstream — run \`clagentic-lite update\` to install, or set CLAGENTIC_SKIP_UPDATE_ALERT=1 to suppress."
    fi
  fi
fi

# ---- 3. Emit combined additionalContext ------------------------------------
# Build the context string from whichever parts are non-empty.

CONTEXT=""

if [ -n "$CONTRACT_CONTENT" ]; then
  CONTEXT="$CONTRACT_CONTENT"
fi

if [ -n "$RECENT" ]; then
  _recall_block="CLAGENTIC RECALL · ${PWD##*/} · most recent session summaries:\n${RECENT}"
  if [ -n "$CONTEXT" ]; then
    CONTEXT="${CONTEXT}\n\n${_recall_block}"
  else
    CONTEXT="$_recall_block"
  fi
fi

if [ -n "$UPDATE_MSG" ]; then
  if [ -n "$CONTEXT" ]; then
    CONTEXT="${CONTEXT}\n\n${UPDATE_MSG}"
  else
    CONTEXT="$UPDATE_MSG"
  fi
fi

[ -z "$CONTEXT" ] && exit 0

# Escape the context string for safe embedding in a JSON string value.
# Must produce spec-compliant output: RFC 8259 §7 requires escaping U+0000-U+001F.
# Strategy: python3 (already a project dependency via ds_json_field) handles the
# full control-character range correctly in one pass. The sed+tr fallback (for
# environments without python3) escapes: \\ \" \t (0x09) \r (0x0D), converts
# literal newlines to \n via awk, then strips the remaining obscure control chars
# (0x01-0x08, 0x0B-0x0C, 0x0E-0x1F) that are near-impossible in session context
# and have no standard single-letter JSON escape sequence.
_json_escape() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c '
import sys, json
raw = sys.stdin.read()
# json.dumps produces a quoted string; strip the surrounding quotes.
encoded = json.dumps(raw)
sys.stdout.write(encoded[1:-1])
'
  else
    # Fallback: escape backslash and double-quote; escape tab (0x09) as \t and
    # CR (0x0D) as \r; convert literal newlines to \n escape sequences via awk;
    # strip remaining 0x01-0x08, 0x0B-0x0C, 0x0E-0x1F control bytes. The tr
    # ranges exclude 0x09 (already \t), 0x0A (handled by awk), and 0x0D
    # (already \r). Uses octal ranges which are POSIX-portable.
    printf '%s' "$1" \
      | sed 's/\\/\\\\/g; s/"/\\"/g' \
      | sed 's/'"$(printf '\t')"'/\\t/g' \
      | sed 's/'"$(printf '\r')"'/\\r/g' \
      | awk '{if(NR>1)printf "\\n"; printf "%s", $0} END{printf ""}' \
      | tr -d '\001-\010\013-\014\016-\037\177'
  fi
}
CONTEXT_JSON=$(_json_escape "$CONTEXT")

cat <<EOF
{
  "additionalContext": "${CONTEXT_JSON}"
}
EOF
