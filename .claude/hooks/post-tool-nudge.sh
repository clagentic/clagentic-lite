#!/bin/sh
# clagentic-lite :: PostToolUse hook
# Three responsibilities (all non-blocking — always exits 0):
#
# 1. Git-workflow nudge: reminds the session to run /review after git commit
#    or git add (advisory only).
#
# 2. Context-budget monitor: estimates token cost of each tool result (byte
#    proxy: 4 bytes ≈ 1 token), accumulates per-session totals in audit.db,
#    and emits an additionalContext warning when a single result or the running
#    session total crosses a configurable threshold.
#    Opt-out: CLAGENTIC_DISABLE_BUDGET=1
#    Per-result threshold: CLAGENTIC_RESULT_TOKEN_WARN (default 8000, ~32 KB)
#    Session total threshold: CLAGENTIC_SESSION_TOKEN_WARN (default 50000, ~200 KB)
#
# 3. Auto-summarize: when a tool result exceeds CLAGENTIC_AUTOSUMMARIZE_BYTES
#    (default 32768 = 32 KB), pipes it through the Summarizer role via
#    llm-client.sh and stores a digest in memory.db. Also emits the first 100
#    chars of the digest via additionalContext so the session sees a hint.
#    Opt-out: CLAGENTIC_DISABLE_AUTOSUMMARIZE=1
#    Threshold: CLAGENTIC_AUTOSUMMARIZE_BYTES (default 32768)

set +e

HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || HOOK_DIR=.

# Load platform shims for ds_json_field, ds_repo_root, ds_load_env.
# If platform.sh is missing or broken, skip everything — non-blocking.
. "$HOOK_DIR/../../scripts/platform.sh" 2>/dev/null || exit 0
ds_load_env 2>/dev/null || true

# Read tool payload from stdin once; both sections share it.
PAYLOAD=$(cat 2>/dev/null) || exit 0
[ -z "$PAYLOAD" ] && exit 0

# ---- shared state ----

REPO_ROOT=$(ds_repo_root 2>/dev/null || true)
AUDIT_DB=""
[ -n "$REPO_ROOT" ] && AUDIT_DB="$REPO_ROOT/.clagentic/lite/audit.db"

# JSON-escape a plain-text string for safe embedding in a JSON string value.
# Uses python3 (already a project dependency). Falls back to the raw value on
# failure — the worst outcome is a slightly malformed additionalContext, not a
# session block (hook is non-blocking).
_json_escape() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c '
import sys, json
raw = sys.stdin.read()
encoded = json.dumps(raw)
sys.stdout.write(encoded[1:-1])
' 2>/dev/null || printf '%s' "$1"
  else
    printf '%s' "$1"
  fi
}

# ---- section 1: context-budget monitor ----

BUDGET_MSG=""

if [ "${CLAGENTIC_DISABLE_BUDGET:-0}" != "1" ]; then
  # Thresholds.
  RESULT_WARN="${CLAGENTIC_RESULT_TOKEN_WARN:-8000}"
  SESSION_WARN="${CLAGENTIC_SESSION_TOKEN_WARN:-50000}"

  # Extract fields from the payload.
  # PostToolUse payload shape (Claude Code):
  #   {"session_id":...,"tool_name":...,"tool_input":{...},"tool_response":{"output":...,...}}
  # "output" may appear at the top level or inside tool_response; ds_json_field
  # reads top-level keys, so we try "output" first (some Claude Code versions
  # flatten it) and fall back to an empty string when absent.
  SESSION_ID=$(printf '%s' "$PAYLOAD" | ds_json_field session_id 2>/dev/null) || SESSION_ID=""
  TOOL_NAME=$(printf '%s' "$PAYLOAD" | ds_json_field tool_name 2>/dev/null) || TOOL_NAME=""
  OUTPUT=$(printf '%s' "$PAYLOAD" | ds_json_field output 2>/dev/null) || OUTPUT=""

  # Estimate tokens via byte count (4 bytes ≈ 1 token).
  RESULT_BYTES=$(printf '%s' "$OUTPUT" | wc -c | tr -d '[:space:]')
  RESULT_TOKENS=$(( RESULT_BYTES / 4 ))

  # Persist to audit.db and compute cumulative session total.
  CUMULATIVE=0
  if [ -n "$AUDIT_DB" ] && [ -f "$AUDIT_DB" ]; then
    # Ensure the context_budget table exists (best-effort; failure is silent).
    sqlite3 "$AUDIT_DB" \
      "CREATE TABLE IF NOT EXISTS context_budget (
         session_id TEXT,
         ts TEXT DEFAULT (datetime('now')),
         tool TEXT,
         result_tokens INTEGER,
         cumulative_tokens INTEGER
       );" 2>/dev/null || true

    # Query existing session total.
    SID_ESC=$(ds_sql_escape "${SESSION_ID:-}")
    PRIOR=$(sqlite3 "$AUDIT_DB" \
      "SELECT COALESCE(SUM(result_tokens),0) FROM context_budget WHERE session_id='${SID_ESC}';" \
      2>/dev/null) || PRIOR=0
    # Guard against non-numeric values (empty result, error text, etc.).
    case "$PRIOR" in
      ''|*[!0-9]*) PRIOR=0 ;;
    esac
    CUMULATIVE=$(( PRIOR + RESULT_TOKENS ))

    # Insert this result row.
    TN_ESC=$(ds_sql_escape "${TOOL_NAME:-}")
    sqlite3 "$AUDIT_DB" \
      "INSERT INTO context_budget (session_id, tool, result_tokens, cumulative_tokens)
       VALUES ('${SID_ESC}', '${TN_ESC}', ${RESULT_TOKENS}, ${CUMULATIVE});" \
      2>/dev/null || true
  else
    # No DB available: best-effort — cumulative equals this result only.
    CUMULATIVE="$RESULT_TOKENS"
  fi

  # Determine which warning labels to append.
  RESULT_LABEL=""
  SESSION_LABEL=""
  if [ "$RESULT_TOKENS" -gt "$RESULT_WARN" ] 2>/dev/null; then
    RESULT_LABEL=" [RESULT_WARN: large result]"
  fi
  if [ "$CUMULATIVE" -gt "$SESSION_WARN" ] 2>/dev/null; then
    SESSION_LABEL=" [SESSION_WARN: session context heavy]"
  fi

  # Only emit when at least one threshold is crossed.
  if [ -n "$RESULT_LABEL" ] || [ -n "$SESSION_LABEL" ]; then
    _raw_msg=$(printf \
      'CLAGENTIC BUDGET \302\267 tool result: ~%s tokens (session total: ~%s tokens)%s%s' \
      "$RESULT_TOKENS" "$CUMULATIVE" "$RESULT_LABEL" "$SESSION_LABEL")
    BUDGET_MSG=$(_json_escape "$_raw_msg")
  fi
fi

# ---- section 2: git-workflow nudge ----

GIT_MSG=""

CMD=$(printf '%s' "$PAYLOAD" | ds_json_field command 2>/dev/null) || CMD=""
if [ -n "$CMD" ]; then
  case "$CMD" in
    *"git commit"*)
      GIT_MSG="clagentic-lite: changes committed. Run /review to get a cross-vendor review of the staged diff before /ship, or run /ship to execute all gates in sequence."
      ;;
    *"git add"*)
      case "$CMD" in
        *"-p"*|*"--patch"*) : ;;
        *)
          GIT_MSG="clagentic-lite: changes staged. When ready, run /review for cross-vendor review before committing, or /ship to run all gates."
          ;;
      esac
      ;;
  esac
fi

# ---- section 3: auto-summarize large tool results ----

AUTOSUMMARIZE_MSG=""

if [ "${CLAGENTIC_DISABLE_AUTOSUMMARIZE:-0}" != "1" ] && [ -n "$REPO_ROOT" ]; then
  AUTOSUMMARIZE_BYTES="${CLAGENTIC_AUTOSUMMARIZE_BYTES:-32768}"
  # Integer guard: reject non-integer values; fall back to default.
  case "$AUTOSUMMARIZE_BYTES" in ''|*[!0-9]*) AUTOSUMMARIZE_BYTES=32768 ;; esac

  # RESULT_BYTES may already be set by the budget monitor; re-derive if empty.
  # OUTPUT was extracted above (budget monitor section). Both are in scope because
  # they share the same shell, not a subshell.
  if [ -z "${RESULT_BYTES:-}" ]; then
    OUTPUT=$(printf '%s' "$PAYLOAD" | ds_json_field output 2>/dev/null) || OUTPUT=""
    RESULT_BYTES=$(printf '%s' "$OUTPUT" | wc -c | tr -d '[:space:]')
  fi

  # Only proceed when RESULT_BYTES is a plain integer.
  case "${RESULT_BYTES:-}" in
    ''|*[!0-9]*) : ;;  # not numeric — skip silently
    *)
      if [ "$RESULT_BYTES" -gt "$AUTOSUMMARIZE_BYTES" ] 2>/dev/null; then
        # Summarize: pipe result through Summarizer; best-effort, 10s timeout.
        # Use $DS_TIMEOUT_CMD if available (from platform.sh), fall back to plain exec.
        _summarize_cmd="$REPO_ROOT/scripts/llm-client.sh"
        if [ -x "$_summarize_cmd" ]; then
          if [ -n "${DS_TIMEOUT_CMD:-}" ]; then
            DIGEST=$(printf '%s' "$OUTPUT" | $DS_TIMEOUT_CMD 10 "$_summarize_cmd" summarize 2>/dev/null | head -c 300) || DIGEST=""
          else
            DIGEST=$(printf '%s' "$OUTPUT" | "$_summarize_cmd" summarize 2>/dev/null | head -c 300) || DIGEST=""
          fi
          if [ -n "$DIGEST" ]; then
            # Store digest in memory.db — best-effort, failures are silent.
            "$REPO_ROOT/scripts/memory.sh" log-turn "$DIGEST" "autosummarize tool-result" "autosummarize" >/dev/null 2>&1 || true
            # Build the additionalContext hint: first 100 chars of the digest.
            _digest_hint=$(printf '%s' "$DIGEST" | head -c 100)
            _approx_tokens=$(( RESULT_BYTES / 4 ))
            _raw_autosummarize=$(printf 'CLAGENTIC AUTOSUMMARIZE \302\267 large result (~%s tokens) stored as digest: %s...' \
              "$_approx_tokens" "$_digest_hint")
            AUTOSUMMARIZE_MSG=$(_json_escape "$_raw_autosummarize")
          fi
        fi
      fi
      ;;
  esac
fi

# ---- emit combined additionalContext ----

# Accumulate all non-empty message parts, separated by \n\n in the JSON string.
CONTEXT=""

_append_context() {
  _part="$1"
  if [ -n "$_part" ]; then
    if [ -n "$CONTEXT" ]; then
      CONTEXT="${CONTEXT}\\n\\n${_part}"
    else
      CONTEXT="$_part"
    fi
  fi
}

_append_context "$BUDGET_MSG"
_append_context "$AUTOSUMMARIZE_MSG"
# GIT_MSG needs JSON-escaping (BUDGET_MSG and AUTOSUMMARIZE_MSG are pre-escaped).
if [ -n "$GIT_MSG" ]; then
  _append_context "$(_json_escape "$GIT_MSG")"
fi

# Exit silently when no section produced output.
[ -z "$CONTEXT" ] && exit 0

printf '{"additionalContext": "%s"}\n' "$CONTEXT"

exit 0
