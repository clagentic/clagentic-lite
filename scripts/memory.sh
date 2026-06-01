#!/bin/sh
# clagentic-lite :: memory layer
# SQLite session memory. One DB per project at .clagentic/memory.db.
#
# Subcommands:
#   init                  create schema if missing
#   log-turn <summary> [tags]
#   recall <keywords>     grep summaries, return top 5 recent matches
#   summarize-turn        read transcript from stdin, pipe to summarizer, insert
#   digest                one-screen overview
#   seed-demo             insert a few demo rows

set -e
. "$(dirname "$0")/platform.sh"
ds_load_env

# Tool home: resolved from this script's own location (same convention as gates.sh).
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_HOME="$(dirname "$SCRIPTS_DIR")"

# Project root resolution: same convention as gates.sh.
# CLAGENTIC_PROJECT_ROOT env var wins, then git show-toplevel of cwd.
# See gates.sh header comment for the rationale.
if [ -n "${CLAGENTIC_PROJECT_ROOT:-}" ]; then
  REPO_ROOT="$CLAGENTIC_PROJECT_ROOT"
else
  REPO_ROOT=$(ds_repo_root)
fi
[ -n "$REPO_ROOT" ] || { echo "memory.sh: not in a git repo" 1>&2; exit 1; }

DB="$REPO_ROOT/.clagentic/memory.db"
mkdir -p "$REPO_ROOT/.clagentic"

cmd_init() {
  sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS turns (
  id          INTEGER PRIMARY KEY,
  ts          TEXT NOT NULL,
  session_id  TEXT NOT NULL DEFAULT 'unknown',
  branch      TEXT,
  summary     TEXT NOT NULL,
  tags        TEXT,
  source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_turns_ts   ON turns(ts);
CREATE INDEX IF NOT EXISTS idx_turns_tags ON turns(tags);
SQL
}

cmd_log_turn() {
  cmd_init
  SUMMARY="$1"
  TAGS="${2:-}"
  SOURCE="${3:-manual}"
  BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  TS=$(ds_date_iso)
  # CLAGENTIC_MEMORY_MAX_ROWS: opportunistic row cap (default 5000).
  # After each INSERT, oldest rows beyond the cap are silently pruned.
  # No scheduler, no daemon — one DELETE per write path. Silent housekeeping.
  MAX_ROWS="${CLAGENTIC_MEMORY_MAX_ROWS:-5000}"
  # Integer guard: reject non-integer values (empty, float, or injection attempt)
  # and fall back to the documented default. ds_sql_escape does not protect an
  # unquoted numeric SQL position; the integer check makes the slot unconditionally safe.
  case "$MAX_ROWS" in ''|*[!0-9]*) MAX_ROWS=5000 ;; esac
  # String slots go through ds_sql_escape. Including the branch —
  # a value like `feat/o'hare` would otherwise break the INSERT.
  SUMMARY_ESC=$(ds_sql_escape "$SUMMARY")
  TAGS_ESC=$(ds_sql_escape "$TAGS")
  SOURCE_ESC=$(ds_sql_escape "$SOURCE")
  BRANCH_ESC=$(ds_sql_escape "$BRANCH")
  sqlite3 "$DB" \
    "INSERT INTO turns (ts, branch, summary, tags, source) VALUES ('$TS', '$BRANCH_ESC', '$SUMMARY_ESC', '$TAGS_ESC', '$SOURCE_ESC');
DELETE FROM turns WHERE id NOT IN (SELECT id FROM turns ORDER BY ts DESC LIMIT $MAX_ROWS);"
}

cmd_recall() {
  cmd_init
  # CLAGENTIC_RECALL_LIMIT: max rows returned (default 5).
  RECALL_LIMIT="${CLAGENTIC_RECALL_LIMIT:-5}"
  # Integer guard: reject non-integer values and fall back to the documented default.
  # ds_sql_escape does not protect an unquoted numeric SQL LIMIT position.
  case "$RECALL_LIMIT" in ''|*[!0-9]*) RECALL_LIMIT=5 ;; esac
  # CLAGENTIC_RECALL_MAX_CHARS: hard cap on total injected text (default 1500).
  # Whole rows are dropped from the tail; the last retained row is never split.
  RECALL_MAX_CHARS="${CLAGENTIC_RECALL_MAX_CHARS:-1500}"
  # Integer guard: reject non-integer values and fall back to the documented default.
  # Used in shell arithmetic; a non-integer here would cause a syntax error or worse.
  case "$RECALL_MAX_CHARS" in ''|*[!0-9]*) RECALL_MAX_CHARS=1500 ;; esac
  KW="$*"
  if [ -z "$KW" ]; then
    RAW=$(sqlite3 -separator ' | ' "$DB" "SELECT ts, substr(summary,1,120) FROM turns ORDER BY ts DESC LIMIT $RECALL_LIMIT;")
  else
    WHERE=""
    for kw in $KW; do
      # Quote-escape (for SQL injection) AND escape LIKE wildcards % and _
      # (so a user prompt like "auth_check" doesn't match "authxcheck" etc.).
      # The ESCAPE '\' clause on each LIKE tells SQLite to treat backslash as
      # the wildcard-escape character.
      KW_ESC=$(ds_sql_escape "$kw" | sed 's/\\/\\\\/g; s/%/\\%/g; s/_/\\_/g')
      if [ -z "$WHERE" ]; then
        WHERE="(summary LIKE '%$KW_ESC%' ESCAPE '\\' OR tags LIKE '%$KW_ESC%' ESCAPE '\\')"
      else
        WHERE="$WHERE OR (summary LIKE '%$KW_ESC%' ESCAPE '\\' OR tags LIKE '%$KW_ESC%' ESCAPE '\\')"
      fi
    done
    RAW=$(sqlite3 -separator ' | ' "$DB" \
      "SELECT ts, substr(summary,1,120) FROM turns WHERE $WHERE ORDER BY ts DESC LIMIT $RECALL_LIMIT;")
  fi
  # Apply RECALL_MAX_CHARS: accumulate lines until the budget is exhausted,
  # then drop trailing rows whole (never split mid-row).
  # Uses a temp file to avoid the pipe-subshell variable-isolation trap.
  _recall_tmp=$(mktemp -t clagentic-recall.XXXXXX)
  printf '%s\n' "$RAW" > "$_recall_tmp"
  USED=0
  while IFS= read -r _rl; do
    _rl_len=$(printf '%s\n' "$_rl" | wc -c)
    if [ $((USED + _rl_len)) -gt "$RECALL_MAX_CHARS" ]; then
      # Budget exhausted — drop this and all remaining rows.
      break
    fi
    printf '%s\n' "$_rl"
    USED=$((USED + _rl_len))
  done < "$_recall_tmp"
  rm -f "$_recall_tmp"
}

cmd_summarize_turn() {
  # Pipe stdin through the Summarizer role-call wrapper, then log-turn.
  SUMMARY=$("$TOOL_HOME/scripts/llm-client.sh" summarize | head -c 200)
  [ -z "$SUMMARY" ] && { echo "memory.sh summarize-turn: empty summary, skipping" 1>&2; exit 0; }
  TAGS=$(printf '%s' "$SUMMARY" | tr '[:upper:]' '[:lower:]' | tr -c '[:alnum:]' ' ' | tr ' ' '\n' | \
    awk 'length($0) >= 4 && !/^(this|that|with|from|have|will|what|when|where|which|should|would|could|about|into|been|being|some|then|than|over|under|done|made|note|like|just|also|here|there|their|them)$/' | \
    sort -u | head -3 | tr '\n' ' ')
  cmd_log_turn "$SUMMARY" "$TAGS" "summarize-turn"
}

cmd_digest() {
  cmd_init
  printf '\n== clagentic-lite memory digest ==\n\n'
  printf 'total turns:    %s\n' "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM turns')"
  printf 'most recent:    %s\n' "$(sqlite3 "$DB" 'SELECT ts FROM turns ORDER BY ts DESC LIMIT 1')"
  printf 'top tags:       %s\n' "$(sqlite3 "$DB" "SELECT GROUP_CONCAT(tags, ' ') FROM turns" | tr ' ' '\n' | sort | uniq -c | sort -rn | head -5 | awk '{print $2"("$1")"}' | tr '\n' ' ')"
  printf '\nlast 5:\n'
  sqlite3 -separator ' | ' "$DB" \
    'SELECT ts, branch, substr(summary,1,80) FROM turns ORDER BY ts DESC LIMIT 5'
  printf '\n'
}

cmd_seed_demo() {
  cmd_init
  cmd_log_turn "Initial auth refactor: split login() and session handling into separate modules." "auth refactor" "seed"
  cmd_log_turn "Discussed input normalization for auth; decided strip+lower is insufficient." "auth normalization" "seed"
  cmd_log_turn "Adversarial pass surfaced null-byte injection in _normalize_email; fix planned." "auth security" "seed"
}

case "${1:-}" in
  init)            cmd_init ;;
  log-turn)        shift; cmd_log_turn "$@" ;;
  recall)          shift; cmd_recall "$@" ;;
  summarize-turn)  cmd_summarize_turn ;;
  digest)          cmd_digest ;;
  seed-demo)       cmd_seed_demo ;;
  *) echo "usage: memory.sh {init|log-turn|recall|summarize-turn|digest|seed-demo}" 1>&2; exit 1 ;;
esac
