#!/bin/sh
# clagentic-lite :: memory layer
# SQLite session memory. One DB per project at .clagentic/lite/memory.db.
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

DB="$REPO_ROOT/.clagentic/lite/memory.db"
mkdir -p "$REPO_ROOT/.clagentic/lite"

# _mem_repo_root_is_scoped — true only when REPO_ROOT itself is the git repo
# `git -C "$REPO_ROOT"` will actually operate on. Local mirror of gates.sh's
# `_git_repo_root_is_scoped` (lr-da1f28 sweep) — see that helper's doc
# comment for the ancestor-walk-up rationale. Not extracted to a shared
# location: this file does not source gates.sh, and this is the only call
# site here that reads repo state rather than merely resolving REPO_ROOT.
_mem_repo_root_is_scoped() {
  _mrs_repo_root_canon=$(cd "$REPO_ROOT" 2>/dev/null && pwd -P || printf '%s' "$REPO_ROOT")
  _mrs_git_toplevel=$(git -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null || echo "")
  [ -n "$_mrs_git_toplevel" ] && [ "$_mrs_git_toplevel" = "$_mrs_repo_root_canon" ]
}

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
  # FTS5 virtual table + triggers: created only when SQLite was compiled with
  # FTS5 support (3.9+, 2015) and CLAGENTIC_DISABLE_FTS is not set.
  # Detection uses CREATE VIRTUAL TABLE on a probe table (fts5_probe), which
  # fails cleanly when FTS5 is not compiled in. The probe is deleted immediately
  # after. fts5_version() is not a global function and cannot be used for detection.
  # Failure is silent — callers fall back to LIKE.
  if [ "${CLAGENTIC_DISABLE_FTS:-0}" != "1" ]; then
    _fts5_ok=$(sqlite3 "$DB" \
      "CREATE VIRTUAL TABLE IF NOT EXISTS fts5_probe USING fts5(x); DROP TABLE IF EXISTS fts5_probe;" \
      2>/dev/null && echo 1 || echo 0)
    if [ "${_fts5_ok:-0}" = "1" ]; then
      sqlite3 "$DB" <<'SQL'
CREATE VIRTUAL TABLE IF NOT EXISTS turns_fts USING fts5(summary, tags, content=turns, content_rowid=id);
CREATE TRIGGER IF NOT EXISTS turns_fts_insert AFTER INSERT ON turns BEGIN
  INSERT INTO turns_fts(rowid, summary, tags) VALUES (new.id, new.summary, new.tags);
END;
CREATE TRIGGER IF NOT EXISTS turns_fts_delete AFTER DELETE ON turns BEGIN
  INSERT INTO turns_fts(turns_fts, rowid, summary, tags) VALUES ('delete', old.id, old.summary, old.tags);
END;
CREATE TRIGGER IF NOT EXISTS turns_fts_update AFTER UPDATE ON turns BEGIN
  INSERT INTO turns_fts(turns_fts, rowid, summary, tags) VALUES ('delete', old.id, old.summary, old.tags);
  INSERT INTO turns_fts(rowid, summary, tags) VALUES (new.id, new.summary, new.tags);
END;
SQL
      # Backfill: if turns_fts is empty but turns has rows, populate from turns.
      # This covers existing installations where rows predate FTS5 schema creation.
      _fts_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM turns_fts;" 2>/dev/null || echo 0)
      _turns_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM turns;" 2>/dev/null || echo 0)
      if [ "${_fts_count:-0}" = "0" ] && [ "${_turns_count:-0}" != "0" ]; then
        sqlite3 "$DB" "INSERT INTO turns_fts(rowid, summary, tags) SELECT id, summary, tags FROM turns;" 2>/dev/null || true
      fi
    fi
  fi
}

cmd_log_turn() {
  cmd_init
  SUMMARY="$1"
  TAGS="${2:-}"
  SOURCE="${3:-manual}"

  # CHOKEPOINT DEGRADED GUARD (lr-7047bf, INV-1b, fold-in, BOBBIE finding 3):
  # log-turn is the single sink every summarizer-role caller in this repo
  # funnels through -- memory.sh's own cmd_summarize_turn, plus every
  # external caller that pipes llm-client.sh's `summarize` output here
  # (.claude/hooks/stop-summarize.sh, .claude/hooks/post-tool-nudge.sh).
  # Requiring every CALLER to remember a degraded check is exactly the
  # defect class this task closes -- a forgetful caller (twice, now,
  # discovered in two separate hook files after this task's own gates.sh
  # fix shipped) writes a fabricated summarizer-degraded banner into
  # session memory as if it were real content. Rejecting the payload here,
  # at the one place all of them write, makes the wrong form UNWRITABLE
  # rather than merely discouraged -- callers should still skip the write
  # themselves (cheaper, avoids a wasted round-trip through this function),
  # but a caller that doesn't is now caught anyway, not just documented.
  #
  # Detection: emit_degraded's line-mode banner (llm-client.sh) is
  # prefixed with DEGRADED_MARKER, a literal ASCII SOH byte (0x01,
  # unforgeable by a real model response stream -- see llm-client.sh's own
  # DEGRADED_MARKER comment for the full rationale). A real summary, manual
  # pin, or seed-demo string can never legitimately start with this byte,
  # so checking for it can never reject genuine content.
  _lt_first_byte=$(printf '%s' "$SUMMARY" | head -c 1 | od -An -tx1 2>/dev/null | tr -d ' \n')
  if [ "$_lt_first_byte" = "01" ]; then
    echo "memory.sh log-turn: refusing to write a degraded-marked payload (source=$SOURCE) — not writing a fabricated summary" 1>&2
    return 1
  fi

  # Repo-scoped (lr-da1f28 sweep): `-C "$REPO_ROOT"` alone does not stop
  # git's ancestor-directory discovery — see _mem_repo_root_is_scoped's doc
  # comment. Without this guard, a non-git REPO_ROOT with a git ancestor
  # would silently stamp this row with the ancestor repo's branch name.
  BRANCH=""
  if _mem_repo_root_is_scoped; then
    BRANCH=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
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
  # Pin-first ordering: source='manual' rows surface before auto rows (lr-17a8).
  # Within each group, most-recent-first.  ORDER BY uses only user-authored facts
  # (source and ts) — never a computed score.  Bright line: tome #552.
  #
  # Display-only occurrence count: a correlated subquery counts rows whose summary
  # shares the first 60 chars with this row.  Appended to the display text only;
  # MUST NOT appear in any ORDER BY or WHERE clause.  Omitted when count = 1.
  # Correlated subquery is safe on old SQLite (macOS ships pre-3.25 without window
  # functions) — no window function required.
  #
  # The [pin] marker is embedded in the summary text column (second column) so the
  # existing ' | ' separator contract between columns is not broken.
  _SEEN_EXPR="(SELECT COUNT(*) FROM turns t2 WHERE t2.summary LIKE substr(t1.summary,1,60) || '%')"
  _DISP_EXPR="CASE WHEN t1.source='manual' THEN '[pin] ' ELSE '' END ||
    substr(t1.summary,1,120) ||
    CASE WHEN ($_SEEN_EXPR) >= 2 THEN ' (seen ' || ($_SEEN_EXPR) || ')' ELSE '' END"
  if [ -z "$KW" ]; then
    RAW=$(sqlite3 -separator ' | ' "$DB" \
      "SELECT t1.ts, $_DISP_EXPR
       FROM turns t1
       ORDER BY (t1.source='manual') DESC, t1.ts DESC
       LIMIT $RECALL_LIMIT;")
  else
    # FTS5 path: use MATCH for filtering when turns_fts exists and FTS is not
    # disabled. ORDER BY remains recency+intent only — never by BM25 rank.
    # Bright-line: FTS5 changes which rows are candidates, not their visible
    # ordering. (AGENTS.md hc-2026-06-01-litemem, tome #552.)
    _use_fts=0
    if [ "${CLAGENTIC_DISABLE_FTS:-0}" != "1" ]; then
      _fts_exists=$(sqlite3 "$DB" \
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='turns_fts';" 2>/dev/null || echo 0)
      if [ "${_fts_exists:-0}" = "1" ]; then
        _use_fts=1
      fi
    fi
    if [ "$_use_fts" = "1" ]; then
      # Build FTS5 MATCH expression: each keyword double-quoted to prevent
      # FTS5 from interpreting user text as operator syntax (AND/OR/NOT/NEAR).
      # Double-quote chars inside the keyword are escaped by doubling ("").
      # Space between terms = implicit OR in FTS5.
      FTS_QUERY=""
      for kw in $KW; do
        # Escape any embedded double-quote by doubling it (FTS5 convention).
        _fkw=$(printf '%s' "$kw" | sed 's/"/""/g')
        if [ -z "$FTS_QUERY" ]; then
          FTS_QUERY="\"$_fkw\""
        else
          # Explicit OR between terms: FTS5 uses AND by default for adjacent
          # quoted phrases; explicit OR gives correct multi-keyword recall.
          FTS_QUERY="$FTS_QUERY OR \"$_fkw\""
        fi
      done
      RAW=$(sqlite3 -separator ' | ' "$DB" \
        "SELECT t1.ts, $_DISP_EXPR
         FROM turns t1
         JOIN turns_fts f ON t1.id = f.rowid
         WHERE turns_fts MATCH '$FTS_QUERY'
         ORDER BY (t1.source='manual') DESC, t1.ts DESC
         LIMIT $RECALL_LIMIT;" 2>/dev/null || true)
    else
      # LIKE fallback: used when FTS5 is unavailable or CLAGENTIC_DISABLE_FTS=1.
      WHERE=""
      for kw in $KW; do
        # Quote-escape (for SQL injection) AND escape LIKE wildcards % and _
        # (so a user prompt like "auth_check" doesn't match "authxcheck" etc.).
        # The ESCAPE '\' clause on each LIKE tells SQLite to treat backslash as
        # the wildcard-escape character.
        KW_ESC=$(ds_sql_escape "$kw" | sed 's/\\/\\\\/g; s/%/\\%/g; s/_/\\_/g')
        if [ -z "$WHERE" ]; then
          WHERE="(t1.summary LIKE '%$KW_ESC%' ESCAPE '\\' OR t1.tags LIKE '%$KW_ESC%' ESCAPE '\\')"
        else
          WHERE="$WHERE OR (t1.summary LIKE '%$KW_ESC%' ESCAPE '\\' OR t1.tags LIKE '%$KW_ESC%' ESCAPE '\\')"
        fi
      done
      RAW=$(sqlite3 -separator ' | ' "$DB" \
        "SELECT t1.ts, $_DISP_EXPR
         FROM turns t1
         WHERE $WHERE
         ORDER BY (t1.source='manual') DESC, t1.ts DESC
         LIMIT $RECALL_LIMIT;")
    fi
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
  #
  # STATUS-CHECKED + DEGRADED-CHECKED (lr-7047bf, INV-1b, fold-in): this was
  # the fifth, unwired consumer of walk_chain's outcome channel — the exact
  # defect class this task exists to close, hiding in the one file the
  # gates.sh-scoped sweep (test_llm_client_consumer_sweep.py) could not see.
  # walk_chain now returns 3 whenever it emits a degraded envelope
  # (llm-client.sh:1461-1468, 1557-1571), and llm-client.sh's cmd_summarize
  # now propagates that status as its own exit status (fixed alongside this
  # site — it used to be lost on a `walk_chain | head -c 200; echo` pipeline,
  # whose reported status was always echo's, i.e. always 0). Capturing the
  # status directly on the call here (`|| _szt_status=$?`, no pipe after the
  # command substitution) is what makes that status observable at all.
  #
  # walk_chain's summarizer role has TWO distinct emit_degraded-adjacent
  # outcomes, and they must not be conflated:
  #   - no chain configured at all: a deliberate, silent, exempted no-op
  #     (walk_chain returns 0, empty stdout) — established by
  #     test_walk_chain_degraded_status.py
  #     ::test_summarizer_role_with_no_chain_still_returns_0. This remains a
  #     silent skip; an unconfigured summarizer must not start "failing".
  #   - a chain IS configured and every step failed: walk_chain returns 3
  #     and writes a non-empty "[clagentic-lite degraded] ..." line
  #     (emit_degraded, line mode). Previously this line was indistinguishable
  #     from a real summary — non-empty, so the old empty-string guard below
  #     did not fire, and the degraded banner was truncated to 200 chars and
  #     written into the turns table via cmd_log_turn as a FABRICATED SUMMARY,
  #     polluting session memory and lore recall with an infra-failure banner
  #     disguised as real content.
  #
  # Decision: on a genuine degraded chain, do NOT write to the turns table —
  # a missing summary is correct, a fabricated one is not — and log the
  # failure to stderr so it is visible without being written to persistent
  # memory. This mirrors the "surfaced, not silent; not written as data"
  # posture gates.sh uses for its own degraded consumers.
  #
  # ALL THREE degraded exit statuses checked explicitly (lr-49df97 fold-in,
  # HOLDEN "also verify" item): this used to test only `-eq 3`, and relied
  # on the text-marker grep (below) to ALSO catch status 4 ("unwrap") and 5
  # ("turns-exhausted") by accident -- emit_degraded's line-mode banner
  # ("[clagentic-lite degraded] (CAUSE) ...") contains the same literal
  # substring regardless of cause, so the grep happened to be cause-agnostic
  # even though the status comparison next to it was not. That accident held
  # for causes 3/4/5 only because emit_degraded's banner text was designed
  # that way; a future new exit code is NOT guaranteed to share it, and
  # nothing here would tell a reader that the status check itself was
  # incomplete. Testing -eq 3/4/5 explicitly makes the intent (every
  # walk_chain degraded outcome, not just "infra") visible in the code
  # itself rather than only in this comment; the text-marker check remains
  # as defense in depth for a caller path that loses the status but still
  # sees the payload.
  _szt_status=0
  SUMMARY=$("$TOOL_HOME/scripts/llm-client.sh" summarize) || _szt_status=$?
  if [ "$_szt_status" -eq 3 ] || [ "$_szt_status" -eq 4 ] || [ "$_szt_status" -eq 5 ] || printf '%s' "$SUMMARY" | grep -qF '[clagentic-lite degraded]'; then
    echo "memory.sh summarize-turn: summarizer chain degraded (status=$_szt_status), skipping — not writing a fabricated summary" 1>&2
    exit 0
  fi
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
  # Tag-grouped recent view (lr-17a8): replace the flat "last 5" block with entries
  # grouped by the first literal tag token in the tags column.  Grouping key is a
  # string the user (or the summarizer) wrote — not computed similarity.  Entries
  # with no tags fall under "(untagged)".
  #
  # Display-only occurrence count follows the same bright-line rule as cmd_recall:
  # the count is computed in a correlated subquery, appended to the display text,
  # and MUST NOT appear in any ORDER BY or WHERE (tome #552).
  printf '\nby tag:\n'
  # Fetch up to 20 recent rows with first-tag and display text.
  # The seen-N count is display-only; the ORDER BY is recency only.
  _SEEN_D="(SELECT COUNT(*) FROM turns t2 WHERE t2.summary LIKE substr(t1.summary,1,60) || '%')"
  _DISP_D="CASE WHEN t1.source='manual' THEN '[pin] ' ELSE '' END ||
    substr(t1.summary,1,80) ||
    CASE WHEN ($_SEEN_D) >= 2 THEN ' (seen ' || ($_SEEN_D) || ')' ELSE '' END"
  # First tag token: take the portion of tags before the first space (or the whole
  # string if no space).  Empty/null tags map to the literal string '(untagged)'.
  _TAG_EXPR="CASE WHEN tags IS NULL OR tags='' THEN '(untagged)'
    ELSE CASE WHEN instr(tags,' ')>0 THEN substr(tags,1,instr(tags,' ')-1) ELSE tags END
  END"
  _digest_tmp=$(mktemp -t clagentic-digest.XXXXXX)
  sqlite3 -separator '	' "$DB" \
    "SELECT $_TAG_EXPR, t1.ts, $_DISP_D
     FROM turns t1
     ORDER BY t1.ts DESC
     LIMIT 20;" > "$_digest_tmp"
  # Iterate over rows, printing a header line when the tag group changes.
  _cur_tag=""
  while IFS='	' read -r _tag _ts _disp; do
    if [ "$_tag" != "$_cur_tag" ]; then
      printf '\n  [%s]\n' "$_tag"
      _cur_tag="$_tag"
    fi
    printf '    %s  %s\n' "$_ts" "$_disp"
  done < "$_digest_tmp"
  rm -f "$_digest_tmp"
  printf '\n'
}

cmd_seed_demo() {
  cmd_init
  cmd_log_turn "Initial auth refactor: split login() and session handling into separate modules." "auth refactor" "seed"
  cmd_log_turn "Discussed input normalization for auth; decided strip+lower is insufficient." "auth normalization" "seed"
  cmd_log_turn "Adversarial pass surfaced null-byte injection in _normalize_email; fix planned." "auth security" "seed"
}

# ENROLL-TIME TRUST GATE (lr-33fb89, PR #152 second fold-in, coordinator-
# escalated bobbie.sast.3 follow-through) -- mirrors the identical gate in
# gates.sh; see that file's own comment at its dispatch site for the full
# rationale. `init` is the ONE subcommand reachable BEFORE a repo has been
# enrolled (`clagentic-lite enroll` invokes `memory.sh init` directly,
# bin/clagentic-lite _enroll_one, from cwd that is commonly INSIDE the
# not-yet-enrolled target repo). cmd_init reads no CLAGENTIC_* config value
# except CLAGENTIC_DISABLE_FTS (a host/environment sqlite3-capability knob,
# not a per-repo semantic choice), so skipping ds_load_env for `init`
# specifically closes the pre-trust execution window with no material
# behavior change. Every other subcommand (log-turn, recall, summarize-turn,
# digest, seed-demo) is reachable only post-enrollment (hook shims/operator
# already working in an enrolled repo) and still gets the full, unchanged
# ds_load_env exactly as before this fold-in.
if [ "${1:-}" != "init" ]; then
  ds_load_env
fi

case "${1:-}" in
  init)            cmd_init ;;
  log-turn)        shift; cmd_log_turn "$@" ;;
  recall)          shift; cmd_recall "$@" ;;
  summarize-turn)  cmd_summarize_turn ;;
  digest)          cmd_digest ;;
  seed-demo)       cmd_seed_demo ;;
  *) echo "usage: memory.sh {init|log-turn|recall|summarize-turn|digest|seed-demo}" 1>&2; exit 1 ;;
esac
