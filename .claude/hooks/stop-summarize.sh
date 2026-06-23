#!/bin/sh
# clagentic-lite :: Stop hook
# Async: summarize the last assistant turn via the Summarizer role, write one
# row to .clagentic/lite/memory.db. Best-effort. Never blocks the user.
#
# Claude Code passes a JSON payload on stdin with fields including
# session_id, transcript_path, and stop_hook_active. We read it before
# detaching so the payload is captured before the parent closes stdin.

HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || HOOK_DIR=.
. "$HOOK_DIR/../../scripts/platform.sh" 2>/dev/null || exit 0
ds_load_env 2>/dev/null || true

DEBOUNCE="${CLAGENTIC_SUMMARIZE_DEBOUNCE_SEC:-20}"
REPO_ROOT=$(ds_repo_root || pwd)
PAYLOAD=$(cat 2>/dev/null || true)

# Pull transcript_path / session_id via real JSON parsing — NOT sed, which
# truncated on escaped quotes in path components.
TRANSCRIPT=$(printf '%s' "$PAYLOAD" | ds_json_field transcript_path)
SESSION_ID=$(printf '%s' "$PAYLOAD" | ds_json_field session_id)

# Lockfile for debounce: only the last Stop in a burst should summarize.
LOCK="$REPO_ROOT/.clagentic/lite/stop-summarize.lock"

# Fire and forget: detach so Claude Code's Stop event returns immediately.
(
  MY_PID=$$
  printf '%s\n' "$MY_PID" > "$LOCK" 2>/dev/null || true

  sleep "$DEBOUNCE"

  # Debounce check: if a newer Stop fired and wrote a different PID, exit.
  CURRENT_PID=$(cat "$LOCK" 2>/dev/null || echo "")
  [ "$CURRENT_PID" = "$MY_PID" ] || exit 0

  [ -n "$TRANSCRIPT" ] && [ -f "$TRANSCRIPT" ] || exit 0

  # Slice the last assistant turn from the JSONL transcript. python3 is
  # required for robust JSON parsing — it ships on every supported platform
  # (Ubuntu 22.04+, macOS 12+). If python3 is missing, log a one-row
  # diagnostic to audit.db and exit cleanly. A grep+tail fallback would
  # feed raw JSONL into the summarizer, which is worse than no summary.
  if ! command -v python3 >/dev/null 2>&1; then
    AUDIT="$REPO_ROOT/.clagentic/lite/audit.db"
    if [ -f "$AUDIT" ]; then
      sqlite3 "$AUDIT" \
        "INSERT INTO gate_runs (ts, gate, outcome, details) VALUES (datetime('now'), 'summarize', 'skip', 'python3 missing');" 2>/dev/null || true
    fi
    exit 0
  fi

  LAST_TURN=$(python3 - "$TRANSCRIPT" <<'PY' 2>/dev/null
import json, sys
last = None
for line in open(sys.argv[1], errors="replace"):
    line = line.strip()
    if not line: continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    # Claude Code transcript: top-level either {"role":...,"content":...}
    # (older shape) or {"type":"assistant","message":{"role":...,"content":...}}.
    role = obj.get("role") or obj.get("type") or ""
    if role == "assistant":
        c = obj.get("content")
        if c is None:
            c = obj.get("message", {}).get("content") or ""
        if isinstance(c, list):
            parts = []
            for blk in c:
                if isinstance(blk, dict) and blk.get("type") == "text":
                    parts.append(blk.get("text", ""))
            c = "\n".join(parts)
        last = c
print(last or "")
PY
)

  [ -z "$LAST_TURN" ] && exit 0

  # Run the summarizer via the role-call wrapper.
  SUMMARY=$(printf '%s' "$LAST_TURN" | "$REPO_ROOT/scripts/llm-client.sh" summarize 2>/dev/null | head -c 200)
  [ -z "$SUMMARY" ] && exit 0

  # Extract up to 3 tag tokens (>=4 chars, non-stopword) from the summary.
  TAGS=$(printf '%s' "$SUMMARY" | tr '[:upper:]' '[:lower:]' | tr -c '[:alnum:]' ' ' | tr ' ' '\n' | \
    awk 'length($0) >= 4 && !/^(this|that|with|from|have|will|what|when|where|which|should|would|could|about|into|been|being|some|then|than|over|under|been|done|made|note|like|just|also|here|there|their|them)$/' | \
    sort -u | head -3 | tr '\n' ' ')

  # Insert via memory.sh (it handles SQL escaping and schema init).
  "$REPO_ROOT/scripts/memory.sh" log-turn "$SUMMARY" "$TAGS" "stop-hook" >/dev/null 2>&1 || true

  # Log to audit trail. ds_audit_log escapes both details and session_id.
  ds_audit_log summarize pass "stop-summarize: session=$SESSION_ID" "$SESSION_ID"

  # Write handoff frame — best-effort, must not block or error.
  # Disabled by CLAGENTIC_DISABLE_HANDOFF=1.
  if [ "${CLAGENTIC_DISABLE_HANDOFF:-0}" != "1" ]; then
    HANDOFF_FILE="$REPO_ROOT/.clagentic/lite/handoff.md"
    HANDOFF_TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "unknown")
    python3 - "$HANDOFF_FILE" "$HANDOFF_TS" "$SESSION_ID" "$SUMMARY" "$LAST_TURN" <<'PY' 2>/dev/null || true
import sys, re, os

handoff_file = sys.argv[1]
ts           = sys.argv[2]
session_id   = sys.argv[3]
summary      = sys.argv[4]
last_turn    = sys.argv[5]

# Active task: last 1-2 sentences of summary.
sentences = re.split(r'(?<=[.!?])\s+', summary.strip())
active_task = ' '.join(sentences[-2:]) if len(sentences) >= 2 else summary.strip()

# Open threads: lines from summary containing "next:" / "TODO:" / unresolved markers.
thread_lines = []
for line in summary.splitlines():
    low = line.lower().strip()
    if low.startswith(('next:', 'todo:', 'follow-up:', 'followup:', '- [ ]', '* [ ]')):
        thread_lines.append(line.strip())
open_threads = '\n'.join(thread_lines) if thread_lines else '(none extracted)'

# Key files: path-like tokens from the last assistant turn.
path_pattern = re.compile(
    r'(?:^|[\s`\'"])(/[\w./\-]+[\w./\-]|[\w./\-]+(?:/[\w./\-]+)+\.\w+)',
    re.MULTILINE,
)
paths_seen = []
for m in path_pattern.finditer(last_turn):
    p = m.group(1)
    if p not in paths_seen:
        paths_seen.append(p)
key_files = '\n'.join(paths_seen[:20]) if paths_seen else '(none extracted)'

content = (
    f"## Handoff Frame — {session_id} — {ts}\n\n"
    f"### Active task\n{active_task}\n\n"
    f"### Open threads\n{open_threads}\n\n"
    f"### Key files touched\n{key_files}\n\n"
    f"### Session notes\n{summary}\n"
)

os.makedirs(os.path.dirname(handoff_file), exist_ok=True)
with open(handoff_file, 'w', encoding='utf-8') as fh:
    fh.write(content)
PY
  fi

  # Clean up lock file (best-effort).
  rm -f "$LOCK" 2>/dev/null || true
) >/dev/null 2>&1 &

exit 0
