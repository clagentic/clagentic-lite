#!/bin/sh
# clagentic-lite :: platform shims
# Detects GNU vs BSD tools and exports portable variants.
# Source this in every script: . "$(dirname "$0")/platform.sh"

# OS detection
case "$(uname -s)" in
  Linux*)  DS_OS="linux" ;;
  Darwin*) DS_OS="darwin" ;;
  *)       DS_OS="unknown" ;;
esac
export DS_OS

# sed -i variant
if sed --version >/dev/null 2>&1; then
  DS_SED_INPLACE="-i"        # GNU
else
  DS_SED_INPLACE="-i ''"     # BSD (macOS)
fi
export DS_SED_INPLACE

# date ISO-8601
if date -Iseconds >/dev/null 2>&1; then
  DS_DATE_ISO_CMD='date -Iseconds'
else
  DS_DATE_ISO_CMD='date -u +%Y-%m-%dT%H:%M:%SZ'
fi
ds_date_iso() { eval "$DS_DATE_ISO_CMD"; }
export DS_DATE_ISO_CMD

# stat mtime (epoch)
if stat -c %Y . >/dev/null 2>&1; then
  ds_stat_mtime() { stat -c %Y "$1"; }    # GNU
else
  ds_stat_mtime() { stat -f %m "$1"; }    # BSD
fi

# Are we under WSL?
DS_WSL=0
if [ "$DS_OS" = "linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
  DS_WSL=1
fi
export DS_WSL

# Repo root (cached)
ds_repo_root() {
  git rev-parse --show-toplevel 2>/dev/null
}

# Load configuration into the current shell. Load order (each layer can
# override the previous):
#   1. ~/.config/clagentic/config   — global defaults (written by `clagentic init`)
#   2. <project-root>/.clagentic/config — per-repo sparse overrides (optional)
#   3. Legacy: <project-root>/.env  — backward compat; honored if present
#
# Idempotent — honors a CLAGENTIC_ENV_LOADED guard so re-sourcing in the
# same process doesn't double-export. Every runtime entry point (hooks,
# gates.sh, llm-client.sh, memory.sh, smoke.sh) calls this immediately
# after sourcing platform.sh.
ds_load_env() {
  [ "${CLAGENTIC_ENV_LOADED:-0}" = "1" ] && return 0

  # 1. Global config.
  _GLOBAL_CFG="$HOME/.config/clagentic/config"
  if [ -f "$_GLOBAL_CFG" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$_GLOBAL_CFG"
    set +a
  fi

  RR=$(ds_repo_root)
  if [ -n "$RR" ]; then
    # 2. Per-repo sparse config (v0.2: optional; not created by default).
    _REPO_CFG="$RR/.clagentic/config"
    if [ -f "$_REPO_CFG" ]; then
      set -a
      # shellcheck disable=SC1090
      . "$_REPO_CFG"
      set +a
    fi
    # 3. Legacy .env (v0.1 compatibility; honored but not created in v0.2).
    _ENV_FILE="$RR/.env"
    if [ -f "$_ENV_FILE" ]; then
      set -a
      # shellcheck disable=SC1090
      . "$_ENV_FILE"
      set +a
    fi
  fi

  CLAGENTIC_ENV_LOADED=1
  export CLAGENTIC_ENV_LOADED
}

# Portable timeout. GNU coreutils ships `timeout`. macOS does NOT by default —
# users install it via `brew install coreutils` which provides `gtimeout`.
# Detect at source time and export DS_TIMEOUT_CMD. Callers run:
#   $DS_TIMEOUT_CMD "$LLM_TIMEOUT" some-cli ...
# When neither tool is present, DS_TIMEOUT_CMD is set to an empty wrapper
# that runs the command without a timeout — degraded but doesn't fail-open
# in a confusing way (`clagentic doctor` warns when timeout is missing).
if command -v timeout >/dev/null 2>&1; then
  DS_TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  DS_TIMEOUT_CMD="gtimeout"
else
  # Stub: ignore the timeout arg, run the rest.
  ds_no_timeout() { shift; "$@"; }
  DS_TIMEOUT_CMD="ds_no_timeout"
fi
export DS_TIMEOUT_CMD

# ---------------------------------------------------------------- shared helpers

# Escape a string for safe single-quoted SQL interpolation.
# POSIX sed: replace every single quote with two single quotes.
ds_sql_escape() {
  printf '%s' "$1" | sed "s/'/''/g"
}

# Write one row to .clagentic/audit.db. Resolves repo root itself so callers
# from any cwd (subdirectory hook invocations, etc.) hit the right DB.
# Args: GATE OUTCOME DETAILS [SESSION_ID]
# Silent on any failure — audit logging is best-effort by contract.
ds_audit_log() {
  GATE="$1"; OUTCOME="$2"; DETAILS="${3:-}"; SID="${4:-}"
  RR=$(ds_repo_root)
  [ -n "$RR" ] || return 0
  DB="$RR/.clagentic/audit.db"
  [ -f "$DB" ] || return 0
  G_ESC=$(ds_sql_escape "$GATE")
  O_ESC=$(ds_sql_escape "$OUTCOME")
  D_ESC=$(ds_sql_escape "$DETAILS")
  S_ESC=$(ds_sql_escape "$SID")
  sqlite3 "$DB" \
    "INSERT INTO gate_runs (ts, gate, outcome, details, session_id) VALUES (datetime('now'), '$G_ESC', '$O_ESC', '$D_ESC', '$S_ESC');" 2>/dev/null || true
}

# Extract a top-level string field from a JSON object on stdin.
# Args: FIELD_NAME
# Uses jq if present, python3 as fallback. Robust against escaped quotes and
# unicode escapes — sed-based parsing was vulnerable to truncation on `\"`.
#
# Exit codes:
#   0 — field extracted (may be empty if the JSON has it set to "")
#   1 — JSON parse error
#   2 — NO VALIDATOR AVAILABLE. Caller MUST fail closed: a hook without a
#       JSON validator cannot trust its input, so it must block rather than
#       silently exit 0.
ds_json_field() {
  FIELD="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg f "$FIELD" '.[$f] // empty' 2>/dev/null
    return $?
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys
try:
    obj = json.load(sys.stdin)
    v = obj.get(sys.argv[1], "")
    if v is None: v = ""
    sys.stdout.write(str(v))
except Exception:
    sys.exit(1)
' "$FIELD" 2>/dev/null
    return $?
  else
    # No validator. Fail closed signal to the caller.
    return 2
  fi
}

# ---------------------------------------------------------------- tool detection
#
# ds_check_tool NAME HINT_LINUX HINT_DARWIN
#   Prints "found: /path" or "MISSING — install: <hint>" based on OS.
#   Returns 0 if found, 1 if missing.
#   REQUIRED flag: when the fourth arg is "required", also sets DS_CHECK_MISSING
#   (caller initializes DS_CHECK_MISSING=0 before a loop and inspects after).
#
# ds_offer_install NAME HINT_LINUX HINT_DARWIN
#   Calls ds_check_tool. If missing and stdin is a TTY, prompts
#   "Run it now? [y/N]:" and on 'y' execs the install command.
#   On 'N' (or non-TTY), prints the manual command and returns 1.
#   Returns 0 if the tool was already present, or if the user ran the install
#   command successfully. Returns 1 if the user declined or the install failed.
#   Callers use this for REQUIRED tools where a missing tool is a hard stop.

ds_check_tool() {
  _CT_NAME="$1"
  _CT_LINUX="$2"
  _CT_DARWIN="$3"
  _CT_FLAG="${4:-}"
  if command -v "$_CT_NAME" >/dev/null 2>&1; then
    printf '  %-15s found: %s\n' "$_CT_NAME" "$(command -v "$_CT_NAME")"
    return 0
  fi
  if [ "$DS_OS" = "darwin" ]; then
    printf '  %-15s MISSING — install: %s\n' "$_CT_NAME" "$_CT_DARWIN"
  else
    printf '  %-15s MISSING — install: %s\n' "$_CT_NAME" "$_CT_LINUX"
  fi
  if [ "${_CT_FLAG:-}" = "required" ]; then
    DS_CHECK_MISSING=$((${DS_CHECK_MISSING:-0}+1))
    export DS_CHECK_MISSING
  fi
  return 1
}

ds_offer_install() {
  _OI_NAME="$1"
  _OI_LINUX="$2"
  _OI_DARWIN="$3"
  if command -v "$_OI_NAME" >/dev/null 2>&1; then
    printf '  %-15s found: %s\n' "$_OI_NAME" "$(command -v "$_OI_NAME")"
    return 0
  fi
  if [ "$DS_OS" = "darwin" ]; then
    _OI_HINT="$_OI_DARWIN"
  else
    _OI_HINT="$_OI_LINUX"
  fi
  printf 'MISSING: %s — install with: %s\n' "$_OI_NAME" "$_OI_HINT"
  if [ -t 0 ]; then
    printf 'Run it now? [y/N]: '
    read -r _OI_REPLY || _OI_REPLY=""
    case "$_OI_REPLY" in
      y|Y|yes|YES)
        # exec the install command; eval needed because hint may be multi-word
        if eval "$_OI_HINT"; then
          printf '  %s installed\n' "$_OI_NAME"
          return 0
        else
          printf '  install command failed — install manually and re-run\n' 1>&2
          return 1
        fi
        ;;
    esac
  fi
  printf '  Run manually: %s\n' "$_OI_HINT"
  return 1
}
