#!/bin/sh
# clagentic-lite :: PreToolUse (Write|Edit) hook
# Blocks writes to the default branch, outside the repo, or to sensitive paths.
# Exit 2 = block.

set -e

HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || HOOK_DIR=.
. "$HOOK_DIR/../../scripts/platform.sh"
ds_load_env

DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
REPO_ROOT=$(ds_repo_root || echo "")

# Read the Claude Code tool-call JSON and extract file_path via real JSON
# parsing — NOT sed.
INPUT=$(cat 2>/dev/null || true)
JF_EXIT=0
RAW_PATH=$(printf '%s' "$INPUT" | ds_json_field file_path) || JF_EXIT=$?

# Fail closed on ANY non-zero ds_json_field exit. See pre-bash-guard.sh.
if [ "$JF_EXIT" -ne 0 ]; then
  case "$JF_EXIT" in
    2) REASON="no JSON validator available (install jq or python3)" ;;
    *) REASON="malformed JSON payload" ;;
  esac
  printf '[clagentic-lite/pre-write-guard] BLOCKED: %s\n' "$REASON" 1>&2
  ds_audit_log write-guard block "fail-closed: $REASON"
  exit 2
fi

[ -z "$RAW_PATH" ] && exit 0

# Normalize the path so relative inputs like "../outside.txt" can't bypass the
# repo-scope check. Resolve against REPO_ROOT (the path doesn't have to exist;
# we just want a canonical absolute form).
if command -v python3 >/dev/null 2>&1 && [ -n "$REPO_ROOT" ]; then
  PATH_TARGET=$(python3 -c '
import os, sys
root = sys.argv[1]
raw = sys.argv[2]
# os.path.realpath normalizes ../ and absolute paths alike.
# Resolve relative paths against the repo root, not the cwd.
if os.path.isabs(raw):
    sys.stdout.write(os.path.realpath(raw))
else:
    sys.stdout.write(os.path.realpath(os.path.join(root, raw)))
' "$REPO_ROOT" "$RAW_PATH" 2>/dev/null)
else
  # No python3 — keep the raw value. The rule checks below are less robust
  # without normalization; `clagentic doctor` warns about this case.
  PATH_TARGET="$RAW_PATH"
fi

[ -z "$PATH_TARGET" ] && PATH_TARGET="$RAW_PATH"

block() {
  RULE="$1"
  REASON="$2"
  printf '[clagentic-lite/pre-write-guard] BLOCKED: %s — %s\n  path: %s\n' "$RULE" "$REASON" "$PATH_TARGET" 1>&2
  ds_audit_log write-guard block "$RULE: $PATH_TARGET"
  exit 2
}

# W-001: writes only on a feature branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [ "${CLAGENTIC_ALLOW_DEFAULT_BRANCH_WRITE:-0}" != "1" ] && [ "$CURRENT_BRANCH" = "$DEFAULT_BRANCH" ]; then
  block W-001 "writes forbidden on default branch '$DEFAULT_BRANCH'"
fi

# W-002: writes only inside repo. After normalization PATH_TARGET is absolute;
# any path outside REPO_ROOT (including ../-traversal targets) trips this.
if [ -n "$REPO_ROOT" ]; then
  case "$PATH_TARGET" in
    "$REPO_ROOT"|"$REPO_ROOT"/*) : ;;
    /*) block W-002 "write target outside repo root '$REPO_ROOT'" ;;
    *)  block W-002 "could not resolve write target against repo root '$REPO_ROOT'" ;;
  esac
fi

# W-003: writes to sensitive paths
case "$PATH_TARGET" in
  *.git/*|*/.git/*) block W-003 "writes to .git/ are forbidden" ;;
  *.clagentic/*|*/.clagentic/*) block W-003 "writes to .clagentic/ are forbidden" ;;
  *.env|*/.env) block W-003 "writes to .env are forbidden" ;;
esac

# W-004: credential file patterns
case "$PATH_TARGET" in
  *.pem|*id_rsa*|*.key) block W-004 "writes to credential-shaped files are forbidden" ;;
esac

exit 0
