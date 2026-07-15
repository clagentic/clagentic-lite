#!/bin/sh
# clagentic-lite :: PreToolUse (Write|Edit) hook
# Blocks writes to the default branch, outside the repo, or to sensitive paths.
# Exit 2 = block.

# set -e intentionally absent: unexpected failures must exit 0, not crash the
# session. Only the explicit block() paths below exit 2 to block a tool call.
# If platform.sh is missing or broken the hook fails open (allow + no audit).

HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || HOOK_DIR=.
if ! . "$HOOK_DIR/../../scripts/platform.sh" 2>/dev/null; then
  exit 0
fi
ds_load_env 2>/dev/null || true

DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
REPO_ROOT=$(ds_repo_root || echo "")

# Wrapper-CWD fallback: if CWD is not a git repo but has a .clagentic-project
# pointer, read the first enrolled repo path and use it as REPO_ROOT so W-001
# and W-002 checks operate against the actual project repo.
# If neither applies, keep fail-closed behavior (REPO_ROOT stays empty).
if [ -z "$REPO_ROOT" ] && [ -f "${PWD}/.clagentic-project" ]; then
  _pwg_primary=$(head -n 1 "${PWD}/.clagentic-project" 2>/dev/null || true)
  if [ -n "$_pwg_primary" ]; then
    REPO_ROOT="$_pwg_primary"
  fi
fi

# Read the Claude Code tool-call JSON and extract file_path via real JSON
# parsing — NOT sed.
INPUT=$(cat 2>/dev/null || true)
JF_EXIT=0
RAW_PATH=$(printf '%s' "$INPUT" | ds_json_field file_path) || JF_EXIT=$?

# W-006 signal capture (warn-only, non-blocking): Claude Code populates
# agent_type in the PreToolUse payload only when the tool call fires inside a
# named subagent (verified precedent: lr-2a51, Claude Code docs
# https://code.claude.com/docs/en/hooks). Its ABSENCE is the verified signal
# that this Write/Edit was authored by the main/orchestrator loop rather than
# a dispatched subagent — we do not hardcode a specific builder agent_type
# string here because the exact value the `clagentic-lite:builder` subagent
# emits (namespaced vs bare) has not been empirically confirmed; keying on
# absence is the only signal confirmed safe to use. A JSON-parse failure on
# this best-effort read must NOT escalate to a W-006 warning or affect the
# fail-closed JF_EXIT handling below — AGENT_TYPE simply stays empty and W-006
# treats that the same as "absent".
AGENT_TYPE=$(printf '%s' "$INPUT" | ds_json_field agent_type 2>/dev/null || true)

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
  # python3 not available — use POSIX sh fallback to resolve ../ traversal.
  # This resolves ../ components but does not resolve symlinks.
  _posix_realpath() {
    _pr_path="$1"
    # Make absolute: join with REPO_ROOT if relative.
    case "$_pr_path" in
      /*) ;;
      *)  _pr_path="$REPO_ROOT/$_pr_path" ;;
    esac
    # Walk up from the full path, finding the deepest existing ancestor,
    # then reconstruct the path from pwd + remaining components.
    _pr_tail=""
    while [ -n "$_pr_path" ] && [ "$_pr_path" != "/" ]; do
      if _pr_dir=$(CDPATH= cd -- "$_pr_path" 2>/dev/null && pwd); then
        # Found an existing ancestor; return its pwd + tail.
        printf '%s%s' "$_pr_dir" "$_pr_tail"
        return 0
      fi
      # Parent doesn't exist; accumulate the component and walk up.
      _pr_tail="/$(basename "$_pr_path")$_pr_tail"
      _pr_path=$(dirname "$_pr_path")
    done
    # Fallback: return the joined absolute path (still better than raw).
    printf '%s' "$REPO_ROOT/$RAW_PATH"
  }
  PATH_TARGET=$(_posix_realpath "$RAW_PATH")
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
# Use REPO_ROOT for the branch check so wrapper sessions (where $PWD is not a
# git repo) resolve the branch against the actual enrolled repo, not the
# wrapper directory. Without -C, git rev-parse returns "" in a wrapper CWD,
# "$ != main" is false, and W-001 silently allows writes to main.
CURRENT_BRANCH=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [ "${CLAGENTIC_ALLOW_DEFAULT_BRANCH_WRITE:-0}" != "1" ] && [ "$CURRENT_BRANCH" = "$DEFAULT_BRANCH" ]; then
  block W-001 "writes forbidden on default branch '$DEFAULT_BRANCH'"
fi

# W-002: writes only inside repo. After normalization PATH_TARGET is absolute;
# any path outside REPO_ROOT (including ../-traversal targets) trips this.
# Fail-closed when REPO_ROOT is empty: we cannot determine what "inside the
# repo" means, so any write must be blocked rather than allowed through.
# This matches the bash-guard's "can't evaluate → block" stance.
if [ -z "$REPO_ROOT" ]; then
  block W-002 "cannot determine repo root — blocking write to unknown scope"
fi
case "$PATH_TARGET" in
  "$REPO_ROOT"|"$REPO_ROOT"/*) : ;;
  /*) block W-002 "write target outside repo root '$REPO_ROOT'" ;;
  *)  block W-002 "could not resolve write target against repo root '$REPO_ROOT'" ;;
esac

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

# W-005 (warn-only, non-blocking): editing a cache-prefix artifact mid-session
# invalidates Claude's prompt cache. Claude's cache is a prefix over:
#   tool definitions → system prompt → messages
# Any change to CLAUDE.md, hook scripts, settings.json, or MCP config causes the
# next LLM call to pay full input cost (the 1.25x write cost is wasted too).
warn_cache() {
  printf '[clagentic-lite/pre-write-guard] WARN W-005: editing a cache-prefix artifact mid-session invalidates the prompt cache — next turn will pay full input cost\n' 1>&2
  ds_audit_log write-guard warn "W-005: cache-prefix artifact edit: $PATH_TARGET"
}

case "$PATH_TARGET" in
  */CLAUDE.md) warn_cache ;;
  */.claude/settings.json) warn_cache ;;
  */.claude/settings.local.json) warn_cache ;;
  */.claude/hooks/*.sh) warn_cache ;;
  */.claude/*mcp*|*/.claude/*MCP*) warn_cache ;;
esac

# W-006 (warn-only, non-blocking, AGGRESSIVE): the orchestrator (main Claude
# Code loop) is authoring code directly instead of delegating to the
# clagentic-lite:builder subagent. Detected by the ABSENCE of agent_type in
# the PreToolUse payload — see the AGENT_TYPE capture above for why absence,
# not a specific subagent string, is the signal. Decision (Andy, 2026-07-15):
# warn-only, no hard-block, exit 0 always. Subagent calls (agent_type present)
# pass through untouched — no message, no audit row.
warn_delegate() {
  printf '[clagentic-lite/pre-write-guard] WARN W-006: this Write/Edit was authored by the orchestrator, not a subagent — DELEGATE to the clagentic-lite:builder subagent for code changes. The orchestrator should not author code directly; use the Builder role so cross-vendor review and the gate chain apply as designed.\n  path: %s\n' "$PATH_TARGET" 1>&2
  ds_audit_log write-guard warn "W-006: orchestrator authored write (no agent_type): $PATH_TARGET"
}

if [ -z "$AGENT_TYPE" ]; then
  warn_delegate
fi

exit 0
