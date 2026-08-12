#!/bin/sh
# clagentic-lite :: host adapter contract (lr-2b07a8)
#
# HOST-NEUTRAL BY CONTRACT: gate logic (gates.sh, review-merge.sh) must never
# name a git-hosting vendor directly. This file is the ONE place vendor
# names/tools are allowed to appear -- every adapter implementation lives
# here, behind three functions gate logic is permitted to call:
#
#   host_adapter_available          -- exit 0 iff a usable adapter is
#                                       discovered for REPO_ROOT's origin
#                                       remote, exit 1 otherwise (fallback).
#   host_adapter_open_change_request BASE HEAD
#                                    -- open (or find an existing) PR/MR for
#                                       HEAD against BASE. Prints nothing of
#                                       significance to stdout; status via
#                                       exit code + stderr, same posture as
#                                       the rest of gates.sh.
#   host_adapter_post_comment BODY_FILE
#                                    -- post BODY_FILE's contents as ONE
#                                       comment on the change-request thread
#                                       for the current branch. Exit 0 on
#                                       success, non-zero otherwise.
#   host_adapter_read_comments      -- print existing comment bodies for the
#                                       current branch's change request, one
#                                       JSON object per line (best-effort;
#                                       used by callers that need to check
#                                       for a prior comment before posting,
#                                       not required by the publish path
#                                       below, provided for contract
#                                       completeness per the task's item 1).
#
# DISCOVERY: adapter selection is config-first, remote-sniff second --
# matches ds_check_tool's own "explicit override, then probe" idiom
# elsewhere in this codebase (see platform.sh capability-probe comments).
#   1. CLAGENTIC_REPO_HOST, if set to a non-"none" value with a matching
#      adapter below, wins outright (operator already told us; this is the
#      SAME var docs/LLM-USAGE.md has documented since before this task as
#      "where gates ship opens PRs" -- previously read by nothing).
#   2. Otherwise, sniff `git remote get-url origin` for a recognizable
#      hostname and pick the adapter whose CLI is ALSO on PATH and
#      authenticated. A hostname match with no working CLI is not a usable
#      adapter -- falls through to "no adapter", never a partial one.
#   3. No remote, no config match, no CLI match -- no adapter. Caller's
#      fallback contract (item 4) applies: the local ledger is the complete
#      flow, publish is skipped with a one-line notice, and this is NOT a
#      degraded state.
#
# ADDING A NEW HOST: implement three functions following the `gh` example
# below (_host_adapter_gh_open_change_request /
# _host_adapter_gh_post_comment / _host_adapter_gh_read_comments), add one
# recognition arm to _host_adapter_detect, and document the new adapter in
# docs/GATES.md's adapter table -- no other file changes needed. Gate logic
# (gates.sh, review-merge.sh) must never reference the new vendor by name.

# _host_adapter_detect — sets _HOST_ADAPTER to a known adapter id ("gh" is
# the only one shipped; see file header) or "" when none is usable. Config
# override first, then remote-URL sniff + CLI-presence probe.
_host_adapter_detect() {
  _HOST_ADAPTER=""

  _had_configured="${CLAGENTIC_REPO_HOST:-}"
  case "$_had_configured" in
    none|"") ;;
    github)
      if command -v gh >/dev/null 2>&1; then
        _HOST_ADAPTER="gh"
        return 0
      fi
      ;;
  esac

  # Config didn't resolve to a usable adapter (unset, "none", an unshipped
  # host name, or the configured host's CLI is missing) -- fall through to
  # remote-URL sniffing rather than failing outright, so an un-configured
  # repo still gets adapter behavior when the tooling is actually there.
  _had_remote=""
  if command -v git >/dev/null 2>&1; then
    _had_remote=$(git -C "${REPO_ROOT:-.}" remote get-url origin 2>/dev/null || echo "")
  fi
  [ -n "$_had_remote" ] || return 1

  case "$_had_remote" in
    *github.com*)
      if command -v gh >/dev/null 2>&1; then
        _HOST_ADAPTER="gh"
        return 0
      fi
      ;;
  esac

  return 1
}

# host_adapter_available — exit 0 iff a usable adapter is discovered.
host_adapter_available() {
  _host_adapter_detect
}

# host_adapter_open_change_request BASE HEAD — open (or reuse) a PR for
# HEAD against BASE. This is the refactored seam cmd_ship's PR-open path now
# calls instead of invoking `gh` directly (item 2).
host_adapter_open_change_request() {
  _haocr_base="$1"
  _haocr_head="$2"
  _host_adapter_detect || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_open_change_request "$_haocr_base" "$_haocr_head" ;;
    *)  return 1 ;;
  esac
}

# host_adapter_post_comment BODY_FILE — post one comment on the current
# branch's change-request thread. Used by the review-verdict publish step
# (item 3). Never called when no adapter is available -- callers check
# host_adapter_available first per the fallback contract (item 4).
host_adapter_post_comment() {
  _hapc_body_file="$1"
  _host_adapter_detect || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_post_comment "$_hapc_body_file" ;;
    *)  return 1 ;;
  esac
}

# host_adapter_read_comments — print existing comment bodies for the current
# branch's change request, one JSON object per line. Contract-completeness
# (item 1); not required by the publish path, which only ever appends.
host_adapter_read_comments() {
  _host_adapter_detect || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_read_comments ;;
    *)  return 1 ;;
  esac
}

# --------------------------------------------------------------- gh adapter
#
# The only adapter shipped by this task (per the task's own OUT OF SCOPE:
# "adapter implementations for hosts nobody has enrolled yet"). `gh` is the
# GitHub CLI; every vendor-specific detail is confined to these three
# functions and _host_adapter_detect above.

_HOST_ADAPTER_SHIP_TIMEOUT="${CLAGENTIC_SHIP_TIMEOUT_SEC:-120}"

_host_adapter_gh_open_change_request() {
  _hagocr_base="$1"
  _hagocr_head="$2"
  if run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr view "$_hagocr_head" >/dev/null 2>&1; then
    echo "[host-adapter/gh] PR already open for $_hagocr_head"
    return 0
  fi
  run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr create --fill --base "$_hagocr_base" --head "$_hagocr_head"
}

_host_adapter_gh_post_comment() {
  _hagpc_body_file="$1"
  [ -f "$_hagpc_body_file" ] || return 1
  _hagpc_branch=""
  if command -v git >/dev/null 2>&1; then
    _hagpc_branch=$(git -C "${REPO_ROOT:-.}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  [ -n "$_hagpc_branch" ] || return 1
  run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr comment "$_hagpc_branch" --body-file "$_hagpc_body_file"
}

_host_adapter_gh_read_comments() {
  _hagrc_branch=""
  if command -v git >/dev/null 2>&1; then
    _hagrc_branch=$(git -C "${REPO_ROOT:-.}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  [ -n "$_hagrc_branch" ] || return 1
  run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr view "$_hagrc_branch" --json comments --jq '.comments[] | {body: .body}'
}
