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
#   host_adapter_open_change_request BASE HEAD [BODY_FILE]
#                                    -- open (or find an existing) PR/MR for
#                                       HEAD against BASE. BODY_FILE, when
#                                       given, is a path to a file whose
#                                       contents become the PR body on
#                                       CREATE only (lr-429b32) -- an
#                                       already-open PR is reused as-is, body
#                                       unchanged, matching this function's
#                                       existing find-or-open contract. The
#                                       caller renders BODY_FILE's contents
#                                       (gate side, e.g. gates.sh's
#                                       _build_ship_pr_body) -- this file
#                                       only transports it, never composes
#                                       it, per the file-header contract
#                                       above. Omitted BODY_FILE preserves
#                                       the pre-lr-429b32 behavior exactly.
#                                       Prints nothing of significance to
#                                       stdout; status via exit code +
#                                       stderr, same posture as the rest of
#                                       gates.sh.
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
# EVERY repo-state git call added here must gate on
# _host_adapter_repo_root_is_scoped first (INV-6, see that function's own
# doc comment) -- scripts/test_host_adapter_publish.py's
# TestHostAdapterRepoScopingSweep enforces this class-wide.

# _host_adapter_repo_root_is_scoped — INV-6 (AGENTS.md), mirrored from
# gates.sh's _git_repo_root_is_scoped (same predicate, same rationale, this
# file's own local copy rather than a cross-file call): true (exit 0) only
# when REPO_ROOT itself is the git repo `git -C "$REPO_ROOT" ...` will
# actually operate on. `-C <dir>` only changes cwd before git's own repo
# discovery runs -- it still walks UP the filesystem looking for a `.git`
# directory. On a host where an ancestor of REPO_ROOT happens to be a git
# repo (a valid wrapper layout this workspace itself uses) -- or REPO_ROOT
# is not a git repo at all -- any repo-state git call here would silently
# resolve that unrelated ANCESTOR repo instead of the intended one: a
# wrong-repo result, not a git error, so nothing about the call itself
# signals the mistake. In this file specifically, an unscoped
# `git remote get-url origin` in _host_adapter_detect can make
# host_adapter_available report success against the wrong repo's remote,
# and an unscoped rev-parse in the gh adapter's comment paths can post a
# review verdict's findings to the WRONG repository's change-request thread
# -- wrong-repo disclosure of findings content, silently. Every repo-state
# git call in this file must gate on this predicate first.
#
# Why a local copy instead of calling gates.sh's version: host-adapter.sh is
# sourced by gates.sh near the very top of that file, BEFORE REPO_ROOT is
# resolved and BEFORE gates.sh's own `_git_repo_root_is_scoped` is defined
# later in the file, so an inter-file call is not reliably available at
# source time, and this file is also sourced/tested standalone (see
# scripts/test_host_adapter_publish.py). A local, self-contained mirror
# avoids a load-order dependency and keeps this file usable on its own —
# the same reasoning review-merge.sh's own local helpers already follow.
#
# `git rev-parse --show-toplevel` always prints an absolute, canonical
# (symlink-resolved) path; REPO_ROOT is not guaranteed to be either (it can
# come verbatim from CLAGENTIC_PROJECT_ROOT, or ds_repo_root's
# wrapper/.clagentic-project fallback) -- canonicalize with `cd DIR && pwd -P`
# (POSIX `pwd -P`, not plain `pwd`) to match. `cd` failing (REPO_ROOT does
# not exist / not a directory) falls back to the raw value, which will
# simply continue to correctly mismatch below. An EMPTY REPO_ROOT (never
# set) is treated as unscoped too -- `${REPO_ROOT:-.}`'s bare "." fallback
# elsewhere in this file's individual git calls is exactly the unscoped
# shape this predicate exists to refuse; it deliberately does NOT default
# REPO_ROOT to "." itself.
#
# STRUCTURALLY BLIND to an inherited GIT_DIR (lr-dfd45f) — see gates.sh's
# own copy of this predicate for the full explanation: an exported GIT_DIR
# silently overrides `-C "$REPO_ROOT"`, so both sides of the comparison
# below can derive from the same foreign repo and spuriously report
# "scoped." This file does not currently call ds_git_env_scrub
# (scripts/platform.sh) at its own top level — a known follow-up, not fixed
# in lr-dfd45f's PR (scoped to gates.sh's own canary defect there).
_host_adapter_repo_root_is_scoped() {
  [ -n "${REPO_ROOT:-}" ] || return 1
  _harris_repo_root_canon=$(cd "$REPO_ROOT" 2>/dev/null && pwd -P || printf '%s' "$REPO_ROOT")
  _harris_git_toplevel=$(git -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null || echo "")
  [ -n "$_harris_git_toplevel" ] && [ "$_harris_git_toplevel" = "$_harris_repo_root_canon" ]
}

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
  # INV-6: refuse rather than resolve an ancestor repo's remote when
  # REPO_ROOT is not itself the git repo `-C` would operate on.
  _had_remote=""
  if command -v git >/dev/null 2>&1 && _host_adapter_repo_root_is_scoped; then
    _had_remote=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || echo "")
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

# host_adapter_open_change_request BASE HEAD [BODY_FILE] — open (or reuse) a
# PR for HEAD against BASE. This is the refactored seam cmd_ship's PR-open
# path now calls instead of invoking `gh` directly (item 2). BODY_FILE is
# optional (lr-429b32) — see the file-header contract table above.
host_adapter_open_change_request() {
  _haocr_base="$1"
  _haocr_head="$2"
  _haocr_body_file="${3:-}"
  _host_adapter_detect || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_open_change_request "$_haocr_base" "$_haocr_head" "$_haocr_body_file" ;;
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
  _hagocr_body_file="${3:-}"
  if run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr view "$_hagocr_head" >/dev/null 2>&1; then
    echo "[host-adapter/gh] PR already open for $_hagocr_head"
    return 0
  fi
  # A rendered body file (lr-429b32) wins over --fill's commit-message
  # scrape -- --fill supplies no review-provenance section at all, which is
  # the defect this task exists to close. --title still comes from --fill's
  # own commit-derived title; only the body is replaced.
  if [ -n "$_hagocr_body_file" ] && [ -f "$_hagocr_body_file" ]; then
    run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr create --fill-first --base "$_hagocr_base" --head "$_hagocr_head" --body-file "$_hagocr_body_file"
  else
    run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr create --fill --base "$_hagocr_base" --head "$_hagocr_head"
  fi
}

_host_adapter_gh_post_comment() {
  _hagpc_body_file="$1"
  [ -f "$_hagpc_body_file" ] || return 1
  _hagpc_branch=""
  # INV-6: refuse rather than resolve an ancestor repo's branch when
  # REPO_ROOT is not itself the git repo `-C` would operate on -- an
  # unscoped read here would post a review verdict's findings to the WRONG
  # repository's change-request thread.
  if command -v git >/dev/null 2>&1 && _host_adapter_repo_root_is_scoped; then
    _hagpc_branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  [ -n "$_hagpc_branch" ] || return 1
  run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr comment "$_hagpc_branch" --body-file "$_hagpc_body_file"
}

_host_adapter_gh_read_comments() {
  _hagrc_branch=""
  # INV-6: same scoping requirement as _host_adapter_gh_post_comment above.
  if command -v git >/dev/null 2>&1 && _host_adapter_repo_root_is_scoped; then
    _hagrc_branch=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  [ -n "$_hagrc_branch" ] || return 1
  run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh pr view "$_hagrc_branch" --json comments --jq '.comments[] | {body: .body}'
}
