#!/bin/sh
# clagentic-lite :: host adapter contract (lr-2b07a8)
#
# HOST-NEUTRAL BY CONTRACT: gate logic (gates.sh, review-merge.sh) must never
# name a git-hosting vendor directly. This file is the ONE place vendor
# names/tools are allowed to appear -- every adapter implementation lives
# here, behind the functions below, which are all gate logic is permitted to
# call:
#
#   host_adapter_available          -- exit 0 iff a usable adapter is
#                                       discovered for REPO_ROOT's origin
#                                       remote, exit 1 otherwise (fallback).
#   host_adapter_open_change_request BASE HEAD [BODY_FILE]
#                                    -- the SOLE decider of "which change
#                                       request, created or reused". Looks up
#                                       the OPEN change request for HEAD
#                                       (closed and merged ones never count),
#                                       reuses it if found, creates one if
#                                       not. Prints exactly one line on
#                                       stdout: `created <num>` or
#                                       `reused <num>`; everything else goes
#                                       to stderr. Exits non-zero, printing
#                                       nothing on stdout, when the outcome
#                                       cannot be determined (the lookup
#                                       failed -- it never creates blind) or
#                                       the create itself failed. BODY_FILE,
#                                       when given, becomes the body on
#                                       CREATE only (lr-429b32); a reused
#                                       change request's body is never
#                                       touched. The caller renders BODY_FILE
#                                       (gate side, gates.sh's
#                                       _build_ship_pr_body) -- this file only
#                                       transports it. Omitted BODY_FILE
#                                       preserves the pre-lr-429b32 behavior.
#   host_adapter_find_open_change_request BRANCH
#                                    -- print the number of the OPEN change
#                                       request for BRANCH. TRI-STATE exit:
#                                       0 found, 1 none, 2 could not be
#                                       determined (adapter, auth, network).
#                                       For callers that only need to address
#                                       an existing change request (the
#                                       review-verdict publisher); a caller
#                                       that must choose create-vs-reuse uses
#                                       open_change_request instead, which
#                                       shares this lookup.
#   host_adapter_post_comment PR_NUM BODY_FILE
#                                    -- post BODY_FILE's contents as ONE
#                                       comment on change request PR_NUM.
#                                       Exit 0 on success, non-zero otherwise.
#   host_adapter_read_comments PR_NUM
#                                    -- print existing comment bodies for
#                                       change request PR_NUM, one JSON object
#                                       per line (best-effort; contract
#                                       completeness, not required by the
#                                       publish path).
#   host_adapter_read_thread_text PR_NUM
#                                    -- print change request PR_NUM's body,
#                                       then every comment body in
#                                       chronological order, as plain text on
#                                       stdout. Exit 0 iff the host read
#                                       SUCCEEDED (an empty thread is still
#                                       success); non-zero on any
#                                       adapter/auth/network failure, so a
#                                       caller never mistakes a failed read for
#                                       "no prior content". Read-only. The
#                                       caller parses the text (gates.sh looks
#                                       for its own hidden ship marker) --
#                                       adapters transport, they never
#                                       interpret.
#   host_adapter_artifact_limit      -- print the host's hard character limit
#                                       for ONE change-request body or ONE
#                                       comment. Gate logic budgets every
#                                       rendered artifact against this and
#                                       never hardcodes a number of its own.
#                                       Without a detected adapter it prints
#                                       the smallest limit any shipped adapter
#                                       has (_HOST_ADAPTER_DEFAULT_ARTIFACT_LIMIT)
#                                       so an artifact rendered before/without
#                                       an adapter is still safe to send.
#   Per-PR reads and comments take the change-request NUMBER, never a branch
#   name (a bare branch can match a closed or merged change request on the
#   same branch) and never a repo-state read of their own: the number comes
#   from the one lookup above, once per ship/publish.
#   A change-request BODY is written ONLY by host_adapter_open_change_request
#   at create. No adapter function may edit an existing body: later ships add
#   comments (host_adapter_post_comment), never rewrite the body.
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
# ADDING A NEW HOST: implement the six functions following the `gh` example
# below (_host_adapter_gh_open_change_request /
# _host_adapter_gh_post_comment / _host_adapter_gh_read_comments /
# _host_adapter_gh_find_open_change_request /
# _host_adapter_gh_read_thread_text / _host_adapter_gh_artifact_limit), add one
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
# and the comment paths used to read the current branch the same way, which
# could post a review verdict's findings to the WRONG repository's
# change-request thread -- wrong-repo disclosure of findings content,
# silently. The comment paths now take an explicit change-request number and
# read no repo state at all; every remaining repo-state git call in this
# file must gate on this predicate first.
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

# _host_adapter_is_number VALUE -- true iff VALUE is a non-empty run of digits.
# Every per-PR call below addresses a change request by number; a branch name
# or an empty string reaching one is a caller bug that must fail closed rather
# than reach the host CLI, where a bare ref can match a closed or merged PR.
_host_adapter_is_number() {
  case "$1" in
    ""|*[!0-9]*) return 1 ;;
  esac
  return 0
}

# host_adapter_open_change_request BASE HEAD [BODY_FILE] -- the sole decider of
# created-vs-reused. Prints `created <num>` or `reused <num>` on stdout, exits
# non-zero (stdout empty) when that cannot be determined. See the file-header
# contract above.
host_adapter_open_change_request() {
  _haocr_base="$1"
  _haocr_head="$2"
  _haocr_body_file="${3:-}"
  _host_adapter_detect || return 1
  _host_adapter_repo_root_is_scoped || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_open_change_request "$_haocr_base" "$_haocr_head" "$_haocr_body_file" ;;
    *)  return 1 ;;
  esac
}

# host_adapter_find_open_change_request BRANCH -- print the OPEN change
# request's number. Tri-state exit: 0 found, 1 none, 2 undeterminable.
host_adapter_find_open_change_request() {
  _hafocr_branch="$1"
  [ -n "$_hafocr_branch" ] || return 2
  _host_adapter_detect || return 2
  _host_adapter_repo_root_is_scoped || return 2
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_find_open_change_request "$_hafocr_branch" ;;
    *)  return 2 ;;
  esac
}

# host_adapter_post_comment PR_NUM BODY_FILE -- post one comment on change
# request PR_NUM. Never called when no adapter is available -- callers check
# host_adapter_available first per the fallback contract (item 4).
host_adapter_post_comment() {
  _hapc_num="$1"
  _hapc_body_file="${2:-}"
  _host_adapter_is_number "$_hapc_num" || return 1
  _host_adapter_detect || return 1
  _host_adapter_repo_root_is_scoped || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_post_comment "$_hapc_num" "$_hapc_body_file" ;;
    *)  return 1 ;;
  esac
}

# host_adapter_read_comments PR_NUM -- print existing comment bodies for
# change request PR_NUM, one JSON object per line. Contract-completeness
# (item 1); not required by the publish path, which only ever appends.
host_adapter_read_comments() {
  _harc_num="${1:-}"
  _host_adapter_is_number "$_harc_num" || return 1
  _host_adapter_detect || return 1
  _host_adapter_repo_root_is_scoped || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_read_comments "$_harc_num" ;;
    *)  return 1 ;;
  esac
}

# host_adapter_read_thread_text PR_NUM -- print the change request's body and
# then each comment body (chronological) to stdout. Exit status is the host
# read's own: 0 = read succeeded, non-zero = it did not.
host_adapter_read_thread_text() {
  _hartt_num="${1:-}"
  _host_adapter_is_number "$_hartt_num" || return 1
  _host_adapter_detect || return 1
  _host_adapter_repo_root_is_scoped || return 1
  case "$_HOST_ADAPTER" in
    gh) _host_adapter_gh_read_thread_text "$_hartt_num" ;;
    *)  return 1 ;;
  esac
}

# The smallest hard body/comment limit of any shipped adapter. Used when no
# adapter is detected so an artifact is still rendered within a limit every
# shipped host honors; it lives here, not in gate logic, so the number has one
# owner.
_HOST_ADAPTER_DEFAULT_ARTIFACT_LIMIT=65536

# host_adapter_artifact_limit -- print the host's hard character limit for one
# change-request body or one comment.
host_adapter_artifact_limit() {
  _host_adapter_detect >/dev/null 2>&1 || true
  case "${_HOST_ADAPTER:-}" in
    gh) _host_adapter_gh_artifact_limit ;;
    *)  printf '%s\n' "$_HOST_ADAPTER_DEFAULT_ARTIFACT_LIMIT" ;;
  esac
}

# --------------------------------------------------------------- gh adapter
#
# The only adapter shipped by this task (per the task's own OUT OF SCOPE:
# "adapter implementations for hosts nobody has enrolled yet"). `gh` is the
# GitHub CLI; every vendor-specific detail is confined to these three
# functions and _host_adapter_detect above.

_HOST_ADAPTER_SHIP_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_SHIP_TIMEOUT_SEC "${CLAGENTIC_SHIP_TIMEOUT_SEC:-}" 120)

# _host_adapter_gh_run ARGS... -- the ONLY place `gh` is invoked. gh infers the
# repository it acts on from the process's working directory, so a bare call
# from a shell sitting in some other git repo would query or mutate THAT repo
# even though the INV-6 scope check passed for REPO_ROOT. Running it from
# REPO_ROOT (in a subshell, leaving the caller's cwd alone) binds every call to
# the repository the scope check approved. Fails closed when REPO_ROOT cannot be
# entered. Path arguments (a body file) must be absolute for the same reason.
# scripts/test_host_adapter_publish.py's sweep fails on any other `gh` call.
_host_adapter_gh_run() {
  [ -n "${REPO_ROOT:-}" ] || return 1
  (
    cd "$REPO_ROOT" 2>/dev/null || exit 1
    run_bounded "$_HOST_ADAPTER_SHIP_TIMEOUT" -- gh "$@"
  )
}

# _host_adapter_gh_open_pr_number BRANCH -- the ONE place that answers "which
# OPEN PR is there for BRANCH". Prints its number on stdout. Exit 0 = found,
# 1 = none, 2 = the host could not be asked (auth/network/timeout/
# unparseable). Bare `gh pr view|comment BRANCH` cannot be used for this or
# for later per-PR calls: it also matches CLOSED and MERGED PRs, so with a
# closed and an open PR on one branch name it can hit the wrong one, and it
# cannot tell "no PR" from a failed call without parsing error text. Every
# per-PR read/comment therefore addresses the PR by the number found here.
_host_adapter_gh_open_pr_number() {
  _hagopn_out=$(_host_adapter_gh_run pr list --head "$1" --state open --json number --jq '.[0].number // empty' 2>/dev/null) || return 2
  case "$_hagopn_out" in
    "") return 1 ;;
    *[!0-9]*) return 2 ;;
    *) printf '%s\n' "$_hagopn_out" ;;
  esac
}

# GitHub rejects a pull-request body or a comment over 65536 characters.
_host_adapter_gh_artifact_limit() {
  printf '%s\n' 65536
}

_host_adapter_gh_find_open_change_request() {
  _host_adapter_gh_open_pr_number "$1"
}

# Prints `created <num>` / `reused <num>` on stdout and nothing else there:
# gh's own output is relayed to stderr so the one stdout line stays
# machine-readable.
_host_adapter_gh_open_change_request() {
  _hagocr_base="$1"
  _hagocr_head="$2"
  _hagocr_body_file="${3:-}"
  _hagocr_state=0
  _hagocr_num=$(_host_adapter_gh_open_pr_number "$_hagocr_head") || _hagocr_state=$?
  case "$_hagocr_state" in
    0)
      echo "[host-adapter/gh] PR #$_hagocr_num already open for $_hagocr_head" 1>&2
      printf 'reused %s\n' "$_hagocr_num"
      return 0
      ;;
    1) ;;
    *)
      # Creating blind on a failed lookup could duplicate an open PR.
      echo "[host-adapter/gh] could not determine whether a PR is already open for $_hagocr_head -- not creating one" 1>&2
      return 1
      ;;
  esac
  # A rendered body file (lr-429b32) wins over --fill's commit-message
  # scrape -- --fill supplies no review-provenance section at all, which is
  # the defect this task exists to close. --title still comes from --fill's
  # own commit-derived title; only the body is replaced.
  _hagocr_rc=0
  if [ -n "$_hagocr_body_file" ] && [ -f "$_hagocr_body_file" ]; then
    _hagocr_out=$(_host_adapter_gh_run pr create --fill-first--base "$_hagocr_base" --head "$_hagocr_head" --body-file "$_hagocr_body_file") || _hagocr_rc=$?
  else
    _hagocr_out=$(_host_adapter_gh_run pr create --fill --base "$_hagocr_base" --head "$_hagocr_head") || _hagocr_rc=$?
  fi
  [ -z "$_hagocr_out" ] || printf '%s\n' "$_hagocr_out" 1>&2
  [ "$_hagocr_rc" -eq 0 ] || return "$_hagocr_rc"
  # `gh pr create` ends its output with the new PR's URL. Reading the number
  # from it keeps this call the only lookup: no second query to learn what
  # was just created.
  _hagocr_url=$(printf '%s\n' "$_hagocr_out" | tail -n 1)
  _hagocr_num=${_hagocr_url##*/pull/}
  if [ "$_hagocr_num" = "$_hagocr_url" ] || ! _host_adapter_is_number "$_hagocr_num"; then
    echo "[host-adapter/gh] the PR was created but its number could not be read from gh's output" 1>&2
    return 1
  fi
  printf 'created %s\n' "$_hagocr_num"
}

_host_adapter_gh_post_comment() {
  [ -f "$2" ] || return 1
  _host_adapter_gh_run pr comment "$1" --body-file "$2"
}

_host_adapter_gh_read_comments() {
  _host_adapter_gh_run pr view "$1" --json comments --jq '.comments[] | {body: .body}'
}

# Body first, then comments in the order the host returns them
# (chronological). `gh` exits non-zero on auth/network failure, which this
# function passes straight through -- the caller treats that as "read
# failed", never as "no content".
_host_adapter_gh_read_thread_text() {
  _host_adapter_gh_run pr view "$1" --json body,comments --jq '.body, (.comments[].body)'
}
