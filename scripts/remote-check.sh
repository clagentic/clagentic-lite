#!/bin/sh
# clagentic-lite :: enrolled-repo remote reachability check
#
# Source AFTER scripts/platform.sh. Functions only; nothing runs at source
# time. Consumers: `doctor` and `update` in bin/clagentic-lite.
#
# Why this exists: gates.sh fetches, ls-remotes and pushes to `origin` under
# the user's own git configuration (credential helpers, url rewrites, proxy
# settings). A host where that configuration does not authenticate fails every
# remote operation in a gate run. This check runs the same kind of call under
# the same git environment gates.sh uses (ds_git_env_scrub: repo-redirecting
# variables cleared, user configuration left alone) so the failure is seen
# once, by name, instead of as a stale-baseline or push failure mid-gate.

# ds_remote_check REPO [TIMEOUT_SEC]
#
# Runs `git ls-remote origin HEAD` against REPO with prompts disabled and
# prints ONE line: STATE|DETAIL|HELPERS
#   ok        origin answered
#   noremote  REPO has no `origin` remote
#   skip      REPO is not itself a git repo (DETAIL says why); nothing was run
#   timeout   the bound fired; DETAIL is "timed out after Ns". A network
#             problem, distinct from authentication
#   auth      git's own error looks like an authentication failure; DETAIL is
#             that error line (URL credentials masked) and HELPERS lists the
#             credential.helper entries git would consult (first word of each,
#             so an inline helper script is never echoed), or "none configured"
#   fail      any other failure; DETAIL is git's own error line, masked
# Never prompts: GIT_TERMINAL_PROMPT=0 and stdin closed. An ssh remote can
# still ask for a passphrase on the controlling terminal; the wall-clock bound
# keeps that from hanging the caller.
ds_remote_check() {
  _drc_repo="$1"
  _drc_to=$(ds_positive_int_or_warn CLAGENTIC_REMOTE_CHECK_TIMEOUT_SEC "${2:-${CLAGENTIC_REMOTE_CHECK_TIMEOUT_SEC:-}}" 20)
  (
    ds_git_env_scrub
    [ -d "$_drc_repo" ] || { printf 'skip|not a directory|\n'; exit 0; }
    # `git -C DIR` alone walks UP to an ancestor repo when DIR is not itself
    # one, which would check the wrong repository's remote. Require DIR to be
    # the toplevel it resolves to.
    _drc_canon=$(cd "$_drc_repo" 2>/dev/null && pwd -P || true)
    _drc_top=$(git -C "$_drc_repo" rev-parse --show-toplevel 2>/dev/null || true)
    if [ -z "$_drc_canon" ] || [ "$_drc_top" != "$_drc_canon" ]; then
      printf 'skip|not the root of a git repo|\n'
      exit 0
    fi
    if ! git -C "$_drc_repo" config --get remote.origin.url >/dev/null 2>&1; then
      printf 'noremote||\n'
      exit 0
    fi
    _drc_err=$(mktemp "${TMPDIR:-/tmp}/clagentic-remote-check-XXXXXX")
    trap 'rm -f "$_drc_err"' EXIT
    _drc_rc=0
    $DS_TIMEOUT_CMD "$_drc_to" env GIT_TERMINAL_PROMPT=0 git -C "$_drc_repo" ls-remote origin HEAD >/dev/null 2>"$_drc_err" </dev/null || _drc_rc=$?
    if [ "$_drc_rc" -eq 0 ]; then
      printf 'ok||\n'
      exit 0
    fi
    _drc_reason=$(_bounded_failure_reason "$_drc_rc" "$_drc_to" "$_drc_err" | tr -d '|\n')
    if [ "$_drc_rc" -eq 124 ]; then
      printf 'timeout|%s|\n' "$_drc_reason"
      exit 0
    fi
    _drc_lower=$(tr 'A-Z' 'a-z' < "$_drc_err")
    case "$_drc_lower" in
      *"authentication failed"*|*"could not read username"*|*"could not read password"*|*"terminal prompts disabled"*|*"permission denied"*|*"invalid credentials"*|*"access denied"*|*"returned error: 401"*|*"returned error: 403"*)
        _drc_helpers=$(git -C "$_drc_repo" config --get-all credential.helper 2>/dev/null | awk 'NF { print $1 }' | cut -c1-60 | tr '\n' ',' | sed 's/,$//; s/,/, /g' || true)
        printf 'auth|%s|%s\n' "$_drc_reason" "${_drc_helpers:-none configured}"
        ;;
      *)
        printf 'fail|%s|\n' "$_drc_reason"
        ;;
    esac
  )
}
