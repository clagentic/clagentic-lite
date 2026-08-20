#!/bin/sh
# clagentic-lite :: gate orchestrator
# Runs gates in sequence, logs outcomes to .clagentic/lite/audit.db.
#
# Subcommands:
#   init             create audit schema
#   bleed            scan committed files for internal/private string bleed
#   secrets          run gitleaks on staged hunks; branch history scan when no staged changes
#   deps             run osv-scanner (pre-push)
#   sast             run semgrep (pre-push)
#   review           run cross-vendor review on staged diff; branch diff when no staged changes
#   adversarial      run non-blocking adversarial pass
#   ship             run all blocking gates, then push + open PR if green
#   render-review    pretty-print .clagentic/lite/last-review.json
#   digest           summarize today's audit rows
#   status           last N runs per gate (default N=10) with color outcomes
#   tail             follow audit.db, render new gate_runs rows as they land; --no-follow exits after one poll
#   pre-push         hook entry point (deps + sast + optional review)
#   log-run          internal: insert one row into gate_runs
#   deferrals-lint   validate .clagentic/deferrals.json against the gate-code schema
#   audit-vocab-lint warn-only: flag "cmd_log_run <gate> pass" audit rows whose
#                    details string contains a failure word (a tool that never
#                    ran should not log as a clean pass)

set -e
. "$(dirname "$0")/platform.sh"
. "$(dirname "$0")/review-merge.sh"
. "$(dirname "$0")/host-adapter.sh"

# Tool home: the directory containing scripts/ — resolved from this script's
# own location so it's correct whether invoked via PATH, symlink, or directly.
# This is the install tree ($CLAGENTIC_LITE_HOME), not the enrolled project root.
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_HOME="$(dirname "$SCRIPTS_DIR")"

# Project root resolution: CLAGENTIC_PROJECT_ROOT env var wins, then git
# show-toplevel of cwd. The env var is the override path used when gates.sh
# is called from a hook shim installed by `clagentic-lite enroll` — the shim
# stamps __CLAGENTIC_LITE_HOME__ at enroll time but does NOT override the project
# root; instead, git show-toplevel of the repo under commit is used because
# the hook always runs from inside the enrolled repo's working tree.
# Explicit CLAGENTIC_PROJECT_ROOT is still supported for scripted/test use.
if [ -n "${CLAGENTIC_PROJECT_ROOT:-}" ]; then
  REPO_ROOT="$CLAGENTIC_PROJECT_ROOT"
else
  REPO_ROOT=$(ds_repo_root)
fi
[ -n "$REPO_ROOT" ] || { echo "gates.sh: not in a git repo" 1>&2; exit 1; }

# _git — run git against REPO_ROOT, not $PWD. In wrapper/repo layouts $PWD may
# be the (non-git) wrapper directory or an unrelated outer repo whose HEAD has
# nothing to do with REPO_ROOT. All git operations that inspect history, staged
# state, or branch identity must be keyed to the enrolled project root.
_git() { git -C "$REPO_ROOT" "$@"; }

# _git_repo_root_is_scoped — true (exit 0) only when REPO_ROOT itself is the
# git repo `_git` (or any `git -C "$REPO_ROOT" ...` call) will actually
# operate on. `-C <dir>` only changes cwd before git's own repo discovery
# runs — it still walks UP the filesystem looking for a `.git` directory. On
# a host where an ancestor of REPO_ROOT happens to be a git repo (or
# REPO_ROOT is not a git repo at all, as with the wrapper/.clagentic-project
# layout ds_repo_root, platform.sh, can legitimately produce), any call that
# reads repo state (rev-parse, diff, log, status, merge-base, fetch,
# ls-remote, ...) would silently operate on that unrelated ancestor repo
# instead — a wrong-repo result, not a git error, so nothing about the call
# itself signals the mistake. Every call site that reads repo state for a
# security- or correctness-relevant decision (a merge-base security-scan
# baseline, a staged/branch diff fed to the review gates, a SHA staleness
# comparison, a push-target branch name) must gate on this helper first, not
# assume `_git`/`-C` alone is safe (lr-da1f28 sweep).
#
# `git rev-parse --show-toplevel` always prints an absolute, canonical
# (symlink-resolved) path. REPO_ROOT is not guaranteed to be either: it can
# come verbatim from CLAGENTIC_PROJECT_ROOT, or from ds_repo_root's
# wrapper/.clagentic-project pointer-file fallback (platform.sh), neither of
# which canonicalizes the path. A literal string compare between an
# always-canonical toplevel and a possibly-relative/symlinked REPO_ROOT
# falsely mismatches on a real git repo, silently no-op-ing every caller of
# this helper on a repo it should have resolved. Canonicalize REPO_ROOT with
# `cd DIR && pwd -P` (POSIX `pwd -P`, not plain `pwd`, which prints the
# logical path and would leave a symlink component unresolved) to match what
# `git rev-parse --show-toplevel` always returns. `cd` failing (REPO_ROOT
# does not exist / not a directory) falls back to the raw value, which will
# simply continue to correctly mismatch below.
_git_repo_root_is_scoped() {
  _grs_repo_root_canon=$(cd "$REPO_ROOT" 2>/dev/null && pwd -P || printf '%s' "$REPO_ROOT")
  _grs_git_toplevel=$(_git rev-parse --show-toplevel 2>/dev/null || echo "")
  [ -n "$_grs_git_toplevel" ] && [ "$_grs_git_toplevel" = "$_grs_repo_root_canon" ]
}

# _git_repo_scoped_head_sha — resolve HEAD's SHA, but ONLY when
# _git_repo_root_is_scoped. Prints the resolved SHA on stdout, or nothing
# when REPO_ROOT is not the git repo being consulted (or is not a git repo
# at all).
_git_repo_scoped_head_sha() {
  if _git_repo_root_is_scoped; then
    _git rev-parse HEAD 2>/dev/null || echo ""
  fi
}

# run_bounded [TIMEOUT_SEC] -- CMD [ARGS...]
#
# INV-1a/INV-2 enforcement (class-4 foundry fix): the SOLE entry point for
# every external-process invocation in this file that was previously
# untimed — gitleaks, osv-scanner, semgrep, `git push`, and (at the time of
# that fix) the host's PR-open CLI, since generalized behind the host
# adapter (lr-2b07a8; every adapter call still routes through run_bounded —
# see scripts/host-adapter.sh). (`git fetch`/`git ls-remote` inside
# _gate_resolve_fresh_default_branch_ref were already timed via
# $DS_TIMEOUT_CMD directly, predating this task — not converted here since
# they were never part of the untimed set, but they benefit from the same
# platform.sh fail-closed guarantee this function relies on.) Before this
# fix, each of the untimed sites ran with NO wall-clock budget at all — a
# hung scanner, a stalled push, or a `semgrep --config=auto` rule download
# that never completes blocks a blocking security gate indefinitely with no
# diagnostic. Routing every one of these through a single named wrapper
# makes the unbounded form UNWRITABLE (a reviewer or future contributor
# cannot add a tenth bare invocation without it being visibly different
# from every sibling call) and gives one place to raise the default or add
# a turn/output cap later, rather than a per-site timeout variable that a
# future call site can simply omit.
#
# Args: TIMEOUT_SEC (optional, positive integer seconds) then `--` then the
# command and its arguments. Omitting TIMEOUT_SEC (i.e. starting directly
# with `--`) falls back to CLAGENTIC_EXTERNAL_TIMEOUT_SEC (default 120) —
# long enough for a full-tree semgrep/osv-scanner pass on a mid-size repo,
# short enough that a hung process surfaces as a step failure inside a
# single gate invocation rather than wedging it. A non-numeric OR ZERO
# TIMEOUT_SEC falls back the same way, via ds_positive_int_or_default
# (platform.sh) — matching every other timeout/interval var in this file,
# and every one in llm-client.sh's llm_timeout_for (lr-49df97 fold-up: a
# bare `case ''|*[!0-9]*` guard admits "0" unchanged, and `timeout 0`
# disables bounding entirely — see that helper's own doc comment).
#
# Relies on DS_TIMEOUT_CMD (platform.sh) for the actual bound. On a host
# missing both `timeout` and `gtimeout`, DS_TIMEOUT_CMD resolves to
# ds_timeout_missing, which fails closed (returns 99, refuses to run the
# command at all) rather than silently running unbounded — that guarantee
# is what makes every timeout this function applies actually mean
# something (see platform.sh's own INV-1a comment).
run_bounded() {
  case "$1" in
    --)
      _rb_timeout="${CLAGENTIC_EXTERNAL_TIMEOUT_SEC:-120}"
      shift
      ;;
    *)
      _rb_timeout="$1"
      shift
      # Expect the `--` separator next; tolerate its absence (a caller that
      # passes TIMEOUT_SEC directly followed by the command, no separator)
      # since this is an internal call convention, not a public CLI.
      [ "${1:-}" = "--" ] && shift
      ;;
  esac
  _rb_timeout=$(ds_positive_int_or_default "$_rb_timeout" "${CLAGENTIC_EXTERNAL_TIMEOUT_SEC:-120}")
  _rb_timeout=$(ds_positive_int_or_default "$_rb_timeout" 120)
  $DS_TIMEOUT_CMD "$_rb_timeout" "$@"
}

AUDIT_DB="$REPO_ROOT/.clagentic/lite/audit.db"
mkdir -p "$REPO_ROOT/.clagentic/lite"

cmd_init() {
  ds_sqlite3 "$AUDIT_DB" <<'SQL'
CREATE TABLE IF NOT EXISTS gate_runs (
  id         INTEGER PRIMARY KEY,
  ts         TEXT NOT NULL,
  gate       TEXT NOT NULL,
  outcome    TEXT NOT NULL,
  details    TEXT,
  session_id TEXT,
  branch     TEXT
);
CREATE INDEX IF NOT EXISTS idx_gate_runs_ts ON gate_runs(ts);
SQL
}

cmd_log_run() {
  cmd_init
  GATE="$1"
  OUTCOME="$2"
  DETAILS="${3:-}"
  # Repo-scoped (lr-da1f28 sweep): lower stakes than the security-relevant
  # sites above (this is only an audit-log cosmetic column), but the same
  # ancestor-walk-up defect applies — REPO_ROOT can come verbatim from
  # CLAGENTIC_PROJECT_ROOT and need not itself be a git repo.
  BRANCH=""
  if _git_repo_root_is_scoped; then
    BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  TS=$(ds_date_iso)
  # Every interpolated value must go through the same escape helper. A branch
  # named `feat/o'hare` would otherwise corrupt the INSERT under set -e.
  GATE_ESC=$(ds_sql_escape "$GATE")
  OUT_ESC=$(ds_sql_escape "$OUTCOME")
  DETAILS_ESC=$(ds_sql_escape "$DETAILS")
  BRANCH_ESC=$(ds_sql_escape "$BRANCH")
  ds_sqlite3 "$AUDIT_DB" \
    "INSERT INTO gate_runs (ts, gate, outcome, details, branch) VALUES ('$TS', '$GATE_ESC', '$OUT_ESC', '$DETAILS_ESC', '$BRANCH_ESC');"
}

# _cmd_log_run_checked_pass GATE DETAILS (lr-2e8444)
#
# THE CHECKED PATH for logging a "pass" outcome whose details string is
# assembled at runtime (fully or partly from a variable) rather than a
# static literal. cmd_audit_vocab_lint (below) is a STATIC lint over
# gates.sh's own source text -- its regex can only see a literal
# double-quoted string, so a `cmd_log_run <gate> pass "$SOME_VAR"` or
# `cmd_log_run <gate> pass "literal ($SOME_VAR)"` call site is invisible to
# it in whole (bare variable) or in part (mixed literal+variable): the lint
# reports a clean scan of the literal half while the interpolated half --
# which is exactly where a suppression reason like "scope reduced" or
# "config replaced" lives -- goes unexamined. See docs/GATES.md
# "Audit-vocabulary lint" for the full class writeup.
#
# This closes that hole from the RUNTIME side instead of teaching the
# static matcher to resolve shell variables (open-ended, and cannot see
# values that only exist after interpolation at call time): every
# non-literal "pass" call site in this file must route through this
# function rather than calling `cmd_log_run <gate> pass ...` directly. It
# checks the FULLY ASSEMBLED, POST-INTERPOLATION details string -- so a
# variable's actual runtime content is examined, not its source-text name
# -- against the same failure vocabulary cmd_audit_vocab_lint enforces
# statically. A hit downgrades the logged outcome from "pass" to "warn"
# (never silently promotes a real pass; matches this lint's existing
# warn-only, non-blocking product posture -- see cmd_audit_vocab_lint's own
# doc comment) so the audit trail records the contradiction honestly
# instead of a false-clean "pass".
#
# _AUDIT_FAILURE_WORDS below must stay in sync with cmd_audit_vocab_lint's
# Python _FAILURE_WORDS list -- test_audit_vocab_lint.py's
# TestUnifiedFailureWordVocabulary sweeps both and fails if they diverge.
_AUDIT_FAILURE_WORDS="failed
not found
empty
no package sources
skipped
unavailable"

_cmd_log_run_checked_pass() {
  _clrcp_gate="$1"
  _clrcp_details="$2"
  _clrcp_details_lower=$(printf '%s' "$_clrcp_details" | tr '[:upper:]' '[:lower:]')
  _clrcp_hit=""
  _clrcp_old_ifs="$IFS"
  IFS='
'
  for _clrcp_word in $_AUDIT_FAILURE_WORDS; do
    case "$_clrcp_details_lower" in
      *"$_clrcp_word"*) _clrcp_hit="$_clrcp_word"; break ;;
    esac
  done
  IFS="$_clrcp_old_ifs"
  if [ -n "$_clrcp_hit" ]; then
    echo "[gates/audit-vocab] $_clrcp_gate: 'pass' details contain failure word '$_clrcp_hit' at runtime -- logging as 'warn' instead: $_clrcp_details" 1>&2
    cmd_log_run "$_clrcp_gate" warn "$_clrcp_details"
    return 0
  fi
  cmd_log_run "$_clrcp_gate" pass "$_clrcp_details"
}

# _gate_resolve_fresh_default_branch_ref DEFAULT_BRANCH TIMEOUT_SEC
#
# Resolves `origin/<DEFAULT_BRANCH>` and prints it to stdout ONLY when it can
# be shown to be PROVABLY CURRENT, not merely present. Any caller that scopes
# a security gate to a diff against the default branch (cmd_sast's
# --baseline-commit, cmd_bleed's branch-diff file-set) needs this same
# precondition — see below for why "we have some ref" is not enough on its
# own.
#
# GOVERNING PRINCIPLE (security-audit follow-up to lr-06b87e, generalized
# under lr-caebc5's bleed follow-up so cmd_bleed does not grow a second,
# parallel freshness check): freshness of a resolved origin/<default-branch>
# ref is a PRECONDITION, not an assumption. A non-fatal `git fetch` on the
# theory that a failure "would simply make the later resolution fail too" is
# false — if origin/<default-branch> already exists locally from a PRIOR
# successful fetch, a fetch failure THIS run leaves that stale tracking ref
# in place, and the later resolution succeeds against it anyway. If the
# default branch was force-pushed/rewritten upstream since that last
# successful fetch, the stale ref can resolve CLOSER TO HEAD than the true
# tip — silently narrowing a diff-scoped window while the caller reports a
# normal-looking verdict with a plausible-looking ref. This is a
# SUCCESSFUL-LOOKING WRONG RESOLUTION, not a failure, so it slips past any
# fallback keyed on "did the command error."
#
# The fix: fetch under a timeout (a blocking security gate must not hang
# indefinitely on a stalled network op), and only trust the fetch as
# PROVABLY CURRENT when it (a) exits 0 — not timed out, not any other
# failure — AND (b) the resulting origin/<default-branch> tip matches a
# fresh, independent `git ls-remote origin <default-branch>` read of the same
# remote taken in this same run. (b) is what makes "we have some ref"
# insufficient on its own: a fetch can exit 0 against a mirror/cache that
# itself served stale data, or race a concurrent rewrite between the fetch
# and the later resolution. Comparing two independent reads of the remote tip
# is the only way to establish the resolution is current, not merely
# present. A fetch timeout is treated identically to a fetch failure — a
# timed-out fetch IS a failed fetch, not a third case.
#
# Args: DEFAULT_BRANCH (branch name, e.g. "main"), TIMEOUT_SEC (seconds,
# already validated numeric by the caller).
# stdout: the verified-current origin/<DEFAULT_BRANCH> SHA on success.
# stderr: empty on success; a one-line reason on any failure path.
# Exit: 0 with a SHA on stdout when provably current; 1 with nothing on
# stdout otherwise. Callers must check the exit status, not just emptiness
# of stdout, to distinguish "no ref at all" from other failures if they ever
# need to (current callers only need pass/fail + the reason on stderr).
#
# REPO SCOPING (lr-da1f28 sweep, highest-stakes site in that sweep): the
# `git fetch`/`git ls-remote` calls below use `git -C "$REPO_ROOT"` directly
# rather than `_git`, because $DS_TIMEOUT_CMD needs a literal external
# command to exec, not a shell function — `_git` cannot be passed to it.
# That means neither call was ever covered by `_git`'s own scoping
# discipline, and — worse than a merely mis-stamped SHA — this is the
# function whose output becomes cmd_sast's semgrep --baseline-commit and
# cmd_bleed's branch-diff scope: if REPO_ROOT is not itself a git repo but
# an ancestor is, every call below would silently fetch/resolve/diff against
# that UNRELATED ancestor repo, producing a plausible-looking merge-base
# that silently narrows a blocking security gate's scan window rather than
# erroring. Gate the whole function on _git_repo_root_is_scoped up front and
# refuse (same as any other resolution failure) when REPO_ROOT is not
# provably the repo being consulted.
_gate_resolve_fresh_default_branch_ref() {
  _gfdbr_branch="$1"
  _gfdbr_timeout="$2"

  if ! _git_repo_root_is_scoped; then
    echo "REPO_ROOT is not a git repo — cannot establish a provably current baseline" 1>&2
    return 1
  fi

  if ! $DS_TIMEOUT_CMD "$_gfdbr_timeout" git -C "$REPO_ROOT" fetch origin "$_gfdbr_branch" >/dev/null 2>&1; then
    echo "git fetch origin ${_gfdbr_branch} failed or timed out after ${_gfdbr_timeout}s — cannot establish a provably current baseline" 1>&2
    return 1
  fi

  if ! _git rev-parse --verify -q "origin/${_gfdbr_branch}" >/dev/null 2>&1; then
    echo "origin/${_gfdbr_branch} not resolvable (missing remote-tracking ref)" 1>&2
    return 1
  fi

  _gfdbr_local_tip=$(_git rev-parse "origin/${_gfdbr_branch}" 2>/dev/null || echo "")
  _gfdbr_remote_tip=""
  if [ -n "$_gfdbr_local_tip" ]; then
    _gfdbr_remote_tip=$($DS_TIMEOUT_CMD "$_gfdbr_timeout" git -C "$REPO_ROOT" ls-remote origin "refs/heads/${_gfdbr_branch}" 2>/dev/null | awk '{print $1}')
  fi

  if [ -z "$_gfdbr_local_tip" ] || [ -z "$_gfdbr_remote_tip" ]; then
    echo "could not verify origin/${_gfdbr_branch} freshness (ls-remote failed or timed out) — resolution not provably current" 1>&2
    return 1
  fi

  if [ "$_gfdbr_local_tip" != "$_gfdbr_remote_tip" ]; then
    echo "origin/${_gfdbr_branch} (${_gfdbr_local_tip}) does not match remote tip (${_gfdbr_remote_tip}) — stale ref, not provably current" 1>&2
    return 1
  fi

  printf '%s\n' "$_gfdbr_local_tip"
  return 0
}

cmd_secrets() {
  if ! command -v gitleaks >/dev/null 2>&1; then
    # FAIL CLOSED. AGENTS.md §4 contract: local tools own the security gate.
    # If the tool is missing, the gate is offline — the only honest outcome
    # is to block. Explicit opt-in to skip via CLAGENTIC_ALLOW_MISSING_GITLEAKS=1.
    if [ "${CLAGENTIC_ALLOW_MISSING_GITLEAKS:-0}" = "1" ]; then
      echo "[gates] gitleaks not installed — skipping (CLAGENTIC_ALLOW_MISSING_GITLEAKS=1 set)" 1>&2
      cmd_log_run secrets skip "gitleaks not installed (opt-in skip)"
      return 0
    fi
    echo "[gates] gitleaks not installed — BLOCKING (set CLAGENTIC_ALLOW_MISSING_GITLEAKS=1 to skip, or install: brew install gitleaks | apt install gitleaks)" 1>&2
    cmd_log_run secrets block "gitleaks not installed (fail-closed)"
    return 1
  fi
  # Build the invocation: gitleaks 8.18+ uses `gitleaks git --pre-commit --staged`;
  # older versions use `gitleaks protect --staged`. Both honor --config.
  CFG_ARG=""
  [ -f "$REPO_ROOT/.gitleaks.toml" ] && CFG_ARG="--config=$REPO_ROOT/.gitleaks.toml"

  # Determine whether there are staged changes. When the index is empty and
  # we are on a feature branch, scan the full branch history instead — staged-
  # only mode is a no-op on a clean index and would silently miss committed
  # secrets in a PR workflow.
  #
  # REPO SCOPING (lr-da1f28 sweep): guard on _git_repo_root_is_scoped before
  # trusting either read below. If REPO_ROOT is not itself a git repo but an
  # ancestor is, `_git diff --cached`/`_git rev-parse --abbrev-ref HEAD`
  # would silently resolve against that unrelated ancestor repo — same class
  # as get_review_diff's ancestor-diff leak, but feeding gitleaks instead of
  # the LLM review gates.
  _SECRETS_STAGED=""
  _SECRETS_CURRENT_BRANCH=""
  if _git_repo_root_is_scoped; then
    _SECRETS_STAGED=$(_git diff --cached --name-only 2>/dev/null)
    _SECRETS_CURRENT_BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  _SECRETS_DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  _SECRETS_ON_FEATURE=0
  if [ -z "$_SECRETS_STAGED" ] && [ -n "$_SECRETS_CURRENT_BRANCH" ] && [ "$_SECRETS_CURRENT_BRANCH" != "$_SECRETS_DEFAULT_BRANCH" ] && [ "$_SECRETS_CURRENT_BRANCH" != "HEAD" ]; then
    _SECRETS_ON_FEATURE=1
  fi

  # Probe by capability, not version string — `gitleaks version` output
  # format varies (`v8.18.4`, `8.18.4`, multi-line banner). The `git`
  # subcommand was added in 8.18; if `gitleaks git --help` exits 0 we use
  # it, otherwise we fall back to `gitleaks protect`.
  # Bound every gitleaks invocation (INV-1a/INV-2, class-4 foundry fix): a
  # full branch-history scan in particular can legitimately take longer than
  # the generic run_bounded default, so gitleaks gets its own configurable
  # timeout rather than sharing CLAGENTIC_EXTERNAL_TIMEOUT_SEC's 120s.
  _SECRETS_TIMEOUT="${CLAGENTIC_SECRETS_TIMEOUT_SEC:-300}"
  _SECRETS_TIMEOUT=$(ds_positive_int_or_default "$_SECRETS_TIMEOUT" 300)

  if gitleaks git --help >/dev/null 2>&1; then
    if [ "$_SECRETS_ON_FEATURE" = "1" ]; then
      # No staged changes on a feature branch — scan the branch's committed
      # history rather than the (empty) index. This catches secrets in
      # already-committed hunks that would otherwise be invisible to --staged.
      printf '[gates/secrets] no staged changes — scanning branch history with gitleaks git\n' 1>&2
      # shellcheck disable=SC2086
      if run_bounded "$_SECRETS_TIMEOUT" -- gitleaks git --redact --no-banner $CFG_ARG; then
        cmd_log_run secrets pass "branch history scan (no staged changes)"
      else
        cmd_log_run secrets block "gitleaks reported findings or timed out after ${_SECRETS_TIMEOUT}s (branch history scan)"
        return 1
      fi
    else
      # shellcheck disable=SC2086
      if run_bounded "$_SECRETS_TIMEOUT" -- gitleaks git --staged --pre-commit --redact --no-banner $CFG_ARG; then
        cmd_log_run secrets pass ""
      else
        cmd_log_run secrets block "gitleaks reported findings or timed out after ${_SECRETS_TIMEOUT}s"
        return 1
      fi
    fi
  else
    if [ "$_SECRETS_ON_FEATURE" = "1" ]; then
      # Older gitleaks has no history-scan subcommand. The staged scan is a
      # no-op on an empty index, so skip it and log the limitation.
      printf '[gates/secrets] no staged changes on feature branch — older gitleaks cannot scan history; skipping staged scan\n' 1>&2
      cmd_log_run secrets warn "older gitleaks; no staged changes on feature branch (history scan unavailable)"
    else
      # shellcheck disable=SC2086
      if run_bounded "$_SECRETS_TIMEOUT" -- gitleaks protect --staged --redact --no-banner $CFG_ARG; then
        cmd_log_run secrets pass ""
      else
        cmd_log_run secrets block "gitleaks reported findings or timed out after ${_SECRETS_TIMEOUT}s"
        return 1
      fi
    fi
  fi
}

cmd_deps() {
  if ! command -v osv-scanner >/dev/null 2>&1; then
    if [ "${CLAGENTIC_ALLOW_MISSING_OSV:-0}" = "1" ]; then
      echo "[gates] osv-scanner not installed — skipping (CLAGENTIC_ALLOW_MISSING_OSV=1 set)" 1>&2
      cmd_log_run deps skip "osv-scanner not installed (opt-in skip)"
      return 0
    fi
    echo "[gates] osv-scanner not installed — BLOCKING (set CLAGENTIC_ALLOW_MISSING_OSV=1 to skip, or install: brew install osv-scanner | https://google.github.io/osv-scanner/installation/)" 1>&2
    cmd_log_run deps block "osv-scanner not installed (fail-closed)"
    return 1
  fi

  SEVERITY="${CLAGENTIC_OSV_SEVERITY:-CRITICAL}"
  GLOBAL_IGNORE="$HOME/.config/clagentic/osv-ignore"
  REPO_IGNORE="$REPO_ROOT/.clagentic/osv-ignore"

  # Bound every osv-scanner invocation (INV-1a/INV-2, class-4 foundry fix):
  # one path does a network vulnerability-DB lookup, so this defaults higher
  # than the generic run_bounded default.
  _OSV_TIMEOUT="${CLAGENTIC_OSV_TIMEOUT_SEC:-300}"
  _OSV_TIMEOUT=$(ds_positive_int_or_default "$_OSV_TIMEOUT" 300)

  # Capability-probe: osv-scanner v2.x uses `scan source` subcommand; v1.x
  # used a flat invocation with --severity / --ignore-vulns flags (removed in
  # v2). Probe in preference order: v2 (`scan source`), v1-new (`scan`), else
  # legacy flat invocation. We probe by subcommand availability, not version
  # string.
  # Determine invocation style by major version. v2.x uses `scan source -r`;
  # v1.x new-style uses `scan --recursive`; very old releases use flat flags.
  # --help exits 127 on all subcommands (urfave/cli behavior), so we parse
  # the version string instead.
  _OSV_MAJOR=$(osv-scanner --version 2>/dev/null | sed -n 's/osv-scanner version: \([0-9]*\)\..*/\1/p')
  _OSV_SUBCMD=""
  if [ "${_OSV_MAJOR:-0}" -ge 2 ] 2>/dev/null; then
    _OSV_SUBCMD="source"   # v2.x: scan source -r
  elif osv-scanner scan --help 2>&1 | grep -q 'USAGE'; then
    _OSV_SUBCMD="scan"     # v1.x with scan subcommand
  fi

  if [ -n "$_OSV_SUBCMD" ]; then
    # Newer path: ignores remain config-file entries, but there is no scan
    # config key for minimum severity. Capture JSON and apply the configured
    # threshold to osv-scanner's computed group.max_severity values locally.
    _OSV_TMP=$(mktemp /tmp/clagentic-osv-XXXXXX.toml)
    _OSV_JSON=$(mktemp /tmp/clagentic-osv-XXXXXX.json)
    trap 'rm -f "$_OSV_TMP" "$_OSV_JSON"' EXIT
    : > "$_OSV_TMP"

    # IgnoredVulns: one [[IgnoredVulns]] block per ID from ignore files.
    # One ID per line; blank lines and # comments are stripped.
    for _IGNORE_FILE in "$GLOBAL_IGNORE" "$REPO_IGNORE"; do
      [ -f "$_IGNORE_FILE" ] || continue
      while IFS= read -r LINE; do
        case "$LINE" in ''|'#'*) continue ;; esac
        ID=$(printf '%s' "$LINE" | sed 's/[[:space:]]*#.*//' | sed 's/[[:space:]]*$//')
        [ -n "$ID" ] || continue
        printf '\n[[IgnoredVulns]]\nid = "%s"\nreason = "clagentic osv-ignore"\n' "$ID" >> "$_OSV_TMP"
      done < "$_IGNORE_FILE"
    done

    # Build exclude flags from CLAGENTIC_OSV_EXCLUDE (space-separated paths).
    # v2 uses --experimental-exclude; v1-scan has no equivalent (skip silently).
    _OSV_EXCL_FLAGS=""
    if [ -n "${CLAGENTIC_OSV_EXCLUDE:-}" ] && [ "$_OSV_SUBCMD" = "source" ]; then
      for _ep in $CLAGENTIC_OSV_EXCLUDE; do
        _OSV_EXCL_FLAGS="$_OSV_EXCL_FLAGS --experimental-exclude $_ep"
      done
    fi

    _OSV_STATUS=0
    if [ "$_OSV_SUBCMD" = "source" ]; then
      # shellcheck disable=SC2086
      run_bounded "$_OSV_TIMEOUT" -- osv-scanner scan source -r --format=json "--config=$_OSV_TMP" $_OSV_EXCL_FLAGS . > "$_OSV_JSON" || _OSV_STATUS=$?
    else
      run_bounded "$_OSV_TIMEOUT" -- osv-scanner scan --recursive --format=json "--config=$_OSV_TMP" . > "$_OSV_JSON" || _OSV_STATUS=$?
    fi
    case "$_OSV_STATUS" in
      0)
        cmd_log_run deps pass ""
        ;;
      1)
        _OSV_BLOCKERS=$(osv_json_blockers "$_OSV_JSON" "$SEVERITY")
        if [ "${_OSV_BLOCKERS:-99}" -gt 0 ]; then
          cat "$_OSV_JSON"
          cmd_log_run deps block "$_OSV_BLOCKERS vulnerability group(s) at >= $SEVERITY or with unknown severity"
          return 1
        fi
        echo "[gates] osv-scanner reported vulnerabilities below $SEVERITY threshold" 1>&2
        _cmd_log_run_checked_pass deps "osv-scanner findings below $SEVERITY threshold"
        ;;
      128)
        # v2.x exits 128 when no package sources are found (e.g. all paths
        # excluded). Treat as clean — nothing to scan is not a failure.
        echo "[gates] osv-scanner: no package sources found (all paths excluded or empty repo)" 1>&2
        cmd_log_run deps pass "no package sources found"
        ;;
      *)
        cat "$_OSV_JSON" 1>&2
        cmd_log_run deps block "osv-scanner failed (exit=$_OSV_STATUS)"
        return 1
        ;;
    esac
  else
    # Legacy releases (pre-scan-subcommand): build argument list via positional
    # parameters (POSIX-safe, no eval, no word-splitting surprises).
    # (POSIX-safe, no eval, no word-splitting surprises).
    set -- --recursive "--severity=$SEVERITY"

    for _IGNORE_FILE in "$GLOBAL_IGNORE" "$REPO_IGNORE"; do
      [ -f "$_IGNORE_FILE" ] || continue
      while IFS= read -r LINE; do
        case "$LINE" in ''|'#'*) continue ;; esac
        ID=$(printf '%s' "$LINE" | sed 's/[[:space:]]*#.*//' | sed 's/[[:space:]]*$//')
        [ -n "$ID" ] && set -- "$@" "--ignore-vulns=$ID"
      done < "$_IGNORE_FILE"
    done

    set -- "$@" .   # trailing path arg

    if run_bounded "$_OSV_TIMEOUT" -- osv-scanner "$@"; then
      cmd_log_run deps pass ""
    else
      cmd_log_run deps block "osv-scanner reported vulnerabilities or timed out after ${_OSV_TIMEOUT}s"
      return 1
    fi
  fi
}

# Count osv-scanner JSON vulnerability groups that meet the configured
# threshold. Missing or malformed severity data blocks: a scanner finding
# without a trustworthy score is not safe to discard.
osv_json_blockers() {
  FILE="$1"; SEVERITY="$2"
  case "$SEVERITY" in
    CRITICAL|critical) MIN_SCORE=9 ;;
    HIGH|high)         MIN_SCORE=7 ;;
    MEDIUM|medium)     MIN_SCORE=4 ;;
    LOW|low)           MIN_SCORE=0.1 ;;
    *)                 MIN_SCORE=9 ;;
  esac

  if command -v jq >/dev/null 2>&1; then
    R=$(jq -r --argjson min "$MIN_SCORE" '
      [.results[]?.packages[]?
       | if ((.groups // []) | length) == 0
         then select(((.vulnerabilities // []) | length) > 0) | {max_severity: ""}
         else .groups[]
         end
       | (.max_severity // "" | try tonumber catch null) as $score
       | select(($score == null) or ($score >= $min))]
      | length
    ' "$FILE" 2>/dev/null)
    if [ -z "$R" ]; then echo 99; else echo "$R"; fi
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$FILE" "$MIN_SCORE" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    minimum = float(sys.argv[2])
    blockers = 0
    for result in data.get("results", []):
        for package in result.get("packages", []):
            groups = package.get("groups", [])
            if not groups and package.get("vulnerabilities", []):
                blockers += 1
            for group in groups:
                try:
                    score = float(group.get("max_severity", ""))
                except (TypeError, ValueError):
                    blockers += 1
                else:
                    blockers += score >= minimum
    print(blockers)
except Exception:
    print(99)
PY
  else
    echo 99
  fi
}

cmd_bleed() {
  # Internal-bleed scan: grep the changed-file set for patterns loaded from a
  # user-supplied pattern file. Patterns are BRE (grep -f), one per line;
  # lines starting with # and blank lines are ignored.
  #
  # Pattern file resolution (first found wins):
  #   1. ${CLAGENTIC_PROJECT_ROOT:-$PWD}/.clagentic/bleed-patterns  (repo-level)
  #   2. $HOME/.config/clagentic/bleed-patterns                     (global user config)
  #
  # If neither exists, the gate skips non-blocking with a warning — the gate
  # is opt-in via pattern config, not fail-closed on missing config.
  # Project-level exclusions: .clagentic-bleed-ignore (one path-substring per line).
  #
  # SCOPE (lr-caebc5): this gate used to run `git ls-files` against the whole
  # repo on every invocation — every tracked file, every run, regardless of
  # what changed. Sibling gates already scope to the change under review
  # (secrets: staged diff / branch history at :110; sast: merge-base baseline
  # at :588; merge-gate: staged diff / branch diff further below). Bleed now
  # follows the same precedent: staged files when the index is non-empty,
  # else the current branch's diff against a PROVABLY CURRENT
  # origin/<default-branch>, else full tree — full-tree is the fallback
  # path, not the default, and stays reachable via --full-scan or
  # automatically whenever a change-scoped resolution can't be established
  # (fresh repo, no baseline, detached HEAD, a branch baseline that cannot
  # be verified current, or the pattern file itself changed — a
  # pattern-file edit can turn an old, already-committed hit newly
  # relevant, so it forces a full scan).
  #
  # NOT the same fallback cmd_secrets uses (BOBBIE, lr-caebc5 follow-up):
  # cmd_secrets' feature-branch fallback (:110-134) scans local branch
  # HISTORY and never diffs against a remote ref. The branch-diff step here
  # instead resolves and diffs against origin/<default-branch> — the same
  # shape as cmd_sast's --baseline-commit mechanism (:588), including its
  # freshness precondition (_gate_resolve_fresh_default_branch_ref, :88).
  # See docs/GATES.md Gate 4d for the full writeup.
  _BLEED_FULL_SCAN=0
  for _bleed_arg in "$@"; do
    case "$_bleed_arg" in
      --full-scan) _BLEED_FULL_SCAN=1 ;;
    esac
  done

  _BLEED_PAT_FILE=""
  if [ -f "${CLAGENTIC_PROJECT_ROOT:-$PWD}/.clagentic/bleed-patterns" ]; then
    _BLEED_PAT_FILE="${CLAGENTIC_PROJECT_ROOT:-$PWD}/.clagentic/bleed-patterns"
  elif [ -f "$HOME/.config/clagentic/bleed-patterns" ]; then
    _BLEED_PAT_FILE="$HOME/.config/clagentic/bleed-patterns"
  fi

  if [ -z "$_BLEED_PAT_FILE" ]; then
    echo "[gates/bleed] no pattern file found — skipping (configure ~/.config/clagentic/bleed-patterns to enable)"
    cmd_log_run bleed pass "no pattern file"
    return 0
  fi

  # Strip comments/blanks into a temp file of active patterns.
  _BLEED_TMP=$(mktemp -t clagentic-bleed-pats.XXXXXX)
  grep -v '^[[:space:]]*#' "$_BLEED_PAT_FILE" | grep -v '^[[:space:]]*$' > "$_BLEED_TMP" || true
  if [ ! -s "$_BLEED_TMP" ]; then
    rm -f "$_BLEED_TMP"
    echo "[gates/bleed] pattern file has no active patterns — skipping"
    cmd_log_run bleed pass "empty pattern file"
    return 0
  fi

  # Determine the file-set scope. Same fallback ladder as cmd_secrets
  # (:110-116): staged diff first, else branch diff against the default
  # branch when there is nothing staged, else full tree when neither can be
  # established or --full-scan was requested.
  _BLEED_DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  _BLEED_SCOPE_REASON=""
  _BLEED_FILES=""

  # REPO SCOPING (lr-da1f28 sweep): every `_git` call below (staged diff,
  # branch name, ls-files) needs REPO_ROOT to provably be the git repo `_git`
  # resolves against — see _git_repo_root_is_scoped's doc comment. Resolve
  # this once up front rather than per call site; when not scoped, force a
  # full-tree scan (the documented fallback path this gate already has for
  # "no usable git state") instead of silently trusting an ancestor repo's
  # staged/branch state for a security-relevant file-set decision.
  if ! _git_repo_root_is_scoped; then
    _BLEED_FULL_SCAN=1
    echo "[gates/bleed] REPO_ROOT is not a git repo — forcing full-tree scan" 1>&2
  fi

  # A pattern-file change makes any prior full-scan history relevant again
  # (a newly added pattern could match content in files the current diff
  # never touches) — force full scan rather than silently narrowing.
  _BLEED_PAT_FILE_REL=${_BLEED_PAT_FILE#"$REPO_ROOT"/}
  if [ "$_BLEED_FULL_SCAN" != "1" ]; then
    _BLEED_STAGED_CHECK=$(_git diff --cached --name-only 2>/dev/null || true)
    if printf '%s\n' "$_BLEED_STAGED_CHECK" | grep -qF "$_BLEED_PAT_FILE_REL" 2>/dev/null; then
      _BLEED_FULL_SCAN=1
      _BLEED_SCOPE_REASON="pattern file changed in this diff"
    fi
  fi

  if [ "$_BLEED_FULL_SCAN" = "1" ]; then
    [ -z "$_BLEED_SCOPE_REASON" ] && _BLEED_SCOPE_REASON="--full-scan requested"
    # lr-da1f28 sweep: was a bare `git -C "$REPO_ROOT" ls-files`, bypassing
    # `_git` (and its scoping) for no documented reason — this is the same
    # file-set the rest of cmd_bleed already resolves via `_git`.
    _BLEED_FILES=$(_git ls-files 2>/dev/null) || {
      rm -f "$_BLEED_TMP"
      echo "[gates/bleed] git ls-files failed — skipping" 1>&2
      cmd_log_run bleed pass "git ls-files failed (non-blocking)"
      return 0
    }
    echo "[gates/bleed] full-tree scan ($_BLEED_SCOPE_REASON)" 1>&2
  else
    _BLEED_STAGED=$(_git diff --cached --name-only 2>/dev/null || true)
    if [ -n "$_BLEED_STAGED" ]; then
      _BLEED_FILES="$_BLEED_STAGED"
      _BLEED_SCOPE_REASON="staged diff"
    else
      _BLEED_CURRENT_BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
      if [ -n "$_BLEED_CURRENT_BRANCH" ] && [ "$_BLEED_CURRENT_BRANCH" != "HEAD" ] && [ "$_BLEED_CURRENT_BRANCH" != "$_BLEED_DEFAULT_BRANCH" ]; then
        # FRESHNESS IS A PRECONDITION, NOT AN ASSUMPTION (BOBBIE, lr-caebc5
        # follow-up to lr-06b87e). This scope used to trust a bare
        # `git rev-parse --verify origin/<default-branch>` — present-but-
        # stale is a SUCCESSFUL-LOOKING WRONG RESOLUTION: it exits 0,
        # produces a plausible file set, and silently narrows the scan on a
        # long-lived clone that was fetched once and never refreshed. A
        # secret-bleed pattern committed to the default branch afterward is
        # then invisible to this scope, and the gate reports an
        # authoritative-looking clean pass. Delegate to the same
        # provably-current fetch+ls-remote check cmd_sast uses
        # (_gate_resolve_fresh_default_branch_ref, :88-164) rather than
        # inventing a second mechanism — reuse first (AGENTS.md code-craft
        # rule 2).
        #
        # NOTE ON PARITY: this is NOT "the same fallback cmd_secrets uses"
        # (cmd_secrets' feature-branch fallback, :110-116, scans local
        # branch HISTORY and never diffs against a remote ref at all). The
        # actual precedent for a remote-ref-diff scope is cmd_sast's
        # baseline-commit mechanism (:588-663) — see docs/GATES.md.
        _BLEED_FETCH_TIMEOUT="${CLAGENTIC_BLEED_FETCH_TIMEOUT_SEC:-30}"
        _BLEED_FETCH_TIMEOUT=$(ds_positive_int_or_default "$_BLEED_FETCH_TIMEOUT" 30)

        _BLEED_FRESH_ERR_TMP=$(mktemp -t clagentic-bleed-fresh-err.XXXXXX)
        _BLEED_FRESH_TIP=$(_gate_resolve_fresh_default_branch_ref "$_BLEED_DEFAULT_BRANCH" "$_BLEED_FETCH_TIMEOUT" 2>"$_BLEED_FRESH_ERR_TMP") || true
        _BLEED_FRESH_ERR=$(cat "$_BLEED_FRESH_ERR_TMP" 2>/dev/null || echo "")
        rm -f "$_BLEED_FRESH_ERR_TMP"

        if [ -n "$_BLEED_FRESH_TIP" ]; then
          _BLEED_FILES=$(_git diff "${_BLEED_FRESH_TIP}...HEAD" --name-only 2>/dev/null || true)
          _BLEED_SCOPE_REASON="branch diff vs origin/${_BLEED_DEFAULT_BRANCH}"
        else
          # Unverifiable/stale baseline: fail toward MORE coverage, never
          # less. Narrowing requires a positively-verified fresh baseline —
          # a resolution we cannot prove is current degrades straight to
          # full-tree, exactly like cmd_sast, rather than silently scanning
          # nothing or trusting a possibly-stale ref.
          echo "[gates/bleed] branch baseline not provably current ($_BLEED_FRESH_ERR) — falling back to full-tree scan" 1>&2
        fi
      fi
      # Nothing staged, no usable branch baseline (detached HEAD, on the
      # default branch itself, no origin/<default-branch> ref, or the
      # branch baseline could not be shown to be provably current — fresh
      # repo, first run, or a stale/unfetched remote-tracking ref): fall
      # back to a full scan rather than silently scanning nothing or
      # trusting an unverified baseline.
      if [ -z "$_BLEED_FILES" ] && [ -z "$_BLEED_SCOPE_REASON" ]; then
        # lr-da1f28 sweep: same bare `git -C "$REPO_ROOT"` bypass as the
        # full-scan branch above — no documented reason to skip `_git` here.
        _BLEED_FILES=$(_git ls-files 2>/dev/null) || {
          rm -f "$_BLEED_TMP"
          echo "[gates/bleed] git ls-files failed — skipping" 1>&2
          cmd_log_run bleed pass "git ls-files failed (non-blocking)"
          return 0
        }
        _BLEED_SCOPE_REASON="full-tree fallback (no staged changes, no usable branch baseline)"
      fi
    fi
    echo "[gates/bleed] scanning $_BLEED_SCOPE_REASON" 1>&2
  fi

  # Always exclude .git/ and .clagentic/ (binary DBs, pattern files).
  _BLEED_FILES=$(printf '%s\n' "$_BLEED_FILES" \
    | grep -v -e '^\.git/' -e '^\.clagentic/' || true)

  if [ -z "$_BLEED_FILES" ]; then
    rm -f "$_BLEED_TMP"
    _cmd_log_run_checked_pass bleed "no files to scan ($_BLEED_SCOPE_REASON)"
    return 0
  fi

  # Apply project-level exclusions from .clagentic-bleed-ignore.
  _BLEED_IGNORE="$REPO_ROOT/.clagentic-bleed-ignore"
  if [ -f "$_BLEED_IGNORE" ]; then
    while IFS= read -r _BLINE; do
      case "$_BLINE" in ''|'#'*) continue ;; esac
      _BLEED_FILES=$(printf '%s\n' "$_BLEED_FILES" | grep -vF "$_BLINE" || true)
    done < "$_BLEED_IGNORE"
  fi

  if [ -z "$_BLEED_FILES" ]; then
    rm -f "$_BLEED_TMP"
    _cmd_log_run_checked_pass bleed "all files excluded ($_BLEED_SCOPE_REASON)"
    return 0
  fi

  # Only scan files that still exist in the working tree (a diff-scoped list
  # can include deletions, which have nothing left to grep).
  _BLEED_FILES=$(printf '%s\n' "$_BLEED_FILES" \
    | while IFS= read -r _bf; do [ -f "$REPO_ROOT/$_bf" ] && printf '%s\n' "$_bf"; done)

  if [ -z "$_BLEED_FILES" ]; then
    rm -f "$_BLEED_TMP"
    _cmd_log_run_checked_pass bleed "no existing files to scan ($_BLEED_SCOPE_REASON)"
    return 0
  fi

  # Scan: grep -f reads patterns from file; -I skips binary; -l names files only.
  # Prepend REPO_ROOT so xargs can reach files from any cwd.
  _BLEED_HITS=$(printf '%s\n' "$_BLEED_FILES" \
    | xargs -I{} grep -lIf "$_BLEED_TMP" -- "$REPO_ROOT/{}" 2>/dev/null || true)
  rm -f "$_BLEED_TMP"

  if [ -n "$_BLEED_HITS" ]; then
    echo "[gates/bleed] BLOCKED — internal bleed patterns found:" 1>&2
    printf '%s\n' "$_BLEED_HITS" 1>&2
    cmd_log_run bleed block "bleed patterns found in: $(printf '%s' "$_BLEED_HITS" | tr '\n' ' ')"
    return 1
  fi

  echo "[gates/bleed] clean"
  _cmd_log_run_checked_pass bleed "no bleed patterns found ($_BLEED_SCOPE_REASON)"
  return 0
}

# _sast_exclude_rule_flags — build the `--exclude-rule <id>` argument list
# from the two-level exclude ladder, mirroring cmd_deps' osv-ignore mechanism
# (:404-450, :500-507) exactly (reuse-first, AGENTS.md code-craft rule 2) —
# same two file paths (global then repo), same one-id-per-line format, same
# `''|'#'*` comment/blank skip, same trailing-comment-and-whitespace strip.
#
# Args: GLOBAL_FILE REPO_FILE (both paths, existence checked internally —
# same "[ -f ... ] || continue" tolerance cmd_deps uses for a ladder level
# that isn't present).
# stdout: NUL-free, newline-separated argv tokens — "--exclude-rule\n<id>"
# per active entry, one token per line, ready for reconstruction via a
# `while read` loop (a single space-joined string would break on a rule id
# containing whitespace, though semgrep rule ids never do in practice; the
# newline-per-token form is simply the safer POSIX shape and costs nothing
# extra here).
_sast_exclude_rule_flags() {
  _serf_global="$1"
  _serf_repo="$2"
  for _serf_file in "$_serf_global" "$_serf_repo"; do
    [ -f "$_serf_file" ] || continue
    while IFS= read -r _serf_line; do
      case "$_serf_line" in ''|'#'*) continue ;; esac
      _serf_id=$(printf '%s' "$_serf_line" | sed 's/[[:space:]]*#.*//' | sed 's/[[:space:]]*$//')
      [ -n "$_serf_id" ] || continue
      printf -- '--exclude-rule\n%s\n' "$_serf_id"
    done < "$_serf_file"
  done
}

# _sast_config_flag — print the semgrep `--config` argument(s) to use.
# DEFAULT STAYS auto (CLAGENTIC_SEMGREP_CONFIG unset or empty): lite ships to
# other people, so pinning a policy file is a per-repo opt-in, never a
# hardcoded preference baked into gates.sh itself. When set, the env var
# value replaces --config=auto outright — auto is not contacted at all.
#
# stdout: NUL-free, newline-separated argv tokens ("--config\n<value>" or
# "--config=auto"), same shape _sast_exclude_rule_flags uses.
_sast_config_flag() {
  if [ -n "${CLAGENTIC_SEMGREP_CONFIG:-}" ]; then
    printf -- '--config\n%s\n' "$CLAGENTIC_SEMGREP_CONFIG"
  else
    printf -- '--config=auto\n'
  fi
}

# _sast_pinned_config_from_argv ARG1 ARG2 — extract the pinned config path
# from cmd_sast's own reconstructed argv (its first two positional
# parameters, before --exclude-rule tokens are appended), given the shape
# _sast_config_flag emits: a literal "--config" token followed by the path,
# when CLAGENTIC_SEMGREP_CONFIG was set, or the single fused
# "--config=auto" token when it was not (which never matches "--config" as
# a standalone ARG1, so this prints nothing in the default case).
#
# BOBBIE finding (PR #159, comment 5258964196): a pinned config can replace
# --config=auto with a policy path that disables every rule, and that
# override used to reach neither stderr nor the audit-log details string --
# the same silent-suppression failure the task forbids for the exclude
# ladder, just on the config pin instead. This helper is what cmd_sast now
# calls to detect the pin so it can surface it, the same way
# _sast_exclude_rule_flags' output already gets scanned for visibility.
#
# stdout: the pinned config path, or empty when --config=auto is active.
_sast_pinned_config_from_argv() {
  if [ "${1:-}" = "--config" ]; then
    printf '%s' "${2:-}"
  fi
}

cmd_sast() {
  if ! command -v semgrep >/dev/null 2>&1; then
    if [ "${CLAGENTIC_ALLOW_MISSING_SEMGREP:-0}" = "1" ]; then
      echo "[gates] semgrep not installed — skipping (CLAGENTIC_ALLOW_MISSING_SEMGREP=1 set)" 1>&2
      cmd_log_run sast skip "semgrep not installed (opt-in skip)"
      return 0
    fi
    echo "[gates] semgrep not installed — BLOCKING (set CLAGENTIC_ALLOW_MISSING_SEMGREP=1 to skip, or install: pipx install semgrep | brew install semgrep)" 1>&2
    cmd_log_run sast block "semgrep not installed (fail-closed)"
    return 1
  fi

  # Baseline scoping: semgrep's native --baseline-commit reports only
  # findings introduced relative to a given commit, so pre-existing
  # findings in files the branch never touched no longer block. This is
  # STRICTLY a narrowing of what blocks, never a widening — every
  # resolution failure below falls back to the prior full-tree behavior.
  #
  # FAIL-CLOSED CONTRACT: if the merge base cannot be confidently resolved
  # (semgrep too old for --baseline-commit, detached HEAD, on the default
  # branch itself, shallow clone with the base not fetched, no
  # origin/<default-branch>), scan the full tree exactly as before. Never
  # silently narrow to an empty/partial scan on a resolution failure — a
  # scoping bug must not become a security bypass.
  #
  # GOVERNING PRINCIPLE — preserve when uncertain: freshness of the
  # resolved origin/<default-branch> ref is a PRECONDITION, not an
  # assumption. A resolution that cannot be shown to be current (fetch
  # failed, fetch timed out, or the local tracking ref does not match an
  # independent `git ls-remote` read of the same remote taken in this
  # run) is uncertain, and uncertain degrades to the full-tree fallback
  # below — never to a narrower window silently resolved against a stale
  # ref. See the fetch block below for why "we have some ref" is not
  # sufficient on its own.
  _SAST_BASELINE=""
  _SAST_BASELINE_SKIP_REASON=""

  # Probed via `semgrep scan --help`, not bare `semgrep --help` — modern
  # semgrep (1.x) is a command group (scan/ci/...) and --baseline-commit is
  # a `scan` subcommand flag; it does not appear in the top-level help text.
  if ! semgrep scan --help 2>&1 | grep -q -- '--baseline-commit'; then
    _SAST_BASELINE_SKIP_REASON="installed semgrep does not support --baseline-commit"
  else
    _SAST_DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
    # REPO SCOPING (lr-da1f28 sweep): guard before trusting the branch name
    # — an unscoped REPO_ROOT would otherwise silently resolve an ancestor
    # repo's (real, non-empty, non-"HEAD") branch name, which the emptiness
    # checks below would not catch. _gate_resolve_fresh_default_branch_ref
    # (called further down) independently refuses on the same condition, but
    # guarding here too keeps the diagnostic message honest rather than
    # implying a real branch was found.
    _SAST_CURRENT_BRANCH=""
    if _git_repo_root_is_scoped; then
      _SAST_CURRENT_BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    fi

    if [ -z "$_SAST_CURRENT_BRANCH" ] || [ "$_SAST_CURRENT_BRANCH" = "HEAD" ]; then
      _SAST_BASELINE_SKIP_REASON="detached HEAD — no branch to diff against a base"
    elif [ "$_SAST_CURRENT_BRANCH" = "$_SAST_DEFAULT_BRANCH" ]; then
      _SAST_BASELINE_SKIP_REASON="on default branch $_SAST_DEFAULT_BRANCH — nothing to baseline against"
    else
      # Freshness resolution delegates to _gate_resolve_fresh_default_branch_ref
      # (:88-164) — the shared PROVABLY-CURRENT fetch+ls-remote check every
      # gate that diffs against origin/<default-branch> must use. See that
      # function's own docstring for the full rationale (security-audit
      # follow-up to lr-06b87e); this call site only adds the merge-base
      # step, which is specific to semgrep's --baseline-commit and not part
      # of the shared freshness precondition itself.
      _SAST_FETCH_TIMEOUT="${CLAGENTIC_SAST_FETCH_TIMEOUT_SEC:-30}"
      _SAST_FETCH_TIMEOUT=$(ds_positive_int_or_default "$_SAST_FETCH_TIMEOUT" 30)

      _SAST_FRESH_ERR_TMP=$(mktemp -t clagentic-sast-fresh-err.XXXXXX)
      _SAST_FRESH_TIP=$(_gate_resolve_fresh_default_branch_ref "$_SAST_DEFAULT_BRANCH" "$_SAST_FETCH_TIMEOUT" 2>"$_SAST_FRESH_ERR_TMP") || true
      _SAST_FRESH_ERR=$(cat "$_SAST_FRESH_ERR_TMP" 2>/dev/null || echo "")
      rm -f "$_SAST_FRESH_ERR_TMP"

      if [ -z "$_SAST_FRESH_TIP" ]; then
        _SAST_BASELINE_SKIP_REASON="$_SAST_FRESH_ERR"
      else
        # Use the verified-fresh SHA _gate_resolve_fresh_default_branch_ref
        # just proved current (lr-53dc6e; matches cmd_bleed's own use of
        # its verified tip at :546, `_git diff "${_BLEED_FRESH_TIP}...HEAD"`).
        # Re-resolving "origin/${_SAST_DEFAULT_BRANCH}" BY NAME here would
        # discard that proof and reopen the same TOCTOU gap the helper
        # exists to close: a concurrent fetch/rewrite between the freshness
        # check and this merge-base call could move the named ref again.
        _SAST_MERGE_BASE=$(_git merge-base "$_SAST_FRESH_TIP" HEAD 2>/dev/null || echo "")
        if [ -z "$_SAST_MERGE_BASE" ]; then
          _SAST_BASELINE_SKIP_REASON="merge-base resolution failed (shallow clone with base not fetched, or unrelated histories)"
        else
          _SAST_BASELINE="$_SAST_MERGE_BASE"
        fi
      fi
    fi
  fi

  # Bound every semgrep invocation (INV-1a/INV-2, class-4 foundry fix):
  # --config=auto DOWNLOADS RULES FROM THE NETWORK on top of running a scan,
  # so this defaults higher than the generic run_bounded default.
  _SAST_TIMEOUT="${CLAGENTIC_SAST_TIMEOUT_SEC:-300}"
  _SAST_TIMEOUT=$(ds_positive_int_or_default "$_SAST_TIMEOUT" 300)

  # Config: --config=auto by default, or CLAGENTIC_SEMGREP_CONFIG when set —
  # DEFAULT STAYS auto (lite ships to other people; pinning is per-repo
  # opt-in, never hardcoded here). Reconstructed via positional parameters
  # (POSIX-safe, no eval), same technique the legacy osv-scanner branch
  # (:495-517) uses. Config comes FIRST in $@ so the no-exclusions,
  # no-CLAGENTIC_SEMGREP_CONFIG case reconstructs the exact prior argv
  # (`semgrep --config=auto --error --severity=ERROR`) byte-for-byte.
  set --
  while IFS= read -r _SAST_CFG_TOK; do
    [ -n "$_SAST_CFG_TOK" ] || continue
    set -- "$@" "$_SAST_CFG_TOK"
  done <<EOF_CFG
$(_sast_config_flag)
EOF_CFG

  # Exclude ladder (lr-321e18): $HOME/.config/clagentic/semgrep-exclude
  # (global) union $REPO_ROOT/.clagentic/semgrep-exclude (repo) — mirrors
  # cmd_deps' osv-ignore mechanism exactly (reuse-first). Each rule id
  # becomes an --exclude-rule flag on BOTH the baseline and full-tree
  # invocations below.
  while IFS= read -r _SAST_EXCL_TOK; do
    [ -n "$_SAST_EXCL_TOK" ] || continue
    set -- "$@" "$_SAST_EXCL_TOK"
  done <<EOF_EXCL
$(_sast_exclude_rule_flags "$HOME/.config/clagentic/semgrep-exclude" "$REPO_ROOT/.clagentic/semgrep-exclude")
EOF_EXCL

  # A suppressed rule must never be silent (task requirement): when the
  # ladder produced at least one --exclude-rule flag, name the excluded rule
  # ids on stderr and fold the count/ids into the audit-log details string
  # for both outcome branches below.
  _SAST_EXCL_IDS=""
  _SAST_EXCL_COUNT=0
  _sast_prev=""
  for _sast_tok in "$@"; do
    if [ "$_sast_prev" = "--exclude-rule" ]; then
      _SAST_EXCL_COUNT=$((_SAST_EXCL_COUNT + 1))
      if [ -z "$_SAST_EXCL_IDS" ]; then
        _SAST_EXCL_IDS="$_sast_tok"
      else
        _SAST_EXCL_IDS="$_SAST_EXCL_IDS,$_sast_tok"
      fi
    fi
    _sast_prev="$_sast_tok"
  done
  if [ "$_SAST_EXCL_COUNT" -gt 0 ]; then
    echo "[gates/sast] excluding $_SAST_EXCL_COUNT rule(s): $_SAST_EXCL_IDS" 1>&2
  fi

  # A pinned config must never be silent either (BOBBIE, PR #159 comment
  # 5258964196): CLAGENTIC_SEMGREP_CONFIG can replace --config=auto with a
  # policy path that disables every rule, and that override used to reach
  # neither stderr nor the audit-log details string -- the same
  # silent-suppression failure the task forbids for the exclude ladder,
  # applied to the config pin. See _sast_pinned_config_from_argv's own
  # doc comment for how the pin is detected from the reconstructed argv.
  _SAST_PINNED_CONFIG=$(_sast_pinned_config_from_argv "${1:-}" "${2:-}")
  if [ -n "$_SAST_PINNED_CONFIG" ]; then
    echo "[gates/sast] using pinned config: $_SAST_PINNED_CONFIG" 1>&2
  fi

  # Semgrep natively honors .semgrepignore at the repo root. Add paths or rules there to suppress findings.
  if [ -n "$_SAST_BASELINE" ]; then
    echo "[gates/sast] scoping to diff-introduced findings (baseline-commit=$_SAST_BASELINE)" 1>&2
    if run_bounded "$_SAST_TIMEOUT" -- semgrep "$@" --error --severity=ERROR "--baseline-commit=$_SAST_BASELINE"; then
      _SAST_PASS_DETAILS="baseline-commit=$_SAST_BASELINE"
      [ -n "$_SAST_PINNED_CONFIG" ] && _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; config=$_SAST_PINNED_CONFIG"
      if [ "$_SAST_EXCL_COUNT" -gt 0 ]; then
        _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; excluded $_SAST_EXCL_COUNT rule(s): $_SAST_EXCL_IDS"
      fi
      _cmd_log_run_checked_pass sast "$_SAST_PASS_DETAILS"
    else
      cmd_log_run sast block "semgrep reported ERROR-severity findings introduced since $_SAST_BASELINE (or timed out after ${_SAST_TIMEOUT}s)"
      return 1
    fi
  else
    echo "[gates/sast] full-tree scan (baseline scoping unavailable: $_SAST_BASELINE_SKIP_REASON)" 1>&2
    if run_bounded "$_SAST_TIMEOUT" -- semgrep "$@" --error --severity=ERROR; then
      _SAST_PASS_DETAILS="full-tree (baseline unavailable: $_SAST_BASELINE_SKIP_REASON)"
      [ -n "$_SAST_PINNED_CONFIG" ] && _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; config=$_SAST_PINNED_CONFIG"
      if [ "$_SAST_EXCL_COUNT" -gt 0 ]; then
        _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; excluded $_SAST_EXCL_COUNT rule(s): $_SAST_EXCL_IDS"
      fi
      _cmd_log_run_checked_pass sast "$_SAST_PASS_DETAILS"
    else
      cmd_log_run sast block "semgrep reported ERROR-severity findings (full-tree scan: $_SAST_BASELINE_SKIP_REASON; or timed out after ${_SAST_TIMEOUT}s)"
      return 1
    fi
  fi
}

# ---------------------------------------------------------------- review ledger --
#
# The review ledger (lr-01ae73) is the append-only, per-branch history of
# every `gates.sh review` verdict: base_sha, head_sha, pass/block outcome,
# structured findings, timestamp, and the gate config in effect. It replaces
# floating, unanchored review state with an immutable record keyed to the
# exact (base_sha, head_sha) pair a verdict evaluated — the same property
# that makes a crew change-request review trustworthy across rounds (see
# this task's own WHY). Storage and read/write primitives live in
# review-merge.sh (ledger_append / ledger_entries_for_branch /
# ledger_latest_for_branch) — gates.sh only builds entries and interprets
# them; JSONL append/read is generic and belongs alongside this file's other
# shared persistence helpers (dedup_findings' SEEN_FILE,
# finding_recurrence_bump's COUNTS_FILE).
#
# FILE: .clagentic/lite/review-ledger.jsonl (gitignored local gate state,
# same directory convention as last-review.json/review-seen-keys/
# review-recurrence.json). One JSON object per line, oldest first.
#
# ANCHORED VERDICTS: a ledger entry's `verdict` field is one of:
#   "pass"       — review ran, resolved a real head_sha, findings below the
#                  block threshold.
#   "block"      — review ran, resolved a real head_sha, findings at or
#                  above the block threshold (or a degraded/infra failure).
#   "unanchored" — review ran but HEAD's SHA could not be resolved (REPO_ROOT
#                  not a git repo, or _git_repo_scoped_head_sha otherwise
#                  came back empty). An unanchored entry is recorded for
#                  audit-trail completeness but MUST NEVER be read as a
#                  passing verdict by any consumer (_ledger_anchored_pass_at_head
#                  below is the one sanctioned check) — a verdict with no
#                  resolvable head SHA has nothing to anchor to and is
#                  treated as NO verdict at all, per this task's own
#                  acceptance criterion.
#
# _review_ledger_path — the one place the ledger's on-disk path is spelled,
# so every reader/writer agrees on it.
_review_ledger_path() {
  printf '%s/.clagentic/lite/review-ledger.jsonl' "$REPO_ROOT"
}

# _review_current_branch — current branch name, or empty when REPO_ROOT is
# not (provably) a git repo or HEAD is detached. Repo-scoped (lr-da1f28
# sweep posture): guards on _git_repo_root_is_scoped exactly like every
# other branch-name read in this file.
_review_current_branch() {
  _rcb_branch=""
  if _git_repo_root_is_scoped; then
    _rcb_branch=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  [ "$_rcb_branch" = "HEAD" ] && _rcb_branch=""
  printf '%s' "$_rcb_branch"
}

# _resolve_base_sha DEFAULT_BRANCH TIMEOUT_SEC — merge-base(origin/DEFAULT_BRANCH,
# HEAD), using the SAME provably-current freshness precondition cmd_sast's
# --baseline-commit scoping already established
# (_gate_resolve_fresh_default_branch_ref) — reuse, not a second freshness
# check. Prints the merge-base SHA on success; prints nothing on any
# resolution failure (detached HEAD, on the default branch itself, fetch
# failure/timeout, unverifiable freshness, shallow clone with no common
# ancestor). Callers treat empty as "base_sha unresolvable" and must not
# treat that as a hard error — a ledger entry with an empty base_sha is
# still a valid, anchored entry as long as head_sha resolved; base_sha is
# provenance (which merge-base a verdict was computed relative to), not the
# anchor itself (head_sha is).
_resolve_base_sha() {
  _rbs_default_branch="$1"
  _rbs_timeout="$2"

  if ! _git_repo_root_is_scoped; then
    return 0
  fi
  _rbs_current_branch=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  if [ -z "$_rbs_current_branch" ] || [ "$_rbs_current_branch" = "HEAD" ] || [ "$_rbs_current_branch" = "$_rbs_default_branch" ]; then
    return 0
  fi

  _rbs_fresh_err_tmp=$(mktemp -t clagentic-basesha-err.XXXXXX)
  _rbs_fresh_tip=$(_gate_resolve_fresh_default_branch_ref "$_rbs_default_branch" "$_rbs_timeout" 2>"$_rbs_fresh_err_tmp") || true
  rm -f "$_rbs_fresh_err_tmp"
  [ -n "$_rbs_fresh_tip" ] || return 0

  _git merge-base "$_rbs_fresh_tip" HEAD 2>/dev/null || true
}

# _ledger_config_snapshot — one-line JSON object of the gate config in
# effect for this review run (item 1's "gate config in effect" requirement).
# Deliberately narrow: only the knobs that change WHAT was evaluated or HOW
# a verdict was scored, not every CLAGENTIC_* var in the process environment
# (an unbounded env dump would itself be an injection/bloat surface into a
# file later read back and rendered).
_ledger_config_snapshot() {
  _lcs_threshold="${CLAGENTIC_BLOCK_SEVERITY:-high}"
  _lcs_dedup="${CLAGENTIC_CROSS_ROUND_DEDUP:-1}"
  _lcs_recurrence_threshold=$(_review_recurrence_threshold)
  printf '{"block_severity":"%s","cross_round_dedup":%s,"recurrence_threshold":%s}' \
    "$_lcs_threshold" \
    "$([ "$_lcs_dedup" = "1" ] && echo true || echo false)" \
    "$_lcs_recurrence_threshold"
}

# _ledger_anchored_pass_at_head LEDGER_FILE BRANCH HEAD_SHA — exit 0 (true)
# only when the MOST RECENT ledger entry for BRANCH is anchored to HEAD_SHA
# (its head_sha field equals HEAD_SHA) AND its verdict is "pass". This is
# the one sanctioned "is there a currently-valid verdict" predicate — every
# consumer (build_gate_summary) must route through this rather than
# re-deriving the same check inline, mirroring this file's existing
# "one shared helper, not a re-derivation per call site" discipline
# (_git_repo_root_is_scoped, _gate_resolve_fresh_default_branch_ref).
#
# An "unanchored" verdict (empty/unresolvable head_sha at record time) can
# never satisfy this check even if HEAD_SHA is also empty — an empty
# head_sha never equals HEAD_SHA because HEAD_SHA is only ever passed in
# from a resolved _git_repo_scoped_head_sha call, which is non-empty
# whenever this function is worth calling at all; callers with no resolvable
# HEAD_SHA should not call this function (there is nothing to anchor to).
_ledger_anchored_pass_at_head() {
  _laph_file="$1"
  _laph_branch="$2"
  _laph_head="$3"
  [ -n "$_laph_head" ] || return 1

  _laph_latest=$(ledger_latest_for_branch "$_laph_file" "$_laph_branch")
  [ -n "$_laph_latest" ] || return 1

  _laph_entry_head=""
  _laph_entry_verdict=""
  if command -v jq >/dev/null 2>&1; then
    _laph_entry_head=$(printf '%s' "$_laph_latest" | jq -r '.head_sha // ""' 2>/dev/null)
    _laph_entry_verdict=$(printf '%s' "$_laph_latest" | jq -r '.verdict // ""' 2>/dev/null)
  elif command -v python3 >/dev/null 2>&1; then
    _laph_entry_head=$(printf '%s' "$_laph_latest" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("head_sha",""))
except Exception:
    print("")' 2>/dev/null)
    _laph_entry_verdict=$(printf '%s' "$_laph_latest" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("verdict",""))
except Exception:
    print("")' 2>/dev/null)
  else
    return 1
  fi

  [ -n "$_laph_entry_head" ] || return 1
  [ "$_laph_entry_head" = "$_laph_head" ] || return 1
  [ "$_laph_entry_verdict" = "pass" ]
}

# _ledger_mark_recurrence FINDINGS_JSON DIFF_FILE LEDGER_FILE BRANCH
#
# Item 5: findings carry stable identity across rounds so the ledger can
# mark a finding recurring vs new. RECORDS RECURRENCE ONLY: this function
# never adjusts severity, never excludes anything from severity_blockers'
# count, and is entirely independent of
# _review_recurrence_demote/_recurrence_demoted (that mechanism's
# SEVERITY-DEMOTION POLICY is explicitly prior art this task must not
# resurrect — see lr-66e598 and this task's own OUT OF SCOPE). The output
# is informational annotation only: each finding in the returned array gets
# `_ledger_recurring: true|false`.
#
# MATCH KEY: the (file, category, message) triple — deliberately NOT
# finding_content_keys' sha256-of-a-diff-context-window key. That key is a
# function of THIS ROUND's diff content around the finding's line; a
# recurring finding very often lands in a round whose diff does not touch
# the finding's file again at all (the model is simply re-reporting an
# unresolved issue while THIS round's diff is elsewhere), which makes the
# content-hash key uncomputable for both the live finding and the
# re-derived prior one — a false negative, not a real absence of
# recurrence. The (file, category, message) triple is exactly the SAME
# match key `_review_recurrence_demote` and `_review_deferral_match`
# already use for the identical "survive rounds where the file/line isn't
# in the current diff" property (see their own doc comments in this file).
#
# stdout: the findings array with `_ledger_recurring` spliced onto every
# finding object. On any failure (no python3, unparseable input, no prior
# entries) prints FINDINGS_JSON unchanged (conservative passthrough — a
# recurrence-marking failure must never alter which findings exist or their
# severity, only whether the informational annotation is present).
_ledger_mark_recurrence() {
  _lmr_findings_json="$1"
  _lmr_diff="$2"
  _lmr_ledger="$3"
  _lmr_branch="$4"

  if ! command -v python3 >/dev/null 2>&1; then
    printf '%s' "$_lmr_findings_json"
    return 0
  fi

  _lmr_prior_entries=$(mktemp -t clagentic-ledger-prior.XXXXXX)
  if [ -f "$_lmr_ledger" ]; then
    ledger_entries_for_branch "$_lmr_ledger" "$_lmr_branch" > "$_lmr_prior_entries" 2>/dev/null
  fi

  _lmr_out=$(python3 - "$_lmr_findings_json" "$_lmr_prior_entries" <<'PYEOF'
import json, sys

findings_json, prior_entries_path = sys.argv[1], sys.argv[2]

try:
    findings = json.loads(findings_json)
    if not isinstance(findings, list):
        raise ValueError
except Exception:
    print(findings_json)
    sys.exit(0)

def triple(f):
    return (str(f.get("file", "")), str(f.get("category", "")), str(f.get("message", "")))

prior_triples = set()
try:
    with open(prior_entries_path) as pf:
        for line in pf:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            for prior_f in entry.get("findings", []):
                if isinstance(prior_f, dict):
                    prior_triples.add(triple(prior_f))
except Exception:
    pass

# OWN THE FIELD for every finding this loop touches (explicit, definite
# value), same posture as _review_recurrence_demote's own splice —
# never leave whatever the object already carried untouched.
for f in findings:
    if isinstance(f, dict):
        f["_ledger_recurring"] = triple(f) in prior_triples

print(json.dumps(findings))
PYEOF
)
  rm -f "$_lmr_prior_entries"
  [ -n "$_lmr_out" ] && printf '%s' "$_lmr_out" || printf '%s' "$_lmr_findings_json"
  return 0
}

# _ledger_record_review_verdict OUT_FILE DIFF_FILE OUTCOME BASE_SHA HEAD_SHA
#
# Item 1/2/5: builds and appends one ledger entry for this review run.
# OUTCOME is "pass" or "block" (the caller's own severity_blockers/degraded
# determination — this function does not re-derive it). HEAD_SHA empty means
# the verdict is UNANCHORED (see "review ledger" above) regardless of
# OUTCOME — recorded for audit-trail completeness but never readable as a
# passing verdict by _ledger_anchored_pass_at_head.
#
# Fail-open: a ledger write failure (no python3/jq, malformed OUT_FILE) must
# never abort or alter the review gate's own pass/block decision — the
# ledger is a durability/history layer on top of that decision, not a
# precondition for it. Matches every other on-disk gate-state writer's
# posture in this file.
_ledger_record_review_verdict() {
  _lrrv_out="$1"
  _lrrv_diff="$2"
  _lrrv_outcome="$3"
  _lrrv_base_sha="$4"
  _lrrv_head_sha="$5"

  _lrrv_verdict="$_lrrv_outcome"
  [ -n "$_lrrv_head_sha" ] || _lrrv_verdict="unanchored"

  _lrrv_ledger=$(_review_ledger_path)
  _lrrv_branch=$(_review_current_branch)
  _lrrv_ts=$(ds_date_iso)
  _lrrv_config=$(_ledger_config_snapshot)

  _lrrv_findings='[]'
  if [ -f "$_lrrv_out" ]; then
    _lrrv_findings=$(_extract_findings_json "$_lrrv_out")
    [ -n "$_lrrv_findings" ] || _lrrv_findings='[]'
  fi

  # Recurrence marking (item 5) — informational only, see
  # _ledger_mark_recurrence's own doc comment.
  _lrrv_findings=$(_ledger_mark_recurrence "$_lrrv_findings" "$_lrrv_diff" "$_lrrv_ledger" "$_lrrv_branch")
  [ -n "$_lrrv_findings" ] || _lrrv_findings='[]'

  _lrrv_line=""
  if command -v jq >/dev/null 2>&1; then
    _lrrv_line=$(jq -nc \
      --arg ts "$_lrrv_ts" \
      --arg branch "$_lrrv_branch" \
      --arg base "$_lrrv_base_sha" \
      --arg head "$_lrrv_head_sha" \
      --arg verdict "$_lrrv_verdict" \
      --argjson findings "$_lrrv_findings" \
      --argjson config "$_lrrv_config" \
      '{ts: $ts, branch: $branch, base_sha: $base, head_sha: $head, verdict: $verdict, findings: $findings, config: $config}' 2>/dev/null)
  elif command -v python3 >/dev/null 2>&1; then
    _lrrv_line=$(python3 - "$_lrrv_ts" "$_lrrv_branch" "$_lrrv_base_sha" "$_lrrv_head_sha" "$_lrrv_verdict" "$_lrrv_findings" "$_lrrv_config" <<'PYEOF'
import json, sys
ts, branch, base, head, verdict, findings_json, config_json = sys.argv[1:8]
try:
    findings = json.loads(findings_json)
    if not isinstance(findings, list):
        findings = []
except Exception:
    findings = []
try:
    config = json.loads(config_json)
except Exception:
    config = {}
print(json.dumps({
    "ts": ts, "branch": branch, "base_sha": base, "head_sha": head,
    "verdict": verdict, "findings": findings, "config": config,
}))
PYEOF
)
  fi

  [ -n "$_lrrv_line" ] || return 0

  _lrrv_max="${CLAGENTIC_LEDGER_MAX_PER_BRANCH:-0}"
  case "$_lrrv_max" in ''|*[!0-9]*) _lrrv_max=0 ;; esac
  ledger_append "$_lrrv_ledger" "$_lrrv_line" "$_lrrv_max"
  ds_audit_log "review-ledger" "pass" "branch=${_lrrv_branch:-<none>} verdict=${_lrrv_verdict} head=${_lrrv_head_sha:-<unresolved>}"

  # Publish (lr-2b07a8): observability only, never gating -- see
  # _publish_review_verdict's own doc comment for the fallback contract.
  _publish_review_verdict "$_lrrv_branch" "$_lrrv_verdict" "$_lrrv_head_sha" "$_lrrv_findings"

  return 0
}

# _publish_review_verdict BRANCH VERDICT HEAD_SHA FINDINGS_JSON
#
# Item 3/4: after a verdict lands in the ledger, publish it through the host
# adapter as ONE comment per review run -- verdict, head_sha, a findings
# summary, and recurring-finding markers (the `_ledger_recurring` annotation
# _ledger_mark_recurrence already computed on FINDINGS_JSON). One comment
# per invocation of this function, which is called exactly once per
# _ledger_record_review_verdict call, which is called exactly once per
# `cmd_review` run -- never comment spam.
#
# FALLBACK CONTRACT (item 4): no remote, no auth, or no adapter for the host
# means the local ledger IS the complete flow, not a degraded one --
# host_adapter_available's "no adapter" case prints a single one-line notice
# and returns 0 (success), not a failure. A publish FAILURE (adapter present
# but the call itself errored -- auth expired, network down, rate limit)
# NEVER changes the verdict already recorded above and NEVER blocks the
# gate: this function's return value is deliberately never checked by its
# caller. Publish failures are logged to the audit db (ds_audit_log) so
# they're visible without being load-bearing.
_publish_review_verdict() {
  _prv_branch="$1"
  _prv_verdict="$2"
  _prv_head="$3"
  _prv_findings="$4"

  if ! host_adapter_available; then
    echo "[gates/review] no host adapter available for this remote — verdict recorded to the local ledger only"
    return 0
  fi

  _prv_body_file=$(mktemp -t clagentic-review-verdict-comment.XXXXXX)
  if ! _build_review_verdict_comment_body "$_prv_verdict" "$_prv_head" "$_prv_findings" > "$_prv_body_file" 2>/dev/null; then
    rm -f "$_prv_body_file"
    ds_audit_log "review-publish" "block" "branch=${_prv_branch:-<none>} head=${_prv_head:-<unresolved>} reason=body-render-failed"
    return 0
  fi

  if host_adapter_post_comment "$_prv_body_file"; then
    ds_audit_log "review-publish" "pass" "branch=${_prv_branch:-<none>} head=${_prv_head:-<unresolved>} verdict=${_prv_verdict}"
  else
    echo "[gates/review] publish to host adapter failed — local ledger verdict stands, gate outcome unaffected" 1>&2
    ds_audit_log "review-publish" "block" "branch=${_prv_branch:-<none>} head=${_prv_head:-<unresolved>} reason=adapter-post-comment-failed"
  fi
  rm -f "$_prv_body_file"
  return 0
}

# _render_review_verdict_lines VERDICT HEAD_SHA FINDINGS_JSON — the shared
# rendering core both _build_review_verdict_comment_body (one comment per
# review run) and _build_ship_pr_body's review-provenance section (lr-429b32)
# reuse rather than each re-deriving the same head/per-severity/recurring-
# findings formatting. Prints newline-separated lines to stdout: head_sha, a
# per-severity findings count, and a "Recurring from a prior round" block for
# any finding _ledger_mark_recurrence already flagged. Deliberately does NOT
# print a verdict header line -- callers frame the verdict differently (a
# bold comment title vs. a PR-body subsection heading) and VERDICT is still
# taken as a parameter only so the caller doesn't have to duplicate the
# argument-passing contract; it composes into either a standalone comment or
# a PR-body subsection without any string-surgery on the output. Fails
# closed (no output, non-zero exit) with no python3 -- same posture as the
# function it was extracted from.
_render_review_verdict_lines() {
  _rrvl_head="$1"
  _rrvl_findings="$2"

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$_rrvl_head" "$_rrvl_findings" <<'PYEOF'
import json, sys

head, findings_json = sys.argv[1:3]
try:
    findings = json.loads(findings_json)
    if not isinstance(findings, list):
        findings = []
except Exception:
    findings = []

by_severity = {}
recurring = []
for f in findings:
    if not isinstance(f, dict):
        continue
    sev = str(f.get("severity", "unknown"))
    by_severity[sev] = by_severity.get(sev, 0) + 1
    if f.get("_ledger_recurring"):
        recurring.append(f)

lines = []
lines.append("head_sha: `%s`" % (head or "<unresolved>"))
lines.append("")
if findings:
    lines.append("Findings: %d total (%s)" % (
        len(findings),
        ", ".join("%s: %d" % (k, v) for k, v in sorted(by_severity.items())),
    ))
else:
    lines.append("Findings: none")
if recurring:
    lines.append("")
    lines.append("Recurring from a prior round (%d):" % len(recurring))
    for f in recurring:
        lines.append("- [%s] %s: %s" % (
            f.get("severity", "unknown"), f.get("file", "?"), f.get("message", ""),
        ))

print("\n".join(lines))
PYEOF
    return $?
  fi

  # No python3 -- jq alone cannot format multi-line prose cleanly enough for
  # a readable body, so this path fails closed (no partial/garbled output)
  # rather than emitting something malformed. host_adapter_available having
  # returned true is not itself gated on python3, so this is a real, distinct
  # degraded case, logged by the caller.
  return 1
}

# _build_review_verdict_comment_body VERDICT HEAD_SHA FINDINGS_JSON — renders
# the one-comment-per-run body: a bold verdict title, then
# _render_review_verdict_lines' shared head_sha/findings/recurring core.
_build_review_verdict_comment_body() {
  _brvcb_verdict="$1"
  _brvcb_head="$2"
  _brvcb_findings="$3"

  _brvcb_body=$(_render_review_verdict_lines "$_brvcb_head" "$_brvcb_findings") || return 1
  printf '**clagentic-lite review verdict: %s**\n\n%s\n' "$_brvcb_verdict" "$_brvcb_body"
}

# _build_ship_pr_body BRANCH HEAD_SHA (lr-429b32) — renders the four-section
# PR body cmd_ship hands to host_adapter_open_change_request, replacing the
# adapter's prior commit-message-scrape default (which produced no review
# provenance at all -- see docs/GATES.md "Ship-time PR body"). Gate-side by
# contract (host-adapter.sh's own doc comment: adapters transport, they
# never render) -- this function knows nothing about which host or CLI ends
# up posting the body it returns.
#
# DEGRADE HONESTLY, not a nicety here -- the acceptance bar (lr-429b32):
# every section this function cannot populate from what the tool actually
# recorded says so in plain words rather than rendering an empty heading or
# implying a check ran that did not. Section 2 (review provenance) is the
# only section with real data behind it -- it reuses
# _ledger_anchored_pass_at_head/ledger_latest_for_branch/
# _render_review_verdict_lines (the SAME lookup cmd_merge_gate and
# _publish_review_verdict already use) rather than re-deriving a verdict.
# Sections 1/3/4 (what-changed, trade-offs, out-of-scope) have no mechanical
# source in this codebase -- no commit-log/diff-summary synthesis exists
# here (by design: AGENTS.md's non-goals list forbids adding one just for
# this) -- so each renders an explicit placeholder naming that gap, never a
# fabricated summary and never a bare empty heading.
_build_ship_pr_body() {
  _bspb_branch="$1"
  _bspb_head="$2"

  _bspb_ledger=$(_review_ledger_path)
  _bspb_review_section=""
  if [ -n "$_bspb_head" ] && { command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; }; then
    _bspb_latest=$(ledger_latest_for_branch "$_bspb_ledger" "$_bspb_branch")
    if [ -n "$_bspb_latest" ]; then
      _bspb_entry_head=""
      _bspb_entry_verdict=""
      _bspb_entry_findings="[]"
      if command -v jq >/dev/null 2>&1; then
        _bspb_entry_head=$(printf '%s' "$_bspb_latest" | jq -r '.head_sha // ""' 2>/dev/null)
        _bspb_entry_verdict=$(printf '%s' "$_bspb_latest" | jq -r '.verdict // ""' 2>/dev/null)
        _bspb_entry_findings=$(printf '%s' "$_bspb_latest" | jq -c '.findings // []' 2>/dev/null)
      elif command -v python3 >/dev/null 2>&1; then
        _bspb_entry_head=$(printf '%s' "$_bspb_latest" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("head_sha",""))
except Exception:
    print("")' 2>/dev/null)
        _bspb_entry_verdict=$(printf '%s' "$_bspb_latest" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("verdict",""))
except Exception:
    print("")' 2>/dev/null)
        _bspb_entry_findings=$(printf '%s' "$_bspb_latest" | python3 -c 'import json,sys
try:
    print(json.dumps(json.load(sys.stdin).get("findings",[])))
except Exception:
    print("[]")' 2>/dev/null)
      fi
      [ -n "$_bspb_entry_findings" ] || _bspb_entry_findings="[]"

      if [ -n "$_bspb_entry_head" ] && [ "$_bspb_entry_head" = "$_bspb_head" ]; then
        # An anchored entry exists at THIS exact head_sha -- the review this
        # section describes actually evaluated the code being shipped, not a
        # stale prior round. Reuse the same rendering core the posted
        # review-verdict comment uses (reuse, not re-derivation).
        _bspb_lines=$(_render_review_verdict_lines "$_bspb_entry_head" "$_bspb_entry_findings" 2>/dev/null)
        if [ -n "$_bspb_lines" ]; then
          _bspb_review_section=$(printf 'verdict: %s\n\n%s\n' "$_bspb_entry_verdict" "$_bspb_lines")
        fi
      else
        # A ledger entry exists for this branch but not at this head_sha --
        # honest reporting requires saying the review is stale relative to
        # what is being shipped, not silently reusing an older verdict.
        _bspb_review_section="reviewer: prior verdict recorded (head \`${_bspb_entry_head:-<unresolved>}\`), but it does not cover this PR's head (\`${_bspb_head:-<unresolved>}\`) -- treat review as not yet run for this head."
      fi
    fi
  fi
  if [ -z "$_bspb_review_section" ]; then
    # No usable ledger entry for this branch at all (never reviewed, no
    # JSON tool available to read the ledger, or ledger absent) -- this is
    # lr-964f7f's motivating failure mode inverted: never imply a review
    # posture the tool cannot back with a recorded verdict.
    _bspb_review_section="reviewer: none -- no recorded review verdict for this branch. Run \`clagentic-lite gates review\` (or \`gates ship\`, which runs it) before merging if cross-vendor review is expected."
  fi

  printf '## What changed and why\n\n'
  printf '_Not recorded by tooling -- clagentic-lite has no commit-log or diff summarizer; fill in by hand before merging._\n\n'
  printf '## Review provenance\n\n%s\n\n' "$_bspb_review_section"
  printf '## Trade-offs taken and rejected\n\n'
  printf '_Not recorded by tooling; fill in by hand, or state "none" if none were seriously considered._\n\n'
  printf '## Explicitly out of scope\n\n'
  printf '_Not recorded by tooling; fill in by hand, or state "none" if the change is fully self-contained._\n'
}

# get_review_diff — prints the best available diff to stdout for use by
# cmd_review and cmd_adversarial.
#
# Priority:
#   1. Staged diff (git diff --cached) — normal pre-commit path.
#   2. Delta re-review (default-on, lr-01ae73; generalizes the former
#      --since-last-review opt-in flag into the default mode): when the
#      current branch has a prior ANCHORED ledger verdict (see "review
#      ledger" above) whose head_sha resolves as an ancestor of HEAD in
#      THIS repo, diff <that head_sha>..HEAD instead of the full
#      origin/<default>..HEAD branch diff. This is the structural fix for
#      the death-spiral (many fix-commits accumulating into an unreviewed
#      diff). --full-review forces full-range regardless of ledger state.
#      A prior head_sha that no longer resolves as an ancestor of HEAD
#      (rebase, amend, force-push) is NOT usable as a delta base — falls
#      through to full-range and says so on stderr (fail toward MORE
#      coverage, matching cmd_sast/cmd_bleed doctrine — see REVIEW_FULL
#      handling below).
#   3. Branch diff against origin/<default_branch> — PR path when index is
#      clean but we are on a feature branch with committed changes.
#   4. Empty — on the default branch with no staged changes; review will see
#      an empty diff (the merge-gate has an explicit null-review rule for this).
#
# Prints one diagnostic line to stderr indicating which mode is active.
#
# REPO SCOPING (lr-da1f28 sweep): every git call below reads repo state
# (staged diff, branch, HEAD) via `_git`, which only changes cwd before
# git's own ancestor-directory repo discovery runs — see
# _git_repo_root_is_scoped's doc comment. If REPO_ROOT is not itself a git
# repo but an ancestor of it is (the wrapper/.clagentic-project layout
# permits exactly this), every one of these calls would silently operate on
# the ancestor repo's staged/branch/diff state instead of REPO_ROOT's —
# feeding the review/adversarial gates a wrong-repo diff rather than merely
# mis-stamping a SHA. Guard the whole function the same way: skip straight
# to the documented "no staged changes" empty-diff fallback when REPO_ROOT
# is not the git repo `_git` would actually resolve to.
get_review_diff() {
  DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"

  if ! _git_repo_root_is_scoped; then
    printf '[gates/review] REPO_ROOT is not a git repo — empty diff\n' 1>&2
    return 0
  fi

  CURRENT_BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")

  if _git diff --cached --name-only 2>/dev/null | grep -q .; then
    printf '[gates/review] using staged diff\n' 1>&2
    _git diff --cached --unified=3 2>/dev/null
    return 0
  fi

  # Delta re-review (default-on, lr-01ae73 — generalizes the former
  # --since-last-review opt-in into the default mode; the flag itself
  # remains accepted as a backward-compatible no-op, since it now names the
  # default behavior rather than a distinct one). REVIEW_FULL=1 (set by
  # cmd_review's --full-review flag parsing) opts back out to full-range.
  #
  # SOURCE OF TRUTH: the review ledger's latest ANCHORED verdict for the
  # current branch (_review_ledger_path / ledger_latest_for_branch,
  # review-merge.sh) — not last-review.json's _clagentic_diff_sha stamp,
  # which only ever remembers the SINGLE most recent run and is overwritten
  # on every call regardless of outcome. The ledger is append-only and
  # verdict-aware, so this reads the same value the "generalize, don't
  # parallel" reuse-seam instruction points at, just from the durable
  # record rather than the single mutable snapshot.
  if [ "${REVIEW_FULL:-0}" != "1" ]; then
    _grd_ledger=$(_review_ledger_path)
    _grd_prior_head=""
    if [ -f "$_grd_ledger" ]; then
      _grd_latest_entry=$(ledger_latest_for_branch "$_grd_ledger" "$CURRENT_BRANCH")
      if [ -n "$_grd_latest_entry" ]; then
        if command -v jq >/dev/null 2>&1; then
          _grd_prior_head=$(printf '%s' "$_grd_latest_entry" | jq -r '.head_sha // ""' 2>/dev/null)
        elif command -v python3 >/dev/null 2>&1; then
          _grd_prior_head=$(printf '%s' "$_grd_latest_entry" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("head_sha",""))
except Exception:
    print("")' 2>/dev/null)
        fi
      fi
    fi

    if [ -n "$_grd_prior_head" ]; then
      # UNRESOLVABLE PRIOR SHA (rebase/amend/force-push): a prior head_sha
      # this repo can no longer parse as a commit, or that is not an
      # ancestor of current HEAD, cannot anchor a delta diff — `git diff
      # A..B` between two unrelated/missing points is not "the delta since
      # the prior verdict," it is either a hard error or a misleading
      # unrelated-history diff. Fail toward MORE coverage: fall through to
      # full-range below and SAY SO, matching cmd_sast/cmd_bleed's own
      # "never silently narrow on a resolution failure" doctrine.
      if _git rev-parse --verify -q "${_grd_prior_head}^{commit}" >/dev/null 2>&1 \
         && _git merge-base --is-ancestor "$_grd_prior_head" HEAD 2>/dev/null; then
        printf '[gates/review] delta re-review: diffing %s..HEAD (prior anchored verdict on this branch)\n' "$_grd_prior_head" 1>&2
        _git diff "${_grd_prior_head}..HEAD" --unified=3 2>/dev/null
        return 0
      else
        printf '[gates/review] delta re-review: prior verdict SHA %s is no longer an ancestor of HEAD (rebase/amend/force-push) — falling back to full-range review\n' "$_grd_prior_head" 1>&2
      fi
    else
      printf '[gates/review] delta re-review: no prior anchored verdict for branch %s — full-range review\n' "${CURRENT_BRANCH:-<none>}" 1>&2
    fi
  fi

  if [ -n "$CURRENT_BRANCH" ] && [ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ] && [ "$CURRENT_BRANCH" != "HEAD" ]; then
    # FRESHNESS IS A PRECONDITION, NOT AN ASSUMPTION (lr-53dc6e, propagating
    # _gate_resolve_fresh_default_branch_ref's already-hardened form, :132-164,
    # to this site). This used to do a bare `git fetch origin ... || true`
    # (non-fatal on the theory that "git diff will simply fall back to local
    # state") followed by a raw `origin/${DEFAULT_BRANCH}` name resolution —
    # exactly the refuted fallacy _gate_resolve_fresh_default_branch_ref's own
    # docstring (:96-131) exists to close: a stale local tracking ref from a
    # PRIOR successful fetch resolves successfully even when THIS fetch fails
    # or times out, silently narrowing the diff this function feeds to BOTH
    # LLM security gates (cmd_review, cmd_adversarial) while producing a
    # normal-looking, plausible diff and verdict.
    #
    # Delegate to the shared provably-current check instead of trusting
    # presence alone. On any failure to prove freshness, fail toward MORE
    # coverage or a hard error — never a silently narrower diff: this
    # function returns non-zero, and under gates.sh's `set -e`, a caller that
    # does not explicitly guard the call (cmd_review, cmd_adversarial both
    # call it unguarded via `get_review_diff > "$tmp"`) aborts the gate
    # rather than proceeding to review a partial diff as if it were complete.
    _grd_fetch_timeout="${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-30}"
    _grd_fetch_timeout=$(ds_positive_int_or_default "$_grd_fetch_timeout" 30)

    _grd_fresh_err_tmp=$(mktemp -t clagentic-review-fresh-err.XXXXXX)
    _grd_fresh_tip=$(_gate_resolve_fresh_default_branch_ref "$DEFAULT_BRANCH" "$_grd_fetch_timeout" 2>"$_grd_fresh_err_tmp") || true
    _grd_fresh_err=$(cat "$_grd_fresh_err_tmp" 2>/dev/null || echo "")
    rm -f "$_grd_fresh_err_tmp"

    if [ -z "$_grd_fresh_tip" ]; then
      printf '[gates/review] branch baseline not provably current (%s) — refusing to produce a possibly-narrowed diff\n' "$_grd_fresh_err" 1>&2
      return 1
    fi

    printf '[gates/review] no staged changes — using branch diff vs verified origin/%s\n' "$DEFAULT_BRANCH" 1>&2
    _git diff "${_grd_fresh_tip}...HEAD" --unified=3 2>/dev/null
    return 0
  fi

  printf '[gates/review] no staged changes and on default branch — empty diff\n' 1>&2
}

# _cross_round_dedup ENVELOPE_FILE DIFF_FILE SEEN_FILE
#
# Reads the findings array from ENVELOPE_FILE, pipes it through dedup_findings
# content-hash (from review-merge.sh) with SEEN_FILE as the persisted key store
# and DIFF_FILE as the context source, splices the deduped findings back into
# ENVELOPE_FILE in place, and logs a gate_runs audit row with the suppression count.
#
# Conservative by design: dedup_findings retains findings when the key cannot be
# computed (no diff window, no sha256 tool) — wrong suppressions are worse than
# missed dedups. Seen-file absent on first call is a no-op (fail-open).
#
# Called only when CLAGENTIC_CROSS_ROUND_DEDUP=1. Not called on degraded envelopes
# (caller checks degraded state after this function returns).
_cross_round_dedup() {
  _crd_envelope="$1"
  _crd_diff="$2"
  _crd_seen="$3"

  # Absent seen-file: no prior keys; dedup_findings will populate it from this run.
  # This is the correct first-run behavior — no-op suppression, but keys are seeded.

  # Snapshot the count before dedup to compute suppression delta.
  _crd_before=0
  if command -v jq >/dev/null 2>&1; then
    _crd_before=$(jq -r '.findings | length // 0' "$_crd_envelope" 2>/dev/null || echo 0)
  elif command -v python3 >/dev/null 2>&1; then
    _crd_before=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get("findings",[])))' \
      "$_crd_envelope" 2>/dev/null || echo 0)
  fi
  case "$_crd_before" in ''|*[!0-9]*) _crd_before=0 ;; esac

  # Extract findings, pipe through dedup_findings, splice result back.
  _crd_raw_findings=$(mktemp -t clagentic-crd-raw.XXXXXX)
  _crd_deduped_findings=$(mktemp -t clagentic-crd-dedup.XXXXXX)
  _crd_ok=0

  if command -v jq >/dev/null 2>&1; then
    jq -c '.findings // []' "$_crd_envelope" > "$_crd_raw_findings" 2>/dev/null && _crd_ok=1
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d.get("findings",[])))' \
      "$_crd_envelope" > "$_crd_raw_findings" 2>/dev/null && _crd_ok=1
  fi

  if [ "$_crd_ok" = "1" ]; then
    # dedup_findings appends new keys to _crd_seen in-place and writes deduped array to stdout.
    dedup_findings "content-hash" "$_crd_seen" "$_crd_diff" \
      < "$_crd_raw_findings" > "$_crd_deduped_findings" 2>/dev/null || _crd_ok=0
  fi

  if [ "$_crd_ok" = "1" ]; then
    # Splice the deduped findings array back into the envelope JSON.
    _crd_tmp=$(mktemp -t clagentic-crd-env.XXXXXX)
    _crd_spliced=0
    if command -v jq >/dev/null 2>&1; then
      _crd_deduped_json=$(cat "$_crd_deduped_findings")
      if jq --argjson df "$_crd_deduped_json" '.findings = $df' "$_crd_envelope" > "$_crd_tmp" 2>/dev/null; then
        mv "$_crd_tmp" "$_crd_envelope"
        _crd_spliced=1
      else
        rm -f "$_crd_tmp"
      fi
    elif command -v python3 >/dev/null 2>&1; then
      if python3 - "$_crd_envelope" "$_crd_deduped_findings" "$_crd_tmp" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as f:
        env = json.load(f)
    with open(sys.argv[2]) as f:
        deduped = json.load(f)
    if not isinstance(deduped, list):
        raise ValueError("not a list")
    env["findings"] = deduped
    with open(sys.argv[3], "w") as f:
        json.dump(env, f)
except Exception:
    sys.exit(1)
PYEOF
      then
        mv "$_crd_tmp" "$_crd_envelope"
        _crd_spliced=1
      else
        rm -f "$_crd_tmp"
      fi
    fi

    if [ "$_crd_spliced" = "1" ]; then
      # Compute suppression count and surface to operator.
      _crd_after=0
      if command -v jq >/dev/null 2>&1; then
        _crd_after=$(jq -r '.findings | length // 0' "$_crd_envelope" 2>/dev/null || echo 0)
      elif command -v python3 >/dev/null 2>&1; then
        _crd_after=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get("findings",[])))' \
          "$_crd_envelope" 2>/dev/null || echo 0)
      fi
      case "$_crd_after" in ''|*[!0-9]*) _crd_after=0 ;; esac
      _crd_suppressed=$((_crd_before - _crd_after))
      [ "$_crd_suppressed" -lt 0 ] && _crd_suppressed=0
      if [ "$_crd_suppressed" -gt 0 ]; then
        printf '[dedup] suppressed %d finding(s) seen in prior run(s)\n' \
          "$_crd_suppressed" 1>&2
      fi
      ds_audit_log "review-dedup" "pass" \
        "suppressed:${_crd_suppressed}/total:${_crd_before}"
    else
      # Conservative: splice failed, retain original findings.
      printf '[gates/review] cross-round dedup: splice failed — retaining all findings (conservative)\n' 1>&2
      cmd_log_run review warn "cross-round dedup: splice failed; original findings retained"
    fi
  else
    # Conservative: extraction or dedup failed, retain original findings.
    printf '[gates/review] cross-round dedup: key computation failed — retaining all findings (conservative)\n' 1>&2
    cmd_log_run review warn "cross-round dedup: key computation failed; original findings retained"
  fi

  rm -f "$_crd_raw_findings" "$_crd_deduped_findings"
}

# _review_recurrence_threshold — round count at which a recurring finding is
# demoted from blocking to advisory. Configurable via
# CLAGENTIC_RECURRENCE_THRESHOLD (default 2 — "reported in a prior round AND
# reported again" is what "recurs" means; a finding seen for the first time
# is never demotable no matter how confident the model is). Same
# integer-guard pattern as _invariant_feed_max_lines.
_review_recurrence_threshold() {
  _rrt_n="${CLAGENTIC_RECURRENCE_THRESHOLD:-2}"
  case "$_rrt_n" in ''|*[!0-9]*) _rrt_n=2 ;; esac
  # A threshold of 0 or 1 would demote a finding on its FIRST report ever,
  # which is not "recurs" by any reading of the task -- floor at 2 so the
  # configured value can only ever raise the bar for demotion, never make a
  # brand-new finding demotable.
  [ "$_rrt_n" -lt 2 ] && _rrt_n=2
  printf '%s' "$_rrt_n"
}

# _review_recurrence_demote ENVELOPE_FILE DIFF_FILE COUNTS_FILE
#
# Third pass over ENVELOPE_FILE's findings, run AFTER _cross_round_dedup: for
# every finding that SURVIVED dedup (i.e. is still in .findings — a finding
# dedup suppressed was never reported this round and cannot recur by
# definition), compute its content-hash key (finding_content_keys,
# review-merge.sh — the SAME key space _cross_round_dedup/dedup_findings
# already persists in SEEN_FILE, applied here to a SEPARATE counts file so
# recurrence tracking never mutates dedup's own seen-keys semantics) and bump
# its persisted round-count (finding_recurrence_bump, review-merge.sh).
#
# THRESHOLD SEMANTICS: "recurs" means this finding has now been reported in
# at least _review_recurrence_threshold DISTINCT rounds, counting this one --
# a finding on its first-ever reported round always has count 1 and is never
# demotable. When count >= threshold, the finding's SEVERITY IS NEVER
# TOUCHED (docs/GATES.md "wrong suppressions are worse than missed dedups"
# — the same posture forbids silently rewriting a finding's own reported
# severity). Instead two fields are added to the finding object:
#   _recurrence_count    — integer, rounds this key has been reported in
#   _recurrence_demoted  — boolean, true when count >= threshold
# severity_blockers() (this file) excludes _recurrence_demoted findings from
# its block count — this is the mechanism that makes demotion a THRESHOLD
# change, not suppression: the finding stays in .findings, fully visible in
# cmd_render_review's output and in the audit trail, with its honest severity
# unchanged; only its eligibility to gate /ship is affected.
#
# SECURITY-FLOOR INTERACTION: this function has no notion of a security floor
# on its own — review findings do not carry reachable/tier fields (those are
# adversarial-pass concepts, Gate 5). The floor this repo actually enforces
# for review findings is severity_blockers()'s threshold comparison itself:
# a review finding blocks solely because its severity rank meets
# CLAGENTIC_BLOCK_SEVERITY. Demotion here can exempt a recurring finding from
# THAT count, same as it does for any other review finding — there is no
# separate reachable/tier-based floor to bypass on this path (that floor only
# exists on the adversarial parser, _parse_adversarial_findings, which this
# function does not touch and which is NOT wired into _review_recurrence_demote
# at all). See the test suite for an explicit adversarial-floor-is-never-
# demotable regression case covering the gate that DOES have a floor.
#
# CONSERVATIVE BIAS (mirrors _cross_round_dedup exactly, per task constraint
# (d)): a finding whose key cannot be computed (empty key, no diff window, no
# sha256 tool) is retained AND left un-demoted (finding_recurrence_bump gives
# it a fresh count of 1, never eligible). Extraction or splice failure at any
# step leaves the original findings untouched, un-annotated, un-demoted —
# same fail-open direction as _cross_round_dedup's own failure paths. No JSON
# tool at all is a full passthrough — ENVELOPE_FILE is left byte-identical.
#
# SECURITY PRECONDITION (lr-66e598 follow-up, BOBBIE-caught): this function
# ASSUMES ENVELOPE_FILE's findings have already been reduced to the closed
# review-finding schema by _sanitize_review_findings_envelope (this file),
# which every caller runs immediately after the raw LLM write and before
# this function ever sees the file. Before that fix existed, a finding whose
# triple did NOT match a row in this round's bumped TSV was `continue`d over
# UNTOUCHED below -- so a model that emitted _recurrence_demoted:true in its
# OWN raw JSON response had that self-forged value survive verbatim, and a
# first-ever-reported finding could self-exempt from blocking with zero
# actual repetition. The splice below now explicitly OWNS the field for
# every finding it processes (sets a definite _recurrence_count/
# _recurrence_demoted even on the unmatched branch) as a second, independent
# layer -- but the real closure point is the upstream ingest strip; this
# function's own defense-in-depth does not substitute for it, since a
# forged field on a MATCHED finding would still need the ingest strip to
# have never let non-schema fields (or a spoofed value this splice
# overwrites correctly, by coincidence, only on the matched path) reach this
# function's other, non-recurrence-related reads of the object in the first
# place.
_review_recurrence_demote() {
  _rrd_envelope="$1"
  _rrd_diff="$2"
  _rrd_counts="$3"

  if ! command -v python3 >/dev/null 2>&1; then
    # The splice step (matching bumped TSV rows back to finding objects and
    # rewriting the array) needs a real JSON encoder/decoder pair operating
    # on the same data structure; python3 is used for that regardless of
    # whether jq is also present (only jq's FINAL `.findings = $nf` merge
    # differs between the two branches below). No python3 at all — full
    # passthrough, matching dedup_findings' own posture on missing tools.
    return 0
  fi

  _rrd_threshold=$(_review_recurrence_threshold)

  _rrd_findings=$(_extract_findings_json "$_rrd_envelope")
  [ -n "$_rrd_findings" ] || _rrd_findings='[]'

  # Compute content-hash keys for this round's SURVIVING findings and bump
  # their persisted round-counts. finding_content_keys emits one TSV row
  # PER FINDING WITH A COMPUTABLE KEY ONLY (uncomputable-key findings are
  # silently omitted from its output by design — see its own doc comment) —
  # so downstream matching is done BY VALUE (file/category/message), never
  # by array position, which would misalign the moment any finding in this
  # round lacks a computable key.
  _rrd_keyed_tsv=$(mktemp -t clagentic-rrd-keyed.XXXXXX)
  printf '%s' "$_rrd_findings" | finding_content_keys "$_rrd_diff" > "$_rrd_keyed_tsv" 2>/dev/null

  if [ ! -s "$_rrd_keyed_tsv" ]; then
    # No finding in this round had a computable key (empty diff window, no
    # sha256 tool, or genuinely zero findings) — nothing to bump or demote.
    # Conservative: leave ENVELOPE_FILE untouched.
    rm -f "$_rrd_keyed_tsv"
    return 0
  fi

  _rrd_bumped_tsv=$(mktemp -t clagentic-rrd-bumped.XXXXXX)
  finding_recurrence_bump "$_rrd_counts" < "$_rrd_keyed_tsv" > "$_rrd_bumped_tsv" 2>/dev/null
  rm -f "$_rrd_keyed_tsv"

  if [ ! -s "$_rrd_bumped_tsv" ]; then
    rm -f "$_rrd_bumped_tsv"
    return 0
  fi

  # Splice _recurrence_count/_recurrence_demoted into every finding matched
  # BY VALUE (file/category/message triple) against the bumped TSV — the
  # content-hash key itself has no independent meaning to a splice step
  # outside review-merge.sh's own derivation, and a finding object does not
  # carry its own key, so matching on the triple that identifies a finding
  # row in finding_content_keys' TSV output is the natural join key here. A
  # genuine triple collision between two DISTINCT findings in the same round
  # would only ever mis-share a recurrence count between them — no worse
  # than dedup_findings' own "location" strategy already treats an identical
  # file/line/category/message as one finding by design.
  #
  # Emits the demoted-count on its own final line (stdout) so the caller can
  # log it to the audit trail without a second read of ENVELOPE_FILE — this
  # is the ONLY output contract of the python step; the spliced findings
  # array is written directly to a temp file, not printed, so the two
  # results never interleave on one stream.
  _rrd_spliced_file=$(mktemp -t clagentic-rrd-spliced.XXXXXX)
  _rrd_demoted_count=$(python3 - "$_rrd_findings" "$_rrd_bumped_tsv" "$_rrd_threshold" "$_rrd_spliced_file" <<'PYEOF'
import json, sys

findings_json, tsv_path, threshold, out_path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

try:
    findings = json.loads(findings_json)
    if not isinstance(findings, list):
        raise ValueError("not a list")
except Exception:
    print(0)
    sys.exit(0)

counts_by_triple = {}
try:
    with open(tsv_path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            fname, category, message, count_s = parts[1], parts[2], parts[3], parts[4]
            try:
                count = int(count_s)
            except ValueError:
                continue
            counts_by_triple[(fname, category, message)] = count
except Exception:
    print(0)
    sys.exit(0)

demoted = 0
for f in findings:
    if not isinstance(f, dict):
        continue
    # OWN THE FIELD, DO NOT MERELY OVERWRITE-ON-MATCH (BOBBIE, lr-66e598
    # follow-up): every finding this loop touches gets an EXPLICIT,
    # definite _recurrence_demoted/_recurrence_count this function itself
    # decided -- never a value left over from whatever the object already
    # carried (in-band ingest is stripped upstream by
    # _sanitize_review_findings_envelope, but this is the second,
    # independent layer: even if that upstream strip were ever bypassed,
    # skipped, or a future refactor moved this call before it, an
    # unmatched finding still gets a definite False here, not a `continue`
    # that leaves whatever pre-existing value untouched).
    triple = (str(f.get("file", "")), str(f.get("category", "")), str(f.get("message", "")))
    count = counts_by_triple.get(triple)
    if count is None:
        f["_recurrence_count"] = 0
        f["_recurrence_demoted"] = False
        continue
    f["_recurrence_count"] = count
    f["_recurrence_demoted"] = bool(count >= threshold)
    if count >= threshold:
        demoted += 1

try:
    with open(out_path, "w") as f:
        json.dump(findings, f)
except Exception:
    print(0)
    sys.exit(0)

print(demoted)
PYEOF
)
  case "$_rrd_demoted_count" in ''|*[!0-9]*) _rrd_demoted_count=0 ;; esac

  if [ -s "$_rrd_spliced_file" ]; then
    if command -v jq >/dev/null 2>&1; then
      _rrd_tmp=$(mktemp -t clagentic-rrd-env.XXXXXX)
      if jq --slurpfile nf "$_rrd_spliced_file" '.findings = $nf[0]' "$_rrd_envelope" > "$_rrd_tmp" 2>/dev/null; then
        mv "$_rrd_tmp" "$_rrd_envelope"
      else
        rm -f "$_rrd_tmp"
      fi
    else
      # No jq: python3-only merge-back, same "read envelope, replace
      # .findings, write back" shape as the jq branch above.
      _rrd_tmp=$(mktemp -t clagentic-rrd-env.XXXXXX)
      if python3 - "$_rrd_envelope" "$_rrd_spliced_file" "$_rrd_tmp" <<'PYEOF2' 2>/dev/null
import json, sys
env_path, spliced_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(env_path) as f:
        env = json.load(f)
    with open(spliced_path) as f:
        spliced = json.load(f)
    if not isinstance(spliced, list):
        raise ValueError("not a list")
    env["findings"] = spliced
    with open(out_path, "w") as f:
        json.dump(env, f)
except Exception:
    sys.exit(1)
PYEOF2
      then
        mv "$_rrd_tmp" "$_rrd_envelope"
      else
        rm -f "$_rrd_tmp"
      fi
    fi
  fi

  if [ "$_rrd_demoted_count" -gt 0 ]; then
    printf '[recurrence] %d finding(s) demoted to advisory (reported >= %d rounds running)\n' \
      "$_rrd_demoted_count" "$_rrd_threshold" 1>&2
  fi
  ds_audit_log "review-recurrence" "pass" \
    "demoted:${_rrd_demoted_count} threshold:${_rrd_threshold}"

  rm -f "$_rrd_bumped_tsv" "$_rrd_spliced_file"
  return 0
}

# _review_deferral_match ENVELOPE_FILE (lr-2ebc41)
#
# WHY THIS EXISTS: lr-c567 shipped .clagentic/deferrals.json and injected it
# into the Reviewer's prompt as context to weigh — suppression was left
# entirely inside model judgment (docs/GATES.md "Suppression is inside model
# judgment, not gate code"). Field evidence (lr-2ebc41 task description):
# a single stage-contract finding, accepted with a stable documented
# rationale, was re-raised by the stateless Reviewer SIX times across a
# 7-round run because nothing MECHANICALLY excluded it once accepted — the
# Reviewer was merely asked to honor the deferral, not required to. This
# function is the gate-code enforcement half: a finding whose (file,
# category, message) triple matches a deferral entry AND whose named file's
# content is byte-identical to the file's content when the deferral was
# granted is annotated _deferral_matched: true / _deferral_id so
# severity_blockers() (below) can exclude it from the block count — same
# THRESHOLD-NOT-SUPPRESSION posture _recurrence_demoted already established
# (lr-66e598): the finding stays fully visible in .findings, in
# cmd_render_review's output, and in the audit trail with its honest
# severity untouched. The gate does NOT drop rows or rewrite severity; it
# only changes eligibility to block /ship. This deliberately reverses
# lr-c567's "not in gate plumbing" call — see docs/GATES.md "Reviewer-
# consulted deferrals" for the reversal rationale.
#
# MATCH KEY (the hard design question, lr-2ebc41 comment 1). Deliberately
# NOT finding_content_keys' sha256-of-a-+-2-line-diff-window key
# (review-merge.sh) — that key is exactly why this problem exists: it is
# computed from SURROUNDING lines, so incidental edits nearby (a comment
# added two lines up, a reflow) change the key and silently break the
# match. The key here is the (file, category, message) triple instead —
# the SAME triple _review_recurrence_demote already uses to join a bumped
# TSV row back to a finding object (see its own doc comment above) — because
# that triple is exactly what the model re-emits when it re-derives the
# SAME observation about the SAME code: it is insensitive to line-number
# drift by construction (it does not mention a line number at all), which
# is the "survive incidental edits around the finding" property this task
# requires. What it deliberately does NOT distinguish: two findings in
# different files that happen to share category+message (extremely
# unlikely for anything but a boilerplate lint rule, and even then the
# `file` component of the triple still disambiguates); a finding whose
# MESSAGE TEXT itself changes between rounds is a NEW finding, not a
# re-raise, and correctly fails to match — this key does not attempt fuzzy/
# semantic sameness (explicitly out of scope, task description).
#
# LAPSE (the other half of the hard design question, comment 2 and comment
# 3). A (file, category, message) triple alone is stable enough to survive
# incidental edits but is NOT sensitive to the deferred logic changing —
# comment 2's field evidence is a deferral granted against round-3 behavior
# that would still match round-6 behavior in the same file if line-window-
# insensitivity were the ONLY property enforced. So capture (see
# .clagentic/deferrals.json's new required `file_sha256` field,
# scripts/llm-client.sh) pins the sha256 of the NAMED FILE's full content at
# grant time, and matching here recomputes that same hash and requires an
# EXACT match. Any edit anywhere in that file — not just near the finding —
# lapses the deferral back to blocking. This correctly handles a :466-class
# stable-contract acceptance (comment 3): the deferral's own validity
# depends only on its own file's content, so a hash of that file is a sound
# dependency signal.
#
# WHAT THIS DELIBERATELY DOES NOT SUPPORT (comment 3, outcome (b), blessed
# by the task as a legitimate outcome rather than a failure): a deferral
# whose validity depends on code in a DIFFERENT file or region than the one
# it's filed against (comment 3's :139 case — a scope-boundary acceptance
# whose truth depends on reset logic living elsewhere in a different file)
# is NOT SUPPORTED by a single-file content hash — that dependency is
# invisible to this mechanism by construction, since the named file's own
# bytes can stay identical while the true dependency changes. This is a
# DELIBERATE, DOCUMENTED restriction to the stable-contract class, not an
# oversight: capture-time guidance (llm-client.sh's deferral schema comment,
# docs/GATES.md, plugins/clagentic-lite/agents/builder.md) instructs the
# capturing agent to REFUSE to write a deferral entry whose rationale
# depends on anything outside the named file, loudly, at capture time,
# rather than writing one this function would silently mis-honor. There is
# no mechanical enforcement of that refusal (the shell has no way to verify
# an English rationale is self-contained) — this is a documented boundary
# of the feature's shape, not a false completeness claim.
#
# FAIL-CLOSED (the property that matters most, per the task). Any of the
# following causes a finding to be retained as blocking, exactly as if no
# deferral existed: deferrals.json absent/empty/malformed; a deferral entry
# missing `file_sha256`, `scope`, `id`, `file`, or `message`; a deferral
# entry whose `scope` is anything other than the literal string
# "stable-contract" (only supported value — see capture-side validation);
# the named file missing on disk; no sha256 tool available; more than one
# LIVE (hash-matching) deferral entry claiming the same finding (ambiguous
# match — "preserve when uncertain" per docs/GATES.md "wrong suppressions
# are worse than missed dedups"; the task's own restated principle). No
# JSON tool at all is a full passthrough — ENVELOPE_FILE is left untouched,
# matching every other splice step in this file's fail-open-on-tooling,
# fail-closed-on-ambiguity posture.
_review_deferral_match() {
  _rdm_envelope="$1"

  if ! command -v python3 >/dev/null 2>&1; then
    # Splicing _deferral_matched/_deferral_id into finding objects needs a
    # real JSON encoder/decoder, matching _review_recurrence_demote's own
    # python3-only posture. No python3 — full passthrough.
    return 0
  fi

  _rdm_dfile="$REPO_ROOT/.clagentic/deferrals.json"
  [ -f "$_rdm_dfile" ] || return 0

  _rdm_deferrals=$(cat "$_rdm_dfile" 2>/dev/null) || return 0
  [ -n "$_rdm_deferrals" ] || return 0

  _rdm_findings=$(_extract_findings_json "$_rdm_envelope")
  [ -n "$_rdm_findings" ] || return 0

  # Build one TSV row per LIVE deferral entry: id<TAB>file<TAB>category<TAB>message
  # A deferral is LIVE only when file_sha256 matches the named file's
  # CURRENT on-disk content hash — computed here, in shell, via the same
  # _rm_sha256 shim finding_content_keys uses (review-merge.sh; gates.sh
  # sources that file, so the shim is already in scope). A file that no
  # longer exists, or whose hash cannot be computed, yields no row for that
  # entry (fail-closed: absent row means no match is possible for it).
  _rdm_live_tsv=$(mktemp -t clagentic-rdm-live.XXXXXX)
  _rdm_ids=$(python3 -c '
import json, sys
try:
    d = json.loads(sys.argv[1])
    if not isinstance(d, list):
        raise ValueError
except Exception:
    sys.exit(0)
for e in d:
    if not isinstance(e, dict):
        continue
    eid = e.get("id")
    scope = e.get("scope")
    fname = e.get("file")
    fsha = e.get("file_sha256")
    category = e.get("category", "")
    message = e.get("message")
    # Fail-closed schema check: id/scope/file/file_sha256/message are all
    # required for a deferral to be eligible for MECHANICAL matching (the
    # original six lr-c567 fields — category/description/expires/
    # acknowledged_by — remain valid for the prompt-side path regardless;
    # this is an ADDITIONAL, stricter gate for the gate-code path only). A
    # deferral missing any of these is still injected into the prompt for
    # the model to weigh (unchanged lr-c567 behavior) but is never
    # mechanically matched here.
    if not (isinstance(eid, str) and eid
            and isinstance(fname, str) and fname
            and isinstance(fsha, str) and fsha
            and isinstance(message, str) and message
            and scope == "stable-contract"):
        continue
    print("\t".join([eid, fname, str(category), message, fsha]))
' "$_rdm_deferrals" 2>/dev/null)

  if [ -z "$_rdm_ids" ]; then
    rm -f "$_rdm_live_tsv"
    return 0
  fi

  printf '%s\n' "$_rdm_ids" | while IFS="$(printf '\t')" read -r _rdm_id _rdm_file _rdm_cat _rdm_msg _rdm_want_sha; do
    [ -n "$_rdm_id" ] || continue
    _rdm_target="$REPO_ROOT/$_rdm_file"
    [ -f "$_rdm_target" ] || continue
    _rdm_actual_sha=$(_rm_sha256 < "$_rdm_target" 2>/dev/null)
    [ -n "$_rdm_actual_sha" ] || continue
    if [ "$_rdm_actual_sha" = "$_rdm_want_sha" ]; then
      printf '%s\t%s\t%s\t%s\n' "$_rdm_id" "$_rdm_file" "$_rdm_cat" "$_rdm_msg" >> "$_rdm_live_tsv"
    fi
  done

  if [ ! -s "$_rdm_live_tsv" ]; then
    rm -f "$_rdm_live_tsv"
    return 0
  fi

  # Splice: for every finding whose (file, category, message) triple
  # matches EXACTLY ONE live deferral row, set _deferral_matched: true and
  # _deferral_id: <id>. A triple matching MORE THAN ONE live row is
  # AMBIGUOUS and is left unmatched — fail-closed, per "preserve when
  # uncertain": two deferral entries independently claiming the same
  # finding is a data-quality problem in deferrals.json, not something this
  # function should silently resolve by picking one. OWN THE FIELD for
  # every finding this loop touches (explicit False on no/ambiguous match),
  # mirroring _review_recurrence_demote's own "overwrite-on-match is not
  # own-the-field" discipline (lr-66e598 follow-up) — never leave whatever
  # the object already carried untouched.
  _rdm_spliced=$(mktemp -t clagentic-rdm-spliced.XXXXXX)
  _rdm_matched_count=$(python3 - "$_rdm_findings" "$_rdm_live_tsv" "$_rdm_spliced" <<'PYEOF'
import json, sys

findings_json, tsv_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    findings = json.loads(findings_json)
    if not isinstance(findings, list):
        raise ValueError("not a list")
except Exception:
    print(0)
    sys.exit(0)

# triple -> list of ids (collect ALL matches per triple so a triple with
# more than one live row is detectable and treated as ambiguous below).
ids_by_triple = {}
try:
    with open(tsv_path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            did, fname, category, message = parts[0], parts[1], parts[2], parts[3]
            ids_by_triple.setdefault((fname, category, message), []).append(did)
except Exception:
    print(0)
    sys.exit(0)

matched = 0
for f in findings:
    if not isinstance(f, dict):
        continue
    triple = (str(f.get("file", "")), str(f.get("category", "")), str(f.get("message", "")))
    candidates = ids_by_triple.get(triple, [])
    if len(candidates) == 1:
        f["_deferral_matched"] = True
        f["_deferral_id"] = candidates[0]
        matched += 1
    else:
        # Zero matches, or more than one (ambiguous) -- fail closed either
        # way: explicit False, no id field, finding stays blocking-eligible.
        f["_deferral_matched"] = False

try:
    with open(out_path, "w") as f:
        json.dump(findings, f)
except Exception:
    print(0)
    sys.exit(0)

print(matched)
PYEOF
)
  case "$_rdm_matched_count" in ''|*[!0-9]*) _rdm_matched_count=0 ;; esac

  if [ -s "$_rdm_spliced" ]; then
    if command -v jq >/dev/null 2>&1; then
      _rdm_tmp=$(mktemp -t clagentic-rdm-env.XXXXXX)
      if jq --slurpfile nf "$_rdm_spliced" '.findings = $nf[0]' "$_rdm_envelope" > "$_rdm_tmp" 2>/dev/null; then
        mv "$_rdm_tmp" "$_rdm_envelope"
      else
        rm -f "$_rdm_tmp"
      fi
    else
      _rdm_tmp=$(mktemp -t clagentic-rdm-env.XXXXXX)
      if python3 - "$_rdm_envelope" "$_rdm_spliced" "$_rdm_tmp" <<'PYEOF2' 2>/dev/null
import json, sys
env_path, spliced_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(env_path) as f:
        env = json.load(f)
    with open(spliced_path) as f:
        spliced = json.load(f)
    if not isinstance(spliced, list):
        raise ValueError("not a list")
    env["findings"] = spliced
    with open(out_path, "w") as f:
        json.dump(env, f)
except Exception:
    sys.exit(1)
PYEOF2
      then
        mv "$_rdm_tmp" "$_rdm_envelope"
      else
        rm -f "$_rdm_tmp"
      fi
    fi
  fi

  if [ "$_rdm_matched_count" -gt 0 ]; then
    printf '[deferral] %d finding(s) matched a live operator deferral (threshold, not suppression — see clagentic-lite render-review)\n' \
      "$_rdm_matched_count" 1>&2
  fi
  ds_audit_log "review-deferral-match" "pass" \
    "matched:${_rdm_matched_count}"

  rm -f "$_rdm_live_tsv" "$_rdm_spliced"
  return 0
}

# _extract_findings_json FILE — print FILE's .findings array (or "[]" on any
# failure). jq-then-python3 fallback, matching the pattern used throughout
# this file (e.g. _cross_round_dedup's own findings extraction) rather than
# introducing a third way to read the same shape.
#
# NOT a validation point: this is a pure read, matching every caller's
# expectation that FILE has already been sanitized by
# _sanitize_review_findings_envelope (below) BEFORE any of them ever see it.
_extract_findings_json() {
  _efj_file="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -c '.findings // []' "$_efj_file" 2>/dev/null || printf '[]'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d.get("findings",[])))' \
      "$_efj_file" 2>/dev/null || printf '[]'
  else
    printf '[]'
  fi
}

# _sanitize_review_findings_envelope FILE
#
# SECURITY (lr-66e598 follow-up, BOBBIE-caught). Reduces FILE's .findings
# array in place to EXACTLY the closed review-finding schema
# (ds_review_prompt, llm-client.sh: severity/file/line/category/message/
# evidence/suggestion) via _llm_json_array_allowlist_fields
# (scripts/platform.sh), DROPPING every other key -- including, critically,
# any `_recurrence_demoted` / `_recurrence_count` (or any other future
# internal `_`-prefixed control field) the MODEL ITSELF may have emitted in
# its raw JSON response.
#
# WHY THIS EXISTS: last-review.json is written directly from LLM output
# (llm-client.sh's `review` role) with no field allowlist anywhere on that
# write path -- validate_output (llm-client.sh) checks only that .findings
# is an array and that .severity, if present, is a legal enum value. Nothing
# stopped a model (compromised, manipulated by attacker-influenced code
# under review, or simply miscalibrated) from emitting
# {"severity":"critical", ..., "_recurrence_demoted": true} in its
# structured JSON on the FIRST-EVER round. Before this fix,
# _review_recurrence_demote's splice step only OVERWRITES
# _recurrence_demoted/_recurrence_count on a finding whose (file,category,
# message) triple matches a row in this round's bumped TSV (i.e. whose line
# falls inside finding_content_keys' diff-context window); a finding whose
# triple does NOT match is `continue`d over UNTOUCHED (see
# _review_recurrence_demote), so a self-forged _recurrence_demoted:true
# survived verbatim into last-review.json and severity_blockers (which reads
# ._recurrence_demoted with no provenance check) excluded it from the block
# count -- a first-ever-reported finding could self-exempt from blocking
# with zero actual repetition. Overwrite-on-match is not the same as
# owning the field.
#
# THE FIX IS AT INGEST, THE SAME CHOKE-POINT PATTERN THIS CODEBASE ALREADY
# USES: _sanitize_adversarial_findings_json sanitizes immediately after
# _parse_adversarial_findings and before the sidecar is EVER written to
# disk (docs/GATES.md "Round-trip sanitization"); ds_review_prompt
# allowlists deferrals.json before it is EVER interpolated into a prompt.
# This function is the equivalent choke point for review findings: it MUST
# run immediately after every raw LLM write to an envelope file (both the
# single-pass path and each per-chunk envelope in the chunked path, BEFORE
# merge_envelopes ever unions them -- merge_envelopes/dedup_findings are
# pure concatenation/dedup with no field validation of their own, so an
# unsanitized chunk would carry a forged field through the merge
# untouched), and BEFORE _cross_round_dedup, _review_recurrence_demote,
# severity_blockers, or cmd_render_review ever read the file. Once this
# runs, there is no field left on any finding object for
# _review_recurrence_demote or severity_blockers to trust-by-accident --
# the ONLY way _recurrence_demoted/_recurrence_count can exist on a finding
# from this point forward is if THIS repo's own code (the recurrence
# splice) put it there this round.
#
# NUMERIC `line` FIELD: _llm_json_array_allowlist_fields' base contract
# keeps only STRING-valued fields (safe for deferrals.json, an all-string
# schema) -- review findings legitimately define `line` as a JSON number
# (ds_review_prompt). Rather than write a second, parallel stripper for
# this one schema (which would violate "reuse the existing allowlist
# helper, do not grow a parallel one" the same way _llm_json_array_
# sanitize_fields' own docstring warns against), _llm_json_array_
# allowlist_fields was widened to accept a "fieldname:number" suffix that
# ALSO permits a plain JSON number under that one key (still dropping an
# object/array/bool/null there, never coercing) -- see that function's
# updated docstring in platform.sh for the exact contract and why bool is
# explicitly excluded from the numeric-accepted branch.
#
# CONSERVATIVE BIAS, matching every other on-disk-envelope helper in this
# file: if FILE is missing, unparseable, has no .findings array, or
# _llm_json_array_allowlist_fields' own fail-open path is hit (no jq/
# python3), the function makes NO changes and returns 0 -- a strip failure
# must never turn into "findings vanish" (that would be an over-suppression,
# the exact failure direction docs/GATES.md:150 forbids) or "findings block
# on a synthetic error" (severity_blockers' own sentinel-99 path already
# owns fail-closed for genuinely unparseable JSON; this function's job is
# narrower than that and must not duplicate or fight it).
#
# ISSUE_CLASS / CLASS_FIX (lr-3eb18c): two additional string fields, same
# bare-name (string-only) allowlist shape as the original five -- every
# finding must name the recurring issue class it belongs to and, if any,
# the structural fix that eliminates the class (see ds_review_prompt,
# scripts/llm-client.sh). validate_output enforces PRESENCE (a review
# missing either field is malformed and the step fails); this allowlist
# only prevents a model from smuggling an unrelated field under either
# name. Neither field is read by severity_blockers -- see that function's
# own comment for why this stays mandatory-but-non-blocking by construction.
_sanitize_review_findings_envelope() {
  _srfe_file="$1"
  [ -f "$_srfe_file" ] || return 0

  _srfe_findings=$(_extract_findings_json "$_srfe_file")
  [ -n "$_srfe_findings" ] || return 0

  _srfe_clean=$(_llm_json_array_allowlist_fields "$_srfe_findings" \
    severity file "line:number" category message evidence suggestion \
    issue_class class_fix)
  [ -n "$_srfe_clean" ] || return 0

  if command -v jq >/dev/null 2>&1; then
    _srfe_tmp=$(mktemp -t clagentic-srfe-env.XXXXXX)
    if jq --argjson nf "$_srfe_clean" '.findings = $nf' "$_srfe_file" > "$_srfe_tmp" 2>/dev/null; then
      mv "$_srfe_tmp" "$_srfe_file"
    else
      rm -f "$_srfe_tmp"
    fi
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$_srfe_file" "$_srfe_clean" <<'PYEOF' 2>/dev/null
import json, sys
env_path, clean_json = sys.argv[1], sys.argv[2]
try:
    with open(env_path) as f:
        env = json.load(f)
    clean = json.loads(clean_json)
    if not isinstance(clean, list):
        raise ValueError("not a list")
    env["findings"] = clean
    with open(env_path, "w") as f:
        json.dump(env, f)
except Exception:
    sys.exit(1)
PYEOF
  fi
  return 0
}

# _invariant_feed_max_lines — line cap on invariants.json entries. Guards
# against unbounded growth: the invariant-feed exists to CATCH unbounded-growth
# findings, so its own storage must not be the thing that grows without bound.
# Configurable via CLAGENTIC_INVARIANT_FEED_MAX (default 200 — generous for a
# single branch's review lifetime; oldest entries are dropped first on cap).
_invariant_feed_max_lines() {
  _ifml_max="${CLAGENTIC_INVARIANT_FEED_MAX:-200}"
  case "$_ifml_max" in ''|*[!0-9]*) _ifml_max=200 ;; esac
  printf '%s' "$_ifml_max"
}

# _invariant_feed_max_field_chars and _llm_field_sanitize moved to
# platform.sh (lr-4f8316 follow-up): llm-client.sh needed to sanitize a
# THIRD round-trip field (the change-class commit-message hint) and could
# not reach this sanitizer because llm-client.sh does not source gates.sh —
# the omission that shipped the un-sanitized hint was structurally forced,
# not an oversight at the call site. platform.sh is the one file both
# gates.sh and llm-client.sh already source, so it is the shared home for
# any sanitizer that must be reachable from both prompt-construction paths.
# See platform.sh for the full function bodies and rationale; both are
# available here unchanged (gates.sh sources platform.sh at the top of the
# file, before any function body in this file runs).

# _invariant_feed_append INVARIANTS_FILE ID CATEGORY FILE STATEMENT
#
# Appends one invariant object to INVARIANTS_FILE (creating a fresh JSON array
# if the file is absent/empty/unparseable — same fail-open posture as the
# rest of the invariant-feed). Dedupes on (file, statement): re-resolving the
# same finding class in a later round does not grow the file. Caps the total
# entry count at _invariant_feed_max_lines by dropping the oldest entries —
# the feature that exists to catch unbounded-growth findings must not itself
# grow unboundedly.
#
# SECURITY (lr-cda4b9): category/srcfile/statement all ultimately trace back
# to adversarial-LLM-controlled or review-LLM-controlled finding text (a
# compromised/manipulated model, or attacker-influenced code under audit that
# steers model output, could plant a finding whose message is a prompt-
# injection payload). This is the sole writer of invariants.json, so every
# field is run through _llm_field_sanitize before it is ever written — a
# single write-boundary choke point rather than relying on every current and
# future reader to sanitize on its own. (lr-e2b975 generalized this function
# — was _invariant_feed_sanitize_field — to a second call site: the
# adversarial-findings sidecar build_gate_summary feeds into the merge-gate
# prompt has the identical round-trip shape, so it reuses the same
# choke point rather than growing a parallel sanitizer.)
_invariant_feed_append() {
  _ifa_file="$1"; _ifa_id="$2"; _ifa_category="$3"; _ifa_srcfile="$4"; _ifa_statement="$5"

  _ifa_category=$(_llm_field_sanitize "$_ifa_category")
  _ifa_srcfile=$(_llm_field_sanitize "$_ifa_srcfile")
  _ifa_statement=$(_llm_field_sanitize "$_ifa_statement")

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$_ifa_file" "$_ifa_id" "$_ifa_category" "$_ifa_srcfile" "$_ifa_statement" "$(_invariant_feed_max_lines)" <<'PYEOF'
import json, sys

path, new_id, category, srcfile, statement, max_n = sys.argv[1:7]
max_n = int(max_n)

try:
    with open(path) as f:
        invariants = json.load(f)
    if not isinstance(invariants, list):
        invariants = []
except Exception:
    invariants = []

# Dedupe on (file, statement) — the same resolved-finding class re-appearing
# in a later round (e.g. resolved again after a partial regression) must not
# duplicate the entry.
for existing in invariants:
    if existing.get("file") == srcfile and existing.get("statement") == statement:
        sys.exit(0)  # already present — no-op, no growth

invariants.append({
    "id": new_id,
    "category": category,
    "file": srcfile,
    "statement": statement,
})

# Cap: drop oldest entries first (list is append-ordered).
if len(invariants) > max_n:
    invariants = invariants[-max_n:]

with open(path, "w") as f:
    json.dump(invariants, f, indent=2)
    f.write("\n")
PYEOF
    return $?
  elif command -v jq >/dev/null 2>&1; then
    _ifa_tmp=$(mktemp -t clagentic-inv-append.XXXXXX)
    _ifa_current='[]'
    if [ -f "$_ifa_file" ] && jq -e '. | type == "array"' "$_ifa_file" >/dev/null 2>&1; then
      _ifa_current=$(cat "$_ifa_file")
    fi
    # Dedupe check via jq: does an entry with this (file, statement) already exist?
    _ifa_dup=$(printf '%s' "$_ifa_current" | jq --arg f "$_ifa_srcfile" --arg s "$_ifa_statement" \
      'any(.[]; .file == $f and .statement == $s)' 2>/dev/null)
    if [ "$_ifa_dup" = "true" ]; then
      return 0
    fi
    printf '%s' "$_ifa_current" | jq --arg id "$_ifa_id" --arg cat "$_ifa_category" \
      --arg f "$_ifa_srcfile" --arg s "$_ifa_statement" --argjson max "$(_invariant_feed_max_lines)" \
      '. + [{"id": $id, "category": $cat, "file": $f, "statement": $s}] | if length > $max then .[-$max:] else . end' \
      > "$_ifa_tmp" 2>/dev/null
    if [ -s "$_ifa_tmp" ]; then
      mv "$_ifa_tmp" "$_ifa_file"
    else
      rm -f "$_ifa_tmp"
      return 1
    fi
    return 0
  fi
  # No JSON tool — cannot safely append (writing raw text risks corrupting
  # the JSON array). Fail silently; the invariant-feed remains empty/stale,
  # which is the same fail-open posture as ds_adversarial_prompt reading it.
  return 0
}

# _key_lookup_line FILE KEY — print the first TSV line in FILE whose first
# field exactly equals KEY, or nothing if no such line exists.
#
# Exact-match via awk field comparison, NOT grep with the key interpolated
# into a pattern: KEY is a content-hash (normally a sha256 hex digest, but
# review-merge.sh's sha256 shim falls back to an IDENTITY function — the raw
# content itself — when neither sha256sum nor shasum is on PATH). An
# identity-fallback "key" can contain BRE metacharacters (., *, ^, $, [, \),
# which would corrupt a `grep "^${key}..."` pattern match (BOBBIE finding,
# lr-63359e review). awk -F'\t' with a literal string comparison ($1 == k)
# never treats KEY as a pattern, so this is correct regardless of key
# strategy or content. Match-correctness fix only — the identity-fallback
# path has no untrusted-input execution surface, just an incorrect match.
_key_lookup_line() {
  _kll_file="$1"
  _kll_key="$2"
  [ -f "$_kll_file" ] || return 0
  awk -F'\t' -v k="$_kll_key" '$1 == k { print; exit }' "$_kll_file" 2>/dev/null
}

# _invariant_feed_write ROLE FINDINGS_JSON DIFF_FILE PRIOR_SEEN_SNAPSHOT SEEN_FILE
#
# Writer half of the adversarial invariant-feed (lr-63359e, follow-up to
# lr-24c80e's read/injection half). Detects "a finding present in a prior
# round is absent this round on changed lines" using the SAME content-hash
# key space _cross_round_dedup/dedup_findings already persists — this is the
# resolve signal, not a new one: PRIOR_SEEN_SNAPSHOT is a copy of SEEN_FILE
# taken BEFORE this round's dedup_findings call added this round's keys to
# it, so (PRIOR_SEEN_SNAPSHOT - this round's live finding keys) is exactly
# "keys the prior round(s) saw that this round's findings no longer contain."
#
# This does NOT alter _cross_round_dedup's suppression behavior — it is a
# read-only comparison run after dedup completes, against a separate snapshot
# file, and the invariants.json file it writes is never consulted by dedup_findings.
#
# ROLE: "review" (structured JSON findings, clean distill) or "adversarial"
# (findings already normalized to the same {file,line,category,message} shape
# by the caller via loose [FINDING]-header parsing — see cmd_adversarial).
#
# Gated the same as the read half: only runs when CLAGENTIC_ADVERSARIAL_INVARIANTS=1.
# Writing invariants nobody reads (feed off) would be dead state; keeping the
# gate identical for read and write keeps the feature's on/off behavior
# consistent end-to-end, per the task's "keep gating consistent" constraint.
_invariant_feed_write() {
  _ifw_role="$1"
  _ifw_findings_json="$2"
  _ifw_diff="$3"
  _ifw_prior_seen="$4"
  _ifw_seen_file="$5"

  [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ] || return 0
  [ -f "$_ifw_prior_seen" ] || return 0  # first round ever — nothing to resolve against

  _ifw_invariants_file="$REPO_ROOT/.clagentic/lite/invariants.json"
  mkdir -p "$REPO_ROOT/.clagentic/lite"

  # This round's live finding keys (with metadata), via the shared key
  # derivation in review-merge.sh — identical algorithm to what SEEN_FILE
  # already contains, so the two sets are directly comparable.
  _ifw_live_keys=$(mktemp -t clagentic-inv-live.XXXXXX)
  printf '%s' "$_ifw_findings_json" | finding_content_keys "$_ifw_diff" > "$_ifw_live_keys" 2>/dev/null

  # Resolved keys: present in the prior snapshot, absent from this round's
  # live keys. Conservative: a key with no metadata line this round (i.e. not
  # in _ifw_live_keys at all) is the resolve candidate; we do not guess why
  # it disappeared (fixed vs. diff not touching that file this round) beyond
  # what the existing content-hash semantics already encode (a key persists
  # only while the 5-line context window it hashed remains unchanged).
  _ifw_resolved_count=0
  while IFS= read -r _ifw_prior_key; do
    [ -z "$_ifw_prior_key" ] && continue
    if [ -z "$(_key_lookup_line "$_ifw_live_keys" "$_ifw_prior_key")" ]; then
      # This key is gone from the live set. We don't have its metadata (the
      # prior seen-keys file is key-only by design, matching dedup_findings'
      # SEEN_FILE format) unless it also appears in the metadata side-cache
      # written by a prior _invariant_feed_write call — see below.
      _ifw_meta_file="${_ifw_seen_file}.meta"
      if [ -f "$_ifw_meta_file" ]; then
        _ifw_meta_line=$(_key_lookup_line "$_ifw_meta_file" "$_ifw_prior_key")
        if [ -n "$_ifw_meta_line" ]; then
          _ifw_meta_srcfile=$(printf '%s' "$_ifw_meta_line" | cut -f2)
          _ifw_meta_category=$(printf '%s' "$_ifw_meta_line" | cut -f3)
          _ifw_meta_message=$(printf '%s' "$_ifw_meta_line" | cut -f4)
          _ifw_new_id="inv-${_ifw_role}-$(printf '%s' "$_ifw_prior_key" | cut -c1-12)"
          _ifw_statement=$(_invariant_feed_distill "$_ifw_meta_category" "$_ifw_meta_message")
          if _invariant_feed_append "$_ifw_invariants_file" "$_ifw_new_id" "$_ifw_meta_category" "$_ifw_meta_srcfile" "$_ifw_statement"; then
            _ifw_resolved_count=$((_ifw_resolved_count + 1))
          fi
        fi
      fi
    fi
  done < "$_ifw_prior_seen"

  if [ "$_ifw_resolved_count" -gt 0 ]; then
    printf '[invariant-feed] wrote %d resolved-finding invariant(s) to %s\n' \
      "$_ifw_resolved_count" "$_ifw_invariants_file" 1>&2
    ds_audit_log "invariant-feed-write" "pass" "role:${_ifw_role} resolved:${_ifw_resolved_count}"
  fi

  # Update the metadata side-cache with THIS round's live keys, so a finding
  # resolved in the round AFTER NEXT can still be distilled. The side-cache
  # is metadata for the SAME key space dedup_findings maintains (SEEN_FILE) —
  # not an independent tracker: every key in it also exists (or existed) in
  # SEEN_FILE, and it carries no suppression/dedup semantics of its own.
  _ifw_meta_file="${_ifw_seen_file}.meta"
  if [ -s "$_ifw_live_keys" ]; then
    cat "$_ifw_live_keys" >> "$_ifw_meta_file"
    # Keep the side-cache from growing unboundedly too: dedupe by key,
    # keeping the most recent metadata line for each key.
    if command -v awk >/dev/null 2>&1; then
      _ifw_meta_dedup=$(mktemp -t clagentic-inv-meta.XXXXXX)
      awk -F'\t' '{ line[$1] = $0 } END { for (k in line) print line[k] }' "$_ifw_meta_file" > "$_ifw_meta_dedup" 2>/dev/null
      if [ -s "$_ifw_meta_dedup" ]; then
        mv "$_ifw_meta_dedup" "$_ifw_meta_file"
      else
        rm -f "$_ifw_meta_dedup"
      fi
    fi
  fi

  rm -f "$_ifw_live_keys"
  return 0
}

# _invariant_feed_distill CATEGORY MESSAGE — turn a resolved finding's
# category+message into a forward-looking invariant statement. Deliberately
# mechanical (no LLM call in the writer path — the writer is gate plumbing,
# not a role): prefix the original message with a standing "must still hold"
# framing so ds_adversarial_prompt's existing instruction text (which already
# tells the Auditor how to use invariant statements) does the interpretive work.
_invariant_feed_distill() {
  _ifd_category="$1"
  _ifd_message="$2"
  if [ -n "$_ifd_category" ]; then
    printf 'Resolved %s finding must not recur, including at a wider scope: %s' \
      "$_ifd_category" "$_ifd_message"
  else
    printf 'Resolved finding must not recur, including at a wider scope: %s' \
      "$_ifd_message"
  fi
}

cmd_review() {
  # Parse flags; all args consumed by the subcommand dispatcher.
  #
  # --since-last-review: RETAINED as a backward-compatible no-op (lr-01ae73
  # generalized the behavior it used to opt into — diffing since the prior
  # verdicted SHA — into the DEFAULT mode; see get_review_diff). A caller
  # that still passes it gets exactly the behavior it always asked for,
  # silently, rather than an "unknown flag" surprise.
  # --full-review: the new opt-OUT, replacing the old opt-IN's role — forces
  # get_review_diff to skip the ledger-anchored delta and use the full
  # branch-diff-against-default (or staged-diff) path instead.
  REVIEW_FULL=0
  _crv_reset_dedup=0
  for _crv_arg in "$@"; do
    case "$_crv_arg" in
      --full-review)        REVIEW_FULL=1 ;;
      --since-last-review)  : ;;  # no-op: this is the default now
      --reset-dedup)        _crv_reset_dedup=1 ;;
    esac
  done
  export REVIEW_FULL

  # --reset-dedup: delete the persisted seen-keys file (and the recurrence
  # counts file, which is derived from the same content-hash key space and
  # would otherwise still remember round counts from before the reset) and
  # exit. Operator calls this to clear cross-round dedup state (e.g. after a
  # major rebase or when they want the next review to re-report all findings
  # AND treat every finding as fresh, not "already reported N rounds").
  _crv_seen_file="$REPO_ROOT/.clagentic/lite/review-seen-keys"
  _crv_recurrence_file="$REPO_ROOT/.clagentic/lite/review-recurrence.json"
  if [ "$_crv_reset_dedup" = "1" ]; then
    if [ -f "$_crv_seen_file" ] || [ -f "$_crv_recurrence_file" ]; then
      rm -f "$_crv_seen_file" "$_crv_recurrence_file"
      echo "[gates/review] cross-round dedup state reset (review-seen-keys and review-recurrence.json deleted)"
      cmd_log_run review pass "cross-round dedup reset by --reset-dedup (recurrence counts cleared)"
    else
      echo "[gates/review] cross-round dedup state already empty (review-seen-keys and review-recurrence.json not found)"
      cmd_log_run review pass "cross-round dedup reset by --reset-dedup (files were absent)"
    fi
    return 0
  fi

  OUT="$REPO_ROOT/.clagentic/lite/last-review.json"

  # Collect the diff into a temp file so we can measure its size for the
  # chunking threshold check and pass it to split_diff without re-running git.
  _crv_diff_tmp=$(mktemp -t clagentic-review-diff.XXXXXX)
  get_review_diff > "$_crv_diff_tmp"
  _crv_diff_bytes=$(ds_file_size "$_crv_diff_tmp")

  # Chunking threshold: CLAGENTIC_REVIEWER_MAX_DIFF_KB (operator-facing alias,
  # in KB) takes precedence; CLAGENTIC_REVIEW_CHUNK_BYTES (in bytes) is the
  # secondary alias; default 262144 bytes (256 KB).
  _crv_chunk_bytes="${CLAGENTIC_REVIEW_CHUNK_BYTES:-262144}"
  if [ -n "${CLAGENTIC_REVIEWER_MAX_DIFF_KB:-}" ]; then
    case "$CLAGENTIC_REVIEWER_MAX_DIFF_KB" in
      ''|*[!0-9]*) : ;;
      *) _crv_chunk_bytes=$(( CLAGENTIC_REVIEWER_MAX_DIFF_KB * 1024 )) ;;
    esac
  fi
  case "$_crv_chunk_bytes" in
    ''|*[!0-9]*) _crv_chunk_bytes=262144 ;;
  esac

  # Squash hint: warn the operator when the diff is large, before the chunking decision.
  if [ "$_crv_diff_bytes" -gt "$_crv_chunk_bytes" ]; then
    printf '[gates/review] diff is %d bytes (threshold %d) — delta re-review (default) or squashing commits reduces review scope\n' \
      "$_crv_diff_bytes" "$_crv_chunk_bytes" 1>&2
  fi

  # Chunking path: CLAGENTIC_REVIEW_CHUNKING=1 AND diff > threshold.
  if [ "${CLAGENTIC_REVIEW_CHUNKING:-0}" = "1" ] && [ "$_crv_diff_bytes" -gt "$_crv_chunk_bytes" ]; then
    _crv_chunk_dir=$(mktemp -d -t clagentic-review-chunks.XXXXXX)
    _crv_env_dir=$(mktemp -d -t clagentic-review-envs.XXXXXX)

    printf '[gates/review] chunked review: cross-file analysis may be incomplete\n' 1>&2

    _crv_nchunks=$(split_diff "$_crv_diff_tmp" "$_crv_chunk_dir" "$_crv_chunk_bytes")
    case "$_crv_nchunks" in
      ''|*[!0-9]*) _crv_nchunks=0 ;;
    esac

    if [ "$_crv_nchunks" -eq 0 ]; then
      printf '[gates/review] split_diff produced 0 chunks — falling back to single-pass review\n' 1>&2
      rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
    else
      _crv_cidx=0
      for _crv_chunk in "$_crv_chunk_dir"/chunk-*; do
        [ -f "$_crv_chunk" ] || continue
        _crv_cidx=$((_crv_cidx + 1))
        _crv_cbytes=$(ds_file_size "$_crv_chunk")
        _crv_env_file=$(printf '%s/envelope-%03d.json' "$_crv_env_dir" "$_crv_cidx")
        printf '[gates/review] reviewing chunk %d/%d (%d bytes)\n' "$_crv_cidx" "$_crv_nchunks" "$_crv_cbytes" 1>&2
        # STATUS-CHECKED (lr-7047bf, INV-1b): walk_chain now returns 3 on a
        # degraded emission (see llm-client.sh walk_chain). Capture the real
        # status instead of discarding it -- the `|| true` here used to hide
        # BOTH a degraded envelope AND any other invoke_* failure (127, a
        # crash) behind the same silent success. The degraded FILE check
        # below still runs unconditionally as the second, mode-appropriate
        # channel (INV-1b requires both); a nonzero status that is NOT a
        # degraded emission (chunk_status not in {3,4}, e.g. an actual
        # crash) is still surfaced via the audit details string rather than
        # swallowed. STATUS 4 (lr-33958f, PR-C): walk_chain's second
        # degraded exit status, the "unwrap" cause (model ran, output was
        # unparseable) -- also a real degraded envelope with a trustworthy
        # payload, not a crash, so it belongs on this same branch as 3.
        _crv_chunk_status=0
        _crv_chunk_err=$(mktemp -t clagentic-review-chunk-err.XXXXXX)
        "$TOOL_HOME/scripts/llm-client.sh" review < "$_crv_chunk" > "$_crv_env_file" 2>"$_crv_chunk_err" || _crv_chunk_status=$?
        _crv_chunk_outcome="pass"
        if [ "$_crv_chunk_status" -ne 0 ] && [ "$_crv_chunk_status" -ne 3 ] && [ "$_crv_chunk_status" -ne 4 ]; then
          # A nonzero status that is NOT one of walk_chain's own degraded
          # markers (3 = infra cause, 4 = unwrap cause) means the call
          # crashed before writing a usable envelope (or wrote
          # partial/garbage content) -- $_crv_env_file cannot be trusted as
          # review JSON. Overwrite it with an explicit degraded envelope
          # BEFORE sanitize/merge ever see it, so merge_envelopes' own
          # per-file `.degraded` check (review-merge.sh) counts this chunk
          # correctly instead of silently treating unparseable content as
          # "not degraded" (merge_envelopes' jq lookup on unparseable JSON
          # returns empty, which compares false to "true").
          # Strip characters that would break the hand-rolled JSON string
          # below (this synthetic envelope is written before any jq/python3
          # tool involvement, so there is no JSON encoder available to lean
          # on here -- same constraint build_gate_summary's no-tool fallback
          # documents).
          _crv_chunk_err_hint=$(head -1 "$_crv_chunk_err" 2>/dev/null | cut -c1-200 | tr -d '"\\')
          printf '{"degraded": true, "summary": "[clagentic-lite degraded] llm-client.sh exited %d: %s", "checked": [], "findings": []}\n' \
            "$_crv_chunk_status" "$_crv_chunk_err_hint" > "$_crv_env_file"
          printf '[gates/review] chunk %d/%d: llm-client.sh exited %d: %s\n' \
            "$_crv_cidx" "$_crv_nchunks" "$_crv_chunk_status" "$_crv_chunk_err_hint" 1>&2
        fi
        rm -f "$_crv_chunk_err"
        # SECURITY (lr-66e598 follow-up): strip every finding in THIS chunk's
        # raw envelope to the closed review-finding schema BEFORE
        # merge_envelopes ever unions it with the other chunks --
        # merge_envelopes/dedup_findings are pure concatenation/dedup with
        # no field validation of their own, so an unsanitized chunk would
        # carry a model-forged internal field (e.g. a self-set
        # _recurrence_demoted) straight through the merge. See
        # _sanitize_review_findings_envelope's own doc comment for the full
        # rationale.
        _sanitize_review_findings_envelope "$_crv_env_file"
        # Audit one row per chunk. STATUS-CHECKED (lr-7047bf, INV-1b): a
        # nonzero status is checked directly (3 = walk_chain's own degraded
        # signal; any other nonzero was normalized to a degraded envelope
        # above), alongside review_is_degraded as the mode-appropriate
        # file-content check -- either alone would miss a case the other
        # catches.
        if [ "$_crv_chunk_status" -ne 0 ] || review_is_degraded "$_crv_env_file" 2>/dev/null; then
          _crv_chunk_outcome="degraded"
        fi
        cmd_log_run review-chunk "$_crv_chunk_outcome" \
          "chunk=${_crv_cidx}/${_crv_nchunks} bytes=${_crv_cbytes} status=${_crv_chunk_status}"
      done

      # Merge all chunk envelopes into the final output.
      _crv_merged=$(merge_envelopes "$_crv_env_dir" "location")
      printf '%s\n' "$_crv_merged" > "$OUT"

      # Stamp the merged envelope with the current HEAD SHA — same logic as
      # the single-chunk path below. Repo-scoped (lr-da1f28 sweep): see
      # _git_repo_scoped_head_sha's doc comment for why a bare `_git
      # rev-parse HEAD` is not sufficient here.
      _review_sha=$(_git_repo_scoped_head_sha)
      if [ -n "$_review_sha" ]; then
        _stamp_envelope "$OUT" "$_review_sha"
      fi
      # base_sha for the ledger entry (item 1/2) — merge-base against the
      # default branch, the SAME provably-current resolution cmd_sast's
      # baseline scoping uses. Empty on any resolution failure; a ledger
      # entry with empty base_sha is still valid as long as head_sha
      # resolved (see _resolve_base_sha's own doc comment).
      _crv_fetch_timeout="${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-30}"
      _crv_fetch_timeout=$(ds_positive_int_or_default "$_crv_fetch_timeout" 30)
      _crv_base_sha=$(_resolve_base_sha "${CLAGENTIC_DEFAULT_BRANCH:-main}" "$_crv_fetch_timeout")

      # Cross-round dedup (default-on). Suppresses findings already seen in a prior
      # round when the relevant diff lines are unchanged (content-hash strategy).
      # CLAGENTIC_CROSS_ROUND_DEDUP=0 disables; default is ON.
      if [ "${CLAGENTIC_CROSS_ROUND_DEDUP:-1}" = "1" ]; then
        # Initialize seen-keys file on first run so dedup_findings never sees
        # a missing file (created empty; appended to by dedup_findings).
        [ -f "$_crv_seen_file" ] || touch "$_crv_seen_file"
        # Invariant-feed writer (lr-63359e): snapshot seen-keys BEFORE this
        # round's dedup call adds this round's keys, so the writer can diff
        # "keys the prior round(s) saw" against "keys still live this round."
        _crv_prior_seen_snap=$(mktemp -t clagentic-inv-prior.XXXXXX)
        cp "$_crv_seen_file" "$_crv_prior_seen_snap" 2>/dev/null || : > "$_crv_prior_seen_snap"
        _cross_round_dedup "$OUT" "$_crv_diff_tmp" "$_crv_seen_file"
        # Recurrence demotion (lr-66e598): a finding that survived dedup and
        # keeps reappearing across rounds is demoted to advisory (excluded
        # from severity_blockers' count) rather than re-litigated forever.
        # Second use of the same content-hash key space, per its own
        # threshold (CLAGENTIC_RECURRENCE_THRESHOLD, default 2) — see
        # _review_recurrence_demote for the full mechanics.
        _review_recurrence_demote "$OUT" "$_crv_diff_tmp" "$_crv_recurrence_file"
        if [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ]; then
          _crv_live_findings=$(_extract_findings_json "$OUT")
          _invariant_feed_write review "$_crv_live_findings" "$_crv_diff_tmp" "$_crv_prior_seen_snap" "$_crv_seen_file"
        fi
        rm -f "$_crv_prior_seen_snap"
      fi

      # Operator deferral matching (lr-2ebc41): gate-code enforcement of
      # .clagentic/deferrals.json, independent of cross-round dedup state —
      # a deferral can match on the very first round a finding is reported,
      # so this runs unconditionally rather than being nested inside the
      # CLAGENTIC_CROSS_ROUND_DEDUP gate above. See _review_deferral_match's
      # own doc comment for the full match-key/lapse/fail-closed rationale.
      _review_deferral_match "$OUT"

      # Aggregate audit row for the merged result.
      _crv_merged_outcome="pass"
      if review_is_degraded "$OUT" 2>/dev/null; then
        _crv_merged_outcome="block"
      fi
      cmd_log_run review "$_crv_merged_outcome" \
        "chunked: ${_crv_nchunks} chunks reviewed"

      # Partial-degradation surfacing.
      if review_is_degraded "$OUT"; then
        _crv_chunks_deg=$(_review_chunks_degraded "$OUT")
        _crv_total=$(_review_chunks_total "$OUT")
        if [ "$_crv_chunks_deg" -lt "$_crv_total" ]; then
          echo "[gates/review] INFRA_DEGRADED: ${_crv_chunks_deg}/${_crv_total} chunks degraded — partial review only." 1>&2
        else
          echo "[gates/review] INFRA_DEGRADED: all chunks degraded — no real review occurred." 1>&2
        fi
        echo "[gates/review] Check LLM CLI config/auth. Set CLAGENTIC_REVIEWER_REQUIRED=1 to make this a hard gate error." 1>&2
        echo "[gates/review] full details: $OUT  |  scripts/gates.sh digest" 1>&2
        # Degraded: no real verdict was reached. Record as unanchored/block
        # rather than skipping the ledger entirely — the audit trail should
        # show a degraded round happened, and an unresolved head_sha
        # (or a resolved one paired with outcome "block" below) can never
        # be read as a passing verdict either way.
        _ledger_record_review_verdict "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
        rm -f "$_crv_diff_tmp"
        rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
        return 2
      fi

      THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"
      BLOCKERS=$(severity_blockers "$OUT" "$THRESHOLD")
      if [ "${BLOCKERS:-0}" -gt 0 ]; then
        cmd_log_run review block "review-blocked: $BLOCKERS finding(s) at >= $THRESHOLD"
        echo "[gates/review] REVIEW_BLOCKED: $BLOCKERS finding(s) at or above severity '$THRESHOLD'." 1>&2
        cmd_render_review "$OUT" 1>&2
        _ledger_record_review_verdict "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
        rm -f "$_crv_diff_tmp"
        rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
        return 1
      fi
      _cmd_log_run_checked_pass review "0 findings at >= $THRESHOLD (chunked)"
      cmd_render_review "$OUT"
      _ledger_record_review_verdict "$OUT" "$_crv_diff_tmp" "pass" "$_crv_base_sha" "$_review_sha"
      rm -f "$_crv_diff_tmp"
      rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
      return 0
    fi
  fi

  # Single-pass path (original behavior).
  # STATUS-CHECKED (lr-7047bf, INV-1b): guard explicitly -- gates.sh runs
  # under `set -e`, and walk_chain now returns 3 on a degraded emission (see
  # llm-client.sh walk_chain). An unguarded call here would abort the whole
  # gate on a degraded envelope instead of reaching the mode-appropriate
  # degraded check (review_is_degraded, below) that turns it into the
  # INFRA_DEGRADED (exit 2) path. _crv_review_status is recorded in the audit
  # details string below for the same reason the chunked path records it.
  _crv_review_status=0
  "$TOOL_HOME/scripts/llm-client.sh" review < "$_crv_diff_tmp" > "$OUT" || _crv_review_status=$?
  # Note: _crv_diff_tmp is NOT deleted yet — cross-round dedup needs it below.

  # SECURITY (lr-66e598 follow-up): strip every finding to the closed
  # review-finding schema IMMEDIATELY after the raw LLM write and BEFORE
  # anything else (stamp, dedup, recurrence, severity_blockers,
  # cmd_render_review) ever reads $OUT. See _sanitize_review_findings_envelope's
  # own doc comment for the full rationale — this is the choke point that
  # closes the self-exempting-suppression gap a raw, unallowlisted model
  # finding could otherwise use.
  _sanitize_review_findings_envelope "$OUT"

  # Stamp the output with the current HEAD SHA so build_gate_summary can
  # detect stale payloads (file written against a different branch/commit).
  # Best-effort: if git or jq/python3 are unavailable, skip silently.
  # Repo-scoped (lr-da1f28 sweep): see _git_repo_scoped_head_sha's doc
  # comment for why a bare `_git rev-parse HEAD` is not sufficient here.
  _review_sha=$(_git_repo_scoped_head_sha)
  if [ -n "$_review_sha" ]; then
    _stamp_envelope "$OUT" "$_review_sha"
  fi
  # base_sha for the ledger entry (item 1/2) — see the chunked-path comment
  # above for the full rationale (same logic, single-pass path).
  _crv_fetch_timeout="${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-30}"
  _crv_fetch_timeout=$(ds_positive_int_or_default "$_crv_fetch_timeout" 30)
  _crv_base_sha=$(_resolve_base_sha "${CLAGENTIC_DEFAULT_BRANCH:-main}" "$_crv_fetch_timeout")

  # Cross-round dedup (default-on). Suppresses findings already seen in a prior
  # round when the relevant diff lines are unchanged (content-hash strategy).
  # CLAGENTIC_CROSS_ROUND_DEDUP=0 disables; default is ON.
  if [ "${CLAGENTIC_CROSS_ROUND_DEDUP:-1}" = "1" ]; then
    # Initialize seen-keys file on first run so dedup_findings never sees
    # a missing file (created empty; appended to by dedup_findings).
    [ -f "$_crv_seen_file" ] || touch "$_crv_seen_file"
    # Invariant-feed writer (lr-63359e): snapshot seen-keys BEFORE this
    # round's dedup call adds this round's keys — see the chunked-path
    # comment above for the full rationale (same logic, single-pass path).
    _crv_prior_seen_snap=$(mktemp -t clagentic-inv-prior.XXXXXX)
    cp "$_crv_seen_file" "$_crv_prior_seen_snap" 2>/dev/null || : > "$_crv_prior_seen_snap"
    _cross_round_dedup "$OUT" "$_crv_diff_tmp" "$_crv_seen_file"
    # Recurrence demotion (lr-66e598) — see the chunked-path comment above
    # for the full rationale (same logic, single-pass path).
    _review_recurrence_demote "$OUT" "$_crv_diff_tmp" "$_crv_recurrence_file"
    if [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ]; then
      _crv_live_findings=$(_extract_findings_json "$OUT")
      _invariant_feed_write review "$_crv_live_findings" "$_crv_diff_tmp" "$_crv_prior_seen_snap" "$_crv_seen_file"
    fi
    rm -f "$_crv_prior_seen_snap"
  fi

  # Operator deferral matching (lr-2ebc41) — see the chunked-path comment
  # above for the full rationale (same logic, single-pass path). Runs
  # unconditionally, outside the CLAGENTIC_CROSS_ROUND_DEDUP gate above.
  _review_deferral_match "$OUT"

  # NOTE: $_crv_diff_tmp is deleted at each exit point below (not here) —
  # _ledger_record_review_verdict (item 1/2/5) still needs it for recurrence
  # marking (finding_content_keys reads the diff to recompute content-hash
  # keys) at every one of the three exits that follow.

  # Reject degraded envelopes outright. An LLM wrapper that failed every
  # chain step emits valid JSON with findings:[] — schema-valid but
  # meaningless. Without this check, a misconfigured / auth-broken /
  # network-out Reviewer chain reports "clean review" and the ship passes.
  # Exit 2 = INFRA_DEGRADED: distinct from exit 1 (REVIEW_BLOCKED) so callers
  # and CI can distinguish "retry — infra flaked" from "fix your code."
  #
  # Both channels (lr-7047bf, INV-1b): a nonzero $_crv_review_status is
  # walk_chain's own outcome signal (3 = degraded envelope written; 1 = hard
  # failure under CLAGENTIC_REVIEWER_REQUIRED=1, in which case $OUT was never
  # written and is empty -- review_is_degraded's JSON parse would not
  # recognize an empty file as "degraded": true on its own); review_is_degraded
  # is the mode-appropriate file-content check for the ordinary case. Either
  # alone would miss a case the other catches, so both gate this check.
  if [ "$_crv_review_status" -ne 0 ] || review_is_degraded "$OUT"; then
    _crv_cause=$(_llm_degraded_cause "$_crv_review_status" "$OUT")
    if [ "$_crv_cause" = "unwrap" ]; then
      cmd_log_run review block "model-output-unparseable: reviewer ran but returned no parseable role-shaped JSON (status=$_crv_review_status)"
      echo "[gates/review] MODEL_OUTPUT_UNPARSEABLE: reviewer ran successfully but its output could not be reduced to exactly one parseable review — no real review occurred." 1>&2
    elif [ "$_crv_cause" = "turns-exhausted" ]; then
      cmd_log_run review block "turns-exhausted: reviewer ran out of turns before completing (status=$_crv_review_status)"
      echo "[gates/review] TURNS_EXHAUSTED: reviewer exhausted its turn limit before completing — a truncated run, not a real review. This is the failure a well-formed-but-truncated findings:[] would otherwise hide as a clean pass." 1>&2
    else
      cmd_log_run review block "infra-degraded: all reviewer chain steps failed (status=$_crv_review_status)"
      echo "[gates/review] INFRA_DEGRADED: reviewer chain returned degraded envelope — no real review occurred." 1>&2
    fi
    _llm_degraded_remediation_lines "$_crv_cause" 1>&2
    echo "[gates/review] Set CLAGENTIC_REVIEWER_REQUIRED=1 to make this a hard gate error." 1>&2
    # Pull the per-step failure reasons from the audit DB so the user sees them
    # in the terminal without having to run `digest` or open last-review.json.
    ADB="$REPO_ROOT/.clagentic/lite/audit.db"
    if [ -f "$ADB" ] && command -v sqlite3 >/dev/null 2>&1; then
      STEP_HINTS=$(ds_sqlite3 "$ADB" \
        "SELECT '  ' || details FROM gate_runs WHERE gate='llm-call' AND outcome='step-failed' AND details LIKE 'reviewer%' ORDER BY id DESC LIMIT 6;" \
        2>/dev/null)
      if [ -n "$STEP_HINTS" ]; then
        printf '[gates/review] per-step failures (most recent first):\n' 1>&2
        printf '%s\n' "$STEP_HINTS" 1>&2
      fi
    fi
    echo "[gates/review] full details: $OUT  |  scripts/gates.sh digest" 1>&2
    # Degraded: no real verdict was reached — see the chunked-path comment
    # at its own degraded exit for why this is still recorded.
    _ledger_record_review_verdict "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
    rm -f "$_crv_diff_tmp"
    return 2
  fi
  # Severity gate: count findings >= configured threshold.
  THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"
  BLOCKERS=$(severity_blockers "$OUT" "$THRESHOLD")
  if [ "${BLOCKERS:-0}" -gt 0 ]; then
    cmd_log_run review block "review-blocked: $BLOCKERS finding(s) at >= $THRESHOLD"
    echo "[gates/review] REVIEW_BLOCKED: $BLOCKERS finding(s) at or above severity '$THRESHOLD'." 1>&2
    cmd_render_review "$OUT" 1>&2
    _ledger_record_review_verdict "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
    rm -f "$_crv_diff_tmp"
    return 1
  fi
  _cmd_log_run_checked_pass review "0 findings at >= $THRESHOLD"
  cmd_render_review "$OUT"
  _ledger_record_review_verdict "$OUT" "$_crv_diff_tmp" "pass" "$_crv_base_sha" "$_review_sha"
  rm -f "$_crv_diff_tmp"
}

# _stamp_envelope FILE SHA — add _clagentic_diff_sha to a JSON envelope file.
# Best-effort: silently skips if no JSON tool or if jq/python3 fail.
_stamp_envelope() {
  _se_file="$1"
  _se_sha="$2"
  if command -v jq >/dev/null 2>&1; then
    _se_tmp=$(mktemp -t clagentic-review-stamp.XXXXXX)
    if jq --arg sha "$_se_sha" '. + {_clagentic_diff_sha: $sha}' "$_se_file" > "$_se_tmp" 2>/dev/null; then
      mv "$_se_tmp" "$_se_file"
    else
      rm -f "$_se_tmp"
    fi
  elif command -v python3 >/dev/null 2>&1; then
    _se_tmp=$(mktemp -t clagentic-review-stamp.XXXXXX)
    if python3 - "$_se_file" "$_se_sha" "$_se_tmp" <<'PYEOF' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    d["_clagentic_diff_sha"] = sys.argv[2]
    with open(sys.argv[3], "w") as f:
        json.dump(d, f)
except Exception:
    sys.exit(1)
PYEOF
    then
      mv "$_se_tmp" "$_se_file"
    else
      rm -f "$_se_tmp"
    fi
  fi
}

# _review_chunks_degraded FILE — extract chunks_degraded from a merged envelope.
# Returns 0 on parse error (conservative: assume none degraded for counting).
_review_chunks_degraded() {
  _rcd_file="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.chunks_degraded // 0' "$_rcd_file" 2>/dev/null || echo 0
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("chunks_degraded",0))' \
      "$_rcd_file" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

# _review_chunks_total FILE — extract chunks from a merged envelope.
_review_chunks_total() {
  _rct_file="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.chunks // 0' "$_rct_file" 2>/dev/null || echo 0
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("chunks",0))' \
      "$_rct_file" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

# _llm_output_is_degraded MODE FILE
#
# Mode-complete detector for the degraded envelope emit_degraded
# (llm-client.sh) writes when every chain step failed. Covers all three
# output shapes emit_degraded can produce:
#   json     - {"degraded": true, ...}
#   line     - DEGRADED_MARKER (a literal ASCII SOH byte, 0x01) followed by
#              "[clagentic-lite degraded] "
#   markdown - a document whose first line starts with DEGRADED_MARKER
#              followed by "# Degraded output" -- OR, once cmd_adversarial
#              prepends its SHA-stamp comment (gates.sh cmd_adversarial,
#              "<!-- clagentic-diff-sha: ... -->\n" + cat), the SECOND line.
#
# Prior to this, only the json shape had ANY detector anywhere in the repo
# (review_is_degraded below, json-only). The markdown shape
# (cmd_adversarial's output) and the line shape (cmd_summarize's output)
# had none — that absence is exactly why cmd_adversarial had no degraded
# check: there was nothing to call. review_is_degraded is now a thin
# json-mode wrapper around this function so its many existing call sites
# are unaffected.
#
# UNFORGEABLE PREFIX (BOBBIE finding 1, lr-7047bf fold-in): line/markdown
# mode previously matched on plain banner text alone ("[clagentic-lite
# degraded] " / "# Degraded output"), which a prompt-injected model
# response could reproduce verbatim, misclassifying a real audit as
# degraded (over-cautious direction only -- emit_degraded's own output is
# never model-generated, so a genuine degraded envelope could never be
# hidden this way). The detector now requires the leading DEGRADED_MARKER
# control byte (emit_degraded, llm-client.sh) to be present before it will
# even consider the banner text -- a byte no realistic model response
# stream emits (see DEGRADED_MARKER's own comment in llm-client.sh for the
# full rationale). Banner text with no leading marker byte is NOT treated
# as degraded.
#
# STAMP-AWARE MARKDOWN CHECK (BOBBIE finding 1 remainder, lr-7047bf
# fold-in, PR #141 review #2): markdown mode originally checked ONLY byte 1
# of the file, which is correct for cmd_adversarial's own in-process check
# (_adv_status/_llm_output_is_degraded at the call site, BEFORE the SHA
# stamp is prepended) but silently wrong for any LATER reader of the
# persisted last-adversarial.md, whose first line is by then the SHA-stamp
# HTML comment, pushing the DEGRADED_MARKER byte + banner to line 2.
# build_gate_summary hand-rolled its own `sed -n '1,2p' | grep -qF` check
# for exactly this reason, WITHOUT the marker-byte hardening this function
# has -- two detectors for the same envelope, one hardened and one not, is
# the documented failure mode this repo tracks (drift between duplicated
# checks). Markdown mode now checks line 1 first, then falls back to line
# 2 -- covering both the pre-stamp (cmd_adversarial's own call) and
# post-stamp (build_gate_summary's persisted-file read) shapes with the
# same hardened, marker-byte-gated logic.
#
# FAIL CLOSED on no validator: unlike the old review_is_degraded (which
# fail-OPEN'd to "not degraded" when jq/python3 were both absent, relying
# on severity_blockers' own fail-closed as a backstop that does not exist
# for adversarial/markdown output), this treats "cannot verify" as
# "assume degraded" for every mode. A caller that cannot prove the output
# is real must not treat it as real.
#
# Returns 0 if degraded, 1 if not.
_llm_output_is_degraded() {
  _lod_mode="$1"
  _lod_file="$2"
  case "$_lod_mode" in
    json)
      if command -v jq >/dev/null 2>&1; then
        jq -e '.degraded == true' "$_lod_file" >/dev/null 2>&1
      elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("degraded") is True else 1)' "$_lod_file" 2>/dev/null
      else
        return 0
      fi
      ;;
    line)
      [ -f "$_lod_file" ] || return 0
      _lod_first_byte=$(head -c 1 "$_lod_file" 2>/dev/null | od -An -tx1 | tr -d ' \n')
      [ "$_lod_first_byte" = "01" ] || return 1
      head -1 "$_lod_file" 2>/dev/null | grep -qF '[clagentic-lite degraded]'
      ;;
    markdown|*)
      [ -f "$_lod_file" ] || return 0
      _lod_first_byte=$(head -c 1 "$_lod_file" 2>/dev/null | od -An -tx1 | tr -d ' \n')
      if [ "$_lod_first_byte" = "01" ]; then
        head -1 "$_lod_file" 2>/dev/null | grep -qF '# Degraded output' && return 0
        return 1
      fi
      # Stamp-shifted case: line 1 is the SHA-stamp comment, so the marker
      # (if present at all) is on line 2.
      _lod_second_byte=$(sed -n '2p' "$_lod_file" 2>/dev/null | head -c 1 | od -An -tx1 | tr -d ' \n')
      [ "$_lod_second_byte" = "01" ] || return 1
      sed -n '2p' "$_lod_file" 2>/dev/null | grep -qF '# Degraded output'
      ;;
  esac
}

# Detect the "degraded": true marker written by emit_degraded in llm-client.sh.
# Args: FILE
# Returns 0 if degraded, 1 if not.
#
# Thin json-mode wrapper around _llm_output_is_degraded, kept for the many
# existing review call sites. NOTE: the no-validator branch now fails
# CLOSED (assumes degraded) — see _llm_output_is_degraded's doc comment.
# Previously this fail-opened ("assume not degraded"), relying on
# severity_blockers' own fail-closed as a backstop; that backstop does not
# exist for every consumer, so the detector itself must not fail open.
review_is_degraded() {
  _llm_output_is_degraded json "$1"
}

# _llm_degraded_cause STATUS FILE
#
# MODEL-RETURNED-PROSE CLASSIFICATION (lr-33958f, PR-C, the fix the foundry
# insisted on hardest; extended class-4). Distinguishes walk_chain's
# degraded causes so a caller can point its remediation hint at the right
# place instead of always saying "check LLM CLI config/auth":
#   "infra"            — misconfigured/auth-broken/network-out chain. The
#                         name INFRA_DEGRADED actually describes. "check CLI
#                         config/auth" is correct remediation.
#   "unwrap"            — the model ran successfully (auth worked, tokens
#                         were spent) but its output could not be reduced to
#                         exactly one role-shaped JSON candidate (prose-only,
#                         or ambiguous). NOT an infrastructure problem;
#                         sending the operator to check CLI config/auth here
#                         is the exact misdirection the foundry named as a
#                         plausible contributor to two real misdiagnoses.
#                         Remediation hint: reviewer OUTPUT SHAPE.
#   "turns-exhausted"   — the model ran, spent tokens, and was cut off by
#                         its own internal turn ceiling before completing
#                         (subtype=="error_max_turns"). NOT infra, NOT
#                         unwrap: the output may be perfectly well-formed
#                         JSON, which is exactly what makes this cause the
#                         one the foundry flagged hardest -- it can look
#                         identical to a clean pass to any check that only
#                         inspects shape. Remediation hint: the diff is too
#                         large or the caller-tracing work too deep for the
#                         model's turn budget on this call.
#
# STATUS is walk_chain's own captured exit code where available (4 = the
# unwrap cause, 5 = the turns-exhausted cause, both unambiguous on their
# own) — checked FIRST because it needs no JSON tool at all and is
# authoritative for the single-pass call site that still has it in scope.
# FILE's own "cause" field (emit_degraded, llm-client.sh) is the fallback
# for callers where the exit status was already collapsed to a boolean
# before this point (e.g. after `merge_envelopes`), or where STATUS is not
# available/passed as empty. Defaults to "infra" when neither source
# resolves a value — the pre-existing behavior for every degraded envelope
# this task predates, so an unlabeled legacy envelope (no "cause" field,
# e.g. one written before this PR) is never misclassified as a newer,
# narrower cause it cannot actually be.
_llm_degraded_cause() {
  _ldc_status="${1:-}"
  _ldc_file="$2"
  if [ "$_ldc_status" = "4" ]; then
    printf 'unwrap'
    return 0
  fi
  if [ "$_ldc_status" = "5" ]; then
    printf 'turns-exhausted'
    return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    _ldc_cause=$(jq -r '.cause // "infra"' "$_ldc_file" 2>/dev/null || echo "infra")
  elif command -v python3 >/dev/null 2>&1; then
    _ldc_cause=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("cause") or "infra")' "$_ldc_file" 2>/dev/null || echo "infra")
  else
    _ldc_cause="infra"
  fi
  case "$_ldc_cause" in
    unwrap)           printf 'unwrap' ;;
    turns-exhausted)  printf 'turns-exhausted' ;;
    *)                printf 'infra' ;;
  esac
}

# _llm_degraded_remediation_lines CAUSE — prints the cause-specific
# remediation hint line(s) for INFRA_DEGRADED/MODEL_OUTPUT_UNPARSEABLE/
# TURNS_EXHAUSTED stderr output. Single source of the message bodies so
# every call site (review, adversarial, merge-gate) stays in sync rather
# than each hand-rolling its own copy that could drift.
_llm_degraded_remediation_lines() {
  case "$1" in
    unwrap)
      printf '%s\n' "Check the reviewer/auditor OUTPUT SHAPE — the model ran (auth and network both worked) but did not return parseable role-shaped JSON. Not a CLI config/auth problem."
      ;;
    turns-exhausted)
      printf '%s\n' "The model exhausted its turn limit before finishing — not a CLI config/auth problem. The diff may be too large, or the required caller-tracing too deep, for the model's turn budget on this call. Check num_turns in the audit trail (scripts/gates.sh digest / llm-call rows) against recent successful runs."
      ;;
    *)
      printf '%s\n' "Check LLM CLI config/auth."
      ;;
  esac
}

# _parse_adversarial_findings MARKDOWN_FILE
#
# Loose-parses [FINDING] header lines from adversarial markdown output into
# the same {file,line,category,message} JSON shape review findings use, so
# they can be run through the EXISTING finding_content_keys / dedup_findings
# machinery unmodified, plus gate-plumbing fields (reachable, tier, class)
# added for the advisory/blocking split (lr-e2b975) and the change-class
# threshold (lr-4f8316). Header format (ds_adversarial_prompt, llm-client.sh):
#   [FINDING] CWE-XXX | file.ext:line | severity: <level> | reachable: <yes|no> | tier: <blocking|advisory> | class: <durable|ephemeral> | title: <phrase>
# "category" is set to the CWE id (e.g. "CWE-770") — adversarial findings
# have no review-style category, and the CWE id IS the class identity that
# matters for invariant re-derivation. "message" is the title field. A
# missing/malformed line number degrades to line 0 (finding_content_keys then
# fails to compute a context window and the finding is simply omitted from
# the key set — same conservative-drop behavior documented there).
#
# Parser default (fail-open, non-blocking side): reachable/tier are OPTIONAL
# fields for backward compatibility with a model that emits the pre-lr-e2b975
# header shape (severity | title, no reachable/tier), or that omits them
# despite the prompt instruction. A finding with no parseable tier is
# classified "advisory" — never "blocking" — so a parser gap can only ever
# under-block (findings still fully visible in output/audit), matching the
# task's "never suppression" constraint from the other direction: silence in
# a gate-plumbing field must not manufacture a block that was never earned.
#
# Every enum-shaped field (severity, reachable, tier, class) is validated and
# force-corrected here, at parse time, to a member of its closed set — none
# of the four is ever passed through as raw captured text. This was a real
# gap for severity specifically until a follow-up review caught it: severity
# was captured as free text bounded only by the next "|" with no enum check,
# so model- or attacker-authored text in the severity position reached the
# JSON sidecar and the merge-gate prompt's fenced data block completely
# unvalidated — see the inline comment at the severity assignment below for
# the fix and its rationale.
#
# TWO MECHANICAL CLAMPS on tier (lr-4f8316 follow-up), same posture, legible
# as a pair: (1) reachable != "yes" forces tier to "advisory" — reachability
# is the mechanical precondition for blocking, never a judgment call tier
# alone can override. (2) reachable == "yes" AND severity in (high,critical)
# forces tier to "blocking" — this is the security floor, and it is NOT
# LLM self-restraint: a finding meeting this bar cannot be downgraded to
# advisory by class or by anything else the model writes in the tier field.
# See the inline comment at the floor-clamp assignment below for exactly
# what "the security floor" is mechanically defined as (and is NOT) given
# the fields this parser actually has.
_parse_adversarial_findings() {
  _paf_file="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$_paf_file" <<'PYEOF'
import json, re, sys

path = sys.argv[1]
findings = []
_paf_read_failed = False
# CWE and file:line are mandatory leading fields. severity is mandatory.
# reachable/tier/class are optional (may be absent entirely, in any order
# relative to each other, as long as all precede title when present) so a
# model still emitting an older header keeps parsing. title remains the
# final field, capturing to end-of-line.
#
# `class` (lr-4f8316) is the Auditor's own resolved change-class judgment
# for the diff this finding lives in -- durable|ephemeral, see
# ds_adversarial_prompt for the vocabulary and threshold implications. It is
# a per-finding field (like reachable/tier) purely so it rides the same
# parse loop and sanitize path; in practice one diff has one resolved class,
# so every finding from the same adversarial pass carries the same value.
header_re = re.compile(
    r'^\[FINDING\]\s*([^|]+)\|\s*([^|]+)\|\s*severity:\s*([^|]+?)\s*'
    r'(?:\|\s*reachable:\s*([^|]+?)\s*)?'
    r'(?:\|\s*tier:\s*([^|]+?)\s*)?'
    r'(?:\|\s*class:\s*([^|]+?)\s*)?'
    r'\|\s*title:\s*(.+)$'
)
# FAIL LOUD ON A GENUINE READ FAILURE (BOBBIE, lr-33958f PR-C fold-in
# review, Class 2.7): an unreadable/unparseable adversarial markdown file
# used to fall back to lines = [] here, which then yields the SAME
# zero-findings JSON array a genuinely clean audit produces --
# INDISTINGUISHABLE from a clean pass. This is the identical fail-open
# class BOBBIE blocked on twice in PR-B (lr-7047bf): a failure signalled by
# writing empty data rather than returning status. The distinction that
# matters: $path is $OUT, written moments earlier in cmd_adversarial by the
# same shell invocation (gates.sh) that is about to call this parser, so a
# read failure here means something is wrong with the filesystem/permissions
# between that write and this read, NOT "the auditor legitimately found
# nothing" (which instead produces a readable file with zero [FINDING]
# headers -- an ordinary, valid outcome that must NOT hit this branch).
# SIGNAL ON THE RETURN CHANNEL, not via stdout content: print nothing to
# stdout and exit 1, so the caller (cmd_adversarial, gates.sh) can tell
# "read failed" (nonzero exit, empty stdout) apart from "clean audit"
# (exit 0, stdout "[]") mechanically, rather than the two being the exact
# same bytes on stdout.
try:
    with open(path) as f:
        lines = f.readlines()
except Exception as e:
    print(f"_parse_adversarial_findings: could not read {path}: {e}", file=sys.stderr)
    sys.exit(1)

for line in lines:
    line = line.rstrip("\n")
    m = header_re.match(line.strip())
    if not m:
        continue
    cwe = m.group(1).strip()
    fileline = m.group(2).strip()
    severity_raw = m.group(3).strip().lower()
    reachable_raw = (m.group(4) or "").strip().lower()
    tier_raw = (m.group(5) or "").strip().lower()
    class_raw = (m.group(6) or "").strip().lower()
    title = m.group(7).strip()
    # FILE:LINE EXTRACTION -- LOCATE AND VALIDATE, NOT SPLIT-AND-HOPE
    # (BOBBIE, lr-33958f PR-C fold-in review, Class 2.5): the prior form
    # (`if ":" in fileline: fname, _, lineno = fileline.rpartition(":")`)
    # was unanchored and permissive -- ANY colon anywhere in fileline routed
    # it down the "has a line number" branch, including a path that
    # legitimately contains a colon with no trailing digits (rpartition then
    # falls back to (fileline, 0) via the ValueError catch, which happens to
    # be safe here, but only by accident of the fallback, not by validating
    # the shape up front). Mirrors _llm_unwrap_json_envelope's own INV-2
    # discipline: LOCATE the expected shape with an anchored pattern, then
    # only accept it once it has actually been confirmed to match, rather
    # than probing for a substring and coercing whatever falls out.
    #
    # file_line_re anchors the ENTIRE fileline string end-to-end: everything
    # up to the LAST colon is the file (greedy `.+`, so a path containing an
    # earlier colon, e.g. a drive letter, is still captured whole), and
    # everything after that last colon must be ONE OR MORE DIGITS with
    # nothing else trailing -- not "starts with digits", not "contains
    # digits somewhere". Any other shape (no colon at all, e.g. "general";
    # a colon with non-numeric trailing text; a colon with an empty
    # trailing segment) is REJECTED by the regex not matching at all, and
    # falls back to (fileline, 0) explicitly -- the same conservative
    # default the prior code used for "no colon", now also covering every
    # colon-bearing shape that isn't genuinely file:line.
    file_line_re = re.compile(r'^(.+):(\d+)$')
    m_fl = file_line_re.match(fileline)
    if m_fl:
        fname = m_fl.group(1)
        lineno = int(m_fl.group(2))
    else:
        fname, lineno = fileline, 0
    # severity is a closed set, same as reachable/tier/class below -- enum-check
    # and force-correct rather than pass the raw captured text through.
    # Before this (lr-e2b975 follow-up), severity was free text bounded only
    # by the next "|" in the header line: model- or attacker-authored text
    # in the severity position reached the JSON sidecar and the merge-gate
    # prompt's fenced block completely unvalidated -- the identical
    # fence-escape shape _llm_field_sanitize closes for message/file/
    # category, just left open on this one field. "unknown" is the sentinel
    # for an unparseable/unrecognized value: distinguishable from a real
    # severity in review/audit output rather than silently coercing to a
    # specific level. severity_blockers() (this file) ranks "unknown" the
    # same as any other unrecognized string (rank 0, below "low") when this
    # feeds a caller that ranks severities, so an unparseable severity can
    # never inflate itself into a blocking rank.
    severity = severity_raw if severity_raw in ("low", "medium", "high", "critical") else "unknown"
    reachable = reachable_raw if reachable_raw in ("yes", "no") else "no"
    # tier defaults to advisory when absent/unparseable (fail-open, see
    # docstring above) and is force-corrected to advisory when the model's
    # own reachable field says "no" -- reachability is the mechanical
    # precondition for blocking, not a judgment call the tier field alone
    # can override.
    if tier_raw in ("blocking", "advisory"):
        tier = tier_raw
    else:
        tier = "advisory"
    if reachable != "yes":
        tier = "advisory"
    # class (lr-4f8316): closed set durable|ephemeral, absent/unparseable
    # defaults to "durable" -- fail-closed on the SAME axis severity/
    # reachable/tier fail-open on (never-under-block), because durable is
    # the class that does NOT relax the blocking threshold. A parser gap in
    # this field can therefore only ever leave the full bar in place, never
    # silently grant a downgrade.
    change_class = class_raw if class_raw in ("durable", "ephemeral") else "durable"
    # SECURITY FLOOR CLAMP (lr-4f8316 follow-up, MECHANICAL, mirrors the
    # reachability clamp immediately above -- same function, same posture,
    # legible as a pair): before this fix, whether an ephemeral-classed,
    # reachable, high/critical finding stayed tier:blocking was ENTIRELY
    # LLM self-restraint -- the parser recorded the declared class but never
    # independently verified the Auditor actually honored "the security
    # floor is absolute regardless of class" from its own prompt. Docs and
    # the prompt asserted that floor as absolute; nothing in code enforced
    # it. That is the identical failure shape lr-e2b975 fixed for severity:
    # a documented safety property with no corresponding mechanical check.
    #
    # The floor as documented (live credentials, reachable injection sinks,
    # real exploit paths) is not fully expressible from the fields available
    # to this parser -- there is no structured "is this a credential" or
    # "is this a real exploit path" signal, only file/line/category/message/
    # severity/reachable/tier/class. The mechanically enforceable subset of
    # that intent, translated into the fields actually available: reachable
    # (a cited concrete exploit path/trigger, per the Auditor's own
    # Pre-Report Gate) AND severity high/critical (the Auditor's own
    # judgment that this is a live, serious exposure) together are the
    # closed-form proxy for "this is the kind of finding the floor
    # protects." class can never downgrade a finding meeting that bar,
    # regardless of what tier the model wrote. This does NOT independently
    # verify "is a live credential" or "is a real exploit path" beyond what
    # reachable+severity already encode -- those are represented via the
    # Auditor's severity/reachable judgment, not via a separate mechanical
    # signal this parser has no field to check. If that distinction matters
    # to a future reader: reachable+high/critical is the enforced floor;
    # "live credential" / "real exploit path" specifically is prompt-level
    # instruction to the Auditor for HOW to set reachable/severity, not a
    # second mechanical predicate over different fields.
    if reachable == "yes" and severity in ("high", "critical"):
        tier = "blocking"
    findings.append({
        "file": fname,
        "line": lineno,
        "category": cwe,
        "message": title,
        "severity": severity,
        "reachable": reachable,
        "tier": tier,
        "class": change_class,
    })
print(json.dumps(findings))
PYEOF
  else
    printf '[]'
  fi
}

# _sanitize_adversarial_findings_json JSON_ARRAY
#
# SECURITY (lr-e2b975, mirrors lr-cda4b9): _parse_adversarial_findings above
# is purely structural (header-field extraction) and does not sanitize.
# This is the write-boundary control for the round-trip path
# _parse_adversarial_findings feeds: LLM-authored finding text ->
# last-adversarial-findings.json -> build_gate_summary -> the merge-gate
# system prompt (ds_merge_gate_prompt, llm-client.sh) -- the same shape
# lr-cda4b9 closed for the invariant-feed's file/category/statement fields.
# Without this, a finding whose title contained a forged
# "===END ADVERSARIAL FINDINGS DATA===" marker could survive verbatim into
# the sidecar and attempt to escape the merge-gate prompt's fenced data
# block.
#
# Calls _llm_field_sanitize itself, once per finding per string field — the
# exact same function _invariant_feed_append calls, invoked as a normal
# shell function call (not a reimplementation, not a copy of its logic).
# JSON decomposition/rebuild is jq (this codebase's primary JSON tool
# everywhere else in gates.sh); python3 is the documented fallback the rest
# of the file already uses for JSON when jq is absent.
#
# Per-field disposition (audited lr-e2b975 follow-up, RE-AUDITED lr-33958f
# PR-C fold-in per BOBBIE's explicit instruction not to fix 2.5/2.7 narrowly
# and leave a third field of the same shape unaudited — every field in the
# parsed finding record, enumerated deliberately rather than asserted):
#   file, category, message — free-form model text, no enum, unbounded
#     length. SANITIZED here via _llm_field_sanitize. `file` specifically is
#     ALSO structurally constrained one layer up, in
#     _parse_adversarial_findings itself (lr-33958f PR-C fold-in, Class
#     2.5): the file:line header field is extracted via an ANCHORED regex
#     (`^(.+):(\d+)$`) that only recognizes a genuine trailing line number,
#     never an unanchored `rpartition(":")` that would treat any colon
#     anywhere in the field as a line-number separator. That constraint is
#     about SHAPE (does this look like a real file:line pair), not content
#     — `file`'s content is still free text and still goes through
#     _llm_field_sanitize here exactly like category/message; the two
#     protections are independent and both apply.
#   severity  — closed set (low/medium/high/critical). ENUM-VALIDATED AND
#     FORCE-CORRECTED at parse time in _parse_adversarial_findings (an
#     unrecognized value becomes "unknown", never passed through raw). NOT
#     additionally routed through _llm_field_sanitize here, because after
#     that fix it can only ever be one of five fixed literals — there is no
#     free text left to sanitize. This was NOT true before the fix that
#     accompanies this comment: severity used to be captured as unvalidated
#     free text bounded only by the next "|" in the header line, which was a
#     real gap (same fence-escape shape as file/category/message) that a
#     prior version of this comment incorrectly asserted was already closed.
#     If you are re-reading this after touching the severity regex capture,
#     re-verify the enum check in _parse_adversarial_findings still runs
#     before trusting this comment again.
#   reachable — closed set (yes/no). ENUM-VALIDATED AND FORCE-CORRECTED at
#     parse time (unrecognized/absent -> "no"). Same reasoning as severity:
#     no free text left after parsing, nothing for this function to do.
#   tier      — closed set (blocking/advisory). ENUM-VALIDATED AND
#     FORCE-CORRECTED at parse time: (unrecognized/absent -> "advisory");
#     forced to "advisory" whenever reachable != "yes"; and, as of the
#     lr-4f8316 follow-up, forced to "blocking" whenever reachable == "yes"
#     AND severity is high/critical, REGARDLESS of class or of whatever tier
#     value the model wrote — this is the mechanical security-floor clamp,
#     not LLM self-restraint. Same reasoning as severity/reachable on the
#     "no free text left, nothing for this function to do" point.
#   class     — closed set (durable/ephemeral, lr-4f8316). ENUM-VALIDATED AND
#     FORCE-CORRECTED at parse time (unrecognized/absent -> "durable" — the
#     class that does NOT relax the blocking threshold, so a parser gap can
#     only ever leave the full bar in place, never silently grant a
#     downgrade). Same reasoning as severity/reachable/tier: after
#     validation there is no free text left in the field. class CAN
#     influence tier (a durability-only finding at reachable:yes but
#     medium/low severity may legitimately stay advisory under either
#     class), but it can never OVERRIDE the security-floor clamp above —
#     the clamp runs unconditionally after class is resolved, so an
#     ephemeral declaration cannot buy a downgrade on a finding the clamp's
#     predicate already caught.
#   line      — always an int (lr-33958f PR-C fold-in, Class 2.5: extracted
#     via the SAME anchored `^(.+):(\d+)$` match as `file` above — the
#     digit-only trailing group means int() on the captured text can never
#     raise, unlike the pre-fix `rpartition(":")` + try/except ValueError
#     shape, which relied on the exception path to reject a non-numeric
#     trailing segment rather than never matching one to begin with). Falls
#     back to 0 when fileline does not match the anchored pattern at all
#     (no colon, e.g. "general"; a colon with non-numeric or empty trailing
#     text). Not text; nothing to sanitize; not enum-shaped either, so
#     "validated" isn't quite the right word — it is type-and-shape-
#     constrained by construction (regex match + Python int(), never a
#     pass-through of the captured string).
#
# Net: every field is either free-text-and-sanitized (file/category/message)
# or closed-set-and-force-corrected-at-parse-time (severity/reachable/tier/
# class) or non-text-by-construction (line). There is no field in this
# record that is "probably fine" or asserted-safe-without-a-mechanism — each
# one has an actual enforcement point, named above, that a future change to
# this function or to _parse_adversarial_findings should re-verify still
# holds before relying on this comment again.
_sanitize_adversarial_findings_json() {
  _safj_json="$1"
  # Thin wrapper over the shared decompose/sanitize/rebuild helper
  # (_llm_json_array_sanitize_fields, platform.sh, lr-4f8316 follow-up) --
  # this function used to carry its own duplicated jq/python3
  # decompose-sanitize-rebuild loop; that loop is now the shared machinery
  # a second caller (the deferrals array, ds_review_prompt in llm-client.sh)
  # reuses instead of hand-rolling a variant. Behavior is unchanged: every
  # finding's file/category/message field is sanitized via
  # _llm_field_sanitize, exactly as before.
  _llm_json_array_sanitize_fields "$_safj_json" file category message
}

cmd_adversarial() {
  OUT="$REPO_ROOT/.clagentic/lite/last-adversarial.md"
  FINDINGS_OUT="$REPO_ROOT/.clagentic/lite/last-adversarial-findings.json"
  _adv_diff_tmp=$(mktemp -t clagentic-adv-diff.XXXXXX)
  get_review_diff > "$_adv_diff_tmp"
  # STATUS-CHECKED + DEGRADED-CHECKED (lr-7047bf, INV-1b): this used to be
  # THE WORST site in the class -- no check of any kind. A fully-dead
  # auditor wrote a degraded markdown envelope, _parse_adversarial_findings
  # found zero [FINDING] headers (a dead auditor and a genuinely clean diff
  # were indistinguishable), build_gate_summary reported
  # adversarial_blocking_count 0 and resolved_change_class null, and the
  # merge-gate was told the audit was CLEAN. Capture the real exit status
  # AND check the markdown-mode degraded marker (the mode-complete detector
  # this task adds, _llm_output_is_degraded -- the markdown shape had no
  # detector anywhere in the repo before this) BEFORE the SHA-stamp prepend
  # below mutates $OUT's first line.
  _adv_status=0
  "$TOOL_HOME/scripts/llm-client.sh" adversarial < "$_adv_diff_tmp" > "$OUT" || _adv_status=$?
  _adv_degraded=0
  # STATUS 4 (lr-33958f, PR-C): walk_chain's second degraded exit status,
  # the "unwrap" cause -- also checked here alongside 3 so an auditor that
  # ran successfully but returned unparseable output is not missed by this
  # detector (see llm-client.sh walk_chain's DEGRADED_EXIT comment).
  # STATUS 5 (class-4 foundry fix): walk_chain's THIRD degraded exit status,
  # the "turns-exhausted" cause -- a truncated auditor run must never be
  # indistinguishable from a genuinely clean pass.
  if [ "$_adv_status" -eq 3 ] || [ "$_adv_status" -eq 4 ] || [ "$_adv_status" -eq 5 ] || _llm_output_is_degraded markdown "$OUT"; then
    _adv_degraded=1
  fi
  # Prepend a SHA stamp comment as the first line so build_gate_summary can
  # detect stale payloads. Best-effort: skip if git unavailable or SHA empty.
  # Repo-scoped (lr-da1f28 sweep): see _git_repo_scoped_head_sha's doc
  # comment for why a bare `_git rev-parse HEAD` is not sufficient here.
  _adv_sha=$(_git_repo_scoped_head_sha)
  if [ -n "$_adv_sha" ]; then
    _adv_tmp=$(mktemp -t clagentic-adv-stamp.XXXXXX)
    printf '<!-- clagentic-diff-sha: %s -->\n' "$_adv_sha" > "$_adv_tmp"
    cat "$OUT" >> "$_adv_tmp"
    mv "$_adv_tmp" "$OUT"
  fi

  # Structured findings sidecar (lr-e2b975): loose-parse [FINDING] headers
  # into {file,line,category,message,severity,reachable,tier} JSON,
  # unconditionally (not gated behind CLAGENTIC_ADVERSARIAL_INVARIANTS — the
  # advisory/blocking split is a base behavior, not opt-in). This is what
  # build_gate_summary reads to give the merge-gate a mechanical count of
  # tier:blocking vs tier:advisory findings instead of asking the LLM to
  # re-derive the split from markdown prose. The markdown in $OUT remains
  # the full human-readable record either way — this sidecar never replaces
  # it, only adds a structured view for gate plumbing.
  #
  # SECURITY (lr-e2b975): sanitize immediately after parsing, before the
  # sidecar is written to disk or handed to dedup/invariant-feed below —
  # every downstream consumer of $_adv_findings_json then gets clean data
  # for free, matching _llm_field_sanitize's own write-boundary-not-
  # read-time design rationale. The unsanitized $OUT markdown file is
  # untouched (still the full raw record); only the structured sidecar that
  # round-trips into a later system prompt is sanitized.
  # COUNT BOUND AT EMISSION (lr-33958f, PR-C, required foundry fix):
  # _parse_adversarial_findings builds its array with no count bound of its
  # own, and that array is embedded TWICE into the merge-gate system
  # prompt (adversarial_findings and adversarial_findings_fenced,
  # build_gate_summary below) -- the foundry ranked this the single most
  # likely source of the next unreported filing, the sibling repo's
  # seven-occurrence verdict-fence class restated as an emission-side cap
  # rather than a parse-time presence check. Capped AFTER sanitize (order
  # matches _invariant_feed_append's own sanitize-then-cap sequencing) so
  # every retained finding is still clean.
  #
  # SEVERITY/TIER-SORTED BEFORE THE CAP (BOBBIE, lr-33958f PR-C fold-in
  # review, bobbie.sast.unbounded-truncation-drops-severity): capping in
  # raw PARSE order (the pre-fix behavior) truncates in the order the
  # Auditor's markdown lists findings -- attacker-influenceable via prompt
  # injection in the diff under review, so a late-emitted tier:"blocking"
  # finding could be silently dropped while earlier tier:"advisory"
  # findings survive. _adversarial_findings_sort_blocking_first
  # (platform.sh) reorders tier:"blocking" findings first, severity
  # descending within each tier, BEFORE _llm_json_array_cap ever runs --
  # the cap can then only ever drop the least-severe, non-blocking tail.
  # PARSE-READ-FAILURE CLASSIFICATION (BOBBIE, lr-33958f PR-C fold-in
  # review, Class 2.7): _parse_adversarial_findings now exits nonzero (with
  # nothing on stdout) on a genuine read failure -- a readable file with
  # zero [FINDING] headers (an ordinary clean audit) still exits 0 with
  # "[]". Guarded explicitly (`set -e` is active in this script) so a read
  # failure is CLASSIFIED, not silently treated as "the parser produced an
  # empty findings array" -- the same fail-open-by-writing-empty-data class
  # BOBBIE blocked on twice in PR-B (lr-7047bf). A read failure here is
  # distinct from _adv_degraded above (that covers the LLM chain itself
  # failing to produce output at all); this covers the parse step failing
  # on output that DID get written moments earlier in this same function.
  _adv_parse_status=0
  _adv_findings_json_raw=$(_parse_adversarial_findings "$OUT") || _adv_parse_status=$?
  if [ "$_adv_parse_status" -ne 0 ]; then
    cmd_log_run adversarial degraded "adversarial-findings-parse-failed: could not read $OUT to extract structured findings (status=$_adv_parse_status) — sidecar not trustworthy"
    echo "[gates/adversarial] ADVERSARIAL_FINDINGS_PARSE_FAILED: could not read $OUT to extract structured [FINDING] headers — the markdown audit above may still be valid, but the structured sidecar the merge-gate reads could not be built. Check filesystem/permissions." 1>&2
    _adv_findings_json_raw='[]'
  fi
  _adv_findings_json_sanitized=$(_sanitize_adversarial_findings_json "$_adv_findings_json_raw")
  _adv_findings_json_sorted=$(_adversarial_findings_sort_blocking_first "$_adv_findings_json_sanitized")
  _adv_findings_json=$(_llm_json_array_cap "$_adv_findings_json_sorted" "${CLAGENTIC_ADVERSARIAL_FINDINGS_MAX:-200}")
  printf '%s\n' "$_adv_findings_json" > "$FINDINGS_OUT"

  # DROPPED-COUNT VISIBILITY (BOBBIE, lr-33958f PR-C fold-in review): a
  # truncated audit must never be silently presented as complete. Compute
  # how many findings the cap actually dropped (pre-cap count minus
  # post-cap count -- both read from the already-materialized JSON, no
  # re-parse) and persist it to a small sidecar build_gate_summary reads,
  # so the merge-gate payload can surface "N findings dropped by the count
  # cap" instead of a bare capped array that looks indistinguishable from
  # "the auditor only found this many." Logged to the audit trail and
  # stderr whenever nonzero; the sidecar itself always exists so
  # build_gate_summary has a single, unconditional read path (0 on a
  # normal run, same "absent == 0" fail-open posture as every other
  # optional gate-plumbing file in this codebase).
  _adv_findings_dropped_count=0
  if command -v jq >/dev/null 2>&1; then
    _adv_findings_total_before_cap=$(printf '%s' "$_adv_findings_json_sorted" | jq 'length' 2>/dev/null || echo 0)
    _adv_findings_total_after_cap=$(printf '%s' "$_adv_findings_json" | jq 'length' 2>/dev/null || echo 0)
  elif command -v python3 >/dev/null 2>&1; then
    _adv_findings_total_before_cap=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else 0)' <<EOF2 2>/dev/null || echo 0
$_adv_findings_json_sorted
EOF2
)
    _adv_findings_total_after_cap=$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d, list) else 0)' <<EOF3 2>/dev/null || echo 0
$_adv_findings_json
EOF3
)
  else
    _adv_findings_total_before_cap=0
    _adv_findings_total_after_cap=0
  fi
  case "$_adv_findings_total_before_cap" in ''|*[!0-9]*) _adv_findings_total_before_cap=0 ;; esac
  case "$_adv_findings_total_after_cap" in ''|*[!0-9]*) _adv_findings_total_after_cap=0 ;; esac
  if [ "$_adv_findings_total_before_cap" -gt "$_adv_findings_total_after_cap" ]; then
    _adv_findings_dropped_count=$((_adv_findings_total_before_cap - _adv_findings_total_after_cap))
  fi
  printf '{"dropped_count": %d, "total_before_cap": %d}\n' \
    "$_adv_findings_dropped_count" "$_adv_findings_total_before_cap" \
    > "$REPO_ROOT/.clagentic/lite/last-adversarial-findings-meta.json"
  if [ "$_adv_findings_dropped_count" -gt 0 ]; then
    cmd_log_run adversarial warn "adversarial findings count cap dropped $_adv_findings_dropped_count finding(s) (severity/tier-sorted before cap, so only the least-severe tail was dropped)"
    printf '[gates/adversarial] %d finding(s) dropped by the count cap (CLAGENTIC_ADVERSARIAL_FINDINGS_MAX=%s) -- lowest severity/advisory-tier findings only, sorted before truncation.\n' \
      "$_adv_findings_dropped_count" "${CLAGENTIC_ADVERSARIAL_FINDINGS_MAX:-200}" 1>&2
  fi

  # Invariant-feed writer (lr-63359e), adversarial half. Reuses the same
  # parsed findings above (previously re-parsed only inside this if-block;
  # now shared with the sidecar write above). Reuses dedup_findings'
  # content-hash key derivation via a dedicated seen-keys file for the
  # adversarial modality (adversarial does not otherwise participate in
  # cross-round dedup — CLAGENTIC_CROSS_ROUND_DEDUP only wires into
  # cmd_review — so this is the first time an adversarial round's findings
  # are content-hash-keyed at all, not a second dedup layer competing with
  # an existing one).
  if [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ]; then
    _adv_seen_file="$REPO_ROOT/.clagentic/lite/adversarial-seen-keys"
    [ -f "$_adv_seen_file" ] || touch "$_adv_seen_file"
    _adv_prior_seen_snap=$(mktemp -t clagentic-inv-adv-prior.XXXXXX)
    cp "$_adv_seen_file" "$_adv_prior_seen_snap" 2>/dev/null || : > "$_adv_prior_seen_snap"

    # dedup_findings' return value is unused here — we only want it to
    # persist this round's keys into _adv_seen_file (same side effect
    # _cross_round_dedup relies on for the review path); the deduped
    # markdown stdout is never re-derived from JSON, so we discard it.
    printf '%s' "$_adv_findings_json" | dedup_findings "content-hash" "$_adv_seen_file" "$_adv_diff_tmp" >/dev/null 2>&1 || true
    _invariant_feed_write adversarial "$_adv_findings_json" "$_adv_diff_tmp" "$_adv_prior_seen_snap" "$_adv_seen_file"
    rm -f "$_adv_prior_seen_snap"
  fi
  rm -f "$_adv_diff_tmp"

  # cmd_adversarial can no longer report a clean audit when the auditor was
  # dead. A degraded emission is a distinct, mechanically-detectable outcome
  # ("degraded") from an ordinary non-blocking pass ("warn") -- both land in
  # the audit trail, but only the degraded case returns non-zero. Existing
  # non-blocking-by-design behavior (cmd_ship runs this as
  # `cmd_adversarial || true`, docs/GATES.md) is preserved for the outcome
  # this gate was actually designed to be non-blocking for (real findings,
  # or a clean pass); it is NOT preserved silently for "the auditor never
  # ran" -- that distinction is now visible on both the exit status and the
  # audit row, and it is the caller's explicit `|| true` that decides
  # whether a dead auditor still lets ship proceed.
  if [ "$_adv_degraded" -eq 1 ]; then
    # markdown mode carries no JSON "cause" field -- _adv_status itself is
    # authoritative here (4 = unwrap cause is unambiguous on its own; see
    # _llm_degraded_cause's own doc comment for why STATUS is checked
    # first, before any file-content fallback).
    _adv_cause=$(_llm_degraded_cause "$_adv_status" "$OUT")
    if [ "$_adv_cause" = "unwrap" ]; then
      cmd_log_run adversarial degraded "model-output-unparseable: auditor ran but returned no parseable output (status=$_adv_status)"
      echo "[gates/adversarial] MODEL_OUTPUT_UNPARSEABLE: auditor ran successfully but its output could not be reduced to a parseable audit — no real audit occurred." 1>&2
    elif [ "$_adv_cause" = "turns-exhausted" ]; then
      cmd_log_run adversarial degraded "turns-exhausted: auditor ran out of turns before completing (status=$_adv_status)"
      echo "[gates/adversarial] TURNS_EXHAUSTED: auditor exhausted its turn limit before completing — no real audit occurred." 1>&2
    else
      cmd_log_run adversarial degraded "auditor produced a degraded envelope (status=$_adv_status) — no real audit occurred"
      echo "[gates/adversarial] INFRA_DEGRADED: auditor chain returned a degraded envelope — no real audit occurred." 1>&2
    fi
    _llm_degraded_remediation_lines "$_adv_cause" 1>&2
    echo "[gates/adversarial] full details: $OUT  |  scripts/gates.sh digest" 1>&2
    cat "$OUT"
    return 2
  fi
  cmd_log_run adversarial warn "wrote $OUT (non-blocking)"
  cat "$OUT"
}

# _mg_state_identity — print "<HEAD-SHA>:<content-hash>" for the current
# working tree, or empty if REPO_ROOT is not (provably) a git repo.
#
# ROOT CAUSE (lr-caebc5): gate results previously carried no notion of which
# commit/tree state they validated, only the file mtimes of gate output
# files (last-review.json, last-adversarial.md). Any incidental mtime change
# — a checkout, a stash, an editor save with no content change, a re-run in
# the same session — looked indistinguishable from a real change, so the
# merge-gate re-ran (and re-prompted the operator) every time. mtime is not
# a reliable proxy for "did anything change."
#
# The commit SHA alone is also insufficient: a dirty working tree (staged or
# unstaged edits not yet committed) is the NORMAL state while iterating, not
# an edge case, and two dirty trees on the same HEAD can differ. So the
# identity is HEAD SHA plus a content hash of the in-scope diff:
#   - `git diff HEAD` captures staged AND unstaged changes to tracked files
#     relative to HEAD (empty string on a clean tree).
#   - `git status --porcelain` captures untracked files (added test/data
#     files git diff would not otherwise reflect) without depending on any
#     file's mtime — porcelain output is derived from content/index state.
# Both are hashed together via the existing _rm_sha256 shim (review-merge.sh)
# used by dedup_findings/_review_deferral_match for the exact same
# fingerprint-content-not-timestamps reason. Symlink/toplevel canonicalization
# delegates to _git_repo_scoped_head_sha (gates.sh, near the _git
# definition), not a locally-duplicated inline check (lr-da1f28 sweep — this
# used to hand-roll the same canonicalize-and-compare logic the --recheck
# guard below also hand-rolled; both now share one implementation).
_mg_state_identity() {
  _mgsi_head=$(_git_repo_scoped_head_sha)
  [ -n "$_mgsi_head" ] || return 0
  _mgsi_content_hash=$( { _git diff HEAD 2>/dev/null; _git status --porcelain 2>/dev/null; } | _rm_sha256)
  printf '%s:%s' "$_mgsi_head" "$_mgsi_content_hash"
}

cmd_merge_gate() {
  # Final LLM sanity check: feed gate outputs back through the merge-gate
  # role, which decides approve/refuse. BLOCKING BY DEFAULT — set
  # CLAGENTIC_MERGE_GATE_BLOCKING=0 to make a 'refuse' decision advisory only.
  #
  # --recheck: skip build_gate_summary and re-feed the existing gate-summary.json
  # directly to the LLM. Use after a transient LLM failure when the summary was
  # already built fresh in the same session and you do not need to re-run review
  # or adversarial. Does NOT bypass CLAGENTIC_MERGE_GATE_BLOCKING.
  _mg_recheck=0
  for _mg_arg in "$@"; do
    case "$_mg_arg" in
      --recheck) _mg_recheck=1 ;;
    esac
  done

  IN="$REPO_ROOT/.clagentic/lite/gate-summary.json"
  OUT="$REPO_ROOT/.clagentic/lite/last-merge-gate.json"

  # STATE-IDENTITY CACHE (lr-caebc5): if the current commit+content state
  # already has a recorded PASS in the audit trail, this invocation is a
  # no-op — report the cached pass and return without calling the LLM or
  # touching last-merge-gate.json. This is what stops repeated re-prompts on
  # unchanged content: a re-run for the same state is now provably a repeat
  # of work already done, not a fresh judgment call. Only a stored PASS
  # short-circuits; a stored refuse never does, so a real refusal is never
  # silently bypassed by re-running gates merge-gate again.
  _mg_state_id=$(_mg_state_identity)
  if [ -n "$_mg_state_id" ]; then
    _mg_cached=$(ds_sqlite3 -separator '|' "$AUDIT_DB" \
      "SELECT outcome, details FROM gate_runs
       WHERE gate IN ('merge-gate','merge-gate recheck')
       ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")
    if [ -n "$_mg_cached" ]; then
      _mg_cached_outcome=${_mg_cached%%|*}
      _mg_cached_details=${_mg_cached#*|}
      case "$_mg_cached_details" in
        *"[state=${_mg_state_id}]"*)
          if [ "$_mg_cached_outcome" = "pass" ]; then
            printf '[gates/merge-gate] already passed for this exact commit+content state — no-op (state=%s)\n' "$_mg_state_id" 1>&2
            if [ -f "$OUT" ]; then
              cat "$OUT"
            else
              printf '{"decision": "approve", "reason": "cached pass for unchanged state %s"}\n' "$_mg_state_id"
            fi
            return 0
          fi
          ;;
      esac
    fi
  fi

  if [ "$_mg_recheck" = "1" ]; then
    # Recheck path: gate-summary.json must already exist.
    if [ ! -f "$IN" ]; then
      printf '[gates/merge-gate] no gate-summary.json found — run gates merge-gate without --recheck first\n' 1>&2
      cmd_log_run "merge-gate recheck" block "gate-summary.json not found"
      return 1
    fi

    # SHA-staleness guard: --recheck is for retrying a transient LLM failure,
    # not for replaying an old summary against a new commit. Read the SHA
    # stamped inside gate-summary.json (review._clagentic_diff_sha, written by
    # _stamp_envelope via build_gate_summary) and compare it to HEAD. Refuse
    # if the SHA is missing or mismatches — the caller must rebuild first.
    #
    # HEAD resolution goes through _git_repo_scoped_head_sha (gates.sh, near
    # the _git definition), not a bare `_git rev-parse HEAD`: see that
    # helper's doc comment for the full ancestor-walk-up / symlinked-REPO_ROOT
    # rationale (lr-4a3f88 and follow-up, lr-da1f28 sweep — this was the
    # original call site the fix was built for; the logic now lives in the
    # shared helper so the other call sites needing it don't duplicate it).
    _mg_summary_sha=""
    _mg_head_sha=$(_git_repo_scoped_head_sha)
    if [ -n "$_mg_head_sha" ]; then
      if command -v jq >/dev/null 2>&1; then
        _mg_summary_sha=$(jq -r '.review._clagentic_diff_sha // ""' "$IN" 2>/dev/null || echo "")
      elif command -v python3 >/dev/null 2>&1; then
        _mg_summary_sha=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    rv = d.get("review") or {}
    print(rv.get("_clagentic_diff_sha", ""))
except Exception:
    print("")
' "$IN" 2>/dev/null || echo "")
      fi
      if [ -z "$_mg_summary_sha" ] || [ "$_mg_summary_sha" != "$_mg_head_sha" ]; then
        printf '[gates/merge-gate] --recheck refused: gate-summary.json is for %s, HEAD is %s. Run '"'"'gates review'"'"' then '"'"'gates merge-gate'"'"', or '"'"'gates ship'"'"' to rebuild.\n' \
          "${_mg_summary_sha:-<no sha>}" "$_mg_head_sha" 1>&2
        cmd_log_run "merge-gate recheck" block "SHA mismatch: summary=${_mg_summary_sha:-<absent>} head=${_mg_head_sha}"
        return 1
      fi
    fi

    printf '[gates/merge-gate] --recheck: re-feeding existing gate-summary.json to LLM\n' 1>&2
  else
    build_gate_summary > "$IN"
  fi

  # Use a distinct gate name in audit rows so the trail shows recheck vs fresh run.
  if [ "$_mg_recheck" = "1" ]; then
    _mg_gate_name="merge-gate recheck"
  else
    _mg_gate_name="merge-gate"
  fi

  # Detect a gate-summary-degraded envelope FIRST, tool-agnostically. This is
  # site 1.12 (lr-7047bf): build_gate_summary's no-jq/no-python3 fallback
  # writes "gate_summary_degraded": true as a literal, grep-able string
  # specifically because the environment that produced it has no JSON
  # parser -- checking for it here with jq/python3 would be circular (the
  # exact case it flags is the case those tools are absent). A plain
  # substring grep needs no JSON tool at all.
  if grep -qF '"gate_summary_degraded": true' "$IN" 2>/dev/null; then
    printf '{"decision": "refuse", "reason": "gate summary could not be built (no jq or python3 available) — install one or the other to run the merge gate"}\n' > "$OUT"
    cmd_log_run "$_mg_gate_name" block "gate-summary degraded — no JSON tool available to build it"
    cat "$OUT"
    if [ "${CLAGENTIC_MERGE_GATE_BLOCKING:-1}" != "0" ]; then
      return 1
    fi
    return 0
  fi

  # Detect a stale-payload envelope emitted by build_gate_summary.
  # A stale payload means gate artifacts describe a different commit — skip
  # the LLM call entirely (deterministic refusal, no token burn) and write a
  # synthetic refusal to last-merge-gate.json.
  # Note: --recheck skips build_gate_summary entirely, so stale_payload will
  # not be set in the existing gate-summary.json; this check is a no-op on
  # the recheck path but is preserved for safety.
  _stale_check=""
  if command -v jq >/dev/null 2>&1; then
    _stale_check=$(jq -r '.stale_payload // "false"' "$IN" 2>/dev/null || echo "false")
  elif command -v python3 >/dev/null 2>&1; then
    _stale_check=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(str(d.get("stale_payload","false")).lower())' "$IN" 2>/dev/null || echo "false")
  fi
  if [ "${_stale_check}" = "true" ]; then
    printf '{"decision": "refuse", "reason": "stale gate payload — re-run clagentic-lite gates review and gates adversarial first"}\n' > "$OUT"
    cmd_log_run "$_mg_gate_name" block "stale payload — re-run review + adversarial (SHA mismatch)"
    cat "$OUT"
    if [ "${CLAGENTIC_MERGE_GATE_BLOCKING:-1}" != "0" ]; then
      return 1
    fi
    return 0
  fi

  # STATUS-CHECKED (lr-7047bf, INV-1b): guard explicitly -- gates.sh runs
  # under `set -e`, and walk_chain now returns 3 on a degraded emission (see
  # llm-client.sh walk_chain). $_mg_status is checked immediately below
  # alongside the merge-gate's own JSON-mode degraded marker so a degraded
  # emission cannot be read as an ordinary parseable decision.
  _mg_status=0
  "$TOOL_HOME/scripts/llm-client.sh" merge-gate < "$IN" > "$OUT" || _mg_status=$?
  # STATUS 4 (lr-33958f, PR-C): also checked, alongside 3, for the "unwrap"
  # cause -- see llm-client.sh walk_chain's DEGRADED_EXIT comment.
  # STATUS 5 (class-4 foundry fix): also checked for the "turns-exhausted"
  # cause -- a merge-gate decision truncated mid-reasoning must never be
  # read as a real approve/refuse.
  if [ "$_mg_status" -eq 3 ] || [ "$_mg_status" -eq 4 ] || [ "$_mg_status" -eq 5 ] || _llm_output_is_degraded json "$OUT"; then
    _mg_cause=$(_llm_degraded_cause "$_mg_status" "$OUT")
    if [ "$_mg_cause" = "unwrap" ]; then
      cmd_log_run "$_mg_gate_name" block "model-output-unparseable: merge-gate ran but returned no parseable decision (status=$_mg_status)"
      echo "[gates/merge-gate] MODEL_OUTPUT_UNPARSEABLE: merge-gate ran successfully but its output could not be reduced to a parseable decision — no real decision was made." 1>&2
    elif [ "$_mg_cause" = "turns-exhausted" ]; then
      cmd_log_run "$_mg_gate_name" block "turns-exhausted: merge-gate ran out of turns before completing (status=$_mg_status)"
      echo "[gates/merge-gate] TURNS_EXHAUSTED: merge-gate exhausted its turn limit before completing — no real decision was made." 1>&2
    else
      cmd_log_run "$_mg_gate_name" block "infra-degraded: all merge-gate chain steps failed (status=$_mg_status)"
      echo "[gates/merge-gate] INFRA_DEGRADED: merge-gate chain returned a degraded envelope — no real decision was made." 1>&2
    fi
    _llm_degraded_remediation_lines "$_mg_cause" 1>&2
    echo "[gates/merge-gate] full details: $OUT  |  scripts/gates.sh digest" 1>&2
    if [ "${CLAGENTIC_MERGE_GATE_BLOCKING:-1}" != "0" ]; then
      return 1
    fi
    return 0
  fi

  # Resolved change class + downgrade count (lr-4f8316): read back from the
  # gate-summary payload ($IN, the exact input build_gate_summary produced)
  # so the audit trail records which class applied to this ship attempt and
  # how many findings it downgraded — independent of the merge-gate's own
  # decision, since the class is gate plumbing, not a merge-gate judgment
  # call. Empty/unparseable is silently treated as "no class info" (fail-open,
  # matching the rest of this codepath); a missing class never blocks.
  _mg_class=""
  _mg_class_downgraded=0
  if command -v jq >/dev/null 2>&1; then
    _mg_class=$(jq -r '.resolved_change_class // ""' "$IN" 2>/dev/null || echo "")
    _mg_class_downgraded=$(jq -r '.adversarial_downgraded_by_class_count // 0' "$IN" 2>/dev/null || echo 0)
  elif command -v python3 >/dev/null 2>&1; then
    _mg_class=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d.get("resolved_change_class"); print(v if v else "")' "$IN" 2>/dev/null || echo "")
    _mg_class_downgraded=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("adversarial_downgraded_by_class_count",0))' "$IN" 2>/dev/null || echo 0)
  fi
  case "$_mg_class_downgraded" in ''|*[!0-9]*) _mg_class_downgraded=0 ;; esac
  _mg_class_suffix=""
  if [ -n "$_mg_class" ]; then
    _mg_class_suffix=" [class=$_mg_class downgraded=$_mg_class_downgraded]"
  fi

  # Recompute the state identity right before logging (not reused from the
  # cache-check above): the LLM call/build_gate_summary happened in between,
  # and stamping the identity actually current at decision time is what
  # makes the next invocation's cache lookup correct, even in the unlikely
  # case the tree changed mid-run.
  _mg_state_id_now=$(_mg_state_identity)
  _mg_state_suffix=""
  if [ -n "$_mg_state_id_now" ]; then
    _mg_state_suffix=" [state=${_mg_state_id_now}]"
  fi

  DECISION=""
  if command -v jq >/dev/null 2>&1; then
    DECISION=$(jq -r '.decision // "unknown"' "$OUT" 2>/dev/null)
  elif command -v python3 >/dev/null 2>&1; then
    DECISION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("decision","unknown"))' "$OUT" 2>/dev/null)
  fi
  case "$DECISION" in
    approve)
      ACK_COUNT=0
      ACK_DETAIL=""
      if command -v jq >/dev/null 2>&1; then
        ACK_COUNT=$(jq -r '(.acknowledged // []) | length' "$OUT" 2>/dev/null || echo 0)
        # Serialize per-finding detail (cwe + file + rationale) into the audit
        # details column so the audit trail records WHICH findings were waved
        # through, not just how many. AGENTS.md §6: the audit trail is the artifact.
        if [ "${ACK_COUNT:-0}" -gt 0 ]; then
          ACK_DETAIL=$(jq -r '.acknowledged[] | "\(.cwe) \(.file) — \(.rationale)"' "$OUT" 2>/dev/null | tr '\n' '; ')
        fi
      elif command -v python3 >/dev/null 2>&1; then
        ACK_COUNT=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d.get("acknowledged",[])))' "$OUT" 2>/dev/null || echo 0)
        if [ "${ACK_COUNT:-0}" -gt 0 ]; then
          ACK_DETAIL=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
parts = ["{} {} — {}".format(f.get("cwe",""), f.get("file",""), f.get("rationale","")) for f in d.get("acknowledged",[])]
print("; ".join(parts))
' "$OUT" 2>/dev/null)
        fi
      fi
      if [ "${ACK_COUNT:-0}" -gt 0 ]; then
        _cmd_log_run_checked_pass "$_mg_gate_name" "approve ($ACK_COUNT acknowledged finding(s)): $ACK_DETAIL$_mg_class_suffix$_mg_state_suffix"
      else
        _cmd_log_run_checked_pass "$_mg_gate_name" "approve$_mg_class_suffix$_mg_state_suffix"
      fi
      ;;
    refuse)
      cmd_log_run "$_mg_gate_name" block "refuse$_mg_class_suffix"
      cat "$OUT"
      # Default blocking; set CLAGENTIC_MERGE_GATE_BLOCKING=0 to override.
      if [ "${CLAGENTIC_MERGE_GATE_BLOCKING:-1}" != "0" ]; then
        return 1
      fi
      ;;
    *)
      # An unparseable decision is a failure of the merge gate itself.
      # Fail closed unless explicitly opted out — same rationale as missing
      # security tools above.
      cmd_log_run "$_mg_gate_name" block "decision=$DECISION (unparseable)"
      cat "$OUT" 1>&2
      if [ "${CLAGENTIC_MERGE_GATE_BLOCKING:-1}" != "0" ]; then
        return 1
      fi
      ;;
  esac
  return 0
}

# Severity helpers — POSIX ordering: low < medium < high < critical.
severity_rank() {
  case "$1" in
    low)      echo 1 ;;
    medium)   echo 2 ;;
    high)     echo 3 ;;
    critical) echo 4 ;;
    *)        echo 0 ;;
  esac
}

# ISSUE_CLASS / CLASS_FIX (lr-3eb18c): deliberately NOT read anywhere in
# this function. issue_class/class_fix are mandatory-but-non-blocking by
# design (presence is enforced by validate_output, scripts/llm-client.sh) --
# an unresolved class escalation must never become a new way to gate /ship.
# Do not add either field to this function's selection logic.
severity_blockers() {
  FILE="$1"; THRESHOLD="$2"
  TR=$(severity_rank "$THRESHOLD")
  [ "$TR" -eq 0 ] && TR=3   # default to 'high' on unknown threshold
  # Parse-failure policy: ALWAYS fail closed. The sentinel value 99 trips
  # the caller's `> 0` block check unambiguously. Three branches that
  # could fail (jq parse, python3 parse, no validator at all) all return
  # 99 — there is no path where an unparseable review counts as "clean."
  # Severity strings are normalized case-insensitively. LLM models routinely
  # return "HIGH" or "CRITICAL" uppercase — without normalization these rank
  # 0 (unknown) and blocking findings silently pass.
  #
  # _recurrence_demoted exclusion (lr-66e598): a finding _review_recurrence_demote
  # annotated with _recurrence_demoted: true is excluded from this count —
  # this IS the mechanism that makes recurrence demotion a threshold change
  # rather than suppression: the finding stays in .findings (still counted,
  # still rendered by cmd_render_review, still in the audit trail) with its
  # honest severity untouched; it simply no longer contributes to whether
  # /ship blocks. A finding without the annotation (feature off, or key
  # uncomputable that round) is counted exactly as before — the exclusion is
  # additive and only ever REDUCES the blocker count, never increases it.
  #
  # _deferral_matched exclusion (lr-2ebc41): identical mechanism, second
  # source. A finding _review_deferral_match annotated with
  # _deferral_matched: true matched a LIVE (file-hash-verified) operator
  # deferral and is likewise excluded from this count — see that function's
  # doc comment for the full match-key/lapse/fail-closed rationale. Composes
  # additively with the recurrence exclusion above (a finding can be
  # excluded by either, neither, or in principle both; either annotation
  # alone is sufficient).
  if command -v jq >/dev/null 2>&1; then
    R=$(jq -r --argjson tr "$TR" '
      def rank(s):
        (s // "" | ascii_downcase) as $s
        | if $s == "critical" then 4
        elif $s == "high" then 3
        elif $s == "medium" then 2
        elif $s == "low" then 1
        else 0 end;
      [(.findings // [])[] | select(rank(.severity) >= $tr and (._recurrence_demoted // false) != true and (._deferral_matched // false) != true)] | length
    ' "$FILE" 2>/dev/null)
    if [ -z "$R" ]; then echo 99; else echo "$R"; fi
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$FILE" "$TR" <<'PY'
import json, sys
ranks = {"low":1,"medium":2,"high":3,"critical":4}
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print(99); sys.exit(0)
tr = int(sys.argv[2])
print(sum(
    1 for f in d.get("findings", [])
    if ranks.get(str(f.get("severity","")).lower(),0) >= tr
    and f.get("_recurrence_demoted") is not True
    and f.get("_deferral_matched") is not True
))
PY
  else
    # No validator at all — fail closed. Sentinel 99 makes the audit-row
    # message ("99 finding(s) at >= high") visibly unusual so users know
    # this is "blocked because the gate couldn't read the review" rather
    # than a model that legitimately found 99 issues.
    echo 99
  fi
}

# _fence_adversarial_findings JSON_ARRAY — render an (already sanitized)
# adversarial-findings JSON array as a JSON string value, human-readable and
# wrapped in the ===BEGIN/END ADVERSARIAL FINDINGS DATA=== fence
# ds_merge_gate_prompt (llm-client.sh) instructs the Merge Gate to treat as
# data, not instructions. Mirrors ds_adversarial_prompt's own
# ===BEGIN/END INVARIANTS DATA=== fence framing (lr-cda4b9) for the
# equivalent round-trip shape. Assumes the input is already sanitized
# (_sanitize_adversarial_findings_json, called by cmd_adversarial before the
# sidecar is ever written) — this function only renders and fences, it does
# not sanitize a second time.
_fence_adversarial_findings() {
  _faf_json="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -Rs '.' <<EOF
===BEGIN ADVERSARIAL FINDINGS DATA===
$(printf '%s' "$_faf_json" | jq '.' 2>/dev/null || printf '%s' "$_faf_json")
===END ADVERSARIAL FINDINGS DATA===
EOF
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys
raw = sys.argv[1]
try:
    pretty = json.dumps(json.loads(raw), indent=2)
except Exception:
    pretty = raw
block = "===BEGIN ADVERSARIAL FINDINGS DATA===\n" + pretty + "\n===END ADVERSARIAL FINDINGS DATA==="
print(json.dumps(block))
' "$_faf_json"
    return 0
  fi
  printf '""'
}

# _read_deterministic_gates (lr-367a21) — INFORMATIONAL ONLY.
#
# Reads the latest gate_runs row for each deterministic gate (secrets, deps,
# sast) from audit.db and prints a JSON object on stdout:
#
#   {"secrets": {"outcome": "pass", "details": "..."}, "deps": null,
#    "sast": {"outcome": "warn", "details": "..."}, "audit_db_unavailable": false}
#
# A gate with no row at all (never ran) is null — distinct from an outcome
# string, so the payload can tell "absent" apart from any real outcome
# (pass/warn/skip/block). Nothing here changes a merge decision: this
# function only reads what cmd_secrets/cmd_deps/cmd_sast already wrote via
# cmd_log_run; it does not re-run them, does not re-derive their outcome,
# and its own read failure never blocks (see below).
#
# DEGRADE, NEVER BLOCK (same pattern as gates.sh:3258's per-step-failure
# hint read, and platform.sh's ds_audit_log/ds_sqlite3 -- audit-db access is
# best-effort by contract everywhere else in this codebase). No sqlite3, no
# audit.db, or an unreadable/corrupt DB all degrade the same way: every gate
# field is null and audit_db_unavailable is true. build_gate_summary's
# callers (cmd_merge_gate, ds_merge_gate_prompt) proceed to the LLM call
# exactly as they do today when this block is entirely absent -- adding this
# field never introduces a new fail-closed path.
_read_deterministic_gates() {
  _rdg_db="$REPO_ROOT/.clagentic/lite/audit.db"
  _rdg_unavailable=false
  _rdg_secrets='null'
  _rdg_deps='null'
  _rdg_sast='null'
  if [ -f "$_rdg_db" ] && command -v sqlite3 >/dev/null 2>&1; then
    for _rdg_gate in secrets deps sast; do
      _rdg_row=$(ds_sqlite3 -separator '|' "$_rdg_db" \
        "SELECT outcome, details FROM gate_runs WHERE gate='$_rdg_gate' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")
      if [ -n "$_rdg_row" ]; then
        _rdg_outcome=$(printf '%s' "$_rdg_row" | cut -d'|' -f1)
        _rdg_details=$(printf '%s' "$_rdg_row" | cut -d'|' -f2-)
        if command -v jq >/dev/null 2>&1; then
          _rdg_entry=$(jq -cn --arg o "$_rdg_outcome" --arg d "$_rdg_details" '{"outcome": $o, "details": $d}')
        elif command -v python3 >/dev/null 2>&1; then
          _rdg_entry=$(python3 -c 'import json,sys; print(json.dumps({"outcome": sys.argv[1], "details": sys.argv[2]}))' "$_rdg_outcome" "$_rdg_details")
        else
          # No JSON encoder to safely build the entry -- degrade this gate's
          # field to null rather than risk unescaped interpolation; the
          # caller's own no-JSON-tool branch already marks the whole payload
          # gate_summary_degraded in this case.
          _rdg_entry='null'
        fi
        case "$_rdg_gate" in
          secrets) _rdg_secrets="$_rdg_entry" ;;
          deps) _rdg_deps="$_rdg_entry" ;;
          sast) _rdg_sast="$_rdg_entry" ;;
        esac
      fi
    done
  else
    _rdg_unavailable=true
  fi
  printf '{"secrets": %s, "deps": %s, "sast": %s, "audit_db_unavailable": %s}' \
    "$_rdg_secrets" "$_rdg_deps" "$_rdg_sast" "$_rdg_unavailable"
}

build_gate_summary() {
  RV="$REPO_ROOT/.clagentic/lite/last-review.json"
  AD="$REPO_ROOT/.clagentic/lite/last-adversarial.md"
  ADF="$REPO_ROOT/.clagentic/lite/last-adversarial-findings.json"
  # ADF_META (BOBBIE, lr-33958f PR-C fold-in review): cmd_adversarial's
  # dropped-count sidecar (see the "DROPPED-COUNT VISIBILITY" comment at its
  # write site) -- a truncated audit must never be silently presented as
  # complete. Absent/unparseable degrades to dropped_count=0, matching the
  # rest of this function's fail-open posture on optional gate-plumbing
  # files: a missing meta file predates this feature, not evidence of a
  # truncation that actually happened.
  ADF_META="$REPO_ROOT/.clagentic/lite/last-adversarial-findings-meta.json"
  ACKS_FILE="$REPO_ROOT/.clagentic/adversarial-acks.json"
  AR_FILE="$REPO_ROOT/.clagentic/accepted-risks.md"
  THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"
  # ADVERSARIAL_DEGRADED (lr-7047bf, cmd_adversarial fold-in): cmd_adversarial
  # now writes a degraded markdown envelope AND a fresh (matching) SHA stamp
  # when the auditor chain failed -- a dead auditor is NOT "file absent"
  # (ADVERSARIAL_MISSING) or "stale" (SHA mismatch); it is a third, distinct
  # state this field surfaces to the merge-gate payload so a dead auditor
  # cannot look identical to a clean pass. Default false: only the
  # staleness-check block below (skipped entirely under
  # CLAGENTIC_ALLOW_STALE_PAYLOAD=1) inspects last-adversarial.md's content
  # to set this.
  ADVERSARIAL_DEGRADED=false

  # Staleness check: compare HEAD SHA against the SHA stamped in each gate
  # output file. A mismatch means the file was written against a different
  # commit and the merge-gate would receive stale data. Fail-open for the
  # stamp itself — if no stamp is present the file may predate this feature,
  # which we treat as stale (it could be arbitrarily old).
  #
  # Skip the check when CLAGENTIC_ALLOW_STALE_PAYLOAD=1 (e.g. CI pipelines
  # that write gate artifacts in a prior step, or air-gapped environments).
  # Repo-scoped (lr-da1f28 sweep): see _git_repo_scoped_head_sha's doc
  # comment for why a bare `_git rev-parse HEAD` is not sufficient here — the
  # same ancestor-repo walk-up risk applies to this comparison SHA as to the
  # stamps it's compared against (cmd_review/cmd_adversarial above).
  CURRENT_SHA=$(_git_repo_scoped_head_sha)
  ADVERSARIAL_MISSING=false
  # Fail-closed when REPO_ROOT is a valid git repo but CURRENT_SHA is empty:
  # treat as stale so the merge-gate refuses on incomplete data. Only the
  # genuine non-git case (REPO_ROOT is not itself a git repo) may skip the
  # check. Consistent with the "missing stamp = stale" philosophy at line
  # ~1105. This must use the same toplevel-equality test as
  # _git_repo_scoped_head_sha (via _git_repo_root_is_scoped), not a bare
  # `_git rev-parse --git-dir`: the latter has the identical ancestor-walk-up
  # problem (an ancestor of a non-git REPO_ROOT being a git repo would
  # wrongly report git_dir_ok=1), which would then fail-closed on a repo
  # REPO_ROOT was never part of rather than correctly skipping the check as
  # the genuine non-git case.
  _git_dir_ok=0
  if _git_repo_root_is_scoped; then _git_dir_ok=1; fi
  if [ -z "$CURRENT_SHA" ] && [ "$_git_dir_ok" = "1" ] && [ "${CLAGENTIC_ALLOW_STALE_PAYLOAD:-0}" != "1" ]; then
    printf '{"stale_payload": true, "stale_gates": ["review","adversarial"], "current_sha": "", "review_sha": "", "adversarial_sha": ""}\n'
    return 0
  fi
  if [ -n "$CURRENT_SHA" ] || [ "$_git_dir_ok" = "0" ]; then
    if [ "${CLAGENTIC_ALLOW_STALE_PAYLOAD:-0}" = "1" ]; then
      cmd_log_run merge-gate warn "CLAGENTIC_ALLOW_STALE_PAYLOAD=1: proceeding with potentially stale gate payload"
    else
      STALE_PAYLOAD=false
      STALE_GATES=""

      # Extract SHA from last-review.json.
      _rv_sha=""
      if [ -f "$RV" ]; then
        if command -v jq >/dev/null 2>&1; then
          _rv_sha=$(jq -r '._clagentic_diff_sha // ""' "$RV" 2>/dev/null || echo "")
        elif command -v python3 >/dev/null 2>&1; then
          _rv_sha=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("_clagentic_diff_sha",""))' "$RV" 2>/dev/null || echo "")
        fi
        # File exists: stale if stamp is empty (pre-feature file) OR stamp mismatches.
        if [ -z "$_rv_sha" ] || [ "$_rv_sha" != "$CURRENT_SHA" ]; then
          STALE_PAYLOAD=true
          STALE_GATES="review"
        fi
      fi

      # LEDGER-ANCHORED CHECK (item 4, lr-01ae73): last-review.json's own
      # _clagentic_diff_sha stamp above only ever remembers the SINGLE most
      # recent review run, regardless of whether it passed or blocked, and
      # is silently overwritten by the next run. The ledger is the durable,
      # append-only, verdict-aware record — require its latest entry for the
      # CURRENT branch to be an ANCHORED PASS at CURRENT_SHA, via the one
      # sanctioned predicate (_ledger_anchored_pass_at_head). This is
      # strictly ADDITIONAL to the check above, never a replacement: a
      # last-review.json stamp match with no matching ledger entry (ledger
      # absent entirely, ledger present but with no entry for this branch/
      # SHA, or a ledger write failure) still stales here, and a missing/
      # stale verdict-at-HEAD in EITHER check means "re-review, never
      # proceed" per this task's own item 4. Deliberately NOT exempted when
      # the ledger file is simply absent (PEACHES/coordinator finding on
      # PR #162, comment 5260223912): a "skip when no ledger exists" carve-
      # out is indistinguishable from "ledger deleted to bypass the gate,"
      # and a repo that only ever hand-populates last-review.json without
      # calling cmd_review would sail through this check forever. There is
      # no bootstrap exemption — the very first review on a branch must
      # itself go through cmd_review (which creates the ledger entry as
      # part of that same run) before merge-gate will ever pass.
      #
      # NO-JSON-TOOL EXEMPTION (retained, orthogonal to the above): when
      # neither jq nor python3 is available, _ledger_anchored_pass_at_head
      # cannot read the ledger at all and fails closed (treats it as no
      # anchored pass) -- but this function ALREADY has a dedicated,
      # canonical no-tool signal downstream (the site-1.12 "no JSON encoder
      # available" fallback, which emits `gate_summary_degraded: true`
      # rather than a bare stale-payload refusal, so the merge gate can
      # tell "we could not evaluate this environment at all" apart from "we
      # evaluated it and it's stale"). Pre-empting that with a
      # ledger-driven stale refusal here would collapse that distinction
      # back to a generic staleness message. This is a tooling-availability
      # accommodation, not a verdict bypass: the environment still refuses
      # to approve (gate_summary_degraded routes to a refuse decision, see
      # cmd_merge_gate), it just reports the more specific cause.
      if [ "$STALE_PAYLOAD" != "true" ]; then
        if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
          : # no-json-tool exemption: defer to the canonical gate_summary_degraded path
        else
          _mg_ledger=$(_review_ledger_path)
          _mg_ledger_branch=$(_review_current_branch)
          if ! _ledger_anchored_pass_at_head "$_mg_ledger" "$_mg_ledger_branch" "$CURRENT_SHA"; then
            STALE_PAYLOAD=true
            if [ -n "$STALE_GATES" ]; then
              STALE_GATES="$STALE_GATES review-ledger"
            else
              STALE_GATES="review-ledger"
            fi
          fi
        fi
      fi

      # Extract SHA from last-adversarial.md (first-line comment).
      # Distinguish two cases:
      #   - File absent: not stale; set ADVERSARIAL_MISSING=true and continue.
      #   - File exists but SHA mismatches: stale payload — block.
      _ad_sha=""
      ADVERSARIAL_MISSING=false
      if [ -f "$AD" ]; then
        _ad_sha=$(sed -n '1s/<!-- clagentic-diff-sha: \(.*\) -->/\1/p' "$AD" 2>/dev/null || echo "")
        if [ -z "$_ad_sha" ] || [ "$_ad_sha" != "$CURRENT_SHA" ]; then
          STALE_PAYLOAD=true
          if [ -n "$STALE_GATES" ]; then
            STALE_GATES="$STALE_GATES adversarial"
          else
            STALE_GATES="adversarial"
          fi
        fi
        # ROUTED THROUGH THE HARDENED DETECTOR (BOBBIE finding 1 remainder,
        # lr-7047bf fold-in, PR #141 review #2): this used to be a raw
        # `sed -n '1,2p' | grep -qF '# Degraded output'` -- a second,
        # unhardened copy of _llm_output_is_degraded's own job, with no
        # DEGRADED_MARKER control-byte gate, so a prompt-injected model
        # response that reproduced the banner text verbatim (in either of
        # the two lines checked) would misclassify a real audit as
        # degraded. _llm_output_is_degraded markdown now handles the
        # stamp-shifted (line 2) case itself -- see its own doc comment --
        # so this call site no longer needs to hand-roll the line-1-or-2
        # search.
        if _llm_output_is_degraded markdown "$AD"; then
          ADVERSARIAL_DEGRADED=true
        fi
      else
        # File absent: warn, do not treat as stale. The LLM decides.
        ADVERSARIAL_MISSING=true
        printf '[gates/build-gate-summary] last-adversarial.md not found — proceeding with adversarial=null\n' 1>&2
      fi

      if [ "$STALE_PAYLOAD" = "true" ]; then
        # Emit a minimal stale-payload envelope and return. cmd_merge_gate will
        # detect this and short-circuit before making an LLM call.
        _rv_sha_val="${_rv_sha:-}"
        _ad_sha_val="${_ad_sha:-}"
        # Build stale_gates JSON array.
        _stale_arr=""
        for _sg in $STALE_GATES; do
          if [ -n "$_stale_arr" ]; then
            _stale_arr="${_stale_arr}, \"$_sg\""
          else
            _stale_arr="\"$_sg\""
          fi
        done
        printf '{"stale_payload": true, "stale_gates": [%s], "current_sha": "%s", "review_sha": "%s", "adversarial_sha": "%s"}\n' \
          "$_stale_arr" "$CURRENT_SHA" "$_rv_sha_val" "$_ad_sha_val"
        return 0
      fi
    fi
  fi

  # Detect whether the ack/accepted-risks files are net-new (status A) in the
  # current diff. This flag is passed to the merge-gate to enable the bootstrap
  # exemption without requiring the LLM to infer it from prose. We check both
  # the staged index and the branch diff (same priority as get_review_diff).
  # Failure is fail-open (false) — the flag is informational only.
  _ack_rel=".clagentic/adversarial-acks.json"
  _ar_rel=".clagentic/accepted-risks.md"
  INTRODUCES_ACK_FILE="false"
  _diff_status=""
  # REPO SCOPING (lr-da1f28 sweep): guard before trusting the staged diff —
  # same ancestor-repo leak class as get_review_diff, here feeding the
  # ack-bootstrap-exemption detection instead. Fail-open/informational only
  # (denying the exemption is the safe direction), so an unscoped REPO_ROOT
  # falls through to the branch-diff path below rather than hard-erroring.
  if _git_repo_root_is_scoped && _git diff --cached --name-status 2>/dev/null | grep -q .; then
    _diff_status=$(_git diff --cached --name-status 2>/dev/null || true)
  else
    # FRESHNESS IS A PRECONDITION, NOT AN ASSUMPTION (lr-53dc6e, propagating
    # _gate_resolve_fresh_default_branch_ref's already-hardened form, :132-164,
    # to this site). This used to resolve "origin/${_DEFAULT_BRANCH}" by name
    # with no fetch at all — not even the non-fatal `|| true` fetch
    # get_review_diff had — relying purely on whatever the local
    # tracking ref already happened to be. Delegate to the shared
    # provably-current check rather than trusting presence alone.
    #
    # Fail toward MORE coverage, never a silently narrower diff: on a
    # freshness failure, fall back to the raw name resolution's prior
    # behavior only insofar as it still runs — but with an explicit stderr
    # note so the fail-open ack-bootstrap flag below is not mistaken for a
    # verified read. INTRODUCES_ACK_FILE is documented fail-open/
    # informational-only (it only ENABLES an exemption, denying it is the
    # safe direction), so unlike get_review_diff this site degrades rather
    # than hard-errors — but it must still attempt the verified resolution
    # first, not skip straight to an unverified guess.
    _DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
    _bgs_fetch_timeout="${CLAGENTIC_MERGE_GATE_FETCH_TIMEOUT_SEC:-30}"
    case "$_bgs_fetch_timeout" in ''|*[!0-9]*) _bgs_fetch_timeout=30 ;; esac

    _bgs_fresh_err_tmp=$(mktemp -t clagentic-bgs-fresh-err.XXXXXX)
    _bgs_fresh_tip=$(_gate_resolve_fresh_default_branch_ref "$_DEFAULT_BRANCH" "$_bgs_fetch_timeout" 2>"$_bgs_fresh_err_tmp") || true
    _bgs_fresh_err=$(cat "$_bgs_fresh_err_tmp" 2>/dev/null || echo "")
    rm -f "$_bgs_fresh_err_tmp"

    if [ -n "$_bgs_fresh_tip" ]; then
      _diff_status=$(_git diff "${_bgs_fresh_tip}...HEAD" --name-status 2>/dev/null || true)
    else
      printf '[gates/build-gate-summary] branch baseline not provably current (%s) — ack-bootstrap detection may be incomplete\n' "$_bgs_fresh_err" 1>&2
      _diff_status=""
    fi
  fi
  if printf '%s\n' "$_diff_status" | grep -qE "^A[[:space:]]+(\\.clagentic/adversarial-acks\\.json|\\.clagentic/accepted-risks\\.md)$"; then
    INTRODUCES_ACK_FILE="true"
  fi

  # Prefer jq; fall back to python3; finally degrade to a minimal envelope
  # with the review embedded raw (validated as JSON beforehand) and
  # adversarial dropped (we can't safely escape arbitrary markdown without
  # a JSON encoder).
  if command -v jq >/dev/null 2>&1; then
    RV_PAYLOAD='null'
    AD_PAYLOAD='null'
    ADF_PAYLOAD='[]'
    ACKS_PAYLOAD='[]'
    AR_PAYLOAD='""'
    [ -f "$RV" ] && jq -e . "$RV" >/dev/null 2>&1 && RV_PAYLOAD=$(cat "$RV")
    [ -f "$AD" ] && AD_PAYLOAD=$(jq -Rs . < "$AD")
    [ -f "$ADF" ] && ADF_PAYLOAD=$(jq -c '. // []' "$ADF" 2>/dev/null || echo '[]')
    [ -f "$ACKS_FILE" ] && ACKS_PAYLOAD=$(jq -c . "$ACKS_FILE" 2>/dev/null || echo '[]')
    [ -f "$AR_FILE" ] && AR_PAYLOAD=$(jq -Rs . < "$AR_FILE")
    # Mechanical counts (lr-e2b975): the merge-gate does not have to re-derive
    # the blocking/advisory split from prose — it's computed here from the
    # same structured sidecar, identical in spirit to severity_blockers()
    # counting review findings mechanically rather than asking the LLM.
    ADV_BLOCKING_COUNT=$(printf '%s' "$ADF_PAYLOAD" | jq '[.[] | select(.tier == "blocking")] | length' 2>/dev/null || echo 0)
    ADV_ADVISORY_COUNT=$(printf '%s' "$ADF_PAYLOAD" | jq '[.[] | select(.tier == "advisory")] | length' 2>/dev/null || echo 0)
    case "$ADV_BLOCKING_COUNT" in ''|*[!0-9]*) ADV_BLOCKING_COUNT=0 ;; esac
    case "$ADV_ADVISORY_COUNT" in ''|*[!0-9]*) ADV_ADVISORY_COUNT=0 ;; esac
    # Resolved change class (lr-4f8316): the Auditor states its own class
    # judgment per finding (see _parse_adversarial_findings); one diff has
    # one resolved class in practice, so "any finding says ephemeral" is the
    # mechanical resolution rule -- a single ephemeral-classified finding
    # means the Auditor read the diff as ephemeral overall. null when there
    # are no findings at all (nothing to resolve; the merge-gate and audit
    # trail should not fabricate a class for a clean pass).
    RESOLVED_CHANGE_CLASS='null'
    ADF_LEN=$(printf '%s' "$ADF_PAYLOAD" | jq 'length' 2>/dev/null || echo 0)
    case "$ADF_LEN" in ''|*[!0-9]*) ADF_LEN=0 ;; esac
    if [ "$ADF_LEN" -gt 0 ]; then
      if printf '%s' "$ADF_PAYLOAD" | jq -e 'any(.[]; .class == "ephemeral")' >/dev/null 2>&1; then
        RESOLVED_CHANGE_CLASS='"ephemeral"'
      else
        RESOLVED_CHANGE_CLASS='"durable"'
      fi
    fi
    # Mechanical proxy for "downgraded because of class" (lr-4f8316): a
    # finding that met the blocking-eligible bar on reachability+severity
    # (reachable:yes, severity high/critical -- the same two conditions
    # "Blocking vs advisory" requires) but still rode as tier:advisory,
    # while class:ephemeral. Since the lr-4f8316 follow-up's mechanical
    # security-floor clamp (_parse_adversarial_findings, this file) forces
    # tier:blocking to ALWAYS apply for exactly this shape (reachable:yes +
    # severity high/critical), regardless of class, a finding produced by
    # the real parser can never actually match this select() -- this count
    # is computed independently by reading whatever JSON is on disk in
    # last-adversarial-findings.json, as a defense-in-depth cross-check
    # that should always read 0 for any sidecar the real parser wrote. A
    # nonzero value here is itself a signal worth investigating: either the
    # sidecar was populated by something other than
    # _parse_adversarial_findings, or the clamp has regressed. Recorded in
    # the audit trail so a human can see how many findings the class
    # shifted, not just what the resolved class was.
    ADV_DOWNGRADED_BY_CLASS_COUNT=$(printf '%s' "$ADF_PAYLOAD" | jq \
      '[.[] | select(.class == "ephemeral" and .tier == "advisory" and .reachable == "yes" and (.severity == "high" or .severity == "critical"))] | length' \
      2>/dev/null || echo 0)
    case "$ADV_DOWNGRADED_BY_CLASS_COUNT" in ''|*[!0-9]*) ADV_DOWNGRADED_BY_CLASS_COUNT=0 ;; esac
    # DROPPED-COUNT VISIBILITY (BOBBIE, lr-33958f PR-C fold-in review): how
    # many findings cmd_adversarial's count cap actually dropped, read back
    # from its sidecar (see the write site's own comment). Absent/
    # unparseable defaults to 0 -- fail-open, matching every other optional
    # gate-plumbing file this function reads.
    ADV_DROPPED_COUNT=0
    if [ -f "$ADF_META" ]; then
      ADV_DROPPED_COUNT=$(jq -r '.dropped_count // 0' "$ADF_META" 2>/dev/null || echo 0)
    fi
    case "$ADV_DROPPED_COUNT" in ''|*[!0-9]*) ADV_DROPPED_COUNT=0 ;; esac
    # Fenced, explicit-data-block rendering of the (already sanitized)
    # adversarial findings, mirroring the invariant-feed's
    # ===BEGIN/END INVARIANTS DATA=== treatment (lr-e2b975, matches
    # lr-cda4b9). adversarial_findings above is the machine-readable JSON
    # array a caller may want to inspect programmatically; this string field
    # is the SAME (sanitized) content wrapped in the fence
    # ds_merge_gate_prompt instructs the model to treat as data, not
    # instructions — belt-and-suspenders alongside the stdin/system-prompt
    # channel separation the wrapper already provides.
    ADF_FENCED_PAYLOAD=$(_fence_adversarial_findings "$ADF_PAYLOAD")
    # INFORMATIONAL ONLY (lr-367a21): see _read_deterministic_gates's doc
    # comment. Never gates a decision -- read failure degrades to nulls +
    # audit_db_unavailable, never a block.
    DETERMINISTIC_GATES_PAYLOAD=$(_read_deterministic_gates)
    cat <<EOF
{
  "review": $RV_PAYLOAD,
  "adversarial": $AD_PAYLOAD,
  "adversarial_missing": $ADVERSARIAL_MISSING,
  "adversarial_degraded": $ADVERSARIAL_DEGRADED,
  "adversarial_findings": $ADF_PAYLOAD,
  "adversarial_findings_fenced": $ADF_FENCED_PAYLOAD,
  "adversarial_blocking_count": $ADV_BLOCKING_COUNT,
  "adversarial_advisory_count": $ADV_ADVISORY_COUNT,
  "resolved_change_class": $RESOLVED_CHANGE_CLASS,
  "adversarial_downgraded_by_class_count": $ADV_DOWNGRADED_BY_CLASS_COUNT,
  "adversarial_findings_dropped_count": $ADV_DROPPED_COUNT,
  "adversarial_acks": $ACKS_PAYLOAD,
  "accepted_risks": $AR_PAYLOAD,
  "introduces_ack_file": $INTRODUCES_ACK_FILE,
  "threshold": "$THRESHOLD",
  "deterministic_gates": $DETERMINISTIC_GATES_PAYLOAD
}
EOF
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    RV_ARG=""
    AD_ARG=""
    ADF_ARG=""
    ADF_META_ARG=""
    ACKS_ARG=""
    AR_ARG=""
    [ -f "$RV" ] && RV_ARG="$RV"
    [ -f "$AD" ] && AD_ARG="$AD"
    [ -f "$ADF" ] && ADF_ARG="$ADF"
    [ -f "$ADF_META" ] && ADF_META_ARG="$ADF_META"
    [ -f "$ACKS_FILE" ] && ACKS_ARG="$ACKS_FILE"
    [ -f "$AR_FILE" ] && AR_ARG="$AR_FILE"
    # INFORMATIONAL ONLY (lr-367a21): computed in sh (same helper the jq
    # branch above calls) and handed in pre-built, rather than re-querying
    # audit.db inside the python heredoc -- one read site, one degrade
    # posture, for both emitter branches. See _read_deterministic_gates's
    # doc comment.
    DETERMINISTIC_GATES_PAYLOAD=$(_read_deterministic_gates)
    python3 - "$THRESHOLD" "$INTRODUCES_ACK_FILE" "$ADVERSARIAL_MISSING" "$RV_ARG" "$AD_ARG" "$ACKS_ARG" "$AR_ARG" "$ADF_ARG" "$ADVERSARIAL_DEGRADED" "$ADF_META_ARG" "$DETERMINISTIC_GATES_PAYLOAD" <<'PY'
import json, sys
threshold           = sys.argv[1]
introduces_ack      = sys.argv[2].lower() == "true" if len(sys.argv) > 2 else False
adversarial_missing = sys.argv[3].lower() == "true" if len(sys.argv) > 3 else False
rv_path             = sys.argv[4] if len(sys.argv) > 4 else ""
ad_path             = sys.argv[5] if len(sys.argv) > 5 else ""
acks_path           = sys.argv[6] if len(sys.argv) > 6 else ""
ar_path             = sys.argv[7] if len(sys.argv) > 7 else ""
adf_path            = sys.argv[8] if len(sys.argv) > 8 else ""
adversarial_degraded = sys.argv[9].lower() == "true" if len(sys.argv) > 9 else False
adf_meta_path       = sys.argv[10] if len(sys.argv) > 10 else ""
# Pre-built by _read_deterministic_gates (sh) -- fail-open to an
# audit-db-unavailable envelope if this somehow arrives empty/unparseable
# (defense in depth; the sh helper always emits valid JSON on this path).
try:
    deterministic_gates = json.loads(sys.argv[11]) if len(sys.argv) > 11 and sys.argv[11] else {
        "secrets": None, "deps": None, "sast": None, "audit_db_unavailable": True,
    }
except Exception:
    deterministic_gates = {"secrets": None, "deps": None, "sast": None, "audit_db_unavailable": True}
review = None
if rv_path:
    try:
        with open(rv_path) as f:
            review = json.load(f)
    except Exception:
        review = None
adv = None
if adversarial_missing:
    adv = None
elif ad_path:
    try:
        with open(ad_path) as f:
            adv = f.read()
    except Exception:
        adv = None
adv_findings = []
if adf_path:
    try:
        with open(adf_path) as f:
            loaded = json.load(f)
        if isinstance(loaded, list):
            adv_findings = loaded
    except Exception:
        adv_findings = []
adv_blocking_count = sum(1 for f in adv_findings if isinstance(f, dict) and f.get("tier") == "blocking")
adv_advisory_count = sum(1 for f in adv_findings if isinstance(f, dict) and f.get("tier") == "advisory")
# Resolved change class + downgrade count (lr-4f8316) -- same rules as the
# jq branch above: resolved class is "ephemeral" if any finding declares
# class:ephemeral, else "durable" if there is at least one finding, else
# null (nothing to resolve on a clean pass). The downgrade count is a
# mechanical proxy -- reachable:yes + severity high/critical + tier:advisory
# + class:ephemeral -- for "this finding met the blocking bar and rode as
# advisory under an ephemeral class"; see the jq branch's comment for why
# this cannot double as a claim that class was necessarily the deciding
# factor (a security-floor override produces the same never-advisory
# outcome regardless of class, so it never reaches this shape either way).
resolved_change_class = None
if adv_findings:
    resolved_change_class = "ephemeral" if any(
        isinstance(f, dict) and f.get("class") == "ephemeral" for f in adv_findings
    ) else "durable"
adv_downgraded_by_class_count = sum(
    1 for f in adv_findings
    if isinstance(f, dict)
    and f.get("class") == "ephemeral"
    and f.get("tier") == "advisory"
    and f.get("reachable") == "yes"
    and f.get("severity") in ("high", "critical")
)
# DROPPED-COUNT VISIBILITY (BOBBIE, lr-33958f PR-C fold-in review): mirrors
# the jq branch's read of the same sidecar -- see build_gate_summary's
# ADF_META comment and the write site's own comment (cmd_adversarial) for
# the full rationale. Absent/unparseable defaults to 0 (fail-open).
adv_dropped_count = 0
if adf_meta_path:
    try:
        with open(adf_meta_path) as f:
            adf_meta = json.load(f)
        v = adf_meta.get("dropped_count", 0)
        adv_dropped_count = v if isinstance(v, int) else 0
    except Exception:
        adv_dropped_count = 0
# Fenced, explicit-data-block rendering (lr-e2b975) -- same
# ===BEGIN/END ADVERSARIAL FINDINGS DATA=== fence the jq branch above emits
# via _fence_adversarial_findings, mirroring ds_adversarial_prompt's
# ===BEGIN/END INVARIANTS DATA=== treatment (lr-cda4b9). adv_findings here
# is already sanitized (cmd_adversarial calls
# _sanitize_adversarial_findings_json before ever writing the sidecar this
# was read from) -- this only renders and fences, no second sanitize pass.
adv_findings_fenced = (
    "===BEGIN ADVERSARIAL FINDINGS DATA===\n"
    + json.dumps(adv_findings, indent=2)
    + "\n===END ADVERSARIAL FINDINGS DATA==="
)
acks = []
if acks_path:
    try:
        with open(acks_path) as f:
            acks = json.load(f)
    except Exception:
        acks = []
ar = ""
if ar_path:
    try:
        with open(ar_path) as f:
            ar = f.read()
    except Exception:
        ar = ""
print(json.dumps({
    "review": review,
    "adversarial": adv,
    "adversarial_missing": adversarial_missing,
    "adversarial_degraded": adversarial_degraded,
    "adversarial_findings": adv_findings,
    "adversarial_findings_fenced": adv_findings_fenced,
    "adversarial_blocking_count": adv_blocking_count,
    "adversarial_advisory_count": adv_advisory_count,
    "resolved_change_class": resolved_change_class,
    "adversarial_downgraded_by_class_count": adv_downgraded_by_class_count,
    "adversarial_findings_dropped_count": adv_dropped_count,
    "adversarial_acks": acks,
    "accepted_risks": ar,
    "deterministic_gates": deterministic_gates,
    "introduces_ack_file": introduces_ack,
    "threshold": threshold,
}))
PY
    return 0
  fi

  # No JSON encoder available (lr-7047bf, site 1.12: this branch used to
  # emit a normal-shaped envelope -- adversarial: null, all counts 0,
  # resolved_change_class: null -- and return 0, which cmd_merge_gate and the
  # merge-gate LLM would read as an ordinary "nothing to report" clean pass
  # rather than "this environment could not evaluate the gate summary at
  # all." gate_summary_degraded: true names that distinction explicitly so
  # cmd_merge_gate can refuse deterministically (same short-circuit shape as
  # stale_payload below) instead of silently proceeding on a payload it
  # could not actually build. adversarial and accepted_risks are still
  # dropped here -- arbitrary content cannot be safely JSON-encoded without
  # jq or python3 -- but the caller is now told this happened rather than
  # inferring it from an envelope that looks identical to a genuinely empty
  # one. introduces_ack_file is included as false (conservative — no
  # bootstrap exemption in degraded mode).
  if [ -f "$RV" ]; then
    cat <<EOF
{"review": $(cat "$RV"), "adversarial": null, "adversarial_missing": $ADVERSARIAL_MISSING, "adversarial_degraded": $ADVERSARIAL_DEGRADED, "adversarial_findings": [], "adversarial_findings_fenced": "===BEGIN ADVERSARIAL FINDINGS DATA===\n[]\n===END ADVERSARIAL FINDINGS DATA===", "adversarial_blocking_count": 0, "adversarial_advisory_count": 0, "resolved_change_class": null, "adversarial_downgraded_by_class_count": 0, "adversarial_findings_dropped_count": 0, "adversarial_acks": [], "accepted_risks": "", "introduces_ack_file": false, "threshold": "$THRESHOLD", "gate_summary_degraded": true}
EOF
  else
    echo "{\"review\": null, \"adversarial\": null, \"adversarial_missing\": $ADVERSARIAL_MISSING, \"adversarial_degraded\": $ADVERSARIAL_DEGRADED, \"adversarial_findings\": [], \"adversarial_findings_fenced\": \"===BEGIN ADVERSARIAL FINDINGS DATA===\\n[]\\n===END ADVERSARIAL FINDINGS DATA===\", \"adversarial_blocking_count\": 0, \"adversarial_advisory_count\": 0, \"resolved_change_class\": null, \"adversarial_downgraded_by_class_count\": 0, \"adversarial_findings_dropped_count\": 0, \"adversarial_acks\": [], \"accepted_risks\": \"\", \"introduces_ack_file\": false, \"threshold\": \"$THRESHOLD\", \"gate_summary_degraded\": true}"
  fi
}

cmd_render_review() {
  FILE="${1:-$REPO_ROOT/.clagentic/lite/last-review.json}"
  [ -f "$FILE" ] || { echo "no review file at $FILE" 1>&2; return 1; }
  if command -v jq >/dev/null 2>&1; then
    # A recurrence-demoted finding (lr-66e598: _review_recurrence_demote,
    # gates.sh) gets a "reported N rounds running — decide" suffix so the
    # operator sees WHY a finding that looks blocking-severity did not gate
    # /ship, rather than the demotion being silent. Task constraint (c):
    # "surface the recurrence count in the rendered review output ... so a
    # repeated bounce is legible to the operator." A deferral-matched
    # finding (lr-2ebc41: _review_deferral_match, gates.sh) gets an
    # analogous "matched deferral <id>" suffix instead, naming which
    # .clagentic/deferrals.json entry excluded it — same "threshold, not
    # suppression, must be legible" posture. Findings without either
    # annotation (feature off, no match, or first report) render exactly as
    # before — this is purely additive text on the same line.
    #
    # issue_class/class_fix (lr-3eb18c): rendered as a second, indented line
    # under the finding so the class-level answer is visible without adding
    # noise to findings that are genuinely isolated ("none — isolated" is
    # suppressed from this line entirely -- it is the expected, honest
    # majority case and would otherwise drown out the findings that DO name
    # a real class). This is display only, mandatory-but-non-blocking per
    # severity_blockers' own comment above -- never gates /ship.
    jq -r '"== clagentic-lite review ==\nsummary: " + .summary + "\nfindings: " + (.findings | length | tostring) + "\n",
           (.findings[] | "[" + .severity + "] " + .file + ":" + (.line|tostring) + " " + .message +
             (if ._recurrence_demoted == true
              then " (reported " + (._recurrence_count | tostring) + " rounds running — decide)"
              else "" end) +
             (if ._deferral_matched == true
              then " (matched deferral " + (._deferral_id // "?") + ")"
              else "" end) +
             (if (.issue_class != null) and (.issue_class != "none — isolated")
              then "\n    class: " + .issue_class + (if (.class_fix != null) and (.class_fix != "") then " -> " + .class_fix else "" end)
              else "" end))' \
      "$FILE"
  else
    cat "$FILE"
  fi
}

# cmd_deferrals_lint [FILE] (lr-2ebc41)
#
# Validates .clagentic/deferrals.json (or FILE) against the STRICTER schema
# _review_deferral_match requires for gate-code (mechanical) matching, and
# refuses LOUDLY (non-zero exit, one line per problem on stderr) on any
# entry that claims scope "stable-contract" but is not eligible — comment 3
# (lr-2ebc41) requires conditional/scope-boundary acceptances to be
# "explicitly declared unsupported and rejected at capture time rather than
# silently accepted and mis-honored." This is the capture-time half of that
# requirement: the Builder is expected to run this (or have it run for
# them, e.g. from a commit hook or as part of the capture step itself)
# immediately after writing a deferral entry, so a malformed grant is
# caught in the SAME turn it was written, not discovered rounds later when
# it silently fails to match. This does NOT validate the six lr-c567
# prompt-context fields (category/description/expires/acknowledged_by are
# all optional and freeform by design) — only the fields the GATE-CODE path
# depends on: id, file, message, and, when scope=="stable-contract",
# file_sha256 must also be present and must be a 64-hex-char sha256 digest.
# An entry with any OTHER scope value (or no scope at all) is left alone —
# it is not gate-code-eligible and stays purely a prompt-context hint, which
# is a legitimate, unrestricted, always-valid use of this file (unchanged
# lr-c567 behavior). Entries that are not JSON objects, or whose id/file/
# message are missing/blank, are also refused for ANY scope value — a
# deferral gate code cannot even identify is not useful in either mode.
#
# Does NOT compute or write file_sha256 — capture (the Builder, or the
# operator directly) computes it themselves as part of the SAME edit that
# adds the entry (sha256sum <file> | cut -d' ' -f1, or the platform.sh
# _rm_sha256 shim: _rm_sha256 < <file>). This subcommand is a lint gate,
# not a generator — see docs/GATES.md "Reviewer-consulted deferrals" for
# why a separate "gates defer" writer subcommand is deliberately NOT
# provided (lr-2ebc41 comment 1: a subcommand the operator must remember to
# run is the same failure mode with a shorter path).
cmd_deferrals_lint() {
  _cdl_file="${1:-$REPO_ROOT/.clagentic/deferrals.json}"
  [ -f "$_cdl_file" ] || { echo "[gates/deferrals-lint] no deferrals file at $_cdl_file — nothing to lint" ; return 0; }

  if ! command -v python3 >/dev/null 2>&1; then
    echo "[gates/deferrals-lint] python3 not available — cannot validate; deferrals.json will still fail closed at match time on any malformed entry" 1>&2
    return 0
  fi

  python3 - "$_cdl_file" <<'PYEOF'
import json, re, sys

path = sys.argv[1]
try:
    with open(path) as f:
        raw = f.read()
except Exception as e:
    print("[gates/deferrals-lint] cannot read {}: {}".format(path, e))
    sys.exit(1)

if not raw.strip():
    sys.exit(0)

try:
    data = json.loads(raw)
except Exception as e:
    print("[gates/deferrals-lint] {} is not valid JSON: {}".format(path, e))
    print("[gates/deferrals-lint] the reviewer prompt will still receive it (fail-open, sanitized as opaque text), but NO entry in it can be gate-code-matched until this is fixed")
    sys.exit(1)

if not isinstance(data, list):
    print("[gates/deferrals-lint] {} must be a JSON array of deferral objects, got {}".format(path, type(data).__name__))
    sys.exit(1)

sha_re = re.compile(r'^[0-9a-f]{64}$')
problems = []
for i, e in enumerate(data):
    where = "entry {}".format(i)
    if not isinstance(e, dict):
        problems.append("{}: not a JSON object".format(where))
        continue
    eid = e.get("id")
    if isinstance(eid, str) and eid:
        where = "entry {} (id={!r})".format(i, eid)
    else:
        problems.append("{}: missing or empty required field 'id'".format(where))

    # 'file' and 'message' are lr-c567's own optional fields -- an entry
    # with neither is still a valid, unrestricted, prompt-context-only
    # deferral (e.g. a category-wide hint with no specific file). They only
    # become REQUIRED when this entry claims gate-code eligibility via
    # scope=="stable-contract" below, since gate-code matching keys on
    # (file, category, message) verbatim and cannot identify a target
    # without them.
    scope = e.get("scope")
    if scope is None:
        # No scope declared at all -- valid, prompt-context-only entry.
        # lr-c567 behavior, fully unrestricted. Not an error.
        continue
    if scope != "stable-contract":
        problems.append(
            "{}: scope={!r} is not a supported gate-code scope (only \"stable-contract\" is). "
            "REFUSED LOUDLY per design: a conditional or scope-boundary acceptance whose validity "
            "depends on code OUTSIDE this file (e.g. reset logic living elsewhere) is not safely "
            "matchable by a single-file content hash -- see docs/GATES.md 'Reviewer-consulted "
            "deferrals' for why this class is deliberately unsupported rather than silently "
            "mis-honored. Either remove the 'scope' field (valid prompt-context-only deferral, "
            "weighed by the model each round, never mechanically matched) or, if this acceptance's "
            "rationale genuinely depends only on the named file's own content, set scope to "
            "\"stable-contract\" and provide file/message/file_sha256.".format(where, scope)
        )
        continue

    fname = e.get("file")
    if not (isinstance(fname, str) and fname):
        problems.append("{}: scope is \"stable-contract\" but 'file' is missing or empty -- required to identify what gate code should re-hash".format(where))
    message = e.get("message")
    if not (isinstance(message, str) and message):
        problems.append("{}: scope is \"stable-contract\" but 'message' is missing or empty -- gate-code matching keys on (file, category, message) verbatim against the Reviewer's own finding text; without it this entry can never be mechanically matched".format(where))
    fsha = e.get("file_sha256")
    if not (isinstance(fsha, str) and sha_re.match(fsha)):
        problems.append(
            "{}: scope is \"stable-contract\" but file_sha256 is missing or not a 64-hex-char "
            "sha256 digest -- required for gate-code matching to detect the named file changing "
            "since this deferral was granted (lapse-on-edit). Compute it from the SAME file this "
            "entry names: sha256sum <file> | cut -d' ' -f1".format(where)
        )

if problems:
    print("[gates/deferrals-lint] {} problem(s) in {}:".format(len(problems), path))
    for p in problems:
        print("  - " + p)
    sys.exit(1)

print("[gates/deferrals-lint] {} entries, no problems".format(len(data)))
PYEOF
  return $?
}

# cmd_audit_vocab_lint [FILE] (lr-7047bf, foundry sub-class 1.6-1.11; widened
# lr-2e8444)
#
# WARN-ONLY lint over gates.sh's own source: flags every `cmd_log_run <gate>
# pass "<details>"` call whose details string contains a failure word
# (failed / not found / empty / no package sources / skipped / unavailable).
# "cmd_log_run <gate> pass" is a promise: this gate ran and found nothing
# wrong. A details string that itself says the underlying tool never ran
# (git ls-files failed, no package sources found, empty pattern file) is
# DEFINITIONALLY a lie against that promise -- the audit trail records
# "pass" for a security check that produced zero real coverage, and nothing
# downstream (a human reading `gates.sh digest`, or a future gate-code
# consumer of the audit trail) can tell the difference from a genuine clean
# scan without re-reading the gate's own source.
#
# Deliberately scoped to outcome=="pass" only, not "warn": a warn outcome
# already signals "not fully clean" honestly (e.g. cross-round dedup's
# "splice failed; original findings retained" -- a real, conservative
# fallback correctly labeled as a warning, not a false pass). The lie this
# lint closes is specifically a "pass" outcome paired with a details string
# that contradicts it.
#
# WARN-ONLY BY DESIGN (foundry's smallest invariant-establishing step for
# this sub-class): this does NOT rewrite the six gates' behavior. It blocks
# NEW violations (any cmd_log_run pass/failure-word pair not already in
# _AUDIT_VOCAB_KNOWN_VIOLATIONS below) while making the existing backlog
# explicit rather than invisible. Never returns non-zero on its own --
# wire a nonzero-on-new-violation caller separately if this needs to become
# a real gate; today it is diagnostic output only (see docs/GATES.md).
#
# SECOND CHECK -- unchecked variable-assembled "pass" call sites (lr-2e8444).
# The vocabulary check above is purely static: it can only see a LITERAL
# double-quoted details string, so a `cmd_log_run <gate> pass "$SOME_VAR"`
# or `cmd_log_run <gate> pass "literal ($SOME_VAR)"` call site is invisible
# to it in whole or in part -- exactly the false-clean class BOBBIE flagged
# on PR 159 (cmd_sast's `"$_SAST_PASS_DETAILS"`) and the wider sweep this
# task's own comment thread names (cmd_bleed's four `$_BLEED_SCOPE_REASON`
# sites, cmd_merge_gate's two `$_mg_class_suffix$_mg_state_suffix` sites,
# plus cmd_deps/cmd_review/cmd_ship's own variable-assembled pass sites
# found by the same sweep). `_cmd_log_run_checked_pass` (defined earlier in
# this file) closes that gap from the RUNTIME side: it checks the
# fully-assembled, post-interpolation details string against the same
# vocabulary, at the moment the string actually exists, and downgrades
# pass->warn on a hit. This second check closes the corresponding
# REGRESSION gap -- it flags any DIRECT `cmd_log_run <gate> pass ...` call
# site (bare literal, mixed literal+variable, or bare variable) that
# bypasses that checked helper, so a future contributor adding a new
# variable-assembled pass call cannot silently regress back to the
# unchecked (and thus invisible-either-way) form just by calling
# `cmd_log_run` directly instead of `_cmd_log_run_checked_pass`. A direct
# call passing an all-literal details string (no `$` at all) is NOT
# flagged by this second check -- the vocabulary check above already
# covers that case completely, and requiring every literal pass call to
# route through the helper too would be pure churn with no coverage gain.
cmd_audit_vocab_lint() {
  _cavl_file="${1:-$TOOL_HOME/scripts/gates.sh}"
  [ -f "$_cavl_file" ] || { echo "[gates/audit-vocab-lint] no file at $_cavl_file"; return 0; }

  if ! command -v python3 >/dev/null 2>&1; then
    echo "[gates/audit-vocab-lint] python3 not available — cannot lint (warn-only check, non-blocking either way)" 1>&2
    return 0
  fi

  python3 - "$_cavl_file" <<'PYEOF'
import re
import sys

path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()

# Matches `cmd_log_run <gate> pass "<details>"` or `cmd_log_run <gate> pass ""`
# (also the "$_mg_gate_name" quoted-variable gate-name form) -- captures the
# gate name and the details string for the failure-word check below. This
# regex only ever sees a LITERAL double-quoted details string; a bare or
# partially-interpolated variable is invisible to it by construction -- see
# _UNCHECKED_DIRECT_CALL_RE below for the second, complementary check that
# covers exactly that gap.
_CALL_RE = re.compile(
    r'cmd_log_run\s+(?:"([^"]+)"|(\S+))\s+pass\s+"([^"]*)"'
)

# Matches a DIRECT `cmd_log_run <gate> pass ...` call site (not routed
# through `_cmd_log_run_checked_pass`) whose details argument contains a `$`
# -- i.e. is wholly or partly variable-assembled. This is the regression
# guard for the runtime-checked-helper fix (lr-2e8444): every such call site
# must go through `_cmd_log_run_checked_pass` instead, so its fully
# assembled, post-interpolation content is examined against the same
# vocabulary at the moment it actually exists. A literal-only details string
# (no `$`) is deliberately excluded -- `_CALL_RE` above already covers that
# case completely. No lookbehind needed to exclude
# `_cmd_log_run_checked_pass` call sites themselves: this regex requires
# whitespace immediately after the literal text "cmd_log_run", and
# `_cmd_log_run_checked_pass` has "_checked_pass" (not whitespace) in that
# position, so it never matches the helper's own call sites.
_UNCHECKED_DIRECT_CALL_RE = re.compile(
    r'cmd_log_run\s+(?:"[^"]+"|\S+)\s+pass\s+"[^"]*\$[^"]*"'
)

# The exact vocabulary the foundry sweep named: a tool/gate that never
# actually ran or scanned anything, described in the details string of a
# "pass" outcome.
_FAILURE_WORDS = (
    "failed", "not found", "empty", "no package sources", "skipped",
    "unavailable",
)

# KNOWN VIOLATIONS (as of lr-7047bf): the existing backlog, enumerated
# explicitly per the foundry's "make the backlog explicit, not invisible"
# directive. This lint is warn-only and does not rewrite these six gates'
# behavior -- most of these are real, pre-existing "pass" outcomes whose
# details string names a reason the underlying tool did not actually scan
# anything (deps/no-package-sources, bleed/empty-pattern-file,
# bleed/git-ls-files-failed). Keyed as (gate, details) so a NEW violation
# (different gate, or the same gate with new/changed wording) is not
# silently absorbed by this allowlist -- only an EXACT match to one of
# these known lines is suppressed from the warning output below.
#
# sast/"unavailable" WAS a reviewed, intentional exception here (semgrep
# genuinely ran full-tree; "unavailable" described why the SCOPE was
# full-tree, not that the scan was fake) but is REMOVED as of lr-321e18's
# BOBBIE fold-in: cmd_sast's two `cmd_log_run sast pass ...` call sites now
# build their details string into a variable ($_SAST_PASS_DETAILS) so the
# config-pin visibility fix (below) can conditionally append to it. This
# lint's _CALL_RE regex only matches a literal double-quoted details string;
# a variable reference contains no failure word literally, so a bare
# `cmd_log_run sast pass "$_SAST_PASS_DETAILS"` call site would no longer be
# statically flagged by _CALL_RE at all -- the entries that used to
# allowlist it are correctly dead here (their exact literal source text no
# longer appears anywhere in gates.sh) per this section's own contract ("if
# any disappeared, the allowlist should be trimmed rather than silently
# going stale"), removed rather than left behind as no-op entries.
#
# THAT BLINDNESS IS NOW CLOSED FROM THE RUNTIME SIDE INSTEAD (lr-2e8444):
# cmd_sast (and cmd_bleed's four $_BLEED_SCOPE_REASON sites, and
# cmd_merge_gate's two class/state-suffix sites) call
# `_cmd_log_run_checked_pass` rather than `cmd_log_run ... pass ...`
# directly -- see that function's own doc comment. This _KNOWN_VIOLATIONS
# set stays scoped to the STATIC vocabulary check's literal-only backlog;
# it is not where runtime-checked-helper coverage is asserted (that is
# `_UNCHECKED_DIRECT_CALL_RE` below, and scripts/test_audit_vocab_lint.py's
# checked-helper-routing tests).
_KNOWN_VIOLATIONS = {
    ("deps", "no package sources found"),
    ("bleed", "empty pattern file"),
    ("bleed", "git ls-files failed (non-blocking)"),
}

findings = []
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith('#'):
        continue
    m = _CALL_RE.search(line)
    if not m:
        continue
    gate = m.group(1) or m.group(2)
    details = m.group(3)
    details_lower = details.lower()
    hit_words = [w for w in _FAILURE_WORDS if w in details_lower]
    if not hit_words:
        continue
    key = (gate, details)
    findings.append((i + 1, gate, details, hit_words, key in _KNOWN_VIOLATIONS))

new_violations = [f for f in findings if not f[4]]
known_violations = [f for f in findings if f[4]]

if known_violations:
    print("[gates/audit-vocab-lint] {} known (pre-existing, allowlisted) violation(s):".format(len(known_violations)))
    for ln, gate, details, words, _ in known_violations:
        print("  gates.sh:{} gate={} words={} details={!r}".format(ln, gate, words, details))

if new_violations:
    print("[gates/audit-vocab-lint] {} NEW violation(s) -- a \"pass\" outcome whose details string contains a failure word:".format(len(new_violations)))
    for ln, gate, details, words, _ in new_violations:
        print("  gates.sh:{} gate={} words={} details={!r}".format(ln, gate, words, details))
    print("[gates/audit-vocab-lint] add the (gate, details) pair shown above to _KNOWN_VIOLATIONS in cmd_audit_vocab_lint if this is an intentional, reviewed exception; otherwise fix the gate to log block/warn instead of pass.")
else:
    print("[gates/audit-vocab-lint] no new violations ({} known, allowlisted)".format(len(known_violations)))

# Second check (lr-2e8444): any DIRECT cmd_log_run pass call with a
# variable-assembled details string, bypassing the runtime-checked helper.
#
# ONE sanctioned exemption: _cmd_log_run_checked_pass's own internal call to
# cmd_log_run IS the choke point this whole mechanism routes through -- it
# is not a bypass of the checked helper, it is the checked helper's own
# implementation, called only after the vocabulary check above it has
# already run against the fully-assembled details string. Identified by its
# use of the `_clrcp_`-prefixed local variables that are unique to that one
# function's own body (never used anywhere else in gates.sh) -- not by a
# literal reproduction of the call text, which would itself contain the
# shell-call shape this check searches for and self-match when this lint
# scans its own source (this file's default lint target).
unchecked_direct = []
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith('#'):
        continue
    if "_clrcp_gate" in line and "_clrcp_details" in line:
        continue
    if _UNCHECKED_DIRECT_CALL_RE.search(line):
        unchecked_direct.append(i + 1)

if unchecked_direct:
    print("[gates/audit-vocab-lint] {} UNCHECKED variable-assembled 'pass' call site(s) -- bypasses _cmd_log_run_checked_pass, so runtime content is never vocabulary-checked:".format(len(unchecked_direct)))
    for ln in unchecked_direct:
        print("  gates.sh:{}".format(ln))
    print("[gates/audit-vocab-lint] route this call through _cmd_log_run_checked_pass GATE DETAILS instead of calling cmd_log_run GATE pass ... directly.")
else:
    print("[gates/audit-vocab-lint] no unchecked variable-assembled pass call sites")
PYEOF
  return 0
}

# gate_enabled <name> — returns 0 if the named gate is in CLAGENTIC_GATES,
# or if CLAGENTIC_GATES is unset (all gates run by default).
gate_enabled() {
  N="$1"
  G="${CLAGENTIC_GATES-}"
  [ -z "$G" ] && return 0
  case ",$G," in
    *,"$N",*) return 0 ;;
    *)        return 1 ;;
  esac
}

cmd_ship() {
  echo "[gates/ship] running gate sequence (enabled: ${CLAGENTIC_GATES:-all})"
  # ship_step_skip: print + audit-log a skipped gate. Every gate decision —
  # including the decision to skip — lands in audit.db per AGENTS.md §6.
  ship_step_skip() {
    echo "[gates/ship] skip $1 (not in CLAGENTIC_GATES)"
    cmd_log_run "$1" skip "not in CLAGENTIC_GATES=${CLAGENTIC_GATES:-}"
  }
  # ship_step_hint: one-line pointer to the Troubleshooter agent, printed
  # alongside every blocking failure below — same convention as the existing
  # "set CLAGENTIC_ALLOW_MISSING_*=1 to skip" hints in cmd_secrets/cmd_deps.
  # A gate exit code alone ("BLOCKED at secrets") tells you WHAT failed, not
  # where to go next (lr-0c7f99): the affordance belongs where the failure
  # lands, not only in docs a session has to go looking for.
  ship_step_hint() {
    echo "[gates/ship] diagnose with the Troubleshooter agent (plugins/clagentic-lite/agents/troubleshooter.md)"
  }
  if gate_enabled bleed;        then cmd_bleed        || { echo "[gates/ship] BLOCKED at internal-bleed"; ship_step_hint; exit 1; }; else ship_step_skip bleed;        fi
  if gate_enabled secrets;     then cmd_secrets     || { echo "[gates/ship] BLOCKED at secrets";    ship_step_hint; exit 1; }; else ship_step_skip secrets;     fi
  if gate_enabled deps;        then cmd_deps        || { echo "[gates/ship] BLOCKED at deps";       ship_step_hint; exit 1; }; else ship_step_skip deps;        fi
  if gate_enabled sast;        then cmd_sast        || { echo "[gates/ship] BLOCKED at sast";       ship_step_hint; exit 1; }; else ship_step_skip sast;        fi
  if gate_enabled review; then
    _review_rc=0
    cmd_review || _review_rc=$?
    if [ "$_review_rc" -eq 2 ]; then
      echo "[gates/ship] INFRA_DEGRADED at review — reviewer infrastructure failed, no real review occurred"
      ship_step_hint
      cmd_log_run ship block "infra-degraded at review"
      exit 2
    elif [ "$_review_rc" -ne 0 ]; then
      echo "[gates/ship] REVIEW_BLOCKED at review (severity threshold ${CLAGENTIC_BLOCK_SEVERITY:-high})"
      cmd_log_run ship block "review-blocked at review"
      exit 1
    fi
  else
    ship_step_skip review
  fi
  # EXPLICIT, VISIBLE `|| true` (lr-7047bf, INV-1 enforcement): adversarial
  # is a non-blocking gate by design (AGENTS.md #4, docs/GATES.md) -- a
  # degraded auditor must not abort `ship`. cmd_adversarial can now return
  # non-zero (2) on a degraded envelope; this `|| true` is the deliberate,
  # reviewable opt-out that decision requires, not an accidental default.
  # The degraded state is NOT silently lost: cmd_adversarial's own audit row
  # (outcome=degraded) records it, and build_gate_summary/cmd_merge_gate
  # (adversarial_degraded field) independently surface it to the blocking
  # merge-gate step that runs immediately after this line.
  if gate_enabled adversarial; then cmd_adversarial || true; else ship_step_skip adversarial; fi
  if gate_enabled merge-gate;  then cmd_merge_gate  || { echo "[gates/ship] BLOCKED at merge-gate"; ship_step_hint; exit 1; }; else ship_step_skip merge-gate;  fi

  echo "[gates/ship] all blocking gates passed"
  # Repo-scoped (lr-da1f28 sweep): a bare `_git rev-parse --abbrev-ref HEAD`
  # would resolve an ancestor repo's branch name when REPO_ROOT is not
  # itself a git repo (see _git_repo_root_is_scoped's doc comment), and
  # `_git push -u origin "$BRANCH"` below IS correctly scoped to REPO_ROOT —
  # pushing REPO_ROOT's history to a branch name borrowed from an unrelated
  # repo. Treat "not scoped" the same as "no branch resolvable".
  BRANCH=""
  if _git_repo_root_is_scoped; then
    BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  fi
  DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  if [ "$BRANCH" = "$DEFAULT_BRANCH" ] || [ -z "$BRANCH" ]; then
    echo "[gates/ship] on '$BRANCH' — not pushing or opening a PR; create a feature branch first"
    _cmd_log_run_checked_pass ship "gates green; no push (branch=$BRANCH)"
    return 0
  fi

  # Bound every network-touching git/adapter invocation below (INV-1a/INV-2,
  # class-4 foundry fix): `git push` and the host-adapter's open-change-request
  # call were both previously untimed -- a hung push or a stalled host API
  # call would block `ship` indefinitely with no diagnostic, the last step
  # of an otherwise fully-bounded gate sequence.
  _SHIP_TIMEOUT="${CLAGENTIC_SHIP_TIMEOUT_SEC:-120}"
  _SHIP_TIMEOUT=$(ds_positive_int_or_default "$_SHIP_TIMEOUT" 120)

  # Push + open a change request via the host adapter (lr-2b07a8), else
  # print a template. Host-neutral by contract (docs/GATES.md "Host adapter
  # contract"): gate logic never names a vendor CLI/API directly -- see
  # scripts/host-adapter.sh for the one place that's allowed.
  if _git remote get-url origin >/dev/null 2>&1; then
    run_bounded "$_SHIP_TIMEOUT" -- _git push -u origin "$BRANCH" || { echo "[gates/ship] push failed or timed out after ${_SHIP_TIMEOUT}s"; cmd_log_run ship block "push failed"; exit 1; }
  fi
  if host_adapter_available; then
    # Render the PR body gate-side (lr-429b32) before handing off to the
    # adapter -- host-adapter.sh transports, it never composes (file-header
    # contract). A render failure (no jq/python3 -- the same exemption
    # _build_review_verdict_comment_body already has) still opens the PR;
    # it just falls back to no body file, same as pre-lr-429b32 behavior.
    _SHIP_HEAD_SHA=$(_git_repo_scoped_head_sha)
    _SHIP_BODY_FILE=$(mktemp -t clagentic-ship-pr-body.XXXXXX)
    if ! _build_ship_pr_body "$BRANCH" "$_SHIP_HEAD_SHA" > "$_SHIP_BODY_FILE" 2>/dev/null || [ ! -s "$_SHIP_BODY_FILE" ]; then
      rm -f "$_SHIP_BODY_FILE"
      _SHIP_BODY_FILE=""
    fi
    host_adapter_open_change_request "$DEFAULT_BRANCH" "$BRANCH" "$_SHIP_BODY_FILE" || \
      echo "[gates/ship] host-adapter open-change-request failed or timed out after ${_SHIP_TIMEOUT}s — open the PR manually"
    [ -n "$_SHIP_BODY_FILE" ] && rm -f "$_SHIP_BODY_FILE"
  else
    REMOTE=$(_git remote get-url origin 2>/dev/null || echo "<remote>")
    echo "[gates/ship] no host adapter available — open a PR manually:"
    echo "  base=$DEFAULT_BRANCH head=$BRANCH remote=$REMOTE"
  fi
  _cmd_log_run_checked_pass ship "gates green; pushed $BRANCH"
}

cmd_pre_push() {
  cmd_deps || { echo "[gates/pre-push] diagnose with the Troubleshooter agent (plugins/clagentic-lite/agents/troubleshooter.md)"; exit 1; }
  cmd_sast || { echo "[gates/pre-push] diagnose with the Troubleshooter agent (plugins/clagentic-lite/agents/troubleshooter.md)"; exit 1; }
  [ "${CLAGENTIC_REVIEW_ON_PUSH:-0}" = "1" ] && { cmd_review || exit 1; }
  exit 0
}

cmd_digest() {
  cmd_init
  printf '\n== clagentic-lite gate digest (last 24h) ==\n\n'
  ds_sqlite3 -header -column "$AUDIT_DB" \
    "SELECT ts, gate, outcome, substr(details,1,60) AS details
     FROM gate_runs WHERE ts > datetime('now','-1 day') ORDER BY ts DESC;"
  printf '\n'
  printf 'totals:\n'
  ds_sqlite3 -column "$AUDIT_DB" \
    "SELECT outcome, COUNT(*) FROM gate_runs WHERE ts > datetime('now','-1 day') GROUP BY outcome;"
  printf '\n'
}

# ---------------------------------------------------------------- status / tail
#
# Visibility surfaces over .clagentic/lite/audit.db that complement `digest`:
#
#   status — last N runs per gate (default 10), color-coded outcome. Answers
#            "what's the recent state of each gate?" at a glance, without
#            scrolling through a time-ordered digest.
#   tail   — poll audit.db every 1s for new rows and render them as they land.
#            POSIX-portable (no inotify); Ctrl-C to quit. Foreground only.
#
# Both are read-only. Neither writes to audit.db, neither runs a gate, neither
# spawns a daemon. This is the CLI-only visibility step before the proposed
# web inspector (lr-a699) — see docs/DESIGN.md non-goals.

# Color helpers. Honor NO_COLOR (https://no-color.org/) and refuse to emit
# escape codes when stdout is not a TTY (piping to a file should be plain).
_color_init() {
  if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    C_RESET=""; C_GREEN=""; C_RED=""; C_YELLOW=""; C_DIM=""
  else
    C_RESET=$(printf '\033[0m')
    C_GREEN=$(printf '\033[32m')
    C_RED=$(printf '\033[31m')
    C_YELLOW=$(printf '\033[33m')
    C_DIM=$(printf '\033[2m')
  fi
}

_color_outcome() {
  case "$1" in
    pass)  printf '%s%s%s' "$C_GREEN"  "$1" "$C_RESET" ;;
    block) printf '%s%s%s' "$C_RED"    "$1" "$C_RESET" ;;
    warn)  printf '%s%s%s' "$C_YELLOW" "$1" "$C_RESET" ;;
    skip)  printf '%s%s%s' "$C_DIM"    "$1" "$C_RESET" ;;
    *)     printf '%s' "$1" ;;
  esac
}

cmd_status() {
  cmd_init
  _color_init
  N="${1:-10}"
  # Reject anything that isn't a positive integer. A bad N here would inject
  # straight into the SQL LIMIT clause.
  case "$N" in
    ''|*[!0-9]*) echo "gates.sh status: N must be a positive integer (got: $N)" 1>&2; return 2 ;;
  esac
  [ "$N" -lt 1 ] && { echo "gates.sh status: N must be >= 1" 1>&2; return 2; }

  printf '\n== clagentic-lite gate status (last %s per gate) ==\n\n' "$N"

  # One row per known gate. Iterate the gate list rather than GROUP BY because
  # we want a section per gate even when the gate has zero rows (so users
  # notice "review never ran" rather than silently missing).
  for GATE in bleed secrets deps sast review adversarial merge-gate ship; do
    printf '%s\n' "-- $GATE --"
    ROWS=$(ds_sqlite3 -separator '|' "$AUDIT_DB" \
      "SELECT ts, outcome, substr(coalesce(details,''),1,60)
       FROM gate_runs WHERE gate='$GATE' ORDER BY ts DESC LIMIT $N;" 2>/dev/null)
    if [ -z "$ROWS" ]; then
      printf '  %s(no runs)%s\n\n' "$C_DIM" "$C_RESET"
      continue
    fi
    # POSIX read loop; IFS=| splits the sqlite3 -separator output.
    printf '%s\n' "$ROWS" | while IFS='|' read -r TS OUTCOME DETAILS; do
      COLORED=$(_color_outcome "$OUTCOME")
      printf '  %s  %-7s  %s\n' "$TS" "$COLORED" "$DETAILS"
    done
    printf '\n'
  done
}

cmd_tail() {
  cmd_init
  _color_init

  # Parse flags.
  _tail_no_follow=0
  for _tail_arg in "$@"; do
    case "$_tail_arg" in
      --no-follow) _tail_no_follow=1 ;;
    esac
  done

  # Start from the current max id so we only render NEW rows. A fresh tail
  # session shouldn't dump history — use `status` or `digest` for that.
  # CLAGENTIC_TAIL_WATERMARK: when set, use the provided id as the start
  # watermark instead of computing MAX(id). Used by smoke.sh step 6c so the
  # watermark is captured before the sentinel row is logged — ensuring the new
  # row is visible on the first (and only) poll in --no-follow mode.
  if [ -n "${CLAGENTIC_TAIL_WATERMARK:-}" ]; then
    LAST_ID="$CLAGENTIC_TAIL_WATERMARK"
    case "$LAST_ID" in ''|*[!0-9]*) LAST_ID=0 ;; esac
  else
    LAST_ID=$(ds_sqlite3 "$AUDIT_DB" "SELECT COALESCE(MAX(id),0) FROM gate_runs;" 2>/dev/null)
    LAST_ID=${LAST_ID:-0}
  fi

  if [ "$_tail_no_follow" = "1" ]; then
    # --no-follow: emit rows since the watermark and exit 0.
    # Used by smoke.sh (step 6c) to avoid the indefinite-follow hang that
    # occurs inside a Claude Code session.
    printf '== clagentic-lite gate tail (--no-follow, one-shot) ==\n'
    printf '   rows with gate_runs.id > %s\n\n' "$LAST_ID"
    NEW=$(ds_sqlite3 -separator '|' "$AUDIT_DB" \
      "SELECT id, ts, gate, outcome, substr(coalesce(details,''),1,80)
       FROM gate_runs WHERE id > $LAST_ID ORDER BY id ASC;" 2>/dev/null)
    if [ -n "$NEW" ]; then
      printf '%s\n' "$NEW" | while IFS='|' read -r ID TS GATE OUTCOME DETAILS; do
        COLORED=$(_color_outcome "$OUTCOME")
        printf '  %s  %-12s  %-7s  %s\n' "$TS" "$GATE" "$COLORED" "$DETAILS"
      done
    fi
    return 0
  fi

  INTERVAL="${CLAGENTIC_TAIL_INTERVAL_SEC:-1}"
  # Numeric guard (lr-53dc6e): every other timeout/interval var in this file
  # gets this same case-based validation before use (e.g. _BLEED_FETCH_TIMEOUT
  # gates.sh:538, _SAST_FETCH_TIMEOUT :689, BASE/RATE/MAX llm-client.sh:1041-
  # 1043) — INTERVAL was the one sibling that reached `sleep "$INTERVAL"`
  # below unguarded. An operator-set non-numeric CLAGENTIC_TAIL_INTERVAL_SEC
  # would otherwise reach `sleep` raw and fail there instead of falling back
  # to a safe default.
  case "$INTERVAL" in ''|*[!0-9]*) INTERVAL=1 ;; esac
  printf '== clagentic-lite gate tail (Ctrl-C to quit, polling every %ss) ==\n' "$INTERVAL"
  printf '   starting from gate_runs.id > %s\n\n' "$LAST_ID"

  # Trap INT/TERM so the user gets a clean exit instead of a stack trace from
  # set -e + a killed sqlite3.
  trap 'printf "\n[tail] stopped\n"; exit 0' INT TERM

  while :; do
    NEW=$(ds_sqlite3 -separator '|' "$AUDIT_DB" \
      "SELECT id, ts, gate, outcome, substr(coalesce(details,''),1,80)
       FROM gate_runs WHERE id > $LAST_ID ORDER BY id ASC;" 2>/dev/null)
    if [ -n "$NEW" ]; then
      # Update LAST_ID from the last line's id BEFORE the read loop — the
      # loop runs in a subshell (pipe) so any assignment inside is lost.
      LAST_ID=$(printf '%s\n' "$NEW" | awk -F'|' 'END {print $1}')
      printf '%s\n' "$NEW" | while IFS='|' read -r ID TS GATE OUTCOME DETAILS; do
        COLORED=$(_color_outcome "$OUTCOME")
        printf '  %s  %-12s  %-7s  %s\n' "$TS" "$GATE" "$COLORED" "$DETAILS"
      done
    fi
    sleep "$INTERVAL"
  done
}

# ENROLL-TIME TRUST GATE (lr-33fb89, PR #152 second fold-in, coordinator-
# escalated bobbie.sast.3 follow-through): `init` is the ONE subcommand
# reachable BEFORE a repo has been enrolled -- `clagentic-lite enroll`
# invokes `gates.sh init` directly (bin/clagentic-lite _enroll_one) to
# create audit.db's schema, and that invocation's cwd is whatever cwd
# enroll itself was run from, which is very commonly INSIDE the
# not-yet-enrolled target repo (`git clone X && cd X && clagentic-lite
# enroll`). ds_load_env dot-sources (EXECUTES) that repo's own
# .clagentic/config with no trust check -- the same class of pre-trust
# execution bobbie.sast.3 flagged in bin/clagentic-lite's own dispatch, one
# process frame down. Every OTHER subcommand here (bleed, secrets, deps,
# sast, review, adversarial, ship, pre-push, log-run, digest, status,
# tail, merge-gate, render-review, deferrals-lint, audit-vocab-lint) is
# reachable ONLY post-enrollment (via a hook shim `enroll` itself installs,
# or an operator deliberately running `clagentic-lite gates <subcmd>` /
# this script directly against a repo they are already working in) -- see
# ds_load_repo_env's docstring in platform.sh for why that precondition is
# what makes the unconditional combined ds_load_env correct for them.
#
# cmd_init (above) reads NO CLAGENTIC_* config value at all -- verified: its
# only external input is $AUDIT_DB, itself derived only from $REPO_ROOT
# (CLAGENTIC_PROJECT_ROOT, an explicit override the caller passes, or
# ds_repo_root()'s pure git/filesystem resolution -- neither reads a config
# FILE). So skipping ds_load_env specifically for `init` changes nothing
# about what `init` does; it only closes the pre-trust execution window.
# Every other branch below still gets the full, unchanged, combined
# ds_load_env exactly as before this fold-in -- POST-ENROLLMENT BEHAVIOR
# HERE IS UNCHANGED, this is a migration for the init-time path only.
# SOURCE GUARD (lr-bdddcf): everything above this line (functions, version
# constants, REPO_ROOT/_git resolution) is safe and correct to run at
# source time -- a caller that wants to reuse a function needs exactly
# that. Only the block below is execute-as-a-script behavior: the
# ds_load_env call branches on the SOURCING shell's own "$1", and the case
# statement reads it again and calls `exit` -- both wrong/destructive for a
# caller that dot-sources this file to reuse functions.
#
# POSIX sh has no $BASH_SOURCE (or any other sourced-vs-executed
# introspection primitive), so "was this file sourced" cannot be detected
# automatically -- the portable idiom is an explicit opt-in env sentinel the
# caller sets before sourcing. CLAGENTIC_GATES_SOURCE_ONLY=1 is that
# sentinel: unset/empty (the default, and every real `sh gates.sh
# <subcommand>` invocation) runs both blocks exactly as before this guard
# was added -- byte-identical executed-as-a-script behavior, pinned by
# test_gates_source_guard.py. Set only by a caller that is dot-sourcing
# this file on purpose.
#
# TRADE-OFF (named per lr-bdddcf task instructions, see also the PR body):
# the alternative was moving this dispatch into a `main "$@"` invoked only
# when not sourced -- see llm-client.sh's identical guard comment for why
# that was rejected here too: POSIX sh's lack of $BASH_SOURCE means "not
# sourced" still has to be spelled as the same env sentinel, just moved one
# layer down and adding a `main()` wrapper + reindent around this exact
# ds_load_env/case pair, a larger diff against gate-path code for no
# behavioral gain. The sentinel-before-dispatch form keeps both existing
# blocks completely untouched.
#
# FAIL-CLOSED AMENDMENT (lr-bdddcf PR #177 fold-in, coordinator-authorized
# after BOBBIE's original exit-status claim for this branch was
# independently found wrong -- see PR body): a bare `if ... fi` with no
# else and a false condition exits 0. That made EXECUTING this file
# directly (`sh gates.sh <subcmd>`, not sourcing it) with
# CLAGENTIC_GATES_SOURCE_ONLY ambiently set (e.g. exported in a
# developer's shell profile, never intentionally, and forgotten) a
# SILENT no-op indistinguishable from a clean gate run to every
# exit-status-only consumer (scripts/smoke.sh, the pre-push/pre-commit
# hook-shim templates, bin/clagentic-lite's gates subcommand).
#
# The file cannot detect "am I being sourced right now" in POSIX sh (see
# above, and confirmed empirically: dash's own `(return 0 2>/dev/null)`
# top-level-return probe, the textbook portable idiom, does NOT
# discriminate reliably on this project's actual /bin/sh -- it reports
# success even for a directly executed script file, not just a sourced
# one). What the file CAN do is require the caller to say WHY the
# suppress-sentinel is set, via a second, purpose-specific signal:
# CLAGENTIC_GATES_DELIBERATE_SOURCE=1 asserts "I am dot-sourcing this
# file on purpose right now" -- distinct from CLAGENTIC_GATES_SOURCE_ONLY,
# which only means "suppress dispatch." Provenance is information the
# caller has and the file does not; encoding it explicitly, rather than
# inferring it, is what makes this fail closed regardless of shell.
#
#   suppress sentinel set + deliberate signal set     -> silent, no
#     dispatch (real sourcing; current behavior, unchanged)
#   suppress sentinel set + deliberate signal ABSENT   -> loud stderr
#     naming both variables, exit 1 (ambient leak, refuse to report a
#     false pass)
#   neither set                                        -> dispatch
#     exactly as before this whole guard existed, byte-identical
#
# KNOWN RESIDUAL LIMITATION (named per operator instruction, not papered
# over): this two-signal scheme is itself defeatable by a caller/shell
# profile that ambiently exports BOTH variables together -- nothing in
# POSIX sh can distinguish that from genuine deliberate sourcing, since
# both signals are just env vars indistinguishable-by-origin from any
# other ambient export. This amendment closes the SILENT-single-sentinel
# leak (the realistic case: a developer exports only the original
# suppress sentinel, e.g. copy-pasted from a test helper, without the
# second signal) and turns it loud instead of silent. It does not, and
# structurally cannot, defend against a caller that deliberately or
# accidentally exports both. Defense against that residual case is
# scripts/smoke.sh + the hook-shim templates + bin/clagentic-lite
# explicitly unsetting both CLAGENTIC_GATES_SOURCE_ONLY and
# CLAGENTIC_GATES_DELIBERATE_SOURCE before invoking this file as a
# script (same PR, same task) -- stopping the leak from reaching the gate
# at all, rather than relying on this file alone to detect it.
if [ -z "${CLAGENTIC_GATES_SOURCE_ONLY:-}" ]; then
  if [ "${1:-}" != "init" ]; then
    ds_load_env
  fi

  case "${1:-}" in
    init)           cmd_init ;;
    bleed)          shift; cmd_bleed "$@" ;;
    secrets)        cmd_secrets ;;
    deps)           cmd_deps ;;
    sast)           cmd_sast ;;
    review)         shift; cmd_review "$@" ;;
    adversarial)    cmd_adversarial ;;
    merge-gate)     shift; cmd_merge_gate "$@" ;;
    render-review)  shift; cmd_render_review "$@" ;;
    deferrals-lint) shift; cmd_deferrals_lint "$@" ;;
    audit-vocab-lint) shift; cmd_audit_vocab_lint "$@" ;;
    ship)           cmd_ship ;;
    pre-push)       cmd_pre_push ;;
    log-run)        shift; cmd_log_run "$@" ;;
    digest)         cmd_digest ;;
    status)         shift; cmd_status "$@" ;;
    tail)           shift; cmd_tail "$@" ;;
    *) echo "usage: gates.sh {init|bleed [--full-scan]|secrets|deps|sast|review [--full-review] [--since-last-review] [--reset-dedup]|adversarial|merge-gate [--recheck]|render-review|deferrals-lint [FILE]|audit-vocab-lint [FILE]|ship|pre-push|log-run|digest|status|tail [--no-follow]}" 1>&2; exit 1 ;;
  esac
elif [ -z "${CLAGENTIC_GATES_DELIBERATE_SOURCE:-}" ]; then
  echo "gates.sh: CLAGENTIC_GATES_SOURCE_ONLY is set but CLAGENTIC_GATES_DELIBERATE_SOURCE is not -- dispatch suppressed with no provenance asserting deliberate sourcing, refusing to report a false pass. If dot-sourcing this file on purpose, set both variables. If you did not mean to set CLAGENTIC_GATES_SOURCE_ONLY, unset it." 1>&2
  exit 1
fi
