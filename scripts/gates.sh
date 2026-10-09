#!/bin/sh
# clagentic-lite :: gate orchestrator
# Runs gates in sequence, logs outcomes to .clagentic/lite/audit.db.
#
# Subcommands:
#   init             create audit schema
#   bleed            scan committed files for internal/private string bleed
#   secrets          run gitleaks on staged hunks; branch-diff scan (scoped
#                    to merge-base(default-branch, HEAD)..HEAD) when no
#                    staged changes; --full-scan / CLAGENTIC_SECRETS_FULL_SCAN=1
#                    opts into the full-history scan
#   deps             run osv-scanner (pre-push)
#   sast             run semgrep (pre-push)
#   review           run cross-vendor review on staged diff; branch diff when no staged changes
#   adversarial      run non-blocking adversarial pass
#   ship             run all blocking gates, then push + open PR if green
#   render-review    pretty-print .clagentic/lite/last-review.json
#   render-manifest  pretty-print .clagentic/lite/last-gate-manifest.json (gate attestation)
#   digest           summarize today's audit rows
#   status           last N runs per gate (default N=10) with color outcomes
#   tail             follow audit.db, render new gate_runs rows as they land; --no-follow exits after one poll
#   pre-push         hook entry point (deps + sast + optional review). deps
#                    and sast each additionally consult their declared INPUT
#                    DOMAIN against this push's changed-path set (lr-1ad8da)
#                    and log outcome "not_applicable" -- a THIRD state,
#                    distinct from pass/block/skip/warn -- instead of
#                    running when the push provably cannot affect their
#                    verdict. Secrets is NEVER eligible for this (every file,
#                    unconditionally); see "Gate input domain" below cmd_log_run.
#   log-run          internal: insert one row into gate_runs
#   dispositions-lint validate .clagentic/dispositions.json (and the legacy
#                    deferrals/acks files it replaces) against the entry schema
#   deferrals-lint   deprecated alias of dispositions-lint
#   evaluate         the code verdict: unified findings JSON on stdin, dispositions
#                    and guardrails applied, per-HEAD accumulation; exits 1 when
#                    BLOCKED. Alias of findings.py evaluate (standalone agents call
#                    that file directly; runs here do not count toward ship)
#   audit-vocab-lint warn-only: flag "cmd_log_run <gate> pass" audit rows whose
#                    details string contains a failure word (a tool that never
#                    ran should not log as a clean pass)
#
# GATE OUTCOME VOCABULARY (gate_runs.outcome): pass | block | warn | skip |
# not_applicable (lr-1ad8da, gate-contract migration -- see docs/GATES.md
# "Gate input domain"). not_applicable means the gate's verdict provably
# cannot depend on what changed in this push -- distinct from "skip" (tool
# missing, opt-in bypass) and from "pass" (tool ran, found nothing). Every
# not_applicable row's details column carries the domain version tested
# against, the changed-path count, and how that changed-path set was
# derived.

set -e
. "$(dirname "$0")/platform.sh"
. "$(dirname "$0")/review-merge.sh"
. "$(dirname "$0")/host-adapter.sh"

# Tool home: the directory containing scripts/ — resolved from this script's
# own location so it's correct whether invoked via PATH, symlink, or directly.
# This is the install tree ($CLAGENTIC_LITE_HOME), not the enrolled project root.
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_HOME="$(dirname "$SCRIPTS_DIR")"
# The same home reached through any symlinked copy of this script; the finding
# pipeline (ds_findings_py, platform.sh) is looked up under it too.
_DS_REAL_HOME="$(dirname "$(dirname "$(ds_resolve_path "$0")")")"

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

# lr-dfd45f: scrub git's own hook-exported env (GIT_DIR et al) ONLY AFTER
# REPO_ROOT is resolved above. ds_repo_root (platform.sh), used in the
# non-CLAGENTIC_PROJECT_ROOT branch, calls bare `git rev-parse
# --show-toplevel` with no `-C` -- when gates.sh runs as a git hook it
# depends on git's own inherited GIT_DIR to correctly resolve the enrolled
# repo's root; scrubbing before that call would break repo-root resolution
# itself. Once REPO_ROOT is fixed, though, every `_git`/`-C "$REPO_ROOT"`
# call below must be the ONLY thing that decides which repo an operation
# touches -- verified empirically (this task) that an inherited GIT_DIR
# silently overrides an explicit `-C`, so leaving it set here would let it
# keep overriding every `_git` call for the rest of this script's run, not
# just the canary. Scrubbing here pins `-C "$REPO_ROOT"` from "usually
# right" to authoritative for the remainder of this invocation.
#
# This is the NARROW scrub: it clears only the vars that redirect which repo
# git touches, and leaves the user's own git configuration (credential
# helpers, url.*.insteadOf, proxy/CA, core.sshCommand, includeIf) alone.
# Every fetch, ls-remote and push below depends on that configuration to
# authenticate. The config-wiping scrub is ds_git_scratch_env_scrub, used
# only inside the secrets canary's scratch-repo subshell.
ds_git_env_scrub

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
# STRUCTURALLY BLIND to an inherited GIT_DIR (lr-dfd45f): both sides of the
# comparison below derive from the same poisoned resolution when GIT_DIR is
# exported (as git does for a hook invocation) -- `_grs_git_toplevel` comes
# from `_git rev-parse --show-toplevel`, which an inherited GIT_DIR silently
# overrides regardless of `-C "$REPO_ROOT"` (verified empirically), so it
# reports the SAME foreign repo GIT_DIR points at, not REPO_ROOT's own repo.
# The predicate then compares that foreign toplevel against REPO_ROOT and
# can spuriously report "scoped" even though every `_git` call it is meant
# to gate is actually operating on the wrong repo. This is why gates.sh
# calls ds_git_env_scrub (scripts/platform.sh) once, at top level, right
# after REPO_ROOT is resolved -- once GIT_DIR and friends are cleared,
# `-C "$REPO_ROOT"` is authoritative and this predicate's comparison is
# meaningful again. The identical predicate is triplicated in
# scripts/memory.sh (_mem_repo_root_is_scoped) and
# scripts/host-adapter.sh (_host_adapter_repo_root_is_scoped) -- same class,
# same blind spot, each file's own copy; not swept into a shared scrub call
# in this task (see lr-dfd45f PR body for why that follow-up is scoped
# separately).
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
      _rb_timeout=""
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
  _rb_timeout=$(ds_positive_int_or_default "$_rb_timeout" "$(ds_positive_int_or_warn CLAGENTIC_EXTERNAL_TIMEOUT_SEC "${CLAGENTIC_EXTERNAL_TIMEOUT_SEC:-}" 120)")
  $DS_TIMEOUT_CMD "$_rb_timeout" "$@"
}

# _bounded_failure_reason (EXIT_CODE TIMEOUT_SEC STDERR_FILE [NOTE]) is defined
# in scripts/platform.sh: bin/clagentic-lite's remote checks share the same
# credential masking and cannot source this file.

# _gate_check_args SUBCOMMAND "ALLOWED FLAGS" POSITIONAL_NAME ARGS...
#
# Argument hygiene for every subcommand. The dispatcher forwards "$@" to each
# cmd_X, so a subcommand that silently ignores an argument it does not know
# turns a typo (--fullscan) into a quietly narrower or different run.
# Returns 2 with a usage line on stderr for any `-`-prefixed argument not in
# the space-separated ALLOWED FLAGS, and for more than one positional
# argument (POSITIONAL_NAME, empty when the subcommand takes none, names the
# single optional positional in the usage line).
_gate_check_args() {
  _gca_sub="$1"
  _gca_flags="$2"
  _gca_posname="$3"
  shift 3
  _gca_usage="usage: gates.sh $_gca_sub"
  # A flag listed with a trailing '=' takes a value, given as the next argument
  # or as --flag=VALUE.
  for _gca_f in $_gca_flags; do
    case "$_gca_f" in
      *=) _gca_usage="$_gca_usage [${_gca_f%=} VALUE]" ;;
      *) _gca_usage="$_gca_usage [$_gca_f]" ;;
    esac
  done
  [ -n "$_gca_posname" ] && _gca_usage="$_gca_usage [$_gca_posname]"
  _gca_pos=0
  _gca_want_value=""
  for _gca_arg in "$@"; do
    if [ -n "$_gca_want_value" ]; then
      _gca_want_value=""
      continue
    fi
    case "$_gca_arg" in
      -*)
        # The argument is quoted inside the patterns: unquoted, a '*' or '?' in
        # it would match any listed flag.
        case " $_gca_flags " in
          *" ""$_gca_arg"" "*) continue ;;
        esac
        _gca_name=${_gca_arg%%=*}
        case " $_gca_flags " in
          *" ""$_gca_name""= "*)
            [ "$_gca_name" != "$_gca_arg" ] || _gca_want_value="$_gca_name"
            continue
            ;;
        esac
        printf "gates.sh %s: unknown option '%s'\n%s\n" "$_gca_sub" "$_gca_arg" "$_gca_usage" 1>&2
        return 2
        ;;
      *)
        _gca_pos=$((_gca_pos + 1))
        if [ -z "$_gca_posname" ] || [ "$_gca_pos" -gt 1 ]; then
          printf "gates.sh %s: unexpected argument '%s'\n%s\n" "$_gca_sub" "$_gca_arg" "$_gca_usage" 1>&2
          return 2
        fi
        ;;
    esac
  done
  if [ -n "$_gca_want_value" ]; then
    printf "gates.sh %s: option '%s' needs a value\n%s\n" "$_gca_sub" "$_gca_want_value" "$_gca_usage" 1>&2
    return 2
  fi
  return 0
}

AUDIT_DB="$REPO_ROOT/.clagentic/lite/audit.db"
mkdir -p "$REPO_ROOT/.clagentic/lite"

cmd_init() {
  _gate_check_args init "" "" "$@" || return 2
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

  # stderr is captured (not discarded) so the reason names git's own error: a
  # credential-helper or DNS failure must not read as a generic timeout, and
  # the two must stay distinguishable (exit 124 = deadline fired). hooksPath
  # is pinned off for this one command so a user-level hook configuration
  # (reference-transaction fires on fetch) cannot run inside a gate, without
  # wiping the rest of the user's git config the fetch needs to authenticate.
  # GIT_TERMINAL_PROMPT=0 makes a missing credential fail at once with git's
  # own error instead of waiting on a prompt until the timeout fires.
  _gfdbr_err=$(mktemp -t clagentic-gate-fetch-err.XXXXXX) || _gfdbr_err=/dev/null
  _gfdbr_rc=0
  $DS_TIMEOUT_CMD "$_gfdbr_timeout" env GIT_TERMINAL_PROMPT=0 git -C "$REPO_ROOT" -c core.hooksPath=/dev/null fetch origin "$_gfdbr_branch" >/dev/null 2>"$_gfdbr_err" || _gfdbr_rc=$?
  if [ "$_gfdbr_rc" -ne 0 ]; then
    _gfdbr_reason=$(_bounded_failure_reason "$_gfdbr_rc" "$_gfdbr_timeout" "$_gfdbr_err")
    [ "$_gfdbr_err" = /dev/null ] || rm -f "$_gfdbr_err"
    echo "git fetch origin ${_gfdbr_branch} ${_gfdbr_reason} — cannot establish a provably current baseline" 1>&2
    return 1
  fi
  [ "$_gfdbr_err" = /dev/null ] || rm -f "$_gfdbr_err"

  if ! _git rev-parse --verify -q "origin/${_gfdbr_branch}" >/dev/null 2>&1; then
    echo "origin/${_gfdbr_branch} not resolvable (missing remote-tracking ref)" 1>&2
    return 1
  fi

  _gfdbr_local_tip=$(_git rev-parse "origin/${_gfdbr_branch}" 2>/dev/null || echo "")
  _gfdbr_remote_tip=""
  _gfdbr_ls_reason="returned no tip for the branch"
  if [ -n "$_gfdbr_local_tip" ]; then
    _gfdbr_err=$(mktemp -t clagentic-gate-lsremote-err.XXXXXX) || _gfdbr_err=/dev/null
    _gfdbr_out=$(mktemp -t clagentic-gate-lsremote-out.XXXXXX) || _gfdbr_out=/dev/null
    _gfdbr_rc=0
    $DS_TIMEOUT_CMD "$_gfdbr_timeout" env GIT_TERMINAL_PROMPT=0 git -C "$REPO_ROOT" ls-remote origin "refs/heads/${_gfdbr_branch}" >"$_gfdbr_out" 2>"$_gfdbr_err" || _gfdbr_rc=$?
    if [ "$_gfdbr_rc" -ne 0 ]; then
      _gfdbr_ls_reason=$(_bounded_failure_reason "$_gfdbr_rc" "$_gfdbr_timeout" "$_gfdbr_err")
    else
      _gfdbr_remote_tip=$(awk '{print $1; exit}' "$_gfdbr_out")
    fi
    [ "$_gfdbr_err" = /dev/null ] || rm -f "$_gfdbr_err"
    [ "$_gfdbr_out" = /dev/null ] || rm -f "$_gfdbr_out"
  fi

  if [ -z "$_gfdbr_local_tip" ] || [ -z "$_gfdbr_remote_tip" ]; then
    echo "could not verify origin/${_gfdbr_branch} freshness (ls-remote ${_gfdbr_ls_reason}) — resolution not provably current" 1>&2
    return 1
  fi

  if [ "$_gfdbr_local_tip" != "$_gfdbr_remote_tip" ]; then
    echo "origin/${_gfdbr_branch} (${_gfdbr_local_tip}) does not match remote tip (${_gfdbr_remote_tip}) — stale ref, not provably current" 1>&2
    return 1
  fi

  printf '%s\n' "$_gfdbr_local_tip"
  return 0
}

# ---------------------------------------------------------------- gate input domain (lr-1ad8da) --
#
# WHY THIS EXISTS: cmd_pre_push has run deps+sast unconditionally since
# 6fe6fe6 (initial commit). When a push's diff touches no file either gate
# READS, the gate's verdict cannot possibly change — yet a pre-existing
# finding (e.g. an advisory DB publishing against an unchanged dependency)
# still blocks the push. The only escape was --no-verify, which disables
# EVERY gate including ones that genuinely apply — teaching --no-verify is
# itself a defect, and it also contradicts INV-8 (AGENTS.md): a fix must not
# require a flag to be received.
#
# CORRECT UNIT: a gate's INPUT DOMAIN — the set of paths whose contents its
# verdict can possibly depend on. Domain is an ALLOWLIST of what a gate
# READS, never a denylist of what to ignore (a denylist silently narrows on
# every future file shape nobody thought to exclude; an allowlist silently
# narrows on nothing — an unrecognized path is always IN domain by
# construction, see _gate_path_in_domain below).
#
# Irrelevance is COMPUTED by this harness from the changed-path set and the
# gate's declared domain — it is NEVER asserted by the pusher (no
# --docs-only flag, no *.md exemption, no per-repo path-exclusion config;
# all three rejected explicitly, lr-1ad8da task description — a
# pusher-supplied claim about their own diff is a bypass with extra steps).
#
# DOMAIN TABLE (one row per gate that supports skip-when-out-of-domain):
#   secrets      — NOT ELIGIBLE. Every file, unconditionally. This row is
#                  load-bearing: it is what stops this feature from
#                  degenerating into "skip gates on docs" — a credential
#                  pastes into a Markdown file exactly as easily as a
#                  source file. cmd_secrets never consults this mechanism.
#   deps         — manifests+lockfiles PER ECOSYSTEM, resolved from the
#                  ecosystem list the scanner itself supports (see
#                  _gate_deps_domain_globs below), never a hardcoded
#                  filename set maintained independently of the tool.
#   sast         — source files in the languages semgrep's active ruleset
#                  covers, plus build/config files the rules read. Since
#                  cmd_sast's default config is `auto` (registry-selected
#                  per-language rulesets, resolved at scan time from
#                  file extensions actually present), this gate's domain
#                  is "any file semgrep would examine" — approximated here
#                  by the same broad source/config extension set semgrep's
#                  own auto-config targets, documented below rather than
#                  re-derived from a live registry call on every push.
#   review /     — every file (the diff itself is the input to an LLM
#   adversarial    reasoning pass — there is no narrower "domain" to
#                  declare; these are gated by other opt-in mechanisms
#                  already, e.g. CLAGENTIC_REVIEW_ON_PUSH, and are excluded
#                  from this mechanism entirely).
#
# GATE CONFIGURATION IS IN EVERY GATE'S DOMAIN (task requirement 2). If the
# changed-path set touches ANY gate's own config — ruleset, ignore/allow
# list, severity threshold, version floor, suppression file — NO gate may be
# skipped on that push, regardless of what else changed. Without this the
# mechanism has a privilege-escalation shape: weaken a gate's config and
# skip the gate that would have noticed, in the same push. See
# _gate_config_paths and _gate_path_touches_any_gate_config below.
#
# THIRD STATE, NEVER PASS (task requirement 3): a gate whose verdict cannot
# depend on the changed-path set reports outcome "not_applicable" — a
# distinct value from "pass"/"block"/"skip"/"warn" everywhere this codebase
# already writes gate_runs.outcome. A pass claims the tool ran and found
# nothing; not_applicable claims the tool never needed to run at all. The
# audit details column carries the domain tested against, the changed-path
# set tested with, and how that set was derived — see
# _gate_skip_or_run_domain below, the one function that writes this outcome.
#
# FAIL CLOSED (task requirement 5, enumerated per-case below in
# _gate_resolve_changed_paths). Any inconclusive range makes the WHOLE push
# inconclusive — inconclusive means "run the gate," never "skip the gate."
#
# ALWAYS_RUN_ALL_GATES SWITCH (operator decision, task description):
# default OFF — domain-based skipping is active by default. Set
# CLAGENTIC_ALWAYS_RUN_ALL_GATES=1 to disable this mechanism entirely and
# run every gate unconditionally on every push, matching pre-lr-1ad8da
# behavior byte-for-byte. Defaulting this ON would make the whole feature
# dead code (operator's own reasoning, task description) — this is a
# deliberate, recorded default, not an oversight.

# _gate_always_run_all_gates — true (exit 0) when domain-based skipping is
# disabled by operator config. The one place this env var is read, so every
# caller agrees on the same on/off semantics.
_gate_always_run_all_gates() {
  [ "${CLAGENTIC_ALWAYS_RUN_ALL_GATES:-0}" = "1" ]
}

# _gate_deps_domain_globs — print, one per line, the shell glob patterns
# that make up cmd_deps' input domain: manifest/lockfile names PER ECOSYSTEM.
#
# MAINTENANCE PATH (task requirement: "name the maintenance path rather than
# hardcoding a snapshot" — domain data is harness-side knowledge that DRIFTS
# with the upstream scanner): osv-scanner's own `--help` output enumerates
# no machine-readable ecosystem/filename list as of the installed-version
# probe this codebase already does elsewhere (capability-probed, never
# version-string-parsed — see cmd_deps' own _OSV_SUBCMD probe above). There
# is no local, offline way to ask an installed osv-scanner binary "what
# manifest filenames do you recognize" without shipping a TOML/JSON schema
# parser for its internal ecosystem registry, which AGENTS.md's "no new
# external tool dependency without asking" bars introducing for this one
# purpose. The list below is therefore a DOCUMENTED SNAPSHOT of
# osv-scanner's own publicly documented lockfile/manifest support
# (https://google.github.io/osv-scanner/supported-languages-and-lockfiles/),
# versioned via CLAGENTIC_DEPS_DOMAIN_VERSION below so a future drift is a
# one-line diff, not a silent staleness — and it is OVERRIDABLE per-repo via
# CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS (space-separated glob patterns appended
# to this list) for a repo using an ecosystem/manifest shape newer than this
# snapshot, without waiting for a clagentic-lite release.
#
# This list is even more conservative than it needs to be by construction:
# _gate_path_touches_any_gate_config (below) ALSO widens the domain to
# match "anything under scripts/gates.sh's own osv-ignore/config paths" —
# so a gap in this glob list only means a REAL manifest change might be
# missed as in-domain (an under-block risk, not an over-skip risk) is
# still caught by the fail-closed default below: an unrecognized file
# extension/shape is simply matched by none of these globs and therefore
# treated as NOT proven to be in the deps domain — the caller
# (_gate_path_in_domain) still defaults toward running the gate whenever
# ANY changed path fails to match a declared domain (see that function's
# own doc comment for the exact predicate).
CLAGENTIC_DEPS_DOMAIN_VERSION="v1-2026-09"
_gate_deps_domain_globs() {
  cat <<'EOF'
package.json
package-lock.json
npm-shrinkwrap.json
yarn.lock
pnpm-lock.yaml
bun.lock
requirements*.txt
Pipfile
Pipfile.lock
pyproject.toml
poetry.lock
setup.py
setup.cfg
Gemfile
Gemfile.lock
go.mod
go.sum
Cargo.toml
Cargo.lock
composer.json
composer.lock
pom.xml
build.gradle
build.gradle.kts
gradle.lockfile
*.csproj
packages.lock.json
mix.exs
mix.lock
pubspec.yaml
pubspec.lock
conan.lock
EOF
  if [ -n "${CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS:-}" ]; then
    for _gddg_extra in $CLAGENTIC_DEPS_DOMAIN_EXTRA_GLOBS; do
      printf '%s\n' "$_gddg_extra"
    done
  fi
}

# _gate_sast_domain_globs — print, one per line, the glob patterns that make
# up cmd_sast's input domain: source files in the languages semgrep's
# default `--config=auto` ruleset covers, plus build/config files those
# rules commonly read (e.g. package.json for a JS taint rule, Dockerfile for
# an IaC rule). Same maintenance posture as deps: a documented, versioned
# snapshot, overridable via CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS, because
# semgrep's registry-selected rule coverage is upstream knowledge this
# harness does not own and cannot query offline without a network call this
# codebase's own security posture already forbids putting on the blocking
# path unconditionally (AGENTS.md §4: no LLM/network dependency added to the
# blocking security path beyond what the tool itself already does).
#
# When CLAGENTIC_SEMGREP_CONFIG is pinned (a non-auto policy path — see
# _sast_config_flag above), that policy may cover a narrower or wider file
# set than semgrep's registry auto-config. This snapshot is NOT re-derived
# per pinned config (would require parsing the pinned ruleset's own
# `languages:` keys, a materially larger feature) — a pinned config makes
# this domain a conservative approximation, documented here rather than
# silently assumed precise.
CLAGENTIC_SAST_DOMAIN_VERSION="v1-2026-09"
_gate_sast_domain_globs() {
  cat <<'EOF'
*.py
*.js
*.jsx
*.ts
*.tsx
*.mjs
*.cjs
*.go
*.rb
*.php
*.java
*.kt
*.scala
*.c
*.h
*.cpp
*.cc
*.hpp
*.cs
*.swift
*.rs
*.sh
*.bash
*.tf
*.yaml
*.yml
*.json
Dockerfile
Dockerfile.*
*.dockerfile
EOF
  if [ -n "${CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS:-}" ]; then
    for _gsdg_extra in $CLAGENTIC_SAST_DOMAIN_EXTRA_GLOBS; do
      printf '%s\n' "$_gsdg_extra"
    done
  fi
}

# _gate_config_paths — print, one per line, every path (relative to
# REPO_ROOT) or glob this codebase itself treats as GATE CONFIGURATION for
# ANY gate: a ruleset pin, an ignore/allow list, a severity threshold file,
# a version-floor marker, or a suppression file. Task requirement 2: gate
# configuration is in EVERY gate's domain — a change to any one of these
# means NO gate may be skipped on this push, not just the gate the config
# belongs to. This is the mechanical closure of the privilege-escalation
# shape the task names explicitly: weaken a gate's config and skip the gate
# that would have noticed, in the same push.
#
# Repo-local paths only (global config under $HOME is outside any repo diff
# by construction and cannot appear in a changed-path set at all).
_gate_config_paths() {
  cat <<'EOF'
.gitleaks.toml
.clagentic/osv-ignore
.clagentic/semgrep-exclude
.semgrepignore
.clagentic/config
.clagentic-bleed-ignore
.clagentic/bleed-patterns
.clagentic/dispositions.json
.clagentic/deferrals.json
.clagentic/adversarial-acks.json
.clagentic/accepted-risks.md
EOF
}

# _gate_path_touches_any_gate_config CHANGED_PATHS_FILE — true (exit 0) when
# any line in CHANGED_PATHS_FILE exactly matches (or, for the two glob-style
# entries above, is matched by) a path _gate_config_paths declares. Reused
# by every gate's skip decision — see _gate_skip_or_run_domain below.
_gate_path_touches_any_gate_config() {
  _gptagc_file="$1"
  [ -s "$_gptagc_file" ] || return 1
  while IFS= read -r _gptagc_cfg; do
    [ -n "$_gptagc_cfg" ] || continue
    while IFS= read -r _gptagc_changed; do
      [ -n "$_gptagc_changed" ] || continue
      case "$_gptagc_changed" in
        $_gptagc_cfg) return 0 ;;
      esac
    done < "$_gptagc_file"
  done <<EOF_CFG
$(_gate_config_paths)
EOF_CFG
  return 1
}

# _gate_path_in_domain PATH DOMAIN_GLOBS_NEWLINE — true (exit 0) when PATH
# matches at least one glob in DOMAIN_GLOBS_NEWLINE (newline-separated,
# shell glob syntax via `case`). Domain is an ALLOWLIST (task requirement
# 4): an unrecognized path shape simply matches nothing here and is treated
# by the caller as NOT proven in-domain — see _gate_resolve_changed_paths'
# and _gate_skip_or_run_domain's fail-closed composition below. This
# function only answers "does this one path match this one domain," it does
# not itself decide fail-open/fail-closed.
_gate_path_in_domain() {
  _gpid_path="$1"
  _gpid_globs="$2"
  _gpid_base=$(basename -- "$_gpid_path")
  while IFS= read -r _gpid_glob; do
    [ -n "$_gpid_glob" ] || continue
    case "$_gpid_path" in $_gpid_glob) return 0 ;; esac
    case "$_gpid_base" in $_gpid_glob) return 0 ;; esac
  done <<EOF_GLOBS
$_gpid_globs
EOF_GLOBS
  return 1
}

# _gate_resolve_changed_paths OUT_FILE GITLINK_OUT_FILE — resolve the
# changed-path set for THIS invocation of cmd_pre_push and write it, one
# path per line, to OUT_FILE. GITLINK_OUT_FILE additionally receives the
# subset of those paths whose raw diff mode (old or new side) is 160000
# (a submodule gitlink entry) — see _gate_skip_or_run_domain's use of this
# second file, which forces every gate to run whenever it is non-empty,
# the same way a gate-config touch does. A gitlink path essentially never
# matches a source/manifest domain glob on its own, so without this
# explicit escape hatch a submodule-pointer-only push would satisfy the
# "every changed path proven out of domain" skip condition and both deps
# and sast would wrongly report not_applicable on a change that can
# introduce arbitrary new dependency/source content one level down.
# Prints a one-line derivation description on stdout on success (how the
# set was computed — for the audit trail's "how that set was derived"
# requirement). Returns 1 (OUT_FILE left empty/absent) whenever the set
# cannot be determined with certainty — the caller's job is to treat THAT
# as "run every gate," never "skip."
#
# stdin protocol (git's pre-push hook contract): zero or more lines of
# "<local ref> <local sha1> <remote ref> <remote sha1>", one per ref being
# pushed. cmd_pre_push is invoked by share/hook-shims/pre-push.template,
# which execs this script with git's own stdin passed through untouched —
# this function is the first place in this codebase that actually reads
# that stdin protocol; every gate before lr-1ad8da ignored it entirely and
# operated on working-tree/HEAD state regardless of what was being pushed.
#
# FAIL-CLOSED ENUMERATION (task requirement 5 — each case is a real way to
# get this wrong):
#   - Multiple refs in one push: the union of every ref's own changed-path
#     range is the input; any ONE ref's range being inconclusive makes the
#     WHOLE push inconclusive, not just that ref.
#   - A new branch with no merge-base (local sha exists, remote sha is the
#     all-zero deletion/creation sentinel): no base to diff against —
#     inconclusive.
#   - A deletion push (local sha1 is the all-zero sentinel): nothing being
#     pushed to diff FROM — inconclusive (there is no "changed paths of a
#     delete" this mechanism can safely compute).
#   - A force push (the pushed local sha1 is not a descendant of the
#     previously-known remote sha1): `git diff old..new` on a force-pushed
#     ref does not describe what the remote will actually hold afterward —
#     inconclusive. Detected via `git merge-base --is-ancestor`.
#   - Shallow history: `git merge-base`/`git diff` against a commit outside
#     a shallow clone's fetched depth fails or produces a misleading
#     result — detected via `git rev-parse --is-shallow-repository`.
#   - Grafted history (legacy `.git/info/grafts`, or its modern
#     equivalent, a `refs/replace/*` ref rewriting a commit's recorded
#     parents): NOT the same mechanism as shallow and NOT caught by
#     `--is-shallow-repository` — confirmed empirically that a graft does
#     not set the shallow flag. Worse, unlike ordinary truncated/
#     unresolvable history, a graft does not make the ancestor check below
#     fail closed either: it can make `git merge-base --is-ancestor`
#     return a FALSE POSITIVE by forging an ancestry relationship between
#     two otherwise-unrelated commits (verified: grafting one orphan
#     chain's tip to claim a wholly unrelated chain's commit as its parent
#     made `--is-ancestor` report that fake parent as a real ancestor).
#     Detected via a direct check for a non-empty `info/grafts` file
#     (resolved via `--absolute-git-dir`, since `--git-path` returns a
#     REPO_ROOT-relative path this script's CWD may not match) or any ref
#     under `refs/replace`; either signal alone is inconclusive.
#   - A merge commit in the pushed range: can introduce files present in
#     neither parent's first-parent path. `git diff old..new --raw`
#     already reports the full diff (not first-parent-only), so a merge
#     commit's actual file introductions ARE captured by that diff — but
#     this function additionally refuses (falls to inconclusive) if it
#     cannot prove `old` is a proper ancestor of `new` via a clean, single
#     linear merge-base (the same force-push check above also catches an
#     unrelated-history merge).
#   - Submodule pointer changes: `git diff --raw` reports the submodule's
#     own path changing with mode 160000 (a gitlink entry) on the old
#     and/or new side. This function additionally writes every such path
#     to GITLINK_OUT_FILE (a second output param — see this function's own
#     header comment), which _gate_skip_or_run_domain treats the same as
#     a gate-config touch: no gate may be skipped on a push whose
#     changed-path set includes a gitlink. A gitlink path almost never
#     matches a source/manifest domain glob on its own, so without this
#     explicit escape hatch a submodule-pointer-only push would otherwise
#     satisfy the ordinary "every changed path proven out of domain" skip
#     condition despite a submodule bump being able to introduce arbitrary
#     new dependency/source content this push's own diff cannot see.
#   - Symlink creation/retargeting and file mode changes: unlike
#     `--name-only`, `--raw` reports every path whose MODE changed even
#     when its blob content did not, so a path whose ONLY change is a
#     mode/symlink flip with byte-identical content still appears in the
#     changed-path set with no second, parallel parse needed — see the
#     `--raw -z` parse below. A path whose ONLY change is a mode/symlink
#     flip still counts as changed for domain purposes (a .md becoming a
#     symlink or becoming executable is not a prose change, per the task's
#     own framing).
#   - Vendored dependencies under a documentation path, and generated/
#     literate documents that are compiled or executed: this mechanism does
#     not special-case any path by directory name (docs/, vendor/, etc.) at
#     all — domain matching is by file NAME/EXTENSION shape only (see
#     _gate_path_in_domain), never by directory location. A manifest file
#     sitting under docs/ still matches the deps domain; a compiled/literate
#     document with a source-code extension still matches the sast domain.
#     There is no directory-based carve-out anywhere in this mechanism for
#     this exact reason.
_gate_resolve_changed_paths() {
  _grcp_out="$1"
  _grcp_gitlink_out="$2"
  : > "$_grcp_out"
  : > "$_grcp_gitlink_out"

  if ! _git_repo_root_is_scoped; then
    echo "REPO_ROOT is not a git repo — changed-path set cannot be determined" 1>&2
    return 1
  fi

  # Read every "<local-ref> <local-sha> <remote-ref> <remote-sha>" line from
  # stdin (git's pre-push hook protocol). No lines at all (an empty push, or
  # this function invoked outside the real hook context) is itself
  # inconclusive -- there is nothing to compute a range from.
  _grcp_lines_tmp=$(mktemp -t clagentic-prepush-refs.XXXXXX)
  cat > "$_grcp_lines_tmp"
  if [ ! -s "$_grcp_lines_tmp" ]; then
    rm -f "$_grcp_lines_tmp"
    echo "no ref lines on stdin — changed-path set cannot be determined" 1>&2
    return 1
  fi

  _grcp_zero="0000000000000000000000000000000000000000"
  _grcp_union_tmp=$(mktemp -t clagentic-prepush-union.XXXXXX)
  : > "$_grcp_union_tmp"
  _grcp_reasons=""

  while IFS=' ' read -r _grcp_lref _grcp_lsha _grcp_rref _grcp_rsha; do
    [ -n "$_grcp_lref" ] || continue

    # Deletion push: local sha is the all-zero sentinel -- nothing to diff
    # FROM. Inconclusive by definition (task enumeration: "deletions").
    if [ "$_grcp_lsha" = "$_grcp_zero" ]; then
      rm -f "$_grcp_lines_tmp" "$_grcp_union_tmp" "$_grcp_raw_tmp"
      echo "ref $_grcp_lref is a deletion push (local sha all-zero) — inconclusive" 1>&2
      return 1
    fi

    # New branch / no merge-base: remote sha is the all-zero sentinel --
    # nothing to diff AGAINST on the remote side for this ref.
    if [ "$_grcp_rsha" = "$_grcp_zero" ]; then
      rm -f "$_grcp_lines_tmp" "$_grcp_union_tmp" "$_grcp_raw_tmp"
      echo "ref $_grcp_lref has no remote-side base (new ref) — inconclusive" 1>&2
      return 1
    fi

    # Shallow history: a merge-base or diff computed against a commit
    # outside the fetched depth is unreliable. Refuse outright rather than
    # trust whatever git happens to return.
    if _git rev-parse --is-shallow-repository 2>/dev/null | grep -q '^true$'; then
      rm -f "$_grcp_lines_tmp" "$_grcp_union_tmp" "$_grcp_raw_tmp"
      echo "repository is shallow — changed-path range cannot be trusted — inconclusive" 1>&2
      return 1
    fi

    # Grafted history (legacy .git/info/grafts, or its modern equivalent,
    # a refs/replace/* ref rewriting a commit's recorded parents): NOT
    # caught by --is-shallow-repository (grafts are a separate mechanism,
    # confirmed empirically -- a graft does not set the shallow flag) and,
    # unlike ordinary truncated/unresolvable history, does NOT make the
    # ancestor check below fail closed -- it can make `git merge-base
    # --is-ancestor` return a FALSE POSITIVE by forging an ancestry
    # relationship between two otherwise-unrelated commits (verified: a
    # graft giving one orphan chain's tip a fake parent from a second,
    # wholly unrelated chain made --is-ancestor report the fake parent as
    # an ancestor). Refuse outright whenever either mechanism is present,
    # rather than trust an ancestor/diff computation that may be rewritten
    # underneath it.
    _grcp_git_dir=$(_git rev-parse --absolute-git-dir 2>/dev/null)
    if [ -n "$_grcp_git_dir" ] && [ -s "$_grcp_git_dir/info/grafts" ]; then
      rm -f "$_grcp_lines_tmp" "$_grcp_union_tmp" "$_grcp_raw_tmp"
      echo "repository has grafted history (info/grafts) — changed-path range cannot be trusted — inconclusive" 1>&2
      return 1
    fi
    if [ -n "$(_git for-each-ref refs/replace 2>/dev/null)" ]; then
      rm -f "$_grcp_lines_tmp" "$_grcp_union_tmp" "$_grcp_raw_tmp"
      echo "repository has grafted history (refs/replace) — changed-path range cannot be trusted — inconclusive" 1>&2
      return 1
    fi

    # Force push / unrelated history / merge commit onto unrelated history:
    # the remote-known sha must be a proper ancestor of the sha being
    # pushed for old..new to describe what the remote will actually hold
    # afterward. `--is-ancestor` also fails closed on either sha being
    # unresolvable, which is exactly the
    # "cannot be determined" case this function must refuse on.
    if ! _git merge-base --is-ancestor "$_grcp_rsha" "$_grcp_lsha" 2>/dev/null; then
      rm -f "$_grcp_lines_tmp" "$_grcp_union_tmp" "$_grcp_raw_tmp"
      echo "ref $_grcp_lref: remote sha is not an ancestor of the pushed sha (force push, rewrite, or unrelated history) — inconclusive" 1>&2
      return 1
    fi

    # Raw diff, NUL-delimited (-z), no rename/copy detection (-M/-C never
    # passed): a single source of every changed path, sidestepping the
    # quoting class entirely rather than parsing around it (lr-1ad8da
    # follow-up; PEACHES/BOBBIE both independently flagged the prior
    # --name-only + --summary/sed union as fail-open on a quoted path).
    #
    # WHY --raw -z REPLACES BOTH --name-only AND --summary: `--raw` reports
    # every path whose mode, blob sha, or existence changed -- ordinary
    # content edits, additions, deletions, submodule gitlink bumps, AND
    # mode-only/symlink-only flips with byte-identical content -- in one
    # consistent record shape, so no second, parallel invocation is needed
    # to catch the mode/symlink gap --name-only alone has.
    #
    # WHY -z SPECIFICALLY: without -z, git C-quotes any path containing a
    # space, a double quote, a backslash, or a non-ASCII byte as a single
    # double-quoted, backslash-escaped literal (core.quotepath, on by
    # default) -- e.g. `"file with space.py"` INCLUDING the quote
    # characters. That quoted literal then reaches _gate_path_in_domain's
    # glob match unchanged, where `*.py` never matches `"file.py"` -- a
    # content-identical mode flip or symlink retarget on such a path would
    # be silently dropped from the changed-path set and could cause a
    # gate to skip that should have run. `-z` disables this quoting
    # entirely: paths are NUL-terminated raw bytes, never escaped.
    #
    # RESIDUAL, DISCLOSED GAP: converting the NUL stream to newline-
    # delimited text below (`tr '\0' '\n'`) to parse in POSIX sh means a
    # path containing a LITERAL embedded newline byte (permitted by git,
    # vanishingly rare on any real filesystem/toolchain) would still
    # mis-split. This is a narrower, pre-existing residual across most
    # shell tooling (not the vulnerability class found here -- that was
    # ordinary spaces/quotes/non-ASCII defeating quoting, which -z fixes
    # completely) and is unrelated to and no worse than this function's
    # prior --name-only behavior for that same edge case.
    # --no-renames is REQUIRED, not cosmetic: modern git enables rename
    # detection for `git diff` by default (diff.renames), which would
    # widen an R-status record from two NUL-terminated fields
    # (status\0path\0) to three (status\0oldpath\0newpath\0) and desync
    # the fixed "every second token is a path" pairing below for exactly
    # the pushes this mechanism most needs to get right. Forcing it off
    # here pins the two-field shape regardless of the invoking
    # environment's diff.renames setting; --no-renames also does not
    # suppress the change itself -- a rename still surfaces as a plain
    # delete-then-add pair of paths, both still present in the set.
    _grcp_raw_tmp=$(mktemp -t clagentic-prepush-raw.XXXXXX)
    _git diff -z --no-renames "${_grcp_rsha}..${_grcp_lsha}" --raw 2>/dev/null > "$_grcp_raw_tmp" || {
      rm -f "$_grcp_lines_tmp" "$_grcp_union_tmp" "$_grcp_raw_tmp"
      echo "ref $_grcp_lref: git diff --raw failed — inconclusive" 1>&2
      return 1
    }

    # Each raw -z record is ":oldmode newmode oldsha newsha status\0path\0"
    # -- two NUL-terminated fields per changed path (--no-renames above
    # guarantees this shape). Convert to one token per line; odd lines are
    # the status/mode metadata, even lines are the path. Every path goes
    # to the union file; a path whose metadata line names mode 160000 on
    # either side (a submodule gitlink) additionally goes to the gitlink
    # file — see this function's own doc comment for why that second file
    # exists.
    tr '\0' '\n' < "$_grcp_raw_tmp" | awk -v union="$_grcp_union_tmp" -v gitlink="$_grcp_gitlink_out" '
      NR % 2 == 1 { meta = $0; is_gitlink = (meta ~ /(^|[[:space:]])160000([[:space:]]|$)/); next }
      { print > union; if (is_gitlink) print > gitlink }
    '
    rm -f "$_grcp_raw_tmp"

    _grcp_reasons="${_grcp_reasons}${_grcp_reasons:+; }ref $_grcp_lref: diff ${_grcp_rsha}..${_grcp_lsha}"
  done < "$_grcp_lines_tmp"
  rm -f "$_grcp_lines_tmp"

  sort -u "$_grcp_union_tmp" > "$_grcp_out" 2>/dev/null || cp "$_grcp_union_tmp" "$_grcp_out"
  rm -f "$_grcp_union_tmp"

  if [ -z "$_grcp_reasons" ]; then
    echo "no ref lines produced a resolvable range — inconclusive" 1>&2
    return 1
  fi

  printf '%s\n' "$_grcp_reasons"
  return 0
}

# _gate_skip_or_run_domain GATE DOMAIN_GLOBS_FN DOMAIN_VERSION REFS_FILE —
# the single decision point every domain-eligible gate consults. REFS_FILE
# is a snapshot of git's pre-push stdin protocol lines (see
# _gate_resolve_changed_paths' own doc comment) — cmd_pre_push reads real
# stdin exactly ONCE into a temp file and passes that snapshot's path to
# every gate this mechanism covers, so a second/third gate in the same
# pre-push invocation never has to contend with an already-drained pipe.
# Direct/manual invocation (e.g. `gates.sh deps` outside the real hook) has
# no such snapshot; callers pass /dev/null in that case, which
# _gate_resolve_changed_paths correctly reports as "no ref lines" —
# inconclusive, and therefore always runs the gate (fail-closed by
# construction, not a special case this function needs to detect).
#
# Returns 0 and prints nothing when the gate should run normally
# (in-domain, or resolution was inconclusive — fail closed means RUN).
# Returns 2 (a THIRD, distinct status, never confused with "run"=0 or a real
# gate failure=1) when the gate is genuinely out of domain and prints the
# not_applicable audit-details line on stdout — see cmd_deps/cmd_sast's own
# call sites for exactly how that outcome is logged.
#
# Never called for cmd_secrets (secrets is NOT ELIGIBLE for skipping at
# all — task requirement 1, this is load-bearing) or for review/adversarial
# (out of scope — see the domain table's own comment above).
_gate_skip_or_run_domain() {
  _gsord_gate="$1"
  _gsord_domain_fn="$2"
  _gsord_domain_version="$3"
  _gsord_refs_file="$4"

  if _gate_always_run_all_gates; then
    return 0
  fi

  _gsord_changed_tmp=$(mktemp -t clagentic-domain-changed.XXXXXX)
  _gsord_gitlink_tmp=$(mktemp -t clagentic-domain-gitlink.XXXXXX)
  _gsord_err_tmp=$(mktemp -t clagentic-domain-err.XXXXXX)
  _gsord_derivation=""
  if ! _gsord_derivation=$(_gate_resolve_changed_paths "$_gsord_changed_tmp" "$_gsord_gitlink_tmp" < "$_gsord_refs_file" 2>"$_gsord_err_tmp"); then
    echo "[gates/$_gsord_gate] $(cat "$_gsord_err_tmp" 2>/dev/null) — running (fail closed)" 1>&2
    rm -f "$_gsord_changed_tmp" "$_gsord_gitlink_tmp" "$_gsord_err_tmp"
    return 0
  fi
  rm -f "$_gsord_err_tmp"

  if [ ! -s "$_gsord_changed_tmp" ]; then
    rm -f "$_gsord_changed_tmp" "$_gsord_gitlink_tmp"
    return 0
  fi

  if _gate_path_touches_any_gate_config "$_gsord_changed_tmp"; then
    echo "[gates/$_gsord_gate] changed-path set touches gate configuration — no gate may be skipped on this push" 1>&2
    rm -f "$_gsord_changed_tmp" "$_gsord_gitlink_tmp"
    return 0
  fi

  # A submodule pointer (gitlink) change is never skippable either, for
  # either gate: a gitlink path almost never matches a source/manifest
  # domain glob on its own, which would otherwise satisfy the "every
  # changed path proven out of domain" skip condition below even though a
  # submodule bump can introduce an arbitrary new dependency or source
  # tree one level down that this push's own diff cannot see the content
  # of. Same escape-hatch shape as the gate-config check above.
  if [ -s "$_gsord_gitlink_tmp" ]; then
    echo "[gates/$_gsord_gate] changed-path set touches a submodule pointer (gitlink) — no gate may be skipped on this push" 1>&2
    rm -f "$_gsord_changed_tmp" "$_gsord_gitlink_tmp"
    return 0
  fi
  rm -f "$_gsord_gitlink_tmp"

  # A gate skips ONLY when EVERY changed path is proven to be OUTSIDE its
  # domain (allowlist semantics, task requirement 4) -- a single path that
  # is not affirmatively proven in-domain is enough to keep the gate
  # running, since the allowlist has no way to assert "this path is
  # definitely irrelevant" beyond "it doesn't match anything I declared."
  _gsord_domain_globs=$($_gsord_domain_fn)
  _gsord_changed_count=$(wc -l < "$_gsord_changed_tmp" | tr -d '[:space:]')
  _gsord_in_domain_count=0
  while IFS= read -r _gsord_changed_path; do
    [ -n "$_gsord_changed_path" ] || continue
    _gate_path_in_domain "$_gsord_changed_path" "$_gsord_domain_globs" && _gsord_in_domain_count=$((_gsord_in_domain_count + 1))
  done < "$_gsord_changed_tmp"

  if [ "$_gsord_in_domain_count" = "0" ] && [ "$_gsord_changed_count" != "0" ]; then
    echo "not_applicable|domain=${_gsord_domain_version}|changed=${_gsord_changed_count} path(s)|derivation=${_gsord_derivation}"
    rm -f "$_gsord_changed_tmp"
    return 2
  fi

  rm -f "$_gsord_changed_tmp"
  return 0
}

# _gitleaks_config_declares_rules FILE (lr-170808, scope item 1)
#
# WHY THIS EXISTS: gitleaks' --config REPLACES the embedded ruleset, it does
# not merge with it. A repo-supplied .gitleaks.toml consisting solely of an
# [allowlist]/[[allowlists]] block — the single most natural file to write
# when the intent is "suppress these known false positives" — silently loads
# ZERO detection rules. An allowlist can only suppress what a rule first
# matched; with no rules, nothing is ever found, and the gate reports a
# permanent, convincing "no leaks found" pass. Honoring a repo-supplied
# config is correct; the defect is trusting one that eliminates detection
# entirely rather than narrowing it.
#
# CONTRACT: FILE declares usable detection when it contains at least one
# `[[rules]]` table header OR an `[extend]` block with `useDefault = true`
# (gitleaks' own documented mechanism for re-including the built-in ruleset
# on top of a repo override — see .gitleaks.toml's own header comment and
# the gitleaks project's own README "Configuration" section for the
# upstream spec this mirrors). Text-level detection,
# not a TOML parser: gitleaks.toml is a small, well-known config shape and
# this codebase has no TOML library dependency anywhere else (AGENTS.md
# "what to ask the user" — no new external tool without asking). A
# `useDefault` line inside a table this function does not recognize as
# `[extend]` is deliberately NOT enough on its own — see the state-machine
# comment inline below for why a bare substring grep for "useDefault = true"
# would false-positive on that same text appearing in an unrelated table
# (e.g. a future gitleaks config key that happens to share the name) or in
# a comment.
#
# Returns 0 (declares rules — safe to trust) or 1 (declares none — the
# caller must fail closed). A missing/unreadable FILE is the caller's own
# concern (this function is only ever called after `[ -f FILE ]` already
# passed) — treated as "no rules declared" if called directly, matching the
# fail-closed posture of every other branch here.
_gitleaks_config_declares_rules() {
  _gcdr_file="$1"
  [ -f "$_gcdr_file" ] || return 1

  # [[rules]] — an array-of-tables header, one or more. Anchored to the
  # start of a line (ignoring leading whitespace) so this cannot match
  # "[[rules]]" appearing inside a quoted string value or a comment on the
  # same line as other content — gitleaks' own TOML table-header syntax is
  # always alone on its line.
  if grep -qE '^[[:space:]]*\[\[rules\]\][[:space:]]*$' "$_gcdr_file" 2>/dev/null; then
    return 0
  fi

  # [extend] useDefault = true — a two-line state check, not a bare
  # substring grep for "useDefault", because `useDefault = true` is only
  # meaningful directly under an `[extend]` table header. Approach: locate
  # every `[extend]` table header line number, then check whether a
  # `useDefault = true` line (allowing for TOML's optional whitespace around
  # `=` and either bare/quoted `true`) appears before the NEXT table header
  # (`[...]` or `[[...]]`) or end of file — i.e. still inside that same
  # table. This is a real (if minimal) TOML table-scoping check, not a
  # flat grep, so a `useDefault = true` line sitting under a different
  # table (or one gitleaks would itself reject as out of place) is
  # correctly NOT treated as extending the default ruleset.
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$_gcdr_file" <<'PYEOF'
import re
import sys

path = sys.argv[1]
try:
    with open(path) as f:
        lines = f.readlines()
except Exception:
    sys.exit(1)

table_header_re = re.compile(r'^\s*\[\[?[^\]]+\]\]?\s*(#.*)?$')
extend_header_re = re.compile(r'^\s*\[extend\]\s*(#.*)?$')
use_default_re = re.compile(r'^\s*useDefault\s*=\s*true\s*(#.*)?$')

in_extend = False
for line in lines:
    if table_header_re.match(line):
        in_extend = bool(extend_header_re.match(line))
        continue
    if in_extend and use_default_re.match(line):
        sys.exit(0)
sys.exit(1)
PYEOF
    return $?
  fi

  # No python3 — fall back to a narrower (still anchored) heuristic: an
  # exact `[extend]` header line followed, ANYWHERE later in the file, by a
  # `useDefault = true` line. This can false-positive if a later,
  # unrelated table also happens to declare `useDefault = true` (unlikely —
  # not a real gitleaks key outside [extend]), but it cannot false-NEGATIVE
  # relative to the python3 path for any config this codebase's own
  # .gitleaks.toml or docs ever describe, and erring toward "declares
  # rules" here is the direction that still leaves the positive-control
  # canary (item 2) as the actual backstop against a config that silently
  # eliminates detection despite this heuristic's blind spot.
  if grep -qE '^[[:space:]]*\[extend\][[:space:]]*(#.*)?$' "$_gcdr_file" 2>/dev/null; then
    if grep -qE '^[[:space:]]*useDefault[[:space:]]*=[[:space:]]*true[[:space:]]*(#.*)?$' "$_gcdr_file" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

# _gitleaks_positive_control [CFG_ARG] (lr-170808, scope item 2)
#
# WHY THIS EXISTS: a security scanner reporting "clean" proves nothing until
# it has been seen to fail on a known-bad input. Without this, a rules-less
# config (item 1's defect), a shimmed/broken gitleaks binary, or a future
# upstream change to --config semantics all produce the exact same "no
# leaks found" exit 0 a genuinely clean scan produces — indistinguishable
# from the outside. This runs gitleaks against a small scratch git repo
# seeded with REALISTIC, NON-EXAMPLE planted credentials and requires a
# real, countable, rule-attributed finding before the caller trusts a pass
# from the real scan.
#
# IMPLEMENTATION WARNING, learned the hard way (task description): do NOT
# build this out of a documentation example. gitleaks stopwords AWS's own
# published doc-example access key (see AWS's public documentation for the
# exact literal, deliberately NOT reproduced here — see the next paragraph
# for why even a same-file PROSE MENTION of a real stopworded/flagged
# literal is itself a mistake, confirmed the hard way during this task) in
# most contexts, so a canary built from it reports "no leaks found" against
# a FULLY FUNCTIONAL scanner. That is the identical defect this task is
# about, one level up, and harder to notice because it would live in this
# harness rather than a repo's config. Every fixture value below is a
# realistic, correctly-SHAPED, NON-EXAMPLE synthetic secret — never a
# published documentation/test-vector literal — across SEVERAL distinct
# rule families, so one upstream rule change (or one stopword) cannot
# silently disable the whole canary.
#
# NO CREDENTIAL-SHAPED LITERAL IS EVER TRACKED IN SOURCE (PEACHES, PR #188
# review, self-defeating-canary finding). The first shipped version of this
# function embedded each fixture as one complete literal string in a
# heredoc — gitleaks itself then flagged those exact lines in gates.sh's
# OWN committed history (18 findings across five distinct rule families,
# including a generic API-key shape, a GitHub personal-access-token shape,
# a Slack access-token shape, a Stripe access-token shape, and an AWS
# access-token shape), so `gates.sh secrets` blocked on branch history
# scanning this very file once shipped.
# Every fixture below is instead assembled at RUN TIME from two or more
# fragments that are individually sub-pattern (neither fragment alone
# matches any gitleaks rule's regex — verified by construction: each
# fragment is either too short, missing the required prefix token, or
# missing the required length/charset run a rule demands) and concatenated
# only in a shell variable that never itself becomes a source-file literal.
# This is NOT the .gitleaks.toml allowlist route (rejected on purpose,
# PEACHES review): allowlisting gates.sh would suppress detection in the
# very file that OWNS detection, and permanently blind it to any real
# secret introduced there later — a narrower instance of the exact
# fail-open defect this task exists to fix. Reassembly must still produce a
# genuinely detectable value; see the doctest-style verification in
# scripts/test_secrets_positive_control.py, which asserts on the SAME
# count/rule-id contract as before against the real installed gitleaks
# binary.
#
# CONTRACT: prints "<count>\t<comma-separated-rule-ids>" on stdout and
# returns 0 when gitleaks reports at least one finding AND every fixture
# category is represented (see the per-line check below) against the
# scratch repo using CFG_ARG (the SAME config argument the real scan is
# about to use — an empty CFG_ARG runs gitleaks with its full built-in
# ruleset, exactly mirroring cmd_secrets' own no-config path). Returns 1
# with nothing useful on stdout when the scanner finds nothing (or fewer
# than expected) — the caller must treat that as "the scanner cannot be
# trusted this run," not as a real clean result.
#
# Bounded (INV-1a/INV-2): reuses run_bounded with the same
# CLAGENTIC_SECRETS_TIMEOUT_SEC budget the real scan uses — a canary scan is
# no smaller a candidate for hanging than the real one.
_gitleaks_positive_control() {
  _gpc_cfg_arg="${1:-}"

  _gpc_dir=$(mktemp -d -t clagentic-secrets-canary.XXXXXX) || return 1

  # Fixture values assembled from fragments at RUN TIME — see the function
  # doc comment above for why no complete literal lives in source. Every
  # rule below keys on a MINIMUM contiguous alnum/base64-charset RUN LENGTH
  # (plus, for some rules, a fixed literal prefix) — gitleaks scans raw file
  # bytes, so what matters is not shell syntax but the longest contiguous
  # run of secret-alphabet bytes appearing on any ONE source line. The fix
  # enforced here (verified below, PEACHES PR #188 follow-up): every
  # fragment is 3 chars, one per `_gpc_join` call argument, well under
  # every relevant rule's floor (20+ for AWS, 36+ for a GitHub PAT, 24+ for
  # a generic/Stripe-shaped key, Slack's own multi-segment shape) — and the
  # only place a complete run is ever assembled is the loop body inside
  # `_gpc_join` itself, at RUN TIME, in a shell variable that is never
  # written back to any file. `_gpc_join` takes an arbitrary argument
  # count (a fixed $1..$9 form would have silently truncated a fragment
  # list longer than 9, re-introducing exactly this bug in the reverse
  # direction — too few fragments consumed, not too many characters
  # exposed).
  _gpc_join() {
    _gpcj_out=""
    for _gpcj_frag in "$@"; do
      _gpcj_out="${_gpcj_out}${_gpcj_frag}"
    done
    printf '%s' "$_gpcj_out"
  }

  # AWS access key id: literal prefix "AKIA" + 16 alnum = 20 chars.
  _gpc_aws_id=$(_gpc_join AKI A47 QMD LXN ZP2 K6R 3T)
  # AWS secret access key: a 40-char base64-alphabet run, no fixed prefix.
  _gpc_aws_secret=$(_gpc_join Qz8 mR2 vN5 jK9 wL3 xT7 yB1 cF6 hD4 sA0 pE2 gU8 iX5 m)
  # GitHub PAT: literal prefix "ghp_" + 36 alnum.
  _gpc_gh_pat=$(_gpc_join ghp _9f K3m Q7x R2v N5j L8w T4y B6c H1s D0p A3g U9i X2e Z7f)
  # Slack bot token: "xoxb-" + digit run + digit run + base64-ish tail.
  _gpc_slack=$(_gpc_join xox b-8 473 629 510 47- 829 104 657 382 1-Q z8m R2v N5j K9w L3x T7y B1c F6)
  # Generic/Stripe-shaped live key: "sk_live_" + 24+ alnum.
  _gpc_generic=$(_gpc_join sk_ liv e_9 fK3 mQ7 xR2 vN5 jL8 wT4 yB6 cH1 sD0 pA3 g)

  {
    printf 'AWS_ACCESS_KEY_ID=%s\n' "$_gpc_aws_id"
    printf 'AWS_SECRET_ACCESS_KEY=%s\n' "$_gpc_aws_secret"
    printf 'GITHUB_TOKEN=%s\n' "$_gpc_gh_pat"
    printf 'SLACK_BOT_TOKEN=%s\n' "$_gpc_slack"
    printf 'GENERIC_API_KEY=%s\n' "$_gpc_generic"
  } > "$_gpc_dir/canary.env"

  (
    cd "$_gpc_dir" || exit 1
    # lr-dfd45f: when gates.sh runs as a git hook, git exports GIT_DIR (and
    # sometimes GIT_WORK_TREE/GIT_INDEX_FILE) pointing at the CALLER's real
    # repo -- verified empirically to override an explicit `-C`/`cd` for
    # every git invocation in this subshell. Without this scrub, the
    # canary's `git init`/`add`/`commit` below silently operate on the
    # caller's real repo instead of this scratch dir, staging
    # fake-but-detectable credentials into real history and replacing the
    # caller's commit message. See ds_git_env_scrub's own doc comment
    # (scripts/platform.sh) for exactly what it clears and why. This is the
    # SCRATCH-repo scrub: it also wipes global/system git config and the
    # identity vars, which is right for a throwaway repo and wrong anywhere
    # else (the process-wide call near the top of this file deliberately
    # leaves the user's credential helpers intact). core.hooksPath is pinned
    # off per command as a second layer, so no hook of the user's can fire
    # during the canary commit even if a future config source slips past the
    # wipe.
    ds_git_scratch_env_scrub
    git init -q -b canary . 2>/dev/null || git init -q .
    git config user.email "canary@example.invalid"
    git config user.name "clagentic-secrets-canary"
    git -c core.hooksPath=/dev/null add canary.env
    git -c core.hooksPath=/dev/null commit -q -m "canary fixture" --no-verify
  ) >/dev/null 2>&1

  _gpc_timeout=$(ds_positive_int_or_warn CLAGENTIC_SECRETS_TIMEOUT_SEC "${CLAGENTIC_SECRETS_TIMEOUT_SEC:-}" 300)

  _gpc_report="$_gpc_dir/report.json"
  _gpc_status=0
  if gitleaks git --help >/dev/null 2>&1; then
    # Same inherited-GIT_DIR exposure as the canary-build subshell above:
    # `gitleaks git` is a history scanner that performs its own git repo
    # discovery, which honors an inherited GIT_DIR exactly as plain git
    # does -- without this scrub it would silently scan the CALLER's real
    # repo history instead of this scratch repo's, defeating the whole
    # positive-control (the canary would "pass" by finding real-looking
    # leaks in real history, proving nothing about the scanner -- the
    # exact fail-open this function's own doc comment above warns against).
    # shellcheck disable=SC2086
    ( cd "$_gpc_dir" && ds_git_scratch_env_scrub && run_bounded "$_gpc_timeout" -- gitleaks git --no-banner --report-format json --report-path "$_gpc_report" $_gpc_cfg_arg ) >/dev/null 2>&1 || _gpc_status=$?
  else
    # shellcheck disable=SC2086
    ( cd "$_gpc_dir" && run_bounded "$_gpc_timeout" -- gitleaks detect --no-banner --no-git --source "$_gpc_dir" --report-format json --report-path "$_gpc_report" $_gpc_cfg_arg ) >/dev/null 2>&1 || _gpc_status=$?
  fi

  _gpc_count=0
  _gpc_rule_ids=""
  if [ -f "$_gpc_report" ]; then
    if command -v jq >/dev/null 2>&1; then
      _gpc_count=$(jq 'length' "$_gpc_report" 2>/dev/null || echo 0)
      _gpc_rule_ids=$(jq -r '[.[].RuleID] | unique | join(",")' "$_gpc_report" 2>/dev/null || echo "")
    elif command -v python3 >/dev/null 2>&1; then
      _gpc_count=$(python3 -c 'import json,sys
try:
    d = json.load(open(sys.argv[1]))
    print(len(d) if isinstance(d, list) else 0)
except Exception:
    print(0)' "$_gpc_report" 2>/dev/null || echo 0)
      _gpc_rule_ids=$(python3 -c 'import json,sys
try:
    d = json.load(open(sys.argv[1]))
    ids = sorted({f.get("RuleID","") for f in d if isinstance(f, dict) and f.get("RuleID")})
    print(",".join(ids))
except Exception:
    print("")' "$_gpc_report" 2>/dev/null || echo "")
    fi
  fi
  case "$_gpc_count" in ''|*[!0-9]*) _gpc_count=0 ;; esac

  rm -rf "$_gpc_dir"

  # ASSERT ON COUNT AND RULE IDS, NOT MERE EXIT STATUS (task requirement):
  # gitleaks exits non-zero on any finding, so _gpc_status alone already
  # signals "found something" — but a fixture regression that drops to
  # zero real findings while some unrelated tool hiccup still trips a
  # non-zero exit (or vice versa) must not be masked by trusting the exit
  # code alone. Require the report to have parsed to a real positive count.
  if [ "$_gpc_count" -lt 1 ]; then
    printf '0\t\n'
    return 1
  fi
  printf '%s\t%s\n' "$_gpc_count" "$_gpc_rule_ids"
  return 0
}

cmd_secrets() {
  _gate_check_args secrets "--full-scan" "" "$@" || return 2
  # FULL-SCAN OPT-IN (lr-51112e): --full-scan or CLAGENTIC_SECRETS_FULL_SCAN=1
  # forces the branch-history path (below) to walk the entire history
  # reachable from HEAD, the pre-lr-51112e default. Neither `gates ship` nor
  # `gates pre-push` sets either by default — see cmd_ship's own call site.
  #
  # TRIGGER SOURCE (PEACHES PR #217 review, comment 5820512826): the flag and
  # the env var are tracked in SEPARATE booleans, not collapsed into one —
  # _SECRETS_FULL_SCAN alone cannot tell the audit trail (cmd_log_run
  # detail, AGENTS.md rule 7 audit-first) which one actually fired, and a
  # collapsed boolean previously reported every env-only trigger as
  # "(--full-scan)", falsely claiming a CLI flag was supplied. Both can be
  # true at once (redundant, not a conflict); when they are, the reason
  # string names both rather than picking one arbitrarily.
  _SECRETS_FULL_SCAN_FLAG=0
  for _secrets_arg in "$@"; do
    case "$_secrets_arg" in
      --full-scan) _SECRETS_FULL_SCAN_FLAG=1 ;;
    esac
  done
  _SECRETS_FULL_SCAN_ENV=0
  [ "${CLAGENTIC_SECRETS_FULL_SCAN:-0}" = "1" ] && _SECRETS_FULL_SCAN_ENV=1
  _SECRETS_FULL_SCAN=0
  if [ "$_SECRETS_FULL_SCAN_FLAG" = "1" ] || [ "$_SECRETS_FULL_SCAN_ENV" = "1" ]; then
    _SECRETS_FULL_SCAN=1
  fi

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
  # Build the invocation: gitleaks 8.19+ uses `gitleaks git --pre-commit --staged`;
  # older versions use `gitleaks protect --staged`. Both honor --config.
  CFG_ARG=""
  [ -f "$REPO_ROOT/.gitleaks.toml" ] && CFG_ARG="--config=$REPO_ROOT/.gitleaks.toml"

  # PREFLIGHT THE CONFIG, FAIL CLOSED (lr-170808 scope item 1). A
  # repo-supplied .gitleaks.toml that declares neither [[rules]] nor
  # [extend] useDefault = true REPLACES the built-in ruleset with nothing —
  # gitleaks then finds nothing, ever, regardless of what is committed. Catch
  # this before it is ever handed to gitleaks, with a message naming the
  # exact cause and the exact fix, rather than letting the gate report a
  # convincing, permanent, silent pass.
  if [ -n "$CFG_ARG" ] && ! _gitleaks_config_declares_rules "$REPO_ROOT/.gitleaks.toml"; then
    printf '[gates/secrets] BLOCKED: .gitleaks.toml defines no rules and does not set [extend] useDefault = true. gitleaks --config replaces the built-in ruleset, so this configuration detects nothing. Add [extend] useDefault = true or declare rules.\n' 1>&2
    cmd_log_run secrets block ".gitleaks.toml defines no rules and does not set [extend] useDefault = true. gitleaks --config replaces the built-in ruleset, so this configuration detects nothing. Add [extend] useDefault = true or declare rules."
    return 1
  fi

  # POSITIVE CONTROL BEFORE TRUSTING A PASS (lr-170808 scope item 2). Prove
  # the scanner (this binary, this config) actually detects a planted,
  # realistic, non-example credential before the real scan's own "no leaks
  # found" is trusted as a genuine clean result. Catches the whole class —
  # rules-less config, a shimmed/broken gitleaks, an allowlist that
  # accidentally matches everything, a future upstream --config semantics
  # change — not just the one instance item 1 fixes directly. Opt-out via
  # CLAGENTIC_SKIP_SECRETS_CANARY=1 for an air-gapped/offline environment
  # where spinning up a throwaway git repo is undesirable; off by default
  # because the canary is cheap (one small local repo, one bounded scan).
  if [ "${CLAGENTIC_SKIP_SECRETS_CANARY:-0}" != "1" ]; then
    _SECRETS_CANARY_RESULT=$(_gitleaks_positive_control "$CFG_ARG") || _SECRETS_CANARY_STATUS=$?
    _SECRETS_CANARY_STATUS="${_SECRETS_CANARY_STATUS:-0}"
    if [ "$_SECRETS_CANARY_STATUS" != "0" ]; then
      printf '[gates/secrets] BLOCKED: positive-control canary failed — gitleaks (this binary, this config) did not detect a planted, realistic credential in a scratch repo. The real scan'"'"'s "no leaks found" cannot be trusted this run. Check the gitleaks binary and .gitleaks.toml (a rules-less config, a broken install, or an over-broad allowlist all produce this).\n' 1>&2
      cmd_log_run secrets block "positive-control canary failed: gitleaks did not detect a planted credential — scan result cannot be trusted (no coverage)"
      return 1
    fi
    _SECRETS_CANARY_COUNT="${_SECRETS_CANARY_RESULT%%	*}"
    _SECRETS_CANARY_RULES="${_SECRETS_CANARY_RESULT#*	}"
    printf '[gates/secrets] positive-control canary OK: %s finding(s), rule(s): %s\n' "$_SECRETS_CANARY_COUNT" "$_SECRETS_CANARY_RULES" 1>&2
  fi

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
  # subcommand was added in 8.19 (corrected from an earlier "8.18" claim,
  # PEACHES PR #218 review, comment 5833150249); if `gitleaks git --help`
  # exits 0 we use it, otherwise we fall back to `gitleaks protect`.
  # Bound every gitleaks invocation (INV-1a/INV-2, class-4 foundry fix): a
  # full branch-history scan in particular can legitimately take longer than
  # the generic run_bounded default, so gitleaks gets its own configurable
  # timeout rather than sharing CLAGENTIC_EXTERNAL_TIMEOUT_SEC's 120s.
  _SECRETS_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_SECRETS_TIMEOUT_SEC "${CLAGENTIC_SECRETS_TIMEOUT_SEC:-}" 300)

  if gitleaks git --help >/dev/null 2>&1; then
    if [ "$_SECRETS_ON_FEATURE" = "1" ]; then
      # No staged changes on a feature branch — scan the branch's committed
      # history rather than the (empty) index. This catches secrets in
      # already-committed hunks that would otherwise be invisible to --staged.
      #
      # SCOPE (lr-51112e): this used to run `gitleaks git` with no
      # --log-opts at all, which walks EVERY commit reachable from HEAD —
      # including commits that predate the feature branch entirely. Any
      # finding already present on the default branch then blocked EVERY
      # branch, and the "scanning branch history" log line misattributed
      # the finding to the branch under review. Default scope is now
      # merge-base(<provably-current default-branch ref>, HEAD)..HEAD via
      # --log-opts, the same PROVABLY-CURRENT freshness precondition
      # cmd_sast's --baseline-commit and cmd_bleed's branch-diff scoping
      # both already use (_gate_resolve_fresh_default_branch_ref) — reuse,
      # not a third freshness mechanism. In-branch history still counts: a
      # secret introduced then removed earlier on THIS branch is still
      # inside merge-base..HEAD and still blocks (`gitleaks git` scans full
      # blob history within the given log range, not just the tip tree).
      #
      # NEVER SILENTLY NARROW (task requirement 3 — same doctrine cmd_bleed
      # and cmd_sast already apply to their own freshness resolution): a
      # baseline that cannot be POSITIVELY VERIFIED current — fetch
      # failure/timeout, no remote, shallow clone with no common ancestor,
      # REPO_ROOT not provably the repo being consulted — widens to full
      # history instead, with an explicit reason on stderr and in the audit
      # details. Only a verified-fresh baseline narrows; every other case
      # (including --full-scan / CLAGENTIC_SECRETS_FULL_SCAN=1) preserves
      # fail-closed by scanning MORE, never less.
      _SECRETS_LOG_OPTS=""
      _SECRETS_SCOPE_REASON=""
      if [ "$_SECRETS_FULL_SCAN" = "1" ]; then
        # Preserve WHICH trigger actually fired (PEACHES PR #217 review,
        # comment 5820512826) rather than always crediting the CLI flag —
        # an env-only trigger claiming "(--full-scan)" in the audit trail
        # would misattribute the cause to a flag nobody passed. Both can be
        # set at once; name both rather than picking one arbitrarily.
        if [ "$_SECRETS_FULL_SCAN_FLAG" = "1" ] && [ "$_SECRETS_FULL_SCAN_ENV" = "1" ]; then
          _SECRETS_SCOPE_REASON="full history (--full-scan, CLAGENTIC_SECRETS_FULL_SCAN=1)"
        elif [ "$_SECRETS_FULL_SCAN_FLAG" = "1" ]; then
          _SECRETS_SCOPE_REASON="full history (--full-scan)"
        else
          _SECRETS_SCOPE_REASON="full history (CLAGENTIC_SECRETS_FULL_SCAN=1)"
        fi
      elif ! _git_repo_root_is_scoped; then
        _SECRETS_SCOPE_REASON="full history (baseline unavailable: REPO_ROOT is not a git repo)"
      else
        _SECRETS_FETCH_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_SECRETS_FETCH_TIMEOUT_SEC "${CLAGENTIC_SECRETS_FETCH_TIMEOUT_SEC:-}" 30)

        _SECRETS_FRESH_ERR_TMP=$(mktemp -t clagentic-secrets-fresh-err.XXXXXX)
        _SECRETS_FRESH_TIP=$(_gate_resolve_fresh_default_branch_ref "$_SECRETS_DEFAULT_BRANCH" "$_SECRETS_FETCH_TIMEOUT" 2>"$_SECRETS_FRESH_ERR_TMP") || true
        _SECRETS_FRESH_ERR=$(cat "$_SECRETS_FRESH_ERR_TMP" 2>/dev/null || echo "")
        rm -f "$_SECRETS_FRESH_ERR_TMP"

        if [ -z "$_SECRETS_FRESH_TIP" ]; then
          _SECRETS_SCOPE_REASON="full history (baseline unavailable: $_SECRETS_FRESH_ERR)"
        else
          # Merge-base off the verified-fresh SHA itself (matches cmd_sast's
          # and cmd_bleed's own use of their verified tip) — re-resolving
          # "origin/${_SECRETS_DEFAULT_BRANCH}" by name here would discard
          # that proof and reopen the TOCTOU gap
          # _gate_resolve_fresh_default_branch_ref exists to close.
          _SECRETS_MERGE_BASE=$(_git merge-base "$_SECRETS_FRESH_TIP" HEAD 2>/dev/null || echo "")
          if [ -z "$_SECRETS_MERGE_BASE" ]; then
            _SECRETS_SCOPE_REASON="full history (baseline unavailable: merge-base resolution failed — shallow clone with base not fetched, or unrelated histories)"
          else
            _SECRETS_MB_SHORT=$(printf '%.7s' "$_SECRETS_MERGE_BASE")
            _SECRETS_HEAD_SHORT=$(_git rev-parse --short=7 HEAD 2>/dev/null || echo "HEAD")
            _SECRETS_RANGE_COUNT=$(_git rev-list --count "${_SECRETS_MERGE_BASE}..HEAD" 2>/dev/null || echo "?")
            _SECRETS_LOG_OPTS="--log-opts=${_SECRETS_MERGE_BASE}..HEAD"
            _SECRETS_SCOPE_REASON="branch diff ${_SECRETS_MB_SHORT}..${_SECRETS_HEAD_SHORT} (${_SECRETS_RANGE_COUNT} commits)"
          fi
        fi
      fi

      printf '[gates/secrets] no staged changes — scanning %s with gitleaks git\n' "$_SECRETS_SCOPE_REASON" 1>&2
      # REPO_ROOT PINNED EXPLICITLY (PEACHES PR #217 review, comment
      # 5821185384): `gitleaks git` performs its OWN git repo discovery from
      # the process's CWD, exactly the class of defect INV-6's `_git`
      # wrapper (:85-89 above) exists to close for plain `git` -- with no
      # explicit target, a caller whose CWD differs from REPO_ROOT (a
      # wrapper/`.clagentic-project` layout, or a hook invoked from a
      # subdirectory) has gitleaks silently scan the WRONG repo (or the
      # wrapper's own non-repo CWD) while this gate reports whatever that
      # unrelated scan found -- a false pass on the real target, not an
      # error.
      #
      # CORRECTED (PEACHES PR #218 review, comment 5833150249): the previous
      # fix here pinned via a `--source`/`-s` flag on `gitleaks git` itself.
      # That flag never reliably existed on `git`: per gitleaks' own cobra
      # command definitions (cmd/git.go, verified against the v8.19.0
      # introduction of the `git` subcommand through the current v8.30.1),
      # `git`'s `Use` string has always been `"git [flags] [repo]"` with
      # `Args: cobra.MaximumNArgs(1)` -- the repo is a POSITIONAL argument,
      # never a `git`-local flag. `--source` briefly worked on `git` only
      # because root.go's global `--source`/`-s` persistent flag was still
      # inherited in the v8.19.0-v8.19.3 window; v8.20.0 removed that global
      # flag entirely (the same release that made `detect`/`protect` hidden
      # and deprecated in favor of `git`), so `gitleaks git --source=...`
      # fails with an unknown-flag error on every gitleaks from 8.20.0
      # onward -- every secrets gate blocked, even on a clean repo, on any
      # modern gitleaks install. `detect`/`protect` are a genuinely separate
      # code path that registers its OWN local `-s`/`--source` flag
      # (confirmed unchanged through 8.30.1) -- that fallback below is
      # correct as-is and untouched by this fix.
      #
      # The positional `[repo]` argument is the ONLY invocation shape that
      # has worked across the entire `git`-subcommand era (8.19.0-8.30.1
      # confirmed directly against upstream source), so it replaces
      # `--source` here rather than adding a second version-gated branch --
      # gitleaks 8.18 predates the `git` subcommand's existence altogether,
      # so the `gitleaks git --help` capability probe above already excludes
      # every version this positional form would not work on. This makes the
      # scanned repo explicit and CWD-independent, the same property `_git
      # -C "$REPO_ROOT"` already guarantees for every plain git call in this
      # file.
      # shellcheck disable=SC2086
      if run_bounded "$_SECRETS_TIMEOUT" -- gitleaks git --redact --no-banner $CFG_ARG $_SECRETS_LOG_OPTS -- "$REPO_ROOT"; then
        # Runtime-assembled details string (lr-2e8444): route through the
        # checked helper, same as cmd_bleed's own $_BLEED_SCOPE_REASON pass
        # sites, so a scope-reason string that happens to contain a failure
        # word (e.g. "baseline unavailable") never logs as a silent "pass".
        _cmd_log_run_checked_pass secrets "$_SECRETS_SCOPE_REASON (no staged changes)"
      else
        cmd_log_run secrets block "gitleaks reported findings or timed out after ${_SECRETS_TIMEOUT}s ($_SECRETS_SCOPE_REASON)"
        return 1
      fi
    else
      # REPO_ROOT PINNED EXPLICITLY: same CWD-independence fix as above, and
      # the same positional-argument correction (PEACHES PR #218 review,
      # comment 5833150249) -- `gitleaks git` has never accepted `--source`
      # as its own flag; see the comment above the branch-history call site
      # for the full version history.
      # shellcheck disable=SC2086
      if run_bounded "$_SECRETS_TIMEOUT" -- gitleaks git --staged --pre-commit --redact --no-banner $CFG_ARG -- "$REPO_ROOT"; then
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
      # REPO_ROOT PINNED EXPLICITLY: gitleaks' older `protect` subcommand has
      # the same repo-discovery-from-CWD default as `git` above ("path to
      # source (default: $PWD)", per `gitleaks protect --help`), but unlike
      # `git` it has NO positional [DIRECTORY] argument at all -- confirmed
      # against the real installed binary (`gitleaks protect --help`
      # advertises zero positional args; a trailing bare token is silently
      # ignored, not an error, which is exactly the false-pass shape this
      # fix exists to close). The correct pin for `protect` is its own
      # `--source`/`-s` flag.
      # shellcheck disable=SC2086
      if run_bounded "$_SECRETS_TIMEOUT" -- gitleaks protect --staged --redact --no-banner $CFG_ARG --source "$REPO_ROOT"; then
        cmd_log_run secrets pass ""
      else
        cmd_log_run secrets block "gitleaks reported findings or timed out after ${_SECRETS_TIMEOUT}s"
        return 1
      fi
    fi
  fi
}

# _gate_migrate_brand_root_file OLD NEW LABEL
#
# lr-8ee2df: migrate a global ignore-list file from the shared brand root
# ($HOME/.config/clagentic/<name>) to this product's own namespace
# ($HOME/.config/clagentic/lite/<name>), mirroring the brand/product split
# lr-7939f8 shipped for the global config (bin/clagentic-lite,
# _migrate_global_config_brand_path) and the rule AGENTS.md item 12 states.
#
# NOT the credentials case. osv-ignore/semgrep-exclude hold CVE IDs and
# semgrep rule ids -- suppression policy, not secrets. This deliberately
# does NOT reuse bin/clagentic-lite's _secret_tmp_create (umask-077
# atomic-create, chmod 600 before/during/after, never-print-a-value): there
# is no confidentiality window to protect and no value that would be
# sensitive to log. A plain `mktemp` in the target directory plus `cat` +
# `mv` is sufficient here -- the atomicity/idempotency/back-compat-read
# properties below all still apply (a stale ignore entry silently going
# unread is a real regression, wrong-direction: a suppressed finding starts
# firing again on a BLOCKING security gate), but the chmod-600 and
# never-leak-a-value apparatus that safety bar exists for a live
# CLAGENTIC_ROUTER_TOKEN would be ceremony here.
#
# Args: OLD (brand-root path) NEW (product-namespace path) LABEL (used only
# in messages, e.g. "osv-ignore" / "semgrep-exclude").
#
# Same contract as _migrate_global_config_brand_path minus the credential
# apparatus:
#   - Never overwrites an existing NEW from OLD. If both exist with
#     different content, says so (byte-diff via cmp, not content) and
#     leaves both untouched -- operator reconciles by hand. If both exist
#     with IDENTICAL content, finishes a prior kill-window's cleanup by
#     removing the now-redundant OLD copy (same idempotent-cleanup shape).
#   - OLD absent: no-op, returns 0 (nothing to migrate).
#   - OLD is a symlink: content is read through it (cat follows
#     transparently) into NEW; only the symlink itself is removed after.
#   - OLD is read-only: still migrates -- only ever READS old, then
#     unlinks it (needs write on the parent dir, not the file).
#   - NEW's parent directory created with plain `mkdir -p` (no chmod --
#     these are not secrets, and no other non-secret state directory in
#     gates.sh chmods its own parent either).
#   - Atomic install: content lands in a temp file in NEW's directory
#     first, then a single same-filesystem `mv` installs it at NEW; OLD is
#     removed only AFTER that mv succeeds. A kill before the mv leaves OLD
#     fully intact and NEW absent (temp file orphaned, harmless, cleaned up
#     or overwritten by a re-run). A kill after the mv but before the OLD
#     removal leaves the content fully intact at BOTH paths (NEW is
#     authoritative; a re-run finishes the cleanup). No step holds content
#     ONLY in a temp file with neither real path populated.
#   - Idempotent: a second call with NEW already present (identical or
#     divergent content) or OLD already gone is either a no-op or finishes
#     cleanup, never double-migrates or corrupts.
_gate_migrate_brand_root_file() {
  _gmbrf_old="$1"
  _gmbrf_new="$2"
  _gmbrf_label="$3"

  [ -f "$_gmbrf_old" ] || return 0

  if [ -f "$_gmbrf_new" ]; then
    # `-f` FOLLOWS SYMLINKS -- if NEW is a symlink (e.g. pointing at OLD, a
    # plausible operator setup to keep one list readable from both
    # locations during a transition), `cmp -s OLD NEW` compares OLD against
    # itself through the symlink and always reports identical, and the old
    # code below would then `rm -f OLD` -- deleting the symlink's TARGET
    # and leaving NEW a dangling symlink with the ignore list gone
    # entirely (HOLDEN/PEACHES/Codex finding, PR #203 review). `-L` tests
    # the path itself, not what it resolves to, so this is safe against
    # any symlink chain without needing to reason about what NEW points
    # at. Falls through to the DIFFERENT-content warn-and-leave-both-alone
    # branch, which never deletes anything -- the conservative outcome.
    if [ -L "$_gmbrf_new" ]; then
      echo "[gates] WARN $_gmbrf_new is a symlink -- not migrating $_gmbrf_label (refusing to risk deleting whatever it points at, including possibly $_gmbrf_old itself)." 1>&2
      echo "[gates]      Replace the symlink with a real file, or remove $_gmbrf_old by hand once you've confirmed its content is preserved." 1>&2
      return 0
    fi
    if cmp -s "$_gmbrf_old" "$_gmbrf_new" 2>/dev/null; then
      rm -f "$_gmbrf_old"
      echo "[gates] removed redundant legacy $_gmbrf_label at $_gmbrf_old (already migrated to $_gmbrf_new)" 1>&2
    else
      echo "[gates] WARN both $_gmbrf_old and $_gmbrf_new exist with DIFFERENT content for $_gmbrf_label -- not migrating." 1>&2
      echo "[gates]      $_gmbrf_new is authoritative (read by every gate, never the old path, once it exists)." 1>&2
      echo "[gates]      Review $_gmbrf_old by hand and merge or remove it; this step will not touch either file until you do." 1>&2
    fi
    return 0
  fi

  _gmbrf_new_dir=$(dirname "$_gmbrf_new")
  if [ ! -d "$_gmbrf_new_dir" ]; then
    mkdir -p "$_gmbrf_new_dir" \
      || { echo "[gates] WARN could not create $_gmbrf_new_dir -- skipping $_gmbrf_label migration (old path still honored)" 1>&2; return 1; }
  fi

  _gmbrf_tmp="$_gmbrf_new.migrate.$$"
  if ! cat "$_gmbrf_old" > "$_gmbrf_tmp" 2>/dev/null; then
    echo "[gates] WARN could not read $_gmbrf_old -- skipping $_gmbrf_label migration" 1>&2
    rm -f "$_gmbrf_tmp"
    return 1
  fi

  mv "$_gmbrf_tmp" "$_gmbrf_new" \
    || { echo "[gates] WARN could not install migrated $_gmbrf_label at $_gmbrf_new -- skipping (old path still honored)" 1>&2; rm -f "$_gmbrf_tmp"; return 1; }

  rm -f "$_gmbrf_old"
  echo "[gates] migrated $_gmbrf_label: $_gmbrf_old -> $_gmbrf_new (brand/product namespace split)" 1>&2
}

# _gate_resolve_global_ignore_path NEW OLD LABEL
#
# Read-side resolution for a global ignore-list file, mirroring
# ds_load_global_env's (scripts/platform.sh) new-path-wins-with-fallback
# precedence: NEW wins unconditionally when it exists (regardless of
# whether OLD is also still present -- never merges the two). When NEW is
# absent and OLD exists, falls back to OLD with a one-time-per-process
# warning, so an un-migrated install (or one where migration failed, e.g. a
# read-only $HOME/.config/clagentic/) does not silently lose its ignore
# list and start re-flagging suppressed findings on a blocking security
# gate. Prints the resolved path (possibly empty, meaning neither exists)
# on stdout.
#
# The fallback warning below deliberately names no specific gate command.
# It was originally written when cmd_deps/cmd_sast were the only two
# callers and said "run `gates deps`/`sast`" -- accurate at the time, but
# cmd_bleed becoming a third caller (lr-73fa40) made it prescribe two
# unrelated gates to a bleed user. Same shape as the stale docs/GATES.md
# waiver lr-92d931 found: a caller-specific message silently going stale
# as the caller set grows. Generalized instead of re-specialized so a
# fourth caller does not reopen the same defect.
_gate_resolve_global_ignore_path() {
  _grgi_new="$1"
  _grgi_old="$2"
  _grgi_label="$3"
  if [ -f "$_grgi_new" ]; then
    printf '%s' "$_grgi_new"
    return 0
  fi
  if [ -f "$_grgi_old" ]; then
    echo "[gates] reading global $_grgi_label from deprecated path $_grgi_old -- move it to $_grgi_new (brand/product namespace split), or let migration retry on a writable \$HOME/.config/clagentic/lite/" 1>&2
    printf '%s' "$_grgi_old"
    return 0
  fi
  printf '%s' "$_grgi_new"
}

cmd_deps() {
  _gate_check_args deps "" "" "$@" || return 2
  # DOMAIN-BASED SKIP (lr-1ad8da). Only consulted when CLAGENTIC_GATE_REFS_FILE
  # is set -- cmd_pre_push (below) is the sole setter, pointing at a
  # one-time snapshot of git's pre-push stdin protocol. A direct/manual
  # `gates.sh deps` invocation never sets this var, so it runs exactly as
  # before -- this mechanism only ever narrows the pre-push hook path, never
  # changes what a manually-invoked gate does. See _gate_skip_or_run_domain's
  # own doc comment for the full fail-closed contract.
  if [ -n "${CLAGENTIC_GATE_REFS_FILE:-}" ]; then
    _DEPS_DOMAIN_RESULT=""
    _DEPS_DOMAIN_RC=0
    _DEPS_DOMAIN_RESULT=$(_gate_skip_or_run_domain deps _gate_deps_domain_globs "$CLAGENTIC_DEPS_DOMAIN_VERSION" "$CLAGENTIC_GATE_REFS_FILE") || _DEPS_DOMAIN_RC=$?
    if [ "$_DEPS_DOMAIN_RC" = "2" ]; then
      echo "[gates/deps] out of domain — no manifest/lockfile/config in this push's changed-path set — not_applicable" 1>&2
      cmd_log_run deps not_applicable "$_DEPS_DOMAIN_RESULT"
      return 0
    fi
  fi

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
  OLD_GLOBAL_IGNORE="$HOME/.config/clagentic/osv-ignore"
  NEW_GLOBAL_IGNORE="$HOME/.config/clagentic/lite/osv-ignore"
  # `|| true`: a migration failure (unwritable target dir, unreadable old
  # file, ...) must never abort this whole gate under `set -e` -- the
  # resolve step right after falls back to reading the old path directly,
  # same as any other un-migrated install during the deprecation window.
  _gate_migrate_brand_root_file "$OLD_GLOBAL_IGNORE" "$NEW_GLOBAL_IGNORE" "osv-ignore" || true
  GLOBAL_IGNORE=$(_gate_resolve_global_ignore_path "$NEW_GLOBAL_IGNORE" "$OLD_GLOBAL_IGNORE" "osv-ignore")
  REPO_IGNORE="$REPO_ROOT/.clagentic/osv-ignore"

  # Bound every osv-scanner invocation (INV-1a/INV-2, class-4 foundry fix):
  # one path does a network vulnerability-DB lookup, so this defaults higher
  # than the generic run_bounded default.
  _OSV_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_OSV_TIMEOUT_SEC "${CLAGENTIC_OSV_TIMEOUT_SEC:-}" 300)

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

    # CWD PINNED TO REPO_ROOT: the "." target and any CLAGENTIC_OSV_EXCLUDE
    # path resolve against the process CWD, which differs from REPO_ROOT in a
    # wrapper/.clagentic-project layout or when a hook runs from a
    # subdirectory -- the scan would then cover the wrong tree and report a
    # clean pass. Each invocation runs in a POSIX subshell that cds first,
    # leaving argv unchanged. A failed cd exits the subshell nonzero, which
    # the status handling below treats as a failed scan (fail closed).
    # $_OSV_JSON and $_OSV_TMP are absolute mktemp paths, so the redirect and
    # --config are unaffected by the cd.
    _OSV_STATUS=0
    if [ "$_OSV_SUBCMD" = "source" ]; then
      # shellcheck disable=SC2086
      ( cd "$REPO_ROOT" || exit 1; run_bounded "$_OSV_TIMEOUT" -- osv-scanner scan source -r --format=json "--config=$_OSV_TMP" $_OSV_EXCL_FLAGS . ) > "$_OSV_JSON" || _OSV_STATUS=$?
    else
      ( cd "$REPO_ROOT" || exit 1; run_bounded "$_OSV_TIMEOUT" -- osv-scanner scan --recursive --format=json "--config=$_OSV_TMP" . ) > "$_OSV_JSON" || _OSV_STATUS=$?
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

    # Same CWD pin as the scan-subcommand branches above.
    if ( cd "$REPO_ROOT" || exit 1; run_bounded "$_OSV_TIMEOUT" -- osv-scanner "$@" ); then
      cmd_log_run deps pass ""
    else
      cmd_log_run deps block "osv-scanner reported vulnerabilities, timed out after ${_OSV_TIMEOUT}s, or REPO_ROOT could not be entered"
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
  _gate_check_args bleed "--full-scan" "" "$@" || return 2
  # Internal-bleed scan: grep the changed-file set for patterns loaded from a
  # user-supplied pattern file. Patterns are BRE (grep -f), one per line;
  # lines starting with # and blank lines are ignored.
  #
  # Pattern file resolution (first found wins):
  #   1. ${CLAGENTIC_PROJECT_ROOT:-$PWD}/.clagentic/bleed-patterns        (repo-level)
  #   2. $HOME/.config/clagentic/lite/bleed-patterns                     (global user config)
  #
  # Global half moved off the shared brand root ($HOME/.config/clagentic/
  # bleed-patterns) to this product's own namespace (lr-73fa40), same
  # migrate-and-warn mechanism cmd_deps' GLOBAL_IGNORE and cmd_sast's
  # semgrep-exclude use (_gate_migrate_brand_root_file /
  # _gate_resolve_global_ignore_path, defined above cmd_deps) -- third and
  # final known instance of the brand/product split (lr-7939f8,
  # lr-8ee2df). bleed-patterns is a single pattern file, not credentials,
  # same non-credential posture as the ignore lists -- see
  # _gate_migrate_brand_root_file's own doc comment for why it deliberately
  # skips the chmod-600/never-leak apparatus.
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
  # HISTORY within a merge-base..HEAD commit RANGE, not a diffed file set.
  # UPDATED (lr-51112e, PEACHES PR #217 review): cmd_secrets now DOES
  # resolve and diff against a remote ref -- it calls the same
  # _gate_resolve_fresh_default_branch_ref helper this function uses, then
  # takes git merge-base against the verified-fresh tip to scope its
  # --log-opts range. The distinction from this function's own branch-diff
  # step is the CONSUMER, not remote-ref usage: this function resolves
  # origin/<default-branch> and diffs a FILE SET against it -- the same
  # shape as cmd_sast's --baseline-commit mechanism (:588), including its
  # freshness precondition (_gate_resolve_fresh_default_branch_ref, :88).
  # cmd_secrets resolves the identical fresh ref but scopes a commit-range
  # HISTORY scan, not a file diff. See docs/GATES.md Gate 4d for the full
  # writeup.
  _BLEED_FULL_SCAN=0
  for _bleed_arg in "$@"; do
    case "$_bleed_arg" in
      --full-scan) _BLEED_FULL_SCAN=1 ;;
    esac
  done

  _BLEED_OLD_GLOBAL_PAT_FILE="$HOME/.config/clagentic/bleed-patterns"
  _BLEED_NEW_GLOBAL_PAT_FILE="$HOME/.config/clagentic/lite/bleed-patterns"
  # `|| true`: see the matching comment in cmd_deps -- a migration failure
  # must never abort this gate under `set -e`; the resolve step right after
  # falls back to reading the old path directly, same as any other
  # un-migrated install during the deprecation window.
  _gate_migrate_brand_root_file "$_BLEED_OLD_GLOBAL_PAT_FILE" "$_BLEED_NEW_GLOBAL_PAT_FILE" "bleed-patterns" || true
  _BLEED_GLOBAL_PAT_FILE=$(_gate_resolve_global_ignore_path "$_BLEED_NEW_GLOBAL_PAT_FILE" "$_BLEED_OLD_GLOBAL_PAT_FILE" "bleed-patterns")

  _BLEED_PAT_FILE=""
  if [ -f "${CLAGENTIC_PROJECT_ROOT:-$PWD}/.clagentic/bleed-patterns" ]; then
    _BLEED_PAT_FILE="${CLAGENTIC_PROJECT_ROOT:-$PWD}/.clagentic/bleed-patterns"
  elif [ -n "$_BLEED_GLOBAL_PAT_FILE" ] && [ -f "$_BLEED_GLOBAL_PAT_FILE" ]; then
    _BLEED_PAT_FILE="$_BLEED_GLOBAL_PAT_FILE"
  fi

  if [ -z "$_BLEED_PAT_FILE" ]; then
    echo "[gates/bleed] no pattern file found — skipping (configure ${_BLEED_NEW_GLOBAL_PAT_FILE} to enable)"
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
        # branch HISTORY within a commit RANGE, not a diffed file set). As
        # of lr-51112e cmd_secrets DOES resolve a remote ref via the same
        # _gate_resolve_fresh_default_branch_ref helper -- the distinction
        # is the consumer (a --log-opts commit range vs. this function's
        # diffed file set), not remote-ref usage. The actual precedent for
        # a remote-ref-diffed FILE SET scope is cmd_sast's baseline-commit
        # mechanism (:588-663) — see docs/GATES.md.
        _BLEED_FETCH_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_BLEED_FETCH_TIMEOUT_SEC "${CLAGENTIC_BLEED_FETCH_TIMEOUT_SEC:-}" 30)

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
  _gate_check_args sast "" "" "$@" || return 2
  # DOMAIN-BASED SKIP (lr-1ad8da). See cmd_deps' identical block above for
  # the full rationale -- same env-var gate, same fail-closed contract, only
  # the domain glob function and version constant differ.
  if [ -n "${CLAGENTIC_GATE_REFS_FILE:-}" ]; then
    _SAST_DOMAIN_RESULT=""
    _SAST_DOMAIN_RC=0
    _SAST_DOMAIN_RESULT=$(_gate_skip_or_run_domain sast _gate_sast_domain_globs "$CLAGENTIC_SAST_DOMAIN_VERSION" "$CLAGENTIC_GATE_REFS_FILE") || _SAST_DOMAIN_RC=$?
    if [ "$_SAST_DOMAIN_RC" = "2" ]; then
      echo "[gates/sast] out of domain — no source/build/config file in this push's changed-path set — not_applicable" 1>&2
      cmd_log_run sast not_applicable "$_SAST_DOMAIN_RESULT"
      return 0
    fi
  fi

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
      _SAST_FETCH_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_SAST_FETCH_TIMEOUT_SEC "${CLAGENTIC_SAST_FETCH_TIMEOUT_SEC:-}" 30)

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
  _SAST_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_SAST_TIMEOUT_SEC "${CLAGENTIC_SAST_TIMEOUT_SEC:-}" 300)

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

  # Exclude ladder (lr-321e18): $HOME/.config/clagentic/lite/semgrep-exclude
  # (global) union $REPO_ROOT/.clagentic/semgrep-exclude (repo) — mirrors
  # cmd_deps' osv-ignore mechanism exactly (reuse-first). Each rule id
  # becomes an --exclude-rule flag on BOTH the baseline and full-tree
  # invocations below. Global half moved off the shared brand root to this
  # product's own namespace (lr-8ee2df), same migrate-and-warn mechanism
  # cmd_deps' GLOBAL_IGNORE uses (_gate_migrate_brand_root_file /
  # _gate_resolve_global_ignore_path, defined above cmd_deps).
  _OLD_GLOBAL_SEMGREP_EXCLUDE="$HOME/.config/clagentic/semgrep-exclude"
  _NEW_GLOBAL_SEMGREP_EXCLUDE="$HOME/.config/clagentic/lite/semgrep-exclude"
  # `|| true`: see the matching comment in cmd_deps above -- a migration
  # failure must never abort this blocking gate under `set -e`.
  _gate_migrate_brand_root_file "$_OLD_GLOBAL_SEMGREP_EXCLUDE" "$_NEW_GLOBAL_SEMGREP_EXCLUDE" "semgrep-exclude" || true
  _GLOBAL_SEMGREP_EXCLUDE=$(_gate_resolve_global_ignore_path "$_NEW_GLOBAL_SEMGREP_EXCLUDE" "$_OLD_GLOBAL_SEMGREP_EXCLUDE" "semgrep-exclude")
  while IFS= read -r _SAST_EXCL_TOK; do
    [ -n "$_SAST_EXCL_TOK" ] || continue
    set -- "$@" "$_SAST_EXCL_TOK"
  done <<EOF_EXCL
$(_sast_exclude_rule_flags "$_GLOBAL_SEMGREP_EXCLUDE" "$REPO_ROOT/.clagentic/semgrep-exclude")
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
  #
  # CWD PINNED TO REPO_ROOT VIA SUBSHELL, NOT A TARGET ARGUMENT: semgrep's
  # --baseline-commit runs `git cat-file` against the process CWD with no
  # override flag, and a positional target exits 2 whenever CWD != REPO_ROOT,
  # so the positional-path pin available for other scanners does not work
  # here. Each invocation runs in a POSIX subshell that cds first, leaving
  # argv byte-identical. A failed cd exits the subshell nonzero, so an
  # unenterable REPO_ROOT is a gate BLOCK, never a pass. Everything the
  # caller reads afterwards is assigned outside the subshell.
  if [ -n "$_SAST_BASELINE" ]; then
    echo "[gates/sast] scoping to diff-introduced findings (baseline-commit=$_SAST_BASELINE, cwd=$REPO_ROOT)" 1>&2
    if ( cd "$REPO_ROOT" || exit 1; run_bounded "$_SAST_TIMEOUT" -- semgrep "$@" --error --severity=ERROR "--baseline-commit=$_SAST_BASELINE" ); then
      _SAST_PASS_DETAILS="baseline-commit=$_SAST_BASELINE"
      [ -n "$_SAST_PINNED_CONFIG" ] && _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; config=$_SAST_PINNED_CONFIG"
      if [ "$_SAST_EXCL_COUNT" -gt 0 ]; then
        _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; excluded $_SAST_EXCL_COUNT rule(s): $_SAST_EXCL_IDS"
      fi
      _cmd_log_run_checked_pass sast "$_SAST_PASS_DETAILS"
    else
      cmd_log_run sast block "semgrep reported ERROR-severity findings introduced since $_SAST_BASELINE (or timed out after ${_SAST_TIMEOUT}s, or REPO_ROOT could not be entered)"
      return 1
    fi
  else
    echo "[gates/sast] full-tree scan (baseline scoping unavailable: $_SAST_BASELINE_SKIP_REASON; cwd=$REPO_ROOT)" 1>&2
    if ( cd "$REPO_ROOT" || exit 1; run_bounded "$_SAST_TIMEOUT" -- semgrep "$@" --error --severity=ERROR ); then
      _SAST_PASS_DETAILS="full-tree (baseline unavailable: $_SAST_BASELINE_SKIP_REASON)"
      [ -n "$_SAST_PINNED_CONFIG" ] && _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; config=$_SAST_PINNED_CONFIG"
      if [ "$_SAST_EXCL_COUNT" -gt 0 ]; then
        _SAST_PASS_DETAILS="$_SAST_PASS_DETAILS; excluded $_SAST_EXCL_COUNT rule(s): $_SAST_EXCL_IDS"
      fi
      _cmd_log_run_checked_pass sast "$_SAST_PASS_DETAILS"
    else
      cmd_log_run sast block "semgrep reported ERROR-severity findings (full-tree scan: $_SAST_BASELINE_SKIP_REASON; or timed out after ${_SAST_TIMEOUT}s, or REPO_ROOT could not be entered)"
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

# _gate_evaluate GATE INPUT_FILE BASE_SHA SCOPE [EXTRA ARGS...]
#
# The one way gate code asks the finding pipeline for the CODE VERDICT
# (findings.py evaluate): the findings in INPUT_FILE are normalized to the
# unified schema, added to this HEAD's accumulated findings, and the open
# blocking ones, minus those a valid already-merged disposition clears, decide
# pass or block. A model never takes part in that decision. INPUT_FILE empty
# means "no new findings, just recompute" (the merge-gate). SCOPE is "gate"
# (this gate's own findings) or "head" (every gate's, the merge-gate's view).
# BASE_SHA may be empty; the pipeline then resolves the base itself and treats
# every disposition as added in this change when it cannot.
#
# Prints the verdict text on stdout. Returns 0 for PASS, 1 for BLOCKED and
# anything else (2: the pipeline refused the input or could not run) for "no
# verdict was computed", which every caller treats as a block: a verdict that
# could not be computed is never a pass.
_gate_evaluate() {
  _ge_gate="$1"
  _ge_in="$2"
  _ge_base="$3"
  _ge_scope="$4"
  shift 4
  _ge_head=$(_git_repo_scoped_head_sha)
  set -- --gate "$_ge_gate" --caller gates --scope "$_ge_scope" --root "$REPO_ROOT" \
    --default-branch "${CLAGENTIC_DEFAULT_BRANCH:-main}" \
    --threshold "${CLAGENTIC_BLOCK_SEVERITY:-high}" "$@"
  [ -z "$_ge_head" ] || set -- "$@" --head "$_ge_head"
  [ -z "$_ge_base" ] || set -- "$@" --base "$_ge_base"
  _ge_rc=0
  if [ -n "$_ge_in" ]; then
    ds_findings_call -i "$_ge_in" -e any -o 1 evaluate "$@" || _ge_rc=$?
  else
    ds_findings_call -e any -o 1 evaluate --no-input "$@" || _ge_rc=$?
  fi
  return "$_ge_rc"
}

# _ledger_config_snapshot — one-line JSON object of the gate config in
# effect for this review run (item 1's "gate config in effect" requirement).
# Deliberately narrow: only the knobs that change WHAT was evaluated or HOW
# a verdict was scored, not every CLAGENTIC_* var in the process environment
# (an unbounded env dump would itself be an injection/bloat surface into a
# file later read back and rendered).
#
# GATE and DIFF_FILE (optional): for the review gate the snapshot also carries
# the per-run provenance fields (_review_run_provenance_fields) so a recorded
# verdict can be tied to the model, prompt and diff that produced it. The
# adversarial gate shares the ledger but not those inputs, so it gets none.
_ledger_config_snapshot() {
  _lcs_gate="${1:-}"
  _lcs_diff="${2:-}"
  _lcs_threshold="${CLAGENTIC_BLOCK_SEVERITY:-high}"
  _lcs_dedup="${CLAGENTIC_CROSS_ROUND_DEDUP:-1}"
  _lcs_run=""
  if [ "$_lcs_gate" = "review" ]; then
    _lcs_run=",$(_review_run_provenance_fields "$_lcs_diff")"
  fi
  printf '{"block_severity":"%s","cross_round_dedup":%s%s}' \
    "$_lcs_threshold" \
    "$([ "$_lcs_dedup" = "1" ] && echo true || echo false)" \
    "$_lcs_run"
}

# _review_run_provenance_fields DIFF_FILE
#
# Prints (no surrounding braces) the JSON members that make a review verdict
# diagnosable after the fact:
#   model         model id(s) of the chain step(s) that produced accepted output
#   prompt_sha256 sha256 of the assembled system prompt (role prompt plus every
#                 injected block), as llm-client.sh recorded it per call
#   diff_sha256   sha256 of the diff text the reviewer was given. Distinct from
#                 _clagentic_diff_sha, which despite its name stamps HEAD; that
#                 field is kept as is because consumers read it.
#   chunk_count / chunk_sizes  how the diff was split (single pass = one chunk
#                 the size of the diff; empty resolved diff = zero)
# Inputs come from cmd_review's run state (_REVIEW_RUN_PROV_FILE,
# _REVIEW_RUN_CHUNK_SIZES). A value that could not be determined prints as
# "none" rather than being omitted, so absence is itself visible.
_review_run_provenance_fields() {
  _rrpf_diff="$1"
  _rrpf_model=""
  _rrpf_prompt=""
  if [ -n "${_REVIEW_RUN_PROV_FILE:-}" ] && [ -s "$_REVIEW_RUN_PROV_FILE" ]; then
    _rrpf_model=$(cut -f1 "$_REVIEW_RUN_PROV_FILE" | LC_ALL=C sort -u | tr '\n' ',' | tr -cd 'A-Za-z0-9._:/@+,-')
    _rrpf_prompt=$(cut -f4 "$_REVIEW_RUN_PROV_FILE" | LC_ALL=C sort -u | tr '\n' ',' | tr -cd 'A-Za-z0-9,')
    _rrpf_model="${_rrpf_model%,}"
    _rrpf_prompt="${_rrpf_prompt%,}"
  fi
  [ -n "$_rrpf_model" ] || _rrpf_model="none"
  [ -n "$_rrpf_prompt" ] || _rrpf_prompt="none"
  _rrpf_diff_sha=""
  if [ -n "$_rrpf_diff" ]; then
    _rrpf_diff_sha=$(ds_sha256_file "$_rrpf_diff" 2>/dev/null) || _rrpf_diff_sha=""
  fi
  [ -n "$_rrpf_diff_sha" ] || _rrpf_diff_sha="none"
  _rrpf_count=0
  _rrpf_sizes=""
  for _rrpf_sz in ${_REVIEW_RUN_CHUNK_SIZES:-}; do
    case "$_rrpf_sz" in ''|*[!0-9]*) continue ;; esac
    _rrpf_count=$((_rrpf_count + 1))
    _rrpf_sizes="${_rrpf_sizes:+$_rrpf_sizes,}$_rrpf_sz"
  done
  printf '"model":"%s","prompt_sha256":"%s","diff_sha256":"%s","chunk_count":%d,"chunk_sizes":[%s]' \
    "$_rrpf_model" "$_rrpf_prompt" "$_rrpf_diff_sha" "$_rrpf_count" "$_rrpf_sizes"
}

# _ledger_anchored_pass_at_head LEDGER_FILE BRANCH HEAD_SHA — exit 0 (true)
# only when the MOST RECENT ledger entry for BRANCH is anchored to HEAD_SHA
# (its head_sha field equals HEAD_SHA) AND its verdict is "pass". This is
# the one sanctioned "is there a currently-valid verdict" predicate — every
# consumer (build_gate_summary, get_review_diff via
# _ledger_latest_passing_head_for_branch below) must route through this or
# its sibling rather than re-deriving the same check inline, mirroring this
# file's existing "one shared helper, not a re-derivation per call site"
# discipline (_git_repo_root_is_scoped, _gate_resolve_fresh_default_branch_ref).
#
# An "unanchored" verdict (empty/unresolvable head_sha at record time) can
# never satisfy this check even if HEAD_SHA is also empty — an empty
# head_sha never equals HEAD_SHA because HEAD_SHA is only ever passed in
# from a resolved _git_repo_scoped_head_sha call, which is non-empty
# whenever this function is worth calling at all; callers with no resolvable
# HEAD_SHA should not call this function (there is nothing to anchor to).
#
# GATE (4th arg, defaults "review" for backward compatibility with the
# one pre-existing caller in cmd_merge_gate): each gate (review,
# adversarial) now has its own anchor namespace in the ledger, so this
# must find the most recent entry FOR THIS GATE, not merely
# the most recent entry overall for BRANCH — ledger_latest_for_branch reads
# across every gate that writes to the shared review-ledger.jsonl file, so
# taking its result unfiltered would let a later-written adversarial entry
# shadow an earlier, still-valid review pass (or vice versa) purely because
# of write order, not because either gate's own anchor actually changed.
# The predicate itself is findings.py verdict ledger-pass; the latest-entry
# scan keeps the legacy-entry rule: an entry with no `gate` field matches no
# GATE, so back-compat comes from the CALLER always passing an explicit GATE,
# never from the reader guessing "review" for an entry that never recorded one.
_ledger_anchored_pass_at_head() {
  _laph_head="$3"
  [ -n "$_laph_head" ] || return 1
  # Status 1 is the stage's "not an anchored pass" answer; a pipeline failure
  # is also nonzero and so also not a pass, the fail-closed reading.
  ds_findings_call -e any -o 1 verdict ledger-pass "$1" "$2" "$_laph_head" "${4:-review}" || return 1
}

# _ledger_latest_gate_entry LEDGER_FILE BRANCH GATE — print the most recent
# ledger entry (one JSON line) for BRANCH written by GATE, nothing if there is
# none. Returns 1 when the finding pipeline is unavailable. Sole implementation
# of the "latest entry for this gate" scan; _ledger_anchored_pass_at_head and
# _ledger_head_verdict_state both read through the same one in findings.py so
# the pass check and the refusal-reason classification can never disagree
# about which entry is latest.
_ledger_latest_gate_entry() {
  ds_findings_call -e any verdict ledger-latest "$1" "$2" "$3"
}

# _ledger_entry_field ENTRY_JSON FIELD — print FIELD of one ledger entry as a
# string ("" when absent). Returns 1 when the finding pipeline is unavailable.
_ledger_entry_field() {
  ds_findings_call -t "$1" -e any verdict ledger-field "$2"
}

# _ledger_head_verdict_state LEDGER_FILE BRANCH HEAD_SHA GATE
#
# Classify WHY _ledger_anchored_pass_at_head failed, as one token on stdout:
#   review_blocked_at_head  latest GATE entry is anchored to HEAD_SHA with
#                           verdict "block": the review ran at this commit and
#                           its findings are unresolved. Re-running cannot fix
#                           that; the code or a deferral has to change.
#   sha_mismatch            latest GATE entry is anchored to a different SHA
#   missing_stamp           no usable entry: no ledger, no entry for this
#                           gate/branch, an entry with no head_sha, or an
#                           entry at HEAD whose verdict is not pass/block
#                           (skip, unanchored)
#   pass                    the pass predicate holds (nothing to explain)
# Kept as a classifier beside the predicate rather than folded into it: the
# predicate's boolean contract has many callers and must not grow output.
_ledger_head_verdict_state() {
  # An unavailable pipeline reads as no usable entry, the fail-closed answer.
  ds_findings_call verdict ledger-state "$1" "$2" "$3" "${4:-review}" || printf 'missing_stamp'
  return 0
}

# _ledger_latest_passing_head_for_branch LEDGER_FILE BRANCH GATE — stdout: the
# head_sha of the MOST RECENT anchored entry for BRANCH AND GATE whose
# verdict is "pass", or nothing if no such entry exists / LEDGER_FILE is
# absent / no JSON tool available. Sibling of _ledger_anchored_pass_at_head,
# sharing its "pass" doctrine: a "block"/"unanchored"/"skip"/degraded entry
# is never returned, even when it is the LATEST entry overall (lr-542a43 --
# this is exactly the gap _ledger_anchored_pass_at_head's own consumers were
# already closed against: get_review_diff's delta-base lookup used to call
# ledger_latest_for_branch directly and read ONLY head_sha with no verdict
# filter, so a block verdict anchored the next round's delta base
# identically to a pass. Two distinct exploit shapes followed: (a) HEAD
# unchanged since the block -- git merge-base --is-ancestor treats a commit
# as its own ancestor, so the "delta" is an empty diff, an empty diff
# reviews clean, and a pass gets recorded at the SAME sha that just
# blocked; (b) a cosmetic commit after the block -- the delta only covers
# the cosmetic change, never the blocking content below it).
#
# GATE (3rd arg, defaults "review" for backward compatibility):
# review-ledger.jsonl is now shared by BOTH cmd_review and cmd_adversarial,
# each writing its own `gate` field. Without this filter, a review pass
# entry at HEAD anchors the very next cmd_adversarial call's delta lookup
# too -- the adversarial diff resolves to HEAD..HEAD (a hollow-audit
# defect: the auditor examines nothing and reports a clean pass) purely
# because cmd_review ran
# moments earlier in the same `ship` invocation. Filtering on GATE gives
# each gate its own anchor namespace, so no gate's pass can ever anchor a
# different gate's next delta.
#
# NO DEFAULT ON READ (PEACHES, PR #199 review, amos.code-craft.10): same
# doctrine as _ledger_anchored_pass_at_head above -- a legacy entry with no
# `gate` field must never satisfy an explicit GATE match by falling back to
# an assumed "review". That is the exact fail-toward-LESS-coverage shape
# this task exists to close: on a real installed base with a pre-existing
# review-ledger.jsonl, defaulting would let a legacy entry anchor
# cmd_adversarial's delta and narrow its resolved diff. An entry with a
# missing/null/unexpected-type `gate` simply never matches any GATE query;
# the caller falls through to full-range review, same as "no prior passing
# verdict at all."
#
# WHY "latest pass", not "latest entry that happens to be a pass": scanning
# all history (not just the single latest row) matters because the round
# immediately after a block is very often itself a fix attempt that also
# fails, or a cosmetic commit -- the correct re-review base is the last
# point this branch was KNOWN CLEAN, however many blocked/degraded rounds
# came after it, not "the most recent row regardless of what it says."
#
# Reuses ledger_entries_for_branch (oldest-first, same JSON-Lines source
# _ledger_anchored_pass_at_head's own scan reads) rather than re-deriving a
# third ledger-scan primitive -- re-deriving is the exact mistake that
# produced this bug (see lr-542a43 task description).
_ledger_latest_passing_head_for_branch() {
  _llphfb_file="$1"
  [ -f "$_llphfb_file" ] || return 0
  # Without the finding pipeline there is no output: the caller
  # (get_review_diff) treats empty as "no prior passing verdict," which falls
  # through to full-range review (fail toward MORE coverage, never a silent
  # narrower diff).
  ds_findings_call -e any verdict ledger-pass-head "$_llphfb_file" "$2" "${3:-review}" || :
  return 0
}

# _ledger_mark_recurrence FINDINGS_JSON DIFF_FILE LEDGER_FILE BRANCH
#
# Item 5: findings carry stable identity across rounds so the ledger can
# mark a finding recurring vs new. RECORDS RECURRENCE ONLY: this function
# never adjusts severity and never changes whether a finding blocks. The
# output is informational annotation only: each finding in the returned array
# gets `_ledger_recurring: true|false`.
#
# MATCH KEY: the (file, category, message) triple — deliberately NOT
# finding_content_keys' sha256-of-a-diff-context-window key. That key is a
# function of THIS ROUND's diff content around the finding's line; a
# recurring finding very often lands in a round whose diff does not touch
# the finding's file again at all (the model is simply re-reporting an
# unresolved issue while THIS round's diff is elsewhere), which makes the
# content-hash key uncomputable for both the live finding and the
# re-derived prior one — a false negative, not a real absence of
# recurrence.
#
# stdout: the findings array with `_ledger_recurring` spliced onto every
# finding object. On any failure (no python3, unparseable input, no prior
# entries) prints FINDINGS_JSON unchanged (conservative passthrough — a
# recurrence-marking failure must never alter which findings exist or their
# severity, only whether the informational annotation is present).
_ledger_mark_recurrence() {
  _lmr_findings_json="$1"
  _lmr_ledger="$3"
  _lmr_branch="$4"

  # The diff argument ($2) is accepted for the existing call shape; the
  # (file, category, message) match key does not read it.
  _lmr_out=$(ds_findings_call -t "$_lmr_findings_json" -e array \
    dispositions ledger-recurrence --ledger "$_lmr_ledger" --branch "$_lmr_branch") || _lmr_out=""
  [ -n "$_lmr_out" ] && printf '%s' "$_lmr_out" || printf '%s' "$_lmr_findings_json"
  return 0
}

# _ledger_record_review_verdict GATE OUT_FILE DIFF_FILE OUTCOME BASE_SHA HEAD_SHA
#
# Item 1/2/5: builds and appends one ledger entry for this review run.
# GATE is "review" or "adversarial" — written into the entry's own `gate`
# field so each gate's anchor lookups (_ledger_latest_passing_head_for_branch,
# _ledger_anchored_pass_at_head) can filter to entries THIS gate wrote,
# never a sibling gate's. OUTCOME is "pass", "block", or "skip" (an empty
# resolved diff; see cmd_review/cmd_adversarial's own empty-diff check) —
# the caller's own severity_blockers/degraded/empty-diff determination,
# this function does not re-derive it. HEAD_SHA empty means the verdict is
# UNANCHORED (see
# "review ledger" above) regardless of OUTCOME — recorded for audit-trail
# completeness but never readable as a passing verdict by
# _ledger_anchored_pass_at_head.
#
# Fail-open: a ledger write failure (no python3/jq, malformed OUT_FILE) must
# never abort or alter the review gate's own pass/block decision — the
# ledger is a durability/history layer on top of that decision, not a
# precondition for it. Matches every other on-disk gate-state writer's
# posture in this file.
_ledger_record_review_verdict() {
  _lrrv_gate="$1"
  _lrrv_out="$2"
  _lrrv_diff="$3"
  _lrrv_outcome="$4"
  _lrrv_base_sha="$5"
  _lrrv_head_sha="$6"

  _lrrv_verdict="$_lrrv_outcome"
  [ -n "$_lrrv_head_sha" ] || _lrrv_verdict="unanchored"

  _lrrv_ledger=$(_review_ledger_path)
  _lrrv_branch=$(_review_current_branch)
  _lrrv_ts=$(ds_date_iso)
  _lrrv_config=$(_ledger_config_snapshot "$_lrrv_gate" "$_lrrv_diff")
  if [ "$_lrrv_gate" = "review" ]; then
    # Same fields as the ledger config, in the audit trail InfoSec reads.
    ds_audit_log "review-run" "pass" \
      "head=${_lrrv_head_sha:-<unresolved>} verdict=${_lrrv_verdict} $(_review_run_provenance_fields "$_lrrv_diff" | tr -d '"{}')"
  fi

  _lrrv_findings='[]'
  if [ -f "$_lrrv_out" ]; then
    _lrrv_findings=$(_extract_findings_json "$_lrrv_out")
    [ -n "$_lrrv_findings" ] || _lrrv_findings='[]'
  fi

  # Recurrence marking (item 5) — informational only, see
  # _ledger_mark_recurrence's own doc comment.
  _lrrv_findings=$(_ledger_mark_recurrence "$_lrrv_findings" "$_lrrv_diff" "$_lrrv_ledger" "$_lrrv_branch")
  [ -n "$_lrrv_findings" ] || _lrrv_findings='[]'

  # The findings ride stdin: a ledger entry can carry a list larger than one
  # argv string may be.
  _lrrv_line=$(ds_findings_call -t "$_lrrv_findings" -e object verdict ledger-entry \
    --ts "$_lrrv_ts" --branch "$_lrrv_branch" --gate "$_lrrv_gate" --base "$_lrrv_base_sha" \
    --head "$_lrrv_head_sha" --verdict "$_lrrv_verdict" --config "$_lrrv_config") || _lrrv_line=""

  [ -n "$_lrrv_line" ] || return 0

  _lrrv_max="${CLAGENTIC_LEDGER_MAX_PER_BRANCH:-0}"
  case "$_lrrv_max" in ''|*[!0-9]*) _lrrv_max=0 ;; esac
  ledger_append "$_lrrv_ledger" "$_lrrv_line" "$_lrrv_max"
  ds_audit_log "review-ledger" "pass" "gate=${_lrrv_gate} branch=${_lrrv_branch:-<none>} verdict=${_lrrv_verdict} head=${_lrrv_head_sha:-<unresolved>}"

  # Publish (lr-2b07a8): observability only, never gating -- see
  # _publish_review_verdict's own doc comment for the fallback contract.
  # GATE-SCOPED: _publish_review_verdict's one-comment-per-run contract was
  # designed for cmd_review only (its doc comment says "once per cmd_review
  # run"); this function is now also called from cmd_adversarial to give
  # that gate its own ledger anchor, but adding a second PR-comment stream
  # for adversarial verdicts is a distinct, unscoped feature -- publish
  # only when this
  # entry came from the review gate.
  if [ "$_lrrv_gate" = "review" ]; then
    _publish_review_verdict "$_lrrv_branch" "$_lrrv_verdict" "$_lrrv_head_sha" "$_lrrv_findings"
    [ -z "${_REVIEW_RUN_PROV_FILE:-}" ] || rm -f "$_REVIEW_RUN_PROV_FILE"
    _REVIEW_RUN_PROV_FILE=""
  fi

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

  _prv_tag="branch=${_prv_branch:-<none>} head=${_prv_head:-<unresolved>}"
  _prv_body_file=$(mktemp -t clagentic-review-verdict-comment.XXXXXX)
  _prv_limit=$(_ship_artifact_limit) || _prv_limit=""
  _prv_body=$(_build_review_verdict_comment_body "$_prv_verdict" "$_prv_head" "$_prv_findings" 2>/dev/null) || _prv_body=""
  if [ -z "$_prv_limit" ]; then
    rm -f "$_prv_body_file"
    ds_audit_log "review-publish" "block" "${_prv_tag} reason=artifact-limit-unknown"
    return 0
  fi
  if [ -z "$_prv_body" ]; then
    rm -f "$_prv_body_file"
    ds_audit_log "review-publish" "block" "${_prv_tag} reason=body-render-failed"
    return 0
  fi
  # The comment is bounded like every other artifact handed to the adapter.
  # The final newline of the file is part of the count, hence the -1. A failed
  # write could leave a partial file, which must never be posted.
  if ! _ship_bound_text $(( _prv_limit - 1 )) "$_prv_body" > "$_prv_body_file"; then
    rm -f "$_prv_body_file"
    ds_audit_log "review-publish" "block" "${_prv_tag} reason=body-write-failed"
    return 0
  fi

  # One head-only lookup (no base: a PR targeting a non-default base keeps its
  # review comment) -- the same helper ship uses -- then every call addresses
  # the PR by number: a bare branch name can match a closed or merged PR.
  # Zero or several open PRs for the head post nothing.
  _prv_find_rc=0
  _prv_pr=$(host_adapter_find_open_change_request "$_prv_branch") || _prv_find_rc=$?
  if [ "$_prv_find_rc" -ne 0 ]; then
    echo "[gates/review] publish to host adapter failed — local ledger verdict stands, gate outcome unaffected" 1>&2
    if [ "$_prv_find_rc" -eq 1 ]; then
      ds_audit_log "review-publish" "block" "${_prv_tag} reason=no-open-change-request"
    else
      ds_audit_log "review-publish" "block" "${_prv_tag} reason=change-request-lookup-failed"
    fi
    rm -f "$_prv_body_file"
    return 0
  fi

  if host_adapter_post_comment "$_prv_pr" "$_prv_body_file"; then
    ds_audit_log "review-publish" "pass" "${_prv_tag} verdict=${_prv_verdict}"
  else
    echo "[gates/review] publish to host adapter failed — local ledger verdict stands, gate outcome unaffected" 1>&2
    ds_audit_log "review-publish" "block" "${_prv_tag} reason=adapter-post-comment-failed"
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
# closed (no output, non-zero exit): 2 when the findings are unreadable or not
# an array, another nonzero status when the pipeline could not run (python3 or
# findings.py missing, a stage failure). A caller must tell either failure
# apart from an empty list, which prints "Findings: none".
_render_review_verdict_lines() {
  # The findings ride stdin, not argv: one argv string is capped at ~128 KiB
  # by the kernel, so a large findings list made the exec fail outright and
  # the caller degrade to a false "no review recorded". The renderer returns
  # 2 with no output for unreadable findings; an unavailable pipeline returns
  # 1 the same way, so the caller degrades honestly and logs it.
  ds_findings_call -t "$2" render verdict-lines "$1"
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

# ---------------------------------------------------------------- ship PR commits
#
# Commit-derived content for the PR body (section 1) and for the delta comment
# a re-ship posts. clagentic-lite generates this text itself from git so tests
# assert on content rather than on a host CLI's own body-fill semantics -- the
# reverse (delegating to the host CLI's fill flag) is what silently dropped
# commit text once already. Mechanical git reads only; every read routes
# through `_git` behind _git_repo_root_is_scoped (INV-6).

# Hidden HTML-comment marker carrying the shipped head SHA. Embedded in the
# create-time PR body AND in every delta comment; a re-ship reads the PR
# thread back and takes the newest marker as "what was last posted". The PR
# thread is the authoritative record, so no local state file exists to
# diverge across machines/clones/collaborators. The marker is unsigned and
# forgeable by anyone who can comment; that is acceptable because it only
# selects WHICH commits get listed -- it never gates a merge or a gate.
_SHIP_MARKER_PREFIX='<!-- clagentic-lite:shipped-head='
_SHIP_MARKER_SUFFIX=' -->'

# _ship_marker_line SHA — print the marker line for SHA.
_ship_marker_line() {
  printf '%s%s%s\n' "$_SHIP_MARKER_PREFIX" "$1" "$_SHIP_MARKER_SUFFIX"
}

# _ship_marker_from_file FILE — print the SHA of the LAST marker in FILE
# (body first, comments after, so last == newest), or nothing if none.
_ship_marker_from_file() {
  _smff_marker=$(grep -Eo "${_SHIP_MARKER_PREFIX}[0-9a-f]{40,64}${_SHIP_MARKER_SUFFIX}" "$1" 2>/dev/null | tail -n 1)
  _smff_marker=${_smff_marker#"$_SHIP_MARKER_PREFIX"}
  _smff_marker=${_smff_marker%"$_SHIP_MARKER_SUFFIX"}
  printf '%s' "$_smff_marker"
}

# _ship_default_tip_sha — print the provably-current default-branch tip, from
# _gate_resolve_fresh_default_branch_ref (the sanctioned resolution -- never a
# raw origin/<branch> name, which can resolve a stale local tracking ref). On
# failure prints the actual reason to STDOUT and returns 1 (stdout, not
# stderr, so a config WARN on stderr can never be mistaken for the reason or
# the SHA); when freshness cannot be proven the commit list says so rather
# than guessing a possibly wrong range.
_ship_default_tip_sha() {
  _sdts_default="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  if ! _git_repo_root_is_scoped; then
    echo "REPO_ROOT is not itself a git repo"
    return 1
  fi
  _sdts_timeout=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC "${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-}" 30)
  # stdout is the ref and nothing else; the resolver's stderr (its failure
  # reason, or any warning on success) is kept apart so it can never be
  # glued onto the ref and break merge-base.
  _sdts_err=$(mktemp -t clagentic-ship-base-err.XXXXXX) || _sdts_err=/dev/null
  if ! _sdts_tip=$(_gate_resolve_fresh_default_branch_ref "$_sdts_default" "$_sdts_timeout" 2>"$_sdts_err"); then
    # The reason this function prints can land in a public PR body, so it is
    # a fixed string; the resolver's raw stderr (paths, hosts, git errors)
    # stays on the local stderr only.
    [ ! -s "$_sdts_err" ] || cat "$_sdts_err" 1>&2
    echo "the default branch tip could not be resolved or proven current"
    [ "$_sdts_err" = /dev/null ] || rm -f "$_sdts_err"
    return 1
  fi
  [ ! -s "$_sdts_err" ] || cat "$_sdts_err" 1>&2
  [ "$_sdts_err" = /dev/null ] || rm -f "$_sdts_err"
  printf '%s\n' "$_sdts_tip"
}

# ONE OWNER FOR "RENDERED ARTIFACT <= HOST HARD LIMIT". The limit itself is
# the host adapter's (host_adapter_artifact_limit); this section owns the
# budgeting. Every artifact gates ship hands the adapter (the PR body, the
# re-ship delta comment, the review-verdict comment) is bounded by the
# primitives below: variable-size parts are clipped or listed against a budget
# computed from the limit, and a final whole-artifact guard re-checks the
# assembled text before it is returned. No caller carries a limit of its own.

# _ship_bytes TEXT — byte length of TEXT. Bytes are never fewer than the
# characters the host counts, so measuring in bytes can only be conservative.
_ship_bytes() {
  printf '%s' "$1" | wc -c | tr -d ' '
}

# _ship_artifact_limit — the host's hard limit for one body/comment, from the
# adapter. Non-zero when the adapter answers with anything but a positive
# integer: a limit that is not known is never guessed.
_ship_artifact_limit() {
  _sal_limit=$(host_adapter_artifact_limit 2>/dev/null) || return 1
  case "$_sal_limit" in
    ""|*[!0-9]*|0) return 1 ;;
  esac
  printf '%s\n' "$_sal_limit"
}

# _ship_bound_text MAX TEXT — TEXT unchanged when it fits in MAX characters;
# otherwise whole lines up to MAX minus the notice, then an explicit
# "[truncated, N chars not shown]" line. A single line longer than the budget
# is cut at the budget (by `cut -c`, so by bytes in a C locale: a multi-byte
# character on the cut line may be split, which the host replaces rather than
# rejects). Never silent.
_ship_bound_text() {
  _sbt_max="$1"
  _sbt_text="$2"
  if [ "${#_sbt_text}" -le "$_sbt_max" ]; then
    printf '%s\n' "$_sbt_text"
    return 0
  fi
  # The notice counts inside MAX. Its length is fixed text plus the digits of
  # the largest count it could name; when it alone does not fit it is omitted
  # and the cut text takes the whole budget, so output never exceeds MAX.
  _sbt_total="${#_sbt_text}"
  _sbt_notice_len=$(( 31 + ${#_sbt_total} ))
  _sbt_notice=1
  if [ "$_sbt_max" -gt "$_sbt_notice_len" ]; then
    _sbt_budget=$(( _sbt_max - _sbt_notice_len ))
  else
    _sbt_budget=$_sbt_max
    _sbt_notice=0
  fi
  [ "$_sbt_budget" -gt 0 ] || _sbt_budget=0
  _sbt_used=0
  while IFS= read -r _sbt_line; do
    _sbt_cost=$(( ${#_sbt_line} + 1 ))
    if [ $(( _sbt_used + _sbt_cost )) -le "$_sbt_budget" ]; then
      printf '%s\n' "$_sbt_line"
      _sbt_used=$(( _sbt_used + _sbt_cost ))
    else
      # The cut line carries its own newline, so it gets one char less.
      if [ "$_sbt_used" -eq 0 ] && [ "$_sbt_budget" -gt 1 ]; then
        printf '%s\n' "$(printf '%s' "$_sbt_line" | cut -c1-$(( _sbt_budget - 1 )))"
        _sbt_used=$_sbt_budget
      fi
      break
    fi
  done <<EOF
$_sbt_text
EOF
  [ "$_sbt_notice" -eq 1 ] || return 0
  printf '[truncated, %s chars not shown]\n' "$(( ${#_sbt_text} - _sbt_used ))"
}

# _ship_emit_within_limit ASSEMBLE_FN FIXED_CHARS — print the whole artifact
# ASSEMBLE_FN builds, guaranteed no larger than the host limit. ASSEMBLE_FN is
# called with the character budget left for the commit list (the limit minus
# FIXED_CHARS, the caller's own fixed parts, and a slack for placeholder text)
# and must print the complete artifact. The assembled result is measured and,
# if it is over the limit anyway, the budget is cut by the excess and the
# artifact reassembled; the last resort is a zero budget, where the list
# degrades to an explicit placeholder. An artifact still over the limit then is
# an error (return 1), never an over-limit result. ASSEMBLE_FN's own non-zero
# status (3 empty range, 4 no budget, 1 enumeration failure) is passed through.
_ship_emit_within_limit() {
  _seil_fn="$1"
  _seil_fixed="$2"
  _seil_limit=$(_ship_artifact_limit) || return 1
  _seil_budget=$(( _seil_limit - _seil_fixed - 512 ))
  [ "$_seil_budget" -ge 0 ] || _seil_budget=0
  _seil_try=0
  while :; do
    _seil_rc=0
    _seil_out=$("$_seil_fn" "$_seil_budget") || _seil_rc=$?
    [ "$_seil_rc" -eq 0 ] || return "$_seil_rc"
    _seil_size=$(( $(_ship_bytes "$_seil_out") + 1 ))
    if [ "$_seil_size" -le "$_seil_limit" ]; then
      printf '%s\n' "$_seil_out"
      return 0
    fi
    [ "$_seil_budget" -gt 0 ] || return 1
    _seil_try=$(( _seil_try + 1 ))
    if [ "$_seil_try" -ge 6 ]; then
      _seil_budget=0
    else
      _seil_budget=$(( _seil_budget - (_seil_size - _seil_limit) - 64 ))
      [ "$_seil_budget" -ge 0 ] || _seil_budget=0
    fi
  done
}

# Smallest character budget in which a commit entry is worth showing: the
# entry's own framing (bullet, fences, truncation note) plus a few lines of
# text. A first entry is truncated to the budget it has, so this only decides
# when there is no point starting a list at all.
_SHIP_ENTRY_MIN_CHARS=300

# _ship_format_commit_entry SHA MAX_CHARS — one commit: a short-SHA bullet, then
# the full message (subject first, then body) inside one fenced code block
# nested under the list item. A fence is the only construct whose content
# cannot become markdown structure (indent alone does not: CommonMark allows
# 0-3 leading spaces on an ATX heading), so the fence is made longer than any
# backtick run in the message, which also means it cannot close the fence early.
#
# The whole entry (bullet, fences, message, notice) is at most MAX_CHARS.
# When the commit message does not fit, it is cut by whole lines (a single
# over-long line is clipped), and an explicit
# "[commit message truncated, N chars not shown]" notice follows the closing
# fence so it renders as prose. Exit 0 when the message is shown whole, 10 when
# anything was cut (the caller decides whether a cut entry may be listed),
# 1 when git cannot read the commit.
_ship_format_commit_entry() {
  _sfce_sha="$1"
  _sfce_max="$2"
  _sfce_subject=$(_git log -1 --format=%s "$_sfce_sha" 2>/dev/null) || return 1
  _sfce_body=$(_git log -1 --format=%b "$_sfce_sha" 2>/dev/null) || return 1
  # Subject and body share one fenced block (subject as its first line): the
  # subject is untrusted text too, and inside a fence nothing in it, such as an
  # unclosed "<!--", can become markup, so no escaping code is needed.
  if [ -n "$_sfce_body" ]; then
    _sfce_body="${_sfce_subject}
${_sfce_body}"
  else
    _sfce_body="$_sfce_subject"
  fi
  _sfce_short=$(printf '%s' "$_sfce_sha" | cut -c1-7)
  _sfce_nl='
'
  _sfce_fence='```'
  while :; do
    case $_sfce_body in
      *"$_sfce_fence"*) _sfce_fence="${_sfce_fence}\`" ;;
      *) break ;;
    esac
  done
  # Fixed framing: bullet line, two fence lines, slack.
  _sfce_overhead=$(( 20 + 2 * (${#_sfce_fence} + 3) ))
  _sfce_nlines=0
  [ -z "$_sfce_body" ] || _sfce_nlines=$(printf '%s\n' "$_sfce_body" | wc -l | tr -d ' ')
  _sfce_body_cost=$(( ${#_sfce_body} + 3 * _sfce_nlines + 1 ))
  if [ $(( _sfce_body_cost + _sfce_overhead )) -le "$_sfce_max" ]; then
    _sfce_budget=$_sfce_body_cost
  else
    # Truncating: reserve the notice (at most ~55 chars) from what is left.
    _sfce_avail=$(( _sfce_max - _sfce_overhead - 72 ))
    [ "$_sfce_avail" -ge 2 ] || _sfce_avail=2
    _sfce_budget=$_sfce_avail
  fi
  _sfce_omitted=0
  _sfce_acc=""
  _sfce_used=0
  _sfce_cut=0
  if [ -n "$_sfce_body" ]; then
    while IFS= read -r _sfce_line; do
      _sfce_cost=$(( ${#_sfce_line} + 3 ))
      if [ "$_sfce_cut" -eq 0 ] && [ $(( _sfce_used + _sfce_cost )) -le "$_sfce_budget" ]; then
        if [ -n "$_sfce_line" ]; then
          _sfce_acc="${_sfce_acc}  ${_sfce_line}${_sfce_nl}"
        else
          _sfce_acc="${_sfce_acc}${_sfce_nl}"
        fi
        _sfce_used=$(( _sfce_used + _sfce_cost ))
      elif [ "$_sfce_cut" -eq 0 ] && [ "$_sfce_used" -eq 0 ] && [ "$_sfce_budget" -gt 3 ]; then
        # The first line alone is over budget: keep its head.
        _sfce_keep=$(( _sfce_budget - 3 ))
        _sfce_head=$(printf '%s' "$_sfce_line" | cut -c1-"$_sfce_keep")
        _sfce_acc="${_sfce_acc}  ${_sfce_head}${_sfce_nl}"
        _sfce_omitted=$(( _sfce_omitted + ${#_sfce_line} - ${#_sfce_head} ))
        _sfce_used=$_sfce_budget
        _sfce_cut=1
      else
        _sfce_cut=1
        _sfce_omitted=$(( _sfce_omitted + ${#_sfce_line} + 1 ))
      fi
    done <<EOF
$_sfce_body
EOF
  fi
  printf '%s `%s`\n' '-' "$_sfce_short"
  if [ -n "$_sfce_acc" ]; then
    printf '  %s\n' "$_sfce_fence"
    printf '%s' "$_sfce_acc"
    printf '  %s\n' "$_sfce_fence"
  fi
  [ "$_sfce_omitted" -gt 0 ] || return 0
  printf '  [commit message truncated, %s chars not shown]\n' "$_sfce_omitted"
  return 10
}

# _ship_render_commit_list TIP HEAD MAX_CHARS [MARKER] — THE one range
# primitive for "this branch's commits", used by both the create-time body and
# the delta comment: every non-merge commit reachable from HEAD and from
# neither the provably-current default-branch TIP nor (when given) MARKER, the
# last shipped head. Exclusion by reachability, not a merge-base range, keeps
# the result the same however many merge-bases exist (a default branch merged
# into the branch, criss-cross merges): upstream commits are never listed.
# Oldest first, as one block of at most MAX_CHARS characters in
# total (entries, the "N more commits not shown" line and the marker).
# MAX_CHARS is the caller's budget under the host limit; CLAGENTIC_SHIP_COMMITS_MAX_CHARS
# may lower it, never raise it. An entry that does not fit whole is left out and
# counted in the not-shown line (the PR's Commits tab has every commit), except
# the first entry, which is truncated to the room there is, so a single huge
# commit message can neither overflow the artifact nor block the list.
# Exit: 0 listed >=1 commit, 3 range is empty, 4 the budget leaves no room for
# a single entry, 1 git could not enumerate the range. Ends with the
# shipped-head marker, always HEAD.
_ship_render_commit_list() {
  _srcl_tip="$1"
  _srcl_head="$2"
  _srcl_cap="$3"
  _srcl_marker="${4:-}"
  if [ -n "$_srcl_marker" ]; then
    _srcl_shas=$(_git rev-list --reverse --no-merges "$_srcl_head" "^${_srcl_tip}" "^${_srcl_marker}" 2>/dev/null) || return 1
  else
    _srcl_shas=$(_git rev-list --reverse --no-merges "$_srcl_head" "^${_srcl_tip}" 2>/dev/null) || return 1
  fi
  [ -n "$_srcl_shas" ] || return 3
  [ "$_srcl_cap" -ge 1 ] || return 4
  _srcl_max=$(ds_positive_int_or_warn CLAGENTIC_SHIP_COMMITS_MAX_CHARS "${CLAGENTIC_SHIP_COMMITS_MAX_CHARS:-}" "$_srcl_cap")
  [ "$_srcl_max" -le "$_srcl_cap" ] || _srcl_max="$_srcl_cap"
  # Room kept back for the not-shown line and the marker (SHA up to 64 hex).
  _srcl_reserve=$(( ${#_SHIP_MARKER_PREFIX} + ${#_SHIP_MARKER_SUFFIX} + 64 + 2 + 130 ))
  _srcl_ebudget=$(( _srcl_max - _srcl_reserve ))
  [ "$_srcl_ebudget" -ge "$_SHIP_ENTRY_MIN_CHARS" ] || return 4
  _srcl_total=$(printf '%s\n' "$_srcl_shas" | wc -l | tr -d ' ')
  _srcl_shown=0
  _srcl_used=0
  for _srcl_sha in $_srcl_shas; do
    _srcl_room=$(( _srcl_ebudget - _srcl_used ))
    # An entry is separated from the next by one blank line (+2 chars).
    [ "$_srcl_shown" -eq 0 ] || _srcl_room=$(( _srcl_room - 2 ))
    _srcl_rc=0
    _srcl_entry=$(_ship_format_commit_entry "$_srcl_sha" "$_srcl_room") || _srcl_rc=$?
    case "$_srcl_rc" in
      0) ;;
      10) [ "$_srcl_shown" -eq 0 ] || break ;;
      *) return 1 ;;
    esac
    printf '%s\n\n' "$_srcl_entry"
    _srcl_used=$(( _srcl_used + ${#_srcl_entry} + 2 ))
    _srcl_shown=$(( _srcl_shown + 1 ))
  done
  if [ "$_srcl_shown" -lt "$_srcl_total" ]; then
    printf "_%s more commits not shown -- see this PR's Commits tab._\n" "$(( _srcl_total - _srcl_shown ))"
  fi
  # The ONE marker-emission point for the body and delta-comment paths. It is
  # always HEAD, because unshown commits are not listed by any later ship.
  printf '\n'
  _ship_marker_line "$_srcl_head"
  return 0
}

# _ship_render_commits_section HEAD_SHA MAX_CHARS — body of PR section 1: the
# commits between origin/<default> and HEAD_SHA, within MAX_CHARS. When the
# range cannot be resolved, is genuinely empty, or the budget leaves no room,
# says exactly why; this is the ONLY case a placeholder appears. Exit 0 when
# commits were actually listed, 3 when a placeholder was printed instead -- the
# caller must not record a shipped-head marker for a head whose commits were
# never listed.
_ship_render_commits_section() {
  _srcs_head="$1"
  _srcs_cap="$2"
  if [ -z "$_srcs_head" ]; then
    printf '_Commit list unavailable: %s. Fill in by hand before merging._\n' "the shipped head commit could not be resolved"
    return 3
  fi
  if ! _srcs_tip=$(_ship_default_tip_sha); then
    printf '_Commit list unavailable: %s. Fill in by hand before merging._\n' "$_srcs_tip"
    return 3
  fi
  _srcs_rc=0
  _srcs_out=$(_ship_render_commit_list "$_srcs_tip" "$_srcs_head" "$_srcs_cap") || _srcs_rc=$?
  case "$_srcs_rc" in
    0) printf '%s\n' "$_srcs_out"; return 0 ;;
    3) printf '_No commits to list: nothing between origin/%s and the shipped head (empty range)._\n' "${CLAGENTIC_DEFAULT_BRANCH:-main}" ;;
    4) printf '_Commit list omitted: the host size limit leaves no room for it after the other sections._\n' ;;
    *) printf '_Commit list unavailable: git could not enumerate the commits of %s. Fill in by hand before merging._\n' \
         "$(printf '%s' "$_srcs_head" | cut -c1-7)" ;;
  esac
  return 3
}

# _ship_delta_assemble BUDGET — the delta comment's whole text, for
# _ship_emit_within_limit. Reads its parts from _SPD_* (set by
# _publish_ship_delta_comment); non-zero statuses are the commit list's own.
_ship_delta_assemble() {
  _sda_list=$(_ship_render_commit_list "$_SPD_TIP" "$_SPD_HEAD" "$1" "$_SPD_MARKER") || return $?
  printf '**clagentic-lite ship: %s**\n\n' "$_SPD_TITLE"
  [ -z "$_SPD_NOTE" ] || printf '%s\n\n' "$_SPD_NOTE"
  printf '%s\n' "$_sda_list"
}

# _publish_ship_delta_comment BRANCH HEAD_SHA PR_NUM
#
# Re-ship to an already-open PR (PR_NUM, from host_adapter_open_change_request's
# `reused <num>`): the PR body is NEVER edited (it is written only at create);
# instead post ONE comment listing the commits added since the last ship,
# anchored by the newest hidden marker found by reading the PR thread (body +
# comments) back through the host adapter, by number.
#
#   read FAILED (adapter/auth/network)  -> post nothing, audit-log it. A
#       failed read is never treated as "no marker": that would spam the full
#       list on every transient error.
#   read OK, no marker                  -> full origin/<default>..HEAD list,
#       saying why (PR opened before this feature, or by hand).
#   marker not an ancestor of HEAD      -> full list, saying history was
#       rewritten (rebase/force-push).
#   no commits since the marker         -> post nothing.
#
# FALLBACK CONTRACT, same as _publish_review_verdict: a publish problem never
# blocks ship and never changes its outcome; every non-post is audit-logged.
_publish_ship_delta_comment() {
  _psdc_branch="$1"
  _psdc_head="$2"
  _psdc_pr="$3"
  _psdc_tag="branch=${_psdc_branch:-<none>} head=${_psdc_head:-<unresolved>} pr=${_psdc_pr:-<none>}"

  if [ -z "$_psdc_head" ] || ! _git_repo_root_is_scoped; then
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=head-unresolved"
    return 0
  fi

  if ! _psdc_thread=$(mktemp -t clagentic-ship-thread.XXXXXX); then
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=tempfile-failed"
    return 0
  fi
  if ! host_adapter_read_thread_text "$_psdc_pr" > "$_psdc_thread" 2>/dev/null; then
    rm -f "$_psdc_thread"
    echo "[gates/ship] could not read the PR thread — no delta comment posted, ship outcome unaffected" 1>&2
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=thread-read-failed"
    return 0
  fi
  _psdc_marker=$(_ship_marker_from_file "$_psdc_thread")
  rm -f "$_psdc_thread"

  _psdc_from=""
  _psdc_note=""
  if [ -z "$_psdc_marker" ]; then
    _psdc_note="No earlier ship marker was found on this PR (it was opened before commit tracking existed, or by hand), so every commit on the branch is listed."
  elif _git rev-parse --verify -q "${_psdc_marker}^{commit}" >/dev/null 2>&1 \
       && _git merge-base --is-ancestor "$_psdc_marker" "$_psdc_head" 2>/dev/null; then
    _psdc_from="$_psdc_marker"
  else
    _psdc_note="History was rewritten since the last ship (the last shipped commit ${_psdc_marker} is not an ancestor of the current head), so every commit on the branch is listed."
  fi

  if ! _psdc_tip=$(_ship_default_tip_sha); then
    echo "[gates/ship] no delta comment posted: ${_psdc_tip}" 1>&2
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=base-unresolved"
    return 0
  fi

  if [ -z "$_psdc_from" ]; then
    _psdc_title="all commits on this branch"
  else
    _psdc_title="commits added since the last ship"
  fi

  _SPD_MARKER="$_psdc_from"
  _SPD_TIP="$_psdc_tip"
  _SPD_HEAD="$_psdc_head"
  _SPD_TITLE="$_psdc_title"
  _SPD_NOTE="$_psdc_note"
  if ! _psdc_body_file=$(mktemp -t clagentic-ship-delta-comment.XXXXXX); then
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=tempfile-failed"
    return 0
  fi
  _psdc_rc=0
  _ship_emit_within_limit _ship_delta_assemble $(( ${#_psdc_title} + ${#_psdc_note} + 16 )) > "$_psdc_body_file" || _psdc_rc=$?
  if [ "$_psdc_rc" -eq 3 ]; then
    rm -f "$_psdc_body_file"
    ds_audit_log "ship-delta-publish" "pass" "${_psdc_tag} reason=no-new-commits"
    return 0
  elif [ "$_psdc_rc" -eq 4 ]; then
    rm -f "$_psdc_body_file"
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=size-budget-exhausted"
    return 0
  elif [ "$_psdc_rc" -ne 0 ]; then
    rm -f "$_psdc_body_file"
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=commit-enumeration-failed"
    return 0
  fi

  if host_adapter_post_comment "$_psdc_pr" "$_psdc_body_file"; then
    ds_audit_log "ship-delta-publish" "pass" "${_psdc_tag} reason=posted"
  else
    echo "[gates/ship] delta comment failed to post — ship outcome unaffected" 1>&2
    ds_audit_log "ship-delta-publish" "block" "${_psdc_tag} reason=adapter-post-comment-failed"
  fi
  rm -f "$_psdc_body_file"
  return 0
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
# Section 1 (what changed and why) is the branch's own commit messages
# (subject + full body, oldest first), read mechanically from git by
# _ship_render_commits_section -- no summarization, no LLM. Sections 3/4
# (trade-offs, out-of-scope) have no mechanical source in this codebase, so
# each renders an explicit placeholder naming that gap, never a fabricated
# summary and never a bare empty heading. A hidden marker carrying the
# shipped head SHA is appended so a later re-ship can tell which commits the
# PR thread already lists (see _publish_ship_delta_comment).
_build_ship_pr_body() {
  _bspb_branch="$1"
  _bspb_head="$2"

  _bspb_ledger=$(_review_ledger_path)
  _bspb_review_section=""
  # A review record that exists but cannot be read is reported as exactly
  # that, never as "no review recorded": the two are different facts.
  _bspb_unreadable="reviewer: a review record exists for this branch but could not be read -- treat review as not yet run for this head."
  if [ -n "$_bspb_head" ] && command -v python3 >/dev/null 2>&1; then
    _bspb_latest=$(ledger_latest_for_branch "$_bspb_ledger" "$_bspb_branch")
    if [ -n "$_bspb_latest" ]; then
      _bspb_entry_head=$(_ledger_entry_field "$_bspb_latest" head_sha) || _bspb_entry_head=""
      _bspb_entry_verdict=$(_ledger_entry_field "$_bspb_latest" verdict) || _bspb_entry_verdict=""
      _bspb_entry_findings=$(ds_findings_call -t "$_bspb_latest" verdict ledger-field findings --json-default '[]') \
        || _bspb_entry_findings=""

      if [ -z "$_bspb_entry_findings" ]; then
        # The entry's findings could not be read: an empty value here is an
        # error, never an empty list, so the body says the record is
        # unreadable instead of claiming "no review recorded".
        _bspb_review_section="$_bspb_unreadable"
      elif [ -n "$_bspb_entry_head" ] && [ "$_bspb_entry_head" = "$_bspb_head" ]; then
        # An anchored entry exists at THIS exact head_sha -- the review this
        # section describes actually evaluated the code being shipped, not a
        # stale prior round. Reuse the same rendering core the posted
        # review-verdict comment uses (reuse, not re-derivation).
        _bspb_lines_rc=0
        _bspb_lines=$(_render_review_verdict_lines "$_bspb_entry_head" "$_bspb_entry_findings" 2>/dev/null) || _bspb_lines_rc=$?
        if [ "$_bspb_lines_rc" -eq 0 ] && [ -n "$_bspb_lines" ]; then
          _bspb_review_section=$(printf 'verdict: %s\n\n%s\n' "$_bspb_entry_verdict" "$_bspb_lines")
        else
          _bspb_review_section="$_bspb_unreadable"
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
    _bspb_review_section="reviewer: none -- no readable review verdict recorded for this branch. Run \`clagentic-lite gates review\` (or \`gates ship\`, which runs it) before merging if cross-vendor review is expected."
  fi

  # Gate attestation section (lr-37a9c8): renders from
  # .clagentic/lite/last-gate-manifest.json, the arbiter for what actually
  # ran (see docs/GATES.md "Gate attestation manifest" -- when the ledger/
  # audit.db/PR-comment/router-journal disagree, the manifest is the record
  # of what THIS ship invocation observed). Same "degrade honestly, never a
  # bare heading" discipline as the review-provenance section above.
  _bspb_manifest_section=$(_render_gate_manifest_lines 2>/dev/null) || true
  if [ -z "$_bspb_manifest_section" ]; then
    _bspb_manifest_section="no gate attestation manifest recorded for this run -- run \`clagentic-lite gates ship\` (the manifest is written unconditionally at the start of that command) if attestation is expected. A missing manifest is never inferred as a clean run."
  fi

  # Every variable-size part is bounded against the host limit: the review
  # and attestation sections here (an eighth of the limit each), the commit
  # list by the budget _ship_emit_within_limit derives from what is left.
  _bspb_limit=$(_ship_artifact_limit) || return 1
  _bspb_section_cap=$(( _bspb_limit / 8 ))
  # A bounding failure degrades to the section's fixed placeholder, never a
  # bare heading.
  _bspb_bounded=$(_ship_bound_text "$_bspb_section_cap" "$_bspb_review_section") || _bspb_bounded=""
  if [ -z "$_bspb_bounded" ]; then
    _bspb_bounded="reviewer: review section could not be rendered. Run \`clagentic-lite gates review\` and fill in by hand before merging."
  fi
  _bspb_review_section="$_bspb_bounded"
  _bspb_bounded=$(_ship_bound_text "$_bspb_section_cap" "$_bspb_manifest_section") || _bspb_bounded=""
  if [ -z "$_bspb_bounded" ]; then
    _bspb_bounded="gate attestation could not be rendered. A missing attestation is never inferred as a clean run."
  fi
  _bspb_manifest_section="$_bspb_bounded"

  _SPB_HEAD="$_bspb_head"
  _SPB_TAIL=$(
    printf '## Review provenance\n\n%s\n\n' "$_bspb_review_section"
    printf '## Gate attestation\n\n%s\n\n' "$_bspb_manifest_section"
    printf '## Trade-offs taken and rejected\n\n'
    printf '_Not recorded by tooling; fill in by hand, or state "none" if none were seriously considered._\n\n'
    printf '## Explicitly out of scope\n\n'
    printf '_Not recorded by tooling; fill in by hand, or state "none" if the change is fully self-contained._\n'
  )
  _ship_emit_within_limit _ship_pr_body_assemble $(( ${#_SPB_TAIL} + 64 ))
}

# _ship_pr_body_assemble BUDGET — the PR body's whole text, for
# _ship_emit_within_limit; BUDGET is the characters the commit list may use.
# The shipped-head marker (HEAD) is emitted inside the commit list itself, and
# only when commits were listed -- a placeholder never anchors a head whose
# commits the thread does not show.
_ship_pr_body_assemble() {
  printf '## What changed and why\n\n'
  # Status 3 is the section's own "placeholder printed" answer. Any other
  # status, or no text at all, is a renderer failure: say so with a fixed
  # reason rather than leave the heading bare.
  _spba_rc=0
  _spba_section=$(_ship_render_commits_section "$_SPB_HEAD" "$1") || _spba_rc=$?
  if { [ "$_spba_rc" -ne 0 ] && [ "$_spba_rc" -ne 3 ]; } || [ -z "$_spba_section" ]; then
    _spba_section="_Commit list unavailable: the commit list could not be rendered. Fill in by hand before merging._"
  fi
  printf '%s\n' "$_spba_section"
  printf '\n'
  printf '%s\n' "$_SPB_TAIL"
}

# get_review_diff — prints the best available diff to stdout for use by
# cmd_review and cmd_adversarial.
#
# Priority:
#   1. Staged diff (git diff --cached) — normal pre-commit path.
#   2. Delta re-review (default-on, lr-01ae73; generalizes the former
#      --since-last-review opt-in flag into the default mode): when the
#      current branch has a prior PASSING ANCHORED ledger verdict (see
#      "review ledger" above; lr-542a43 — a block/degraded/unanchored
#      entry, even if it is the LATEST entry for the branch, is never
#      usable as a delta base) whose head_sha resolves as an ancestor of
#      HEAD in THIS repo, diff <that head_sha>..HEAD instead of the full
#      origin/<default>..HEAD branch diff. This is the structural fix for
#      the death-spiral (many fix-commits accumulating into an unreviewed
#      diff). --full-review forces full-range regardless of ledger state.
#      A prior head_sha that no longer resolves as an ancestor of HEAD
#      (rebase, amend, force-push) is NOT usable as a delta base — falls
#      through to full-range and says so on stderr (fail toward MORE
#      coverage, matching cmd_sast/cmd_bleed doctrine — see REVIEW_FULL
#      handling below). An empty computed range (HEAD unchanged since the
#      passing verdict) is likewise never returned as-is — an empty diff
#      reads as a clean re-review of nothing; it falls through to
#      full-range too (lr-542a43).
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
#
# GATE_NAME: which gate is asking for a diff — "review" or "adversarial".
# Required for the ledger-anchored delta lookup below: each gate now has
# its OWN anchor namespace in the ledger
# (_ledger_latest_passing_head_for_branch's GATE argument), so cmd_adversarial
# can never consume cmd_review's just-written HEAD anchor and diff
# HEAD..HEAD against it. Defaults to "review" when omitted, matching this
# function's original behavior for any caller that hasn't been updated.
get_review_diff() {
  _grd_gate="${1:-review}"
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
  # SOURCE OF TRUTH: the review ledger's latest PASSING anchored verdict for
  # the current branch (_review_ledger_path /
  # _ledger_latest_passing_head_for_branch) — not last-review.json's
  # _clagentic_diff_sha stamp, which only ever remembers the SINGLE most
  # recent run and is overwritten on every call regardless of outcome, and
  # NOT the raw latest ledger entry regardless of verdict (lr-542a43: a
  # block/degraded/unanchored entry must never anchor the delta base — see
  # _ledger_latest_passing_head_for_branch's own doc comment for the two
  # exploit shapes that follow from anchoring on an unfiltered "latest
  # entry"). The ledger is append-only and verdict-aware, so this reads the
  # same value the "generalize, don't parallel" reuse-seam instruction
  # points at, just from the durable record rather than the single mutable
  # snapshot, and routed through the one sanctioned pass-filtering path
  # rather than re-deriving a third inline verdict check.
  if [ "${REVIEW_FULL:-0}" != "1" ]; then
    _grd_ledger=$(_review_ledger_path)
    _grd_prior_head=$(_ledger_latest_passing_head_for_branch "$_grd_ledger" "$CURRENT_BRANCH" "$_grd_gate")

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
        # EMPTY RANGE IS NOT CLEAN (lr-542a43, exploit path B): a commit is
        # its own ancestor, so a passing verdict already anchored at
        # current HEAD (nothing new committed since) produces `git diff
        # X..X`, zero bytes. An empty diff must never be handed to the
        # reviewer as "the delta" — it reads as a clean pass on content
        # that was never re-examined. Compute the range into a temp file
        # first and only return it when non-empty; an empty result falls
        # through to full-range below, same fail-toward-MORE-coverage
        # doctrine as the unresolvable-SHA branch above.
        _grd_delta_tmp=$(mktemp -t clagentic-review-delta.XXXXXX)
        _git diff "${_grd_prior_head}..HEAD" --unified=3 2>/dev/null > "$_grd_delta_tmp"
        if [ -s "$_grd_delta_tmp" ]; then
          printf '[gates/%s] delta re-review: diffing %s..HEAD (prior passing anchored verdict on this branch, gate=%s)\n' "$_grd_gate" "$_grd_prior_head" "$_grd_gate" 1>&2
          cat "$_grd_delta_tmp"
          rm -f "$_grd_delta_tmp"
          return 0
        fi
        rm -f "$_grd_delta_tmp"
        printf '[gates/%s] delta re-review: computed range %s..HEAD is empty (no new commits since the last passing verdict) — falling back to full-range review rather than reporting a silent pass\n' "$_grd_gate" "$_grd_prior_head" 1>&2
      else
        printf '[gates/%s] delta re-review: prior passing verdict SHA %s is no longer an ancestor of HEAD (rebase/amend/force-push) — falling back to full-range review\n' "$_grd_gate" "$_grd_prior_head" 1>&2
      fi
    else
      printf '[gates/%s] delta re-review: no prior passing anchored verdict for branch %s (gate=%s) — full-range review\n' "$_grd_gate" "${CURRENT_BRANCH:-<none>}" "$_grd_gate" 1>&2
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
    _grd_fetch_timeout=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC "${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-}" 30)

    _grd_fresh_err_tmp=$(mktemp -t clagentic-review-fresh-err.XXXXXX)
    _grd_fresh_tip=$(_gate_resolve_fresh_default_branch_ref "$DEFAULT_BRANCH" "$_grd_fetch_timeout" 2>"$_grd_fresh_err_tmp") || true
    _grd_fresh_err=$(cat "$_grd_fresh_err_tmp" 2>/dev/null || echo "")
    rm -f "$_grd_fresh_err_tmp"

    if [ -z "$_grd_fresh_tip" ]; then
      printf '[gates/%s] branch baseline not provably current (%s) — refusing to produce a possibly-narrowed diff\n' "$_grd_gate" "$_grd_fresh_err" 1>&2
      return 1
    fi

    printf '[gates/%s] no staged changes — using branch diff vs verified origin/%s\n' "$_grd_gate" "$DEFAULT_BRANCH" 1>&2
    _git diff "${_grd_fresh_tip}...HEAD" --unified=3 2>/dev/null
    return 0
  fi

  printf '[gates/%s] no staged changes and on default branch — empty diff\n' "$_grd_gate" 1>&2
}

# _gate_resolved_diff_is_empty DIFF_FILE — true (exit 0) when DIFF_FILE has
# zero bytes, i.e. get_review_diff resolved a range with nothing in it.
# Thin, named predicate rather than an inline `[ ! -s FILE ]` at each of
# cmd_review/cmd_adversarial's call sites -- both gates must apply the
# identical test, and a shared name makes the intent ("did this gate
# actually have anything to examine") greppable independent of either
# caller's own variable-naming convention.
_gate_resolved_diff_is_empty() {
  [ ! -s "$1" ]
}

# _cross_round_dedup ENVELOPE_FILE DIFF_FILE SEEN_FILE
#
# Reads the findings array from ENVELOPE_FILE, pipes it through dedup_findings
# content-hash (from review-merge.sh) with SEEN_FILE as the persisted key store
# and DIFF_FILE as the context source, splices the result back into
# ENVELOPE_FILE in place, and logs a gate_runs audit row with the counts.
#
# ANNOTATE, NEVER DROP: a finding whose key an earlier run recorded stays in
# the envelope with `_seen_before: true`, so severity_blockers still counts it.
# Dropping it made a re-run of `gates review` at an unchanged HEAD forget the
# first run's blocking finding and pass: the gate's verdict depended on how
# many times it had been asked. Display may collapse seen findings
# (cmd_render_review marks them); the verdict may not change because one was
# seen before. The only suppressions that remain are the ones with their own
# annotation and provenance (_deferral_matched, _recurrence_demoted).
#
# Conservative by design: dedup_findings retains findings when the key cannot be
# computed (no diff window, no sha256 tool). Seen-file absent on first call is a
# no-op that seeds the file.
#
# Called only when CLAGENTIC_CROSS_ROUND_DEDUP=1. Not called on degraded envelopes
# (caller checks degraded state after this function returns).
_cross_round_dedup() {
  _crd_envelope="$1"
  _crd_diff="$2"
  _crd_seen="$3"

  # Absent seen-file: no prior keys; the pipeline populates it from this run.
  # The stage prints "BEFORE AFTER SEEN" counts on success; its exit status
  # says which step failed (10 key computation, 11 splice) and the original
  # findings are retained either way.
  _crd_rc=0
  # ints3 makes a stage that exits 0 with empty or odd output a failure here,
  # instead of letting it reach the arithmetic below unvalidated.
  _crd_counts=$(ds_findings_call -e ints3 dispositions cross-round "$_crd_envelope" \
    --diff "$_crd_diff" --seen "$_crd_seen") || _crd_rc=$?
  case "$_crd_rc" in
    0)
      set -- $_crd_counts
      _crd_before="$1"
      _crd_after="$2"
      _crd_seen_n="$3"
      # Within-run collapses (same key twice in one response) are the only
      # reduction left; prior-run findings are counted separately as seen.
      _crd_suppressed=$((_crd_before - _crd_after))
      [ "$_crd_suppressed" -lt 0 ] && _crd_suppressed=0
      if [ "$_crd_seen_n" -gt 0 ]; then
        printf '[dedup] %d finding(s) seen in prior run(s) kept and still counted toward the verdict\n' \
          "$_crd_seen_n" 1>&2
      fi
      ds_audit_log "review-dedup" "pass" \
        "collapsed:${_crd_suppressed}/total:${_crd_before} seen_before:${_crd_seen_n} mode:annotate"
      ;;
    11)
      # Conservative: splice failed, retain original findings.
      printf '[gates/review] cross-round dedup: splice failed — retaining all findings (conservative)\n' 1>&2
      cmd_log_run review warn "cross-round dedup: splice failed; original findings retained"
      ;;
    *)
      # Conservative: extraction or dedup failed, retain original findings.
      printf '[gates/review] cross-round dedup: key computation failed — retaining all findings (conservative)\n' 1>&2
      cmd_log_run review warn "cross-round dedup: key computation failed; original findings retained"
      ;;
  esac
}

# _review_recurrence_count ENVELOPE_FILE DIFF_FILE COUNTS_FILE
#
# Run AFTER _cross_round_dedup: records on each finding that survived it how
# many rounds that finding has now been reported in (_recurrence_count, keyed
# by the same content-hash key space dedup uses, kept in a separate counts
# file). INFORMATION ONLY: the count is shown by render-review and never
# changes whether a finding blocks. It used to demote a finding to advisory
# once it recurred; that was a way to stop a finding blocking that no operator
# had decided, and it is gone. A finding stays open until it is fixed or a
# disposition (.clagentic/dispositions.json) clears it (docs/GATES.md "The
# code verdict").
#
# Findings dedup kept only because an earlier run saw them (_seen_before) are
# not counted again, so a plain re-run does not inflate the count. A finding
# whose key cannot be computed is simply not counted; a failure leaves the
# envelope's findings as they were. Without python3 this is a passthrough.
_review_recurrence_count() {
  _rrc_envelope="$1"
  _rrc_diff="$2"
  _rrc_counts="$3"

  command -v python3 >/dev/null 2>&1 || return 0

  # The stage prints "none" when nothing was counted and "counted=N" otherwise.
  _rrc_result=$(ds_findings_call dispositions recurrence "$_rrc_envelope" \
    --diff "$_rrc_diff" --counts "$_rrc_counts") || return 0
  case "$_rrc_result" in
    counted=*) _rrc_count="${_rrc_result#counted=}" ;;
    *) return 0 ;;
  esac
  case "$_rrc_count" in ''|*[!0-9]*) _rrc_count=0 ;; esac
  ds_audit_log "review-recurrence" "pass" "counted:${_rrc_count}"
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
  ds_findings_call -e array ingest findings "$1" || printf '[]'
}

# _extract_findings_json_strict FILE — like _extract_findings_json, but FAIL
# CLOSED: a read, parse or tool failure (or no JSON tool at all) returns 1 with
# no output, never "[]". Both branches share one contract: an ABSENT .findings
# key is a genuine empty list and prints "[]"; a present array prints that
# array; a present non-array (null, object, string, number) returns 1, because
# a present-but-null key must not be read as a clean review. Used where "[]"
# would be written over real findings.
_extract_findings_json_strict() {
  ds_findings_call -e array ingest findings "$1" --strict || return 1
}

# _sanitize_review_findings_envelope FILE
#
# SECURITY (lr-66e598 follow-up, BOBBIE-caught). Reduces FILE's .findings
# array in place to EXACTLY the closed review-finding schema
# (ds_review_prompt, llm-client.sh: severity/file/line/category/message/
# evidence/suggestion) via _llm_json_array_allowlist_fields
# (scripts/platform.sh), DROPPING every other key -- including any gate-owned annotation
# (`_recurrence_count`, `disposition`, `fingerprint`, or any future
# `_`-prefixed control field) the MODEL ITSELF may have emitted in its raw
# JSON response.
#
# WHY THIS EXISTS: last-review.json is written directly from LLM output
# (llm-client.sh's `review` role) with no field allowlist anywhere on that
# write path -- validate_output (llm-client.sh) checks only that .findings
# is an array and that .severity, if present, is a legal enum value. Nothing
# stopped a model (compromised, manipulated by attacker-influenced code
# under review, or simply miscalibrated) from writing a field the gate code
# later reads as its own. No annotation decides a verdict any more (the
# exemption annotations are gone), but the strip stays the one choke point
# that makes "this field was written by the gate" true.
#
# THE FIX IS AT INGEST, THE SAME CHOKE-POINT PATTERN THIS CODEBASE ALREADY
# USES: _sanitize_adversarial_findings_json sanitizes immediately after
# _parse_adversarial_findings and before the sidecar is EVER written to
# disk (docs/GATES.md "Merge Gate", round-trip sanitization); ds_review_prompt
# allowlists deferrals.json before it is EVER interpolated into a prompt.
# This function is the equivalent choke point for review findings: it MUST
# run immediately after every raw LLM write to an envelope file (both the
# single-pass path and each per-chunk envelope in the chunked path, BEFORE
# merge_envelopes ever unions them -- merge_envelopes/dedup_findings are
# pure concatenation/dedup with no field validation of their own, so an
# unsanitized chunk would carry a forged field through the merge
# untouched), and BEFORE _cross_round_dedup, the code verdict or
# cmd_render_review ever read the file.
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
# FAIL CLOSED ON A STRIP FAILURE: a missing FILE is left alone (returns 0). If
# FILE exists but its findings cannot be read (unparseable, not an object, a
# tool failure) or the allowlist step or the write-back FAILS, the file still
# holds the model's raw findings, forged internal fields included, or would
# have them replaced by an empty list read as "no findings". Neither is left in
# place: the file is replaced with the degraded-envelope shape the chunk
# failure path already writes (`degraded: true`, empty findings) plus
# `sanitize_failed: true`. review_is_degraded then routes it down the
# INFRA_DEGRADED path, and _sanitize_review_for_prompt reads `sanitize_failed`
# as "source unavailable" so the Merge Gate gets the unavailable marker and
# review_degraded, not an empty findings list it could read as "no findings".
# The replacement is a printf literal, so it needs no JSON tool (the thing that
# may have failed).
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
  # The pipeline reduces the file in place, or replaces it with the degraded
  # stub on any failure. If the pipeline itself cannot run (or could not write
  # the stub), the file still holds the model's raw findings, so the stub is
  # written here too, with a printf literal that needs no tool. If even that
  # fails the raw findings must not be read as a review: return nonzero and let
  # the caller stop the gate.
  if ! ds_findings_call -e any ingest review-envelope "$_srfe_file"; then
    _review_envelope_mark_sanitize_failed "$_srfe_file" || return 1
  fi
  return 0
}

# _review_envelope_mark_sanitize_failed FILE — replace FILE with the degraded
# envelope that says its findings could not be reduced to the closed schema.
# Used when the raw model findings are still in FILE and cannot be cleaned.
# The write is a printf literal so it works with no JSON tool. When the write
# fails the file is removed; if it cannot be removed either, this returns 1:
# unsanitized findings are never left as the answer.
_review_envelope_mark_sanitize_failed() {
  if ! printf '%s\n' '{"degraded": true, "sanitize_failed": true, "summary": "[clagentic-lite degraded] review findings could not be sanitized", "checked": [], "findings": []}' > "$1" 2>/dev/null; then
    rm -f "$1" 2>/dev/null || :
    printf '[gates/review] review findings could not be sanitized and %s could not be replaced with the degraded stub; refusing to use it\n' "$1" 1>&2
    return 1
  fi
  printf '[gates/review] review findings could not be reduced to the closed schema; marked the envelope degraded\n' 1>&2
  return 0
}

# _invariant_feed_max_lines — line cap on invariants.json entries. Guards
# against unbounded growth: the invariant-feed exists to CATCH unbounded-growth
# findings, so its own storage must not be the thing that grows without bound.
# Configurable via CLAGENTIC_INVARIANT_FEED_MAX (default 200 — generous for a
# single branch's review lifetime; oldest entries are dropped first on cap).
_invariant_feed_max_lines() {
  ds_positive_int_or_warn CLAGENTIC_INVARIANT_FEED_MAX "${CLAGENTIC_INVARIANT_FEED_MAX:-}" 200
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
  fi
  # No python3 — cannot safely append (writing raw text risks corrupting
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

# _review_code_verdict ENVELOPE_FILE BASE_SHA
#
# The review gate's block decision. The envelope's findings are handed to the
# finding pipeline (findings.py evaluate), which adds them to this HEAD's
# accumulated findings and returns the code verdict for the review gate: the
# open blocking review findings, minus those a valid, already-merged
# disposition clears. Annotates the envelope's findings with their fingerprint
# and disposition. The verdict text goes to stderr.
#
# Sets _RCV_COMPUTED to 1 and _RCV_BLOCKERS to the number of open blocking
# findings when a verdict was computed. When none could be (the pipeline refused
# the input or could not run) _RCV_COMPUTED is 0 and _RCV_BLOCKERS is the
# sentinel 99, which is never a finding count: a verdict that was not computed
# is a block, never a pass. Callers decide through _review_verdict_blocks,
# which treats anything but a computed zero as a block. Always returns 0 so a
# caller under `set -e` reads the variables, not an exit status.
_review_code_verdict() {
  _rcv_env="$1"
  _rcv_base="$2"
  _rcv_rc=0
  _rcv_text=$(_gate_evaluate review "$_rcv_env" "$_rcv_base" gate --annotate "$_rcv_env") || _rcv_rc=$?
  [ -z "$_rcv_text" ] || printf '%s\n' "$_rcv_text" 1>&2
  _RCV_BLOCKERS=99
  _RCV_COMPUTED=0
  case "$_rcv_rc" in
    0) _RCV_BLOCKERS=0; _RCV_COMPUTED=1 ;;
    1)
      _rcv_n=${_rcv_text#VERDICT: BLOCKED (}
      _rcv_n=${_rcv_n%% *}
      case "$_rcv_n" in
        ''|*[!0-9]*) ;;
        0) ;;
        *) _RCV_BLOCKERS=$_rcv_n; _RCV_COMPUTED=1 ;;
      esac
      ;;
    *) printf '[gates/review] the code verdict could not be computed; treating the review as blocked\n' 1>&2 ;;
  esac
  return 0
}

# _review_verdict_blocks — success (block) unless _review_code_verdict computed
# a verdict with zero open blocking findings. An unset, empty or non-numeric
# count blocks: the old `${BLOCKERS:-0}` read the same states as a pass.
_review_verdict_blocks() {
  [ "${_RCV_COMPUTED:-}" = "1" ] || return 0
  case "${_RCV_BLOCKERS:-}" in ''|*[!0-9]*) return 0 ;; esac
  [ "$_RCV_BLOCKERS" -gt 0 ]
}

# _review_blocked_reason THRESHOLD log|say — what to record (log: the audit-row
# details) or print (say) about a blocked review. The sentinel is never
# printed as a finding count.
_review_blocked_reason() {
  if [ "${_RCV_COMPUTED:-}" != "1" ]; then
    printf 'the verdict could not be computed'
  elif [ "$2" = "log" ]; then
    printf '%s finding(s) at >= %s' "$_RCV_BLOCKERS" "$1"
  else
    printf "%s finding(s) at or above severity '%s'" "$_RCV_BLOCKERS" "$1"
  fi
}

cmd_review() {
  _gate_check_args review "--full-review --since-last-review --reset-dedup" "" "$@" || return 2
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

  # Per-run provenance state (see _review_run_provenance_fields). Reset every
  # run: `ship` calls cmd_review in the same process as other gates, and a
  # stale value from an earlier run must never be recorded against this one.
  _REVIEW_RUN_PROV_FILE=""
  _REVIEW_RUN_CHUNK_SIZES=""

  # --reset-dedup: delete the persisted seen-keys file (and the recurrence
  # counts file, which is derived from the same content-hash key space and
  # would otherwise still remember round counts from before the reset) and
  # exit. Operator calls this to clear cross-round dedup state (e.g. after a
  # major rebase or when they want the next review to re-report all findings
  # AND treat every finding as fresh, not "already reported N rounds").
  _crv_seen_file="$REPO_ROOT/.clagentic/lite/review-seen-keys"
  _crv_recurrence_file="$REPO_ROOT/.clagentic/lite/review-recurrence.json"
  if [ "$_crv_reset_dedup" = "1" ]; then
    # OUTCOME "skip", not "pass": --reset-dedup reviews nothing -- it
    # deletes local dedup state and returns immediately, never touching the
    # ledger. Logging it as "pass" was a third way (alongside the
    # empty-diff case below) to record a passing review verdict for a run
    # that examined zero diff content. "skip" is the same audit-vocabulary
    # cmd_sast's pre-existing semgrep-not-installed skip and the empty-diff
    # skip below already establish, not a new outcome invented for this
    # call site alone.
    if [ -f "$_crv_seen_file" ] || [ -f "$_crv_recurrence_file" ]; then
      rm -f "$_crv_seen_file" "$_crv_recurrence_file"
      echo "[gates/review] cross-round dedup state reset (review-seen-keys and review-recurrence.json deleted)"
      cmd_log_run review skip "cross-round dedup reset by --reset-dedup (recurrence counts cleared) -- no review performed"
    else
      echo "[gates/review] cross-round dedup state already empty (review-seen-keys and review-recurrence.json not found)"
      cmd_log_run review skip "cross-round dedup reset by --reset-dedup (files were absent) -- no review performed"
    fi
    return 0
  fi

  OUT="$REPO_ROOT/.clagentic/lite/last-review.json"

  # Collect the diff into a temp file so we can measure its size for the
  # chunking threshold check and pass it to split_diff without re-running git.
  # Capture get_review_diff's own stderr diagnostic alongside the diff so the
  # empty-diff check below can name the resolved range in its skip reason
  # without re-deriving it (get_review_diff already prints exactly which
  # range/mode it resolved on every path -- see its own printf lines).
  #
  # STATUS EXPLICITLY GUARDED (regression fix): get_review_diff returns
  # NONZERO on an unresolvable freshness precondition (branch baseline not
  # provably current -- see its own doc comment) and this call site must
  # still hard-fail on that per get_review_diff's own contract ("a caller
  # that does not explicitly guard the call aborts the gate"). Redirecting
  # its stderr to a file for the empty-diff reason below, without guarding
  # the exit status here, would let `set -e` abort the WHOLE SCRIPT at this
  # line before the `cat ... 1>&2` a few lines down ever ran -- silently
  # swallowing the exact diagnostic get_review_diff wrote, the opposite of
  # its own fail-loud contract. Capture the status explicitly and print the
  # captured stderr (then re-raise via `return 1`) rather than letting an
  # unguarded call's implicit `set -e` abort hide it.
  _crv_diff_tmp=$(mktemp -t clagentic-review-diff.XXXXXX)
  _crv_diff_reason_tmp=$(mktemp -t clagentic-review-diff-reason.XXXXXX)
  _crv_diff_status=0
  get_review_diff review > "$_crv_diff_tmp" 2>"$_crv_diff_reason_tmp" || _crv_diff_status=$?
  cat "$_crv_diff_reason_tmp" 1>&2
  if [ "$_crv_diff_status" -ne 0 ]; then
    rm -f "$_crv_diff_tmp" "$_crv_diff_reason_tmp"
    return 1
  fi
  _crv_diff_bytes=$(ds_file_size "$_crv_diff_tmp")

  # NO GATE MAY REPORT A VERDICT ON AN EMPTY INPUT -- the input-side half
  # of INV-1b/lr-7047bf that fix never implemented: that fix hardened only
  # "did the LLM run," never "was it given anything to examine". A zero-byte
  # resolved diff must never reach the LLM at all -- it is neither a clean
  # pass (nothing was examined) nor a block (nothing failed); it is SKIP,
  # named with the resolved-range diagnostic get_review_diff already wrote
  # to stderr above. Still records a ledger entry (gate=review, verdict
  # "skip") so a later branch state can be told apart from "review never
  # ran here at all," but a "skip" verdict can never satisfy
  # _ledger_anchored_pass_at_head/_ledger_latest_passing_head_for_branch's
  # "pass" filter -- an empty-diff round can never anchor a future delta or
  # satisfy the merge-gate's ledger check.
  if _gate_resolved_diff_is_empty "$_crv_diff_tmp"; then
    _crv_empty_reason=$(tail -n 1 "$_crv_diff_reason_tmp" 2>/dev/null)
    [ -n "$_crv_empty_reason" ] || _crv_empty_reason="resolved diff is empty"
    rm -f "$_crv_diff_reason_tmp"
    printf '{"degraded": false, "summary": "[clagentic-lite skip] no resolved diff to review: %s", "checked": [], "findings": []}\n' \
      "$(printf '%s' "$_crv_empty_reason" | tr -d '"\\')" > "$OUT"
    _review_sha=$(_git_repo_scoped_head_sha)
    if [ -n "$_review_sha" ]; then
      _stamp_envelope "$OUT" "$_review_sha"
    fi
    _crv_fetch_timeout=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC "${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-}" 30)
    _crv_base_sha=$(_resolve_base_sha "${CLAGENTIC_DEFAULT_BRANCH:-main}" "$_crv_fetch_timeout")
    cmd_log_run review skip "empty-resolved-diff: $_crv_empty_reason"
    printf '[gates/review] SKIP: %s — no findings can be reported on an empty input, this is not a pass\n' "$_crv_empty_reason" 1>&2
    _ledger_record_review_verdict review "$OUT" "$_crv_diff_tmp" "skip" "$_crv_base_sha" "$_review_sha"
    rm -f "$_crv_diff_tmp"
    return 0
  fi
  rm -f "$_crv_diff_reason_tmp"

  # llm-client.sh appends one provenance line per accepted call to this file
  # (CLAGENTIC_LLM_RUN_META_FILE). Removed by _ledger_record_review_verdict.
  _REVIEW_RUN_PROV_FILE=$(mktemp -t clagentic-review-prov.XXXXXX)

  # Chunking threshold: CLAGENTIC_REVIEWER_MAX_DIFF_KB (operator-facing alias,
  # in KB) takes precedence; CLAGENTIC_REVIEW_CHUNK_BYTES (in bytes) is the
  # secondary alias; default 262144 bytes (256 KB).
  # 0 or invalid falls back to the default for both keys: a 0-byte threshold
  # would chunk every diff into one LLM call per fragment.
  _crv_chunk_bytes=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_CHUNK_BYTES "${CLAGENTIC_REVIEW_CHUNK_BYTES:-}" 262144)
  # Unset is silent and yields 0 (no override); a set value of 0 or junk WARNs
  # and also yields 0, so the byte threshold above stays in force.
  _crv_max_diff_kb=$(ds_positive_int_or_warn CLAGENTIC_REVIEWER_MAX_DIFF_KB "${CLAGENTIC_REVIEWER_MAX_DIFF_KB:-}" 0)
  if [ "$_crv_max_diff_kb" -gt 0 ]; then
    _crv_chunk_bytes=$(( _crv_max_diff_kb * 1024 ))
  fi

  # Squash hint: warn the operator when the diff is large, before the chunking decision.
  # lr-e33f73: name CLAGENTIC_REVIEW_CHUNKING explicitly, not just "chunking" --
  # the incident behind this task was an operator on an install whose config
  # predates this key, who saw only the diff-size symptom and spent hours on
  # unrelated root causes before finding the variable by other means. Naming
  # the exact variable here directly shortens that path.
  if [ "$_crv_diff_bytes" -gt "$_crv_chunk_bytes" ]; then
    if [ "${CLAGENTIC_REVIEW_CHUNKING:-0}" = "1" ]; then
      printf '[gates/review] diff is %d bytes (threshold %d) — delta re-review (default) or squashing commits reduces review scope; chunked review will be used (CLAGENTIC_REVIEW_CHUNKING=1)\n' \
        "$_crv_diff_bytes" "$_crv_chunk_bytes" 1>&2
    else
      printf '[gates/review] diff is %d bytes (threshold %d) — delta re-review (default) or squashing commits reduces review scope; set CLAGENTIC_REVIEW_CHUNKING=1 in your global config to review very large diffs in chunks instead of failing/timing out\n' \
        "$_crv_diff_bytes" "$_crv_chunk_bytes" 1>&2
    fi
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
        _REVIEW_RUN_CHUNK_SIZES="${_REVIEW_RUN_CHUNK_SIZES:+$_REVIEW_RUN_CHUNK_SIZES }${_crv_cbytes}"
        CLAGENTIC_LLM_RUN_META_FILE="$_REVIEW_RUN_PROV_FILE" \
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
        if ! _sanitize_review_findings_envelope "$_crv_env_file"; then
          cmd_log_run review block "review envelope could not be sanitized or replaced; raw findings refused"
          rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
          rm -f "$_crv_diff_tmp"
          return 1
        fi
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
      _crv_fetch_timeout=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC "${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-}" 30)
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
        # Informational recurrence count (never changes a verdict) — see
        # _review_recurrence_count.
        _review_recurrence_count "$OUT" "$_crv_diff_tmp" "$_crv_recurrence_file"
        if [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ]; then
          _crv_live_findings=$(_extract_findings_json "$OUT")
          _invariant_feed_write review "$_crv_live_findings" "$_crv_diff_tmp" "$_crv_prior_seen_snap" "$_crv_seen_file"
        fi
        rm -f "$_crv_prior_seen_snap"
      fi

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
        _ledger_record_review_verdict review "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
        rm -f "$_crv_diff_tmp"
        rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
        return 2
      fi

      THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"
      _review_code_verdict "$OUT" "$_crv_base_sha"
      if _review_verdict_blocks; then
        cmd_log_run review block "review-blocked: $(_review_blocked_reason "$THRESHOLD" log)"
        echo "[gates/review] REVIEW_BLOCKED: $(_review_blocked_reason "$THRESHOLD" say)." 1>&2
        cmd_render_review "$OUT" 1>&2
        _ledger_record_review_verdict review "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
        rm -f "$_crv_diff_tmp"
        rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
        return 1
      fi
      _cmd_log_run_checked_pass review "0 findings at >= $THRESHOLD (chunked)"
      cmd_render_review "$OUT"
      _ledger_record_review_verdict review "$OUT" "$_crv_diff_tmp" "pass" "$_crv_base_sha" "$_review_sha"
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
  _REVIEW_RUN_CHUNK_SIZES="$_crv_diff_bytes"
  CLAGENTIC_LLM_RUN_META_FILE="$_REVIEW_RUN_PROV_FILE" \
    "$TOOL_HOME/scripts/llm-client.sh" review < "$_crv_diff_tmp" > "$OUT" || _crv_review_status=$?
  # Note: _crv_diff_tmp is NOT deleted yet — cross-round dedup needs it below.

  # SECURITY (lr-66e598 follow-up): strip every finding to the closed
  # review-finding schema IMMEDIATELY after the raw LLM write and BEFORE
  # anything else (stamp, dedup, recurrence, severity_blockers,
  # cmd_render_review) ever reads $OUT. See _sanitize_review_findings_envelope's
  # own doc comment for the full rationale — this is the choke point that
  # closes the self-exempting-suppression gap a raw, unallowlisted model
  # finding could otherwise use.
  if ! _sanitize_review_findings_envelope "$OUT"; then
    cmd_log_run review block "review envelope could not be sanitized or replaced; raw findings refused"
    rm -f "$_crv_diff_tmp"
    return 1
  fi

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
  _crv_fetch_timeout=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC "${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-}" 30)
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
    # Informational recurrence count — see the chunked-path comment above.
    _review_recurrence_count "$OUT" "$_crv_diff_tmp" "$_crv_recurrence_file"
    if [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ]; then
      _crv_live_findings=$(_extract_findings_json "$OUT")
      _invariant_feed_write review "$_crv_live_findings" "$_crv_diff_tmp" "$_crv_prior_seen_snap" "$_crv_seen_file"
    fi
    rm -f "$_crv_prior_seen_snap"
  fi

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
    _ledger_record_review_verdict review "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
    rm -f "$_crv_diff_tmp"
    return 2
  fi
  # Code verdict: open blocking findings (accumulated at this HEAD, minus the
  # ones a merged disposition clears) at or above the configured threshold.
  THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"
  _review_code_verdict "$OUT" "$_crv_base_sha"
  if _review_verdict_blocks; then
    cmd_log_run review block "review-blocked: $(_review_blocked_reason "$THRESHOLD" log)"
    echo "[gates/review] REVIEW_BLOCKED: $(_review_blocked_reason "$THRESHOLD" say)." 1>&2
    cmd_render_review "$OUT" 1>&2
    _ledger_record_review_verdict review "$OUT" "$_crv_diff_tmp" "block" "$_crv_base_sha" "$_review_sha"
    rm -f "$_crv_diff_tmp"
    return 1
  fi
  _cmd_log_run_checked_pass review "0 findings at >= $THRESHOLD"
  cmd_render_review "$OUT"
  _ledger_record_review_verdict review "$OUT" "$_crv_diff_tmp" "pass" "$_crv_base_sha" "$_review_sha"
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
  # A genuine read failure is signalled on the return channel (nonzero, no
  # stdout), never as an empty array: a readable file with zero [FINDING]
  # headers is an ordinary clean audit and prints "[]" with status 0, and the
  # two must not be the same bytes. Without python3 the parse cannot run at
  # all, which is the same failure, so it is signalled the same way.
  ds_findings_call -e array ingest adversarial-parse "$1"
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
  # (platform.sh) -- this function used to carry its own duplicated jq/python3
  # decompose-sanitize-rebuild loop; that loop is now the shared machinery
  # a second caller (the deferrals array, ds_review_prompt in llm-client.sh)
  # reuses instead of hand-rolling a variant. Every finding's
  # file/category/message field is sanitized via _llm_field_sanitize.
  # FAIL CLOSED: on any failure this returns 1 with no output, never the
  # unsanitized input; cmd_adversarial turns that into a degraded sidecar.
  _llm_json_array_sanitize_fields_strict "$_safj_json" file category message
}

# The adversarial audit's findings are added to HEAD's accumulated set (the
# code verdict). When that cannot be done, a marker naming HEAD is left and the
# merge gate refuses while it matches HEAD; a later successful record removes
# it. The stamp the marker is written with and the stamp the merge gate
# compares it to come from the one function below, so the two cannot drift
# apart and leave a refusal that never fires.
#
# Exit status of cmd_adversarial (and of _adv_record_findings) when the
# findings could not be recorded and the marker could not be written either:
# nothing then makes the merge gate refuse, so the run itself fails loudly.
_ADV_UNRECORDED_RC=4

_adv_unrecorded_marker_path() {
  printf '%s/.clagentic/lite/adversarial-unrecorded' "$REPO_ROOT"
}

_adv_unrecorded_stamp() {
  _git_repo_scoped_head_sha
}

# Success when an unrecorded-findings marker for the current HEAD stands. A
# marker that cannot be read counts as standing: not knowing is a refusal.
_adv_unrecorded_pending() {
  _aup_marker=$(_adv_unrecorded_marker_path)
  [ -f "$_aup_marker" ] || return 1
  _aup_have=$(cat "$_aup_marker") || return 0
  [ "$_aup_have" = "$(_adv_unrecorded_stamp)" ]
}

_adv_unrecorded_mark() {
  _aum_stamp=$(_adv_unrecorded_stamp)
  printf '%s\n' "$_aum_stamp" > "$(_adv_unrecorded_marker_path)"
}

# _adv_record_findings FINDINGS_FILE BASE_SHA [quiet]
#
# Records FINDINGS_FILE (the audit's structured findings; an empty audit is a
# run on record with no findings) in the code verdict. Returns 0 when recorded,
# or when it was not but the marker now makes the merge gate refuse; returns
# _ADV_UNRECORDED_RC when neither could be done. The verdict text goes to
# stderr unless "quiet".
_adv_record_findings() {
  _arf_file="$1"
  _arf_base="$2"
  _arf_quiet="${3:-}"
  _arf_rc=0
  _arf_text=$(_gate_evaluate adversarial "$_arf_file" "$_arf_base" gate) || _arf_rc=$?
  case "$_arf_rc" in
    0|1)
      if [ -z "$_arf_quiet" ] && [ -n "$_arf_text" ]; then
        printf '%s\n' "$_arf_text" 1>&2
      fi
      rm -f "$(_adv_unrecorded_marker_path)"
      return 0
      ;;
  esac
  if _adv_unrecorded_mark; then
    cmd_log_run adversarial warn "adversarial findings could not be recorded for the code verdict (status=$_arf_rc); the merge gate will refuse"
    echo "[gates/adversarial] WARN: adversarial findings could not be recorded for the code verdict; the merge gate will refuse until this is fixed." 1>&2
    return 0
  fi
  cmd_log_run adversarial block "adversarial findings could not be recorded (status=$_arf_rc) and the unrecorded marker could not be written; nothing will make the merge gate refuse"
  echo "[gates/adversarial] ERROR: adversarial findings could not be recorded for the code verdict, and the marker that makes the merge gate refuse could not be written either. Fix the write access to $(_adv_unrecorded_marker_path) and re-run gates adversarial." 1>&2
  return "$_ADV_UNRECORDED_RC"
}

cmd_adversarial() {
  _gate_check_args adversarial "--full-review" "" "$@" || return 2
  # --full-review: gates.sh's dispatcher now forwards argv
  # to this function (previously a bare `cmd_adversarial ;;` with no shift/
  # "$@" -- a documented, accepted flag was silently discarded, producing a
  # confident "I forced a full audit" that was false). Parsed the same way
  # cmd_review parses it: sets/exports REVIEW_FULL=1, which get_review_diff
  # reads to skip the ledger-anchored delta and use the full branch-diff-
  # against-default (or staged-diff) path instead.
  REVIEW_FULL=0
  for _adv_arg in "$@"; do
    case "$_adv_arg" in
      --full-review) REVIEW_FULL=1 ;;
    esac
  done
  export REVIEW_FULL

  OUT="$REPO_ROOT/.clagentic/lite/last-adversarial.md"
  FINDINGS_OUT="$REPO_ROOT/.clagentic/lite/last-adversarial-findings.json"
  _adv_diff_tmp=$(mktemp -t clagentic-adv-diff.XXXXXX)
  # GATE-SCOPED ANCHOR: "adversarial" gives this call its
  # own ledger anchor namespace -- get_review_diff's delta-base lookup now
  # filters on gate, so a review pass recorded moments earlier at HEAD (the
  # normal cmd_ship order: review, then adversarial, in the same process)
  # can never anchor THIS call's delta and collapse it to HEAD..HEAD.
  #
  # STATUS EXPLICITLY GUARDED (same regression fix as cmd_review's own
  # get_review_diff call site -- see its comment for the full rationale):
  # get_review_diff returns nonzero on an unresolvable freshness
  # precondition and must still hard-fail here; redirecting its stderr to a
  # file without guarding the exit status would let `set -e` abort before
  # the `cat ... 1>&2` below ever ran, silently swallowing the diagnostic.
  _adv_diff_reason_tmp=$(mktemp -t clagentic-adv-diff-reason.XXXXXX)
  _adv_diff_status=0
  get_review_diff adversarial > "$_adv_diff_tmp" 2>"$_adv_diff_reason_tmp" || _adv_diff_status=$?
  cat "$_adv_diff_reason_tmp" 1>&2
  if [ "$_adv_diff_status" -ne 0 ]; then
    rm -f "$_adv_diff_tmp" "$_adv_diff_reason_tmp"
    return 1
  fi
  # NO GATE MAY REPORT A VERDICT ON AN EMPTY INPUT -- the input-side half
  # of INV-1b/lr-7047bf that fix never implemented; see that fix's own
  # comment two lines below, which guards only whether the auditor RAN,
  # never whether it was GIVEN ANYTHING. Before this check, cmd_adversarial
  # handed an empty diff straight to the auditor exactly like a non-empty
  # one -- the auditor "examined" zero bytes, wrote zero [FINDING] headers,
  # and this function reported it identically to a genuine clean pass
  # ("warn", exit 0). A zero-byte resolved diff must short-circuit BEFORE
  # the LLM call: it is neither a clean pass (nothing was examined) nor a
  # degraded run (the auditor never got the chance to fail) -- it is SKIP,
  # named with get_review_diff's own resolved-range diagnostic (captured
  # to stderr above). Still records a ledger entry (gate=adversarial,
  # verdict "skip") so a later branch state can be told apart from
  # "adversarial never ran here at all," but a "skip" verdict can never
  # satisfy _ledger_latest_passing_head_for_branch's "pass" filter -- an
  # empty-diff round can never anchor a future adversarial delta either.
  if _gate_resolved_diff_is_empty "$_adv_diff_tmp"; then
    _adv_empty_reason=$(tail -n 1 "$_adv_diff_reason_tmp" 2>/dev/null)
    [ -n "$_adv_empty_reason" ] || _adv_empty_reason="resolved diff is empty"
    rm -f "$_adv_diff_reason_tmp"
    printf '[clagentic-lite skip] no resolved diff to audit: %s\n' "$_adv_empty_reason" > "$OUT"
    _adv_sha=$(_git_repo_scoped_head_sha)
    if [ -n "$_adv_sha" ]; then
      _adv_tmp=$(mktemp -t clagentic-adv-stamp.XXXXXX)
      printf '<!-- clagentic-diff-sha: %s -->\n' "$_adv_sha" > "$_adv_tmp"
      cat "$OUT" >> "$_adv_tmp"
      mv "$_adv_tmp" "$OUT"
    fi
    printf '[]' > "$FINDINGS_OUT"
    printf '{"dropped_count": 0, "total_before_cap": 0}\n' > "$REPO_ROOT/.clagentic/lite/last-adversarial-findings-meta.json"
    cmd_log_run adversarial skip "empty-resolved-diff: $_adv_empty_reason"
    printf '[gates/adversarial] SKIP: %s — no findings can be reported on an empty input, this is not a clean pass\n' "$_adv_empty_reason" 1>&2
    _adv_fetch_timeout=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC "${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-}" 30)
    _adv_base_sha=$(_resolve_base_sha "${CLAGENTIC_DEFAULT_BRANCH:-main}" "$_adv_fetch_timeout")
    # An empty audit is still a run on record (with no findings), so the merge
    # gate's "an adversarial run is on record" requirement holds for it. A
    # failure to record it is handled exactly as on the main path: a marker
    # that makes the merge gate refuse, or a hard error when that fails too.
    _adv_record_rc=0
    _adv_record_findings "$FINDINGS_OUT" "$_adv_base_sha" quiet || _adv_record_rc=$?
    if [ "$_adv_record_rc" -ne 0 ]; then
      rm -f "$_adv_diff_tmp"
      return "$_adv_record_rc"
    fi
    _ledger_record_review_verdict adversarial "$OUT" "$_adv_diff_tmp" "skip" "$_adv_base_sha" "$_adv_sha"
    rm -f "$_adv_diff_tmp"
    cat "$OUT"
    return 0
  fi
  rm -f "$_adv_diff_reason_tmp"
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
  # A sanitize failure must not write raw findings (the sidecar feeds the
  # merge-gate prompt) and must not look like "no findings" either: the
  # sidecar holds an empty array and the meta sidecar below carries
  # findings_degraded, which build_gate_summary turns into the unavailable
  # marker plus adversarial_report_degraded.
  _adv_findings_degraded=false
  if _adv_findings_json_sanitized=$(_sanitize_adversarial_findings_json "$_adv_findings_json_raw") \
      && [ -n "$_adv_findings_json_sanitized" ]; then
    :
  else
    _adv_findings_degraded=true
    _adv_findings_json_sanitized='[]'
    cmd_log_run adversarial warn "adversarial findings could not be sanitized; sidecar marked degraded (merge gate treats the source as unavailable)"
    echo "[gates/adversarial] WARN: adversarial findings could not be sanitized; the merge gate will treat this source as unavailable." 1>&2
  fi
  _adv_findings_json_sorted=$(_adversarial_findings_sort_blocking_first "$_adv_findings_json_sanitized")
  # 0 would slice every finding away; resolved once here so the cap and the
  # dropped-count message below name the same effective value.
  _adv_findings_max=$(ds_positive_int_or_warn CLAGENTIC_ADVERSARIAL_FINDINGS_MAX "${CLAGENTIC_ADVERSARIAL_FINDINGS_MAX:-}" 200)
  _adv_findings_json=$(_llm_json_array_cap "$_adv_findings_json_sorted" "$_adv_findings_max")
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
  # A count that cannot be taken must not read as "nothing was dropped": the
  # sidecar is then marked findings_degraded, which the merge gate treats as an
  # unavailable source.
  _adv_findings_total_before_cap=$(ds_findings_call -t "$_adv_findings_json_sorted" -e int ingest length) \
    || _adv_findings_total_before_cap=""
  _adv_findings_total_after_cap=$(ds_findings_call -t "$_adv_findings_json" -e int ingest length) \
    || _adv_findings_total_after_cap=""
  if [ -z "$_adv_findings_total_before_cap" ] || [ -z "$_adv_findings_total_after_cap" ]; then
    _adv_findings_degraded=true
    _adv_findings_total_before_cap=0
    _adv_findings_total_after_cap=0
    cmd_log_run adversarial warn "adversarial findings could not be counted; sidecar marked degraded (merge gate treats the source as unavailable)"
    echo "[gates/adversarial] WARN: adversarial findings could not be counted; the merge gate will treat this source as unavailable." 1>&2
  fi
  if [ "$_adv_findings_total_before_cap" -gt "$_adv_findings_total_after_cap" ]; then
    _adv_findings_dropped_count=$((_adv_findings_total_before_cap - _adv_findings_total_after_cap))
  fi
  printf '{"dropped_count": %d, "total_before_cap": %d, "findings_degraded": %s}\n' \
    "$_adv_findings_dropped_count" "$_adv_findings_total_before_cap" "$_adv_findings_degraded" \
    > "$REPO_ROOT/.clagentic/lite/last-adversarial-findings-meta.json"
  if [ "$_adv_findings_dropped_count" -gt 0 ]; then
    cmd_log_run adversarial warn "adversarial findings count cap dropped $_adv_findings_dropped_count finding(s) (severity/tier-sorted before cap, so only the least-severe tail was dropped)"
    printf '[gates/adversarial] %d finding(s) dropped by the count cap (CLAGENTIC_ADVERSARIAL_FINDINGS_MAX=%s) -- lowest severity/advisory-tier findings only, sorted before truncation.\n' \
      "$_adv_findings_dropped_count" "$_adv_findings_max" 1>&2
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

  # base_sha for the ledger entry -- same provably-current resolution
  # cmd_review's own ledger write uses (see _resolve_base_sha's own doc
  # comment).
  _adv_fetch_timeout=$(ds_positive_int_or_warn CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC "${CLAGENTIC_REVIEW_FETCH_TIMEOUT_SEC:-}" 30)
  _adv_base_sha=$(_resolve_base_sha "${CLAGENTIC_DEFAULT_BRANCH:-main}" "$_adv_fetch_timeout")

  # Record this run's findings in the HEAD's accumulated set. The audit stays
  # non-blocking here (a hostile-user narrative is not a pass/fail gate), but
  # an open blocking finding is not forgotten: the merge gate's code verdict
  # is the union of every review and adversarial run at this HEAD, so a
  # reachable high-impact finding blocks the merge there until it is fixed or a
  # merged disposition clears it. Skipped when no real audit happened. A failure
  # to record is not silent: it leaves a marker naming this HEAD, and the merge
  # gate refuses while the marker matches HEAD (a later successful run removes
  # it).
  if [ "$_adv_degraded" -ne 1 ] && [ "$_adv_findings_degraded" != "true" ]; then
    _adv_record_rc=0
    _adv_record_findings "$FINDINGS_OUT" "$_adv_base_sha" || _adv_record_rc=$?
    if [ "$_adv_record_rc" -ne 0 ]; then
      rm -f "$_adv_diff_tmp"
      return "$_adv_record_rc"
    fi
  fi

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
    # Degraded: no real audit was reached -- recorded as "block" (never
    # readable as a passing anchor), same doctrine cmd_review's own
    # degraded exits already use for the review ledger.
    _ledger_record_review_verdict adversarial "$OUT" "$_adv_diff_tmp" "block" "$_adv_base_sha" "$_adv_sha"
    rm -f "$_adv_diff_tmp"
    cat "$OUT"
    return 2
  fi
  cmd_log_run adversarial warn "wrote $OUT (non-blocking)"
  _ledger_record_review_verdict adversarial "$OUT" "$_adv_diff_tmp" "pass" "$_adv_base_sha" "$_adv_sha"
  rm -f "$_adv_diff_tmp"
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
# used by dedup_findings for the exact same
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

# _mg_summary_stale_flag SUMMARY_FILE — print "true" when the gate summary is
# the minimal stale-payload envelope build_gate_summary emits, else "false".
_mg_summary_stale_flag() {
  _mssf_out=""
  if command -v jq >/dev/null 2>&1; then
    _mssf_out=$(jq -r '.stale_payload // "false"' "$1" 2>/dev/null || echo "false")
  elif command -v python3 >/dev/null 2>&1; then
    _mssf_out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(str(d.get("stale_payload","false")).lower())' "$1" 2>/dev/null || echo "false")
  fi
  printf '%s' "${_mssf_out:-false}"
}

# _mg_stale_report SUMMARY_FILE
#
# Turns a stale-payload gate summary into the operator-facing refusal. Sets
#   _MG_STALE_PRIMARY  the one reason that decides the headline
#   _MG_STALE_TEXT     refusal text (also the "reason" in last-merge-gate.json)
#   _MG_STALE_AUDIT    audit-trail detail
# The reasons are build_gate_summary's closed set; each gets its own wording
# because the right next step differs: sha_mismatch / missing_stamp / empty_head
# mean the gate output does not describe HEAD, so re-running is the fix, while
# review_blocked_at_head means the review ran at HEAD and BLOCKED, so
# re-running cannot help and the findings are listed instead. A summary with no
# reason fields (older envelope, no JSON tool) reads as sha_mismatch, the one
# cause the old single message described.
_mg_stale_report() {
  # The classification and wording live in the finding pipeline (findings.py
  # render stale-report), which prints PRIMARY, TEXT and AUDIT separated by the
  # ASCII unit separator (the free text never contains one: control bytes are
  # stripped from every finding field before it is listed).
  _msr_us=$(printf '\037')
  _msr_rc=0
  _msr_out=$(ds_findings_call render stale-report "$1") || _msr_rc=$?
  if [ "$_msr_rc" -ne 0 ] || [ -z "$_msr_out" ]; then
    # Could not classify: refuse with the one reason that is always true, and
    # name the real cause rather than assuming one.
    case "$_msr_rc" in
      127) _msr_cause="python3 is not installed" ;;
      126) _msr_cause="the finding pipeline file findings.py was not found" ;;
      0) _msr_cause="the stale-report stage produced no output" ;;
      *) _msr_cause="the stale-report stage failed with status $_msr_rc" ;;
    esac
    _MG_STALE_PRIMARY="missing_stamp"
    _MG_STALE_TEXT="the stale gate payload could not be classified: ${_msr_cause}; re-run clagentic-lite gates review and gates adversarial first."
    _MG_STALE_AUDIT="stale payload [missing_stamp]: could not classify (${_msr_cause})"
    return 0
  fi
  IFS="$_msr_us" read -r _MG_STALE_PRIMARY _MG_STALE_TEXT _MG_STALE_AUDIT <<EOF
$_msr_out
EOF
}

# _mg_refuse_stale SUMMARY_FILE OUT_FILE GATE_NAME
#
# The one deterministic stale-payload refusal (no LLM call, no token burn),
# shared by the normal and --recheck paths so the two cannot word the same
# cause differently. Returns 1 (refuse) unless CLAGENTIC_MERGE_GATE_BLOCKING=0.
_mg_refuse_stale() {
  _mrs_summary="$1"
  _mrs_out="$2"
  _mrs_gate="$3"
  _mg_stale_report "$_mrs_summary"
  printf '{"decision": "refuse", "stale_reason": "%s", "reason": "%s"}\n' \
    "$_MG_STALE_PRIMARY" "$(ds_json_escape "$_MG_STALE_TEXT")" > "$_mrs_out"
  cmd_log_run "$_mrs_gate" block "$_MG_STALE_AUDIT"
  printf '[gates/merge-gate] REFUSED (%s): %s\n' "$_MG_STALE_PRIMARY" "$_MG_STALE_TEXT" 1>&2
  cat "$_mrs_out"
  if [ "${CLAGENTIC_MERGE_GATE_BLOCKING:-1}" != "0" ]; then
    return 1
  fi
  return 0
}

# _mg_refuse_code REASON VERDICT_TEXT GATE_NAME
#
# The deterministic refusal for a code verdict that is BLOCKED, or that could
# not be computed (no model call, no token burn). Writes last-merge-gate.json,
# prints the verdict text (with, for each open finding, the exact disposition
# stanza that would clear it) and returns 1 unless
# CLAGENTIC_MERGE_GATE_BLOCKING=0, like every other refusal here.
_mg_refuse_code() {
  _mrc_reason="$1"
  _mrc_text="$2"
  _mrc_gate="$3"
  printf '{"decision": "refuse", "code_verdict": "BLOCKED", "reason": "%s"}\n' \
    "$(ds_json_escape "$_mrc_reason")" > "$OUT"
  cmd_log_run "$_mrc_gate" block "code verdict BLOCKED: $_mrc_reason"
  [ -z "$_mrc_text" ] || printf '%s\n' "$_mrc_text" 1>&2
  printf '[gates/merge-gate] REFUSED (code verdict): %s\n' "$_mrc_reason" 1>&2
  cat "$OUT"
  if [ "${CLAGENTIC_MERGE_GATE_BLOCKING:-1}" != "0" ]; then
    return 1
  fi
  return 0
}

cmd_merge_gate() {
  _gate_check_args merge-gate "--recheck" "" "$@" || return 2
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
          # A cached pass does not outlive an adversarial run at this state
          # whose findings could not be recorded: that falls through to the
          # full path, which refuses on the marker.
          if [ "$_mg_cached_outcome" = "pass" ] && ! _adv_unrecorded_pending; then
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

    # The summary on disk may itself be the stale-payload envelope an earlier
    # run wrote. It carries no review_sha, so the SHA guard below would report
    # that as a missing stamp whatever the real cause was (a review blocked at
    # HEAD, say). Refuse with the reason the envelope recorded instead.
    if [ "$(_mg_summary_stale_flag "$IN")" = "true" ]; then
      _mg_refuse_stale "$IN" "$OUT" "merge-gate recheck"
      return $?
    fi

    # SHA-staleness guard: --recheck is for retrying a transient LLM failure,
    # not for replaying an old summary against a new commit. Read the SHA
    # stamped inside gate-summary.json (review_sha, lifted from the review's
    # _clagentic_diff_sha by build_gate_summary; a summary written before
    # review_sha existed still carries it under review._clagentic_diff_sha,
    # which is read as a fallback) and compare it to HEAD. Refuse
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
        _mg_summary_sha=$(jq -r '.review_sha // .review._clagentic_diff_sha // ""' "$IN" 2>/dev/null || echo "")
      elif command -v python3 >/dev/null 2>&1; then
        _mg_summary_sha=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    rv = d.get("review") or {}
    print(d.get("review_sha") or rv.get("_clagentic_diff_sha", ""))
except Exception:
    print("")
' "$IN" 2>/dev/null || echo "")
      fi
      if [ -z "$_mg_summary_sha" ]; then
        printf '[gates/merge-gate] --recheck refused: gate-summary.json carries no review SHA stamp (HEAD is %s), so it cannot be matched to this commit. Run '"'"'gates review'"'"' then '"'"'gates merge-gate'"'"', or '"'"'gates ship'"'"' to rebuild.\n' \
          "$_mg_head_sha" 1>&2
        cmd_log_run "merge-gate recheck" block "stale payload [missing_stamp]: gate-summary.json has no review SHA stamp, head=${_mg_head_sha}"
        return 1
      fi
      if [ "$_mg_summary_sha" != "$_mg_head_sha" ]; then
        printf '[gates/merge-gate] --recheck refused: gate-summary.json is for %s, HEAD is %s. Run '"'"'gates review'"'"' then '"'"'gates merge-gate'"'"', or '"'"'gates ship'"'"' to rebuild.\n' \
          "$_mg_summary_sha" "$_mg_head_sha" 1>&2
        cmd_log_run "merge-gate recheck" block "stale payload [sha_mismatch]: SHA mismatch: summary=${_mg_summary_sha} head=${_mg_head_sha}"
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
    printf '{"decision": "refuse", "reason": "gate summary could not be built (python3 not available) — install python3 to run the merge gate"}\n' > "$OUT"
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
  if [ "$(_mg_summary_stale_flag "$IN")" = "true" ]; then
    _mg_refuse_stale "$IN" "$OUT" "$_mg_gate_name"
    return $?
  fi

  # CODE VERDICT. The block decision is made here, in code, before any model
  # is consulted: every review and adversarial run at this HEAD has been added
  # to one accumulated set, and the open blocking findings in it, minus those a
  # valid already-merged disposition clears, decide. A BLOCKED code verdict is
  # final; the merge-gate model is never called and could not change it. On a
  # PASS the model receives the verdict and the applied dispositions in the
  # payload (code_verdict) and may only ADD a refusal. A verdict that cannot be
  # computed refuses: the merge gate does not run without one.
  if _adv_unrecorded_pending; then
    _mg_refuse_code "the adversarial findings at this HEAD could not be recorded, so the code verdict is incomplete; re-run gates adversarial" "" "$_mg_gate_name"
    return $?
  fi
  _mg_cv_json="$REPO_ROOT/.clagentic/lite/code-verdict.json"
  _mg_cv_timeout=$(ds_positive_int_or_warn CLAGENTIC_MERGE_GATE_FETCH_TIMEOUT_SEC "${CLAGENTIC_MERGE_GATE_FETCH_TIMEOUT_SEC:-}" 30)
  _mg_cv_base=$(_resolve_base_sha "${CLAGENTIC_DEFAULT_BRANCH:-main}" "$_mg_cv_timeout")
  _mg_cv_rc=0
  _mg_cv_text=$(_gate_evaluate merge-gate "" "$_mg_cv_base" head --attach-to "$IN" --json-out "$_mg_cv_json") || _mg_cv_rc=$?
  case "$_mg_cv_rc" in
    0) [ -z "$_mg_cv_text" ] || printf '%s\n' "$_mg_cv_text" 1>&2 ;;
    1)
      _mg_cv_n=${_mg_cv_text#VERDICT: BLOCKED (}
      _mg_cv_n=${_mg_cv_n%% *}
      case "$_mg_cv_n" in ''|*[!0-9]*) _mg_cv_n="" ;; esac
      _mg_refuse_code "${_mg_cv_n:-some} open blocking finding(s) at this HEAD; the code verdict is BLOCKED" "$_mg_cv_text" "$_mg_gate_name"
      return $?
      ;;
    *)
      _mg_refuse_code "the code verdict could not be computed; the merge gate does not run without one" "" "$_mg_gate_name"
      return $?
      ;;
  esac

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
      # The findings a disposition cleared are recorded in the audit trail from
      # the code verdict, not from anything the model wrote: they are the
      # artifact reviewers read.
      _mg_cleared=""
      if [ -f "$_mg_cv_json" ]; then
        _mg_cleared=$(ds_findings_call -s -e any render cleared-summary < "$_mg_cv_json" 2>/dev/null) || _mg_cleared=""
      fi
      _cmd_log_run_checked_pass "$_mg_gate_name" "approve${_mg_cleared:+ ($_mg_cleared)}$_mg_class_suffix$_mg_state_suffix"
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
  # The one ranking table lives in findings.py; an unavailable pipeline ranks
  # the name 0 (unknown), which every caller reads as 'use the default'.
  ds_findings_call -e int verdict rank "$1" || echo 0
}

# ISSUE_CLASS / CLASS_FIX (lr-3eb18c): deliberately NOT read anywhere in
# this function. issue_class/class_fix are mandatory-but-non-blocking by
# design (presence is enforced by validate_output, scripts/llm-client.sh) --
# an unresolved class escalation must never become a new way to gate /ship.
# Do not add either field to this function's selection logic.
severity_blockers() {
  # The raw count of findings at or above THRESHOLD in one review file, before
  # accumulation and before any disposition: a diagnostic. The gates decide
  # with the code verdict (_review_code_verdict / findings.py evaluate), not
  # with this number.
  #
  # Parse-failure policy: ALWAYS fail closed. The sentinel value 99 trips the
  # caller's `> 0` block check unambiguously, and makes the audit-row message
  # ("99 finding(s) at >= high") visibly unusual, so users know this is
  # "blocked because the gate couldn't read the review" rather than a model
  # that legitimately found 99 issues. The count itself, the severity ranking
  # (a severity that is not a known rank name cannot be ranked and counts as
  # blocking; known names are matched case-insensitively after stripping) and
  # the unknown-threshold default of 'high' live in findings.py verdict
  # blockers. A missing python3 is the same unreadable-review case.
  _sb_out=$(ds_findings_call -e int verdict blockers "$1" "$2") || _sb_out=""
  if [ -z "$_sb_out" ]; then echo 99; else echo "$_sb_out"; fi
}

# _blocking_findings_json THRESHOLD — read a JSON object with a .findings array
# on stdin and print, as compact JSON, the findings severity_blockers would
# count at THRESHOLD, reduced to {file, line, severity, message}, leaving out
# a finding the review's verdict recorded as cleared by a disposition, so the
# list a refusal shows is the set that blocked. Control bytes are stripped from
# the free text and message is capped:
# the text is model-authored and ends up on a terminal. Prints "null" (not "[]",
# which would read as "nothing blocked") when no JSON tool exists or the input
# is unreadable, never a partial list; _mg_stale_report renders null as "could
# not be listed".
# A non-string, non-null severity cannot be ranked, so it counts as blocking
# (rank 4): the same fail-closed reading severity_blockers applies, which keeps
# the list equal to the set that blocked.
_blocking_findings_json() {
  _bfj_out=$(ds_findings_call -s -e array_or_null verdict blocking-json "$1") || _bfj_out=""
  [ -n "$_bfj_out" ] || _bfj_out="null"
  printf '%s' "$_bfj_out"
  return 0
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
  # A failure returns nonzero with no output. It is never an empty string
  # literal a caller could mistake for "no findings", and never a literal
  # appended to whatever the stage printed before it failed.
  ds_findings_call -t "$1" -e string render fence-findings
}

# _fence_deterministic_gates JSON_OBJECT — render an (already sanitized)
# deterministic_gates JSON object as a JSON string value, human-readable and
# wrapped in the ===BEGIN/END DETERMINISTIC GATES DATA=== fence
# ds_merge_gate_prompt (llm-client.sh) instructs the Merge Gate to treat as
# data, not instructions (lr-92d931, settling the convention question
# lr-367a21 left open: every external-text payload field reaching an LLM
# prompt is BOTH sanitized AND fenced — deterministic_gates.details was
# sanitized via _llm_field_sanitize at lr-367a21 but never fenced; this
# closes that divergence). Mirrors _fence_adversarial_findings's own
# ===BEGIN/END ADVERSARIAL FINDINGS DATA=== fence and
# ds_adversarial_prompt's ===BEGIN/END INVARIANTS DATA=== fence for the
# equivalent round-trip shape. Assumes the input is already sanitized
# (_read_deterministic_gates below calls _llm_field_sanitize on each gate's
# "details" field before this is ever called) — this function only renders
# and fences, it does not sanitize a second time. "outcome" is never
# sanitized upstream (closed 4-value set, not free text) and is fenced here
# unchanged along with everything else in the object — fencing applies to
# the payload field as a whole, not per-subfield, matching how
# adversarial_findings_fenced fences its whole array rather than
# re-selecting only the free-text subfields within each entry.
#
# TRAILING-NEWLINE PARITY (lr-92d931): unlike _fence_adversarial_findings
# (which is only ever exercised from the emitter branch matching its own
# jq/python3 availability, so its two internal paths never have to agree
# byte-for-byte with each other), build_gate_summary's python3 branch below
# calls THIS function directly to compute deterministic_gates_fenced even
# though the caller itself is in the jq-absent branch -- both of this
# function's own jq and python3 paths must therefore produce byte-identical
# output for the same input, or the two build_gate_summary emitter branches
# could disagree on nothing more than a trailing newline. Both paths below
# are written to end the rendered block with the same "\n===END ...===\n"
# shape (the jq path's heredoc blank line before EOF is intentional and
# mirrored explicitly in the python3 path's block string, rather than left
# to a possible divergence).
_fence_deterministic_gates() {
  _fdg_json="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -Rs '.' <<EOF
===BEGIN DETERMINISTIC GATES DATA===
$(printf '%s' "$_fdg_json" | jq '.' 2>/dev/null || printf '%s' "$_fdg_json")
===END DETERMINISTIC GATES DATA===
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
# Trailing "\n" before the closing marker matches the jq path above (heredoc
# blank line before EOF) -- see this function doc comment.
block = "===BEGIN DETERMINISTIC GATES DATA===\n" + pretty + "\n===END DETERMINISTIC GATES DATA===\n"
print(json.dumps(block))
' "$_fdg_json"
    return 0
  fi
  printf '""'
}

# _fence_data_block LABEL KIND TEXT — render TEXT as a JSON string value
# wrapped in a ===BEGIN/END <LABEL> DATA=== fence, for the merge-gate payload
# fields that carry review/adversarial output (review_fenced,
# adversarial_fenced). KIND is "json" (TEXT is a JSON document, pretty-printed
# with sorted keys so the jq and python3 paths agree byte-for-byte) or "text"
# (TEXT is free prose, fenced verbatim). TEXT must already be sanitized
# (_sanitize_review_for_prompt / _sanitize_adversarial_report_for_prompt) --
# this only renders and fences.
#
# Unlike _fence_adversarial_findings/_fence_deterministic_gates, the block is
# assembled in sh and only the final string-encoding step differs by tool, so
# the two paths cannot diverge on the fence wording or trailing newline. A
# fixed "\n" follows the closing marker in both.
_fence_data_block() {
  # TEXT goes over stdin, never argv: a single argv string over the kernel's
  # MAX_ARG_STRLEN (~128 KiB) fails exec with E2BIG. The pretty-print step
  # rewrites TEXT, which is already sanitized, so a failure there falls back to
  # that same sanitized text. An unavailable encoder is a failure (return 1, no
  # output), never an empty string literal a caller could read as "empty
  # content".
  ds_findings_call -t "$3" -e string render fence-data "$1" "$2"
}

# Fixed, pre-encoded replacements for review_fenced / adversarial_fenced when
# the sanitize, fence or extraction step for that source FAILED. They are
# constant JSON string literals so they need no JSON encoder (the very thing
# that may have failed), and their shape is exactly what _fence_data_block
# emits for a text body. A degraded source is never rendered as an empty
# findings list and never as the original, unsanitized content.
_GATE_REVIEW_UNAVAILABLE_FENCED='"===BEGIN REVIEW FINDINGS DATA===\n[source unavailable: sanitize failed]\n===END REVIEW FINDINGS DATA===\n"'
_GATE_ADVERSARIAL_UNAVAILABLE_FENCED='"===BEGIN ADVERSARIAL REPORT DATA===\n[source unavailable: sanitize failed]\n===END ADVERSARIAL REPORT DATA===\n"'
# Same, for adversarial_findings_fenced when cmd_adversarial could not
# sanitize the structured findings (its sidecar meta then says so).
_GATE_ADVERSARIAL_FINDINGS_UNAVAILABLE_FENCED='"===BEGIN ADVERSARIAL FINDINGS DATA===\n[source unavailable: sanitize failed]\n===END ADVERSARIAL FINDINGS DATA==="'

# _sanitize_review_for_prompt FILE — print last-review.json reduced to what
# the Merge Gate may read, with every free-text field routed through
# _llm_field_sanitize, as compact JSON on stdout ("null", exit 0, when FILE is
# absent). FAIL CLOSED: a FILE that exists but cannot be fully extracted and
# sanitized (not a JSON object, a JSON tool or mktemp failure, an empty
# intermediate result) returns 1 with NO output -- never "null", never an
# empty findings list, never the unsanitized input. The caller turns that
# into a degraded marker plus review_degraded.
#
# Reviewer findings carry attacker-influenced text from the diff under review
# (paths, code excerpts, prose about hostile input), and "review" is the
# Merge Gate's primary refusal basis. The field set is a closed allowlist:
# top level keeps only summary/findings/_clagentic_diff_sha; each finding's
# free-text fields (and _deferral_id, which originates in an operator-writable
# file) are sanitized. Findings were already reduced to the closed review
# schema at ingest (_sanitize_review_findings_envelope) and the repo's own
# _-prefixed annotations (_recurrence_*, _deferral_matched) are not free text,
# so they pass through unchanged. Length truncation uses the shared default
# cap; severity/line never carry free text.
#
# Sanitized ONCE here and handed to both build_gate_summary emitter branches,
# so they cannot diverge.
_sanitize_review_for_prompt() {
  # The reduction, sanitizing and fail-closed rules live in findings.py render
  # sanitize-review: 'null' for an absent file, status 1 with no output for
  # one that exists but cannot be fully extracted and sanitized.
  ds_findings_call render sanitize-review "$1"
}

# _json_string_field JSON_OBJECT KEY — print the string value at KEY ("" when
# absent or not a string, or when the finding pipeline is unavailable).
_json_string_field() {
  # Malformed input is a failure (the stage exits nonzero) and so is a missing
  # pipeline; both print nothing, which callers read as an absent field. The
  # cause is reported on stderr, not hidden.
  ds_findings_call -t "$1" -e any render json-field "$2" || :
  return 0
}

# _sanitize_adversarial_report_for_prompt FILE — print last-adversarial.md's
# content run through _llm_field_sanitize. This prose is the Merge Gate's
# fallback refusal basis when adversarial_findings is empty, so it is NOT
# subject to the shared per-field cap (truncating it would silently change
# what the gate can refuse on). The only bound is per-call: three times the
# file's byte length, because defanging a forged fence label roughly doubles
# that label and the cap is applied after defanging, so the file's own length
# alone could still truncate a report full of forged markers. The text is
# passed as a shell-function argument (no exec), and _llm_field_sanitize hands
# it to python3 through a temp file, so no argv string carries the report.
# FAIL CLOSED: a read, length or sanitize failure returns 1 with no output,
# never the unsanitized report and never an empty string.
_sanitize_adversarial_report_for_prompt() {
  ds_findings_call -e any render sanitize-report "$1"
}

# _stage_payload_file PREFIX PAYLOAD — the one handoff primitive for any
# JSON/text payload that has no fixed size bound. Writes PAYLOAD to a new temp
# file and prints its path; the caller removes it. Returns 1 with no output
# (and no file left behind) when the temp file cannot be created or fully
# written. A payload must reach jq or python3 by path (jq --slurpfile /
# --rawfile, python3 argv path) or on stdin, never as an exec argument: one
# argv string over MAX_ARG_STRLEN (~128 KiB) fails exec with E2BIG. The shell
# builtin printf writes the file, so the write itself has no such limit.
# scripts/test_json_payload_handoff.py sweeps gates.sh and host-adapter.sh for
# any other argv-passed payload.
_stage_payload_file() {
  _bsp_path=$(mktemp -t "$1.XXXXXX" 2>/dev/null) || return 1
  [ -n "$_bsp_path" ] || return 1
  if ! printf '%s' "$2" > "$_bsp_path" 2>/dev/null; then
    rm -f "$_bsp_path"
    return 1
  fi
  printf '%s' "$_bsp_path"
}

# _bgs_cleanup_payload_tmp — remove build_gate_summary's staged payload files.
# Registered as its EXIT/INT/TERM/HUP trap so an error or signal mid-build
# cannot leave a review/adversarial payload behind in the temp dir.
_bgs_cleanup_payload_tmp() {
  [ -n "${_bgs_review_tmp:-}" ] && rm -f "$_bgs_review_tmp"
  [ -n "${_bgs_adv_tmp:-}" ] && rm -f "$_bgs_adv_tmp"
  return 0
}

# _read_deterministic_gates (lr-367a21) — INFORMATIONAL ONLY.
#
# Reads the latest gate_runs row for each deterministic gate (secrets, deps,
# sast) from audit.db and prints a JSON object on stdout:
#
#   {"secrets": {"outcome": "pass", "details": "...", "no_coverage": false},
#    "deps": null,
#    "sast": {"outcome": "warn", "details": "...", "no_coverage": false},
#    "audit_db_unavailable": false}
#
# A gate with no row at all (never ran) is null — distinct from an outcome
# string, so the payload can tell "absent" apart from any real outcome
# (pass/warn/skip/block). Nothing here changes a merge decision: this
# function only reads what cmd_secrets/cmd_deps/cmd_sast already wrote via
# cmd_log_run; it does not re-run them, does not re-derive their outcome,
# and its own read failure never blocks (see below).
#
# NO_COVERAGE (lr-170808 scope item 3): a skip currently logs `warn` and
# exits 0, and a preflight/canary refusal (this same task, items 1/2) logs
# `block` — either way merge-gate previously had no way to distinguish "the
# scanner ran and found nothing" from "the scanner did not meaningfully run
# at all." `_rdg_no_coverage` below is a MECHANICAL string match over the
# already-read outcome/details (both cmd_secrets' preflight/canary block
# paths and its older-gitleaks staged-scan-unavailable warn path use fixed,
# greppable vocabulary — see cmd_secrets' own cmd_log_run call sites), not a
# new signal cmd_secrets has to compute and thread through separately. This
# is intentionally the SAME wire item 3's own task description calls for
# ("preflight-block and canary-block both need a downstream representation,
# and inventing one twice is the wrong shape") — one boolean field, derived
# once, here, from data that already exists.
#
# DEGRADE, NEVER BLOCK (same pattern as gates.sh:3258's per-step-failure
# hint read, and platform.sh's ds_audit_log/ds_sqlite3 -- audit-db access is
# best-effort by contract everywhere else in this codebase). No sqlite3, no
# audit.db, or an unreadable/corrupt DB all degrade the same way: every gate
# field is null and audit_db_unavailable is true. build_gate_summary's
# callers (cmd_merge_gate, ds_merge_gate_prompt) proceed to the LLM call
# exactly as they do today when this block is entirely absent -- adding this
# field never introduces a new fail-closed path.
#
# ROUND-TRIP SANITIZATION (lr-367a21 fold-in, BOBBIE): each gate's "details"
# text is attacker-reachable (e.g. .clagentic/semgrep-exclude rule-id lines
# -> _SAST_EXCL_IDS -> cmd_sast's pass details string -> gate_runs -> here)
# and, unlike every sibling external-text round-trip into an LLM prompt in
# this codebase (adversarial findings, invariant feed, change-class hint),
# was not routed through _llm_field_sanitize (platform.sh:710) before this
# fold-in. Sanitized once, at this single shared read point below, so both
# build_gate_summary emitter branches (jq and python3) see identical
# already-clean text and cannot diverge. "outcome" is a closed 4-value set
# (pass/warn/skip/block) written only by cmd_log_run's own callers, never
# free text, so it is deliberately NOT sanitized — only "details" is.
#
# NEWLINE-SAFE ROW READ (lr-acf632): outcome and details used to be read via
# ONE query ("SELECT outcome, details ...") with -separator '|', then split
# with `cut -d'|' -f1`/`-f2-`. cut is LINE-oriented: a details value with an
# embedded newline made its own trailing lines bleed into the outcome field
# on the next cut invocation, corrupting the very pass/warn/skip/block
# distinction this function exists to preserve (the lr-367a21 root-cause
# invariant). No current cmd_secrets/cmd_deps/cmd_sast call site actually
# writes a literal newline into details today (confirmed: _SAST_EXCL_IDS,
# the one attacker-reachable path BOBBIE traced, is built by reading
# .clagentic/semgrep-exclude one line at a time via `read -r`, which cannot
# hand a single token an embedded \n), so this was latent, not live -- but
# ds_sql_escape only escapes quotes, not newlines, so a future/renamed
# caller writing multi-line details would have silently corrupted outcome.
# Fixed by querying outcome and details SEPARATELY, one column per query --
# there is no second column to mis-split against, so an embedded newline in
# details can never bleed into outcome, regardless of its content. This
# avoids `-json` (never used elsewhere in this codebase, and requires
# sqlite3 >= 3.33 -- not a floor this script asserts anywhere) and avoids
# python3 (the jq-only emitter path must keep working without it).
# _rdg_details_is_no_coverage OUTCOME DETAILS — mechanical predicate: does
# this (already-logged) gate_runs row represent a run that produced NO
# meaningful detection coverage, as opposed to a real scan that genuinely
# found nothing? Matched against the FIXED, greppable vocabulary
# cmd_secrets' own cmd_log_run call sites use for exactly this class of
# outcome (never free-form LLM text, so this is a closed-set string match,
# not a heuristic over untrusted content):
#   - "positive-control canary failed" (item 2 block)
#   - "gate_summary_degraded"-adjacent config causes: ".gitleaks.toml
#     defines no rules" (item 1 block)
#   - "history scan unavailable" (pre-existing older-gitleaks warn path,
#     scope item 3's own "a skip currently logs warn and exits 0" case)
# Deliberately case-sensitive substring match on gates.sh's own fixed
# literals, not a regex over arbitrary content — every one of these strings
# is written by gates.sh itself, at a specific, enumerated call site, never
# derived from repo/attacker-controlled text.
_rdg_details_is_no_coverage() {
  _rdnc_outcome="$1"
  _rdnc_details="$2"
  case "$_rdnc_details" in
    *"positive-control canary failed"*) return 0 ;;
    *".gitleaks.toml defines no rules"*) return 0 ;;
    *"history scan unavailable"*) return 0 ;;
  esac
  return 1
}

_read_deterministic_gates() {
  _rdg_db="$REPO_ROOT/.clagentic/lite/audit.db"
  _rdg_unavailable=false
  _rdg_secrets='null'
  _rdg_deps='null'
  _rdg_sast='null'
  if [ -f "$_rdg_db" ] && command -v sqlite3 >/dev/null 2>&1; then
    for _rdg_gate in secrets deps sast; do
      _rdg_id=$(ds_sqlite3 "$_rdg_db" \
        "SELECT id FROM gate_runs WHERE gate='$_rdg_gate' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")
      if [ -n "$_rdg_id" ]; then
        _rdg_outcome=$(ds_sqlite3 "$_rdg_db" \
          "SELECT outcome FROM gate_runs WHERE id=$_rdg_id;" 2>/dev/null || echo "")
        _rdg_details=$(ds_sqlite3 "$_rdg_db" \
          "SELECT details FROM gate_runs WHERE id=$_rdg_id;" 2>/dev/null || echo "")
        # NO_COVERAGE (lr-170808 scope item 3): computed from the RAW
        # (pre-sanitize) details string, before _llm_field_sanitize below —
        # the fixed literals this predicate matches are gates.sh's own
        # constants, never round-tripped through an LLM prompt themselves,
        # so there is no reason to defer this check past sanitization, and
        # doing it first keeps the match immune to whatever (harmless, for
        # this fixed vocabulary) transformation sanitization applies.
        _rdg_no_coverage=false
        if _rdg_details_is_no_coverage "$_rdg_outcome" "$_rdg_details"; then
          _rdg_no_coverage=true
        fi
        # SECURITY (lr-367a21 fold-in, BOBBIE): details is attacker-reachable
        # free text -- e.g. .clagentic/semgrep-exclude rule-id lines flow
        # into _SAST_EXCL_IDS (cmd_sast), into the sast pass details string,
        # into this gate_runs row, into this payload field, into the
        # merge-gate prompt. Route it through the SAME sanitizer every other
        # external-text round-trip into an LLM prompt in this codebase uses
        # (_llm_field_sanitize, platform.sh:710 -- see its call sites at
        # gates.sh's own _invariant_feed_append and llm-client.sh's
        # change-class-hint/deferrals-fallback sites) before it ever reaches
        # the JSON entry below. Sanitizing here, at the single shared read
        # point, means both emitter branches of build_gate_summary (jq and
        # python3) receive already-clean text -- neither can diverge from
        # the other, and outcome is untouched (closed 4-value set, not free
        # text, nothing to sanitize).
        _rdg_details=$(_llm_field_sanitize "$_rdg_details")
        if command -v jq >/dev/null 2>&1; then
          _rdg_entry=$(jq -cn --arg o "$_rdg_outcome" --arg d "$_rdg_details" --argjson nc "$_rdg_no_coverage" '{"outcome": $o, "details": $d, "no_coverage": $nc}')
        elif command -v python3 >/dev/null 2>&1; then
          _rdg_entry=$(python3 -c 'import json,sys; print(json.dumps({"outcome": sys.argv[1], "details": sys.argv[2], "no_coverage": sys.argv[3] == "true"}))' "$_rdg_outcome" "$_rdg_details" "$_rdg_no_coverage")
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

# ---------------------------------------------------------- gate attestation manifest --
#
# _GATE_MANIFEST_PATH (lr-37a9c8) — one machine-readable per-run record of
# what ran, via which path (router|direct), which brand+model actually
# produced the verdict, and any fallback events, for every gate `gates.sh
# ship` declares. WHY THIS EXISTS: exit codes 0/1/2 (lr-0346) fire only at
# total failure; a same-vendor fallback that still produces a schema-valid
# "pass" (lr-b20c0a's codex-401-for-days case) is invisible to every
# existing consumer -- the PR body's review-provenance section
# (_render_review_verdict_lines, above) already answers "did findings block
# /ship" but never "which CLI/model actually produced that verdict, and did
# it get there via a fallback." This closes that gap as a durable artifact,
# not a one-off stderr line.
#
# FILE: .clagentic/lite/last-gate-manifest.json (gitignored local gate
# state, same convention as last-review.json/gate-summary.json). ONE JSON
# object, overwritten each `ship` run (not append-only like the review
# ledger -- a manifest describes "what happened THIS run," not a durable
# cross-round history; the review ledger already owns that job for review
# verdicts specifically, and this file does not duplicate it).
#
# WRITTEN UNCONDITIONALLY (acceptance criterion 4): _manifest_init is called
# at the top of cmd_ship, before any gate runs, so a crashed or
# killed-mid-run `ship` leaves a manifest on disk that is either absent
# (nothing ran yet -- a genuinely fresh state) or visibly INCOMPLETE (some
# gates recorded, others never reached) rather than a stale file from a
# PRIOR successful run silently standing in for this one. Absence or an
# incomplete manifest is reported as failure by every consumer
# (_manifest_is_complete, below) -- NEVER inferred as success.
#
# PROVENANCE VOCABULARY, REUSED FROM lr-429b32 (do not invent a second
# format): "brand" = the CLI (claude/codex/router/<other>) exactly as
# _render_review_verdict_lines' caller and log_attempt already spell it
# (the same CLI token walk_chain's chain-step loop resolves via
# resolve_step, llm-client.sh); "model" = the concrete model string
# resolve_step resolved (may be empty -- a CLI invoked with no model flag
# uses its own default); "path" = "router" or "direct", the SAME two-value
# vocabulary docs/GATES.md "Host adapter contract"/"ROUTER-PATH INVOCATION"
# already establish (never a third value -- Layer 1's in-router advance is
# invisible on this side by construction, per invoke_router's own doc
# comment, so this manifest cannot and does not attempt to report it).
#
# MANIFEST IS LOCAL AND UNSIGNED (lr-54cf2d's forgeability caveat, stated
# here because this is the one artifact this task adds that a later reader
# might mistake for an attestation in the cryptographic sense): like
# audit.db, last-review.json, and review-ledger.jsonl, this file is a plain,
# unsigned JSON file writable by anyone with filesystem access to the
# working tree. It records what THIS INVOCATION of `gates.sh ship` observed
# -- not a claim independently verifiable by a third party, not a substitute
# for host-side CI, and not per-reviewer credentials or attestation (ruled
# out, lr-96f8ba). A hostile local user who wants to fabricate a clean
# manifest can already do so, the same way they could hand-edit
# last-review.json or review-ledger.jsonl today (see docs/GATES.md "Review
# ledger and anchored verdicts" for the identical threat-model posture
# applied to that file). What this manifest
# defends against is an HONEST but UNOBSERVANT run silently mis-reporting
# its own provenance -- a same-vendor fallback masquerading as the
# configured primary, a declared-but-inert router opt-in, a degraded LLM
# chain reported as an ordinary pass -- not a hostile actor with write
# access to the repo.
#
# NO AGENT NAMES IN SHIPPED PROSE (lr-411a35): every string this module
# writes or renders is role/CLI/outcome vocabulary already established
# elsewhere in this codebase (reviewer/auditor/gate, claude/codex/router,
# pass/degraded/failed/skipped) -- never a crew agent's proper name.
_gate_manifest_path() {
  printf '%s/.clagentic/lite/last-gate-manifest.json' "$REPO_ROOT"
}

# _manifest_init — writes a fresh, mostly-empty manifest at the start of
# `ship`, unconditionally (see the module doc comment above for why this
# must happen before any gate runs, not lazily on first gate write).
# Fail-open on the write itself (no jq/no python3, unwritable directory):
# same posture as every other on-disk gate-state writer in this file --
# a manifest-write failure must never abort `ship`, only leave the manifest
# absent, which _manifest_is_complete already treats as failure downstream.
_manifest_init() {
  _mi_path=$(_gate_manifest_path)
  _mi_ts=$(ds_date_iso)
  _mi_branch=""
  _mi_head=""
  if _git_repo_root_is_scoped; then
    _mi_branch=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    _mi_head=$(_git_repo_scoped_head_sha)
  fi
  mkdir -p "$REPO_ROOT/.clagentic/lite" 2>/dev/null || true
  printf '{"ts": "%s", "branch": "%s", "head_sha": "%s", "gates": {}, "complete": false}\n' \
    "$_mi_ts" "$_mi_branch" "$_mi_head" > "$_mi_path" 2>/dev/null || true
}

# _manifest_set_gate GATE OUTCOME PATH BRAND MODEL FALLBACK_JSON EXIT_CLASS DETAILS
#
# Merges one gate's attestation record into the manifest (read-modify-write
# -- gates run sequentially within one `ship` invocation, never concurrently,
# so no locking beyond ds_sqlite3's own busy-timeout precedent is needed).
#
# OUTCOME is the closed vocabulary the task requires: ran|degraded|failed|skipped.
# PATH is "router"|"direct"|"n/a" (deterministic gates -- secrets/deps/sast/
# bleed -- have no LLM path at all; "n/a", never a fabricated "direct").
# BRAND/MODEL are empty string for a non-LLM gate. FALLBACK_JSON is a JSON
# array of {"from":"...","to":"...","reason":"..."} objects (empty array
# "[]" when no fallback occurred). DETAILS is a short human-readable string,
# reusing whatever the gate's own cmd_log_run details string already said
# (reuse, not re-derivation).
#
# Fail-open, matching _manifest_init: a merge failure (no jq/python3) drops
# this gate's record silently rather than corrupting the file -- the
# resulting manifest is then INCOMPLETE for this gate, which
# _manifest_is_complete (below) surfaces as a named gap, never inferred as
# a clean pass.
_manifest_set_gate() {
  _msg_gate="$1"; _msg_outcome="$2"; _msg_path="$3"; _msg_brand="$4"
  _msg_model="$5"; _msg_fallback="${6:-[]}"; _msg_exit_class="${7:-}"; _msg_details="${8:-}"
  _msg_manifest=$(_gate_manifest_path)
  [ -f "$_msg_manifest" ] || return 0

  if command -v jq >/dev/null 2>&1; then
    _msg_tmp=$(mktemp -t clagentic-manifest.XXXXXX)
    if jq --arg g "$_msg_gate" --arg outcome "$_msg_outcome" --arg path "$_msg_path" \
        --arg brand "$_msg_brand" --arg model "$_msg_model" --argjson fallback "$_msg_fallback" \
        --arg exit_class "$_msg_exit_class" --arg details "$_msg_details" \
        '.gates[$g] = {outcome: $outcome, path: $path, brand: $brand, model: $model,
                        fallback_events: $fallback, exit_class: $exit_class, details: $details}' \
        "$_msg_manifest" > "$_msg_tmp" 2>/dev/null; then
      mv "$_msg_tmp" "$_msg_manifest"
    else
      rm -f "$_msg_tmp"
    fi
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$_msg_manifest" "$_msg_gate" "$_msg_outcome" "$_msg_path" "$_msg_brand" \
      "$_msg_model" "$_msg_fallback" "$_msg_exit_class" "$_msg_details" <<'PYEOF' 2>/dev/null
import json, sys
path, gate, outcome, ptype, brand, model, fallback_raw, exit_class, details = sys.argv[1:10]
try:
    with open(path) as f:
        m = json.load(f)
except Exception:
    sys.exit(0)
try:
    fallback = json.loads(fallback_raw)
    if not isinstance(fallback, list):
        fallback = []
except Exception:
    fallback = []
m.setdefault("gates", {})
m["gates"][gate] = {
    "outcome": outcome, "path": ptype, "brand": brand, "model": model,
    "fallback_events": fallback, "exit_class": exit_class, "details": details,
}
try:
    with open(path, "w") as f:
        json.dump(m, f)
except Exception:
    sys.exit(0)
PYEOF
  fi
  return 0
}

# _manifest_finalize DECLARED_GATES_SPACE_SEPARATED
#
# Marks the manifest "complete" (every declared gate has a record) and sets
# a top-level "degraded" flag true iff any recorded gate's outcome is
# "degraded" or "failed" -- the loud, greppable, distinct-from-passed-as-
# configured status the task's policy requires (acceptance criterion 1).
# Called once, at the end of cmd_ship's gate sequence, after the last gate
# that ran (or was skipped) has already called _manifest_set_gate /
# ship_step_skip.
_manifest_finalize() {
  _mf_declared="$1"
  _mf_manifest=$(_gate_manifest_path)
  [ -f "$_mf_manifest" ] || return 0

  if command -v jq >/dev/null 2>&1; then
    _mf_tmp=$(mktemp -t clagentic-manifest-final.XXXXXX)
    if jq --arg declared "$_mf_declared" '
        ($declared | split(" ") | map(select(length > 0))) as $names
        | . + {
            complete: (($names - (.gates | keys)) | length == 0),
            missing_gates: ($names - (.gates | keys)),
            degraded: ([.gates[] | select(.outcome == "degraded" or .outcome == "failed")] | length > 0)
          }' "$_mf_manifest" > "$_mf_tmp" 2>/dev/null; then
      mv "$_mf_tmp" "$_mf_manifest"
    else
      rm -f "$_mf_tmp"
    fi
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$_mf_manifest" "$_mf_declared" <<'PYEOF' 2>/dev/null
import json, sys
path, declared = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        m = json.load(f)
except Exception:
    sys.exit(0)
names = [n for n in declared.split(" ") if n]
gates = m.get("gates", {})
missing = [n for n in names if n not in gates]
m["complete"] = len(missing) == 0
m["missing_gates"] = missing
m["degraded"] = any(g.get("outcome") in ("degraded", "failed") for g in gates.values())
try:
    with open(path, "w") as f:
        json.dump(m, f)
except Exception:
    sys.exit(0)
PYEOF
  fi
  return 0
}

# _manifest_llm_provenance ROLE WATERMARK_ID
#
# Reads back audit.db's own gate_runs rows for gate='llm-call' AND
# details LIKE '<role>:%' with id > WATERMARK_ID (this run's own attempts,
# never a prior run's -- log_attempt, llm-client.sh, already writes exactly
# this shape unconditionally; this function reuses that existing record
# rather than teaching walk_chain a second, parallel reporting channel).
# WATERMARK_ID isolates THIS invocation's rows from a prior `gates review`
# run's leftover rows for the same role.
#
# Prints one line: PATH<TAB>BRAND<TAB>MODEL<TAB>FALLBACK_JSON<TAB>EXIT_CLASS
#   PATH        — "router" if any row's CLI token is "router", else "direct"
#                 (mirrors the log_attempt call sites: the router path logs
#                 CLI="router" TIER="role:<role>-chain"; every direct-CLI
#                 step logs the real CLI name).
#   BRAND/MODEL — from the row whose outcome is "pass" or "fallback" (the
#                 step that actually produced the verdict) — the highest-id
#                 (most recent) such row when more than one exists (a
#                 fallback chain's SUCCESSFUL step, not its earlier
#                 failures). Empty when no pass/fallback row exists for this
#                 role in this run (every step failed, or the role never ran
#                 at all — a genuinely degraded/failed chain).
#   FALLBACK_JSON — one {"from":X,"to":Y,"reason":Z} object per step that
#                 preceded the eventual pass (empty array "[]" when the
#                 primary succeeded on attempt 1, or when no pass exists).
#   EXIT_CLASS  — "degraded" if the run's own audit trail recorded a
#                 gate_runs row with outcome="degraded" for this role in
#                 this run; empty otherwise (the caller already knows
#                 ran/failed from its own control flow — this field exists
#                 only to carry the degraded-vs-ordinary-failure distinction
#                 walk_chain's own exit codes 3/4/5 already draw, since that
#                 distinction is not otherwise visible from audit.db alone).
#
# Fail-open: no sqlite3/no audit.db prints nothing (empty PATH/BRAND/MODEL/
# empty-array fallback/empty exit_class) -- the caller (_manifest_record_llm_gate)
# treats an empty read the same as "no LLM call happened this run," which is
# always the conservative direction for an attestation manifest (never
# fabricate a brand/model this function could not actually observe).
_manifest_llm_provenance() {
  _mlp_role="$1"
  _mlp_watermark="$2"
  _mlp_db="$REPO_ROOT/.clagentic/lite/audit.db"
  [ -f "$_mlp_db" ] && command -v sqlite3 >/dev/null 2>&1 || { printf '\t\t\t[]\t'; return 0; }

  _mlp_rows=$(ds_sqlite3 -separator '|' "$_mlp_db" \
    "SELECT id, outcome, details FROM gate_runs
     WHERE gate='llm-call' AND details LIKE '${_mlp_role}:%' AND id > ${_mlp_watermark}
     ORDER BY id ASC;" 2>/dev/null)
  [ -n "$_mlp_rows" ] || { printf '\t\t\t[]\t'; return 0; }

  if ! command -v python3 >/dev/null 2>&1; then
    # No JSON tool -- cannot safely build the fallback_events array or parse
    # the details string's colon-joined fields. Fail open (empty read),
    # same posture as no-rows-at-all above; the manifest entry for this
    # gate falls back to "outcome recorded, provenance unavailable" rather
    # than a hand-rolled, possibly-corrupting string split.
    printf '\t\t\t[]\t'
    return 0
  fi

  printf '%s\n' "$_mlp_rows" | python3 -c '
import sys, json

path = ""
brand = ""
model = ""
exit_class = ""
fallback = []
prior_steps = []  # (cli, tier) pairs seen before the eventual pass/fallback

for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    parts = line.split("|", 2)
    if len(parts) != 3:
        continue
    _id, outcome, details = parts
    # details shape (log_attempt, llm-client.sh): "role:cli:tier[ model=M][ — hint]"
    head = details.split(" — ", 1)[0]
    model_tok = ""
    if " model=" in head:
        head, _, model_tok = head.partition(" model=")
    rc = head.split(":", 2)
    cli = rc[1] if len(rc) > 1 else ""
    tier = rc[2] if len(rc) > 2 else ""

    if outcome == "degraded":
        exit_class = "degraded"
        continue
    if outcome in ("router-refused", "router-fallback", "hard-failure", "skip"):
        continue
    if outcome == "step-failed":
        prior_steps.append((cli, tier))
        continue
    if outcome in ("pass", "fallback"):
        path = "router" if cli == "router" else "direct"
        brand = cli
        model = model_tok
        for i, (pcli, ptier) in enumerate(prior_steps):
            nxt_cli = prior_steps[i + 1][0] if i + 1 < len(prior_steps) else cli
            fallback.append({"from": pcli, "to": nxt_cli, "reason": "step-failed"})
        prior_steps = []

sys.stdout.write("%s\t%s\t%s\t%s\t%s" % (path, brand, model, json.dumps(fallback), exit_class))
'
}

# _manifest_record_llm_gate GATE ROLE OUTCOME WATERMARK_ID [DETAILS]
#
# Wires _manifest_llm_provenance's read-back into _manifest_set_gate for one
# LLM-backed gate (review|adversarial|merge-gate). OUTCOME is the caller's
# own already-determined ran|degraded|failed|skipped verdict (this function
# does not re-derive it -- cmd_review/cmd_adversarial/cmd_merge_gate already
# know their own outcome from walk_chain's exit status, per INV-1b).
_manifest_record_llm_gate() {
  _mrlg_gate="$1"; _mrlg_role="$2"; _mrlg_outcome="$3"; _mrlg_watermark="$4"; _mrlg_details="${5:-}"
  _mrlg_prov=$(_manifest_llm_provenance "$_mrlg_role" "$_mrlg_watermark")
  _mrlg_path=$(printf '%s' "$_mrlg_prov" | cut -f1)
  _mrlg_brand=$(printf '%s' "$_mrlg_prov" | cut -f2)
  _mrlg_model=$(printf '%s' "$_mrlg_prov" | cut -f3)
  _mrlg_fallback=$(printf '%s' "$_mrlg_prov" | cut -f4)
  _mrlg_exit_class=$(printf '%s' "$_mrlg_prov" | cut -f5)
  [ -n "$_mrlg_path" ] || _mrlg_path="n/a"
  [ -n "$_mrlg_fallback" ] || _mrlg_fallback="[]"
  _manifest_set_gate "$_mrlg_gate" "$_mrlg_outcome" "$_mrlg_path" "$_mrlg_brand" \
    "$_mrlg_model" "$_mrlg_fallback" "$_mrlg_exit_class" "$_mrlg_details"
}

# _manifest_audit_watermark — current MAX(id) in gate_runs, or 0 when
# unavailable. Captured immediately BEFORE a gate's own llm-client.sh call
# so _manifest_llm_provenance's "id > WATERMARK" read only ever sees this
# run's own attempts, never a prior `gates review` run's leftover rows for
# the same role.
_manifest_audit_watermark() {
  _maw_db="$REPO_ROOT/.clagentic/lite/audit.db"
  if [ -f "$_maw_db" ] && command -v sqlite3 >/dev/null 2>&1; then
    _maw_id=$(ds_sqlite3 "$_maw_db" "SELECT COALESCE(MAX(id),0) FROM gate_runs;" 2>/dev/null)
    case "$_maw_id" in ''|*[!0-9]*) _maw_id=0 ;; esac
    printf '%s' "$_maw_id"
  else
    printf '0'
  fi
}

# _manifest_is_complete — exit 0 iff a manifest exists, is parseable, and
# its own "complete" field is true. THE consumer-side predicate for
# acceptance criterion 4 ("missing or incomplete manifest is reported as
# failure, never inferred as success").
#
# NOT WIRED INTO cmd_merge_gate's OWN STALE-PAYLOAD CHECK (unlike the review
# ledger's _ledger_anchored_pass_at_head, which cmd_merge_gate DOES consult
# inline): the manifest is only finalized (its "complete" field only ever
# becomes true) by _manifest_finalize, called at the END of cmd_ship's gate
# sequence -- AFTER merge-gate has already run. Gating merge-gate on
# manifest completeness would be circular: the manifest cannot be complete
# until merge-gate itself has already recorded a result into it. This
# predicate is instead the sanctioned check for a DOWNSTREAM consumer that
# inspects a PAST ship run's manifest after the fact -- NAOMI's merge
# decision, `clagentic-lite doctor`, or an operator inspecting the file
# directly (docs/GATES.md names the manifest the arbiter for "what ran";
# this predicate is how a consumer proves that arbiter itself is trustworthy
# before reading it) -- never a precondition merge-gate checks on itself.
_manifest_is_complete() {
  _mic_manifest=$(_gate_manifest_path)
  [ -f "$_mic_manifest" ] || return 1
  if command -v jq >/dev/null 2>&1; then
    [ "$(jq -r '.complete // false' "$_mic_manifest" 2>/dev/null)" = "true" ]
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys
try:
    d = json.load(open(sys.argv[1]))
    sys.exit(0 if d.get("complete") is True else 1)
except Exception:
    sys.exit(1)' "$_mic_manifest" 2>/dev/null
  else
    # No JSON tool -- cannot prove completeness. Fail closed: treat as
    # incomplete, same posture as every other JSON-tool-dependent gate check
    # in this file when neither jq nor python3 is available.
    return 1
  fi
}

# _render_gate_manifest_lines — renders the manifest's per-gate attestation
# as newline-separated lines, reusing the SAME "explicit sentence per state,
# never a bare heading" discipline _render_review_verdict_lines/
# _build_ship_pr_body already established (lr-429b32) -- one more consumer
# of that rendering discipline, not a second one. Prints nothing (and the
# caller renders its own "no manifest" sentence) when the manifest is
# absent or unparseable.
_render_gate_manifest_lines() {
  _rgml_manifest=$(_gate_manifest_path)
  [ -f "$_rgml_manifest" ] || return 1

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$_rgml_manifest" <<'PYEOF'
import json, sys

path = sys.argv[1]
try:
    with open(path) as f:
        m = json.load(f)
except Exception:
    sys.exit(1)

gates = m.get("gates", {})
if not gates:
    print("no gate attestation recorded")
    sys.exit(0)

degraded_overall = m.get("degraded", False)
complete = m.get("complete", False)
lines = []
if not complete:
    missing = m.get("missing_gates", [])
    lines.append("INCOMPLETE manifest -- missing gate(s): %s" % (", ".join(missing) or "unknown"))
if degraded_overall:
    lines.append("DEGRADED-BUT-PASSED: at least one declared gate ran degraded or failed -- see per-gate detail below, this is distinct from passed-as-configured.")

for name in sorted(gates.keys()):
    g = gates[name]
    outcome = g.get("outcome", "unknown")
    parts = ["%s: %s" % (name, outcome)]
    gpath = g.get("path")
    if gpath and gpath != "n/a":
        parts.append("path=%s" % gpath)
    brand = g.get("brand")
    if brand:
        model = g.get("model")
        brand_str = "brand=%s" % brand
        if model:
            brand_str += " model=%s" % model
        parts.append(brand_str)
    fallback = g.get("fallback_events") or []
    if fallback:
        parts.append("fallback=%d step(s)" % len(fallback))
    lines.append("- " + ", ".join(parts))

print("\n".join(lines))
PYEOF
    return $?
  fi
  return 1
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
    printf '{"stale_payload": true, "stale_reason": "empty_head", "stale_reasons": {"review": "empty_head", "adversarial": "empty_head"}, "stale_gates": ["review","adversarial"], "blocking_findings": [], "current_sha": "", "review_sha": "", "adversarial_sha": ""}\n'
    return 0
  fi
  if [ -n "$CURRENT_SHA" ] || [ "$_git_dir_ok" = "0" ]; then
    if [ "${CLAGENTIC_ALLOW_STALE_PAYLOAD:-0}" = "1" ]; then
      cmd_log_run merge-gate warn "CLAGENTIC_ALLOW_STALE_PAYLOAD=1: proceeding with potentially stale gate payload"
    else
      STALE_PAYLOAD=false
      STALE_GATES=""
      # One "gate=reason" pair per stale gate, reasons drawn from the closed
      # set sha_mismatch | missing_stamp | review_blocked_at_head | empty_head.
      # cmd_merge_gate renders a distinct refusal per reason: the cause decides
      # what the operator should do next, and "re-run" is only right for some.
      STALE_REASONS=""
      STALE_BLOCKING_JSON="[]"

      # Extract SHA from last-review.json.
      _rv_sha=""
      if [ -f "$RV" ]; then
        if command -v jq >/dev/null 2>&1; then
          _rv_sha=$(jq -r '._clagentic_diff_sha // ""' "$RV" 2>/dev/null || echo "")
        elif command -v python3 >/dev/null 2>&1; then
          _rv_sha=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("_clagentic_diff_sha",""))' "$RV" 2>/dev/null || echo "")
        fi
        # File exists: stale if stamp is empty (pre-feature file) OR stamp mismatches.
        if [ -z "$_rv_sha" ]; then
          STALE_PAYLOAD=true
          STALE_GATES="review"
          STALE_REASONS="review=missing_stamp"
        elif [ "$_rv_sha" != "$CURRENT_SHA" ]; then
          STALE_PAYLOAD=true
          STALE_GATES="review"
          STALE_REASONS="review=sha_mismatch"
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
        if ! command -v python3 >/dev/null 2>&1; then
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
            _mg_ledger_state=$(_ledger_head_verdict_state "$_mg_ledger" "$_mg_ledger_branch" "$CURRENT_SHA" review)
            STALE_REASONS="${STALE_REASONS:+$STALE_REASONS }review-ledger=${_mg_ledger_state:-missing_stamp}"
            if [ "$_mg_ledger_state" = "review_blocked_at_head" ]; then
              # The refusal names the findings that blocked, from the ledger
              # entry the verdict was recorded with (last-review.json is
              # overwritten by every run and may no longer match).
              _mg_ledger_entry=$(_ledger_latest_gate_entry "$_mg_ledger" "$_mg_ledger_branch" review)
              STALE_BLOCKING_JSON=$(printf '%s' "$_mg_ledger_entry" | _blocking_findings_json "$THRESHOLD")
              [ -n "$STALE_BLOCKING_JSON" ] || STALE_BLOCKING_JSON="null"
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
          if [ -z "$_ad_sha" ]; then
            STALE_REASONS="${STALE_REASONS:+$STALE_REASONS }adversarial=missing_stamp"
          else
            STALE_REASONS="${STALE_REASONS:+$STALE_REASONS }adversarial=sha_mismatch"
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
        # stale_reasons object from the "gate=reason" pairs; every token is
        # from a closed lowercase set, so it is safe to splice as literals
        # (this branch must work with no JSON encoder at all).
        _stale_reasons_obj=""
        _stale_primary=""
        for _sr in $STALE_REASONS; do
          _sr_gate="${_sr%%=*}"
          _sr_reason="${_sr#*=}"
          [ -n "$_stale_primary" ] || _stale_primary="$_sr_reason"
          _stale_reasons_obj="${_stale_reasons_obj:+$_stale_reasons_obj, }\"$_sr_gate\": \"$_sr_reason\""
        done
        # A blocked review is the actionable cause even when a sibling gate is
        # also stale, so it wins the single top-level stale_reason.
        case " $STALE_REASONS " in
          *"=review_blocked_at_head "*) _stale_primary="review_blocked_at_head" ;;
        esac
        printf '{"stale_payload": true, "stale_reason": "%s", "stale_reasons": {%s}, "stale_gates": [%s], "blocking_findings": %s, "current_sha": "%s", "review_sha": "%s", "adversarial_sha": "%s"}\n' \
          "${_stale_primary:-sha_mismatch}" "$_stale_reasons_obj" "$_stale_arr" "$STALE_BLOCKING_JSON" "$CURRENT_SHA" "$_rv_sha_val" "$_ad_sha_val"
        return 0
      fi
    fi
  fi

  # Review and adversarial output reach the Merge Gate ONLY as sanitized,
  # fenced text (review_fenced, adversarial_fenced) plus review_sha, which
  # --recheck's staleness guard reads. The raw "review"/"adversarial" fields
  # are no longer emitted: they carried attacker-influenced text (the review
  # findings are the gate's primary refusal basis; the adversarial markdown is
  # its fallback basis) with neither sanitization nor a fence. Both emitter
  # branches below are handed these pre-built, so they cannot diverge.
  # A missing/non-object review and a missing adversarial file stay null,
  # distinct from any fenced content.
  #
  # ONE RULE for a sanitize, fence or extraction failure on either source: the
  # field is emitted as a fenced "source unavailable" marker and the matching
  # *_degraded flag is set. It is never an empty/null result the Merge Gate
  # could read as "no findings", and never the original unsanitized content.
  # The Merge Gate treats a degraded source exactly like a missing one.
  REVIEW_DEGRADED=false
  REVIEW_FENCED_PAYLOAD='null'
  REVIEW_SHA_VALUE=""
  if REVIEW_SANITIZED=$(_sanitize_review_for_prompt "$RV") && [ -n "$REVIEW_SANITIZED" ]; then
    if [ "$REVIEW_SANITIZED" != "null" ]; then
      if REVIEW_FENCED_PAYLOAD=$(_fence_data_block "REVIEW FINDINGS" json "$REVIEW_SANITIZED") && [ -n "$REVIEW_FENCED_PAYLOAD" ]; then
        REVIEW_SHA_VALUE=$(_json_string_field "$REVIEW_SANITIZED" _clagentic_diff_sha)
      else
        REVIEW_DEGRADED=true
      fi
    fi
  else
    REVIEW_DEGRADED=true
  fi
  if [ "$REVIEW_DEGRADED" = "true" ]; then
    REVIEW_FENCED_PAYLOAD=$_GATE_REVIEW_UNAVAILABLE_FENCED
    REVIEW_SHA_VALUE=""
  fi
  # adversarial_missing=true means NO report is fenced, whatever the path now
  # holds: a leftover file from an earlier run must never be presented as this
  # commit's report.
  ADVERSARIAL_REPORT_DEGRADED=false
  ADVERSARIAL_FENCED_PAYLOAD='null'
  if [ "$ADVERSARIAL_MISSING" != "true" ] && [ -f "$AD" ]; then
    if _bgs_adv_text=$(_sanitize_adversarial_report_for_prompt "$AD") \
        && ADVERSARIAL_FENCED_PAYLOAD=$(_fence_data_block "ADVERSARIAL REPORT" text "$_bgs_adv_text") \
        && [ -n "$ADVERSARIAL_FENCED_PAYLOAD" ]; then
      :
    else
      ADVERSARIAL_REPORT_DEGRADED=true
      ADVERSARIAL_FENCED_PAYLOAD=$_GATE_ADVERSARIAL_UNAVAILABLE_FENCED
    fi
  fi
  # cmd_adversarial records in its sidecar meta when it could not sanitize the
  # structured findings (it then writes an empty sidecar array, which must not
  # be read as "no findings"). The whole adversarial source is then degraded:
  # marker for the findings and for the report, flag set. A plain grep so the
  # check needs no JSON tool. Not applied when the report is missing.
  ADF_FINDINGS_DEGRADED=false
  if [ "$ADVERSARIAL_MISSING" != "true" ] && [ -f "$ADF_META" ] \
      && grep -q '"findings_degraded": true' "$ADF_META" 2>/dev/null; then
    ADF_FINDINGS_DEGRADED=true
    ADVERSARIAL_REPORT_DEGRADED=true
    ADVERSARIAL_FENCED_PAYLOAD=$_GATE_ADVERSARIAL_UNAVAILABLE_FENCED
  fi

  # The payload is assembled by the finding pipeline (render gate-summary):
  # the mechanical blocking/advisory counts, the resolved change class, the
  # class-downgrade cross-check and the dropped-count are all computed there
  # from the structured sidecar, so the merge gate never re-derives them from
  # prose. Without python3 no fenced content can be built and the minimal
  # degraded envelope at the end of this function is emitted instead.
  if command -v python3 >/dev/null 2>&1; then
    ADF_ARG=""
    ADF_META_ARG=""
    [ -f "$ADF" ] && ADF_ARG="$ADF"
    [ -f "$ADF_META" ] && ADF_META_ARG="$ADF_META"
    # INFORMATIONAL ONLY (lr-367a21): computed in sh and handed in pre-built,
    # rather than re-querying audit.db inside the pipeline. See
    # _read_deterministic_gates's doc comment.
    DETERMINISTIC_GATES_PAYLOAD=$(_read_deterministic_gates)
    # Fenced, explicit-data-block rendering (lr-92d931), handed in pre-built
    # for the same reason DETERMINISTIC_GATES_PAYLOAD is.
    DETERMINISTIC_GATES_FENCED_PAYLOAD=$(_fence_deterministic_gates "$DETERMINISTIC_GATES_PAYLOAD")
    # review_fenced/adversarial_fenced arrive as pre-built JSON string
    # literals (or null) from the sanitize+fence helpers above. They are
    # handed over as temp-file paths, not argv strings: the adversarial report
    # is unbounded, and one argv string over MAX_ARG_STRLEN (~128 KiB) fails
    # exec with E2BIG, which would drop the Merge Gate's adversarial basis.
    # A source that is null, or already degraded, needs no file. A source
    # whose temp file cannot be created or written is marked degraded here
    # (marker + flag), never passed on as an empty path the pipeline would
    # read as None. The trap removes both files on error and signal paths.
    # The whole stage+emit runs in a subshell so its EXIT/INT/TERM/HUP traps
    # are the subshell's own: the caller's traps (cmd_ship's cmd_deps osv
    # temp-file cleanup is one) are never replaced and need no restore.
    # Its output is captured and printed only when the stage succeeded; a
    # failed stage returns 1 with no payload rather than leaving a partial
    # one.
    if _bgs_summary=$(
    _bgs_review_tmp=""
    _bgs_adv_tmp=""
    trap '_bgs_cleanup_payload_tmp' EXIT
    trap '_bgs_cleanup_payload_tmp; exit 130' INT
    trap '_bgs_cleanup_payload_tmp; exit 143' TERM
    trap '_bgs_cleanup_payload_tmp; exit 129' HUP
    if [ "$REVIEW_DEGRADED" != "true" ] && [ "$REVIEW_FENCED_PAYLOAD" != "null" ]; then
      _bgs_review_tmp=$(_stage_payload_file clagentic-gate-review "$REVIEW_FENCED_PAYLOAD") || {
        _bgs_review_tmp=""
        REVIEW_DEGRADED=true
        REVIEW_FENCED_PAYLOAD=$_GATE_REVIEW_UNAVAILABLE_FENCED
        REVIEW_SHA_VALUE=""
      }
    fi
    if [ "$ADVERSARIAL_REPORT_DEGRADED" != "true" ] && [ "$ADVERSARIAL_FENCED_PAYLOAD" != "null" ]; then
      _bgs_adv_tmp=$(_stage_payload_file clagentic-gate-adversarial "$ADVERSARIAL_FENCED_PAYLOAD") || {
        _bgs_adv_tmp=""
        ADVERSARIAL_REPORT_DEGRADED=true
        ADVERSARIAL_FENCED_PAYLOAD=$_GATE_ADVERSARIAL_UNAVAILABLE_FENCED
      }
    fi
    ds_findings_call -e object render gate-summary \
      --threshold "$THRESHOLD" \
      --adversarial-missing "$ADVERSARIAL_MISSING" --adversarial-degraded "$ADVERSARIAL_DEGRADED" \
      --adf "$ADF_ARG" --adf-meta "$ADF_META_ARG" \
      --det-gates "$DETERMINISTIC_GATES_PAYLOAD" --det-gates-fenced "$DETERMINISTIC_GATES_FENCED_PAYLOAD" \
      --review-fenced-file "$_bgs_review_tmp" --adversarial-fenced-file "$_bgs_adv_tmp" \
      --review-sha "$REVIEW_SHA_VALUE" --review-degraded "$REVIEW_DEGRADED" \
      --adversarial-report-degraded "$ADVERSARIAL_REPORT_DEGRADED" \
      --adf-degraded "$ADF_FINDINGS_DEGRADED" \
      --review-unavailable "$_GATE_REVIEW_UNAVAILABLE_FENCED" \
      --adversarial-unavailable "$_GATE_ADVERSARIAL_UNAVAILABLE_FENCED" \
      --adf-unavailable "$_GATE_ADVERSARIAL_FINDINGS_UNAVAILABLE_FENCED"
    ); then
      printf '%s\n' "$_bgs_summary"
      return 0
    fi
    printf '[gates/build-gate-summary] the finding pipeline could not build the gate summary; failing closed with no payload\n' 1>&2
    return 1
  fi

  # No JSON encoder available (lr-7047bf, site 1.12: this branch used to
  # emit a normal-shaped envelope -- adversarial: null, all counts 0,
  # resolved_change_class: null -- and return 0, which cmd_merge_gate and the
  # merge-gate LLM would read as an ordinary "nothing to report" clean pass
  # rather than "this environment could not evaluate the gate summary at
  # all." gate_summary_degraded: true names that distinction explicitly so
  # cmd_merge_gate can refuse deterministically (same short-circuit shape as
  # stale_payload below) instead of silently proceeding on a payload it
  # could not actually build. adversarial is still dropped here -- arbitrary
  # content cannot be safely JSON-encoded without jq or python3 -- but the
  # caller is now told this happened rather than inferring it from an
  # envelope that looks identical to a genuinely empty one.
  # deterministic_gates/deterministic_gates_fenced (lr-92d931): this branch
  # has no jq and no python3, so deterministic_gates was never populated
  # here even before this fix -- _read_deterministic_gates/
  # _fence_deterministic_gates both themselves prefer jq then python3 for
  # their own JSON handling and would degrade to the same audit-db-
  # unavailable shape if called, so there is nothing gained by attempting
  # the call in an environment already known to lack both JSON tools.
  # Emitting the literal audit-db-unavailable envelope directly here (same
  # values _read_deterministic_gates itself falls back to) keeps this
  # degraded branch schema-complete with the other two emitter branches
  # rather than omitting the field entirely, and keeps it fenced per this
  # codebase's now-settled convention (every external-text payload field is
  # both sanitized and fenced) -- there is no free text in this fixed
  # fallback shape to sanitize, only the fence itself to add.
  DETGATES_UNAVAILABLE_JSON='{"secrets": null, "deps": null, "sast": null, "audit_db_unavailable": true}'
  DETGATES_UNAVAILABLE_FENCED='"===BEGIN DETERMINISTIC GATES DATA===\n{\n  \"secrets\": null,\n  \"deps\": null,\n  \"sast\": null,\n  \"audit_db_unavailable\": true\n}\n===END DETERMINISTIC GATES DATA==="'
  # review_fenced/adversarial_fenced/review_sha and the two *_degraded flags:
  # schema-complete with the other branches. Review and adversarial text
  # cannot be encoded without a JSON tool, so none is ever embedded raw (the
  # old raw review embed was the same unsanitized, unfenced path this change
  # closes). A source that exists arrives here already degraded (the helpers
  # above fail closed without an encoder): the fixed unavailable marker plus
  # the flag set. An absent source stays null/false.
  # cmd_merge_gate refuses this envelope before any LLM call.
  # printf, not echo: dash's echo expands the literal \n sequences inside
  # DETGATES_UNAVAILABLE_FENCED into real newlines, corrupting the JSON.
  printf '%s\n' "{\"review_fenced\": $REVIEW_FENCED_PAYLOAD, \"review_sha\": \"\", \"review_degraded\": $REVIEW_DEGRADED, \"adversarial_fenced\": $ADVERSARIAL_FENCED_PAYLOAD, \"adversarial_report_degraded\": $ADVERSARIAL_REPORT_DEGRADED, \"adversarial_missing\": $ADVERSARIAL_MISSING, \"adversarial_degraded\": $ADVERSARIAL_DEGRADED, \"adversarial_findings\": [], \"adversarial_findings_fenced\": \"===BEGIN ADVERSARIAL FINDINGS DATA===\\n[]\\n===END ADVERSARIAL FINDINGS DATA===\", \"adversarial_blocking_count\": 0, \"adversarial_advisory_count\": 0, \"resolved_change_class\": null, \"adversarial_downgraded_by_class_count\": 0, \"adversarial_findings_dropped_count\": 0, \"threshold\": \"$THRESHOLD\", \"deterministic_gates\": $DETGATES_UNAVAILABLE_JSON, \"deterministic_gates_fenced\": $DETGATES_UNAVAILABLE_FENCED, \"gate_summary_degraded\": true}"
}

# cmd_render_manifest [FILE] (lr-37a9c8) — pretty-print the gate attestation
# manifest for operator inspection, mirroring cmd_render_review's own
# posture for last-review.json. A missing/absent manifest is reported as an
# explicit error (exit 1), never printed as an empty/clean-looking manifest
# -- consistent with acceptance criterion 4 ("missing manifest is reported
# as failure, never inferred as success").
cmd_render_manifest() {
  _gate_check_args render-manifest "" "FILE" "$@" || return 2
  FILE="${1:-$(_gate_manifest_path)}"
  [ -f "$FILE" ] || { echo "no gate attestation manifest at $FILE -- absence is reported, never inferred as a clean run" 1>&2; return 1; }
  if command -v jq >/dev/null 2>&1; then
    jq -r '
      "== clagentic-lite gate attestation manifest ==",
      ("branch: " + (.branch // "<unknown>")),
      ("head_sha: " + (.head_sha // "<unresolved>")),
      ("complete: " + ((.complete // false) | tostring)),
      ("degraded: " + ((.degraded // false) | tostring)),
      ""
    ' "$FILE"
    _render_gate_manifest_lines
  else
    cat "$FILE"
  fi
}

# _review_class_footer FILE -- prints one static hand-off line when at least
# one finding names a non-isolated issue_class, nothing otherwise. The line is
# fully static (count-agnostic wording, so no plural defect) and never carries
# model-authored text, so no _llm_field_sanitize call is needed (GATES.md
# review-finding table). The count is only a presence test. Display only:
# severity_blockers() never reads issue_class/class_fix.
#
# The single predicate for "this finding names a non-isolated class" (null,
# empty, and "none — isolated" all count as isolated) lives in findings.py,
# shared by the footer and cmd_render_review so the two cannot drift apart.
_review_class_footer() {
  # A failure returns nonzero with a message: a silent return 0 here would
  # report a successful render with the footer dropped.
  ds_findings_call -e any render class-footer "$1" || return 1
}

cmd_render_review() {
  _gate_check_args render-review "" "FILE" "$@" || return 2
  FILE="${1:-$REPO_ROOT/.clagentic/lite/last-review.json}"
  [ -f "$FILE" ] || { echo "no review file at $FILE" 1>&2; return 1; }
  # Display only: it never gates /ship. Suffixes, class lines and the class
  # footer are all produced by findings.py render review.
  ds_findings_call -e any render review "$FILE" || return 1
}

# cmd_dispositions_lint [FILE]
#
# Validates the dispositions in force (.clagentic/dispositions.json, plus the
# legacy deferrals/acks files still read for one release) or the one FILE
# against the entry schema the code verdict applies: every entry needs an id,
# gates, a match, a kind, a rationale, who and when; a mitigated entry must
# name its control. An entry that fails is ignored by the verdict, loudly, so
# this lint exists to catch it before the verdict does. Exit 1 when any entry
# is invalid (or python3 is missing: nothing can be validated without it).
# The file is operator-owned (the Builder role is blocked from writing it), so
# this is a check, not a generator.
cmd_dispositions_lint() {
  _gate_check_args dispositions-lint "" "FILE" "$@" || return 2
  if [ "$#" -gt 0 ]; then
    [ -f "$1" ] || { echo "[gates/dispositions-lint] no file at $1" 1>&2; return 1; }
    ds_findings_call -e any -o 1 dispositions lint --root "$REPO_ROOT" "$1"
  else
    ds_findings_call -e any -o 1 dispositions lint --root "$REPO_ROOT"
  fi
  return $?
}

# cmd_deferrals_lint [FILE] — deprecated alias kept for one release.
cmd_deferrals_lint() {
  echo "[gates/deferrals-lint] DEPRECATED: use 'gates dispositions-lint'; deferrals.json is read for one more release and is linted with the rest" 1>&2
  cmd_dispositions_lint "$@"
}

# cmd_evaluate — the standalone alias of findings.py evaluate: unified findings
# JSON (or, with --format markdown, the Auditor's report) on stdin, the code
# verdict on stdout, exit 1 when BLOCKED. Runs from here are recorded in the
# same per-HEAD accumulation as the gates' own runs, but they are NOT gate
# runs: they write no ledger entry, so they never satisfy `gates ship`
# (fail closed). Options are findings.py evaluate's; --root defaults to this
# repository.
cmd_evaluate() {
  _gate_check_args evaluate "--no-input --json --gate= --format= --scope= --caller= --root= --head= --base= --default-branch= --threshold= --today= --annotate= --attach-to= --json-out=" "" "$@" || return 2
  _ev_has_root=0
  _ev_no_input=0
  for _ev_arg in "$@"; do
    case "$_ev_arg" in
      --root|--root=*) _ev_has_root=1 ;;
      --no-input) _ev_no_input=1 ;;
    esac
  done
  [ "$_ev_has_root" = "1" ] || set -- --root "$REPO_ROOT" "$@"
  if [ "$_ev_no_input" = "1" ]; then
    ds_findings_call -e any -o 1 evaluate "$@"
  else
    ds_findings_call -s -e any -o 1 evaluate "$@"
  fi
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
  _gate_check_args audit-vocab-lint "" "FILE" "$@" || return 2
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
  _gate_check_args ship "" "" "$@" || return 2
  echo "[gates/ship] running gate sequence (enabled: ${CLAGENTIC_GATES:-all})"
  # Gate attestation manifest (lr-37a9c8): written unconditionally, before
  # any gate runs -- see the module doc comment above _gate_manifest_path
  # for why absence/incompleteness, not a lazily-created file, is what makes
  # a crashed or killed-mid-run ship honestly reportable to every consumer.
  _manifest_init
  _SHIP_DECLARED_GATES="bleed secrets deps sast review adversarial merge-gate"
  # ship_step_skip: print + audit-log a skipped gate. Every gate decision —
  # including the decision to skip — lands in audit.db per AGENTS.md §6.
  ship_step_skip() {
    echo "[gates/ship] skip $1 (not in CLAGENTIC_GATES)"
    cmd_log_run "$1" skip "not in CLAGENTIC_GATES=${CLAGENTIC_GATES:-}"
    _manifest_set_gate "$1" skipped "n/a" "" "" "[]" "" "not in CLAGENTIC_GATES=${CLAGENTIC_GATES:-}"
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
  # Deterministic gates (secrets/deps/sast/bleed): no LLM path, so "path" is
  # always "n/a" and brand/model are always empty -- FAIL-CLOSED ON
  # DEGRADATION per this task's policy (a missing tool already blocks per
  # AGENTS.md §4; the manifest just records that same outcome under the
  # shared vocabulary rather than inventing a parallel one).
  if gate_enabled bleed;   then cmd_bleed   && _manifest_set_gate bleed   ran "n/a" "" "" "[]" "" "" || { _manifest_set_gate bleed failed "n/a" "" "" "[]" "" ""; echo "[gates/ship] BLOCKED at internal-bleed"; ship_step_hint; _manifest_finalize "$_SHIP_DECLARED_GATES"; exit 1; }; else ship_step_skip bleed;   fi
  if gate_enabled secrets; then cmd_secrets && _manifest_set_gate secrets ran "n/a" "" "" "[]" "" "" || { _manifest_set_gate secrets failed "n/a" "" "" "[]" "" ""; echo "[gates/ship] BLOCKED at secrets";    ship_step_hint; _manifest_finalize "$_SHIP_DECLARED_GATES"; exit 1; }; else ship_step_skip secrets; fi
  if gate_enabled deps;    then cmd_deps    && _manifest_set_gate deps    ran "n/a" "" "" "[]" "" "" || { _manifest_set_gate deps failed "n/a" "" "" "[]" "" ""; echo "[gates/ship] BLOCKED at deps";       ship_step_hint; _manifest_finalize "$_SHIP_DECLARED_GATES"; exit 1; }; else ship_step_skip deps;    fi
  if gate_enabled sast;    then cmd_sast    && _manifest_set_gate sast    ran "n/a" "" "" "[]" "" "" || { _manifest_set_gate sast failed "n/a" "" "" "[]" "" ""; echo "[gates/ship] BLOCKED at sast";       ship_step_hint; _manifest_finalize "$_SHIP_DECLARED_GATES"; exit 1; }; else ship_step_skip sast;    fi
  if gate_enabled review; then
    _review_watermark=$(_manifest_audit_watermark)
    _review_rc=0
    cmd_review || _review_rc=$?
    if [ "$_review_rc" -eq 2 ]; then
      echo "[gates/ship] INFRA_DEGRADED at review — reviewer infrastructure failed, no real review occurred"
      ship_step_hint
      cmd_log_run ship block "infra-degraded at review"
      _manifest_record_llm_gate review reviewer degraded "$_review_watermark" "infra-degraded at review"
      _manifest_finalize "$_SHIP_DECLARED_GATES"
      exit 2
    elif [ "$_review_rc" -ne 0 ]; then
      echo "[gates/ship] REVIEW_BLOCKED at review (severity threshold ${CLAGENTIC_BLOCK_SEVERITY:-high})"
      cmd_log_run ship block "review-blocked at review"
      _manifest_record_llm_gate review reviewer failed "$_review_watermark" "review-blocked at review"
      _manifest_finalize "$_SHIP_DECLARED_GATES"
      exit 1
    fi
    _manifest_record_llm_gate review reviewer ran "$_review_watermark" ""
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
  # merge-gate step that runs immediately after this line. The manifest
  # records the same distinction under its own outcome vocabulary
  # (degraded, not a bare "ran") so a degraded-but-non-blocking auditor is
  # still visible as a LOUD, greppable state, per this task's policy.
  #
  # cmd_review runs immediately above and writes a "review" ledger pass
  # entry at HEAD before returning -- previously, cmd_adversarial's OWN
  # delta-base lookup had no gate discriminator of its own, so it consumed
  # that same-run review anchor and resolved HEAD..HEAD (an empty diff),
  # which get_review_diff then handed straight to the auditor with no
  # check, reporting a silent clean audit on `gates ship`'s first run on
  # EVERY branch. Fixed at the source: cmd_adversarial now calls
  # get_review_diff with its own "adversarial" gate name, so it only ever
  # anchors on its OWN prior passing verdicts, never review's -- no
  # ordering change or `cmd_ship`-local workaround is needed here,
  # cmd_adversarial gets the same non-empty range it would get standalone
  # regardless of what cmd_review just wrote.
  if gate_enabled adversarial; then
    _adv_watermark=$(_manifest_audit_watermark)
    _adv_rc=0
    cmd_adversarial || _adv_rc=$?
    if [ "$_adv_rc" -eq "$_ADV_UNRECORDED_RC" ]; then
      # Not recorded and no marker to make the merge gate refuse: ship must
      # not go on as if the audit were on record.
      _manifest_record_llm_gate adversarial auditor failed "$_adv_watermark" "adversarial findings could not be recorded"
      echo "[gates/ship] BLOCKED at adversarial: its findings could not be recorded"; ship_step_hint
      _manifest_finalize "$_SHIP_DECLARED_GATES"
      exit 1
    fi
    if [ "$_adv_rc" -eq 2 ]; then
      _manifest_record_llm_gate adversarial auditor degraded "$_adv_watermark" "adversarial ran degraded (non-blocking)"
    else
      _manifest_record_llm_gate adversarial auditor ran "$_adv_watermark" ""
    fi
  else
    ship_step_skip adversarial
  fi
  if gate_enabled merge-gate; then
    _mg_watermark=$(_manifest_audit_watermark)
    if cmd_merge_gate; then
      _manifest_record_llm_gate merge-gate gate ran "$_mg_watermark" ""
    else
      _manifest_record_llm_gate merge-gate gate failed "$_mg_watermark" "merge-gate refused or degraded"
      echo "[gates/ship] BLOCKED at merge-gate"; ship_step_hint
      _manifest_finalize "$_SHIP_DECLARED_GATES"
      exit 1
    fi
  else
    ship_step_skip merge-gate
  fi

  _manifest_finalize "$_SHIP_DECLARED_GATES"
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
  _SHIP_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_SHIP_TIMEOUT_SEC "${CLAGENTIC_SHIP_TIMEOUT_SEC:-}" 120)

  # Push + open a change request via the host adapter (lr-2b07a8), else
  # print a template. Host-neutral by contract (docs/GATES.md "Host adapter
  # contract"): gate logic never names a vendor CLI/API directly -- see
  # scripts/host-adapter.sh for the one place that's allowed.
  if _git remote get-url origin >/dev/null 2>&1; then
    # The command word handed to run_bounded must be a real executable:
    # $DS_TIMEOUT_CMD execs it, and `_git` is a shell function, so passing it
    # here made every push fail to start and logged a fully green ship as a
    # push failure. Spell out `git -C "$REPO_ROOT"` instead.
    _SHIP_PUSH_ERR=$(mktemp -t clagentic-ship-push-err.XXXXXX) || _SHIP_PUSH_ERR=/dev/null
    _SHIP_PUSH_RC=0
    #
    # The push runs the enrolled pre-push hook (deps + sast, each under its own
    # bound) and the user's own chained hooks, so the push bound must cover
    # them: default = deps bound + sast bound + a network allowance, from the
    # same keys the hook uses. CLAGENTIC_SHIP_TIMEOUT_SEC overrides it.
    # GIT_TERMINAL_PROMPT=0 makes a missing credential fail fast with git's
    # own error instead of hanging until the bound.
    _SHIP_PUSH_OSV=$(ds_positive_int_or_warn CLAGENTIC_OSV_TIMEOUT_SEC "${CLAGENTIC_OSV_TIMEOUT_SEC:-}" 300)
    _SHIP_PUSH_SAST=$(ds_positive_int_or_warn CLAGENTIC_SAST_TIMEOUT_SEC "${CLAGENTIC_SAST_TIMEOUT_SEC:-}" 300)
    _SHIP_PUSH_DEFAULT=$((_SHIP_PUSH_OSV + _SHIP_PUSH_SAST + 120))
    _SHIP_PUSH_TIMEOUT=$(ds_positive_int_or_warn CLAGENTIC_SHIP_TIMEOUT_SEC "${CLAGENTIC_SHIP_TIMEOUT_SEC:-}" "$_SHIP_PUSH_DEFAULT")
    run_bounded "$_SHIP_PUSH_TIMEOUT" -- env GIT_TERMINAL_PROMPT=0 git -C "$REPO_ROOT" push -u origin "$BRANCH" 2>"$_SHIP_PUSH_ERR" || _SHIP_PUSH_RC=$?
    [ -s "$_SHIP_PUSH_ERR" ] && cat "$_SHIP_PUSH_ERR" 1>&2
    if [ "$_SHIP_PUSH_RC" -ne 0 ]; then
      _SHIP_PUSH_REASON=$(_bounded_failure_reason "$_SHIP_PUSH_RC" "$_SHIP_PUSH_TIMEOUT" "$_SHIP_PUSH_ERR" " (may include pre-push hook time)")
      [ "$_SHIP_PUSH_ERR" = /dev/null ] || rm -f "$_SHIP_PUSH_ERR"
      echo "[gates/ship] push $_SHIP_PUSH_REASON"
      cmd_log_run ship block "push $_SHIP_PUSH_REASON"
      exit 1
    fi
    [ "$_SHIP_PUSH_ERR" = /dev/null ] || rm -f "$_SHIP_PUSH_ERR"
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
    # host_adapter_open_change_request is the ONE owner of "which PR, created
    # or reused": a single open-PR lookup, then `created <num>` or
    # `reused <num>` on stdout. A created PR already carries section 1 and the
    # marker in the body just rendered. A reused PR gets that body discarded
    # (a PR body is written only at create) and a delta comment on that same
    # number instead. Failure -- including a lookup that could not be
    # answered, where it never creates blind -- creates and comments nothing;
    # the push result stands.
    _SHIP_OPEN_RC=0
    _SHIP_OPEN_OUT=$(host_adapter_open_change_request "$DEFAULT_BRANCH" "$BRANCH" "$_SHIP_BODY_FILE") || _SHIP_OPEN_RC=$?
    [ -z "$_SHIP_BODY_FILE" ] || rm -f "$_SHIP_BODY_FILE"
    _SHIP_PR_OUTCOME=""
    _SHIP_PR_NUM=""
    if [ "$_SHIP_OPEN_RC" -eq 0 ]; then
      case "$_SHIP_OPEN_OUT" in
        created\ [0-9]*|reused\ [0-9]*)
          _SHIP_PR_OUTCOME=${_SHIP_OPEN_OUT%% *}
          _SHIP_PR_NUM=${_SHIP_OPEN_OUT#* }
          ;;
      esac
      case "$_SHIP_PR_NUM" in
        ""|*[!0-9]*) _SHIP_PR_OUTCOME="" ;;
      esac
    fi
    case "$_SHIP_PR_OUTCOME" in
      created) echo "[gates/ship] PR #${_SHIP_PR_NUM} created" ;;
      reused)
        echo "[gates/ship] PR #${_SHIP_PR_NUM} already open"
        _publish_ship_delta_comment "$BRANCH" "$_SHIP_HEAD_SHA" "$_SHIP_PR_NUM" ;;
      *)
        echo "[gates/ship] host-adapter open-change-request did not complete (it failed, timed out after ${_SHIP_TIMEOUT}s, or created a PR whose number could not be read) — nothing was commented on; check the host before opening a PR by hand (push result stands)" 1>&2
        ds_audit_log "ship-delta-publish" "block" "branch=${BRANCH:-<none>} head=${_SHIP_HEAD_SHA:-<unresolved>} reason=open-change-request-failed"
        ;;
    esac
  else
    REMOTE=$(_git remote get-url origin 2>/dev/null || echo "<remote>")
    echo "[gates/ship] no host adapter available — open a PR manually:"
    echo "  base=$DEFAULT_BRANCH head=$BRANCH remote=$REMOTE"
  fi
  _cmd_log_run_checked_pass ship "gates green; pushed $BRANCH"
}

# cmd_pre_push — hook entry point. git's pre-push hook contract delivers
# zero or more "<local ref> <local sha1> <remote ref> <remote sha1>" lines
# on stdin (one per ref being pushed) -- share/hook-shims/pre-push.template
# execs this script with that stdin passed through untouched. Snapshot it
# to a temp file EXACTLY ONCE here, before either gate runs, and export its
# path via CLAGENTIC_GATE_REFS_FILE (lr-1ad8da) -- cmd_deps/cmd_sast each
# read that snapshot independently for their own domain-skip decision, so
# neither gate drains a pipe the other one still needs. A non-hook,
# non-tty invocation of `gates.sh pre-push` (e.g. manual testing with no
# stdin at all) still produces a valid, empty snapshot, which
# _gate_resolve_changed_paths correctly reports as "no ref lines" --
# inconclusive, and therefore always runs both gates (fail-closed by
# construction).
cmd_pre_push() {
  # git invokes the hook as `pre-push <remote-name> <remote-url>`; accept
  # exactly those two positionals or none, and nothing else (flags included).
  case "$#" in
    0|2) : ;;
    *) echo "usage: gates.sh pre-push [<remote-name> <remote-url>]" 1>&2; exit 2 ;;
  esac
  for _pp_arg in "$@"; do
    case "$_pp_arg" in
      -*) echo "gates.sh pre-push: unknown option '$_pp_arg'" 1>&2; echo "usage: gates.sh pre-push [<remote-name> <remote-url>]" 1>&2; exit 2 ;;
    esac
  done
  _PRE_PUSH_REFS_FILE=$(mktemp -t clagentic-prepush-stdin.XXXXXX)
  cat > "$_PRE_PUSH_REFS_FILE"
  CLAGENTIC_GATE_REFS_FILE="$_PRE_PUSH_REFS_FILE"
  export CLAGENTIC_GATE_REFS_FILE

  cmd_deps || { rm -f "$_PRE_PUSH_REFS_FILE"; echo "[gates/pre-push] diagnose with the Troubleshooter agent (plugins/clagentic-lite/agents/troubleshooter.md)"; exit 1; }
  cmd_sast || { rm -f "$_PRE_PUSH_REFS_FILE"; echo "[gates/pre-push] diagnose with the Troubleshooter agent (plugins/clagentic-lite/agents/troubleshooter.md)"; exit 1; }
  rm -f "$_PRE_PUSH_REFS_FILE"
  [ "${CLAGENTIC_REVIEW_ON_PUSH:-0}" = "1" ] && { cmd_review || exit 1; }
  exit 0
}

cmd_digest() {
  _gate_check_args digest "" "" "$@" || return 2
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
    # not_applicable (lr-1ad8da): a THIRD state, deliberately rendered in its
    # own dim-but-distinct color rather than reusing skip's -- a skip means
    # "opted out" (tool missing, explicit bypass); not_applicable means "this
    # gate's verdict provably cannot depend on what changed here." Reusing
    # skip's color would visually collapse two outcomes this whole feature
    # exists to keep distinguishable (task requirement 3: a skip rendering as
    # a pass would be the fifth report in done/ about exactly this defect
    # class -- not_applicable must not render as anything BUT itself either).
    not_applicable) printf '%s%s%s' "$C_DIM" "$1" "$C_RESET" ;;
    *)     printf '%s' "$1" ;;
  esac
}

cmd_status() {
  _gate_check_args status "" "N" "$@" || return 2
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
  _gate_check_args tail "--no-follow" "" "$@" || return 2
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

  # Numeric guard: every other timeout/interval var in this file is
  # validated before use; INTERVAL was the one sibling that reached
  # `sleep "$INTERVAL"` unguarded. Non-numeric would fail in `sleep`, and 0
  # would turn the poll into a tight loop against the audit DB, so both fall
  # back to the default with a WARN.
  INTERVAL=$(ds_positive_int_or_warn CLAGENTIC_TAIL_INTERVAL_SEC "${CLAGENTIC_TAIL_INTERVAL_SEC:-}" 1)
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

  # log-run takes GATE OUTCOME [DETAILS] positionally and cmd_log_run is also
  # called internally, so its argument-count check sits here, before dispatch,
  # rather than inside the function or the case arm.
  if [ "${1:-}" = "log-run" ] && { [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; }; then
    echo "usage: gates.sh log-run GATE OUTCOME [DETAILS]" 1>&2
    exit 2
  fi

  case "${1:-}" in
    init)           shift; cmd_init "$@" ;;
    bleed)          shift; cmd_bleed "$@" ;;
    secrets)        shift; cmd_secrets "$@" ;;
    deps)           shift; cmd_deps "$@" ;;
    sast)           shift; cmd_sast "$@" ;;
    review)         shift; cmd_review "$@" ;;
    adversarial)    shift; cmd_adversarial "$@" ;;
    merge-gate)     shift; cmd_merge_gate "$@" ;;
    render-review)  shift; cmd_render_review "$@" ;;
    render-manifest) shift; cmd_render_manifest "$@" ;;
    dispositions-lint) shift; cmd_dispositions_lint "$@" ;;
    deferrals-lint) shift; cmd_deferrals_lint "$@" ;;
    evaluate)       shift; cmd_evaluate "$@" ;;
    audit-vocab-lint) shift; cmd_audit_vocab_lint "$@" ;;
    ship)           shift; cmd_ship "$@" ;;
    pre-push)       shift; cmd_pre_push "$@" ;;
    log-run)        shift; cmd_log_run "$@" ;;
    digest)         shift; cmd_digest "$@" ;;
    status)         shift; cmd_status "$@" ;;
    tail)           shift; cmd_tail "$@" ;;
    *) echo "usage: gates.sh {init|bleed [--full-scan]|secrets [--full-scan]|deps|sast|review [--full-review] [--since-last-review] [--reset-dedup]|adversarial [--full-review]|merge-gate [--recheck]|render-review|render-manifest [FILE]|dispositions-lint [FILE]|evaluate [OPTIONS]|audit-vocab-lint [FILE]|ship|pre-push|log-run|digest|status|tail [--no-follow]}" 1>&2; exit 1 ;;
  esac
elif [ -z "${CLAGENTIC_GATES_DELIBERATE_SOURCE:-}" ]; then
  echo "gates.sh: CLAGENTIC_GATES_SOURCE_ONLY is set but CLAGENTIC_GATES_DELIBERATE_SOURCE is not -- dispatch suppressed with no provenance asserting deliberate sourcing, refusing to report a false pass. If dot-sourcing this file on purpose, set both variables. If you did not mean to set CLAGENTIC_GATES_SOURCE_ONLY, unset it." 1>&2
  exit 1
fi
