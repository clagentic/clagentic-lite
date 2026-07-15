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

set -e
. "$(dirname "$0")/platform.sh"
ds_load_env
. "$(dirname "$0")/review-merge.sh"

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

AUDIT_DB="$REPO_ROOT/.clagentic/lite/audit.db"
mkdir -p "$REPO_ROOT/.clagentic/lite"

cmd_init() {
  sqlite3 "$AUDIT_DB" <<'SQL'
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
  BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  TS=$(ds_date_iso)
  # Every interpolated value must go through the same escape helper. A branch
  # named `feat/o'hare` would otherwise corrupt the INSERT under set -e.
  GATE_ESC=$(ds_sql_escape "$GATE")
  OUT_ESC=$(ds_sql_escape "$OUTCOME")
  DETAILS_ESC=$(ds_sql_escape "$DETAILS")
  BRANCH_ESC=$(ds_sql_escape "$BRANCH")
  sqlite3 "$AUDIT_DB" \
    "INSERT INTO gate_runs (ts, gate, outcome, details, branch) VALUES ('$TS', '$GATE_ESC', '$OUT_ESC', '$DETAILS_ESC', '$BRANCH_ESC');"
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
  _SECRETS_STAGED=$(_git diff --cached --name-only 2>/dev/null)
  _SECRETS_DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  _SECRETS_CURRENT_BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  _SECRETS_ON_FEATURE=0
  if [ -z "$_SECRETS_STAGED" ] && [ -n "$_SECRETS_CURRENT_BRANCH" ] && [ "$_SECRETS_CURRENT_BRANCH" != "$_SECRETS_DEFAULT_BRANCH" ] && [ "$_SECRETS_CURRENT_BRANCH" != "HEAD" ]; then
    _SECRETS_ON_FEATURE=1
  fi

  # Probe by capability, not version string — `gitleaks version` output
  # format varies (`v8.18.4`, `8.18.4`, multi-line banner). The `git`
  # subcommand was added in 8.18; if `gitleaks git --help` exits 0 we use
  # it, otherwise we fall back to `gitleaks protect`.
  if gitleaks git --help >/dev/null 2>&1; then
    if [ "$_SECRETS_ON_FEATURE" = "1" ]; then
      # No staged changes on a feature branch — scan the branch's committed
      # history rather than the (empty) index. This catches secrets in
      # already-committed hunks that would otherwise be invisible to --staged.
      printf '[gates/secrets] no staged changes — scanning branch history with gitleaks git\n' 1>&2
      # shellcheck disable=SC2086
      if gitleaks git --redact --no-banner $CFG_ARG; then
        cmd_log_run secrets pass "branch history scan (no staged changes)"
      else
        cmd_log_run secrets block "gitleaks reported findings (branch history scan)"
        return 1
      fi
    else
      # shellcheck disable=SC2086
      if gitleaks git --staged --pre-commit --redact --no-banner $CFG_ARG; then
        cmd_log_run secrets pass ""
      else
        cmd_log_run secrets block "gitleaks reported findings"
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
      if gitleaks protect --staged --redact --no-banner $CFG_ARG; then
        cmd_log_run secrets pass ""
      else
        cmd_log_run secrets block "gitleaks reported findings"
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
      osv-scanner scan source -r --format=json "--config=$_OSV_TMP" $_OSV_EXCL_FLAGS . > "$_OSV_JSON" || _OSV_STATUS=$?
    else
      osv-scanner scan --recursive --format=json "--config=$_OSV_TMP" . > "$_OSV_JSON" || _OSV_STATUS=$?
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
        cmd_log_run deps pass "osv-scanner findings below $SEVERITY threshold"
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

    if osv-scanner "$@"; then
      cmd_log_run deps pass ""
    else
      cmd_log_run deps block "osv-scanner reported vulnerabilities"
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
  # Internal-bleed scan: grep committed tracked files for patterns loaded from
  # a user-supplied pattern file. Patterns are BRE (grep -f), one per line;
  # lines starting with # and blank lines are ignored.
  #
  # Pattern file resolution (first found wins):
  #   1. ${CLAGENTIC_PROJECT_ROOT:-$PWD}/.clagentic/bleed-patterns  (repo-level)
  #   2. $HOME/.config/clagentic/bleed-patterns                     (global user config)
  #
  # If neither exists, the gate skips non-blocking with a warning — the gate
  # is opt-in via pattern config, not fail-closed on missing config.
  # Project-level exclusions: .clagentic-bleed-ignore (one path-substring per line).

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

  # Collect tracked file list; warn but don't block if git fails.
  _BLEED_FILES=$(git -C "$REPO_ROOT" ls-files 2>/dev/null) || {
    rm -f "$_BLEED_TMP"
    echo "[gates/bleed] git ls-files failed — skipping" 1>&2
    cmd_log_run bleed pass "git ls-files failed (non-blocking)"
    return 0
  }

  # Always exclude .git/ and .clagentic/ (binary DBs, pattern files).
  _BLEED_FILES=$(printf '%s\n' "$_BLEED_FILES" \
    | grep -v -e '^\.git/' -e '^\.clagentic/' || true)

  if [ -z "$_BLEED_FILES" ]; then
    rm -f "$_BLEED_TMP"
    cmd_log_run bleed pass "no files to scan"
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
    cmd_log_run bleed pass "all files excluded"
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
  cmd_log_run bleed pass "no bleed patterns found"
  return 0
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
  # Semgrep natively honors .semgrepignore at the repo root. Add paths or rules there to suppress findings.
  if semgrep --config=auto --error --severity=ERROR; then
    cmd_log_run sast pass ""
  else
    cmd_log_run sast block "semgrep reported ERROR-severity findings"
    return 1
  fi
}

# get_review_diff — prints the best available diff to stdout for use by
# cmd_review and cmd_adversarial.
#
# Priority:
#   1. Staged diff (git diff --cached) — normal pre-commit path.
#   2. --since-last-review: when REVIEW_SINCE_LAST=1 is set (by cmd_review
#      parsing the --since-last-review flag) AND .clagentic/lite/last-review.json
#      contains a _clagentic_diff_sha, diff <that-sha>..HEAD instead of the
#      full origin/<default>..HEAD branch diff. This is the structural fix for
#      the death-spiral (many fix-commits accumulating into an unreviewed diff).
#   3. Branch diff against origin/<default_branch> — PR path when index is
#      clean but we are on a feature branch with committed changes.
#   4. Empty — on the default branch with no staged changes; review will see
#      an empty diff (the merge-gate has an explicit null-review rule for this).
#
# Prints one diagnostic line to stderr indicating which mode is active.
get_review_diff() {
  DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  CURRENT_BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")

  if _git diff --cached --name-only 2>/dev/null | grep -q .; then
    printf '[gates/review] using staged diff\n' 1>&2
    _git diff --cached --unified=3 2>/dev/null
    return 0
  fi

  # --since-last-review: diff from the SHA in last-review.json..HEAD.
  # Activated only when REVIEW_SINCE_LAST=1 (set by cmd_review's flag parsing).
  if [ "${REVIEW_SINCE_LAST:-0}" = "1" ]; then
    _grd_last_json="$REPO_ROOT/.clagentic/lite/last-review.json"
    _grd_last_sha=""
    if [ -f "$_grd_last_json" ]; then
      if command -v jq >/dev/null 2>&1; then
        _grd_last_sha=$(jq -r '._clagentic_diff_sha // ""' "$_grd_last_json" 2>/dev/null)
      elif command -v python3 >/dev/null 2>&1; then
        _grd_last_sha=$(python3 -c \
          'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("_clagentic_diff_sha",""))' \
          "$_grd_last_json" 2>/dev/null)
      fi
    fi
    if [ -n "$_grd_last_sha" ]; then
      printf '[gates/review] --since-last-review: diffing %s..HEAD\n' "$_grd_last_sha" 1>&2
      _git diff "${_grd_last_sha}..HEAD" --unified=3 2>/dev/null
      return 0
    else
      printf '[gates/review] --since-last-review: no prior review SHA found; falling through to branch diff\n' 1>&2
    fi
  fi

  if [ -n "$CURRENT_BRANCH" ] && [ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ] && [ "$CURRENT_BRANCH" != "HEAD" ]; then
    # Fetch the base ref so the comparison is accurate even in a fresh clone.
    # Failure here is non-fatal — git diff will simply fall back to local state.
    _git fetch origin "$DEFAULT_BRANCH" >/dev/null 2>&1 || true
    printf '[gates/review] no staged changes — using branch diff vs origin/%s\n' "$DEFAULT_BRANCH" 1>&2
    _git diff "origin/${DEFAULT_BRANCH}...HEAD" --unified=3 2>/dev/null
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

# _extract_findings_json FILE — print FILE's .findings array (or "[]" on any
# failure). jq-then-python3 fallback, matching the pattern used throughout
# this file (e.g. _cross_round_dedup's own findings extraction) rather than
# introducing a third way to read the same shape.
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

# _invariant_feed_max_field_chars — per-field length cap applied at the write
# boundary (see _invariant_feed_sanitize_field). Configurable via
# CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS (default 500 — generous for a
# one-sentence CWE title/statement, small enough that a single adversarial-
# controlled finding cannot balloon invariants.json or the prompt it is later
# injected into).
_invariant_feed_max_field_chars() {
  _ifmfc_max="${CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS:-500}"
  case "$_ifmfc_max" in ''|*[!0-9]*) _ifmfc_max=500 ;; esac
  printf '%s' "$_ifmfc_max"
}

# _invariant_feed_sanitize_field TEXT — neutralize adversarial-LLM-controlled
# finding text before it is ever written to invariants.json (lr-cda4b9,
# hardening the round-trip lr-24c80e/lr-63359e shipped). WRITE-BOUNDARY
# sanitization, not read-time: invariants.json has exactly one writer
# (_invariant_feed_append, below) and an unknown/growing number of future
# readers (today: ds_adversarial_prompt; potentially the merge-gate summary
# or a future consumer) — cleaning once at ingest means every reader gets
# clean data for free, instead of every current AND future reader needing to
# remember to re-sanitize. Applied to every field that ultimately traces back
# to adversarial/review LLM output: category, file, and the distilled
# statement (which embeds the original finding message verbatim).
#
# Neutralizes prompt-control sequences without attempting semantic
# interpretation (this is gate plumbing, not a role — no LLM call here,
# consistent with _invariant_feed_distill's own "mechanical, not an LLM
# call" framing):
#   - Strips ASCII control/non-printable bytes (0x00-0x08, 0x0B-0x1F, 0x7F),
#     including ANSI/terminal escape sequences a hostile finding could embed
#     to visually spoof a delimiter or hide text from a human audit-log
#     reader. Newline (0x0A) and tab (0x09) are preserved — legitimate
#     structure in a multi-line finding message, not a control sequence.
#   - Collapses the delimiter label a hostile finding could forge to fake a
#     new INVARIANTS:/DEFERRED FINDINGS:/end-of-data marker — including the
#     literal fenced ===BEGIN INVARIANTS DATA===/===END INVARIANTS DATA===
#     markers ds_adversarial_prompt now emits (llm-client.sh) — and smuggle a
#     bare instruction after it: case-insensitively replaces any of those
#     literal label strings with a defanged spaced-out form. This does not
#     make the text nonsensical to a human reviewer (the words are still
#     legible) but prevents it from being byte-identical to the real
#     delimiter the model was told to trust. Without this, a finding
#     containing the literal fence string survives verbatim into
#     invariants.json and can forge a fake "===END INVARIANTS DATA==="
#     inside the block, escaping the fence entirely (BOBBIE, lr-cda4b9
#     follow-up).
#   - Caps length at _invariant_feed_max_field_chars, truncating rather than
#     rejecting — a merely-too-long finding is not attacker behavior, and
#     rejecting it would silently drop a real resolved-finding invariant
#     (fail-open posture matches the rest of the invariant-feed).
_invariant_feed_sanitize_field() {
  _ifsf_text="$1"
  _ifsf_max=$(_invariant_feed_max_field_chars)

  if command -v python3 >/dev/null 2>&1; then
    # Text goes through a temp file, NOT stdin: `python3 -` already reads the
    # script itself from stdin (the heredoc below), so piping the untrusted
    # text into the same stdin would either be silently discarded or
    # interleaved with the script depending on shell/buffering — the data
    # channel and the script channel must be different file descriptors.
    _ifsf_tmp=$(mktemp -t clagentic-inv-sanitize.XXXXXX)
    printf '%s' "$_ifsf_text" > "$_ifsf_tmp"
    python3 - "$_ifsf_tmp" "$_ifsf_max" <<'PYEOF'
import re
import sys

path, max_chars = sys.argv[1], int(sys.argv[2])
with open(path) as f:
    text = f.read()

# Strip ANSI/terminal escape sequences (CSI, OSC, and bare ESC-prefixed
# sequences) before the general control-char strip below, so a multi-byte
# escape sequence does not leave stray printable fragments behind.
text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)   # CSI: ESC [ ... letter
text = re.sub(r'\x1b\][^\x07\x1b]*(\x07|\x1b\\)', '', text)  # OSC: ESC ] ... BEL/ST
text = re.sub(r'\x1b.', '', text)                   # any remaining ESC + one byte

# Strip remaining control/non-printable bytes, preserving tab and newline.
text = ''.join(ch for ch in text if ch in ('\t', '\n') or 0x20 <= ord(ch) != 0x7f)

# Defang forged delimiter labels: a hostile finding message could contain
# the literal string "INVARIANTS:" or "DEFERRED FINDINGS:" -- or the fenced
# ===BEGIN/END INVARIANTS DATA=== markers ds_adversarial_prompt wraps this
# content in (llm-client.sh) -- to try to spoof a fresh data-block boundary
# once re-injected into a future prompt. Insert a zero-width-safe space so
# the string is still legible to a human but no longer byte-identical to the
# real delimiter.
for label in ("INVARIANTS:", "DEFERRED FINDINGS:", "END INVARIANTS",
              "END DEFERRED FINDINGS",
              "===BEGIN INVARIANTS DATA===", "===END INVARIANTS DATA==="):
    pattern = re.compile(re.escape(label), re.IGNORECASE)
    text = pattern.sub(lambda m: ' '.join(m.group(0)), text)

# Truncate so the FINAL string (content + suffix) fits within max_chars --
# slicing to max_chars and then appending the suffix would let the suffix
# push the total length past the configured cap (PEACHES, lr-cda4b9
# follow-up).
suffix = "...[truncated]"
if len(text) > max_chars:
    keep = max(max_chars - len(suffix), 0)
    text = text[:keep] + suffix

sys.stdout.write(text)
PYEOF
    _ifsf_status=$?
    rm -f "$_ifsf_tmp"
    return $_ifsf_status
  fi

  # No python3: best-effort POSIX fallback. tr strips the bulk of control
  # bytes (octal escapes for 0x01-0x08, 0x0B-0x1F, 0x7F; 0x00 cannot appear
  # in a shell string so no explicit strip needed); sed defangs the fenced
  # ===BEGIN/END INVARIANTS DATA=== markers specifically (literal, fixed-case
  # substitution — no GNU/BSD sed extension needed, unlike a general case-
  # insensitive label match); cut caps length. This path does NOT defang the
  # case-insensitive INVARIANTS:/DEFERRED FINDINGS: labels the python3 path
  # covers (no portable case-insensitive substitution without sed extensions
  # that vary GNU/BSD) — acceptable degradation given no-python3 already
  # means jq is the active JSON tool elsewhere in this codepath. The fenced
  # markers ARE covered here because they are the one label an attacker could
  # use to escape the fence entirely (BOBBIE, lr-cda4b9 follow-up), so this
  # path closes that specific gap even though it cannot close the general one.
  printf '%s' "$_ifsf_text" \
    | tr -d '\001-\010\013-\037\177' \
    | sed 's|===BEGIN INVARIANTS DATA===|= = =BEGIN INVARIANTS DATA= = =|g; s|===END INVARIANTS DATA===|= = =END INVARIANTS DATA= = =|g' \
    | cut -c "1-${_ifsf_max}"
}

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
# field is run through _invariant_feed_sanitize_field before it is ever
# written — a single write-boundary choke point rather than relying on every
# current and future reader to sanitize on its own.
_invariant_feed_append() {
  _ifa_file="$1"; _ifa_id="$2"; _ifa_category="$3"; _ifa_srcfile="$4"; _ifa_statement="$5"

  _ifa_category=$(_invariant_feed_sanitize_field "$_ifa_category")
  _ifa_srcfile=$(_invariant_feed_sanitize_field "$_ifa_srcfile")
  _ifa_statement=$(_invariant_feed_sanitize_field "$_ifa_statement")

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
  REVIEW_SINCE_LAST=0
  _crv_reset_dedup=0
  for _crv_arg in "$@"; do
    case "$_crv_arg" in
      --since-last-review) REVIEW_SINCE_LAST=1 ;;
      --reset-dedup)       _crv_reset_dedup=1 ;;
    esac
  done
  export REVIEW_SINCE_LAST

  # --reset-dedup: delete the persisted seen-keys file and exit.
  # Operator calls this to clear cross-round dedup state (e.g. after a major
  # rebase or when they want the next review to re-report all findings).
  _crv_seen_file="$REPO_ROOT/.clagentic/lite/review-seen-keys"
  if [ "$_crv_reset_dedup" = "1" ]; then
    if [ -f "$_crv_seen_file" ]; then
      rm -f "$_crv_seen_file"
      echo "[gates/review] cross-round dedup state reset (review-seen-keys deleted)"
      cmd_log_run review pass "cross-round dedup reset by --reset-dedup"
    else
      echo "[gates/review] cross-round dedup state already empty (review-seen-keys not found)"
      cmd_log_run review pass "cross-round dedup reset by --reset-dedup (file was absent)"
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
    printf '[gates/review] diff is %d bytes (threshold %d) — consider --since-last-review or squashing commits to reduce review scope\n' \
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
        "$TOOL_HOME/scripts/llm-client.sh" review < "$_crv_chunk" > "$_crv_env_file" 2>/dev/null || true
        # Audit one row per chunk.
        _crv_chunk_outcome="pass"
        if review_is_degraded "$_crv_env_file" 2>/dev/null; then
          _crv_chunk_outcome="degraded"
        fi
        cmd_log_run review-chunk "$_crv_chunk_outcome" \
          "chunk=${_crv_cidx}/${_crv_nchunks} bytes=${_crv_cbytes}"
      done

      # Merge all chunk envelopes into the final output.
      _crv_merged=$(merge_envelopes "$_crv_env_dir" "location")
      printf '%s\n' "$_crv_merged" > "$OUT"

      # Stamp the merged envelope with the current HEAD SHA — same logic as
      # the single-chunk path below.
      _review_sha=$(_git rev-parse HEAD 2>/dev/null || echo "")
      if [ -n "$_review_sha" ]; then
        _stamp_envelope "$OUT" "$_review_sha"
      fi

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
        rm -f "$_crv_diff_tmp"
        rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
        return 1
      fi
      cmd_log_run review pass "0 findings at >= $THRESHOLD (chunked)"
      cmd_render_review "$OUT"
      rm -f "$_crv_diff_tmp"
      rm -rf "$_crv_chunk_dir" "$_crv_env_dir"
      return 0
    fi
  fi

  # Single-pass path (original behavior).
  "$TOOL_HOME/scripts/llm-client.sh" review < "$_crv_diff_tmp" > "$OUT"
  # Note: _crv_diff_tmp is NOT deleted yet — cross-round dedup needs it below.

  # Stamp the output with the current HEAD SHA so build_gate_summary can
  # detect stale payloads (file written against a different branch/commit).
  # Best-effort: if git or jq/python3 are unavailable, skip silently.
  _review_sha=$(_git rev-parse HEAD 2>/dev/null || echo "")
  if [ -n "$_review_sha" ]; then
    _stamp_envelope "$OUT" "$_review_sha"
  fi

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
    if [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ]; then
      _crv_live_findings=$(_extract_findings_json "$OUT")
      _invariant_feed_write review "$_crv_live_findings" "$_crv_diff_tmp" "$_crv_prior_seen_snap" "$_crv_seen_file"
    fi
    rm -f "$_crv_prior_seen_snap"
  fi
  rm -f "$_crv_diff_tmp"

  # Reject degraded envelopes outright. An LLM wrapper that failed every
  # chain step emits valid JSON with findings:[] — schema-valid but
  # meaningless. Without this check, a misconfigured / auth-broken /
  # network-out Reviewer chain reports "clean review" and the ship passes.
  # Exit 2 = INFRA_DEGRADED: distinct from exit 1 (REVIEW_BLOCKED) so callers
  # and CI can distinguish "retry — infra flaked" from "fix your code."
  if review_is_degraded "$OUT"; then
    cmd_log_run review block "infra-degraded: all reviewer chain steps failed"
    echo "[gates/review] INFRA_DEGRADED: reviewer chain returned degraded envelope — no real review occurred." 1>&2
    echo "[gates/review] Check LLM CLI config/auth. Set CLAGENTIC_REVIEWER_REQUIRED=1 to make this a hard gate error." 1>&2
    # Pull the per-step failure reasons from the audit DB so the user sees them
    # in the terminal without having to run `digest` or open last-review.json.
    ADB="$REPO_ROOT/.clagentic/lite/audit.db"
    if [ -f "$ADB" ] && command -v sqlite3 >/dev/null 2>&1; then
      STEP_HINTS=$(sqlite3 "$ADB" \
        "SELECT '  ' || details FROM gate_runs WHERE gate='llm-call' AND outcome='step-failed' AND details LIKE 'reviewer%' ORDER BY id DESC LIMIT 6;" \
        2>/dev/null)
      if [ -n "$STEP_HINTS" ]; then
        printf '[gates/review] per-step failures (most recent first):\n' 1>&2
        printf '%s\n' "$STEP_HINTS" 1>&2
      fi
    fi
    echo "[gates/review] full details: $OUT  |  scripts/gates.sh digest" 1>&2
    return 2
  fi
  # Severity gate: count findings >= configured threshold.
  THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"
  BLOCKERS=$(severity_blockers "$OUT" "$THRESHOLD")
  if [ "${BLOCKERS:-0}" -gt 0 ]; then
    cmd_log_run review block "review-blocked: $BLOCKERS finding(s) at >= $THRESHOLD"
    echo "[gates/review] REVIEW_BLOCKED: $BLOCKERS finding(s) at or above severity '$THRESHOLD'." 1>&2
    cmd_render_review "$OUT" 1>&2
    return 1
  fi
  cmd_log_run review pass "0 findings at >= $THRESHOLD"
  cmd_render_review "$OUT"
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

# Detect the "degraded": true marker written by emit_degraded in llm-client.sh.
# Args: FILE
# Returns 0 if degraded, 1 if not (or if validators are unavailable — see M2).
review_is_degraded() {
  FILE="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -e '.degraded == true' "$FILE" >/dev/null 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("degraded") is True else 1)' "$FILE" 2>/dev/null
  else
    # No validator — assume not degraded; the no-validator branch is itself
    # caught by severity_blockers fail-closed.
    return 1
  fi
}

# _parse_adversarial_findings MARKDOWN_FILE
#
# Loose-parses [FINDING] header lines from adversarial markdown output into
# the same {file,line,category,message} JSON shape review findings use, so
# they can be run through the EXISTING finding_content_keys / dedup_findings
# machinery unmodified. Header format (ds_adversarial_prompt, llm-client.sh):
#   [FINDING] CWE-XXX | file.ext:line | severity: <level> | title: <phrase>
# "category" is set to the CWE id (e.g. "CWE-770") — adversarial findings
# have no review-style category, and the CWE id IS the class identity that
# matters for invariant re-derivation. "message" is the title field. A
# missing/malformed line number degrades to line 0 (finding_content_keys then
# fails to compute a context window and the finding is simply omitted from
# the key set — same conservative-drop behavior documented there).
_parse_adversarial_findings() {
  _paf_file="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$_paf_file" <<'PYEOF'
import json, re, sys

path = sys.argv[1]
findings = []
header_re = re.compile(
    r'^\[FINDING\]\s*([^|]+)\|\s*([^|]+)\|\s*severity:\s*([^|]+)\|\s*title:\s*(.+)$'
)
try:
    with open(path) as f:
        lines = f.readlines()
except Exception:
    lines = []

for line in lines:
    line = line.rstrip("\n")
    m = header_re.match(line.strip())
    if not m:
        continue
    cwe = m.group(1).strip()
    fileline = m.group(2).strip()
    severity = m.group(3).strip().lower()
    title = m.group(4).strip()
    if ":" in fileline:
        fname, _, lineno = fileline.rpartition(":")
        try:
            lineno = int(lineno)
        except ValueError:
            fname, lineno = fileline, 0
    else:
        fname, lineno = fileline, 0
    findings.append({
        "file": fname,
        "line": lineno,
        "category": cwe,
        "message": title,
        "severity": severity,
    })
print(json.dumps(findings))
PYEOF
  else
    printf '[]'
  fi
}

cmd_adversarial() {
  OUT="$REPO_ROOT/.clagentic/lite/last-adversarial.md"
  _adv_diff_tmp=$(mktemp -t clagentic-adv-diff.XXXXXX)
  get_review_diff > "$_adv_diff_tmp"
  "$TOOL_HOME/scripts/llm-client.sh" adversarial < "$_adv_diff_tmp" > "$OUT"
  # Prepend a SHA stamp comment as the first line so build_gate_summary can
  # detect stale payloads. Best-effort: skip if git unavailable or SHA empty.
  _adv_sha=$(_git rev-parse HEAD 2>/dev/null || echo "")
  if [ -n "$_adv_sha" ]; then
    _adv_tmp=$(mktemp -t clagentic-adv-stamp.XXXXXX)
    printf '<!-- clagentic-diff-sha: %s -->\n' "$_adv_sha" > "$_adv_tmp"
    cat "$OUT" >> "$_adv_tmp"
    mv "$_adv_tmp" "$OUT"
  fi

  # Invariant-feed writer (lr-63359e), adversarial half. Loose-parses
  # [FINDING] headers into the same shape the writer already knows how to
  # key, then reuses dedup_findings' content-hash key derivation via a
  # dedicated seen-keys file for the adversarial modality (adversarial does
  # not otherwise participate in cross-round dedup — CLAGENTIC_CROSS_ROUND_DEDUP
  # only wires into cmd_review — so this is the first time an adversarial
  # round's findings are content-hash-keyed at all, not a second dedup layer
  # competing with an existing one).
  if [ "${CLAGENTIC_ADVERSARIAL_INVARIANTS:-0}" = "1" ]; then
    _adv_seen_file="$REPO_ROOT/.clagentic/lite/adversarial-seen-keys"
    [ -f "$_adv_seen_file" ] || touch "$_adv_seen_file"
    _adv_prior_seen_snap=$(mktemp -t clagentic-inv-adv-prior.XXXXXX)
    cp "$_adv_seen_file" "$_adv_prior_seen_snap" 2>/dev/null || : > "$_adv_prior_seen_snap"

    _adv_findings_json=$(_parse_adversarial_findings "$OUT")
    # dedup_findings' return value is unused here — we only want it to
    # persist this round's keys into _adv_seen_file (same side effect
    # _cross_round_dedup relies on for the review path); the deduped
    # markdown stdout is never re-derived from JSON, so we discard it.
    printf '%s' "$_adv_findings_json" | dedup_findings "content-hash" "$_adv_seen_file" "$_adv_diff_tmp" >/dev/null 2>&1 || true
    _invariant_feed_write adversarial "$_adv_findings_json" "$_adv_diff_tmp" "$_adv_prior_seen_snap" "$_adv_seen_file"
    rm -f "$_adv_prior_seen_snap"
  fi
  rm -f "$_adv_diff_tmp"

  cmd_log_run adversarial warn "wrote $OUT (non-blocking)"
  cat "$OUT"
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
    _mg_summary_sha=""
    _mg_head_sha=$(git rev-parse HEAD 2>/dev/null || echo "")
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

  "$TOOL_HOME/scripts/llm-client.sh" merge-gate < "$IN" > "$OUT"

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
        cmd_log_run "$_mg_gate_name" pass "approve ($ACK_COUNT acknowledged finding(s)): $ACK_DETAIL"
      else
        cmd_log_run "$_mg_gate_name" pass "approve"
      fi
      ;;
    refuse)
      cmd_log_run "$_mg_gate_name" block "refuse"
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
  if command -v jq >/dev/null 2>&1; then
    R=$(jq -r --argjson tr "$TR" '
      def rank(s):
        (s // "" | ascii_downcase) as $s
        | if $s == "critical" then 4
        elif $s == "high" then 3
        elif $s == "medium" then 2
        elif $s == "low" then 1
        else 0 end;
      [(.findings // [])[] | select(rank(.severity) >= $tr)] | length
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
print(sum(1 for f in d.get("findings", []) if ranks.get(str(f.get("severity","")).lower(),0) >= tr))
PY
  else
    # No validator at all — fail closed. Sentinel 99 makes the audit-row
    # message ("99 finding(s) at >= high") visibly unusual so users know
    # this is "blocked because the gate couldn't read the review" rather
    # than a model that legitimately found 99 issues.
    echo 99
  fi
}

build_gate_summary() {
  RV="$REPO_ROOT/.clagentic/lite/last-review.json"
  AD="$REPO_ROOT/.clagentic/lite/last-adversarial.md"
  ACKS_FILE="$REPO_ROOT/.clagentic/adversarial-acks.json"
  AR_FILE="$REPO_ROOT/.clagentic/accepted-risks.md"
  THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"

  # Staleness check: compare HEAD SHA against the SHA stamped in each gate
  # output file. A mismatch means the file was written against a different
  # commit and the merge-gate would receive stale data. Fail-open for the
  # stamp itself — if no stamp is present the file may predate this feature,
  # which we treat as stale (it could be arbitrarily old).
  #
  # Skip the check when CLAGENTIC_ALLOW_STALE_PAYLOAD=1 (e.g. CI pipelines
  # that write gate artifacts in a prior step, or air-gapped environments).
  CURRENT_SHA=$(_git rev-parse HEAD 2>/dev/null || echo "")
  ADVERSARIAL_MISSING=false
  # Fail-closed when REPO_ROOT is a valid git repo but CURRENT_SHA is empty:
  # treat as stale so the merge-gate refuses on incomplete data. Only the
  # genuine non-git case (rev-parse --git-dir fails) may skip the check.
  # Consistent with the "missing stamp = stale" philosophy at line ~1105.
  _git_dir_ok=0
  if _git rev-parse --git-dir >/dev/null 2>&1; then _git_dir_ok=1; fi
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
  if _git diff --cached --name-status 2>/dev/null | grep -q .; then
    _diff_status=$(_git diff --cached --name-status 2>/dev/null || true)
  else
    _DEFAULT_BRANCH=$(_git remote show origin 2>/dev/null | sed -n 's/.*HEAD branch: //p' | tr -d ' \n')
    [ -z "$_DEFAULT_BRANCH" ] && _DEFAULT_BRANCH="main"
    _diff_status=$(_git diff "origin/${_DEFAULT_BRANCH}...HEAD" --name-status 2>/dev/null || true)
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
    ACKS_PAYLOAD='[]'
    AR_PAYLOAD='""'
    [ -f "$RV" ] && jq -e . "$RV" >/dev/null 2>&1 && RV_PAYLOAD=$(cat "$RV")
    [ -f "$AD" ] && AD_PAYLOAD=$(jq -Rs . < "$AD")
    [ -f "$ACKS_FILE" ] && ACKS_PAYLOAD=$(jq -c . "$ACKS_FILE" 2>/dev/null || echo '[]')
    [ -f "$AR_FILE" ] && AR_PAYLOAD=$(jq -Rs . < "$AR_FILE")
    cat <<EOF
{
  "review": $RV_PAYLOAD,
  "adversarial": $AD_PAYLOAD,
  "adversarial_missing": $ADVERSARIAL_MISSING,
  "adversarial_acks": $ACKS_PAYLOAD,
  "accepted_risks": $AR_PAYLOAD,
  "introduces_ack_file": $INTRODUCES_ACK_FILE,
  "threshold": "$THRESHOLD"
}
EOF
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    RV_ARG=""
    AD_ARG=""
    ACKS_ARG=""
    AR_ARG=""
    [ -f "$RV" ] && RV_ARG="$RV"
    [ -f "$AD" ] && AD_ARG="$AD"
    [ -f "$ACKS_FILE" ] && ACKS_ARG="$ACKS_FILE"
    [ -f "$AR_FILE" ] && AR_ARG="$AR_FILE"
    python3 - "$THRESHOLD" "$INTRODUCES_ACK_FILE" "$ADVERSARIAL_MISSING" "$RV_ARG" "$AD_ARG" "$ACKS_ARG" "$AR_ARG" <<'PY'
import json, sys
threshold           = sys.argv[1]
introduces_ack      = sys.argv[2].lower() == "true" if len(sys.argv) > 2 else False
adversarial_missing = sys.argv[3].lower() == "true" if len(sys.argv) > 3 else False
rv_path             = sys.argv[4] if len(sys.argv) > 4 else ""
ad_path             = sys.argv[5] if len(sys.argv) > 5 else ""
acks_path           = sys.argv[6] if len(sys.argv) > 6 else ""
ar_path             = sys.argv[7] if len(sys.argv) > 7 else ""
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
print(json.dumps({"review": review, "adversarial": adv, "adversarial_missing": adversarial_missing, "adversarial_acks": acks, "accepted_risks": ar, "introduces_ack_file": introduces_ack, "threshold": threshold}))
PY
    return 0
  fi

  # No JSON encoder available — emit a minimal envelope with adversarial
  # and accepted_risks dropped. The Merge Gate will see this and may choose
  # to refuse on incomplete context. introduces_ack_file is included as false
  # (conservative — no bootstrap exemption in degraded mode).
  if [ -f "$RV" ]; then
    cat <<EOF
{"review": $(cat "$RV"), "adversarial": null, "adversarial_missing": $ADVERSARIAL_MISSING, "adversarial_acks": [], "accepted_risks": "", "introduces_ack_file": false, "threshold": "$THRESHOLD"}
EOF
  else
    echo "{\"review\": null, \"adversarial\": null, \"adversarial_missing\": $ADVERSARIAL_MISSING, \"adversarial_acks\": [], \"accepted_risks\": \"\", \"introduces_ack_file\": false, \"threshold\": \"$THRESHOLD\"}"
  fi
}

cmd_render_review() {
  FILE="${1:-$REPO_ROOT/.clagentic/lite/last-review.json}"
  [ -f "$FILE" ] || { echo "no review file at $FILE" 1>&2; return 1; }
  if command -v jq >/dev/null 2>&1; then
    jq -r '"== clagentic-lite review ==\nsummary: " + .summary + "\nfindings: " + (.findings | length | tostring) + "\n",
           (.findings[] | "[" + .severity + "] " + .file + ":" + (.line|tostring) + " " + .message)' \
      "$FILE"
  else
    cat "$FILE"
  fi
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
  if gate_enabled bleed;        then cmd_bleed        || { echo "[gates/ship] BLOCKED at internal-bleed"; exit 1; }; else ship_step_skip bleed;        fi
  if gate_enabled secrets;     then cmd_secrets     || { echo "[gates/ship] BLOCKED at secrets";    exit 1; }; else ship_step_skip secrets;     fi
  if gate_enabled deps;        then cmd_deps        || { echo "[gates/ship] BLOCKED at deps";       exit 1; }; else ship_step_skip deps;        fi
  if gate_enabled sast;        then cmd_sast        || { echo "[gates/ship] BLOCKED at sast";       exit 1; }; else ship_step_skip sast;        fi
  if gate_enabled review; then
    _review_rc=0
    cmd_review || _review_rc=$?
    if [ "$_review_rc" -eq 2 ]; then
      echo "[gates/ship] INFRA_DEGRADED at review — reviewer infrastructure failed, no real review occurred"
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
  if gate_enabled adversarial; then cmd_adversarial || true; else ship_step_skip adversarial; fi
  if gate_enabled merge-gate;  then cmd_merge_gate  || { echo "[gates/ship] BLOCKED at merge-gate"; exit 1; }; else ship_step_skip merge-gate;  fi

  echo "[gates/ship] all blocking gates passed"
  BRANCH=$(_git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  if [ "$BRANCH" = "$DEFAULT_BRANCH" ] || [ -z "$BRANCH" ]; then
    echo "[gates/ship] on '$BRANCH' — not pushing or opening a PR; create a feature branch first"
    cmd_log_run ship pass "gates green; no push (branch=$BRANCH)"
    return 0
  fi

  # Push + open PR if gh is available, else print a template.
  if _git remote get-url origin >/dev/null 2>&1; then
    _git push -u origin "$BRANCH" || { echo "[gates/ship] push failed"; cmd_log_run ship block "push failed"; exit 1; }
  fi
  if command -v gh >/dev/null 2>&1; then
    if gh pr view "$BRANCH" >/dev/null 2>&1; then
      echo "[gates/ship] PR already open for $BRANCH"
    else
      gh pr create --fill --base "$DEFAULT_BRANCH" --head "$BRANCH" || \
        echo "[gates/ship] gh pr create failed — open the PR manually"
    fi
  else
    REMOTE=$(_git remote get-url origin 2>/dev/null || echo "<remote>")
    echo "[gates/ship] gh not installed — open a PR manually:"
    echo "  base=$DEFAULT_BRANCH head=$BRANCH remote=$REMOTE"
  fi
  cmd_log_run ship pass "gates green; pushed $BRANCH"
}

cmd_pre_push() {
  cmd_deps || exit 1
  cmd_sast || exit 1
  [ "${CLAGENTIC_REVIEW_ON_PUSH:-0}" = "1" ] && { cmd_review || exit 1; }
  exit 0
}

cmd_digest() {
  cmd_init
  printf '\n== clagentic-lite gate digest (last 24h) ==\n\n'
  sqlite3 -header -column "$AUDIT_DB" \
    "SELECT ts, gate, outcome, substr(details,1,60) AS details
     FROM gate_runs WHERE ts > datetime('now','-1 day') ORDER BY ts DESC;"
  printf '\n'
  printf 'totals:\n'
  sqlite3 -column "$AUDIT_DB" \
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
    ROWS=$(sqlite3 -separator '|' "$AUDIT_DB" \
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
    LAST_ID=$(sqlite3 "$AUDIT_DB" "SELECT COALESCE(MAX(id),0) FROM gate_runs;" 2>/dev/null)
    LAST_ID=${LAST_ID:-0}
  fi

  if [ "$_tail_no_follow" = "1" ]; then
    # --no-follow: emit rows since the watermark and exit 0.
    # Used by smoke.sh (step 6c) to avoid the indefinite-follow hang that
    # occurs inside a Claude Code session.
    printf '== clagentic-lite gate tail (--no-follow, one-shot) ==\n'
    printf '   rows with gate_runs.id > %s\n\n' "$LAST_ID"
    NEW=$(sqlite3 -separator '|' "$AUDIT_DB" \
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
  printf '== clagentic-lite gate tail (Ctrl-C to quit, polling every %ss) ==\n' "$INTERVAL"
  printf '   starting from gate_runs.id > %s\n\n' "$LAST_ID"

  # Trap INT/TERM so the user gets a clean exit instead of a stack trace from
  # set -e + a killed sqlite3.
  trap 'printf "\n[tail] stopped\n"; exit 0' INT TERM

  while :; do
    NEW=$(sqlite3 -separator '|' "$AUDIT_DB" \
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

case "${1:-}" in
  init)           cmd_init ;;
  bleed)          cmd_bleed ;;
  secrets)        cmd_secrets ;;
  deps)           cmd_deps ;;
  sast)           cmd_sast ;;
  review)         shift; cmd_review "$@" ;;
  adversarial)    cmd_adversarial ;;
  merge-gate)     shift; cmd_merge_gate "$@" ;;
  render-review)  shift; cmd_render_review "$@" ;;
  ship)           cmd_ship ;;
  pre-push)       cmd_pre_push ;;
  log-run)        shift; cmd_log_run "$@" ;;
  digest)         cmd_digest ;;
  status)         shift; cmd_status "$@" ;;
  tail)           shift; cmd_tail "$@" ;;
  *) echo "usage: gates.sh {init|bleed|secrets|deps|sast|review [--since-last-review] [--reset-dedup]|adversarial|merge-gate [--recheck]|render-review|ship|pre-push|log-run|digest|status|tail [--no-follow]}" 1>&2; exit 1 ;;
esac
