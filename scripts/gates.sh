#!/bin/sh
# clagentic-lite :: gate orchestrator
# Runs gates in sequence, logs outcomes to .clagentic/audit.db.
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
#   render-review    pretty-print .clagentic/last-review.json
#   digest           summarize today's audit rows
#   status           last N runs per gate (default N=10) with color outcomes
#   tail             follow audit.db, render new gate_runs rows as they land
#   pre-push         hook entry point (deps + sast + optional review)
#   log-run          internal: insert one row into gate_runs

set -e
. "$(dirname "$0")/platform.sh"
ds_load_env

# Tool home: the directory containing scripts/ — resolved from this script's
# own location so it's correct whether invoked via PATH, symlink, or directly.
# This is the install tree ($CLAGENTIC_HOME), not the enrolled project root.
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_HOME="$(dirname "$SCRIPTS_DIR")"

# Project root resolution: CLAGENTIC_PROJECT_ROOT env var wins, then git
# show-toplevel of cwd. The env var is the override path used when gates.sh
# is called from a hook shim installed by `clagentic-lite enroll` — the shim
# stamps __CLAGENTIC_HOME__ at enroll time but does NOT override the project
# root; instead, git show-toplevel of the repo under commit is used because
# the hook always runs from inside the enrolled repo's working tree.
# Explicit CLAGENTIC_PROJECT_ROOT is still supported for scripted/test use.
if [ -n "${CLAGENTIC_PROJECT_ROOT:-}" ]; then
  REPO_ROOT="$CLAGENTIC_PROJECT_ROOT"
else
  REPO_ROOT=$(ds_repo_root)
fi
[ -n "$REPO_ROOT" ] || { echo "gates.sh: not in a git repo" 1>&2; exit 1; }

AUDIT_DB="$REPO_ROOT/.clagentic/audit.db"
mkdir -p "$REPO_ROOT/.clagentic"

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
  BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
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
  _SECRETS_STAGED=$(git diff --cached --name-only 2>/dev/null)
  _SECRETS_DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  _SECRETS_CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
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
#   2. Branch diff against origin/<default_branch> — PR path when index is
#      clean but we are on a feature branch with committed changes.
#   3. Empty — on the default branch with no staged changes; review will see
#      an empty diff (the merge-gate has an explicit null-review rule for this).
#
# Prints one diagnostic line to stderr indicating which mode is active.
get_review_diff() {
  DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")

  if git diff --cached --name-only 2>/dev/null | grep -q .; then
    printf '[gates/review] using staged diff\n' 1>&2
    git diff --cached --unified=3 2>/dev/null
    return 0
  fi

  if [ -n "$CURRENT_BRANCH" ] && [ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ] && [ "$CURRENT_BRANCH" != "HEAD" ]; then
    # Fetch the base ref so the comparison is accurate even in a fresh clone.
    # Failure here is non-fatal — git diff will simply fall back to local state.
    git fetch origin "$DEFAULT_BRANCH" >/dev/null 2>&1 || true
    printf '[gates/review] no staged changes — using branch diff vs origin/%s\n' "$DEFAULT_BRANCH" 1>&2
    git diff "origin/${DEFAULT_BRANCH}...HEAD" --unified=3 2>/dev/null
    return 0
  fi

  printf '[gates/review] no staged changes and on default branch — empty diff\n' 1>&2
}

cmd_review() {
  OUT="$REPO_ROOT/.clagentic/last-review.json"
  get_review_diff | "$TOOL_HOME/scripts/llm-client.sh" review > "$OUT"
  # Stamp the output with the current HEAD SHA so build_gate_summary can
  # detect stale payloads (file written against a different branch/commit).
  # Best-effort: if git or jq/python3 are unavailable, skip silently.
  _review_sha=$(git rev-parse HEAD 2>/dev/null || echo "")
  if [ -n "$_review_sha" ]; then
    if command -v jq >/dev/null 2>&1; then
      _review_tmp=$(mktemp -t clagentic-review-stamp.XXXXXX)
      if jq --arg sha "$_review_sha" '. + {_clagentic_diff_sha: $sha}' "$OUT" > "$_review_tmp" 2>/dev/null; then
        mv "$_review_tmp" "$OUT"
      else
        rm -f "$_review_tmp"
      fi
    elif command -v python3 >/dev/null 2>&1; then
      _review_tmp=$(mktemp -t clagentic-review-stamp.XXXXXX)
      if python3 - "$OUT" "$_review_sha" "$_review_tmp" <<'PYEOF' 2>/dev/null
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
        mv "$_review_tmp" "$OUT"
      else
        rm -f "$_review_tmp"
      fi
    fi
  fi
  # Reject degraded envelopes outright. An LLM wrapper that failed every
  # chain step emits valid JSON with findings:[] — schema-valid but
  # meaningless. Without this check, a misconfigured / auth-broken /
  # network-out Reviewer chain reports "clean review" and the ship passes.
  if review_is_degraded "$OUT"; then
    cmd_log_run review block "review degraded (all chain steps failed)"
    echo "[gates/review] BLOCKED: reviewer chain returned degraded envelope — no real review occurred." 1>&2
    # Pull the per-step failure reasons from the audit DB so the user sees them
    # in the terminal without having to run `digest` or open last-review.json.
    ADB="$REPO_ROOT/.clagentic/audit.db"
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
    return 1
  fi
  # Severity gate: count findings >= configured threshold.
  THRESHOLD="${CLAGENTIC_BLOCK_SEVERITY:-high}"
  BLOCKERS=$(severity_blockers "$OUT" "$THRESHOLD")
  if [ "${BLOCKERS:-0}" -gt 0 ]; then
    cmd_log_run review block "$BLOCKERS finding(s) at >= $THRESHOLD"
    cmd_render_review "$OUT" 1>&2
    return 1
  fi
  cmd_log_run review pass "0 findings at >= $THRESHOLD"
  cmd_render_review "$OUT"
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

cmd_adversarial() {
  OUT="$REPO_ROOT/.clagentic/last-adversarial.md"
  get_review_diff | "$TOOL_HOME/scripts/llm-client.sh" adversarial > "$OUT"
  # Prepend a SHA stamp comment as the first line so build_gate_summary can
  # detect stale payloads. Best-effort: skip if git unavailable or SHA empty.
  _adv_sha=$(git rev-parse HEAD 2>/dev/null || echo "")
  if [ -n "$_adv_sha" ]; then
    _adv_tmp=$(mktemp -t clagentic-adv-stamp.XXXXXX)
    printf '<!-- clagentic-diff-sha: %s -->\n' "$_adv_sha" > "$_adv_tmp"
    cat "$OUT" >> "$_adv_tmp"
    mv "$_adv_tmp" "$OUT"
  fi
  cmd_log_run adversarial warn "wrote $OUT (non-blocking)"
  cat "$OUT"
}

cmd_merge_gate() {
  # Final LLM sanity check: feed gate outputs back through the merge-gate
  # role, which decides approve/refuse. BLOCKING BY DEFAULT — set
  # CLAGENTIC_MERGE_GATE_BLOCKING=0 to make a 'refuse' decision advisory only.
  IN="$REPO_ROOT/.clagentic/gate-summary.json"
  OUT="$REPO_ROOT/.clagentic/last-merge-gate.json"
  build_gate_summary > "$IN"

  # Detect a stale-payload envelope emitted by build_gate_summary.
  # A stale payload means gate artifacts describe a different commit — skip
  # the LLM call entirely (deterministic refusal, no token burn) and write a
  # synthetic refusal to last-merge-gate.json.
  _stale_check=""
  if command -v jq >/dev/null 2>&1; then
    _stale_check=$(jq -r '.stale_payload // "false"' "$IN" 2>/dev/null || echo "false")
  elif command -v python3 >/dev/null 2>&1; then
    _stale_check=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(str(d.get("stale_payload","false")).lower())' "$IN" 2>/dev/null || echo "false")
  fi
  if [ "${_stale_check}" = "true" ]; then
    printf '{"decision": "refuse", "reason": "stale gate payload — re-run clagentic-lite gates review and gates adversarial first"}\n' > "$OUT"
    cmd_log_run merge-gate block "stale payload — re-run review + adversarial (SHA mismatch)"
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
        cmd_log_run merge-gate pass "approve ($ACK_COUNT acknowledged finding(s)): $ACK_DETAIL"
      else
        cmd_log_run merge-gate pass "approve"
      fi
      ;;
    refuse)
      cmd_log_run merge-gate block "refuse"
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
      cmd_log_run merge-gate block "decision=$DECISION (unparseable)"
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
  RV="$REPO_ROOT/.clagentic/last-review.json"
  AD="$REPO_ROOT/.clagentic/last-adversarial.md"
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
  CURRENT_SHA=$(git rev-parse HEAD 2>/dev/null || echo "")
  if [ -n "$CURRENT_SHA" ]; then
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
      _ad_sha=""
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
  if git diff --cached --name-status 2>/dev/null | grep -q .; then
    _diff_status=$(git diff --cached --name-status 2>/dev/null)
  else
    _DEFAULT_BRANCH=$(git remote show origin 2>/dev/null | sed -n 's/.*HEAD branch: //p' | tr -d ' \n')
    [ -z "$_DEFAULT_BRANCH" ] && _DEFAULT_BRANCH="main"
    _diff_status=$(git diff "origin/${_DEFAULT_BRANCH}...HEAD" --name-status 2>/dev/null)
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
    AD_PAYLOAD='""'
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
    python3 - "$THRESHOLD" "$INTRODUCES_ACK_FILE" "$RV_ARG" "$AD_ARG" "$ACKS_ARG" "$AR_ARG" <<'PY'
import json, sys
threshold       = sys.argv[1]
introduces_ack  = sys.argv[2].lower() == "true" if len(sys.argv) > 2 else False
rv_path         = sys.argv[3] if len(sys.argv) > 3 else ""
ad_path         = sys.argv[4] if len(sys.argv) > 4 else ""
acks_path       = sys.argv[5] if len(sys.argv) > 5 else ""
ar_path         = sys.argv[6] if len(sys.argv) > 6 else ""
review = None
if rv_path:
    try:
        with open(rv_path) as f:
            review = json.load(f)
    except Exception:
        review = None
adv = ""
if ad_path:
    try:
        with open(ad_path) as f:
            adv = f.read()
    except Exception:
        adv = ""
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
print(json.dumps({"review": review, "adversarial": adv, "adversarial_acks": acks, "accepted_risks": ar, "introduces_ack_file": introduces_ack, "threshold": threshold}))
PY
    return 0
  fi

  # No JSON encoder available — emit a minimal envelope with adversarial
  # and accepted_risks dropped. The Merge Gate will see this and may choose
  # to refuse on incomplete context. introduces_ack_file is included as false
  # (conservative — no bootstrap exemption in degraded mode).
  if [ -f "$RV" ]; then
    cat <<EOF
{"review": $(cat "$RV"), "adversarial": "", "adversarial_acks": [], "accepted_risks": "", "introduces_ack_file": false, "threshold": "$THRESHOLD"}
EOF
  else
    echo "{\"review\": null, \"adversarial\": \"\", \"adversarial_acks\": [], \"accepted_risks\": \"\", \"introduces_ack_file\": false, \"threshold\": \"$THRESHOLD\"}"
  fi
}

cmd_render_review() {
  FILE="${1:-$REPO_ROOT/.clagentic/last-review.json}"
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
  if gate_enabled review;      then cmd_review      || { echo "[gates/ship] BLOCKED at review (severity threshold ${CLAGENTIC_BLOCK_SEVERITY:-high})"; exit 1; }; else ship_step_skip review;      fi
  if gate_enabled adversarial; then cmd_adversarial || true; else ship_step_skip adversarial; fi
  if gate_enabled merge-gate;  then cmd_merge_gate  || { echo "[gates/ship] BLOCKED at merge-gate"; exit 1; }; else ship_step_skip merge-gate;  fi

  echo "[gates/ship] all blocking gates passed"
  BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  if [ "$BRANCH" = "$DEFAULT_BRANCH" ] || [ -z "$BRANCH" ]; then
    echo "[gates/ship] on '$BRANCH' — not pushing or opening a PR; create a feature branch first"
    cmd_log_run ship pass "gates green; no push (branch=$BRANCH)"
    return 0
  fi

  # Push + open PR if gh is available, else print a template.
  if git remote get-url origin >/dev/null 2>&1; then
    git push -u origin "$BRANCH" || { echo "[gates/ship] push failed"; cmd_log_run ship block "push failed"; exit 1; }
  fi
  if command -v gh >/dev/null 2>&1; then
    if gh pr view "$BRANCH" >/dev/null 2>&1; then
      echo "[gates/ship] PR already open for $BRANCH"
    else
      gh pr create --fill --base "$DEFAULT_BRANCH" --head "$BRANCH" || \
        echo "[gates/ship] gh pr create failed — open the PR manually"
    fi
  else
    REMOTE=$(git remote get-url origin 2>/dev/null || echo "<remote>")
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
# Visibility surfaces over .clagentic/audit.db that complement `digest`:
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
  # Start from the current max id so we only render NEW rows. A fresh tail
  # session shouldn't dump history — use `status` or `digest` for that.
  LAST_ID=$(sqlite3 "$AUDIT_DB" "SELECT COALESCE(MAX(id),0) FROM gate_runs;" 2>/dev/null)
  LAST_ID=${LAST_ID:-0}
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
  review)         cmd_review ;;
  adversarial)    cmd_adversarial ;;
  merge-gate)     cmd_merge_gate ;;
  render-review)  shift; cmd_render_review "$@" ;;
  ship)           cmd_ship ;;
  pre-push)       cmd_pre_push ;;
  log-run)        shift; cmd_log_run "$@" ;;
  digest)         cmd_digest ;;
  status)         shift; cmd_status "$@" ;;
  tail)           cmd_tail ;;
  *) echo "usage: gates.sh {init|bleed|secrets|deps|sast|review|adversarial|merge-gate|render-review|ship|pre-push|log-run|digest|status|tail}" 1>&2; exit 1 ;;
esac
