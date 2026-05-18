#!/bin/sh
# clagentic-lite :: installer
# POSIX, idempotent. Detects WSL vs macOS, prompts for parameters, wires hooks.
#
# Usage:
#   ./install.sh           # full install (interactive if stdin is a TTY)
#   ./install.sh --check   # verify dependencies, print install hints, no changes
#   ./install.sh --no-prompt  # use .env.example defaults verbatim, no prompts

set -e
. "$(dirname "$0")/scripts/platform.sh"

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

MODE="${1:-install}"

say() { printf '[clagentic-lite] %s\n' "$*"; }
warn() { printf '[clagentic-lite] WARN: %s\n' "$*" 1>&2; }
die() { printf '[clagentic-lite] ERROR: %s\n' "$*" 1>&2; exit 1; }

check_tool() {
  NAME="$1"
  HINT_LINUX="$2"
  HINT_DARWIN="$3"
  if command -v "$NAME" >/dev/null 2>&1; then
    printf '  %-15s found: %s\n' "$NAME" "$(command -v "$NAME")"
    return 0
  fi
  if [ "$DS_OS" = "darwin" ]; then
    printf '  %-15s MISSING — install: %s\n' "$NAME" "$HINT_DARWIN"
  else
    printf '  %-15s MISSING — install: %s\n' "$NAME" "$HINT_LINUX"
  fi
  return 1
}

cmd_check() {
  say "platform: $DS_OS (wsl=$DS_WSL)"
  say "checking dependencies:"
  MISSING=0
  check_tool sqlite3      "apt install sqlite3"           "brew install sqlite"    || MISSING=$((MISSING+1))
  check_tool git          "apt install git"               "xcode-select --install" || MISSING=$((MISSING+1))
  if check_tool gitleaks  "see https://github.com/gitleaks/gitleaks#installing" \
                          "brew install gitleaks"; then
    # Minimum required: 8.25 (allowlist syntax in .gitleaks.toml).
    GLV=$(gitleaks version 2>/dev/null | sed 's/^v//' | head -1)
    case "$GLV" in
      8.25*|8.26*|8.27*|8.28*|8.29*|8.3*|8.4*|8.5*|8.6*|8.7*|8.8*|8.9*|9.*)
        : # ok
        ;;
      *)
        warn "gitleaks $GLV is below the required minimum 8.25 (.gitleaks.toml uses [[allowlists]] + condition=AND, introduced in 8.25). Upgrade: brew upgrade gitleaks | re-download from github.com/gitleaks/gitleaks/releases"
        ;;
    esac
  else
    MISSING=$((MISSING+1))
  fi
  check_tool semgrep      "pipx install semgrep"          "brew install semgrep"   || MISSING=$((MISSING+1))
  check_tool osv-scanner  "see https://google.github.io/osv-scanner/installation/" \
                          "brew install osv-scanner"      || MISSING=$((MISSING+1))
  # jq is functionally required: the PreToolUse hooks fail closed when no JSON
  # validator is available. python3 is the accepted fallback. install.sh treats
  # the absence of BOTH as a hard miss; either one present satisfies preflight.
  HAS_JSON=0
  if command -v jq >/dev/null 2>&1; then
    printf '  %-15s found: %s\n' "jq" "$(command -v jq)"
    HAS_JSON=1
  elif command -v python3 >/dev/null 2>&1; then
    printf '  %-15s missing (ok — python3 fallback present)\n' "jq"
    HAS_JSON=1
  fi
  if [ "$HAS_JSON" -eq 0 ]; then
    if [ "$DS_OS" = "darwin" ]; then
      printf '  %-15s MISSING — install: %s\n' "jq" "brew install jq" 1>&2
    else
      printf '  %-15s MISSING — install: %s\n' "jq" "apt install jq" 1>&2
    fi
    warn "no JSON validator (jq or python3) — PreToolUse hooks will fail closed and block every Bash/Write/Edit tool call until you install one"
    MISSING=$((MISSING+1))
  fi
  check_tool python3      "apt install python3"           "(macOS ships python3)" || true
  check_tool gh           "see https://cli.github.com/"   "brew install gh"        || true
  # timeout: ships with GNU coreutils on Linux; macOS users need `brew install
  # coreutils` (which installs gtimeout). The wrapper detects either at source
  # time and degrades to a no-op stub if neither is present.
  if ! command -v timeout >/dev/null 2>&1 && ! command -v gtimeout >/dev/null 2>&1; then
    printf '  %-15s MISSING — install: %s\n' "timeout" "brew install coreutils (macOS) | apt install coreutils (linux)" 1>&2
    warn "timeout/gtimeout not on PATH — LLM call wrapper will run without timeouts (hung CLI calls won't auto-fail-over)"
  else
    if command -v timeout >/dev/null 2>&1; then
      printf '  %-15s found: %s\n' "timeout" "$(command -v timeout)"
    else
      printf '  %-15s found: %s (macOS gtimeout)\n' "timeout" "$(command -v gtimeout)"
    fi
  fi

  say "checking role CLIs (configure primaries via .env):"
  # Read .env if present so we check the user's actually-configured CLIs.
  [ -f .env ] && { set -a; . ./.env; set +a; }
  BUILDER="${CLAGENTIC_BUILDER_CMD:-claude}"
  REVIEWER="${CLAGENTIC_REVIEWER_CMD:-codex}"
  AUDITOR="${CLAGENTIC_AUDITOR_CMD:-codex}"
  GATE="${CLAGENTIC_GATE_CMD:-claude}"
  SUMMARIZER="${CLAGENTIC_SUMMARIZER_CMD:-claude}"
  for cli in "$BUILDER" "$REVIEWER" "$AUDITOR" "$GATE" "$SUMMARIZER"; do
    [ -n "$cli" ] || continue
    check_tool "$cli" "see your CLI vendor docs" "see your CLI vendor docs" \
      || warn "configured CLI '$cli' not on PATH — calls to roles using it will fall through to the chain or degraded envelope"
  done

  if [ "$BUILDER" = "$REVIEWER" ]; then
    warn "Builder and Reviewer both resolve to '$BUILDER'. Cross-vendor review surfaces blind spots that same-vendor review shares. Recommend setting them to different CLIs."
  fi

  # Branch-vs-default-branch sanity check. The pre-write-guard W-001 blocks
  # writes when the current branch matches CLAGENTIC_DEFAULT_BRANCH; if the
  # repo is on a branch that does NOT match the default branch the user has
  # configured, that's fine (you're on a feature branch). The footgun is the
  # other direction: default is "main" but the repo is still on "master" —
  # then W-001 is effectively disabled and you can write to the protected
  # branch. Warn loudly.
  if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    CB=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    DEF="${CLAGENTIC_DEFAULT_BRANCH:-main}"
    if [ -n "$CB" ] && [ "$CB" != "$DEF" ]; then
      # Are we sitting on a known "default-like" branch with the wrong name?
      case "$CB" in
        master|trunk|develop)
          warn "current branch is '$CB' but CLAGENTIC_DEFAULT_BRANCH=$DEF. Either rename: 'git branch -m $CB $DEF' (then push and update remote HEAD), or set CLAGENTIC_DEFAULT_BRANCH=$CB in .env to match."
          ;;
      esac
    fi
  fi

  [ "$MISSING" -gt 0 ] && warn "$MISSING required tool(s) missing — install before running ./install.sh"
  # Strict preflight: set CLAGENTIC_STRICT_PREFLIGHT=1 to make missing required
  # tools a hard error rather than a warning. Default off so re-running --check
  # in CI doesn't fail just because optional tools aren't pre-installed.
  if [ "${CLAGENTIC_STRICT_PREFLIGHT:-0}" = "1" ] && [ "$MISSING" -gt 0 ]; then
    die "strict preflight: $MISSING required tool(s) missing"
  fi
  return 0
}

# Prompt for one variable. Args: VAR_NAME DEFAULT_VALUE PROMPT_TEXT
# Echoes the final value. Honors non-TTY by accepting default silently.
prompt_var() {
  VN="$1"
  DEFAULT="$2"
  TEXT="$3"
  # If already set in the environment (from a prior .env source), keep it.
  EXISTING=$(eval "printf '%s' \"\${$VN-}\"")
  if [ -n "$EXISTING" ]; then
    printf '%s' "$EXISTING"
    return 0
  fi
  if [ ! -t 0 ] || [ "${CLAGENTIC_NO_PROMPT:-0}" = "1" ]; then
    printf '%s' "$DEFAULT"
    return 0
  fi
  if [ -n "$DEFAULT" ]; then
    printf '  %s [%s]: ' "$TEXT" "$DEFAULT" 1>&2
  else
    printf '  %s: ' "$TEXT" 1>&2
  fi
  read -r REPLY || REPLY=""
  [ -z "$REPLY" ] && REPLY="$DEFAULT"
  printf '%s' "$REPLY"
}

# Read a VAR=value pair from .env.example. Returns the value or empty.
example_default() {
  VN="$1"
  grep -E "^${VN}=" .env.example 2>/dev/null | head -1 | sed "s/^${VN}=//"
}

cmd_init_env() {
  if [ -f .env ]; then
    say ".env exists — leaving in place (delete it to re-prompt)"
    return 0
  fi
  if [ ! -t 0 ] || [ "${CLAGENTIC_NO_PROMPT:-0}" = "1" ]; then
    say ".env missing, non-interactive — copying .env.example defaults"
    cp .env.example .env
    chmod 600 .env
    return 0
  fi

  say "writing .env (interactive — press Enter to accept each default)"

  # Strategy: copy .env.example verbatim so future additions to the template
  # (new CLAGENTIC_* keys, comments, structure) automatically land in the
  # generated .env. Then re-write a prompted subset in place. This avoids
  # the "hardcoded list of keys in install.sh drifts from .env.example"
  # bug — codex review pass #4 M4.
  cp .env.example .env
  chmod 600 .env

  # Keys we actively prompt for — the user-facing surface that should be
  # confirmed at install time. Everything else stays at the .env.example
  # default and is editable in .env after.
  PROMPT_KEYS="
    CLAGENTIC_ORG
    CLAGENTIC_PROJECT
    CLAGENTIC_BUILDER_CMD CLAGENTIC_BUILDER_TIER CLAGENTIC_BUILDER_CHAIN
    CLAGENTIC_REVIEWER_CMD CLAGENTIC_REVIEWER_TIER CLAGENTIC_REVIEWER_CHAIN
    CLAGENTIC_AUDITOR_CMD CLAGENTIC_AUDITOR_TIER CLAGENTIC_AUDITOR_CHAIN
    CLAGENTIC_GATE_CMD CLAGENTIC_GATE_TIER CLAGENTIC_GATE_CHAIN
    CLAGENTIC_SUMMARIZER_CMD CLAGENTIC_SUMMARIZER_TIER CLAGENTIC_SUMMARIZER_CHAIN
    CLAGENTIC_GATES
    CLAGENTIC_BLOCK_SEVERITY
    CLAGENTIC_DEFAULT_BRANCH
    CLAGENTIC_REPO_HOST
  "

  for VN in $PROMPT_KEYS; do
    DEFAULT=$(example_default "$VN")
    VAL=$(prompt_var "$VN" "$DEFAULT" "$VN")
    # Shell-safe single-quote value (handles spaces / #/ $/ quotes).
    Q_VAL=$(printf '%s' "$VAL" | sed "s/'/'\\\\''/g")
    # Replace the line in .env in place. Use a temp file to avoid sed-inplace
    # portability issues (already handled by $DS_SED_INPLACE but a tmp-file
    # rewrite is simpler when the value can contain `/` or other sed metas).
    awk -v key="$VN" -v val="'$Q_VAL'" '
      $0 ~ "^"key"=" { print key"="val; next }
      { print }
    ' .env > .env.tmp && mv .env.tmp .env
  done
  chmod 600 .env
  say "wrote .env (chmod 600) — every .env.example key copied; prompted subset overwritten"
}

cmd_install() {
  cmd_check

  say "initializing .env"
  cmd_init_env

  say "loading .env"
  set -a; . ./.env; set +a

  say "initializing databases"
  scripts/memory.sh init
  scripts/gates.sh init

  say "wiring git hooks"
  # Capture git-dir defensively. Under `set -e` an unprotected $(git rev-parse)
  # in a non-repo context would early-exit the installer. The explicit `||`
  # gives us an empty string we can branch on.
  GIT_DIR=$(git rev-parse --git-dir 2>/dev/null || echo "")
  HOOKS_DIR=""
  [ -n "$GIT_DIR" ] && HOOKS_DIR="$GIT_DIR/hooks"
  if [ -z "$HOOKS_DIR" ]; then
    warn "not a git repo — skipping git hook wiring"
  else
    mkdir -p "$HOOKS_DIR"
    cat > "$HOOKS_DIR/pre-commit" <<EOF
#!/bin/sh
exec "$REPO_ROOT/scripts/gates.sh" secrets
EOF
    cat > "$HOOKS_DIR/pre-push" <<EOF
#!/bin/sh
exec "$REPO_ROOT/scripts/gates.sh" pre-push
EOF
    chmod +x "$HOOKS_DIR/pre-commit" "$HOOKS_DIR/pre-push"
  fi
  chmod +x .claude/hooks/*.sh scripts/*.sh

  say "ready"
  say "next:  review .env,  then open this repo in your Claude Code or Codex CLI"
}

case "$MODE" in
  --check|check)         cmd_check ;;
  --no-prompt|no-prompt) CLAGENTIC_NO_PROMPT=1 cmd_install ;;
  *)                     cmd_install ;;
esac
