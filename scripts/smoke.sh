#!/bin/sh
# clagentic-lite :: smoke test
#
# Non-interactive end-to-end. Runs in CI on both ubuntu-latest and macos-latest
# and locally before pushing. Each step asserts a concrete observable: file
# created, row in audit.db, gitleaks blocks the planted token, etc.
#
# This is the regression net for the demo. If smoke.sh passes, the README's
# 5-minute demo should work.
#
# Usage:
#   scripts/smoke.sh           # full run; non-zero on any failure
#   scripts/smoke.sh --quick   # skip the LLM-call steps (review, summarize)

set -e
. "$(dirname "$0")/platform.sh"
ds_load_env

REPO_ROOT=$(ds_repo_root || { echo "smoke: not in a git repo" 1>&2; exit 1; })
cd "$REPO_ROOT"

MODE="${1:-full}"
PASS=0
FAIL=0

step() { printf '\n[smoke] %s\n' "$*"; }
ok()   { printf '  OK    %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL  %s\n' "$*" 1>&2; FAIL=$((FAIL+1)); }

# ---------------------------------------------------------------- 1. preflight

step "1. install.sh --check"
if ./install.sh --check >/tmp/clagentic-smoke-check.log 2>&1; then
  ok "install.sh --check exits 0"
else
  bad "install.sh --check failed; see /tmp/clagentic-smoke-check.log"
fi

# ------------------------------------------------------------- 2. databases up

step "2. databases initialize"
scripts/memory.sh init && ok "memory.db init"   || bad "memory.db init"
scripts/gates.sh  init && ok "audit.db init"    || bad "audit.db init"

# ----------------------------------------------------------- 3. seed + recall

step "3. seed + recall"
scripts/memory.sh seed-demo >/dev/null && ok "seed-demo ran" || bad "seed-demo"
RECALL=$(scripts/memory.sh recall auth 2>&1)
if printf '%s' "$RECALL" | grep -q '.'; then
  ok "recall 'auth' returned rows"
else
  bad "recall 'auth' returned nothing"
fi

# ------------------------------------------------------- 4. gitleaks blocks token

step "4. gitleaks pre-commit gate blocks planted token"
if command -v gitleaks >/dev/null 2>&1; then
  # We need a path that is NOT in .gitleaks.toml's allowlist (which excludes
  # examples/**/.env.example so the demo fixtures can be committed). Create
  # a temp file inside the repo at a non-allowlisted path, stage it, run the
  # gate, then unstage and remove the file.
  TARGET="$REPO_ROOT/.clagentic-smoke-leak.tmp"
  cat > "$TARGET" <<'EOF'
# clagentic-lite smoke test — staged secret that gitleaks MUST flag.
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
  # Force-add to bypass any .gitignore.
  git add -f -- "$TARGET" 2>/dev/null || true
  if scripts/gates.sh secrets >/tmp/clagentic-smoke-secrets.log 2>&1; then
    bad "gates.sh secrets PASSED on a file with a planted AKIA token (should block)"
  else
    ok "gates.sh secrets blocked the planted token (non-zero exit)"
  fi
  git reset HEAD -- "$TARGET" >/dev/null 2>&1 || true
  rm -f "$TARGET"
else
  printf '  SKIP  gitleaks not installed\n'
fi

# --------------------------------------------------- 5. llm-client.sh review JSON

if [ "$MODE" != "--quick" ]; then
  step "5. llm-client.sh review emits parseable JSON"
  # Use an empty diff so we don't actually charge for an LLM call where possible.
  # The wrapper's degraded envelope is still valid JSON.
  OUT=$(printf '' | scripts/llm-client.sh review 2>/dev/null || true)
  if command -v jq >/dev/null 2>&1; then
    if printf '%s' "$OUT" | jq -e '.findings' >/dev/null 2>&1; then
      ok "review output parses as JSON with .findings"
    else
      bad "review output not valid JSON or missing .findings"
    fi
  elif command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$OUT" | python3 -c 'import json,sys; json.loads(sys.stdin.read())["findings"]' 2>/dev/null; then
      ok "review output parses as JSON with .findings (python3)"
    else
      bad "review output not valid JSON or missing .findings"
    fi
  else
    printf '  SKIP  no jq or python3 to validate JSON\n'
  fi
fi

# ----------------------------------------------------------------- 6. digest

step "6. gates.sh digest runs"
if scripts/gates.sh digest >/tmp/clagentic-smoke-digest.log 2>&1; then
  ok "digest exits 0"
else
  bad "digest failed"
fi

# ----------------------------------------------------- 6b. status + tail (read-only)

step "6b. gates.sh status (read-only visibility)"
# Seed a known row so status has something to render in at least one section.
scripts/gates.sh log-run secrets pass "smoke status seed" >/dev/null 2>&1 || true
if scripts/gates.sh status 5 >/tmp/clagentic-smoke-status.log 2>&1; then
  if grep -q -- '-- secrets --' /tmp/clagentic-smoke-status.log; then
    ok "status exits 0 and renders per-gate sections"
  else
    bad "status ran but didn't render gate sections; see /tmp/clagentic-smoke-status.log"
  fi
else
  bad "status failed; see /tmp/clagentic-smoke-status.log"
fi

# Input validation: status with a non-integer argument must exit non-zero.
if scripts/gates.sh status abc >/dev/null 2>&1; then
  bad "status accepted non-integer N (should reject)"
else
  ok "status rejects non-integer N"
fi

step "6c. gates.sh tail picks up new rows"
# Run tail in the background; insert a row; tail should render it within a
# few poll intervals. Then SIGINT and read the captured output.
TAIL_LOG="/tmp/clagentic-smoke-tail.log"
: > "$TAIL_LOG"
CLAGENTIC_TAIL_INTERVAL_SEC=1 scripts/gates.sh tail >"$TAIL_LOG" 2>&1 &
TAIL_PID=$!
# Give tail a moment to capture MAX(id) before we insert.
sleep 2
SENTINEL="smoke tail sentinel $$"
scripts/gates.sh log-run secrets pass "$SENTINEL" >/dev/null 2>&1 || true
# Allow up to 5 poll cycles for the sentinel to appear.
i=0
while [ $i -lt 5 ]; do
  if grep -q "$SENTINEL" "$TAIL_LOG" 2>/dev/null; then break; fi
  sleep 1
  i=$((i+1))
done
kill -INT "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true
if grep -q "$SENTINEL" "$TAIL_LOG"; then
  ok "tail rendered the new row within the poll window"
else
  bad "tail did not render the new row; see $TAIL_LOG"
fi

# ---------------------------------------------------- 7. audit.db has rows

step "7. audit.db has rows from this run"
COUNT=$(sqlite3 "$REPO_ROOT/.clagentic/audit.db" "SELECT COUNT(*) FROM gate_runs WHERE ts > datetime('now','-1 hour');" 2>/dev/null || echo 0)
if [ "${COUNT:-0}" -gt 0 ]; then
  ok "audit.db gate_runs has $COUNT recent row(s)"
else
  bad "audit.db gate_runs has no recent rows"
fi

# -------------------------------------------------------------------- summary

printf '\n[smoke] passed: %s   failed: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
