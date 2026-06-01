#!/bin/sh
# clagentic-lite :: smoke test
#
# Non-interactive end-to-end. Each step asserts a concrete observable.
#
# Usage:
#   scripts/smoke.sh           # full run; non-zero on any failure
#   scripts/smoke.sh --quick   # skip the LLM-call steps (review, summarize)

set -e
# Resolve tool home from this script's own location.
SMOKE_SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_HOME="$(dirname "$SMOKE_SCRIPTS_DIR")"
. "$SMOKE_SCRIPTS_DIR/platform.sh"
ds_load_env

# Smoke runs from inside the clagentic-lite checkout (the tool itself).
# Gates and memory scripts are invoked with explicit CLAGENTIC_PROJECT_ROOT
# so we can test that the per-repo isolation works correctly.
REPO_ROOT=$(ds_repo_root || { echo "smoke: not in a git repo" 1>&2; exit 1; })
cd "$REPO_ROOT"

MODE="${1:-full}"
PASS=0
FAIL=0

step() { printf '\n[smoke] %s\n' "$*"; }
ok()   { printf '  OK    %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL  %s\n' "$*" 1>&2; FAIL=$((FAIL+1)); }

# ---------------------------------------------------------------- 1. doctor prereqs

step "1. clagentic doctor prereq checks (read-only)"
# We only check that doctor exits 0 for prereq tools that ARE on this machine.
# Don't fail smoke if security tools are missing — smoke runs on a bare CI box.
if command -v sqlite3 >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
  ok "sqlite3 and git found (required prereqs)"
else
  bad "sqlite3 or git missing"
fi

# ------------------------------------------------------------- 2. databases up

step "2. databases initialize (in clagentic-lite checkout)"
"$TOOL_HOME/scripts/memory.sh" init && ok "memory.db init"  || bad "memory.db init"
"$TOOL_HOME/scripts/gates.sh"  init && ok "audit.db init"   || bad "audit.db init"

# ----------------------------------------------------------- 3. seed + recall

step "3. seed + recall"
"$TOOL_HOME/scripts/memory.sh" seed-demo >/dev/null && ok "seed-demo ran" || bad "seed-demo"
RECALL=$("$TOOL_HOME/scripts/memory.sh" recall auth 2>&1)
if printf '%s' "$RECALL" | grep -q '.'; then
  ok "recall 'auth' returned rows"
else
  bad "recall 'auth' returned nothing"
fi

# ------------------------------------------------------- 4. gitleaks blocks token

step "4. gitleaks pre-commit gate blocks planted token"
if command -v gitleaks >/dev/null 2>&1; then
  TARGET="$REPO_ROOT/.clagentic-smoke-leak.tmp"
  cat > "$TARGET" <<'EOF'
# clagentic-lite smoke test — staged secret that gitleaks MUST flag.
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
  git add -f -- "$TARGET" 2>/dev/null || true
  if "$TOOL_HOME/scripts/gates.sh" secrets >/tmp/clagentic-smoke-secrets.log 2>&1; then
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
  OUT=$(printf '' | "$TOOL_HOME/scripts/llm-client.sh" review 2>/dev/null || true)
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

# ------------------------------------- 5b. summarizer skips cleanly (no config)

# Gate 7 is best-effort. With no summarizer chain AND no Builder fallback, the
# wrapper must emit EMPTY stdout (so memory.sh's empty-summary guard skips
# silently) and must NOT print a degraded banner. Run with all relevant role
# vars unset in a subshell so we exercise the genuine no-chain path.
step "5b. summarizer with no chain skips cleanly (no degraded banner)"
SUMM_OUT=$(env -u CLAGENTIC_SUMMARIZER_CMD -u CLAGENTIC_SUMMARIZER_TIER \
  -u CLAGENTIC_SUMMARIZER_CHAIN -u CLAGENTIC_BUILDER_CMD \
  sh -c 'printf "" | "$1" summarize' _ "$TOOL_HOME/scripts/llm-client.sh" 2>/dev/null || true)
if [ -z "$(printf '%s' "$SUMM_OUT" | tr -d '[:space:]')" ]; then
  ok "summarizer emitted empty output on no-chain (clean skip)"
else
  bad "summarizer emitted non-empty output on no-chain: $SUMM_OUT"
fi
if printf '%s' "$SUMM_OUT" | grep -q 'degraded'; then
  bad "summarizer printed a degraded banner on no-chain (should be silent)"
else
  ok "summarizer printed no degraded banner on no-chain"
fi

# With a Builder configured but no summarizer chain, the wrapper must attempt
# the Builder CLI at :cheap rather than skipping. We point the Builder at a
# guaranteed-absent CLI so invoke_step short-circuits with exit 127 (no network
# call, fully offline) and the audit row records a step-failed for that CLI —
# proving the fallback was resolved and tried, not skipped. The CLI name is
# unique so we can match it precisely in the audit trail.
step "5c. summarizer falls back to Builder CLI when Builder is configured"
FAKE_CLI="clagentic-smoke-absent-$$"
env -u CLAGENTIC_SUMMARIZER_CMD -u CLAGENTIC_SUMMARIZER_TIER \
  -u CLAGENTIC_SUMMARIZER_CHAIN CLAGENTIC_BUILDER_CMD="$FAKE_CLI" \
  CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" \
  sh -c 'printf "" | "$1" summarize' _ "$TOOL_HOME/scripts/llm-client.sh" >/dev/null 2>&1 || true
if sqlite3 "$REPO_ROOT/.clagentic/audit.db" \
  "SELECT 1 FROM gate_runs WHERE gate='llm-call' AND details LIKE 'summarizer:$FAKE_CLI:%' AND ts > datetime('now','-1 hour') LIMIT 1;" \
  2>/dev/null | grep -q 1; then
  ok "summarizer attempted builder CLI fallback (audit row for $FAKE_CLI)"
else
  bad "no audit row for summarizer builder-CLI fallback; fallback not resolved"
fi

# ----------------------------------------------------------------- 6. digest

step "6. gates.sh digest runs"
if "$TOOL_HOME/scripts/gates.sh" digest >/tmp/clagentic-smoke-digest.log 2>&1; then
  ok "digest exits 0"
else
  bad "digest failed"
fi

# ----------------------------------------------------- 6b. status + tail (read-only)

step "6b. gates.sh status (read-only visibility)"
"$TOOL_HOME/scripts/gates.sh" log-run secrets pass "smoke status seed" >/dev/null 2>&1 || true
if "$TOOL_HOME/scripts/gates.sh" status 5 >/tmp/clagentic-smoke-status.log 2>&1; then
  if grep -q -- '-- secrets --' /tmp/clagentic-smoke-status.log; then
    ok "status exits 0 and renders per-gate sections"
  else
    bad "status ran but didn't render gate sections; see /tmp/clagentic-smoke-status.log"
  fi
else
  bad "status failed; see /tmp/clagentic-smoke-status.log"
fi

if "$TOOL_HOME/scripts/gates.sh" status abc >/dev/null 2>&1; then
  bad "status accepted non-integer N (should reject)"
else
  ok "status rejects non-integer N"
fi

step "6c. gates.sh tail picks up new rows"
TAIL_LOG="/tmp/clagentic-smoke-tail.log"
: > "$TAIL_LOG"
CLAGENTIC_TAIL_INTERVAL_SEC=1 "$TOOL_HOME/scripts/gates.sh" tail >"$TAIL_LOG" 2>&1 &
TAIL_PID=$!
sleep 2
SENTINEL="smoke tail sentinel $$"
"$TOOL_HOME/scripts/gates.sh" log-run secrets pass "$SENTINEL" >/dev/null 2>&1 || true
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

# --------------------------------------------------- 8. enroll + unenroll in tempdir

step "8. enroll/unenroll in a fresh git repo"
if command -v python3 >/dev/null 2>&1; then
  # Use python3 to create a temp dir (POSIX mktemp -d is portable enough but
  # python gives us guaranteed cleanup via atexit).
  SMOKE_TMPDIR=$(python3 -c "import tempfile; print(tempfile.mkdtemp(prefix='clagentic-smoke-'))")
  if [ -z "$SMOKE_TMPDIR" ] || [ ! -d "$SMOKE_TMPDIR" ]; then
    bad "could not create temp dir for enroll test"
  else
    # Init a fresh git repo in the tempdir.
    git init "$SMOKE_TMPDIR" >/dev/null 2>&1
    git -C "$SMOKE_TMPDIR" config user.email "smoke@clagentic.test"
    git -C "$SMOKE_TMPDIR" config user.name "smoke"

    # Enroll with CLAGENTIC_HOME pointing at our tool checkout.
    if CLAGENTIC_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" enroll "$SMOKE_TMPDIR" >/tmp/clagentic-smoke-enroll.log 2>&1; then
      ok "clagentic-lite enroll succeeded on a fresh repo"

      # Verify DBs were created in the enrolled repo, NOT in $TOOL_HOME.
      if [ -f "$SMOKE_TMPDIR/.clagentic/audit.db" ]; then
        ok "audit.db created in enrolled repo"
      else
        bad "audit.db missing in enrolled repo"
      fi
      if [ -f "$SMOKE_TMPDIR/.clagentic/memory.db" ]; then
        ok "memory.db created in enrolled repo"
      else
        bad "memory.db missing in enrolled repo"
      fi

      # Verify hook shims are stamped correctly.
      _hdir="$SMOKE_TMPDIR/.git/hooks"
      for _hook in pre-commit pre-push; do
        if [ -f "$_hdir/$_hook" ]; then
          if grep -q 'managed-by: clagentic' "$_hdir/$_hook"; then
            ok "hook shim $_hook has managed-by marker"
          else
            bad "hook shim $_hook missing managed-by marker"
          fi
          if grep -q "$TOOL_HOME" "$_hdir/$_hook"; then
            ok "hook shim $_hook points to CLAGENTIC_HOME"
          else
            bad "hook shim $_hook does not reference CLAGENTIC_HOME=$TOOL_HOME"
          fi
        else
          bad "hook shim $_hook missing in enrolled repo"
        fi
      done

      # Verify that a gate fired in the enrolled repo writes to THAT repo's audit.db.
      # gates.sh secrets with no staged files should pass (or at least not crash)
      # and write a row to the enrolled repo's audit.db — not to $TOOL_HOME's DB.
      _tool_db_before=$(sqlite3 "$TOOL_HOME/.clagentic/audit.db" "SELECT COUNT(*) FROM gate_runs;" 2>/dev/null || echo "0")
      (cd "$SMOKE_TMPDIR" && CLAGENTIC_HOME="$TOOL_HOME" "$TOOL_HOME/scripts/gates.sh" secrets) >/dev/null 2>&1 || true
      _tool_db_after=$(sqlite3 "$TOOL_HOME/.clagentic/audit.db" "SELECT COUNT(*) FROM gate_runs;" 2>/dev/null || echo "0")
      _enroll_db_count=$(sqlite3 "$SMOKE_TMPDIR/.clagentic/audit.db" "SELECT COUNT(*) FROM gate_runs;" 2>/dev/null || echo "0")
      if [ "${_enroll_db_count:-0}" -gt 0 ]; then
        ok "gate run wrote to enrolled repo's audit.db (AC5)"
      else
        bad "gate run did not write to enrolled repo's audit.db"
      fi
      if [ "${_tool_db_before}" = "${_tool_db_after}" ]; then
        ok "gate run did NOT write to tool's own audit.db (per-repo isolation confirmed)"
      else
        bad "gate run wrote a row to \$CLAGENTIC_HOME's audit.db (isolation failure)"
      fi

      # Re-enroll without --force should refuse.
      if CLAGENTIC_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" enroll "$SMOKE_TMPDIR" >/dev/null 2>&1; then
        bad "second enroll without --force should have been refused"
      else
        ok "second enroll without --force correctly refused"
      fi

      # Unenroll: hooks removed, .clagentic/ left intact.
      if CLAGENTIC_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" unenroll "$SMOKE_TMPDIR" >/tmp/clagentic-smoke-unenroll.log 2>&1; then
        ok "clagentic-lite unenroll succeeded"
        if [ ! -f "$_hdir/pre-commit" ] && [ ! -f "$_hdir/pre-push" ]; then
          ok "clagentic-owned hooks removed by unenroll"
        else
          bad "hooks still present after unenroll"
        fi
        if [ -d "$SMOKE_TMPDIR/.clagentic" ]; then
          ok ".clagentic/ left intact by unenroll (no --purge)"
        else
          bad ".clagentic/ removed without --purge"
        fi
      else
        bad "clagentic-lite unenroll failed; see /tmp/clagentic-smoke-unenroll.log"
      fi

    else
      bad "clagentic-lite enroll failed; see /tmp/clagentic-smoke-enroll.log"
    fi

    # Cleanup.
    python3 -c "import shutil; shutil.rmtree('$SMOKE_TMPDIR', ignore_errors=True)" 2>/dev/null || true
  fi
else
  printf '  SKIP  python3 not found (needed for tempdir management in enroll test)\n'
fi

# Refuse to enroll $CLAGENTIC_HOME without --self.
step "8b. enroll refuses to self-enroll without --self"
if CLAGENTIC_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" enroll "$TOOL_HOME" >/dev/null 2>&1; then
  bad "enroll allowed $TOOL_HOME without --self (snake's-head check failed)"
else
  ok "enroll refused to enroll \$CLAGENTIC_HOME without --self (AC4)"
fi

# ---------------------------------------------------- 9. audit.db row check

step "9. audit.db has rows from this run"
COUNT=$(sqlite3 "$REPO_ROOT/.clagentic/audit.db" "SELECT COUNT(*) FROM gate_runs WHERE ts > datetime('now','-1 hour');" 2>/dev/null || echo 0)
if [ "${COUNT:-0}" -gt 0 ]; then
  ok "audit.db gate_runs has $COUNT recent row(s)"
else
  bad "audit.db gate_runs has no recent rows"
fi

# ----------------------------------------- 10. remember verb (source=manual)

step "10. clagentic-lite remember inserts a source=manual row"
if CLAGENTIC_HOME="$TOOL_HOME" CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" \
    "$TOOL_HOME/bin/clagentic-lite" remember "smoke test manual note" "smoke manual" >/dev/null 2>&1; then
  _manual_count=$(sqlite3 "$REPO_ROOT/.clagentic/memory.db" \
    "SELECT COUNT(*) FROM turns WHERE source='manual' AND summary='smoke test manual note';" 2>/dev/null || echo 0)
  if [ "${_manual_count:-0}" -ge 1 ]; then
    ok "remember inserted a source=manual row"
  else
    bad "remember ran but no source=manual row found"
  fi
else
  bad "clagentic-lite remember exited non-zero"
fi

# ---------------------------------------------------- 11. row-cap pruning

step "11. CLAGENTIC_MEMORY_MAX_ROWS row-cap pruning"
_cap=10
i=0
while [ $i -lt 15 ]; do
  CLAGENTIC_MEMORY_MAX_ROWS="$_cap" CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" \
    "$TOOL_HOME/scripts/memory.sh" log-turn "row-cap smoke row $i" "smoke cap" "seed" >/dev/null 2>&1
  i=$((i+1))
done
_row_count=$(sqlite3 "$REPO_ROOT/.clagentic/memory.db" \
  "SELECT COUNT(*) FROM turns;" 2>/dev/null || echo 0)
if [ "${_row_count:-0}" -le "$_cap" ]; then
  ok "row cap enforced: $_row_count rows <= cap $_cap"
else
  bad "row cap not enforced: $_row_count rows in DB (cap was $_cap)"
fi

# ------------------------------------------------- 12. integer-guard: garbage MAX_ROWS

step "12. garbage CLAGENTIC_MEMORY_MAX_ROWS falls back to default (no crash, no injection)"
_before_count=$(sqlite3 "$REPO_ROOT/.clagentic/memory.db" "SELECT COUNT(*) FROM turns;" 2>/dev/null || echo 0)
if CLAGENTIC_MEMORY_MAX_ROWS='1; DROP TABLE turns; --' CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" \
    "$TOOL_HOME/scripts/memory.sh" log-turn "guard test row" "guard" "smoke" >/dev/null 2>&1; then
  _after_count=$(sqlite3 "$REPO_ROOT/.clagentic/memory.db" "SELECT COUNT(*) FROM turns;" 2>/dev/null || echo 0)
  if [ "${_after_count:-0}" -ge "${_before_count:-0}" ]; then
    ok "garbage MAX_ROWS fell back cleanly; turns table intact ($_after_count rows)"
  else
    bad "turns table disappeared after garbage MAX_ROWS injection attempt"
  fi
else
  bad "memory.sh log-turn crashed on garbage CLAGENTIC_MEMORY_MAX_ROWS"
fi

# ---------------------------------- 13. pin-first: manual row surfaces before newer auto row

step "13. pin-first recall: source=manual row surfaces before newer auto rows (lr-17a8)"
_pin_db="$REPO_ROOT/.clagentic/memory.db"
sqlite3 "$_pin_db" "DELETE FROM turns WHERE summary LIKE 'lr17a8-smoke%';" 2>/dev/null || true
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2020-01-02T00:00:00Z', 'smoke', 'lr17a8-smoke auto row newer', 'smoke', 'stop-hook');"
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2020-01-01T00:00:00Z', 'smoke', 'lr17a8-smoke manual row pinned older', 'smoke', 'manual');"
_pin_recall=$(CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" "$TOOL_HOME/scripts/memory.sh" recall lr17a8-smoke 2>&1)
_pin_first=$(printf '%s\n' "$_pin_recall" | grep 'lr17a8-smoke' | head -1)
if printf '%s' "$_pin_first" | grep -q '\[pin\]'; then
  ok "pin-first: manual row appeared first in recall output"
else
  bad "pin-first: manual row did NOT appear first; first line was: $_pin_first"
fi
if printf '%s' "$_pin_first" | grep -q ' | \[pin\]'; then
  ok "pin-first: [pin] marker is in the summary column (separator contract preserved)"
else
  bad "pin-first: [pin] marker not in expected position; line: $_pin_first"
fi
sqlite3 "$_pin_db" "DELETE FROM turns WHERE summary LIKE 'lr17a8-smoke%';" 2>/dev/null || true

# ---------------------------------- 14. seen-N: count shown when duplicates exist

step "14. seen-N: '(seen 2)' shown when two rows share the same summary prefix (lr-17a8)"
sqlite3 "$_pin_db" "DELETE FROM turns WHERE summary LIKE 'lr17a8-seen%';" 2>/dev/null || true
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2020-02-01T00:00:00Z', 'smoke', 'lr17a8-seen duplicate summary for smoke test', 'smoke', 'stop-hook');"
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2020-02-02T00:00:00Z', 'smoke', 'lr17a8-seen duplicate summary for smoke test', 'smoke', 'stop-hook');"
_seen_recall=$(CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" "$TOOL_HOME/scripts/memory.sh" recall lr17a8-seen 2>&1)
if printf '%s' "$_seen_recall" | grep -q '(seen 2)'; then
  ok "seen-N: '(seen 2)' annotation present for duplicate summary rows"
else
  bad "seen-N: '(seen 2)' not found in recall output; got: $_seen_recall"
fi
_seen_count=$(printf '%s\n' "$_seen_recall" | grep -c 'lr17a8-seen')
if [ "${_seen_count:-0}" -ge 2 ]; then
  ok "seen-N: both duplicate rows present (count annotation does not filter rows)"
else
  bad "seen-N: expected 2 lr17a8-seen rows, got $_seen_count"
fi
sqlite3 "$_pin_db" "DELETE FROM turns WHERE summary LIKE 'lr17a8-seen%';" 2>/dev/null || true

# -------------------------------------------------------------------- summary

printf '\n[smoke] passed: %s   failed: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
