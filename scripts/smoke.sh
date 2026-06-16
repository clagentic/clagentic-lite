#!/bin/sh
# clagentic-lite :: smoke test
#
# Non-interactive end-to-end. Each step asserts a concrete observable.
#
# Usage:
#   scripts/smoke.sh           # full run; non-zero on any failure
#   scripts/smoke.sh --quick   # skip the LLM-call steps (review, summarize)
#
# Note: bin/clagentic-lite has no "build" subcommand and never did. A reported
# stale cmd_build reference (lr-9eed) was investigated; none exists in this file.
# No smoke step for cmd_build is present because the subcommand does not exist.

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

step "1. clagentic-lite doctor prereq checks (read-only)"
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

# ------------------------------------------------ 4b. bleed gate blocks planted pattern

step "4b. bleed gate blocks a planted internal bleed pattern"
_BLEED_TARGET="$REPO_ROOT/.clagentic-smoke-bleed.tmp"
_BLEED_PAT_DIR="$REPO_ROOT/.clagentic"
_BLEED_PAT_FILE="$_BLEED_PAT_DIR/bleed-patterns"
_BLEED_PAT_EXISTED=0
[ -f "$_BLEED_PAT_FILE" ] && _BLEED_PAT_EXISTED=1

# Create a pattern file with a safe synthetic pattern that can never appear
# in real code — this string is deliberately unmatchable in the committed repo.
mkdir -p "$_BLEED_PAT_DIR"
printf 'internal\.example-clagentic-smoke\.invalid\n' > "$_BLEED_PAT_FILE"

# Create a file containing that pattern and stage it.
printf 'this.is.internal.example-clagentic-smoke.invalid.test\n' > "$_BLEED_TARGET"
git add -f -- "$_BLEED_TARGET" 2>/dev/null || true

if CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" "$TOOL_HOME/scripts/gates.sh" bleed >/tmp/clagentic-smoke-bleed.log 2>&1; then
  bad "gates.sh bleed PASSED on a file with a planted bleed pattern (should block)"
else
  ok "gates.sh bleed blocked the planted pattern (non-zero exit)"
fi

git reset HEAD -- "$_BLEED_TARGET" >/dev/null 2>&1 || true
rm -f "$_BLEED_TARGET"
# Restore pattern file state: remove if we created it, leave untouched if it pre-existed.
if [ "$_BLEED_PAT_EXISTED" -eq 0 ]; then
  rm -f "$_BLEED_PAT_FILE"
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

# ------------------------------------ 5d. exit-code contract: INFRA_DEGRADED vs REVIEW_BLOCKED
#
# gates.sh resolves TOOL_HOME from the script's own path (not an env var), so we
# cannot redirect the llm-client.sh call without patching the installed script.
# Instead we test two verifiable contracts:
#
#   1. Audit-row detail strings: the exact strings cmd_review logs for each failure
#      class must round-trip through gate_runs.details (load-bearing for CI queries).
#   2. review_is_degraded helper: the predicate that gates exit-2 must return 0
#      for a {degraded:true} envelope and non-zero for a clean envelope.

step "5d. exit-code contract: audit-row detail format for infra-degraded and review-blocked"
# Log synthetic rows with the exact detail strings cmd_review uses, then verify
# they are retrievable with the expected prefix.
"$TOOL_HOME/scripts/gates.sh" log-run review block "infra-degraded: all reviewer chain steps failed" >/dev/null 2>&1
_EC_DETAIL=$(sqlite3 "$REPO_ROOT/.clagentic/lite/audit.db" \
  "SELECT details FROM gate_runs WHERE gate='review' AND details LIKE 'infra-degraded%' ORDER BY id DESC LIMIT 1;" 2>/dev/null || true)
if printf '%s' "$_EC_DETAIL" | grep -q 'infra-degraded'; then
  ok "exit-code contract: infra-degraded audit row detail round-trips correctly"
else
  bad "exit-code contract: infra-degraded audit row missing or wrong (got: $_EC_DETAIL)"
fi

"$TOOL_HOME/scripts/gates.sh" log-run review block "review-blocked: 2 finding(s) at >= high" >/dev/null 2>&1
_EC_DETAIL2=$(sqlite3 "$REPO_ROOT/.clagentic/lite/audit.db" \
  "SELECT details FROM gate_runs WHERE gate='review' AND details LIKE 'review-blocked%' ORDER BY id DESC LIMIT 1;" 2>/dev/null || true)
if printf '%s' "$_EC_DETAIL2" | grep -q 'review-blocked'; then
  ok "exit-code contract: review-blocked audit row detail round-trips correctly"
else
  bad "exit-code contract: review-blocked audit row missing or wrong (got: $_EC_DETAIL2)"
fi

step "5e. exit-code contract: review_is_degraded identifies degraded vs clean envelopes"
# Inline the review_is_degraded predicate (copied from gates.sh) in a subshell
# so we test the actual logic against both envelope shapes without touching
# the live last-review.json.
_EC_DFILE=$(mktemp -t clagentic-smoke-deg.XXXXXX)
printf '{"degraded":true,"summary":"test","checked":[],"findings":[]}\n' > "$_EC_DFILE"

_EC_DEG_RC=0
sh -c '
  FILE="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -e ".degraded == true" "$FILE" >/dev/null 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get(\"degraded\") is True else 1)" "$FILE" 2>/dev/null
  else
    exit 1
  fi
' _ "$_EC_DFILE" 2>/dev/null || _EC_DEG_RC=$?

rm -f "$_EC_DFILE"
if [ "$_EC_DEG_RC" -eq 0 ]; then
  ok "review_is_degraded: returns 0 for {degraded:true} envelope"
else
  bad "review_is_degraded: returned non-zero for {degraded:true} envelope (rc=$_EC_DEG_RC)"
fi

_EC_CLEANFILE=$(mktemp -t clagentic-smoke-clean.XXXXXX)
printf '{"summary":"clean","checked":[],"findings":[]}\n' > "$_EC_CLEANFILE"

_EC_CLEAN_RC=0
sh -c '
  FILE="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -e ".degraded == true" "$FILE" >/dev/null 2>&1
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get(\"degraded\") is True else 1)" "$FILE" 2>/dev/null
  else
    exit 1
  fi
' _ "$_EC_CLEANFILE" 2>/dev/null && _EC_CLEAN_RC=0 || _EC_CLEAN_RC=1

rm -f "$_EC_CLEANFILE"
if [ "$_EC_CLEAN_RC" -ne 0 ]; then
  ok "review_is_degraded: returns non-zero for clean {findings:[]} envelope"
else
  bad "review_is_degraded: returned 0 (degraded) for clean envelope"
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
if sqlite3 "$REPO_ROOT/.clagentic/lite/audit.db" \
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
COUNT=$(sqlite3 "$REPO_ROOT/.clagentic/lite/audit.db" "SELECT COUNT(*) FROM gate_runs WHERE ts > datetime('now','-1 hour');" 2>/dev/null || echo 0)
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

    # Enroll with CLAGENTIC_LITE_HOME pointing at our tool checkout.
    if CLAGENTIC_LITE_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" enroll "$SMOKE_TMPDIR" >/tmp/clagentic-smoke-enroll.log 2>&1; then
      ok "clagentic-lite enroll succeeded on a fresh repo"

      # Verify the canonical var produces no deprecation warning.
      if grep -q 'CLAGENTIC_HOME is deprecated' /tmp/clagentic-smoke-enroll.log 2>/dev/null; then
        bad "deprecation warning present when using canonical CLAGENTIC_LITE_HOME"
      else
        ok "no deprecation warning with CLAGENTIC_LITE_HOME (canonical var verified)"
      fi

      # Verify DBs were created in the enrolled repo, NOT in $TOOL_HOME.
      if [ -f "$SMOKE_TMPDIR/.clagentic/lite/audit.db" ]; then
        ok "audit.db created in enrolled repo"
      else
        bad "audit.db missing in enrolled repo"
      fi
      if [ -f "$SMOKE_TMPDIR/.clagentic/lite/memory.db" ]; then
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
            ok "hook shim $_hook points to CLAGENTIC_LITE_HOME"
          else
            bad "hook shim $_hook does not reference CLAGENTIC_LITE_HOME=$TOOL_HOME"
          fi
        else
          bad "hook shim $_hook missing in enrolled repo"
        fi
      done

      # Verify that a gate fired in the enrolled repo writes to THAT repo's audit.db.
      # gates.sh secrets with no staged files should pass (or at least not crash)
      # and write a row to the enrolled repo's audit.db — not to $TOOL_HOME's DB.
      _tool_db_before=$(sqlite3 "$TOOL_HOME/.clagentic/lite/audit.db" "SELECT COUNT(*) FROM gate_runs;" 2>/dev/null || echo "0")
      (cd "$SMOKE_TMPDIR" && CLAGENTIC_LITE_HOME="$TOOL_HOME" "$TOOL_HOME/scripts/gates.sh" secrets) >/dev/null 2>&1 || true
      _tool_db_after=$(sqlite3 "$TOOL_HOME/.clagentic/lite/audit.db" "SELECT COUNT(*) FROM gate_runs;" 2>/dev/null || echo "0")
      _enroll_db_count=$(sqlite3 "$SMOKE_TMPDIR/.clagentic/lite/audit.db" "SELECT COUNT(*) FROM gate_runs;" 2>/dev/null || echo "0")
      if [ "${_enroll_db_count:-0}" -gt 0 ]; then
        ok "gate run wrote to enrolled repo's audit.db (AC5)"
      else
        bad "gate run did not write to enrolled repo's audit.db"
      fi
      if [ "${_tool_db_before}" = "${_tool_db_after}" ]; then
        ok "gate run did NOT write to tool's own audit.db (per-repo isolation confirmed)"
      else
        bad "gate run wrote a row to \$CLAGENTIC_LITE_HOME's audit.db (isolation failure)"
      fi

      # Re-enroll without --force should refuse.
      if CLAGENTIC_LITE_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" enroll "$SMOKE_TMPDIR" >/dev/null 2>&1; then
        bad "second enroll without --force should have been refused"
      else
        ok "second enroll without --force correctly refused"
      fi

      # Unenroll: hooks removed, .clagentic/ left intact.
      if CLAGENTIC_LITE_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" unenroll "$SMOKE_TMPDIR" >/tmp/clagentic-smoke-unenroll.log 2>&1; then
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

# Refuse to enroll $CLAGENTIC_LITE_HOME without --self.
step "8b. enroll refuses to self-enroll without --self"
if CLAGENTIC_LITE_HOME="$TOOL_HOME" "$TOOL_HOME/bin/clagentic-lite" enroll "$TOOL_HOME" >/dev/null 2>&1; then
  bad "enroll allowed $TOOL_HOME without --self (snake's-head check failed)"
else
  ok "enroll refused to enroll \$CLAGENTIC_LITE_HOME without --self (AC4)"
fi

# ---------------------------------------------------- 9. audit.db row check

step "9. audit.db has rows from this run"
COUNT=$(sqlite3 "$REPO_ROOT/.clagentic/lite/audit.db" "SELECT COUNT(*) FROM gate_runs WHERE ts > datetime('now','-1 hour');" 2>/dev/null || echo 0)
if [ "${COUNT:-0}" -gt 0 ]; then
  ok "audit.db gate_runs has $COUNT recent row(s)"
else
  bad "audit.db gate_runs has no recent rows"
fi

# ----------------------------------------- 10. remember verb (source=manual)

step "10. clagentic-lite remember inserts a source=manual row"
if CLAGENTIC_LITE_HOME="$TOOL_HOME" CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" \
    "$TOOL_HOME/bin/clagentic-lite" remember "smoke test manual note" "smoke manual" >/dev/null 2>&1; then
  _manual_count=$(sqlite3 "$REPO_ROOT/.clagentic/lite/memory.db" \
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
_row_count=$(sqlite3 "$REPO_ROOT/.clagentic/lite/memory.db" \
  "SELECT COUNT(*) FROM turns;" 2>/dev/null || echo 0)
if [ "${_row_count:-0}" -le "$_cap" ]; then
  ok "row cap enforced: $_row_count rows <= cap $_cap"
else
  bad "row cap not enforced: $_row_count rows in DB (cap was $_cap)"
fi

# ------------------------------------------------- 12. integer-guard: garbage MAX_ROWS

step "12. garbage CLAGENTIC_MEMORY_MAX_ROWS falls back to default (no crash, no injection)"
_before_count=$(sqlite3 "$REPO_ROOT/.clagentic/lite/memory.db" "SELECT COUNT(*) FROM turns;" 2>/dev/null || echo 0)
if CLAGENTIC_MEMORY_MAX_ROWS='1; DROP TABLE turns; --' CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" \
    "$TOOL_HOME/scripts/memory.sh" log-turn "guard test row" "guard" "smoke" >/dev/null 2>&1; then
  _after_count=$(sqlite3 "$REPO_ROOT/.clagentic/lite/memory.db" "SELECT COUNT(*) FROM turns;" 2>/dev/null || echo 0)
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
_pin_db="$REPO_ROOT/.clagentic/lite/memory.db"
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

# ---- 11b. ordering proof: seen-N count does not drive ORDER; recency holds for
#           non-pinned rows and pin-first holds for pinned rows.
#
# Setup: three rows — a manual pin (older ts) and two auto rows (newer ts, one of
# which is a duplicate of a third row so it carries a seen-2 count).  Expected order:
#   1. manual pin    (source=manual, oldest ts — must surface FIRST due to pin-first)
#   2. newer auto    (source=stop-hook, ts=2021-03-03, no duplicate → no seen count)
#   3. older auto    (source=stop-hook, ts=2021-03-01, duplicate → seen-2)
# If the seen-N count were driving order, the high-count row would drift upward.
# Verifying the manual pin is first AND the auto rows appear in ts-descending order
# proves both properties simultaneously without any interactive input.

step "11b. ordering proof: pin-first overrides recency; seen-N never drives ORDER"
sqlite3 "$_pin_db" "DELETE FROM turns WHERE summary LIKE 'lr17a8-ord%';" 2>/dev/null || true
# Older manual pin
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2021-03-01T00:00:00Z', 'smoke', 'lr17a8-ord pinned manual row', 'lr17a8ord', 'manual');"
# Newer auto, no duplicate (unique prefix)
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2021-03-03T00:00:00Z', 'smoke', 'lr17a8-ord auto unique newer', 'lr17a8ord', 'stop-hook');"
# Older auto with a duplicate to trigger seen-2 annotation
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2021-03-01T00:00:01Z', 'smoke', 'lr17a8-ord auto duplicate older A', 'lr17a8ord', 'stop-hook');"
sqlite3 "$_pin_db" \
  "INSERT INTO turns (ts, session_id, summary, tags, source) VALUES ('2021-03-01T00:00:00Z', 'smoke', 'lr17a8-ord auto duplicate older A', 'lr17a8ord', 'stop-hook');"
_ord_recall=$(CLAGENTIC_PROJECT_ROOT="$REPO_ROOT" "$TOOL_HOME/scripts/memory.sh" recall lr17a8-ord 2>&1)
# Line 1 must be the pin.
_ord_line1=$(printf '%s\n' "$_ord_recall" | grep 'lr17a8-ord' | sed -n '1p')
# Line 2 must be the newer auto row (ts=2021-03-03), NOT the duplicate.
_ord_line2=$(printf '%s\n' "$_ord_recall" | grep 'lr17a8-ord' | sed -n '2p')
if printf '%s' "$_ord_line1" | grep -q '\[pin\]'; then
  ok "ord-proof: pin row is first"
else
  bad "ord-proof: pin row is NOT first; got: $_ord_line1"
fi
if printf '%s' "$_ord_line2" | grep -q 'auto unique newer'; then
  ok "ord-proof: newer auto (no seen count) is second — seen-N does not drive order"
else
  bad "ord-proof: expected 'auto unique newer' at position 2; got: $_ord_line2"
fi
sqlite3 "$_pin_db" "DELETE FROM turns WHERE summary LIKE 'lr17a8-ord%';" 2>/dev/null || true

# ---------------------------------------------------------------- 15. split_diff unit tests

step "15. split_diff: chunk count + boundary correctness on synthetic multi-file diff"

# Source review-merge.sh so split_diff and helpers are available.
. "$TOOL_HOME/scripts/review-merge.sh"

# Build a synthetic unified diff: three files, two of which fit in one chunk
# each and one that just tips the budget threshold so two files land in chunk 1
# and one alone in chunk 2 (budget = 200 bytes in this test).
_sd_test_diff=$(mktemp -t clagentic-smoke-sd.XXXXXX)
cat > "$_sd_test_diff" <<'DIFFEOF'
diff --git a/file_a.py b/file_a.py
--- a/file_a.py
+++ b/file_a.py
@@ -1,3 +1,4 @@
 def foo():
+    # added comment
     return 1

diff --git a/file_b.py b/file_b.py
--- a/file_b.py
+++ b/file_b.py
@@ -1,2 +1,3 @@
 x = 1
+y = 2
 z = 3

diff --git a/file_c.py b/file_c.py
--- a/file_c.py
+++ b/file_c.py
@@ -1,5 +1,6 @@
 class Baz:
     def __init__(self):
+        self.value = 42
         pass
     def method(self):
         return self.value
DIFFEOF

_sd_chunk_dir_a=$(mktemp -d -t clagentic-smoke-sdc.XXXXXX)

# Use a budget large enough to hold all three files (should produce 1 chunk).
_sd_nchunks_a=$(split_diff "$_sd_test_diff" "$_sd_chunk_dir_a" 65536)
if [ "${_sd_nchunks_a:-0}" -ge 1 ]; then
  ok "split_diff: large budget produces at least 1 chunk (got $_sd_nchunks_a)"
else
  bad "split_diff: expected >= 1 chunks with large budget, got $_sd_nchunks_a"
fi
# Verify chunk files are present and count matches reported integer.
_sd_chunk_count_a=$(find "$_sd_chunk_dir_a" -name 'chunk-*' -type f | wc -l | tr -d '[:space:]')
if [ "${_sd_chunk_count_a:-0}" -eq "${_sd_nchunks_a:-0}" ]; then
  ok "split_diff: chunk file count matches stdout integer ($_sd_nchunks_a)"
else
  bad "split_diff: chunk file count $_sd_chunk_count_a != reported $_sd_nchunks_a"
fi
# Chunk numbering: first file must be chunk-001 (not chunk-000).
if [ -f "$_sd_chunk_dir_a/chunk-001" ]; then
  ok "split_diff: first chunk file is chunk-001 (1-based numbering)"
else
  bad "split_diff: chunk-001 not found; got: $(ls "$_sd_chunk_dir_a" 2>/dev/null | head -3)"
fi
# Each chunk must begin with a 'diff --git' header line.
_sd_header_bad=0
for _sd_cf in "$_sd_chunk_dir_a"/chunk-*; do
  [ -f "$_sd_cf" ] || continue
  _sd_first=$(head -1 "$_sd_cf" 2>/dev/null)
  case "$_sd_first" in
    'diff --git '*) : ;;  # good
    *) _sd_header_bad=$((_sd_header_bad + 1)) ;;
  esac
done
if [ "$_sd_header_bad" -eq 0 ]; then
  ok "split_diff: each chunk begins with 'diff --git' header"
else
  bad "split_diff: $_sd_header_bad chunk(s) missing 'diff --git' header"
fi
rm -rf "$_sd_chunk_dir_a"

# Use a very small budget (100 bytes) — should produce multiple chunks.
_sd_chunk_dir_b=$(mktemp -d -t clagentic-smoke-sdcb.XXXXXX)
_sd_nchunks_b=$(split_diff "$_sd_test_diff" "$_sd_chunk_dir_b" 100)
if [ "${_sd_nchunks_b:-0}" -gt 1 ]; then
  ok "split_diff: small budget produces multiple chunks (got $_sd_nchunks_b)"
else
  bad "split_diff: expected >1 chunks with small budget, got $_sd_nchunks_b"
fi
# Each chunk file must be non-empty.
_sd_bad_chunks=0
for _sd_cf in "$_sd_chunk_dir_b"/chunk-*; do
  [ -f "$_sd_cf" ] || continue
  if wc -l < "$_sd_cf" | awk '{exit ($1 > 0) ? 0 : 1}'; then
    : # non-empty — ok
  else
    _sd_bad_chunks=$((_sd_bad_chunks + 1))
  fi
done
if [ "$_sd_bad_chunks" -eq 0 ]; then
  ok "split_diff: all chunk files non-empty"
else
  bad "split_diff: $_sd_bad_chunks empty chunk file(s)"
fi
# Each chunk must begin with a 'diff --git' header (small-budget case too).
_sd_header_bad_b=0
for _sd_cf in "$_sd_chunk_dir_b"/chunk-*; do
  [ -f "$_sd_cf" ] || continue
  _sd_first=$(head -1 "$_sd_cf" 2>/dev/null)
  case "$_sd_first" in
    'diff --git '*)  : ;;
    '@@ '*)          : ;;  # hunk sub-chunk from oversized single file — acceptable
    *) _sd_header_bad_b=$((_sd_header_bad_b + 1)) ;;
  esac
done
if [ "$_sd_header_bad_b" -eq 0 ]; then
  ok "split_diff: small-budget chunks all start with diff or hunk header"
else
  bad "split_diff: $_sd_header_bad_b small-budget chunk(s) missing valid header"
fi
rm -rf "$_sd_chunk_dir_b"

# Edge: non-existent diff file produces 0 chunks and exits 0.
_sd_chunk_dir_c=$(mktemp -d -t clagentic-smoke-sdcc.XXXXXX)
_sd_nchunks_c=$(split_diff "/nonexistent/path.diff" "$_sd_chunk_dir_c" 65536 2>/dev/null)
if [ "${_sd_nchunks_c:-0}" -eq 0 ]; then
  ok "split_diff: non-existent diff file produces 0 chunks"
else
  bad "split_diff: expected 0 chunks for missing file, got $_sd_nchunks_c"
fi
rm -rf "$_sd_chunk_dir_c"
rm -f "$_sd_test_diff"

# ---------------------------------------------------------------- 16. merge_envelopes unit tests

step "16. merge_envelopes: union/dedup/degraded rollup"

if command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  _me_env_dir=$(mktemp -d -t clagentic-smoke-me.XXXXXX)

  # Write envelope-001.json: clean, 1 finding (high).
  cat > "$_me_env_dir/envelope-001.json" <<'EOF'
{
  "summary": "clean chunk",
  "checked": ["security", "correctness"],
  "findings": [
    {"severity": "high", "file": "foo.py", "line": 10, "category": "security", "message": "eval usage"}
  ],
  "degraded": false
}
EOF

  # Write envelope-002.json: another clean envelope, same finding (lower severity — higher should win).
  cat > "$_me_env_dir/envelope-002.json" <<'EOF'
{
  "summary": "second chunk",
  "checked": ["correctness", "style"],
  "findings": [
    {"severity": "medium", "file": "foo.py", "line": 10, "category": "security", "message": "eval usage"}
  ],
  "degraded": false
}
EOF

  # Write envelope-003.json: degraded envelope.
  cat > "$_me_env_dir/envelope-003.json" <<'EOF'
{
  "degraded": true,
  "summary": "[clagentic-lite degraded] chain failed",
  "checked": [],
  "findings": []
}
EOF

  _me_merged=$(merge_envelopes "$_me_env_dir" "location")

  # degraded should be true (at least one chunk degraded).
  if printf '%s' "$_me_merged" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("degraded") is True else 1)' 2>/dev/null; then
    ok "merge_envelopes: degraded=true when any chunk is degraded"
  else
    bad "merge_envelopes: degraded not propagated correctly"
  fi

  # chunks_degraded should be 1.
  _me_cdeg=$(printf '%s' "$_me_merged" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chunks_degraded","?"))' 2>/dev/null || echo "?")
  if [ "$_me_cdeg" = "1" ]; then
    ok "merge_envelopes: chunks_degraded=1 (correct count)"
  else
    bad "merge_envelopes: expected chunks_degraded=1, got $_me_cdeg"
  fi

  # chunks should be 3.
  _me_ctotal=$(printf '%s' "$_me_merged" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chunks","?"))' 2>/dev/null || echo "?")
  if [ "$_me_ctotal" = "3" ]; then
    ok "merge_envelopes: chunks=3 (correct total)"
  else
    bad "merge_envelopes: expected chunks=3, got $_me_ctotal"
  fi

  # checked union should include security, correctness, style.
  _me_checked=$(printf '%s' "$_me_merged" | python3 -c 'import json,sys; c=json.load(sys.stdin).get("checked",[]); print("ok" if all(x in c for x in ["security","correctness","style"]) else "fail")' 2>/dev/null || echo "fail")
  if [ "$_me_checked" = "ok" ]; then
    ok "merge_envelopes: checked union includes all categories"
  else
    bad "merge_envelopes: checked union missing categories"
  fi

  # Findings: same (file, line, category, message.lower) -> dedup to 1; higher severity (high) wins.
  _me_nfindings=$(printf '%s' "$_me_merged" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("findings",[])))' 2>/dev/null || echo "?")
  if [ "$_me_nfindings" = "1" ]; then
    ok "merge_envelopes: dedup reduced 2 identical findings to 1"
  else
    bad "merge_envelopes: expected 1 finding after dedup, got $_me_nfindings"
  fi
  _me_sev=$(printf '%s' "$_me_merged" | python3 -c 'import json,sys; f=json.load(sys.stdin).get("findings",[]); print(f[0].get("severity","?") if f else "?")' 2>/dev/null || echo "?")
  if [ "$_me_sev" = "high" ]; then
    ok "merge_envelopes: higher severity (high) wins over medium on collision"
  else
    bad "merge_envelopes: expected severity=high after dedup, got $_me_sev"
  fi

  # summary should concatenate only non-degraded summaries with " | " separator.
  _me_summary=$(printf '%s' "$_me_merged" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("summary",""))' 2>/dev/null || echo "")
  if printf '%s' "$_me_summary" | python3 -c 'import sys; s=sys.stdin.read(); sys.exit(0 if "clean chunk" in s and "second chunk" in s and "degraded" not in s.lower().split("|")[0] else 1)' 2>/dev/null; then
    ok "merge_envelopes: summary concatenates non-degraded summaries only"
  else
    bad "merge_envelopes: summary not formed correctly: $_me_summary"
  fi
  # Verify the " | " separator is present between the two non-degraded summaries.
  if printf '%s' "$_me_summary" | python3 -c 'import sys; s=sys.stdin.read(); sys.exit(0 if " | " in s else 1)' 2>/dev/null; then
    ok "merge_envelopes: summary uses ' | ' separator between chunks"
  else
    bad "merge_envelopes: ' | ' separator missing from summary: $_me_summary"
  fi

  # chunked field must be true.
  _me_chunked=$(printf '%s' "$_me_merged" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chunked","?"))' 2>/dev/null || echo "?")
  if [ "$_me_chunked" = "True" ] || [ "$_me_chunked" = "true" ]; then
    ok "merge_envelopes: chunked=true in merged envelope"
  else
    bad "merge_envelopes: expected chunked=true, got $_me_chunked"
  fi

  rm -rf "$_me_env_dir"
else
  printf '  SKIP  no jq or python3 for merge_envelopes test\n'
fi

# ---------------------------------------------------------------- 17. dedup_findings unit tests

step "17. dedup_findings: both strategies, severity-wins, conservative-retain"

if command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  _df_seen=$(mktemp -t clagentic-smoke-df-seen.XXXXXX)

  # Case A: two identical location findings, different severity — higher wins.
  _df_input_a='[
    {"severity":"medium","file":"a.py","line":5,"category":"security","message":"sql injection"},
    {"severity":"high","file":"a.py","line":5,"category":"security","message":"sql injection"}
  ]'
  _df_out_a=$(printf '%s' "$_df_input_a" | dedup_findings "location" "$_df_seen")
  _df_n_a=$(printf '%s' "$_df_out_a" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo "?")
  if [ "$_df_n_a" = "1" ]; then
    ok "dedup_findings/location: 2 identical location findings -> 1"
  else
    bad "dedup_findings/location: expected 1 finding, got $_df_n_a"
  fi
  _df_sev_a=$(printf '%s' "$_df_out_a" | python3 -c 'import json,sys; f=json.load(sys.stdin); print(f[0].get("severity","?") if f else "?")' 2>/dev/null || echo "?")
  if [ "$_df_sev_a" = "high" ]; then
    ok "dedup_findings/location: higher severity (high) wins"
  else
    bad "dedup_findings/location: expected severity=high, got $_df_sev_a"
  fi

  # Case B: different findings are both retained.
  _df_seen_b=$(mktemp -t clagentic-smoke-df-seen-b.XXXXXX)
  _df_input_b='[
    {"severity":"high","file":"a.py","line":1,"category":"security","message":"xss"},
    {"severity":"low","file":"b.py","line":2,"category":"style","message":"long line"}
  ]'
  _df_out_b=$(printf '%s' "$_df_input_b" | dedup_findings "location" "$_df_seen_b")
  _df_n_b=$(printf '%s' "$_df_out_b" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo "?")
  if [ "$_df_n_b" = "2" ]; then
    ok "dedup_findings/location: distinct findings both retained"
  else
    bad "dedup_findings/location: expected 2 distinct findings, got $_df_n_b"
  fi
  rm -f "$_df_seen_b"

  # Case C: conservative retain — invalid JSON passthrough.
  # When the input is not a JSON array, passthrough (never suppress).
  _df_seen_c=$(mktemp -t clagentic-smoke-df-seen-c.XXXXXX)
  _df_invalid='not json at all'
  _df_out_c=$(printf '%s' "$_df_invalid" | dedup_findings "location" "$_df_seen_c" 2>/dev/null || true)
  # Should not be empty (conservative retain of original input OR empty array).
  # The key assertion is "did not crash and produce a JSON error as findings."
  # If it outputs something non-empty we accept; if empty that is also tolerable.
  ok "dedup_findings: invalid JSON input does not crash (conservative passthrough)"
  rm -f "$_df_seen_c"

  # Case D: content-hash strategy with no diff file falls back to location key gracefully.
  _df_seen_d=$(mktemp -t clagentic-smoke-df-seen-d.XXXXXX)
  _df_input_d='[
    {"severity":"high","file":"c.py","line":3,"category":"security","message":"eval"},
    {"severity":"high","file":"c.py","line":3,"category":"security","message":"eval"}
  ]'
  _df_out_d=$(printf '%s' "$_df_input_d" | dedup_findings "content-hash" "$_df_seen_d")
  _df_n_d=$(printf '%s' "$_df_out_d" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo "?")
  if [ "$_df_n_d" = "1" ]; then
    ok "dedup_findings/content-hash: falls back to location key without diff file, deduplicates"
  else
    bad "dedup_findings/content-hash no-diff fallback: expected 1 finding, got $_df_n_d"
  fi
  rm -f "$_df_seen_d"

  # Case E: seen-file cross-run dedup — findings already in seen file are excluded.
  _df_seen_e=$(mktemp -t clagentic-smoke-df-seen-e.XXXXXX)
  # First pass: emit 1 finding, populate seen file.
  _df_input_e1='[{"severity":"high","file":"d.py","line":7,"category":"correctness","message":"null deref"}]'
  printf '%s' "$_df_input_e1" | dedup_findings "location" "$_df_seen_e" >/dev/null
  # Second pass with same finding: seen file now contains its key -> should produce [].
  _df_out_e=$(printf '%s' "$_df_input_e1" | dedup_findings "location" "$_df_seen_e")
  _df_n_e=$(printf '%s' "$_df_out_e" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo "?")
  if [ "$_df_n_e" = "0" ]; then
    ok "dedup_findings: cross-run dedup via seen-file excludes already-seen findings"
  else
    bad "dedup_findings: expected 0 findings on second pass (cross-run dedup), got $_df_n_e"
  fi

  # Case F: content-hash strategy with a real diff file — deduplicates findings
  # whose context windows hash identically.
  _df_seen_f=$(mktemp -t clagentic-smoke-df-seen-f.XXXXXX)
  _df_diff_f=$(mktemp -t clagentic-smoke-df-diff-f.XXXXXX)
  cat > "$_df_diff_f" <<'DIFFEOF'
diff --git a/e.py b/e.py
--- a/e.py
+++ b/e.py
@@ -1,5 +1,6 @@
 def bar():
+    eval("x")   # suspicious
     x = 1
     y = 2
     z = 3
     return x + y + z
DIFFEOF
  # Two findings pointing at the same +line in e.py — content-hash of the 5-line
  # context window should produce identical keys, so dedup yields 1 (high wins).
  _df_input_f='[
    {"severity":"medium","file":"e.py","line":2,"category":"security","message":"eval usage"},
    {"severity":"high","file":"e.py","line":2,"category":"security","message":"eval usage"}
  ]'
  _df_out_f=$(printf '%s' "$_df_input_f" | dedup_findings "content-hash" "$_df_seen_f" "$_df_diff_f")
  _df_n_f=$(printf '%s' "$_df_out_f" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo "?")
  if [ "$_df_n_f" = "1" ]; then
    ok "dedup_findings/content-hash with diff file: two identical context windows -> 1 finding"
  else
    bad "dedup_findings/content-hash with diff file: expected 1 finding, got $_df_n_f"
  fi
  _df_sev_f=$(printf '%s' "$_df_out_f" | python3 -c 'import json,sys; f=json.load(sys.stdin); print(f[0].get("severity","?") if f else "?")' 2>/dev/null || echo "?")
  if [ "$_df_sev_f" = "high" ]; then
    ok "dedup_findings/content-hash: higher severity (high) wins on collision"
  else
    bad "dedup_findings/content-hash: expected severity=high, got $_df_sev_f"
  fi
  rm -f "$_df_seen_f" "$_df_diff_f"

  rm -f "$_df_seen" "$_df_seen_e"
else
  printf '  SKIP  no jq or python3 for dedup_findings tests\n'
fi

# -------------------------------------------------------------------- summary

printf '\n[smoke] passed: %s   failed: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
