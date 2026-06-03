#!/bin/sh
# clagentic-lite :: LLM role-call wrapper
#
# Role-aware and CLI-agnostic. Each subcommand reads
#   CLAGENTIC_<ROLE>_CMD / _TIER / _CHAIN
# from the environment, resolves tier->model via the
#   CLAGENTIC_MODEL_<CLI>_<TIER>
# table, invokes the configured CLI, and falls through the chain on failure.
#
# Subcommands:
#   review       stdin = diff;       stdout = JSON findings (reviewer.md schema)
#   summarize    stdin = transcript; stdout = one-line summary (<=200 chars)
#   adversarial  stdin = diff;       stdout = markdown attack scenarios
#   merge-gate   stdin = gate-summary JSON; stdout = JSON approve|refuse + reason
#
# Failure semantics:
#   - Each chain step is tried in order. On non-zero exit, parse-fail (for
#     JSON outputs), or empty output, the wrapper advances to the next entry.
#   - If every step fails, the wrapper emits a "degraded but valid" output
#     so the caller (gate orchestrator, hook) never crashes.
#   - Each attempt is logged to .clagentic/audit.db.gate_runs with
#     gate='llm-call', outcome='pass'|'fallback'|'degraded', details=<role:cmd:tier>.

set -e
. "$(dirname "$0")/platform.sh"
ds_load_env

# Tool home: resolved from this script's own location.
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_HOME="$(dirname "$SCRIPTS_DIR")"

# Project root: CLAGENTIC_PROJECT_ROOT wins, then git show-toplevel.
# llm-client.sh writes LLM call audit rows to the enrolled project's audit.db,
# not to $CLAGENTIC_HOME. See gates.sh header for the full rationale.
if [ -n "${CLAGENTIC_PROJECT_ROOT:-}" ]; then
  REPO_ROOT="$CLAGENTIC_PROJECT_ROOT"
else
  REPO_ROOT=$(ds_repo_root || pwd)
fi
AUDIT_DB="$REPO_ROOT/.clagentic/audit.db"

# ---------------------------------------------------------------- prompts -----

ds_build_prompt() {
  cat <<'EOF'
You are the clagentic-lite Builder. Read AGENTS.md in the repository root for
repo-level conventions, then read the user instruction on stdin.

Write, edit, or refactor code on the current feature branch. Follow the hard
contract from .claude/agents/builder.md:
- Never write to the default branch (main).
- Never merge pull requests.
- Never bypass security gates.
- Read every file in full before modifying it.
- Commit in small, reviewable chunks with terse technical messages.

Output your changes as a unified diff or as a clear description of what you
created/changed and in which files, so the caller can apply or review the work.
No emojis. No exclamation points. Match the tone of AGENTS.md.
EOF
}

ds_review_prompt() {
  cat <<'EOF'
You are the clagentic-lite Reviewer. Read the staged git diff on stdin.

Return STRICT JSON matching this schema, no prose before or after:
{
  "summary": "one-sentence overall assessment",
  "checked": ["category", ...],
  "findings": [
    {
      "severity": "low|medium|high|critical",
      "file": "path/relative/to/repo",
      "line": 123,
      "category": "security|correctness|performance|maintainability|style|docs",
      "message": "what is wrong, in one sentence",
      "evidence": "the specific code or pattern that triggered this",
      "suggestion": "concrete fix"
    }
  ]
}

Apply the Pre-Report Gate from .claude/agents/reviewer.md: only report
findings you are >80% confident about. Empty findings is valid and expected
for clean diffs. Do not pad. No emojis. No "looks good to me" filler.
EOF
}

ds_summarize_prompt() {
  cat <<'EOF'
You are the clagentic-lite Summarizer. Read the assistant turn on stdin
and return ONE sentence (max 30 words, <=200 chars total) capturing what
was decided, built, or learned. No preamble. No quotes. No emojis.
EOF
}

ds_adversarial_prompt() {
  cat <<'EOF'
You are the clagentic-lite Auditor in adversarial mode. Read the staged
diff on stdin. Argue, concretely, how a hostile user could exploit each
new or modified input surface. Cite file:line. Name the threat (CWE if
obvious). If nothing is exploitable, say so in one sentence and list the
surfaces you considered. Output is markdown. Non-blocking by design.
EOF
}

ds_merge_gate_prompt() {
  cat <<'EOF'
You are the clagentic-lite Merge Gate. Read the gate-summary JSON on
stdin (outputs of secrets/deps/sast/review/adversarial gates). Decide
whether the change is safe to merge.

Return STRICT JSON: {"decision":"approve|refuse","reason":"<one sentence>"}

Refuse on any blocking gate failure, on any review finding at or above
the configured severity threshold, or on contradictions between gates
(e.g. review says clean but sast errored). Approve only when every
blocking gate passed AND the adversarial output, if present, contains no
unmitigated CWE-cited attack.
EOF
}

# ----------------------------------------------------- env / tier resolution --

# Read CLAGENTIC_<ROLE>_<FIELD> with a fallback default.
# Args: ROLE_UPPER FIELD DEFAULT
role_env() {
  RU="$1"; F="$2"; DEF="$3"
  V=$(eval "printf '%s' \"\${CLAGENTIC_${RU}_${F}-}\"")
  [ -n "$V" ] && { printf '%s' "$V"; return; }
  printf '%s' "$DEF"
}

# Resolve a "cmd:tier" pair to a concrete (cmd, model) by consulting
# CLAGENTIC_MODEL_<CLI>_<TIER>. Emits "<cmd>\t<model>" on stdout. Model may
# be empty if the table has no entry — the CLI is then invoked without a
# model flag (it uses its own default).
#
# Resolution order for the codex CLI:
#   1. CLAGENTIC_MODEL_CODEX_<TIER> env var (set in ~/.config/clagentic/config)
#   2. ~/.codex/models.json tiers.<tier>.model  (runtime tier map, never stale)
#   3. Empty — codex uses its own default
#
# The models.json path is the workspace subagent pattern: one file to update
# when OpenAI renames models, consulted at runtime so enrolled projects do not
# need to re-run `clagentic-lite init` after a model rename. Env vars always win so
# users who prefer explicit control can still pin via config.
resolve_step() {
  STEP="$1"
  # Parse cmd[:tier]. POSIX `cut -d:` on a string with no `:` returns the
  # whole input as both -f1 and -f2 — `claude` would yield TIER="claude"
  # and resolve CLAGENTIC_MODEL_CLAUDE_CLAUDE instead of CLAUDE_DEFAULT.
  # Detect the colon explicitly to default tier correctly.
  case "$STEP" in
    *:*)
      CLI=$(printf '%s' "$STEP" | cut -d: -f1)
      TIER=$(printf '%s' "$STEP" | cut -d: -f2-)
      ;;
    *)
      CLI="$STEP"
      TIER="default"
      ;;
  esac
  [ -z "$TIER" ] && TIER="default"
  # Uppercase via tr (POSIX, no bash ${var^^}).
  CLI_U=$(printf '%s' "$CLI" | tr '[:lower:]-' '[:upper:]_')
  TIER_U=$(printf '%s' "$TIER" | tr '[:lower:]-' '[:upper:]_')
  MODEL=$(eval "printf '%s' \"\${CLAGENTIC_MODEL_${CLI_U}_${TIER_U}-}\"")

  # For codex: if no env-var model, probe ~/.codex/models.json.
  # Tier names in models.json mirror clagentic tiers: flagship, mini, spark.
  # "default" maps to the default_tier entry in models.json.
  if [ -z "$MODEL" ] && [ "$CLI" = "codex" ]; then
    _mjson="$HOME/.codex/models.json"
    if [ -f "$_mjson" ]; then
      _mj_tier="$TIER"
      # "default" -> read default_tier from the file, then look up that tier.
      if [ "$_mj_tier" = "default" ] && command -v python3 >/dev/null 2>&1; then
        _mj_default=$(python3 -c "
import json,sys
try:
  d=json.load(open('$_mjson'))
  print(d.get('default_tier','flagship'))
except: pass
" 2>/dev/null)
        [ -n "$_mj_default" ] && _mj_tier="$_mj_default"
      fi
      if command -v python3 >/dev/null 2>&1; then
        MODEL=$(python3 -c "
import json,sys
try:
  d=json.load(open('$_mjson'))
  print(d.get('tiers',{}).get('$_mj_tier',{}).get('model',''))
except: pass
" 2>/dev/null) || MODEL=""
      elif command -v jq >/dev/null 2>&1; then
        MODEL=$(jq -r ".tiers[\"$_mj_tier\"].model // empty" "$_mjson" 2>/dev/null) || MODEL=""
      fi
    fi
  fi

  printf '%s\t%s' "$CLI" "$MODEL"
}

# Build the ordered chain for a role: primary first, then CHAIN entries.
# Echoes one "cmd:tier" per line.
role_chain() {
  RU="$1"
  PRI_CMD=$(role_env "$RU" CMD "")
  PRI_TIER=$(role_env "$RU" TIER "default")
  [ -n "$PRI_CMD" ] && printf '%s:%s\n' "$PRI_CMD" "$PRI_TIER"
  CHAIN=$(role_env "$RU" CHAIN "")
  if [ -n "$CHAIN" ]; then
    # Split on commas. POSIX-safe.
    OLD_IFS="$IFS"; IFS=,
    for entry in $CHAIN; do
      # Trim surrounding whitespace.
      e=$(printf '%s' "$entry" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
      [ -n "$e" ] && printf '%s\n' "$e"
    done
    IFS="$OLD_IFS"
  fi
  # Summarizer-only code-level default. Gate 7 (Stop-hook per-turn summary) is
  # best-effort; older installs whose config predates the CLAGENTIC_SUMMARIZER_*
  # block resolve an empty chain and emit a noisy degraded banner. If the
  # summarizer has no primary CMD and no CHAIN, fall back to the Builder's
  # configured CLI at the cheapest tier the project uses for summaries. Anyone
  # who can run the tool at all has a Builder configured, so the summarizer then
  # silently works. Scoped to SUMMARIZER on purpose: a missing reviewer/auditor/
  # gate is a real problem and must stay visible — only the summarizer is benign.
  if [ "$RU" = "SUMMARIZER" ] && [ -z "$PRI_CMD" ] && [ -z "$CHAIN" ]; then
    BUILDER_CMD=$(role_env BUILDER CMD "")
    [ -n "$BUILDER_CMD" ] && printf '%s:cheap\n' "$BUILDER_CMD"
  fi
  # Always succeed: role_chain is consumed in a command substitution under
  # `set -e`. A trailing false test (empty builder fallback) would otherwise
  # propagate non-zero and abort the caller mid-resolution.
  return 0
}

# ----------------------------------------------------------- CLI invocation ---

# Log one chain attempt to audit.db. Goes through ds_audit_log so the
# string interpolation is SQL-escaped and the repo-root resolution is correct.
# Args: ROLE CLI TIER OUTCOME [ERR_HINT]
log_attempt() {
  ROLE="$1"; CLI="$2"; TIER="$3"; OUTCOME="$4"; HINT="${5:-}"
  DETAILS="$ROLE:$CLI:$TIER"
  [ -n "$HINT" ] && DETAILS="$DETAILS — $HINT"
  ds_audit_log llm-call "$OUTCOME" "$DETAILS"
}

# Configurable per-call timeout (seconds). Defaults to 3 minutes — long
# enough for a high-effort review on a deep prompt, short enough that a
# hung CLI surfaces as a step failure rather than wedging the gate.
LLM_TIMEOUT="${CLAGENTIC_LLM_TIMEOUT_SEC:-180}"

# Per-CLI invocation helpers. Each function receives the same fixed args:
#   MODEL PROMPT_FILE INPUT_FILE OUTPUT_FILE ERR_FILE
# Returns 0 on apparent success, non-zero on failure (including exit 124 for
# timeout, 127 for cli-not-on-PATH). The caller (invoke_step) owns the
# command-v check and the timeout command prefix.

# Claude Code headless.
#
# --bare trade-off: it skips hooks/LSP/plugin sync/auto-memory/CLAUDE.md
# auto-discovery, which protects against recursive hook firing when
# this wrapper is invoked from inside an active Claude session.
# BUT --bare also disables OAuth/keychain reads — it requires
# ANTHROPIC_API_KEY (or apiKeyHelper). Default Claude Code users
# auth via OAuth, so --bare would break their setup.
#
# Default behavior: NO --bare. OAuth/keychain auth works; recursion
# protection comes from the prompt-inject.sh / session-start.sh
# hooks honoring CLAGENTIC_DISABLE_RECALL (set internally) instead.
#
# Set CLAGENTIC_CLAUDE_BARE=1 if you authenticate via API key and
# prefer the tighter --bare invocation surface.
invoke_claude() {
  MODEL="$1"; PROMPT_FILE="$2"; INPUT_FILE="$3"; OUTPUT_FILE="$4"; ERR_FILE="$5"
  BARE_FLAG=""
  [ "${CLAGENTIC_CLAUDE_BARE:-0}" = "1" ] && BARE_FLAG="--bare"
  # Tell the inner Claude session NOT to inject recall summaries —
  # this is the recursion-avoidance path that doesn't require --bare.
  export CLAGENTIC_DISABLE_RECALL=1
  if [ -n "$MODEL" ]; then
    # shellcheck disable=SC2086
    cat "$INPUT_FILE" | $DS_TIMEOUT_CMD "$LLM_TIMEOUT" claude --print $BARE_FLAG --model "$MODEL" \
      --append-system-prompt "$(cat "$PROMPT_FILE")" \
      > "$OUTPUT_FILE" 2> "$ERR_FILE"
  else
    # shellcheck disable=SC2086
    cat "$INPUT_FILE" | $DS_TIMEOUT_CMD "$LLM_TIMEOUT" claude --print $BARE_FLAG \
      --append-system-prompt "$(cat "$PROMPT_FILE")" \
      > "$OUTPUT_FILE" 2> "$ERR_FILE"
  fi
}

# Codex non-interactive.
#
# We combine prompt and input into a single temp file and feed it via stdin
# using the documented `-` sentinel (`codex exec - < FILE`). This avoids the
# MAX_ARG_STRLEN ceiling (~131 KB on Linux) that rejects large diffs when the
# combined input is passed as a positional argument. stdin has no such limit.
#
# `codex exec --help`: "If not provided as an argument (or if `-` is used),
# instructions are read from stdin."
#
# stdout from codex exec is progress/spinner output (the final response goes to
# -o OUTPUT_FILE), so we redirect both stdout and stderr to ERR_FILE — that is
# intentional, not a mistake.
invoke_codex() {
  MODEL="$1"; PROMPT_FILE="$2"; INPUT_FILE="$3"; OUTPUT_FILE="$4"; ERR_FILE="$5"
  TMP_COMBINED=$(mktemp -t clagentic-codex-combined.XXXXXX)
  TMP_RAW=$(mktemp -t clagentic-codex-raw.XXXXXX)
  { cat "$PROMPT_FILE"; printf '\n\n'; cat "$INPUT_FILE"; } > "$TMP_COMBINED"
  if [ -n "$MODEL" ]; then
    $DS_TIMEOUT_CMD "$LLM_TIMEOUT" codex exec --skip-git-repo-check -m "$MODEL" \
      --color never -o "$TMP_RAW" - < "$TMP_COMBINED" > "$ERR_FILE" 2>&1
  else
    $DS_TIMEOUT_CMD "$LLM_TIMEOUT" codex exec --skip-git-repo-check \
      --color never -o "$TMP_RAW" - < "$TMP_COMBINED" > "$ERR_FILE" 2>&1
  fi
  EXIT_CODE=$?
  # Strip ANSI CSI sequences from the -o output file before handing it to
  # validate_output. `codex exec -o` should write clean JSON/text, but
  # --color never is advisory and some codex versions leak escape sequences
  # into -o files. A stray ESC sequence causes jq to fail the parse, which
  # then marks the step as schema-invalid and advances the chain — silently
  # turning a working Reviewer into a degraded block. Strip is idempotent on
  # clean output. We already strip the error path (ERR_FILE); this closes
  # the asymmetry noted in the engineering foundry review (F-009).
  if [ -s "$TMP_RAW" ]; then
    sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$TMP_RAW" > "$OUTPUT_FILE" 2>/dev/null || cp "$TMP_RAW" "$OUTPUT_FILE"
  fi
  rm -f "$TMP_COMBINED" "$TMP_RAW"
  return $EXIT_CODE
}

# Generic: pipe prompt+input via stdin to `<cli> -p -`. If the CLI does not
# accept that invocation, the step fails and the chain advances.
invoke_generic() {
  CLI_BIN="$1"; MODEL="$2"; PROMPT_FILE="$3"; INPUT_FILE="$4"; OUTPUT_FILE="$5"; ERR_FILE="$6"
  { cat "$PROMPT_FILE"; printf '\n\n'; cat "$INPUT_FILE"; } | \
    $DS_TIMEOUT_CMD "$LLM_TIMEOUT" "$CLI_BIN" -p - > "$OUTPUT_FILE" 2> "$ERR_FILE"
}

# Dispatch a single chain step. Args: CLI MODEL PROMPT_FILE INPUT_FILE OUTPUT_FILE ERR_FILE
# Fails with exit 127 if the CLI binary is not on PATH.
invoke_step() {
  CLI="$1"; MODEL="$2"; PROMPT_FILE="$3"; INPUT_FILE="$4"; OUTPUT_FILE="$5"; ERR_FILE="$6"
  command -v "$CLI" >/dev/null 2>&1 || return 127
  case "$CLI" in
    claude)  invoke_claude  "$MODEL" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" ;;
    codex)   invoke_codex   "$MODEL" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" ;;
    *)       invoke_generic "$CLI" "$MODEL" "$PROMPT_FILE" "$INPUT_FILE" "$OUTPUT_FILE" "$ERR_FILE" ;;
  esac
}




# Validate output by mode + role. Args: MODE FILE [ROLE]
# Returns 0 if the file matches the EXPECTED SCHEMA for that mode+role —
# not just "is it parseable JSON?". This is what catches the failure case
# where a CLI returns valid JSON like `{"error":"auth expired"}` and the
# wrapper would otherwise accept it as a clean review with zero findings.
validate_output() {
  MODE="$1"; F="$2"; ROLE="${3:-}"
  [ -s "$F" ] || return 1
  case "$MODE" in
    json)
      # Pick the per-role required shape.
      # - reviewer/auditor: top-level .findings must be an array
      # - gate: top-level .decision must be "approve" or "refuse"
      # - other roles: accept any valid JSON object
      if command -v jq >/dev/null 2>&1; then
        jq -e . "$F" >/dev/null 2>&1 || return 1
        case "$ROLE" in
          reviewer|auditor)
            # .findings must be an array; if findings exist, each must have
            # a severity that normalizes to one of the four valid tiers.
            # Catches `{"findings":[{"severity":"HIGH"}]}` (would pass with
            # plain array check) AND `{"findings":[{"severity":"oops"}]}`.
            jq -e '.findings | type == "array"' "$F" >/dev/null 2>&1 || return 1
            jq -e '.findings // [] | all(.severity == null or (.severity | ascii_downcase | IN("low","medium","high","critical")))' "$F" >/dev/null 2>&1 || return 1
            ;;
          gate)
            # Decision must be approve|refuse, case-insensitive.
            jq -e '.decision | ascii_downcase | IN("approve","refuse")' "$F" >/dev/null 2>&1 || return 1
            ;;
        esac
        return 0
      elif command -v python3 >/dev/null 2>&1; then
        python3 - "$F" "$ROLE" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
role = sys.argv[2] if len(sys.argv) > 2 else ""
if role in ("reviewer", "auditor"):
    if not isinstance(d.get("findings"), list):
        sys.exit(1)
elif role == "gate":
    if d.get("decision") not in ("approve", "refuse"):
        sys.exit(1)
sys.exit(0)
PY
        return $?
      else
        # No JSON validator available (no jq, no python3). For JSON-gated
        # roles we cannot prove schema, so we fail closed — the chain
        # advances to the next step or to the degraded envelope. This is
        # the "same shape as missing security tools" principle: if the
        # gate can't be evaluated, the gate is offline, the gate blocks.
        return 1
      fi
      ;;
    line)
      # Any non-empty payload; truncated to 200 chars downstream.
      return 0
      ;;
    markdown|*)
      return 0
      ;;
  esac
}

# Walk the chain for a role. Args: ROLE_LOWER MODE PROMPT_FUNC
# Reads input from stdin, writes successful output to stdout.
#
# IMPORTANT: the chain loop reads from a temp file via < redirection (NOT a
# pipe) so the loop body runs in the parent shell. With `while … | read`,
# the body would run in a subshell and `return 0` would escape only the
# subshell, leaving every successful call to fall through to the degraded
# envelope at function exit.
walk_chain() {
  ROLE_L="$1"; MODE="$2"; PFUNC="$3"
  ROLE_U=$(printf '%s' "$ROLE_L" | tr '[:lower:]-' '[:upper:]_')

  TMP_IN=$(mktemp -t clagentic-in.XXXXXX)
  TMP_PROMPT=$(mktemp -t clagentic-prompt.XXXXXX)
  TMP_OUT=$(mktemp -t clagentic-out.XXXXXX)
  TMP_ERR=$(mktemp -t clagentic-err.XXXXXX)
  TMP_CHAIN=$(mktemp -t clagentic-chain.XXXXXX)
  # No EXIT trap: traps in POSIX sh are shell-wide, not function-scoped, and
  # would leak across repeated calls in the same process. Clean up explicitly
  # at every return path.

  cat > "$TMP_IN"
  $PFUNC > "$TMP_PROMPT"
  role_chain "$ROLE_U" > "$TMP_CHAIN"

  if [ ! -s "$TMP_CHAIN" ]; then
    if [ "$ROLE_U" = "SUMMARIZER" ]; then
      # Best-effort role with no chain (and no Builder fallback): emit nothing
      # and log a clean skip. memory.sh cmd_summarize_turn already guards on an
      # empty summary ("empty summary, skipping"), so empty stdout is the
      # correct silent no-op. No scary degraded banner for a benign role.
      log_attempt "$ROLE_L" "" "" "skip" "no chain configured"
    else
      emit_degraded "$MODE" "no chain configured for role $ROLE_L"
      log_attempt "$ROLE_L" "" "" "degraded" ""
    fi
    rm -f "$TMP_IN" "$TMP_PROMPT" "$TMP_OUT" "$TMP_ERR" "$TMP_CHAIN"
    return 0
  fi

  ATTEMPT=0
  RESULT=1
  while IFS= read -r STEP; do
    [ -z "$STEP" ] && continue
    ATTEMPT=$((ATTEMPT+1))
    PAIR=$(resolve_step "$STEP")
    CLI=$(printf '%s' "$PAIR" | cut -f1)
    MODEL=$(printf '%s' "$PAIR" | cut -f2)
    # Audit tier: extract from the same parse resolve_step uses (colon-aware,
    # defaults to "default"). Avoids logging tier="claude" when the chain
    # entry was just `claude` with no `:tier` suffix.
    case "$STEP" in
      *:*) TIER=$(printf '%s' "$STEP" | cut -d: -f2-) ;;
      *)   TIER="default" ;;
    esac
    [ -z "$TIER" ] && TIER="default"
    # Truncate BOTH err and output files between attempts. Without truncating
    # TMP_OUT, a successful-on-write-but-exit-nonzero primary could leave
    # stale bytes that validate as the fallback step's "output."
    : > "$TMP_ERR"
    : > "$TMP_OUT"
    EXIT_CODE=0
    invoke_step "$CLI" "$MODEL" "$TMP_PROMPT" "$TMP_IN" "$TMP_OUT" "$TMP_ERR" \
      || EXIT_CODE=$?
    if [ "$EXIT_CODE" -eq 0 ] && validate_output "$MODE" "$TMP_OUT" "$ROLE_L"; then
      if [ "$ATTEMPT" -eq 1 ]; then
        log_attempt "$ROLE_L" "$CLI" "$TIER" "pass" ""
      else
        log_attempt "$ROLE_L" "$CLI" "$TIER" "fallback" ""
      fi
      cat "$TMP_OUT"
      RESULT=0
      break
    fi
    # Step failed. Capture a diagnostic hint for the audit row. For CLIs like
    # codex whose error output is ANSI-decorated multi-line banners, we strip
    # escape sequences and skip blank lines to reach the actual error message.
    # This is what surfaces "model not available on this account" / "auth
    # expired" / "timeout" rather than a blank or a spinner artifact.
    if [ "$EXIT_CODE" -eq 124 ]; then
      ERR_HINT="timeout after ${LLM_TIMEOUT}s"
    elif [ "$EXIT_CODE" -eq 127 ]; then
      ERR_HINT="cli not on PATH"
    elif [ -s "$TMP_ERR" ]; then
      # Strip ANSI CSI sequences (ESC [ ... m) then take the first non-empty line.
      # sed -E is not POSIX but is available on every target (GNU + BSD sed both
      # support it). POSIX fallback: if sed -E fails, fall back to head -1.
      ERR_HINT=$(sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$TMP_ERR" 2>/dev/null \
        | grep -v '^[[:space:]]*$' | head -1 | cut -c1-200) || \
        ERR_HINT=$(head -1 "$TMP_ERR" | cut -c1-200)
      [ -z "$ERR_HINT" ] && ERR_HINT="non-empty stderr (exit=$EXIT_CODE)"
    elif [ -s "$TMP_OUT" ]; then
      ERR_HINT="output failed schema validation"
    else
      ERR_HINT="empty output (exit=$EXIT_CODE)"
    fi
    log_attempt "$ROLE_L" "$CLI" "$TIER" "step-failed" "$ERR_HINT"
  done < "$TMP_CHAIN"

  if [ "$RESULT" -ne 0 ]; then
    # CLAGENTIC_<ROLE>_REQUIRED=1 makes a full-chain failure hard: the wrapper
    # exits non-zero instead of emitting a degraded envelope. Use this when the
    # cross-vendor property is non-negotiable — e.g. CLAGENTIC_REVIEWER_REQUIRED=1
    # ensures a claude-only fallback is a detectable gate failure, not a silent
    # same-vendor review.
    REQUIRED_KEY="CLAGENTIC_$(printf '%s' "$ROLE_U" | tr '[:lower:]-' '[:upper:]_')_REQUIRED"
    IS_REQUIRED=$(eval "printf '%s' \"\${${REQUIRED_KEY}:-0}\"")
    if [ "$IS_REQUIRED" = "1" ]; then
      printf '[clagentic-lite/llm-client] HARD FAILURE: all chain steps failed for required role %s\n' "$ROLE_L" 1>&2
      log_attempt "$ROLE_L" "" "" "hard-failure" "required role — no fallback permitted"
      rm -f "$TMP_IN" "$TMP_PROMPT" "$TMP_OUT" "$TMP_ERR" "$TMP_CHAIN"
      return 1
    fi
    emit_degraded "$MODE" "all chain steps failed for role $ROLE_L"
    log_attempt "$ROLE_L" "" "" "degraded" ""
  fi
  rm -f "$TMP_IN" "$TMP_PROMPT" "$TMP_OUT" "$TMP_ERR" "$TMP_CHAIN"
  return 0
}

# Degraded envelopes — valid output shapes the caller can still parse.
# The "degraded": true field is the load-bearing marker: gates.sh treats
# it as a fail-closed condition rather than "0 findings = clean review."
emit_degraded() {
  MODE="$1"; REASON="$2"
  case "$MODE" in
    json)
      cat <<EOF
{
  "degraded": true,
  "summary": "[clagentic-lite degraded] $REASON",
  "checked": [],
  "findings": []
}
EOF
      ;;
    line)
      echo "[clagentic-lite degraded] $REASON"
      ;;
    markdown|*)
      cat <<EOF
# Degraded output

clagentic-lite role-call wrapper could not produce a real response: $REASON.

This is non-fatal; the calling gate continues. Configure
CLAGENTIC_*_CMD / _CHAIN in .env and ensure the CLIs are on PATH.
EOF
      ;;
  esac
}

# --------------------------------------------------------------- subcommands --

# build: invoke the configured Builder CLI non-interactively. CLAGENTIC_BUILDER_CMD
# and CLAGENTIC_BUILDER_TIER in config control which CLI is used. This is the
# non-interactive parallel to the Claude Code builder.md subagent — same role
# contract, different invocation context (hook-triggered vs. interactive session).
# Stdin: user instruction (free text). Stdout: builder output (diff or prose).
cmd_build()       { walk_chain builder    markdown ds_build_prompt; }
cmd_review()      { walk_chain reviewer   json     ds_review_prompt; }
cmd_summarize()   { walk_chain summarizer line     ds_summarize_prompt | head -c 200; echo; }
cmd_adversarial() { walk_chain auditor    markdown ds_adversarial_prompt; }
cmd_merge_gate()  { walk_chain gate       json     ds_merge_gate_prompt; }

case "${1:-}" in
  build)        cmd_build ;;
  review)       cmd_review ;;
  summarize)    cmd_summarize ;;
  adversarial)  cmd_adversarial ;;
  merge-gate)   cmd_merge_gate ;;
  *) echo "usage: llm-client.sh {build|review|summarize|adversarial|merge-gate}" 1>&2; exit 1 ;;
esac
