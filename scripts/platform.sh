#!/bin/sh
# clagentic-lite :: platform shims
# Detects GNU vs BSD tools and exports portable variants.
# Source this in every script: . "$(dirname "$0")/platform.sh"

# OS detection
case "$(uname -s)" in
  Linux*)  DS_OS="linux" ;;
  Darwin*) DS_OS="darwin" ;;
  *)       DS_OS="unknown" ;;
esac
export DS_OS

# sed -i variant
if sed --version >/dev/null 2>&1; then
  DS_SED_INPLACE="-i"        # GNU
else
  DS_SED_INPLACE="-i ''"     # BSD (macOS)
fi
export DS_SED_INPLACE

# date ISO-8601
if date -Iseconds >/dev/null 2>&1; then
  DS_DATE_ISO_CMD='date -Iseconds'
else
  DS_DATE_ISO_CMD='date -u +%Y-%m-%dT%H:%M:%SZ'
fi
ds_date_iso() { eval "$DS_DATE_ISO_CMD"; }
export DS_DATE_ISO_CMD

# stat mtime (epoch)
if stat -c %Y . >/dev/null 2>&1; then
  ds_stat_mtime() { stat -c %Y "$1"; }    # GNU
else
  ds_stat_mtime() { stat -f %m "$1"; }    # BSD
fi

# File size in bytes (portable: wc -c is POSIX; tr strips any whitespace padding
# that BSD wc emits with leading spaces before the count).
ds_file_size() {
  wc -c < "$1" | tr -d '[:space:]'
}

# Are we under WSL?
DS_WSL=0
if [ "$DS_OS" = "linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
  DS_WSL=1
fi
export DS_WSL

# Repo root: try git first, then walk up looking for a .clagentic-project
# pointer written by `clagentic-lite enroll` when the user enrolled a nested repo
# from a wrapper directory.
ds_repo_root() {
  _drr=$(git rev-parse --show-toplevel 2>/dev/null || true)
  if [ -n "$_drr" ]; then
    printf '%s' "$_drr"
    return
  fi
  # Walk upward from $PWD looking for a wrapper pointer file.
  _d="$PWD"
  while [ "$_d" != "/" ]; do
    if [ -f "$_d/.clagentic-project" ]; then
      # Read first non-empty line as the enrolled repo root.
      _ptr=$(grep -m1 . "$_d/.clagentic-project" 2>/dev/null || true)
      [ -n "$_ptr" ] && printf '%s' "$_ptr" && return
      break
    fi
    _d="$(dirname "$_d")"
  done
  # Both failed — return empty; callers handle the empty case.
}

# Load configuration into the current shell. Load order (each layer can
# override the previous):
#   1. ~/.config/clagentic/config   — global defaults (written by `clagentic-lite init`)
#   2. <project-root>/.clagentic/config — per-repo sparse overrides (optional)
#   3. Legacy: <project-root>/.env  — backward compat; honored if present
#
# Idempotent — honors a CLAGENTIC_ENV_LOADED guard so re-sourcing in the
# same process doesn't double-export. Every runtime entry point (hooks,
# gates.sh, llm-client.sh, memory.sh, smoke.sh) calls this immediately
# after sourcing platform.sh.
ds_load_env() {
  [ "${CLAGENTIC_ENV_LOADED:-0}" = "1" ] && return 0

  # 1. Global config.
  _GLOBAL_CFG="$HOME/.config/clagentic/config"
  if [ -f "$_GLOBAL_CFG" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$_GLOBAL_CFG"
    set +a
  fi

  RR=$(ds_repo_root)
  if [ -n "$RR" ]; then
    # 2. Per-repo sparse config (v0.2: optional; not created by default).
    _REPO_CFG="$RR/.clagentic/config"
    if [ -f "$_REPO_CFG" ]; then
      set -a
      # shellcheck disable=SC1090
      . "$_REPO_CFG"
      set +a
    fi
    # 3. Legacy .env (v0.1 compatibility; honored but not created in v0.2).
    _ENV_FILE="$RR/.env"
    if [ -f "$_ENV_FILE" ]; then
      set -a
      # shellcheck disable=SC1090
      . "$_ENV_FILE"
      set +a
    fi
  fi

  CLAGENTIC_ENV_LOADED=1
  export CLAGENTIC_ENV_LOADED
}

# Portable timeout. GNU coreutils ships `timeout`. macOS does NOT by default —
# users install it via `brew install coreutils` which provides `gtimeout`.
# Detect at source time and export DS_TIMEOUT_CMD. Callers run:
#   $DS_TIMEOUT_CMD "$LLM_TIMEOUT" some-cli ...
#
# FAIL CLOSED, NOT SILENTLY UNBOUNDED (INV-1a, class-4 foundry fix). This
# used to fall back to `ds_no_timeout() { shift; "$@"; }` — a stub that
# DISCARDED the duration argument and ran the wrapped command with NO bound
# at all when neither `timeout` nor `gtimeout` was on PATH. Every timeout in
# gates.sh and llm-client.sh routes through $DS_TIMEOUT_CMD, including the
# freshness-check fetches _gate_resolve_fresh_default_branch_ref uses to
# prove a diff baseline hasn't gone stale (its own documented guarantee, "a
# fetch that timed out is treated as a failed fetch", held only because a
# real timeout binary happened to be present — nothing enforced that
# precondition). On a host missing both binaries, EVERY timeout in this
# codebase silently evaporated: a hung `git fetch`, a runaway `semgrep
# --config=auto` network pull, or an LLM CLI call that never returns would
# block a blocking gate indefinitely with no diagnostic, and the freshness
# helper's own safety story became conditional on a binary nobody checked
# for. This fixes zero reported bugs on its own; it makes every other
# timeout in the codebase MEAN what it says.
#
# `ds_timeout_missing` is set as DS_TIMEOUT_CMD instead of ds_no_timeout: it
# still ACCEPTS the same "$DURATION cmd..." call shape every caller already
# uses (so no call site needs to change), but instead of silently dropping
# the duration and running unbounded, it prints a clear diagnostic and
# returns a distinct, greppable exit status (99) the FIRST TIME it is
# actually invoked. This is deliberately NOT a hard `exit` at platform.sh
# SOURCE time: bin/clagentic-lite sources platform.sh unconditionally before
# dispatching to any subcommand, including `doctor` itself — the one tool
# meant to diagnose exactly this gap. A source-time exit would make `doctor`
# unusable on the host it exists to help. Failing at the point of USE (the
# first attempted timeout-bounded call) is "startup failure" for the gate or
# LLM call that needed the bound, without making an unrelated `clagentic-lite
# doctor`/`init` invocation collateral damage.
ds_timeout_missing() {
  # First arg is the (now-refused) duration; the rest is the command that
  # would have run unbounded. Neither is executed.
  shift
  printf 'clagentic-lite: no timeout binary found (checked: timeout, gtimeout) -- refusing to run "%s" unbounded.\n' "$*" 1>&2
  printf '  install: apt install coreutils | brew install coreutils (provides gtimeout on macOS)\n' 1>&2
  printf '  every external process invocation and LLM call in this codebase requires a real timeout binary -- see AGENTS.md Invariants, INV-1a.\n' 1>&2
  return 99
}
if command -v timeout >/dev/null 2>&1; then
  DS_TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  DS_TIMEOUT_CMD="gtimeout"
else
  DS_TIMEOUT_CMD="ds_timeout_missing"
fi
export DS_TIMEOUT_CMD

# ---------------------------------------------------------------- shared helpers

# Escape a string for safe single-quoted SQL interpolation.
# POSIX sed: replace every single quote with two single quotes.
ds_sql_escape() {
  printf '%s' "$1" | sed "s/'/''/g"
}

# ds_positive_int_or_default VALUE DEFAULT — normalize VALUE to a positive
# (>= 1) integer, falling back to DEFAULT on empty, non-numeric, OR ZERO
# input. Prints the result on stdout.
#
# WHY THIS EXISTS (lr-49df97 fold-in, BOBBIE finding 3): every wall-clock
# timeout guard in this codebase used the same two-line idiom —
#   case "$VAR" in ''|*[!0-9]*) VAR=default ;; esac
# — which rejects empty and non-digit input but ADMITS the single-digit
# string "0" unchanged, because "0" contains no non-digit character. A
# timeout variable that survives this guard as literal 0 then reaches
# `$DS_TIMEOUT_CMD 0 cmd...` (GNU/BSD `timeout 0` / `gtimeout 0`), and GNU
# coreutils' own documented behavior for `timeout 0 cmd` is to DISABLE the
# timeout entirely and run cmd unbounded — the exact silent-no-op shape
# INV-1a already forbids for a missing timeout binary, reachable here
# through a config value that LOOKS validated (it passed the existing
# numeric guard) rather than through a missing binary. This is the same
# defect class as the DS_TIMEOUT_CMD no-op (INV-1a) and the old
# CALL_ROLE-shaped accepted-but-unread parameter (INV-3): a control that
# LOOKS enforced but silently admits the one value that defeats it.
#
# Fixed EVERYWHERE the pattern occurs on a timeout-like variable (gates.sh
# run_bounded/cmd_secrets/cmd_deps/cmd_bleed/cmd_sast/get_review_diff/
# cmd_ship, llm-client.sh llm_timeout_for's BASE/MAX) rather than at one
# call site — a per-site patch here would be exactly the instance-fixing
# AGENTS.md's Invariants section and the sweeping-test-discovery convention
# both exist to close; see test_invariants.py's sweep for the mechanical
# check that no call site regresses to the bare case-guard idiom.
#
# Deliberately NOT used for CLAGENTIC_LLM_TIMEOUT_MAX_SEC's own MAX
# semantics (llm_timeout_for, llm-client.sh): that variable's 0 is a
# DELIBERATE, DOCUMENTED "no cap" sentinel ("Cap at max when max is set and
# positive") — a pre-existing, intentional, different meaning of zero, not
# an instance of this defect. Only BASE timeouts (the wall-clock bound
# actually handed to $DS_TIMEOUT_CMD) are in scope for this helper.
ds_positive_int_or_default() {
  _dpiod_val="$1"
  _dpiod_default="$2"
  case "$_dpiod_val" in ''|*[!0-9]*) _dpiod_val="$_dpiod_default" ;; esac
  [ "$_dpiod_val" -le 0 ] 2>/dev/null && _dpiod_val="$_dpiod_default"
  printf '%s' "$_dpiod_val"
}

# Write one row to .clagentic/lite/audit.db. Resolves repo root itself so callers
# from any cwd (subdirectory hook invocations, etc.) hit the right DB.
# Args: GATE OUTCOME DETAILS [SESSION_ID]
# Silent on any failure — audit logging is best-effort by contract.
ds_audit_log() {
  GATE="$1"; OUTCOME="$2"; DETAILS="${3:-}"; SID="${4:-}"
  RR=$(ds_repo_root)
  [ -n "$RR" ] || return 0
  DB="$RR/.clagentic/lite/audit.db"
  [ -f "$DB" ] || return 0
  G_ESC=$(ds_sql_escape "$GATE")
  O_ESC=$(ds_sql_escape "$OUTCOME")
  D_ESC=$(ds_sql_escape "$DETAILS")
  S_ESC=$(ds_sql_escape "$SID")
  sqlite3 "$DB" \
    "INSERT INTO gate_runs (ts, gate, outcome, details, session_id) VALUES (datetime('now'), '$G_ESC', '$O_ESC', '$D_ESC', '$S_ESC');" 2>/dev/null || true
}

# Extract a top-level string field from a JSON object on stdin.
# Args: FIELD_NAME
# Uses jq if present, python3 as fallback. Robust against escaped quotes and
# unicode escapes — sed-based parsing was vulnerable to truncation on `\"`.
#
# Exit codes:
#   0 — field extracted (may be empty if the JSON has it set to "")
#   1 — JSON parse error
#   2 — NO VALIDATOR AVAILABLE. Caller MUST fail closed: a hook without a
#       JSON validator cannot trust its input, so it must block rather than
#       silently exit 0.
ds_json_field() {
  FIELD="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg f "$FIELD" '.[$f] // empty' 2>/dev/null
    return $?
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys
try:
    obj = json.load(sys.stdin)
    v = obj.get(sys.argv[1], "")
    if v is None: v = ""
    sys.stdout.write(str(v))
except Exception:
    sys.exit(1)
' "$FIELD" 2>/dev/null
    return $?
  else
    # No validator. Fail closed signal to the caller.
    return 2
  fi
}

# ---------------------------------------------------------------- tool detection
#
# ds_check_tool NAME HINT_LINUX HINT_DARWIN
#   Prints "found: /path" or "MISSING — install: <hint>" based on OS.
#   Returns 0 if found, 1 if missing.
#   REQUIRED flag: when the fourth arg is "required", also sets DS_CHECK_MISSING
#   (caller initializes DS_CHECK_MISSING=0 before a loop and inspects after).
#
# ds_offer_install NAME HINT_LINUX HINT_DARWIN
#   Calls ds_check_tool. If missing and stdin is a TTY, prompts
#   "Run it now? [y/N]:" and on 'y' execs the install command.
#   On 'N' (or non-TTY), prints the manual command and returns 1.
#   Returns 0 if the tool was already present, or if the user ran the install
#   command successfully. Returns 1 if the user declined or the install failed.
#   Callers use this for REQUIRED tools where a missing tool is a hard stop.
#
#   The prompt is suppressed (and the hint printed as manual instructions only)
#   when the hint is not a runnable shell command:
#     - hint starts with "see " (documentation pointer, e.g. "see https://...")
#     - hint contains "://" (any URL — same idea)
#     - hint's first token is not on PATH (e.g. "pipx install ..." on a host
#       without pipx, "brew install ..." on Linux, "apt install ..." on macOS)
#   This prevents the "Run it now? y -> eval: see: not found" footgun where we
#   feed a non-command to `eval` and the user watches it fail in real time.

ds_check_tool() {
  _CT_NAME="$1"
  _CT_LINUX="$2"
  _CT_DARWIN="$3"
  _CT_FLAG="${4:-}"
  if command -v "$_CT_NAME" >/dev/null 2>&1; then
    printf '  %-15s found: %s\n' "$_CT_NAME" "$(command -v "$_CT_NAME")"
    return 0
  fi
  if [ "$DS_OS" = "darwin" ]; then
    printf '  %-15s MISSING — install: %s\n' "$_CT_NAME" "$_CT_DARWIN"
  else
    printf '  %-15s MISSING — install: %s\n' "$_CT_NAME" "$_CT_LINUX"
  fi
  if [ "${_CT_FLAG:-}" = "required" ]; then
    DS_CHECK_MISSING=$((${DS_CHECK_MISSING:-0}+1))
    export DS_CHECK_MISSING
  fi
  return 1
}

ds_offer_install() {
  _OI_NAME="$1"
  _OI_LINUX="$2"
  _OI_DARWIN="$3"
  if command -v "$_OI_NAME" >/dev/null 2>&1; then
    printf '  %-15s found: %s\n' "$_OI_NAME" "$(command -v "$_OI_NAME")"
    return 0
  fi
  if [ "$DS_OS" = "darwin" ]; then
    _OI_HINT="$_OI_DARWIN"
  else
    _OI_HINT="$_OI_LINUX"
  fi
  printf 'MISSING: %s — install with: %s\n' "$_OI_NAME" "$_OI_HINT"

  # Decide whether the hint is actually a runnable command. If not, fall
  # through to "Run manually" without prompting — pasting a doc URL into
  # `eval` just produces a confusing "command not found" right after the
  # user said yes. Three rejection rules:
  #   1. starts with "see " (e.g. "see https://github.com/...")
  #   2. contains "://" (any URL slipped in elsewhere)
  #   3. first token is not on PATH (e.g. pipx/brew/apt unavailable here)
  _OI_RUNNABLE=1
  case "$_OI_HINT" in
    "see "*|*"://"*) _OI_RUNNABLE=0 ;;
  esac
  if [ "$_OI_RUNNABLE" -eq 1 ]; then
    # First whitespace-delimited token — POSIX, no arrays.
    _OI_FIRST=$(printf '%s' "$_OI_HINT" | awk '{print $1}')
    if [ -n "$_OI_FIRST" ] && ! command -v "$_OI_FIRST" >/dev/null 2>&1; then
      _OI_RUNNABLE=0
      printf '  (note: %s not on PATH — cannot run the suggested command for you)\n' \
        "$_OI_FIRST"
    fi
  fi

  if [ "$_OI_RUNNABLE" -eq 1 ] && [ -t 0 ]; then
    printf 'Run it now? [y/N]: '
    read -r _OI_REPLY || _OI_REPLY=""
    case "$_OI_REPLY" in
      y|Y|yes|YES)
        # exec the install command; eval needed because hint may be multi-word
        if eval "$_OI_HINT"; then
          printf '  %s installed\n' "$_OI_NAME"
          return 0
        else
          printf '  install command failed — install manually and re-run\n' 1>&2
          ds_pending_record "$_OI_NAME" "$_OI_HINT"
          return 1
        fi
        ;;
    esac
  fi
  printf '  Run manually: %s\n' "$_OI_HINT"
  ds_pending_record "$_OI_NAME" "$_OI_HINT"
  return 1
}

# ds_pending_record NAME HINT — append a still-missing tool to the pending
# list so the caller can print a single collated summary at the end of a
# prereq check. Newline-separated NAME|HINT pairs. Idempotent: skips duplicates
# (the same tool might be checked from multiple call sites in the future).
ds_pending_record() {
  _PR_NAME="$1"
  _PR_HINT="$2"
  _PR_ENTRY="$_PR_NAME|$_PR_HINT"
  case "
${DS_PENDING_INSTALLS:-}
" in
    *"
$_PR_ENTRY
"*) return 0 ;;
  esac
  if [ -z "${DS_PENDING_INSTALLS:-}" ]; then
    DS_PENDING_INSTALLS="$_PR_ENTRY"
  else
    DS_PENDING_INSTALLS="$DS_PENDING_INSTALLS
$_PR_ENTRY"
  fi
  export DS_PENDING_INSTALLS
}

# ds_pending_summary — print the collated still-missing-tools block.
# No-op when the list is empty. Output goes to stdout; caller decides whether
# to also exit non-zero (init prefers to warn-and-continue).
ds_pending_summary() {
  [ -z "${DS_PENDING_INSTALLS:-}" ] && return 0
  printf '\n--- still to install (run these manually, then re-run \`clagentic-lite init\`) ---\n'
  # POSIX-safe iteration over newline-separated entries: substitute IFS for
  # the loop, avoid bashisms.
  _OLD_IFS="${IFS-}"
  IFS='
'
  for _PS_ENTRY in $DS_PENDING_INSTALLS; do
    _PS_NAME="${_PS_ENTRY%%|*}"
    _PS_HINT="${_PS_ENTRY#*|}"
    printf '  %-15s  %s\n' "$_PS_NAME" "$_PS_HINT"
  done
  IFS="$_OLD_IFS"
  printf '\n'
}

# ds_pending_reset — clear the pending list. Call at the top of a fresh
# prereq pass so re-entry (e.g. cmd_update calling the same helpers) starts
# clean.
ds_pending_reset() {
  DS_PENDING_INSTALLS=""
  export DS_PENDING_INSTALLS
}

# ------------------------------------------------ LLM-text sanitization ------
#
# Moved here from gates.sh (lr-4f8316 follow-up). Both functions are
# unchanged behavior from their original gates.sh bodies — this is a
# relocation, not a rewrite. WHY HERE: llm-client.sh interpolates external
# text (a change-class hint read from a commit message) directly into a
# system prompt, but llm-client.sh does not source gates.sh — only
# platform.sh, which every prompt-constructing script in this codebase
# already sources. The gap that shipped an unsanitized interpolation (the
# change-class hint had no sanitizer call, no fence, no data-vs-instruction
# framing, unlike the adjacent invariants block) was structurally forced by
# _llm_field_sanitize living in a file llm-client.sh could not reach — not
# a call site that merely forgot to use it. Moving the sanitizer to the one
# file both gates.sh and llm-client.sh already source makes that omission
# impossible for the next round-trip path, rather than merely fixing this
# one instance.

# _invariant_feed_max_field_chars — per-field length cap applied at the write
# boundary (see _llm_field_sanitize). Configurable via
# CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS (default 500 — generous for a
# one-sentence CWE title/statement, small enough that a single adversarial-
# controlled finding cannot balloon invariants.json or the prompt it is later
# injected into).
_invariant_feed_max_field_chars() {
  _ifmfc_max="${CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS:-500}"
  case "$_ifmfc_max" in ''|*[!0-9]*) _ifmfc_max=500 ;; esac
  printf '%s' "$_ifmfc_max"
}

# _llm_field_sanitize TEXT [MAX_CHARS] — neutralize LLM-controlled OR
# otherwise externally-sourced text before it is ever written to a file or
# interpolated into a prompt block that a LATER LLM call reads (lr-cda4b9,
# generalized under lr-e2b975, relocated to platform.sh under lr-4f8316 so
# every prompt-constructing file can reach it). WRITE-BOUNDARY/
# INTERPOLATION-BOUNDARY sanitization, not read-time: every known round-trip
# or interpolation path — the invariant-feed (_invariant_feed_append,
# gates.sh), the adversarial findings sidecar consumed by
# build_gate_summary/ds_merge_gate_prompt, and the change-class
# commit-message hint (_change_class_hint, llm-client.sh) — has exactly one
# ingest point and an unknown/growing number of future readers. Cleaning
# once at ingest means every reader gets clean data for free, instead of
# every current AND future reader needing to remember to re-sanitize. This
# is the SOLE sanitizer for externally-sourced text that lands in a prompt
# in this codebase — do not add a second one; if a new round-trip or
# interpolation path needs different behavior, extend this function.
#
# Applied to every field that ultimately traces back to adversarial/review
# LLM output or other external text a prompt interpolates: for the
# invariant-feed, category/file/the distilled statement (which embeds the
# original finding message verbatim); for the adversarial findings sidecar,
# each finding's title/message and any other model-authored string field;
# for the change-class hint, the raw commit-message trailer value before it
# is surfaced to the Reviewer/Auditor prompts.
#
# Args: TEXT (required), MAX_CHARS (optional — falls back to
# _invariant_feed_max_field_chars's default/config value when omitted, since
# every current caller wants the same cap; a future caller needing a
# different cap can pass one explicitly rather than this function growing a
# second knob).
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
#     new data-block boundary once re-injected into a future prompt — both
#     the invariant-feed fence (===BEGIN/END INVARIANTS DATA===,
#     ds_adversarial_prompt in llm-client.sh) and the adversarial-findings
#     fence the merge-gate prompt uses (===BEGIN/END ADVERSARIAL FINDINGS
#     DATA===) are defanged unconditionally, regardless of which pipeline a
#     given finding is travelling through — a payload could be planted once
#     and land in either round-trip. Case-insensitively replaces each
#     literal label string with a defanged spaced-out form. This does not
#     make the text nonsensical to a human reviewer (the words are still
#     legible) but prevents it from being byte-identical to the real
#     delimiter the model was told to trust. Without this, a finding
#     containing a literal fence string survives verbatim into the written
#     artifact and can forge a fake end-of-data marker inside the block,
#     escaping the fence entirely (BOBBIE, lr-cda4b9 follow-up).
#   - Caps length at MAX_CHARS, truncating rather than rejecting — a
#     merely-too-long finding is not attacker behavior, and rejecting it
#     would silently drop a real finding (fail-open posture matches the
#     rest of the invariant-feed and the advisory/blocking split).
_llm_field_sanitize() {
  _lfs_text="$1"
  _lfs_max="${2:-$(_invariant_feed_max_field_chars)}"
  case "$_lfs_max" in ''|*[!0-9]*) _lfs_max=$(_invariant_feed_max_field_chars) ;; esac

  if command -v python3 >/dev/null 2>&1; then
    # Text goes through a temp file, NOT stdin: `python3 -` already reads the
    # script itself from stdin (the heredoc below), so piping the untrusted
    # text into the same stdin would either be silently discarded or
    # interleaved with the script depending on shell/buffering — the data
    # channel and the script channel must be different file descriptors.
    _lfs_tmp=$(mktemp -t clagentic-llm-sanitize.XXXXXX)
    printf '%s' "$_lfs_text" > "$_lfs_tmp"
    python3 - "$_lfs_tmp" "$_lfs_max" <<'PYEOF'
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

# Defang forged delimiter labels: a hostile finding message (or, as of
# lr-4f8316, a hostile commit-message change-class trailer, or a hostile
# deferrals.json entry) could contain the literal string "INVARIANTS:" or
# "DEFERRED FINDINGS:" -- or any of the fenced data-block marker sets this
# codebase uses (===BEGIN/END INVARIANTS DATA===, the invariant-feed fence
# in ds_adversarial_prompt; ===BEGIN/END ADVERSARIAL FINDINGS DATA===, the
# merge-gate fence in ds_merge_gate_prompt; ===BEGIN/END CHANGE-CLASS HINT
# DATA===, the change-class hint fence in both ds_review_prompt and
# ds_adversarial_prompt; ===BEGIN/END DEFERRED FINDINGS DATA===, the
# deferrals fence in ds_review_prompt -- all llm-client.sh) -- to try to
# spoof a fresh data-block boundary once re-injected into a future prompt.
# Insert a zero-width-safe space so the string is still legible to a human
# but no longer byte-identical to the real delimiter. All fence sets are
# defanged unconditionally here (not gated by which caller invoked this
# function) since a single planted payload could round-trip through any
# path.
for label in ("INVARIANTS:", "DEFERRED FINDINGS:", "END INVARIANTS",
              "END DEFERRED FINDINGS",
              "===BEGIN INVARIANTS DATA===", "===END INVARIANTS DATA===",
              "===BEGIN ADVERSARIAL FINDINGS DATA===",
              "===END ADVERSARIAL FINDINGS DATA===",
              "===BEGIN CHANGE-CLASS HINT DATA===",
              "===END CHANGE-CLASS HINT DATA===",
              "===BEGIN DEFERRED FINDINGS DATA===",
              "===END DEFERRED FINDINGS DATA==="):
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
    _lfs_status=$?
    rm -f "$_lfs_tmp"
    return $_lfs_status
  fi

  # No python3: best-effort POSIX fallback. tr strips the bulk of control
  # bytes (octal escapes for 0x01-0x08, 0x0B-0x1F, 0x7F; 0x00 cannot appear
  # in a shell string so no explicit strip needed); sed defangs all fenced
  # marker sets specifically (literal, fixed-case substitution — no GNU/BSD
  # sed extension needed, unlike a general case-insensitive label match);
  # cut caps length. This path does NOT defang the case-insensitive
  # INVARIANTS:/DEFERRED FINDINGS: labels the python3 path covers (no
  # portable case-insensitive substitution without sed extensions that vary
  # GNU/BSD) — acceptable degradation given no-python3 already means jq is
  # the active JSON tool elsewhere in this codepath. The fenced markers ARE
  # covered here because they are the labels an attacker could use to
  # escape a fence entirely (BOBBIE, lr-cda4b9 follow-up), so this path
  # closes that specific gap even though it cannot close the general one.
  printf '%s' "$_lfs_text" \
    | tr -d '\001-\010\013-\037\177' \
    | sed 's|===BEGIN INVARIANTS DATA===|= = =BEGIN INVARIANTS DATA= = =|g; s|===END INVARIANTS DATA===|= = =END INVARIANTS DATA= = =|g; s|===BEGIN ADVERSARIAL FINDINGS DATA===|= = =BEGIN ADVERSARIAL FINDINGS DATA= = =|g; s|===END ADVERSARIAL FINDINGS DATA===|= = =END ADVERSARIAL FINDINGS DATA= = =|g; s|===BEGIN CHANGE-CLASS HINT DATA===|= = =BEGIN CHANGE-CLASS HINT DATA= = =|g; s|===END CHANGE-CLASS HINT DATA===|= = =END CHANGE-CLASS HINT DATA= = =|g; s|===BEGIN DEFERRED FINDINGS DATA===|= = =BEGIN DEFERRED FINDINGS DATA= = =|g; s|===END DEFERRED FINDINGS DATA===|= = =END DEFERRED FINDINGS DATA= = =|g' \
    | cut -c "1-${_lfs_max}"
}

# _llm_json_array_allowlist_fields JSON FIELD1 [FIELD2 ...] — decompose a
# JSON array of objects and reduce EVERY object to ONLY the named fields,
# DROPPING every other key entirely (lr-4f8316 second follow-up). This is
# the schema-validation step that MUST run before
# _llm_json_array_sanitize_fields (below) whenever the array's field set is
# attacker-influenced, not code-controlled -- see that function's own
# "SAFE ONLY for callers with a closed, code-controlled field set" warning.
#
# WHY THIS IS A SEPARATE FUNCTION, NOT A CHANGE TO
# _llm_json_array_sanitize_fields: the adversarial-findings caller
# (_sanitize_adversarial_findings_json, gates.sh) depends on
# _llm_json_array_sanitize_fields' CURRENT contract -- pass through every
# field not named in the sanitize call (line/severity/reachable/tier/class
# survive untouched). That caller is safe leaving those fields alone
# because _parse_adversarial_findings constructs each finding from named
# regex capture groups: an attacker cannot introduce an arbitrary key at
# all, the field set is fixed by the parser's own code. Deferrals reads an
# arbitrary JSON object off disk -- an attacker who can write
# .clagentic/deferrals.json can add any key they like, and sanitizing only
# the SIX NAMED schema fields left every other key riding through
# byte-identical: undefanged, unstripped, uncapped. Same helper, different
# input model, and that difference is the whole bug (BOBBIE, lr-4f8316
# third follow-up). Changing _llm_json_array_sanitize_fields to allowlist
# by default would silently break the adversarial-findings caller's
# reliance on "unnamed fields pass through" -- so the fix is a NEW function
# callers with an attacker-influenced field set call FIRST, not a change to
# the existing one.
#
# Also coerces every RETAINED value to a plain string, dropping (not
# stringifying) any field whose value is not a JSON string -- an object,
# array, number, bool, or null. The deferrals schema (docs/GATES.md
# "Reviewer-consulted deferrals") defines every field as free-form text;
# a legitimate field holding a nested object/array has no defined meaning
# either, and passing one through as an embedded JSON blob (even under a
# real field name) would smuggle attacker content one level deep, past a
# sanitizer that only inspects the field it was told to look at as a flat
# string. Dropping is correct here, matching the "unknown key -> drop, not
# merely sanitize" posture for the field set itself: there is no defined
# meaning to forward in any form.
#
# TYPED FIELDS (lr-66e598 follow-up): a bare field name (e.g. "file") keeps
# ONLY a string value under that key, exactly as above and as every existing
# caller (deferrals) already relies on. Appending ":number" to a field name
# (e.g. "line:number") CHANGES that ONE field's accepted type to a plain
# JSON number INSTEAD OF a string -- not in addition to it. This is a type
# declaration, not a widening: the field's schema type is either string
# (bare name) or number (":number" suffix), never both, so a value of the
# wrong type for that field's declared type is dropped, never coerced and
# never accepted under the other type. This exists because the
# review-findings schema (docs/GATES.md, `ds_review_prompt` in
# llm-client.sh) legitimately defines `line` as a number, and the base
# string-only contract would silently corrupt that schema's own `line`
# value (breaking finding_content_keys' `.line` lookup and
# cmd_render_review's rendered line number) -- adding a type declaration to
# this one field, rather than a second allowlist function, is what "reuse
# the existing helper" means when a caller's own schema needs a non-string
# field. No other type is accepted (no ":bool", no ":object"); this
# codebase's schemas have not needed one yet, and the same "drop, never
# coerce" fail-closed default applies if one shows up before a suffix for it
# is added here.
#
# Fail-open: a non-array or malformed JSON input, or the complete absence
# of jq AND python3, returns the ORIGINAL input unchanged -- identical
# fail-open posture to _llm_json_array_sanitize_fields, so the caller's own
# fail-open contract (deferrals: absent/empty/malformed does not break
# review) composes cleanly across both steps.
#
# Args: JSON (a JSON array of objects), FIELD1..FIELDN (the CLOSED set of
# field names this array's schema defines; each is a bare name for
# string-only, or "name:number" to also accept a JSON number under that key).
# stdout: the reduced JSON array (or the original JSON, on any failure).
_llm_json_array_allowlist_fields() {
  _ljaaf_json="$1"
  shift
  _ljaaf_fields="$*"
  if [ -z "$_ljaaf_fields" ]; then
    # No fields named at all: every key would be dropped from every
    # object. That is very likely a caller bug (an empty allowlist is
    # never a real schema), not an intentional "keep nothing" -- fail open
    # with the original input rather than silently emptying every object,
    # matching this function's fail-open posture on every other error path.
    printf '%s' "$_ljaaf_json"
    return 0
  fi

  if command -v jq >/dev/null 2>&1; then
    if ! printf '%s' "$_ljaaf_json" | jq -e '. | type == "array"' >/dev/null 2>&1; then
      printf '%s' "$_ljaaf_json"
      return 0
    fi
    # Build a jq object mapping field-name -> its ONE declared jq type
    # ("string" by default; "number" when the caller suffixed ":number" --
    # a type declaration, not an added alternative), then apply a single
    # filter: for each object, keep only entries whose key is in the
    # allowlist AND whose value's jq type equals that key's declared type.
    _ljaaf_types_json="{}"
    for _ljaaf_field in $_ljaaf_fields; do
      case "$_ljaaf_field" in
        *:number)
          _ljaaf_name="${_ljaaf_field%:number}"
          _ljaaf_type="number"
          ;;
        *)
          _ljaaf_name="$_ljaaf_field"
          _ljaaf_type="string"
          ;;
      esac
      _ljaaf_types_json=$(printf '%s' "$_ljaaf_types_json" | jq -c --arg f "$_ljaaf_name" --arg t "$_ljaaf_type" '. + {($f): $t}' 2>/dev/null)
      [ -n "$_ljaaf_types_json" ] || { printf '%s' "$_ljaaf_json"; return 0; }
    done
    _ljaaf_out=$(printf '%s' "$_ljaaf_json" | jq -c --argjson types "$_ljaaf_types_json" \
      '[.[] | (if type == "object" then with_entries(select(($types[.key] // null) as $t | $t != null and (.value | type) == $t)) else {} end)]' \
      2>/dev/null)
    [ -n "$_ljaaf_out" ] || { printf '%s' "$_ljaaf_json"; return 0; }
    printf '%s' "$_ljaaf_out"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    _ljaaf_out=$(python3 - "$_ljaaf_json" $_ljaaf_fields <<'PYEOF'
import json, sys

raw = sys.argv[1]
raw_fields = sys.argv[2:]

# name -> its ONE declared python type set: (str,) by default, or
# (int, float) if the caller suffixed ":number" -- a type DECLARATION, not
# an added alternative, mirroring the jq branch's single-type-per-field
# contract. bool is deliberately excluded from the numeric type set even
# though Python's bool is an int subclass -- a JSON true/false must never
# silently pass a numeric field check.
allowed = {}
for f in raw_fields:
    if f.endswith(":number"):
        name = f[: -len(":number")]
        allowed[name] = (int, float)
    else:
        allowed[name] = (str,)

try:
    arr = json.loads(raw)
    if not isinstance(arr, list):
        raise ValueError("not a list")
except Exception:
    print(raw)
    sys.exit(0)

reduced = []
for item in arr:
    if not isinstance(item, dict):
        reduced.append({})
        continue
    out = {}
    for k, v in item.items():
        types = allowed.get(k)
        if types is None:
            continue
        # Reject bool explicitly even when the field's declared type is
        # (int, float) -- isinstance(True, int) is True in Python, which
        # would otherwise let a JSON boolean masquerade as a numeric value.
        if isinstance(v, bool):
            continue
        if isinstance(v, types):
            out[k] = v
    reduced.append(out)

print(json.dumps(reduced))
PYEOF
)
    [ -n "$_ljaaf_out" ] || { printf '%s' "$_ljaaf_json"; return 0; }
    printf '%s' "$_ljaaf_out"
    return 0
  fi

  # No JSON tool at all -- cannot safely decompose/rebuild. Fail-open: same
  # posture as _llm_json_array_sanitize_fields' own no-JSON-tool path.
  printf '%s' "$_ljaaf_json"
}

# _llm_json_array_sanitize_fields JSON FIELD1 [FIELD2 ...] — decompose a
# JSON array of objects, run _llm_field_sanitize over each named string
# field on every object, rebuild, and print the sanitized array. Generic
# extraction of the decompose/sanitize/rebuild shape
# _sanitize_adversarial_findings_json (scripts/gates.sh) already used for
# the adversarial findings sidecar (file/category/message), so a second
# caller with a different field set — the deferrals array
# (id/category/file/description/expires/acknowledged_by), lr-4f8316 follow-
# up — reuses the same machinery instead of hand-rolling a variant. Any
# array-of-objects round-trip in this codebase should extend this function
# rather than growing a parallel decompose/sanitize/rebuild loop.
#
# Fields not named in FIELD... pass through UNCHANGED, undefanged, uncapped
# -- this function sanitizes exactly the fields it is told to and nothing
# else; it does not know or enforce a schema. That is SAFE ONLY when the
# caller controls the object's field set in code -- e.g.
# _sanitize_adversarial_findings_json (gates.sh), where
# _parse_adversarial_findings constructs every finding from named regex
# capture groups, so no key outside file/line/category/message/severity/
# reachable/tier/class can ever exist on the object in the first place.
#
# It is UNSAFE to call this function alone on a JSON array whose field set
# an attacker can influence (e.g. an on-disk file an attacker can write) --
# any key not in FIELD... rides through byte-identical: undefanged,
# unstripped, uncapped (BOBBIE, lr-4f8316 third follow-up). A caller in
# that position MUST run _llm_json_array_allowlist_fields (above) FIRST, to
# reduce every object to the closed schema before this function ever sees
# it -- see that function's docstring for why this is a separate function
# rather than a change to this one's contract (this contract is depended
# on by the adversarial-findings caller and must not change).
#
# Fail-open, matching every other JSON-tool-dependent helper in this
# codebase: an empty/malformed JSON array, or the complete absence of jq
# AND python3, returns the ORIGINAL input unchanged rather than dropping
# entries or raising — the caller's own fail-open posture (e.g. "absent/
# unreadable deferrals file must not break review") is preserved by never
# turning a decompose failure into an empty result.
#
# Args: JSON (a JSON array of objects, as a single string), FIELD1..FIELDN
# (one or more field names to sanitize on every object in the array).
# stdout: the sanitized JSON array (or the original JSON, on any failure).
_llm_json_array_sanitize_fields() {
  _ljasf_json="$1"
  shift
  _ljasf_fields="$*"
  if [ -z "$_ljasf_fields" ]; then
    # No fields named — nothing to sanitize; pass through unchanged rather
    # than silently no-op-ing in a way that could be mistaken for "sanitized".
    printf '%s' "$_ljasf_json"
    return 0
  fi

  if command -v jq >/dev/null 2>&1; then
    # Type check FIRST, not just "length parses as a number" -- jq's
    # `length` returns a number for strings/objects too (e.g. a JSON string
    # scalar's character count), which would otherwise silently pass the
    # numeric guard below and then fail differently (indexing a non-array
    # with .[$i] and producing garbage/empty results) instead of hitting
    # the fail-open path. A non-array input must return the ORIGINAL input
    # unchanged, never an empty array -- an empty array is indistinguishable
    # from "genuinely no entries" and would silently make malformed-but-
    # non-empty content disappear instead of degrading visibly.
    if ! printf '%s' "$_ljasf_json" | jq -e '. | type == "array"' >/dev/null 2>&1; then
      printf '%s' "$_ljasf_json"
      return 0
    fi
    _ljasf_count=$(printf '%s' "$_ljasf_json" | jq 'length' 2>/dev/null)
    case "$_ljasf_count" in ''|*[!0-9]*) printf '%s' "$_ljasf_json"; return 0 ;; esac
    _ljasf_out="[]"
    _ljasf_i=0
    while [ "$_ljasf_i" -lt "$_ljasf_count" ]; do
      _ljasf_item=$(printf '%s' "$_ljasf_json" | jq -c ".[$_ljasf_i]" 2>/dev/null) || break
      _ljasf_jq_args=""
      for _ljasf_field in $_ljasf_fields; do
        _ljasf_raw=$(printf '%s' "$_ljasf_item" | jq -r --arg f "$_ljasf_field" '.[$f] // ""' 2>/dev/null)
        _ljasf_clean=$(_llm_field_sanitize "$_ljasf_raw")
        _ljasf_item=$(printf '%s' "$_ljasf_item" | jq -c --arg f "$_ljasf_field" --arg v "$_ljasf_clean" \
          'if has($f) then .[$f] = $v else . end' 2>/dev/null)
      done
      _ljasf_out=$(printf '%s' "$_ljasf_out" | jq -c --argjson item "$_ljasf_item" '. + [$item]' 2>/dev/null)
      [ -n "$_ljasf_out" ] || { printf '%s' "$_ljasf_json"; return 0; }
      _ljasf_i=$((_ljasf_i + 1))
    done
    printf '%s' "$_ljasf_out"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    # Same type check as the jq branch above: distinguish "valid JSON but
    # not an array" (fail open with the ORIGINAL input) from "a genuine
    # empty array" (both would otherwise produce _ljasf_count=0 and fall
    # through to the same code path, but only one of them should return the
    # original text unchanged).
    _ljasf_is_array=$(python3 -c 'import json,sys
try:
    d = json.loads(sys.argv[1])
    print("1" if isinstance(d, list) else "0")
except Exception:
    print("0")' "$_ljasf_json" 2>/dev/null)
    if [ "$_ljasf_is_array" != "1" ]; then
      printf '%s' "$_ljasf_json"
      return 0
    fi
    _ljasf_count=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(len(d))' "$_ljasf_json" 2>/dev/null)
    case "$_ljasf_count" in ''|*[!0-9]*) printf '%s' "$_ljasf_json"; return 0 ;; esac
    _ljasf_out="[]"
    _ljasf_i=0
    while [ "$_ljasf_i" -lt "$_ljasf_count" ]; do
      _ljasf_item=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(json.dumps(d[int(sys.argv[2])]))' "$_ljasf_json" "$_ljasf_i" 2>/dev/null) || break
      for _ljasf_field in $_ljasf_fields; do
        _ljasf_raw=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); v=d.get(sys.argv[2], ""); print(v if isinstance(v, str) else "")' "$_ljasf_item" "$_ljasf_field" 2>/dev/null)
        _ljasf_clean=$(_llm_field_sanitize "$_ljasf_raw")
        _ljasf_item=$(python3 -c '
import json, sys
item = json.loads(sys.argv[1])
field = sys.argv[2]
if field in item:
    item[field] = sys.argv[3]
print(json.dumps(item))
' "$_ljasf_item" "$_ljasf_field" "$_ljasf_clean" 2>/dev/null)
      done
      _ljasf_out=$(python3 -c 'import json,sys; arr=json.loads(sys.argv[1]); arr.append(json.loads(sys.argv[2])); print(json.dumps(arr))' "$_ljasf_out" "$_ljasf_item" 2>/dev/null)
      [ -n "$_ljasf_out" ] || { printf '%s' "$_ljasf_json"; return 0; }
      _ljasf_i=$((_ljasf_i + 1))
    done
    printf '%s' "$_ljasf_out"
    return 0
  fi

  # No JSON tool at all -- cannot safely decompose/rebuild. Fail-open: same
  # posture as _sanitize_adversarial_findings_json's own no-JSON-tool path.
  printf '%s' "$_ljasf_json"
}

# _adversarial_findings_sort_blocking_first JSON — reorder a JSON array of
# adversarial-finding objects (the {file,line,category,message,severity,
# reachable,tier,class} shape _parse_adversarial_findings produces, gates.sh)
# so tier:"blocking" findings sort before tier:"advisory" findings, and
# within each tier severity sorts critical > high > medium > low > unknown
# (BOBBIE, lr-33958f PR-C fold-in review). Stable within each (tier,severity)
# bucket — same-ranked findings keep their original relative (parse) order,
# matching _llm_json_array_cap's own "first N, stable, deterministic" cap
# contract one step downstream.
#
# WHY THIS EXISTS, SEPARATE FROM _llm_json_array_cap: _llm_json_array_cap
# (below) is a GENERIC truncate-to-first-N helper with no notion of
# severity/tier — every existing and future caller (e.g. a plain-object
# array with no severity field at all) depends on it staying that way, and
# its own test suite asserts first-N truncation is stable and deterministic
# for arbitrary objects. Baking severity-awareness into that function would
# either silently no-op for callers with no severity/tier fields (fine) or
# require every caller to opt in/out of a behavior only one caller
# (cmd_adversarial) actually needs. A caller with a severity/tier-shaped
# array instead sorts FIRST with this function, then caps with
# _llm_json_array_cap exactly as before — composition, not a new mode on
# the shared cap.
#
# THE BUG THIS CLOSES: _parse_adversarial_findings (gates.sh) emits findings
# in the order the Auditor's markdown lists them, which is
# ATTACKER-INFLUENCEABLE — a diff under review can carry a prompt-injection
# payload that steers a compromised/manipulated Auditor into emitting a late
# tier:"blocking" finding after many earlier tier:"advisory" ones. Capping
# to the first N IN PARSE ORDER (the pre-fix behavior) could then silently
# drop the one finding that mattered while keeping N low-value advisory
# findings — a hole the count cap itself introduced. Sorting
# severity/tier-descending BEFORE the cap runs means truncation can only
# ever drop the LEAST-severe, non-blocking tail of the array, never a
# blocking finding while a less-severe one survives.
#
# Fail-open, matching every other JSON-tool-dependent helper in this
# codebase: a non-array, malformed JSON, or the complete absence of jq AND
# python3 returns the ORIGINAL input unchanged.
#
# Args: JSON (a JSON array of adversarial-finding objects, as a single
# string). stdout: the same objects, reordered (or the original JSON
# unchanged, on any failure).
_adversarial_findings_sort_blocking_first() {
  _afsbf_json="$1"

  if command -v jq >/dev/null 2>&1; then
    if ! printf '%s' "$_afsbf_json" | jq -e '. | type == "array"' >/dev/null 2>&1; then
      printf '%s' "$_afsbf_json"
      return 0
    fi
    _afsbf_out=$(printf '%s' "$_afsbf_json" | jq -c '
      def tier_rank: if .tier == "blocking" then 1 else 0 end;
      def sev_rank:
        if .severity == "critical" then 4
        elif .severity == "high" then 3
        elif .severity == "medium" then 2
        elif .severity == "low" then 1
        else 0 end;
      to_entries
      | sort_by([-(.value | tier_rank), -(.value | sev_rank), .key])
      | map(.value)
    ' 2>/dev/null)
    [ -n "$_afsbf_out" ] || { printf '%s' "$_afsbf_json"; return 0; }
    printf '%s' "$_afsbf_out"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    _afsbf_out=$(python3 -c '
import json, sys
raw = sys.argv[1]
sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
try:
    arr = json.loads(raw)
    if not isinstance(arr, list):
        raise ValueError("not a list")
except Exception:
    print(raw)
    sys.exit(0)

def key(pair):
    idx, item = pair
    tier_rank = 1 if isinstance(item, dict) and item.get("tier") == "blocking" else 0
    sr = sev_rank.get(item.get("severity") if isinstance(item, dict) else None, 0)
    # Negate for descending order; idx (ascending) preserves original
    # relative order within an identical (tier_rank, sr) bucket (stable).
    return (-tier_rank, -sr, idx)

ordered = [item for _, item in sorted(enumerate(arr), key=key)]
print(json.dumps(ordered))
' "$_afsbf_json" 2>/dev/null)
    [ -n "$_afsbf_out" ] || { printf '%s' "$_afsbf_json"; return 0; }
    printf '%s' "$_afsbf_out"
    return 0
  fi

  # No JSON tool at all -- cannot safely decompose/rebuild. Fail-open,
  # matching every other JSON-tool-dependent helper in this codebase.
  printf '%s' "$_afsbf_json"
}

# _llm_json_array_cap JSON MAX — truncate a JSON array of objects to the
# first MAX entries (lr-33958f, PR-C, required foundry fix). Generic
# extraction of the same shape _invariant_feed_append's own cap already
# used inline (drop-oldest-first on that append path) — this is the
# EMISSION-side cap the foundry specifically named as the most likely
# source of the next unreported bug: _parse_adversarial_findings
# (gates.sh) built its findings array with NO count bound at all, and that
# array is embedded TWICE into the merge-gate system prompt
# (adversarial_findings and adversarial_findings_fenced, build_gate_summary)
# -- a diff that provokes an unusually chatty Auditor (or a prompt-injected
# one) could grow that prompt without limit. This is a COUNT bound, not a
# presence check, following the same "constrain the count, not the
# presence" lesson INV-2 states explicitly — an earlier fix that merely
# ensured "at least one finding is captured" would not have closed this.
#
# Truncates, does not reject: a merely-large finding set is not attacker
# behavior on its own (a genuinely complex diff can legitimately produce
# many findings), so dropping the excess rather than failing the whole
# audit matches this codebase's established truncate-not-reject posture
# (_llm_field_sanitize's own length cap, same rationale). Truncation
# ALWAYS keeps the first MAX entries (stable, deterministic — the same
# input always caps to the same output) rather than a random or
# last-N selection.
#
# Args: JSON (a JSON array, as a single string), MAX (positive integer;
# non-numeric/absent falls back to CLAGENTIC_ADVERSARIAL_FINDINGS_MAX,
# default 200 -- generous for a single adversarial pass, small enough that
# an unbounded array cannot balloon the merge-gate prompt).
# stdout: the capped JSON array (or the original JSON UNCHANGED, on any
# failure -- fail-open matches every other JSON-tool-dependent helper in
# this codebase; a truncation failure must never turn into an emptied
# array, which would be an over-suppression in the opposite, wrong
# direction).
_llm_json_array_cap() {
  _ljac_json="$1"
  _ljac_max="${2:-${CLAGENTIC_ADVERSARIAL_FINDINGS_MAX:-200}}"
  case "$_ljac_max" in ''|*[!0-9]*) _ljac_max="${CLAGENTIC_ADVERSARIAL_FINDINGS_MAX:-200}" ;; esac
  case "$_ljac_max" in ''|*[!0-9]*) _ljac_max=200 ;; esac

  if command -v jq >/dev/null 2>&1; then
    if ! printf '%s' "$_ljac_json" | jq -e '. | type == "array"' >/dev/null 2>&1; then
      printf '%s' "$_ljac_json"
      return 0
    fi
    _ljac_out=$(printf '%s' "$_ljac_json" | jq -c --argjson max "$_ljac_max" '.[0:$max]' 2>/dev/null)
    [ -n "$_ljac_out" ] || { printf '%s' "$_ljac_json"; return 0; }
    printf '%s' "$_ljac_out"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    _ljac_out=$(python3 -c '
import json, sys
raw, max_n = sys.argv[1], int(sys.argv[2])
try:
    arr = json.loads(raw)
    if not isinstance(arr, list):
        raise ValueError("not a list")
except Exception:
    print(raw)
    sys.exit(0)
print(json.dumps(arr[:max_n]))
' "$_ljac_json" "$_ljac_max" 2>/dev/null)
    [ -n "$_ljac_out" ] || { printf '%s' "$_ljac_json"; return 0; }
    printf '%s' "$_ljac_out"
    return 0
  fi

  # No JSON tool at all -- cannot safely decompose/rebuild. Fail-open,
  # matching every other JSON-tool-dependent helper in this codebase.
  printf '%s' "$_ljac_json"
}
