#!/bin/sh
# clagentic-lite :: review-merge helper
#
# Sourced (not executed) by gates.sh. Provides three pure POSIX-sh functions
# for diff chunking and per-chunk envelope merging:
#
#   split_diff   DIFF_FILE CHUNK_DIR CHUNK_BYTES
#   merge_envelopes ENVELOPE_DIR DEDUP_KEY_STRATEGY
#   dedup_findings  KEY_STRATEGY SEEN_FILE [DIFF_FILE]  (reads stdin, writes stdout)
#
# Dependencies:
#   Required: git, awk, sed (via platform.sh shims), wc
#   Optional: sha256sum or shasum (soft; identity fallback when both absent)
#   Optional: jq or python3 (soft; degraded-envelope if both absent — same pattern
#             as ds_json_field / build_gate_summary in platform.sh / gates.sh)
#
# This module sources platform.sh for ds_json_field, ds_file_size, and the
# DS_TIMEOUT_CMD pattern. It does NOT source memory.sh or llm-client.sh, and
# does NOT call ds_audit_log (audit stays in gates.sh).

# ---------------------------------------------------------------- sha256 shim --
#
# Probed once at source time. Priority: sha256sum (GNU coreutils) ->
# shasum -a 256 (BSD/macOS) -> identity fallback (cat, returns input unchanged).
# The identity fallback means dedup key = the raw input; dedup still works
# locally but is sensitive to whitespace changes. clagentic-lite doctor warns when
# neither sha256 tool is present.
#
# Shim pattern mirrors DS_TIMEOUT_CMD from platform.sh.
#
# _rm_sha256 STDIN -> prints hex digest on stdout.
if command -v sha256sum >/dev/null 2>&1; then
  _rm_sha256() { sha256sum | cut -d' ' -f1; }
  _RM_SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  _rm_sha256() { shasum -a 256 | cut -d' ' -f1; }
  _RM_SHA256_CMD="shasum -a 256"
else
  _rm_sha256() { cat; }
  _RM_SHA256_CMD="identity-fallback"
fi
export _RM_SHA256_CMD

# ----------------------------------------------------------------- split_diff --
#
# split_diff DIFF_FILE CHUNK_DIR CHUNK_BYTES
#
# Splits a unified diff into chunk files chunk-001, chunk-002, ... in CHUNK_DIR.
# Packing strategy:
#   1. Accumulate whole-file diffs until the chunk budget would be exceeded, then
#      flush and start a new chunk.
#   2. If a single file diff exceeds CHUNK_BYTES, split it at @@ hunk boundaries
#      (each hunk begins with a "@@" line). The file header (--- / +++ / diff ...)
#      is repeated in every hunk sub-chunk.
#   3. If a single hunk exceeds CHUNK_BYTES, send it as-is and emit a warning to
#      stderr — no intra-hunk splitting in v1.
#
# NUL-safe file enumeration: uses git diff -z to get the file list, avoiding
# word-splitting on filenames with spaces or special characters.
#
# stdout: number of chunks (one integer)
# stderr: diagnostics
# exit 0: always (errors produce warnings to stderr; callers inspect chunk count)
split_diff() {
  _sd_diff="$1"
  _sd_dir="$2"
  _sd_budget="$3"

  # Validate inputs.
  if [ ! -f "$_sd_diff" ]; then
    printf '[review-merge/split_diff] diff file not found: %s\n' "$_sd_diff" 1>&2
    printf '0\n'
    return 0
  fi

  # Integer guard for budget.
  case "$_sd_budget" in
    ''|*[!0-9]*) _sd_budget=262144 ;;
  esac
  [ "$_sd_budget" -lt 1024 ] && _sd_budget=1024

  mkdir -p "$_sd_dir"

  # Parse the unified diff into per-file sections.
  # A new file section starts at "diff --git" or "--- " (unified diff header).
  # We use awk to split the diff file into per-file segments.
  #
  # Algorithm (awk):
  #   - Accumulate lines per file block (reset on "diff --git ..." header).
  #   - On end-of-file or new header, emit a record: FILE_HEADER \n CONTENT.
  #
  # We write per-file temp files, then pack them into chunks.

  _sd_tmp_dir=$(mktemp -d -t clagentic-sd-files.XXXXXX)
  _sd_file_idx=0

  # awk: split the unified diff on "diff --git" lines (standard git diff format).
  # Each block = one file. Writes one numbered file per block.
  # POSIX awk — no gensub, no arrays needed beyond the accumulator.
  awk -v outdir="$_sd_tmp_dir" '
    BEGIN { buf = ""; idx = 0 }
    /^diff --git / {
      if (buf != "") {
        idx++
        fname = outdir "/file-" sprintf("%05d", idx)
        print buf > fname
        close(fname)
        buf = ""
      }
    }
    { buf = (buf == "") ? $0 : buf "\n" $0 }
    END {
      if (buf != "") {
        idx++
        fname = outdir "/file-" sprintf("%05d", idx)
        print buf > fname
        close(fname)
      }
    }
  ' "$_sd_diff"

  _sd_chunk_idx=0
  _sd_current_chunk=""
  _sd_current_size=0

  # Helper: flush current accumulator to a numbered chunk file.
  _sd_flush_chunk() {
    if [ -n "$_sd_current_chunk" ]; then
      _sd_chunk_idx=$((_sd_chunk_idx + 1))
      _sd_cname=$(printf '%s/chunk-%03d' "$_sd_dir" "$_sd_chunk_idx")
      printf '%s\n' "$_sd_current_chunk" > "$_sd_cname"
      _sd_current_chunk=""
      _sd_current_size=0
    fi
  }

  # Walk each per-file block and pack into chunks.
  for _sd_fblock in "$_sd_tmp_dir"/file-*; do
    [ -f "$_sd_fblock" ] || continue
    _sd_fsize=$(ds_file_size "$_sd_fblock")

    if [ "$_sd_fsize" -le "$_sd_budget" ]; then
      # Whole file fits within budget.
      _sd_fcontent=$(cat "$_sd_fblock")
      if [ $((_sd_current_size + _sd_fsize)) -gt "$_sd_budget" ] && [ "$_sd_current_size" -gt 0 ]; then
        # Would overflow current chunk — flush first.
        _sd_flush_chunk
      fi
      if [ -z "$_sd_current_chunk" ]; then
        _sd_current_chunk="$_sd_fcontent"
      else
        _sd_current_chunk="${_sd_current_chunk}
${_sd_fcontent}"
      fi
      _sd_current_size=$((_sd_current_size + _sd_fsize))
    else
      # File is larger than budget. Try splitting at @@ hunk boundaries.
      # First, flush any accumulated chunk.
      _sd_flush_chunk

      # Extract the file header lines (everything before the first @@ line).
      _sd_file_header=$(awk '/^@@/{exit} {print}' "$_sd_fblock")

      # Split into hunks: each hunk starts at a ^@@ line.
      # Write hunks to temp files using awk.
      _sd_hunk_dir=$(mktemp -d -t clagentic-sd-hunks.XXXXXX)
      awk -v outdir="$_sd_hunk_dir" -v header="$_sd_file_header" '
        BEGIN { hbuf = ""; hidx = 0 }
        /^@@/ {
          if (hbuf != "") {
            hidx++
            hf = outdir "/hunk-" sprintf("%05d", hidx)
            print header "\n" hbuf > hf
            close(hf)
            hbuf = ""
          }
        }
        /^@@/ || hbuf != "" { hbuf = (hbuf == "") ? $0 : hbuf "\n" $0 }
        END {
          if (hbuf != "") {
            hidx++
            hf = outdir "/hunk-" sprintf("%05d", hidx)
            print header "\n" hbuf > hf
            close(hf)
          }
        }
      ' "$_sd_fblock"

      # Pack hunks into chunks (each hunk includes the file header prepended).
      for _sd_hblock in "$_sd_hunk_dir"/hunk-*; do
        [ -f "$_sd_hblock" ] || continue
        _sd_hsize=$(ds_file_size "$_sd_hblock")
        _sd_hcontent=$(cat "$_sd_hblock")

        if [ "$_sd_hsize" -gt "$_sd_budget" ]; then
          # Single hunk exceeds budget — send as-is with a warning.
          printf '[review-merge/split_diff] WARNING: single hunk (%d bytes) exceeds chunk budget (%d bytes); sending as-is\n' \
            "$_sd_hsize" "$_sd_budget" 1>&2
          _sd_flush_chunk
          _sd_chunk_idx=$((_sd_chunk_idx + 1))
          _sd_cname=$(printf '%s/chunk-%03d' "$_sd_dir" "$_sd_chunk_idx")
          printf '%s\n' "$_sd_hcontent" > "$_sd_cname"
        else
          if [ $((_sd_current_size + _sd_hsize)) -gt "$_sd_budget" ] && [ "$_sd_current_size" -gt 0 ]; then
            _sd_flush_chunk
          fi
          if [ -z "$_sd_current_chunk" ]; then
            _sd_current_chunk="$_sd_hcontent"
          else
            _sd_current_chunk="${_sd_current_chunk}
${_sd_hcontent}"
          fi
          _sd_current_size=$((_sd_current_size + _sd_hsize))
        fi
      done

      rm -rf "$_sd_hunk_dir"
    fi
  done

  # Flush remaining accumulator.
  _sd_flush_chunk

  rm -rf "$_sd_tmp_dir"

  printf '%d\n' "$_sd_chunk_idx"
  return 0
}

# ------------------------------------------------------------- merge_envelopes --
#
# merge_envelopes ENVELOPE_DIR DEDUP_KEY_STRATEGY
#
# Merges envelope-NNN.json files (lexicographic order) from ENVELOPE_DIR into
# one canonical envelope. Fields:
#   summary       = concatenation of non-degraded summaries, separated by " | "
#   checked       = unique union of all checked arrays
#   findings      = union of all findings arrays, passed through dedup_findings
#   degraded      = true if ANY envelope has degraded=true
#   chunked       = true
#   chunks        = N (total count)
#   chunks_degraded = count of degraded envelopes
#
# Note: does NOT add the _clagentic_diff_sha stamp (gates.sh does that once
# on the final merged envelope, same as cmd_review does on a single-chunk result).
#
# stdout: merged JSON
# exit 0: ok
# exit 1: no valid envelopes found
merge_envelopes() {
  _me_dir="$1"
  _me_strategy="${2:-location}"

  _me_seen_file=$(mktemp -t clagentic-me-seen.XXXXXX)

  if command -v jq >/dev/null 2>&1; then
    _merge_envelopes_jq "$_me_dir" "$_me_strategy" "$_me_seen_file"
    _me_rc=$?
  elif command -v python3 >/dev/null 2>&1; then
    _merge_envelopes_py "$_me_dir" "$_me_strategy" "$_me_seen_file"
    _me_rc=$?
  else
    # No JSON tool — emit a degraded envelope.
    printf '{"degraded":true,"chunked":true,"chunks":0,"chunks_degraded":0,"summary":"[clagentic-lite degraded] no JSON tool (jq/python3) available for merge_envelopes","checked":[],"findings":[]}\n'
    rm -f "$_me_seen_file"
    return 1
  fi

  rm -f "$_me_seen_file"
  return $_me_rc
}

_merge_envelopes_jq() {
  _mej_dir="$1"
  _mej_strategy="$2"
  _mej_seen="$3"

  # Collect envelope files in lexicographic order.
  _mej_files=""
  _mej_count=0
  _mej_degraded_count=0
  _mej_summaries=""
  _mej_checked='[]'
  _mej_all_findings='[]'
  _mej_any_degraded="false"

  for _mej_f in "$_mej_dir"/envelope-*.json; do
    [ -f "$_mej_f" ] || continue
    _mej_count=$((_mej_count + 1))

    # Check if degraded.
    _mej_is_deg=$(jq -r '.degraded // false' "$_mej_f" 2>/dev/null)
    if [ "$_mej_is_deg" = "true" ]; then
      _mej_degraded_count=$((_mej_degraded_count + 1))
      _mej_any_degraded="true"
    else
      # Accumulate non-degraded summary.
      _mej_s=$(jq -r '.summary // ""' "$_mej_f" 2>/dev/null)
      if [ -n "$_mej_s" ]; then
        if [ -z "$_mej_summaries" ]; then
          _mej_summaries="$_mej_s"
        else
          _mej_summaries="${_mej_summaries} | ${_mej_s}"
        fi
      fi
    fi

    # Union checked arrays.
    _mej_fc=$(jq -c '.checked // []' "$_mej_f" 2>/dev/null)
    _mej_checked=$(printf '%s\n%s\n' "$_mej_checked" "$_mej_fc" \
      | jq -sc 'add | unique' 2>/dev/null || printf '%s' "$_mej_checked")

    # Accumulate findings.
    _mej_ff=$(jq -c '.findings // []' "$_mej_f" 2>/dev/null)
    _mej_all_findings=$(printf '%s\n%s\n' "$_mej_all_findings" "$_mej_ff" \
      | jq -sc 'add' 2>/dev/null || printf '%s' "$_mej_all_findings")
  done

  if [ "$_mej_count" -eq 0 ]; then
    printf '{"degraded":true,"chunked":true,"chunks":0,"chunks_degraded":0,"summary":"[clagentic-lite] no valid envelopes found","checked":[],"findings":[]}\n'
    return 1
  fi

  # Dedup findings.
  _mej_deduped=$(printf '%s' "$_mej_all_findings" \
    | dedup_findings "$_mej_strategy" "$_mej_seen")

  # Escape summary for JSON embedding.
  _mej_summary_json=$(printf '%s' "$_mej_summaries" | jq -Rs '.' 2>/dev/null)
  [ -z "$_mej_summary_json" ] && _mej_summary_json='""'

  printf '{"summary":%s,"checked":%s,"findings":%s,"degraded":%s,"chunked":true,"chunks":%d,"chunks_degraded":%d}\n' \
    "$_mej_summary_json" \
    "$_mej_checked" \
    "$_mej_deduped" \
    "$_mej_any_degraded" \
    "$_mej_count" \
    "$_mej_degraded_count"
  return 0
}

_merge_envelopes_py() {
  _mep_dir="$1"
  _mep_strategy="$2"
  _mep_seen="$3"

  # Phase 1: python aggregates envelopes (no inline dedup — dedup_findings owns that).
  # Emits a JSON object with raw (undeduped) findings plus aggregated metadata.
  # Phase 2: shell pipes raw findings through dedup_findings (same path as jq branch).
  # Phase 3: python splices deduped findings back into the result envelope.

  _mep_raw=$(mktemp -t clagentic-me-raw.XXXXXX)
  _mep_dedup_in=$(mktemp -t clagentic-me-din.XXXXXX)
  _mep_dedup_out=$(mktemp -t clagentic-me-dout.XXXXXX)
  _mep_final_rc=0

  python3 - "$_mep_dir" > "$_mep_raw" <<'PYEOF'
import json, os, sys

env_dir = sys.argv[1]

files = sorted(
    f for f in os.listdir(env_dir)
    if f.startswith("envelope-") and f.endswith(".json")
)

if not files:
    print(json.dumps({
        "_no_envelopes": True, "degraded": True, "chunked": True,
        "chunks": 0, "chunks_degraded": 0,
        "summary": "[clagentic-lite] no valid envelopes found",
        "checked": [], "findings": []
    }))
    sys.exit(1)

total = len(files)
degraded_count = 0
any_degraded = False
summaries = []
checked_set = []
all_findings = []

for fname in files:
    fpath = os.path.join(env_dir, fname)
    try:
        with open(fpath) as f:
            env = json.load(f)
    except Exception:
        degraded_count += 1
        any_degraded = True
        continue

    if env.get("degraded"):
        degraded_count += 1
        any_degraded = True
    else:
        s = env.get("summary", "")
        if s:
            summaries.append(s)

    for c in env.get("checked", []):
        if c not in checked_set:
            checked_set.append(c)

    all_findings.extend(env.get("findings", []))

result = {
    "summary": " | ".join(summaries),
    "checked": checked_set,
    "findings": all_findings,   # raw; will be replaced by dedup_findings output
    "degraded": any_degraded,
    "chunked": True,
    "chunks": total,
    "chunks_degraded": degraded_count
}
print(json.dumps(result))
PYEOF
  _mep_py1_rc=$?

  if [ "$_mep_py1_rc" -ne 0 ]; then
    cat "$_mep_raw"
    rm -f "$_mep_raw" "$_mep_dedup_in" "$_mep_dedup_out"
    return "$_mep_py1_rc"
  fi

  # Extract raw findings array and pass through dedup_findings.
  python3 -c "import json,sys; d=json.load(open('$_mep_raw')); print(json.dumps(d.get('findings',[])))" \
    > "$_mep_dedup_in" 2>/dev/null
  dedup_findings "$_mep_strategy" "$_mep_seen" < "$_mep_dedup_in" > "$_mep_dedup_out"

  # Splice deduped findings back into the envelope.
  python3 - "$_mep_raw" "$_mep_dedup_out" <<'PYEOF2'
import json, sys

raw_path   = sys.argv[1]
dedup_path = sys.argv[2]

with open(raw_path) as f:
    envelope = json.load(f)

try:
    with open(dedup_path) as f:
        deduped = json.load(f)
    if not isinstance(deduped, list):
        raise ValueError("not a list")
except Exception:
    # Conservative: keep raw findings if dedup output is unreadable.
    deduped = envelope.get("findings", [])

envelope["findings"] = deduped
print(json.dumps(envelope))
PYEOF2
  _mep_final_rc=$?

  rm -f "$_mep_raw" "$_mep_dedup_in" "$_mep_dedup_out"
  return $_mep_final_rc
}

# ------------------------------------------------------------- dedup_findings --
#
# dedup_findings KEY_STRATEGY SEEN_FILE [DIFF_FILE]
#
# stdin:  JSON array of findings (the reviewer schema)
# stdout: deduplicated JSON array (higher severity wins on collision)
# exit 0: always (conservative: never suppress on parse error)
#
# KEY_STRATEGY:
#   "location"     sha256(file:line:category:lower(message))
#                  Used for WITHIN-RUN dedup (this task, lr-093c).
#   "content-hash" sha256 of a 5-line +-line context window around the
#                  finding from DIFF_FILE. Reserved for lr-34d2 cross-round
#                  dedup. DIFF_FILE required when strategy="content-hash".
#
# SEEN_FILE: path to a file of previously-seen keys (one per line). New keys
# are appended in place. May be empty or non-existent on first call.
#
# Severity rank: low=1, medium=2, high=3, critical=4 (matches gates.sh).
# Conservative retain: if a key CANNOT be computed (parse error, missing tool,
# strategy=content-hash with no diff_file), the finding is KEPT, never dropped.
dedup_findings() {
  _df_strategy="$1"
  _df_seen="$2"
  _df_difffile="${3:-}"

  if command -v jq >/dev/null 2>&1; then
    _dedup_findings_jq "$_df_strategy" "$_df_seen" "$_df_difffile"
  elif command -v python3 >/dev/null 2>&1; then
    _dedup_findings_py "$_df_strategy" "$_df_seen" "$_df_difffile"
  else
    # No JSON tool — passthrough (conservative: retain all).
    cat
  fi
}

_dedup_findings_jq() {
  _dfj_strategy="$1"
  _dfj_seen="$2"
  _dfj_difffile="${3:-}"

  # Read stdin into a temp file so we can both parse it and re-read it if needed.
  _dfj_in=$(mktemp -t clagentic-df-in.XXXXXX)
  cat > "$_dfj_in"

  # Validate that we have a JSON array; if not, passthrough (conservative).
  if ! jq -e '. | type == "array"' "$_dfj_in" >/dev/null 2>&1; then
    cat "$_dfj_in"
    rm -f "$_dfj_in"
    return 0
  fi

  # Build a set of already-seen keys.
  # jq cannot access files outside its filter, so we pass the seen keys as
  # a $ARGS or --argjson. We read the seen file in shell and pass as a JSON
  # array string.
  _dfj_seen_arr="[]"
  if [ -f "$_dfj_seen" ]; then
    _dfj_seen_arr=$(awk 'NF{printf "%s\"%s\"", (NR>1?",":""), $0} END{printf ""}' "$_dfj_seen")
    _dfj_seen_arr="[${_dfj_seen_arr}]"
  fi

  # For content-hash strategy with a valid diff file, extract the context
  # lines for each finding and compute the hash. Without a diff file, fall
  # back to location key (conservative: keeps findings).
  _dfj_use_content=0
  if [ "$_dfj_strategy" = "content-hash" ] && [ -n "$_dfj_difffile" ] && [ -f "$_dfj_difffile" ]; then
    _dfj_use_content=1
  fi

  # Compute keys for each finding via jq. Strategy=location uses a pure-jq
  # sha256 workaround via @base64 + external sha256sum call piped per-finding.
  # Because jq cannot call external tools, we implement the key computation
  # in a shell loop reading findings one by one.
  #
  # The loop:
  #   1. Extract each finding as a JSON object.
  #   2. Compute the key.
  #   3. Build a parallel key array.
  # Then dedup using the key array + seen set + severity-wins rule.

  _dfj_count=$(jq 'length' "$_dfj_in" 2>/dev/null)
  case "$_dfj_count" in
    ''|*[!0-9]*) _dfj_count=0 ;;
  esac

  _dfj_keys_file=$(mktemp -t clagentic-df-keys.XXXXXX)
  _dfj_idx=0
  while [ "$_dfj_idx" -lt "$_dfj_count" ]; do
    _dfj_finding=$(jq -c ".[$_dfj_idx]" "$_dfj_in" 2>/dev/null)
    _dfj_key=""
    if [ "$_dfj_use_content" = "1" ]; then
      # content-hash: sha256 of 5-line +-line context window.
      _dfj_file=$(printf '%s' "$_dfj_finding" | jq -r '.file // ""' 2>/dev/null)
      _dfj_line=$(printf '%s' "$_dfj_finding" | jq -r '.line // 0' 2>/dev/null)
      # Extract the window from the diff file using awk.
      _dfj_context=$(awk -v fname="$_dfj_file" -v target="$_dfj_line" '
        /^\+\+\+ / {
          cur_file = substr($0, 5)
          # Strip a/ b/ prefix from git unified diffs.
          sub(/^b\//, "", cur_file)
          diff_line = 0
        }
        /^@@ / {
          # Parse hunk header: @@ -a,b +c,d @@
          match($0, /\+([0-9]+)/, arr)
          diff_line = arr[1] + 0 - 1
        }
        /^\+/ && cur_file == fname {
          diff_line++
          if (diff_line >= target - 2 && diff_line <= target + 2) {
            print
          }
        }
      ' "$_dfj_difffile" 2>/dev/null)
      if [ -n "$_dfj_context" ]; then
        _dfj_key=$(printf '%s' "$_dfj_context" | _rm_sha256)
      fi
    fi
    if [ -z "$_dfj_key" ]; then
      # location key (primary path for strategy=location; fallback for content-hash).
      # Surface jq errors to stderr — silent failures hide broken filters.
      _dfj_raw=$(printf '%s' "$_dfj_finding" \
        | jq -r '[(.file // ""), ((.line // 0) | tostring), (.category // ""), ((.message // "") | ascii_downcase)] | join(":")' 2>&1)
      _dfj_jq_rc=$?
      if [ "$_dfj_jq_rc" -ne 0 ]; then
        printf '[review-merge/dedup_findings] jq key-extraction failed (idx=%d): %s\n' "$_dfj_idx" "$_dfj_raw" 1>&2
        _dfj_key=""
      elif [ -n "$_dfj_raw" ]; then
        _dfj_key=$(printf '%s' "$_dfj_raw" | _rm_sha256)
      else
        # Empty output despite rc=0 — conservative retain.
        _dfj_key=""
      fi
    fi
    printf '%s\n' "$_dfj_key" >> "$_dfj_keys_file"
    _dfj_idx=$((_dfj_idx + 1))
  done

  # Now perform dedup: build a combined input for awk (idx, key, severity per line).
  _dfj_combined=$(mktemp -t clagentic-df-comb.XXXXXX)
  _dfj_idx=0
  while IFS= read -r _dfj_k; do
    _dfj_sev=$(jq -r ".[$_dfj_idx].severity // \"\"" "$_dfj_in" 2>/dev/null | tr '[:upper:]' '[:lower:]')
    printf '%d\t%s\t%s\n' "$_dfj_idx" "$_dfj_k" "$_dfj_sev" >> "$_dfj_combined"
    _dfj_idx=$((_dfj_idx + 1))
  done < "$_dfj_keys_file"

  # awk: process combined file, track winner per key.
  # Output: one index per line (the winning index for each key), in insertion order.
  _dfj_winners=$(awk -v seen_file="$_dfj_seen" '
    BEGIN {
      while ((getline line < seen_file) > 0) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line != "") preseen[line] = 1
      }
      close(seen_file)
      srank["low"]      = 1
      srank["medium"]   = 2
      srank["high"]     = 3
      srank["critical"] = 4
      n = 0
    }
    {
      idx = $1; key = $2; sev = $3
      # Empty key: conservative retain.
      if (key == "") {
        retain[n] = idx; retain_key[n] = ""; n++
        next
      }
      r = (sev in srank) ? srank[sev] : 0
      if (key in preseen) {
        # Already seen in a prior run: check if we need to update a retained winner.
        if (key in winner_idx) {
          old_r = (winner_sev[key] in srank) ? srank[winner_sev[key]] : 0
          if (r > old_r) { winner_sev[key] = sev; winner_idx[key] = idx }
        }
        # Do not emit a new entry (already deduplicated by prior run).
        next
      }
      if (!(key in winner_idx)) {
        # First time we see this key in this run.
        winner_idx[key] = idx; winner_sev[key] = sev
        order[n] = key; n++
      } else {
        old_r = (winner_sev[key] in srank) ? srank[winner_sev[key]] : 0
        if (r > old_r) { winner_sev[key] = sev; winner_idx[key] = idx }
      }
    }
    END {
      # Print winning indices in order.
      # retain[i] is set for no-key findings (conservative retain);
      # order[i] is set for keyed findings (winner tracking).
      # Both arrays share the same index n — only one is set per slot.
      for (i = 0; i < n; i++) {
        if (i in retain) {
          print retain[i]
        } else {
          k2 = order[i]
          if (k2 in winner_idx) print winner_idx[k2]
        }
      }
    }
  ' "$_dfj_combined")

  # Collect new keys to append to the seen file.
  _dfj_new_keys=$(awk -v seen_file="$_dfj_seen" '
    BEGIN {
      while ((getline line < seen_file) > 0) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line != "") preseen[line] = 1
      }
      close(seen_file)
    }
    {
      key = $2
      if (key != "" && !(key in preseen)) { new_keys[key] = 1 }
    }
    END { for (k in new_keys) print k }
  ' "$_dfj_combined")

  # Append new keys to seen file.
  if [ -n "$_dfj_new_keys" ]; then
    printf '%s\n' "$_dfj_new_keys" >> "$_dfj_seen"
  fi

  # Build the output JSON array from the winning indices.
  if [ -z "$_dfj_winners" ]; then
    printf '[]\n'
  else
    # Convert newline-separated indices to a jq index list.
    _dfj_jq_indices=$(printf '%s\n' "$_dfj_winners" \
      | awk 'NF{printf "%s%s", (NR>1?",":""), $0} END{printf ""}')
    jq -c "[.[$_dfj_jq_indices]]" "$_dfj_in" 2>/dev/null \
      || cat "$_dfj_in"  # conservative fallback: passthrough on jq error
  fi

  rm -f "$_dfj_in" "$_dfj_keys_file" "$_dfj_combined"
  return 0
}

_dedup_findings_py() {
  _dfp_strategy="$1"
  _dfp_seen="$2"
  _dfp_difffile="${3:-}"

  python3 - "$_dfp_strategy" "$_dfp_seen" "$_dfp_difffile" <<'PYEOF'
import json, sys, hashlib, os

strategy  = sys.argv[1]
seen_file = sys.argv[2]
diff_file = sys.argv[3] if len(sys.argv) > 3 else ""

severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def find_context_window(diff_file, fname, target_line):
    """Extract +-lines around target_line for a given file from a unified diff."""
    result = []
    cur_file = ""
    diff_line = 0
    try:
        with open(diff_file) as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("+++ "):
                    cur_file = line[4:]
                    # Strip b/ prefix from git unified diffs.
                    if cur_file.startswith("b/"):
                        cur_file = cur_file[2:]
                    diff_line = 0
                elif line.startswith("@@ "):
                    import re
                    m = re.search(r'\+(\d+)', line)
                    diff_line = int(m.group(1)) - 1 if m else 0
                elif line.startswith("+") and cur_file == fname:
                    diff_line += 1
                    if abs(diff_line - target_line) <= 2:
                        result.append(line)
    except Exception:
        pass
    return result

def compute_key(f, strategy, diff_file):
    try:
        if strategy == "content-hash" and diff_file and os.path.isfile(diff_file):
            fname = f.get("file", "")
            line  = int(f.get("line", 0) or 0)
            ctx = find_context_window(diff_file, fname, line)
            if ctx:
                return hashlib.sha256("\n".join(ctx).encode()).hexdigest()
        # location key (primary or fallback).
        raw = "{}:{}:{}:{}".format(
            f.get("file", ""),
            str(f.get("line", "")),
            f.get("category", ""),
            str(f.get("message", "")).lower()
        )
        return hashlib.sha256(raw.encode()).hexdigest()
    except Exception:
        return None

# Read stdin.
try:
    findings = json.load(sys.stdin)
    if not isinstance(findings, list):
        raise ValueError("not a list")
except Exception:
    # Conservative: passthrough raw.
    sys.exit(0)

# Load seen keys.
seen = {}
try:
    with open(seen_file) as sf:
        for line in sf:
            k = line.strip()
            if k:
                seen[k] = True
except Exception:
    pass

# Dedup: key -> (index_in_output, severity_rank).
new_keys = {}
deduped = []   # list of findings to output
key_to_pos = {}  # key -> index in deduped

for f in findings:
    key = compute_key(f, strategy, diff_file)
    if key is None:
        # Conservative: retain without dedup.
        deduped.append(f)
        continue

    sev = str(f.get("severity", "")).lower()
    r = severity_rank.get(sev, 0)

    if key in seen:
        # Already seen in a prior run: skip (already deduped).
        # But check if this is a higher-severity version of an existing winner.
        if key in key_to_pos:
            pos = key_to_pos[key]
            old_sev = str(deduped[pos].get("severity", "")).lower()
            old_r = severity_rank.get(old_sev, 0)
            if r > old_r:
                deduped[pos] = f
        continue

    if key not in key_to_pos:
        key_to_pos[key] = len(deduped)
        deduped.append(f)
        new_keys[key] = True
    else:
        pos = key_to_pos[key]
        old_sev = str(deduped[pos].get("severity", "")).lower()
        old_r = severity_rank.get(old_sev, 0)
        if r > old_r:
            deduped[pos] = f

# Append new keys to seen file.
try:
    with open(seen_file, "a") as sf:
        for k in new_keys:
            sf.write(k + "\n")
except Exception:
    pass

print(json.dumps(deduped))
PYEOF
  return $?
}
