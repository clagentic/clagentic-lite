#!/bin/sh
# clagentic-lite :: review-merge helper
#
# Sourced (not executed) by gates.sh. Diff chunking in POSIX sh, plus thin
# wrappers over the finding pipeline (plugins/clagentic-lite/bin/findings.py)
# for per-chunk envelope merging, cross-round key tracking and the review
# ledger. Every finding decision lives in findings.py; nothing here parses or
# ranks a finding.
#
#   split_diff   DIFF_FILE CHUNK_DIR CHUNK_BYTES
#   merge_envelopes ENVELOPE_DIR DEDUP_KEY_STRATEGY
#   dedup_findings  KEY_STRATEGY SEEN_FILE [DIFF_FILE [MODE]]  (reads stdin, writes stdout)
#   finding_content_keys DIFF_FILE  (reads stdin JSON findings array, writes stdout
#                                    TSV: key<TAB>file<TAB>category<TAB>message)
#   finding_recurrence_bump COUNTS_FILE
#   ledger_append / ledger_entries_for_branch / ledger_latest_for_branch
#
# Dependencies:
#   Required: git, awk, sed (via platform.sh shims), wc, python3 (every JSON
#             operation; see ds_findings_call in platform.sh, which fails closed
#             and says so when python3 is missing)
#   Optional: sha256sum or shasum (soft; identity fallback when both absent)
#
# This module needs platform.sh sourced first (ds_findings_call, ds_file_size).
# It does NOT source memory.sh or llm-client.sh, and does NOT call
# ds_audit_log (audit stays in gates.sh).

# ---------------------------------------------------------------- sha256 shim --
#
# Probed once at source time. Priority: sha256sum (GNU coreutils) ->
# shasum -a 256 (BSD/macOS) -> identity fallback (cat, returns input unchanged).
# The identity fallback means a state-identity hash is the raw input; it still
# distinguishes states but is sensitive to whitespace. clagentic-lite doctor
# warns when neither sha256 tool is present.
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

  # Integer guard for budget: non-numeric or empty falls back to the
  # documented default (256 KiB).
  case "$_sd_budget" in
    ''|*[!0-9]*) _sd_budget=262144 ;;
  esac
  # Degenerate-only floor (lr-25ce17): a budget of 0 would make every file
  # block "exceed the budget" and enter the hunk-split branch even for an
  # empty diff, and could loop pathologically on a file with no @@ hunks.
  # Floor only true degenerate values (0) rather than clamping any caller
  # value below an arbitrary 1024-byte threshold -- the previous 1024 floor
  # silently overrode ANY caller-specified budget under 1KB with no stderr
  # notice, defeating the documented CHUNK_BYTES contract (this function's
  # own header comment: "stdout: number of chunks" driven directly by the
  # caller's budget) and making small-budget chunking un-exercisable by any
  # caller, test or production (CLAGENTIC_REVIEW_CHUNK_BYTES /
  # CLAGENTIC_REVIEWER_MAX_DIFF_KB in gates.sh apply no lower bound of their
  # own before reaching here).
  [ "$_sd_budget" -lt 1 ] && _sd_budget=1

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
# one canonical envelope: summaries of non-degraded chunks joined with " | ",
# the union of checked arrays, findings deduplicated within the run (higher
# severity wins), degraded=true if ANY chunk is degraded or unreadable, plus
# chunked/chunks/chunks_degraded. Does NOT add the _clagentic_diff_sha stamp
# (gates.sh does that once on the final merged envelope).
#
# stdout: merged JSON
# exit 0: ok
# exit 1: no valid envelopes found, or the finding pipeline is unavailable
merge_envelopes() {
  _me_dir="$1"
  _me_strategy="${2:-location}"
  _me_rc=0
  # Status 1 is the stage's own "no valid envelopes" answer and comes with its
  # degraded envelope; any other failure comes with no output at all, and the
  # primitive has already said why on stderr.
  _me_out=$(ds_findings_call -e object -o 1 ingest merge "$_me_dir" --strategy "$_me_strategy") || _me_rc=$?
  if [ -z "$_me_out" ]; then
    printf '{"degraded":true,"chunked":true,"chunks":0,"chunks_degraded":0,"summary":"[clagentic-lite degraded] the finding pipeline failed or is unavailable for merge_envelopes","checked":[],"findings":[]}\n'
    return 1
  fi
  printf '%s\n' "$_me_out"
  return "$_me_rc"
}

# ------------------------------------------------------------- dedup_findings --
#
# dedup_findings KEY_STRATEGY SEEN_FILE [DIFF_FILE [MODE]]
#
# stdin:  JSON array of findings (the reviewer schema)
# stdout: deduplicated JSON array (higher severity wins on collision)
# exit 0: always (conservative: never suppress on parse error)
#
# KEY_STRATEGY: "location" (sha256 of file:line:category:lower(message), for
# WITHIN-RUN dedup) or "content-hash" (sha256 of a 5-line +-line context window
# around the finding from DIFF_FILE; falls back to the location key when there
# is no window). SEEN_FILE holds previously-seen keys, one per line; new keys
# are appended in place.
#
# MODE: "drop" removes a finding whose key is already in SEEN_FILE and is only
# safe where the result never feeds a verdict. "annotate" keeps it with
# _seen_before/_seen_key; every verdict-bearing caller must use it.
dedup_findings() {
  _df_strategy="$1"
  _df_seen="$2"
  _df_difffile="${3:-}"
  _df_mode="${4:-drop}"
  # stdin is read ONCE, here: a stage that fails after consuming a pipe leaves
  # nothing to pass through, so the findings are held to print unchanged if the
  # pipeline fails. Passing them through drops nothing and so can only keep a
  # finding blocking; ds_findings_call prints nothing on failure, so the
  # passthrough is never appended to partial output.
  _df_input=$(cat)
  ds_findings_call -t "$_df_input" -e any fingerprint dedup --strategy "$_df_strategy" \
    --seen "$_df_seen" --diff "$_df_difffile" --mode "$_df_mode" \
    || printf '%s\n' "$_df_input"
  return 0
}

# ------------------------------------------------------------ finding_content_keys --
#
# finding_content_keys DIFF_FILE
#
# stdin:  JSON array of findings
# stdout: one TSV row per finding that yields a content-hash key:
#         key<TAB>file<TAB>category<TAB>message
# A key that cannot be computed (no diff window, missing file/line) is omitted
# from this output only; it has no effect on dedup_findings' own retain rule.
# The key is the SAME one dedup_findings' content-hash strategy computes, so a
# key here is directly comparable to one persisted in a SEEN_FILE.
finding_content_keys() {
  # A failed pipeline yields no rows (and ds_findings_call says why on stderr).
  # No key means no recurrence count, so no demotion: the direction that keeps
  # a finding blocking.
  ds_findings_call -s -e any fingerprint keys --diff "$1" || return 0
}

# ------------------------------------------------------- finding_recurrence_bump --
#
# finding_recurrence_bump COUNTS_FILE
#
# stdin:  TSV, one row per finding, the shape finding_content_keys emits
# stdout: the SAME TSV with a 5th column appended: the updated recurrence count
#         for that key (an integer >= 1). COUNTS_FILE is a JSON object mapping
#         key -> count, persisted across rounds. A row with an empty key gets
#         count 1 and is not persisted; an unreadable COUNTS_FILE reads as
#         empty, so a count can only be undercounted, which can only under-demote.
finding_recurrence_bump() {
  _frb_input=$(cat)
  if ds_findings_call -t "$_frb_input" -e any fingerprint bump "$1"; then
    return 0
  fi
  # Failed pipeline: every row gets count 1, the documented undercount, which
  # can only under-demote. Nothing was printed by the failed call.
  printf '%s\n' "$_frb_input" | while IFS= read -r _frb_row; do
    if [ -n "$_frb_row" ]; then
      printf '%s\t1\n' "$_frb_row"
    fi
  done
  return 0
}

# ------------------------------------------------------------- ledger_append --
#
# ledger_append LEDGER_FILE JSON_LINE MAX_PER_BRANCH
#
# Appends ONE JSON object (single line) to LEDGER_FILE in JSON-Lines format,
# creating the file and its parent directory if absent. Append-only except for
# the per-branch cap: when MAX_PER_BRANCH is a positive integer, the OLDEST
# entries of the same branch past that count are dropped; other branches are
# never touched. 0 or non-numeric disables the cap.
#
# exit 0: always -- a ledger write failure must never abort the review gate
# itself (a lost entry only forces a fresh full-range review next round, it
# never reports a false pass).
ledger_append() {
  _la_file="$1"
  _la_line="$2"
  _la_max="${3:-0}"
  case "$_la_max" in ''|*[!0-9]*) _la_max=0 ;; esac
  # A lost entry only forces a fresh full-range review next round; the failure
  # is reported on stderr by ds_findings_call and never changes a verdict.
  ds_findings_call -t "$_la_line" -e any verdict ledger-append "$_la_file" "$_la_max" || :
  return 0
}

# --------------------------------------------------------- ledger_entries_for_branch --
#
# ledger_entries_for_branch LEDGER_FILE BRANCH
#
# stdout: every JSONL entry in LEDGER_FILE belonging to BRANCH, oldest first,
# one compact JSON object per line. Branch names are compared whole, never as
# substrings. Absent/empty LEDGER_FILE or no matching lines: no output, exit 0.
ledger_entries_for_branch() {
  _lefb_file="$1"
  _lefb_branch="$2"
  [ -f "$_lefb_file" ] || return 0
  # A failed pipeline yields no entries, which every reader treats as "no
  # anchored verdict": the fail-closed answer. The cause is reported on stderr
  # by ds_findings_call, so the failure is not mistaken for an empty ledger.
  ds_findings_call -e any verdict ledger-entries "$_lefb_file" "$_lefb_branch" || :
  return 0
}

# ----------------------------------------------------------- ledger_latest_for_branch --
#
# ledger_latest_for_branch LEDGER_FILE BRANCH
#
# stdout: the single most recent (last-appended) entry for BRANCH, or nothing.
ledger_latest_for_branch() {
  _llfb_file="$1"
  _llfb_branch="$2"
  ledger_entries_for_branch "$_llfb_file" "$_llfb_branch" | tail -n 1
}
