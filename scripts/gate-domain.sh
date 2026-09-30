#!/bin/sh
# clagentic-lite :: gate input domains (pre-push)
#
# WHY THIS EXISTS: pre-push used to run deps + sast unconditionally. A push
# whose diff touches nothing either gate reads still got blocked by that
# gate's PRE-EXISTING findings, and the only escape was --no-verify, which
# disables every gate including ones that genuinely apply.
#
# THE UNIT IS THE GATE'S INPUT DOMAIN: the set of paths whose contents the
# gate's verdict can possibly depend on. Irrelevance is COMPUTED here from the
# git-supplied ref list, never asserted by the pusher. Rejected on purpose: a
# --docs-only flag, an *.md exemption, per-repo path-exclusion config (each is
# a pusher-controlled claim about their own diff).
#
# RULES (each one closes a real way this could become "skip gates on docs"):
#   1. A domain is an ALLOWLIST of what a gate reads, never a denylist of what
#      to ignore. A path in no allowlist is out of domain only for gates that
#      declare an allowlist; any gate without one (every future gate included)
#      treats every path as in domain.
#   2. Secret scanning, review, adversarial and merge-gate are NEVER eligible
#      (_gd_gate_eligible_for_skip). Only deps and sast declare a domain.
#   3. Gate configuration is in EVERY gate's domain: a push touching any gate's
#      own config (ruleset, ignore/allow list, severity file, suppression
#      file) skips nothing, so weakening a gate and skipping the gate that
#      would have noticed cannot happen in one push.
#   4. FAIL CLOSED: whenever the changed-path set cannot be determined with
#      certainty (see _gd_collect_changed_paths) every gate runs.
#   5. A skip is the distinct outcome skipped_out_of_domain, never "pass". Its
#      audit row carries the domain tested, the changed paths tested, and how
#      they were derived.
#
# MAINTENANCE PATH for the domain data below: osv-scanner's supported
# manifest/lockfile set and semgrep's language coverage drift with upstream.
# Neither tool reports a file-name/extension map, so both domains are tables
# in this file, deliberately over-inclusive. _GD_OSV_TABLE_VERSION and
# _GD_SEMGREP_TABLE_VERSION record the scanner version each table was last
# audited against; `clagentic-lite doctor` warns when an installed scanner is
# newer than its recorded version. To clear that warning: audit the scanner's
# release notes for new ecosystems/languages, extend the table, bump the
# recorded version.
#
# Sourced by scripts/gates.sh. Functions that read repo state rely on
# gates.sh's _git, _git_repo_root_is_scoped and
# _gate_resolve_fresh_default_branch_ref (INV-6: never a bare git call).

_GD_OSV_TABLE_VERSION="2.2.0"
_GD_SEMGREP_TABLE_VERSION="1.130.0"
_GD_DEPS_DOMAIN_ID="deps-manifests-and-lockfiles@osv-scanner-${_GD_OSV_TABLE_VERSION}"
_GD_SAST_DOMAIN_ID="sast-source-and-config@semgrep-${_GD_SEMGREP_TABLE_VERSION}"
_GD_OUTCOME_SKIPPED="skipped_out_of_domain"

_gd_nl='
'
_gd_tab=$(printf '\t')

# _gd_gate_eligible_for_skip GATE — 0 only for gates that declare an input
# domain. Everything else (secrets above all) always runs.
_gd_gate_eligible_for_skip() {
  case "$1" in
    deps|sast) return 0 ;;
  esac
  return 1
}

# _gd_always_run_all — 0 when CLAGENTIC_ALWAYS_RUN_ALL_GATES asks for uniform
# execution. Default off (domains active). Any value other than 0/empty turns
# it on, so a typo errs toward running gates, never toward skipping them.
_gd_always_run_all() {
  case "${CLAGENTIC_ALWAYS_RUN_ALL_GATES:-0}" in
    0|'') return 1 ;;
  esac
  return 0
}

# _gd_path_ext PATH — lowercased extension of the basename, empty when there
# is none. A leading-dot name with no further dot (.bashrc, .env) has no
# extension: it is a whole name, not an extension.
_gd_path_ext() {
  _gpe_base="${1##*/}"
  _gpe_stem="${_gpe_base#.}"
  case "$_gpe_stem" in
    *.*) printf '%s' "${_gpe_base##*.}" | tr 'A-Z' 'a-z' ;;
    *) printf '' ;;
  esac
}

# _gd_path_is_vendored PATH — vendored dependency trees are dependency surface
# wherever they sit, including under a documentation path.
_gd_path_is_vendored() {
  case "$1" in
    vendor/*|*/vendor/*|node_modules/*|*/node_modules/*) return 0 ;;
    third_party/*|*/third_party/*|thirdparty/*|*/thirdparty/*) return 0 ;;
  esac
  return 1
}

# _gd_path_is_gate_config PATH — 0 when PATH is configuration of any gate.
# Deliberately broad: a false positive costs one full gate run, a false
# negative is the privilege-escalation shape described in rule 3.
_gd_path_is_gate_config() {
  _gpc_path="$1"
  case "$_gpc_path" in
    .clagentic/*|*/.clagentic/*|.semgrep/*|*/.semgrep/*) return 0 ;;
  esac
  case "${_gpc_path##*/}" in
    .gitleaks*|.semgrep*|osv-scanner.toml|.osv-scanner.toml|.clagentic-bleed-ignore) return 0 ;;
  esac
  if [ -n "${CLAGENTIC_SEMGREP_CONFIG:-}" ]; then
    _gpc_pin="${CLAGENTIC_SEMGREP_CONFIG#./}"
    case "$_gpc_path" in
      "$_gpc_pin"|"$_gpc_pin"/*) return 0 ;;
    esac
  fi
  return 1
}

# _gd_path_in_deps_domain PATH — manifests, lockfiles and SBOM/archive inputs
# osv-scanner can read, per ecosystem. Over-inclusive by design (see header).
_gd_path_in_deps_domain() {
  _gdd_path="$1"
  _gd_path_is_vendored "$_gdd_path" && return 0
  _gdd_base="${_gdd_path##*/}"
  case "$_gdd_base" in
    package.json|package-lock.json|npm-shrinkwrap.json|yarn.lock|pnpm-lock.yaml|bun.lock|bun.lockb) return 0 ;;
    requirements*.txt|Pipfile|Pipfile.lock|poetry.lock|pyproject.toml|pdm.lock|uv.lock|setup.py|setup.cfg|environment.yml|environment.yaml) return 0 ;;
    go.mod|go.sum|go.work|Cargo.toml|Cargo.lock|Gemfile|Gemfile.lock|*.gemspec|composer.json|composer.lock) return 0 ;;
    pom.xml|build.gradle|build.gradle.kts|settings.gradle|settings.gradle.kts|gradle.lockfile|buildscript-gradle.lockfile|gradle.properties) return 0 ;;
    mix.exs|mix.lock|pubspec.yaml|pubspec.lock|packages.lock.json|packages.config|paket.lock|paket.dependencies|deps.json|Directory.Packages.props|Directory.Build.props) return 0 ;;
    conan.lock|conanfile.txt|conanfile.py|vcpkg.json|renv.lock|Package.swift|Package.resolved|Podfile|Podfile.lock|Cartfile|Cartfile.resolved|.gitmodules) return 0 ;;
    *.lock|*.lockfile|*-lock.json|*.lock.json|*.resolved) return 0 ;;
    *.csproj|*.fsproj|*.vbproj|*.sln|*.nuspec) return 0 ;;
    *.cdx.json|*.cdx.xml|*.spdx.json|*.spdx|*.sbom|*.sbom.json) return 0 ;;
  esac
  case "$(_gd_path_ext "$_gdd_path")" in
    jar|war|ear|aar) return 0 ;;
  esac
  return 1
}

# _gd_path_in_sast_domain PATH — files semgrep reads: source in the languages
# its rulesets cover, the config/markup formats its rules read, literate
# documents that are compiled or executed, and every extensionless file
# (semgrep infers language from the shebang, so an extensionless file is code
# until proven otherwise).
_gd_path_in_sast_domain() {
  _gds_path="$1"
  _gd_path_is_vendored "$_gds_path" && return 0
  _gds_ext=$(_gd_path_ext "$_gds_path")
  case "$_gds_ext" in
    '') return 0 ;;
    py|pyi|ipynb|js|jsx|mjs|cjs|ts|tsx|mts|cts|vue|svelte|astro|mdx) return 0 ;;
    java|kt|kts|scala|sc|groovy|gradle|go|rb|erb|rake|php|phtml|cs|csx|swift|rs|dart) return 0 ;;
    c|h|cc|cpp|cxx|hpp|hh|hxx|m|mm|lua|pl|pm|r|rmd|qmd|org|jl|ex|exs|erl|hrl) return 0 ;;
    clj|cljs|cljc|edn|ml|mli|hs|lhs|sol|tf|tfvars|hcl|sql|proto|graphql|gql) return 0 ;;
    sh|bash|zsh|ksh|fish|ps1|psm1|bat|cmd|yaml|yml|json|jsonc|json5|toml|ini|cfg|conf|properties|xml) return 0 ;;
    html|htm|xhtml|svg|jsp|asp|aspx|cshtml|tpl|tmpl|j2|jinja|ejs|hbs|mustache) return 0 ;;
  esac
  return 1
}

# _gd_path_in_gate_domain GATE PATH — 0 when PATH can affect GATE's verdict.
# A gate with no declared domain has every path in its domain.
_gd_path_in_gate_domain() {
  case "$1" in
    deps) _gd_path_in_deps_domain "$2" ;;
    sast) _gd_path_in_sast_domain "$2" ;;
    *) return 0 ;;
  esac
}

# _gd_gate_domain_id GATE — the domain snapshot id recorded in skip rows.
_gd_gate_domain_id() {
  case "$1" in
    deps) printf '%s' "$_GD_DEPS_DOMAIN_ID" ;;
    sast) printf '%s' "$_GD_SAST_DOMAIN_ID" ;;
    *) printf 'all-paths' ;;
  esac
}

# _gd_inconclusive REASON — record why the changed-path set is unknown and
# return 1. Every caller treats 1 as "run every gate".
_gd_inconclusive() {
  _GD_INCONCLUSIVE_REASON="$1"
  return 1
}

_gd_is_zero_sha() {
  case "$1" in
    ''|*[!0]*) return 1 ;;
  esac
  return 0
}

# _gd_history_is_plain — 0 when the repo's history is one this module can
# reason about. Shallow clones, grafts and replace refs all make a ref range
# stop describing what the remote will hold.
_gd_history_is_plain() {
  _git_repo_root_is_scoped || { _gd_inconclusive "REPO_ROOT is not a git repo"; return 1; }
  [ "$(_git rev-parse --is-shallow-repository 2>/dev/null)" = "false" ] \
    || { _gd_inconclusive "shallow clone (history incomplete or not verifiable)"; return 1; }
  _gdh_graft=$(_git rev-parse --git-path info/grafts 2>/dev/null || echo "")
  case "$_gdh_graft" in
    '') _gd_inconclusive "cannot locate info/grafts"; return 1 ;;
    /*) ;;
    *) _gdh_graft="$REPO_ROOT/$_gdh_graft" ;;
  esac
  [ ! -e "$_gdh_graft" ] || { _gd_inconclusive "grafted history"; return 1; }
  [ -z "$(_git for-each-ref --count=1 refs/replace/ 2>/dev/null)" ] \
    || { _gd_inconclusive "replace refs present"; return 1; }
  return 0
}

# _gd_new_ref_base HEAD_SHA — merge-base of HEAD_SHA and the PROVABLY CURRENT
# origin/<default-branch> (same freshness precondition cmd_sast's baseline
# uses). Prints nothing on any failure: a stale or unverifiable base can only
# narrow the window, so it is never trusted.
_gd_new_ref_base() {
  _gnb_branch="${CLAGENTIC_DEFAULT_BRANCH:-main}"
  _gnb_timeout=$(ds_positive_int_or_default "${CLAGENTIC_SAST_FETCH_TIMEOUT_SEC:-30}" 30)
  _gnb_tip=$(_gate_resolve_fresh_default_branch_ref "$_gnb_branch" "$_gnb_timeout" 2>/dev/null) || _gnb_tip=""
  [ -n "$_gnb_tip" ] || return 0
  _git merge-base "$_gnb_tip" "$1" 2>/dev/null || true
}

# _gd_check_raw_entry META PATH — classify one `git diff --raw` entry. Returns
# 1 (inconclusive) for anything that is not a plain regular-file content
# change: symlinks, submodule pointers, type changes, mode changes, a file
# that becomes executable. A .md that turns into a symlink or gains the
# executable bit is not a prose change.
_gd_check_raw_entry() {
  _gcr_path="$2"
  set -- $1
  _gcr_omode="${1#:}"
  _gcr_nmode="$2"
  _gcr_status="$5"
  case "$_gcr_omode$_gcr_nmode" in
    *120000*|*160000*) _gd_inconclusive "symlink or submodule change at $_gcr_path"; return 1 ;;
  esac
  case "$_gcr_status" in
    T*) _gd_inconclusive "type change at $_gcr_path"; return 1 ;;
  esac
  if [ "$_gcr_nmode" = "100755" ]; then
    _gd_inconclusive "executable file at $_gcr_path"
    return 1
  fi
  if [ "$_gcr_omode" != "000000" ] && [ "$_gcr_nmode" != "000000" ] && [ "$_gcr_omode" != "$_gcr_nmode" ]; then
    _gd_inconclusive "file mode change at $_gcr_path"
    return 1
  fi
  return 0
}

# _gd_append_diff_paths BASE HEAD — append every path whose content differs
# between BASE and HEAD to _GD_PATHS. Renames are reported as a delete plus an
# add (--no-renames) so both ends are tested.
_gd_append_diff_paths() {
  _gad_raw=$(_git diff --raw --no-renames --no-abbrev --no-ext-diff "$1" "$2" 2>/dev/null) \
    || { _gd_inconclusive "git diff failed for $1..$2"; return 1; }
  while IFS= read -r _gad_line; do
    [ -n "$_gad_line" ] || continue
    _gad_meta="${_gad_line%%"$_gd_tab"*}"
    _gad_path="${_gad_line#*"$_gd_tab"}"
    case "$_gad_path" in
      \"*) _gd_inconclusive "path needing quoting in diff output"; return 1 ;;
    esac
    _gd_check_raw_entry "$_gad_meta" "$_gad_path" || return 1
    _GD_PATHS="${_GD_PATHS}${_GD_PATHS:+$_gd_nl}${_gad_path}"
  done <<EOF_DIFF
$_gad_raw
EOF_DIFF
  return 0
}

# _gd_collect_ref LOCAL_REF LOCAL_SHA REMOTE_REF REMOTE_SHA — one line of the
# pre-push stdin contract. Appends to _GD_PATHS and _GD_DERIVATION or returns
# 1 with _GD_INCONCLUSIVE_REASON set.
_gd_collect_ref() {
  _gcf_lref="$1"; _gcf_lsha="$2"; _gcf_rref="$3"; _gcf_rsha="$4"
  _gd_is_zero_sha "$_gcf_lsha" && { _gd_inconclusive "ref deletion ($_gcf_rref)"; return 1; }
  _gcf_head=$(_git rev-parse --verify --quiet "${_gcf_lsha}^{commit}" 2>/dev/null || echo "")
  [ -n "$_gcf_head" ] || { _gd_inconclusive "pushed object for $_gcf_lref is not a commit"; return 1; }

  if _gd_is_zero_sha "$_gcf_rsha"; then
    _gcf_base=$(_gd_new_ref_base "$_gcf_head")
    [ -n "$_gcf_base" ] || { _gd_inconclusive "new ref $_gcf_rref has no provable merge-base with the current default branch"; return 1; }
    _gcf_how="new ref $_gcf_rref, merge-base ${_gcf_base}..${_gcf_head}"
  else
    _git cat-file -e "${_gcf_rsha}^{commit}" 2>/dev/null \
      || { _gd_inconclusive "remote tip $_gcf_rsha of $_gcf_rref not present locally"; return 1; }
    _git merge-base --is-ancestor "$_gcf_rsha" "$_gcf_head" 2>/dev/null \
      || { _gd_inconclusive "non-fast-forward (force) push to $_gcf_rref"; return 1; }
    _gcf_base="$_gcf_rsha"
    _gcf_how="update $_gcf_rref, ${_gcf_base}..${_gcf_head}"
  fi

  _gcf_merges=$(_git rev-list --merges --count "${_gcf_base}..${_gcf_head}" 2>/dev/null || echo "")
  case "$_gcf_merges" in
    0) ;;
    *) _gd_inconclusive "merge commit(s) in ${_gcf_base}..${_gcf_head} (or count unavailable)"; return 1 ;;
  esac

  _gd_append_diff_paths "$_gcf_base" "$_gcf_head" || return 1
  _GD_DERIVATION="${_GD_DERIVATION}${_GD_DERIVATION:+; }${_gcf_how}"
  return 0
}

# _gd_collect_changed_paths REFS_TEXT — union of the changed paths across every
# ref git is about to push. Sets _GD_PATHS (sorted, unique, newline-separated)
# and _GD_DERIVATION, returns 0 only when EVERY range was conclusive and the
# union is non-empty. Any single inconclusive range makes the whole push
# inconclusive. An empty union is itself inconclusive: a diff that resolves to
# nothing is a derivation failure until proven otherwise.
_gd_collect_changed_paths() {
  _GD_PATHS=""
  _GD_DERIVATION=""
  _GD_INCONCLUSIVE_REASON=""
  _gcc_refs="$1"
  [ -n "$_gcc_refs" ] || { _gd_inconclusive "no pre-push ref list on stdin (not run by a git pre-push hook)"; return 1; }
  _gd_history_is_plain || return 1
  while IFS=' ' read -r _gcc_lref _gcc_lsha _gcc_rref _gcc_rsha _gcc_extra; do
    [ -n "$_gcc_lref$_gcc_lsha$_gcc_rref$_gcc_rsha" ] || continue
    [ -n "$_gcc_rsha" ] || { _gd_inconclusive "malformed pre-push ref line"; return 1; }
    _gd_collect_ref "$_gcc_lref" "$_gcc_lsha" "$_gcc_rref" "$_gcc_rsha" || return 1
  done <<EOF_REFS
$_gcc_refs
EOF_REFS
  _GD_PATHS=$(printf '%s\n' "$_GD_PATHS" | sort -u)
  [ -n "$_GD_PATHS" ] || { _gd_inconclusive "changed-path set is empty"; return 1; }
  return 0
}

# _gd_read_push_refs — the pre-push ref list from stdin, bounded so a caller
# that leaves stdin open cannot hang the hook. Prints nothing on a terminal or
# on timeout; the caller then treats the derivation as inconclusive.
_gd_read_push_refs() {
  [ -t 0 ] && return 0
  # A timed-out read may have captured a prefix of the list; a partial list
  # would silently drop refs from the union, so discard it entirely.
  _gprr_refs=$($DS_TIMEOUT_CMD 10 cat 2>/dev/null) || return 0
  printf '%s' "$_gprr_refs"
}

# _gd_paths_preview — first 10 changed paths on one line, for audit rows.
_gd_paths_preview() {
  printf '%s\n' "$_GD_PATHS" | head -n 10 | tr '\n' ' ' | sed 's/ $//'
}

# _gd_plan_pre_push — decide which eligible gates run for this push. Sets
# _GD_RUN_DEPS and _GD_RUN_SAST (1 = run, 0 = out of domain) plus
# _GD_SKIP_DETAILS_DEPS / _GD_SKIP_DETAILS_SAST for each 0. Every uncertainty
# leaves both at 1.
_gd_plan_pre_push() {
  _GD_RUN_DEPS=1
  _GD_RUN_SAST=1
  _GD_SKIP_DETAILS_DEPS=""
  _GD_SKIP_DETAILS_SAST=""

  if _gd_always_run_all; then
    echo "[gates/pre-push] CLAGENTIC_ALWAYS_RUN_ALL_GATES set -- running every gate" 1>&2
    return 0
  fi
  _gpp_refs=$(_gd_read_push_refs)
  if ! _gd_collect_changed_paths "$_gpp_refs"; then
    echo "[gates/pre-push] changed-path set not provable ($_GD_INCONCLUSIVE_REASON) -- running every gate" 1>&2
    return 0
  fi
  _gpp_config_hit=""
  while IFS= read -r _gpp_path; do
    if _gd_path_is_gate_config "$_gpp_path"; then
      _gpp_config_hit="$_gpp_path"
      break
    fi
  done <<EOF_CFG
$_GD_PATHS
EOF_CFG
  if [ -n "$_gpp_config_hit" ]; then
    echo "[gates/pre-push] push touches gate configuration ($_gpp_config_hit) -- running every gate" 1>&2
    return 0
  fi

  for _gpp_gate in deps sast; do
    _gd_gate_eligible_for_skip "$_gpp_gate" || continue
    if [ "$_gpp_gate" = "sast" ] && [ -n "${CLAGENTIC_SEMGREP_CONFIG:-}" ]; then
      # A pinned ruleset can include generic-language rules that match any
      # file, so the language allowlist no longer bounds what semgrep reads.
      echo "[gates/pre-push] sast: CLAGENTIC_SEMGREP_CONFIG pins a custom ruleset, input domain unbounded -- running" 1>&2
      continue
    fi
    _gpp_hits=0
    while IFS= read -r _gpp_path; do
      if _gd_path_in_gate_domain "$_gpp_gate" "$_gpp_path"; then
        _gpp_hits=$((_gpp_hits + 1))
        break
      fi
    done <<EOF_DOM
$_GD_PATHS
EOF_DOM
    [ "$_gpp_hits" -eq 0 ] || continue
    _gpp_count=$(printf '%s\n' "$_GD_PATHS" | wc -l | tr -d ' ')
    _gpp_details="not applicable, NOT a pass: no changed path is in this gate's input domain; domain=$(_gd_gate_domain_id "$_gpp_gate"); changed_paths=${_gpp_count} [$(_gd_paths_preview)]; derived=${_GD_DERIVATION}"
    case "$_gpp_gate" in
      deps) _GD_RUN_DEPS=0; _GD_SKIP_DETAILS_DEPS="$_gpp_details" ;;
      sast) _GD_RUN_SAST=0; _GD_SKIP_DETAILS_SAST="$_gpp_details" ;;
    esac
  done
  return 0
}

# _gd_version_gt A B — 0 when dotted version A is strictly newer than B.
_gd_version_gt() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, "."); nb = split(b, y, ".")
    n = (na > nb) ? na : nb
    for (i = 1; i <= n; i++) {
      xi = x[i] + 0; yi = y[i] + 0
      if (xi > yi) exit 0
      if (xi < yi) exit 1
    }
    exit 1
  }'
}

# _gd_scanner_version TOOL — first dotted version in `TOOL --version`, empty
# when the tool is absent or prints none.
_gd_scanner_version() {
  command -v "$1" >/dev/null 2>&1 || return 0
  $DS_TIMEOUT_CMD 10 "$1" --version 2>/dev/null | grep -oE '[0-9]+(\.[0-9]+)+' | head -n 1 || true
}
