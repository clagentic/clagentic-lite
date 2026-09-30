#!/bin/sh
# clagentic-lite :: external security-tool version floors
#
# Source AFTER scripts/platform.sh. Defines functions and one data table only;
# nothing runs at source time. Consumers: `doctor` (report) and `update`
# (report plus an unprivileged upgrade attempt), both in bin/clagentic-lite.
#
# ONE table (DS_TOOL_FLOOR_TABLE) declares, per tool in CLAGENTIC_SECURITY_TOOLS,
# the minimum version of each capability the gates depend on and what is lost
# below it. Adding a floor or a tool means editing that table, nowhere else.
# Version comparison is ds_version_ge (platform.sh), so the GNU/BSD `sort -V`
# difference is handled in exactly one place.

# Record format, one per line: TOOL|ID|MIN|LABEL|LOSS
#   MIN   a dotted version, or "none" when no floor could be established.
#   LABEL what the floor buys, used in the passing line.
#   LOSS  what is lost below the floor (or, for MIN=none, why no floor is
#         recorded). No '|' characters, no single quotes.
#
# "none" is deliberate, not a gap: a floor is recorded only when it is known
# from the tool's own behavior. gates.sh capability-probes semgrep and
# osv-scanner at run time instead of assuming a version, so no release of
# either gates a blocking capability, and inventing a number would only
# produce false warnings.
DS_TOOL_FLOOR_TABLE='gitleaks|history|8.19.0|feature-branch history scanning (gitleaks git)|feature-branch history scanning is UNAVAILABLE. On a feature branch with a clean index (the normal state after a commit) the staged-only scan an older gitleaks falls back to is a no-op, so committed secrets go unscanned on every such run, not just intermittently.
gitleaks|allowlist|8.25.0|[[allowlists]] array-of-tables with condition = "AND"|[[allowlists]] (array-of-tables) and condition = "AND" are misread by older gitleaks (default OR semantics), which can let a real secret slip past a path-scoped allowlist meant only for known fixtures. See the header comment of .gitleaks.toml.
semgrep|baseline|none|diff-scoped SAST (--baseline-commit)|no floor recorded: gates.sh probes scan --help for --baseline-commit at run time and falls back to a full-tree scan when it is absent, so no version gates a blocking capability.
osv-scanner|invocation|none|dependency scan invocation style|no floor recorded: gates.sh selects the invocation (scan source, scan --recursive, or legacy flat flags) by capability probe at run time, so no version gates a blocking capability.'

# ds_tool_version_raw TOOL
# Prints TOOL's own version output (bounded, stdin closed), or nothing when it
# fails or times out. Never prompts.
ds_tool_version_raw() {
  _dtvr_tool="$1"
  case "$_dtvr_tool" in
    gitleaks) _dtvr_arg="version" ;;
    *)        _dtvr_arg="--version" ;;
  esac
  _dtvr_to=$(ds_positive_int_or_warn CLAGENTIC_TOOL_VERSION_TIMEOUT_SEC "${CLAGENTIC_TOOL_VERSION_TIMEOUT_SEC:-}" 30)
  $DS_TIMEOUT_CMD "$_dtvr_to" "$_dtvr_tool" "$_dtvr_arg" 2>/dev/null </dev/null || true
}

# ds_tool_floor_report TOOL
#
# One line per floor row declared for TOOL:
#   STATE|TOOL|VERSION|ID|MIN|LABEL|LOSS
# STATE is one of:
#   ok          installed version parses and meets MIN
#   below       installed version parses and is lower than MIN
#   unparseable TOOL is on PATH but its output carried no version; VERSION
#               holds the first 80 chars of that output (pipes removed)
#   missing     TOOL is not on PATH
#   nofloor     the table records no floor for this row (LOSS says why);
#               VERSION is the installed version when parseable
# An unparseable version is never reported as ok: the floor cannot be
# confirmed, so the caller must say so.
ds_tool_floor_report() {
  _dtfr_tool="$1"
  _dtfr_installed=0
  _dtfr_ver=""
  _dtfr_raw=""
  if command -v "$_dtfr_tool" >/dev/null 2>&1; then
    _dtfr_installed=1
    _dtfr_raw=$(ds_tool_version_raw "$_dtfr_tool")
    _dtfr_ver=$(ds_version_extract "$_dtfr_raw")
  fi
  printf '%s\n' "$DS_TOOL_FLOOR_TABLE" | while IFS='|' read -r _r_tool _r_id _r_min _r_label _r_loss; do
    [ "$_r_tool" = "$_dtfr_tool" ] || continue
    if [ "$_dtfr_installed" -eq 0 ]; then
      _r_state=missing
      _r_shown=""
    elif [ "$_r_min" = "none" ]; then
      _r_state=nofloor
      _r_shown="$_dtfr_ver"
    elif [ -z "$_dtfr_ver" ]; then
      _r_state=unparseable
      _r_shown=$(printf '%s' "$_dtfr_raw" | head -1 | tr -d '|' | cut -c1-80)
    elif ds_version_ge "$_dtfr_ver" "$_r_min"; then
      _r_state=ok
      _r_shown="$_dtfr_ver"
    else
      _r_state=below
      _r_shown="$_dtfr_ver"
    fi
    printf '%s|%s|%s|%s|%s|%s|%s\n' "$_r_state" "$_r_tool" "$_r_shown" "$_r_id" "$_r_min" "$_r_label" "$_r_loss"
  done
}

# ds_tool_install_method TOOL
#
# Prints the install method of the TOOL binary on PATH when, and only when,
# that method is detected AND can upgrade it without privileges:
#   brew   the real binary lives under `brew --prefix`/Cellar and the prefix is
#          writable by the current user
#   pipx   the real binary lives in a pipx venv named TOOL that the current
#          user can write
# Anything else (a distro package, a root-owned prefix, a manual download, an
# unknown layout) prints nothing: no upgrade is attempted for it. The path is
# resolved through symlinks first, so a ~/.local/bin shim is judged by where
# the binary really is.
ds_tool_install_method() {
  _dtim_tool="$1"
  _dtim_bin=$(command -v "$_dtim_tool" 2>/dev/null || true)
  [ -n "$_dtim_bin" ] || return 0
  _dtim_real=$(ds_resolve_path "$_dtim_bin")

  case "$_dtim_real" in
    */venvs/"$_dtim_tool"/*)
      _dtim_venv="${_dtim_real%%/venvs/$_dtim_tool/*}/venvs/$_dtim_tool"
      if command -v pipx >/dev/null 2>&1 && [ -d "$_dtim_venv" ] && [ -w "$_dtim_venv" ]; then
        printf 'pipx'
        return 0
      fi
      ;;
  esac

  if command -v brew >/dev/null 2>&1; then
    _dtim_to=$(ds_positive_int_or_warn CLAGENTIC_TOOL_VERSION_TIMEOUT_SEC "${CLAGENTIC_TOOL_VERSION_TIMEOUT_SEC:-}" 30)
    _dtim_prefix=$($DS_TIMEOUT_CMD "$_dtim_to" brew --prefix 2>/dev/null </dev/null || true)
    if [ -n "$_dtim_prefix" ] && [ -d "$_dtim_prefix" ] && [ -w "$_dtim_prefix" ]; then
      _dtim_prefix=$(ds_resolve_path "$_dtim_prefix")
      case "$_dtim_real" in
        "$_dtim_prefix"/Cellar/*)
          printf 'brew'
          return 0
          ;;
      esac
    fi
  fi
  return 0
}

# ds_tool_upgrade_command TOOL METHOD
# Prints the exact command for METHOD (brew|pipx); prints nothing otherwise.
ds_tool_upgrade_command() {
  case "$2" in
    brew) printf 'brew upgrade %s' "$1" ;;
    pipx) printf 'pipx upgrade %s' "$1" ;;
  esac
}

# ds_tool_try_upgrade TOOL
#
# Attempts an unprivileged in-place upgrade of an already-installed TOOL.
# Returns:
#   0  the upgrade command ran and exited 0 (the caller must still re-check the
#      version: a package manager can succeed without reaching the floor)
#   1  no attempt: the install method is undetected or not unprivileged
#   2  the upgrade command failed or timed out
# Never uses sudo, never pipes a download into a shell, never installs a tool
# that is not already present, and never reads from the terminal.
ds_tool_try_upgrade() {
  _dtu_tool="$1"
  _dtu_method=$(ds_tool_install_method "$_dtu_tool")
  [ -n "$_dtu_method" ] || return 1
  _dtu_to=$(ds_positive_int_or_warn CLAGENTIC_TOOL_UPGRADE_TIMEOUT_SEC "${CLAGENTIC_TOOL_UPGRADE_TIMEOUT_SEC:-}" 300)
  case "$_dtu_method" in
    brew) $DS_TIMEOUT_CMD "$_dtu_to" brew upgrade "$_dtu_tool" >/dev/null 2>&1 </dev/null || return 2 ;;
    pipx) $DS_TIMEOUT_CMD "$_dtu_to" pipx upgrade "$_dtu_tool" >/dev/null 2>&1 </dev/null || return 2 ;;
    *) return 1 ;;
  esac
  return 0
}
