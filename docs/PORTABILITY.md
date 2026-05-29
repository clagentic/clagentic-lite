# clagentic-lite — Portability notes (WSL2 + macOS)

clagentic-lite is tested on:
- Ubuntu 22.04 / 24.04 under WSL2 (Windows 11)
- macOS Sonoma (14) and Sequoia (15)

It is **not** tested on bare Windows (no WSL), on Alpine, or on BSDs other than macOS. Patches welcome.

## The portability strategy in one paragraph

Every script that uses `sed`, `date`, `stat`, or `find` sources `scripts/platform.sh`, which detects GNU vs BSD at load time and exports shims (`DS_SED_INPLACE`, `DS_DATE_ISO`, `DS_STAT_MTIME`, `DS_FIND_DELETE`). Scripts use the shims. No script directly invokes the bare tool flag where it differs across platforms.

## Known footguns

| Issue | WSL/Linux | macOS | Our shim |
|---|---|---|---|
| `sed -i` | `sed -i 's/x/y/' f` | requires backup suffix: `sed -i '' 's/x/y/' f` | `sed $DS_SED_INPLACE` |
| `date -Iseconds` | works | not portable; use `date -u +%FT%TZ` | `$DS_DATE_ISO` |
| `stat -c %Y` | works | macOS uses `stat -f %m` | `$DS_STAT_MTIME` |
| `find -delete` | works | works in modern macOS but not all BSD | `$DS_FIND_DELETE` |
| `grep -P` | Perl regex | not supported on BSD grep | avoided; use POSIX or `awk` |
| `xargs -I {}` | works | works but flag order is finicky | explicit `sh -c` wrappers |
| `readlink -f` | works | not on macOS by default | shimmed via `cd && pwd` |
| `mktemp -d -t` | template optional | template required | always provide template |
| `timeout` | GNU coreutils default | not installed by default; `brew install coreutils` provides `gtimeout` | `$DS_TIMEOUT_CMD` (detects `timeout`, falls back to `gtimeout`, then to a no-op wrapper that warns) |
| JSON parsing in hooks | `jq` or `python3` | `jq` or `python3` (python3 ships on modern macOS) | `ds_json_field` helper in `scripts/platform.sh`. **Required** — hooks fail closed without either. |
| `realpath` | available everywhere | not on macOS by default | shimmed via `python3 os.path.realpath` in `pre-write-guard.sh` for the W-002 normalization check |

## Bash version

macOS ships bash 3.2.57 (last GPLv2 release; Apple won't ship newer for licensing reasons). clagentic-lite scripts use **POSIX sh only** — no associative arrays, no `${var^^}`, no `mapfile`, no `[[ ... =~ ... ]]` capture groups.

You can install bash 5 on macOS via Homebrew (`brew install bash`) but clagentic-lite will not assume it.

## SQLite version

macOS ships SQLite ~3.43; Ubuntu 24.04 ships ~3.45. clagentic-lite uses only features available since 3.35. No JSON1 dependency, no FTS5, no window functions.

## Filesystem watching

We don't watch the filesystem. All hooks are pull-driven (fire on a Claude Code or git event). This sidesteps the inotify-vs-FSEvents gap entirely.

## Path separators

Repo paths are POSIX everywhere (WSL2 sees `/mnt/c/...` if you're crossing to Windows-mounted drives, which is slow and not recommended for the repo itself — keep the repo inside the Linux filesystem under WSL).

If macOS users have Homebrew GNU tools on PATH ahead of system tools, clagentic-lite will detect and use them. It does not require them.

## What we deliberately don't do

- Shell out to anything Node-only on the harness side (examples are fine; the harness itself is POSIX sh + sqlite + a small `python3 -c` for JSON parsing where shell isn't safe).
- Assume `gh` (GitHub CLI). `/ship` uses `gh` if present and falls back to printing the PR URL template.

## What we DO require

- `jq` **or** `python3` for JSON parsing in PreToolUse hooks. The previous `sed`-based JSON parser was a known security bypass surface (escaped-quote truncation). Without a real validator the hooks fail closed and block every Bash/Write/Edit tool call. `clagentic-lite doctor` flags this as a hard miss.
- `sqlite3` for the memory and audit databases. macOS ships an old SQLite; we use only features available since 3.35 (no JSON1, no FTS5, no window functions).
- `timeout` or `gtimeout` for LLM-call timeouts. If absent, calls run without timeouts — degraded but not broken, and `clagentic-lite doctor` warns.

## Shell idioms in bin/clagentic-lite

`bin/clagentic-lite` introduces a few portable idioms worth documenting:

| Pattern | Why |
|---|---|
| `ds_realpath` (in platform.sh) | `readlink -f` is not on macOS by default. Shims via `realpath` if present, `python3 os.path.realpath` fallback, then `cd && pwd + basename` POSIX fallback. |
| `python3 -c "import os; os.makedirs(...)"` | `mkdir -p` is POSIX but cannot set permissions atomically. Python `makedirs` accepts a mode argument. Used for `~/.config/clagentic/`, `~/.local/state/clagentic/`, and per-repo `.clagentic/`. |
| `python3 -c "import os; print(os.readlink(...))"` | `readlink` with no flags is POSIX but output varies; Python `os.readlink` is unambiguous. Used by `clagentic-lite doctor` to verify the symlink target. |
| `python3 -c "import shutil; shutil.rmtree(...)"` | `rm -rf` is POSIX but the path argument handling on edge cases (trailing slash, non-existent) varies. Python `shutil.rmtree` is predictable. Used by `clagentic-lite unenroll --purge`. |
| `awk` for in-place config edits | `sed -i` portability issues are already in the table above. `awk` with a temp file and `mv` is portable and handles values that contain `/` or other sed metacharacters. |

## Quick verify

```sh
clagentic-lite doctor
```

Prints what it found, what's missing, and a numbered punch list for any broken items. Exits 0 if clean, non-zero if any check fails.
