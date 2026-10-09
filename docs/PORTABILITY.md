# clagentic-lite — Portability notes (WSL2 + macOS)

clagentic-lite is tested on:
- Ubuntu 22.04 / 24.04 under WSL2 (Windows 11)
- macOS Sonoma (14) and Sequoia (15)

It is **not** tested on bare Windows (no WSL), on Alpine, or on BSDs other than macOS. Patches welcome.

## The portability strategy in one paragraph

Every script that uses `sed`, `date`, `stat`, or a timeout sources `scripts/platform.sh`, which detects GNU vs BSD at load time and provides shims (`DS_SED_INPLACE`, `ds_date_iso`, `ds_stat_mtime`, `$DS_TIMEOUT_CMD`). Scripts use the shims rather than invoking the bare tool flag where it differs across platforms.

## Known footguns

| Issue | WSL/Linux | macOS | Our shim |
|---|---|---|---|
| `sed -i` | `sed -i 's/x/y/' f` | requires backup suffix: `sed -i '' 's/x/y/' f` | `sed $DS_SED_INPLACE` |
| `date -Iseconds` | works | not portable; use `date -u +%FT%TZ` | `ds_date_iso` |
| `stat -c %Y` | works | macOS uses `stat -f %m` | `ds_stat_mtime` |
| `grep -P` | Perl regex | not supported on BSD grep | avoided; use POSIX or `awk` |
| `xargs -I {}` | works | works but flag order is finicky | explicit `sh -c` wrappers |
| `readlink -f` | works | older macOS lacks `-f` | `ds_realpath` (`bin/clagentic-lite`): `realpath`, then `python3 os.path.realpath`, then `cd && pwd`; the CLI's own bootstrap adds a manual `readlink` hop loop |
| `mktemp -d -t` | template optional | template required | always provide template |
| `timeout` | GNU coreutils default | not installed by default; `brew install coreutils` provides `gtimeout` | `$DS_TIMEOUT_CMD` (detects `timeout`, falls back to `gtimeout`; if neither exists, resolves to `ds_timeout_missing`, which FAILS CLOSED — refuses to run the wrapped command unbounded and returns exit 99 with an install hint, rather than silently running without a bound. See AGENTS.md Invariants, INV-1a.) |
| JSON parsing in hooks | `jq` or `python3` | `jq` or `python3` (python3 ships on modern macOS) | `ds_json_field` helper in `scripts/platform.sh`. **Required** — hooks fail closed without either. |
| Finding decisions (review, adversarial, ledger, merge-gate summary) | `python3` | `python3` (ships on macOS) | `plugins/clagentic-lite/bin/findings.py`, stdlib only, called through `ds_findings_call` in `scripts/platform.sh`. **Required** — gate commands fail closed without it; `doctor` and `init` report it missing. |
| `realpath` | available everywhere | not on macOS by default | shimmed via `python3 os.path.realpath` in `pre-write-guard.sh` for the W-002 normalization check |

## Bash version

macOS ships bash 3.2.57 (last GPLv2 release; Apple won't ship newer for licensing reasons). clagentic-lite scripts use **POSIX sh only** — no associative arrays, no `${var^^}`, no `mapfile`, no `[[ ... =~ ... ]]` capture groups.

You can install bash 5 on macOS via Homebrew (`brew install bash`) but clagentic-lite will not assume it.

## SQLite version

macOS ships SQLite ~3.43; Ubuntu 24.04 ships ~3.45. clagentic-lite uses only features available since 3.35, with no JSON1 dependency and no window functions. FTS5 is optional: `memory.sh` creates the `turns_fts` index only when the installed SQLite was built with it, and recall falls back to `LIKE` otherwise (or when `CLAGENTIC_DISABLE_FTS=1`).

## Filesystem watching

We don't watch the filesystem. All hooks are pull-driven (fire on a Claude Code or git event). This sidesteps the inotify-vs-FSEvents gap entirely.

## Path separators

Repo paths are POSIX everywhere (WSL2 sees `/mnt/c/...` if you're crossing to Windows-mounted drives, which is slow and not recommended for the repo itself — keep the repo inside the Linux filesystem under WSL).

If macOS users have Homebrew GNU tools on PATH ahead of system tools, clagentic-lite will detect and use them. It does not require them.

## What we deliberately don't do

- Shell out to anything Node-only on the harness side (examples are fine; the harness itself is POSIX sh + sqlite + a small `python3 -c` for JSON parsing where shell isn't safe).
- Assume `gh` (GitHub CLI). `gates ship` uses `gh` if present (the GitHub adapter in `scripts/host-adapter.sh`) and otherwise prints the base branch, head branch and remote so you can open the PR yourself.

## What we DO require

- `jq` **or** `python3` for JSON parsing in PreToolUse hooks. The previous `sed`-based JSON parser was a known security bypass surface (escaped-quote truncation). Without a real validator the hooks fail closed and block every Bash/Write/Edit tool call. `clagentic-lite doctor` flags this as a hard miss.
- `sqlite3` for the memory and audit databases. macOS ships an old SQLite; we use only features available since 3.35 (no JSON1, no window functions; FTS5 optional, see above).
- `timeout` or `gtimeout` for LLM-call timeouts. If absent, `$DS_TIMEOUT_CMD` resolves to `ds_timeout_missing`, which **fails closed**: it refuses to run the wrapped command at all and returns exit 99, rather than running it unbounded (see the `timeout` row above and AGENTS.md Invariants, INV-1a). `clagentic-lite init` and `update` warn about a missing `timeout`/`gtimeout` in their prerequisite sweep, so you can install one before this bites you.

## Shell idioms in bin/clagentic-lite

`bin/clagentic-lite` introduces a few portable idioms worth documenting:

| Pattern | Why |
|---|---|
| `ds_realpath` (in `bin/clagentic-lite`) | `readlink -f` is not on macOS by default. Uses `realpath` if present, `python3 os.path.realpath` fallback, then `cd && pwd + basename` POSIX fallback. |
| `awk` for in-place edits | `sed -i` portability issues are already in the table above. `awk` with a temp file and `mv` is portable and handles values that contain `/` or other sed metacharacters (config merges, the plugin render's `model:` line insertion). |
| `( umask 077 && : > file )` | Creates a config-bearing temp file at mode 600 in one syscall, instead of a `> file` followed by `chmod` with a window between them. POSIX sh only; no GNU/BSD difference. |
| `python3 -c` for JSON export | `clagentic-lite export` builds its JSON with `python3`; everything else in the CLI avoids it except as a `ds_realpath` fallback. |

## Quick verify

```sh
clagentic-lite doctor
```

Prints an `OK`/`FAIL`/`WARN` line per check and a summary count. Exits 0 if no check failed, non-zero if any did (`WARN` lines are advisory and do not affect the exit status).
