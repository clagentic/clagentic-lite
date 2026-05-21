#!/bin/sh
# clagentic-lite :: PreToolUse (Bash) hook
# Blocks dangerous shell commands. Exit 2 = block.
# Rules R-001..R-020 documented in docs/GATES.md.

set -e

# Source platform shims for ds_json_field / ds_audit_log / ds_repo_root.
# The hook is invoked by Claude Code with cwd = the session's working dir;
# platform.sh lives at a fixed repo-relative path that we resolve via $0.
HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || HOOK_DIR=.
. "$HOOK_DIR/../../scripts/platform.sh"
ds_load_env

# _rule_allowed <rule_id> — returns 0 if the rule is in CLAGENTIC_ALLOW_BASH_RULES, 1 otherwise
_rule_allowed() {
  case ",${CLAGENTIC_ALLOW_BASH_RULES}," in
    *",${1},"*) return 0 ;;
  esac
  return 1
}

DEFAULT_BRANCH="${CLAGENTIC_DEFAULT_BRANCH:-main}"

# Read tool input from stdin (Claude Code JSON) and extract the command field
# via real JSON parsing — NOT sed, which truncated on escaped quotes and let
# attacks like `printf "x"; git reset --hard` evade R-005.
INPUT=$(cat 2>/dev/null || true)
JF_EXIT=0
CMD=$(printf '%s' "$INPUT" | ds_json_field command) || JF_EXIT=$?

# Fail closed on ANY non-zero ds_json_field exit:
#   exit 1 → JSON parse error (malformed payload)
#   exit 2 → no JSON validator (jq + python3 both missing)
# Either way, the hook cannot trust its input and must block.
if [ "$JF_EXIT" -ne 0 ]; then
  case "$JF_EXIT" in
    2) REASON="no JSON validator available (install jq or python3)" ;;
    *) REASON="malformed JSON payload" ;;
  esac
  printf '[clagentic-lite/pre-bash-guard] BLOCKED: %s\n' "$REASON" 1>&2
  ds_audit_log bash-guard block "fail-closed: $REASON"
  exit 2
fi

[ -z "$CMD" ] && exit 0

block() {
  RULE="$1"
  REASON="$2"
  printf '[clagentic-lite/pre-bash-guard] BLOCKED: %s — %s\n  command: %s\n' "$RULE" "$REASON" "$CMD" 1>&2
  # ds_audit_log resolves the repo root via git, so it works regardless of
  # the hook's cwd. SQL-safe — uses ds_sql_escape internally.
  ds_audit_log bash-guard block "$RULE: $CMD"
  exit 2
}

case "$CMD" in
  *"rm -rf /"*|*"rm -rf /*"*)            _rule_allowed R-001 || block R-001 "rm -rf root" ;;
  *"rm -rf \$HOME"*|*"rm -rf ~"*)        _rule_allowed R-002 || block R-002 "rm -rf HOME" ;;
  *"curl"*"| sh"*|*"curl"*"| bash"*|*"wget"*"| sh"*|*"wget"*"| bash"*)
                                          _rule_allowed R-003 || block R-003 "pipe-to-shell antipattern" ;;
  *"chmod -R 777"*)                       _rule_allowed R-004 || block R-004 "overpermissive chmod" ;;
  *"git reset --hard"*)                   _rule_allowed R-005 || block R-005 "destructive reset" ;;
  *"git checkout ."*|*"git restore ."*)   _rule_allowed R-006 || block R-006 "destructive checkout" ;;
  *"git push"*)
    # R-007: block force-push to the default branch. We check for `git push`
    # + ANY force flag anywhere in the command (not just immediately after
    # `git push`) so `git push origin --force main` also trips. Three force
    # variants: --force, -f, --force-with-lease.
    case "$CMD" in
      *"--force"*|*" -f "*|*" -f"|*"-f "*)
        CURRENT_BR=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
        case "$CMD" in
          *"$DEFAULT_BRANCH"*) _rule_allowed R-007 || block R-007 "force-push to default branch (named)" ;;
          *)
            if [ "$CURRENT_BR" = "$DEFAULT_BRANCH" ]; then
              _rule_allowed R-007 || block R-007 "force-push from default branch '$CURRENT_BR' (implicit HEAD)"
            fi
            ;;
        esac
        ;;
    esac
    ;;
  *"git clean -fdx"*|*"git clean -fxd"*)  _rule_allowed R-008 || block R-008 "destructive clean" ;;
  *"--no-verify"*)                        _rule_allowed R-009 || block R-009 "bypass of git hooks" ;;
  *"npm publish"*|*"pip upload"*|*"twine upload"*|*"cargo publish"*)
                                          _rule_allowed R-010 || block R-010 "unguarded registry publish" ;;
  # R-011 sudo: match `sudo ` at start, ` sudo ` mid, or `; sudo`/`&& sudo` chains.
  # Won't match `pseudo`/`sudoers-edit` etc. because of the space requirement.
  "sudo "*|*"; sudo "*|*"&& sudo "*|*"| sudo "*|*" sudo "*)
                                          _rule_allowed R-011 || block R-011 "elevation outside harness" ;;
  *'eval $('*|*'eval "$'*|*"eval '\$("*|*'eval \"$('*)
                                          _rule_allowed R-012 || block R-012 "indirect execution via eval" ;;
  *"aws s3 rm"*"--recursive"*|*"aws s3 rm"*" -r "*)
                                          _rule_allowed R-013 || block R-013 "recursive s3 delete" ;;
  *"terraform destroy"*)
    # Allow if --target=<resource> is present (scoped destroy is legitimate).
    case "$CMD" in
      *"--target="*) : ;;
      *) _rule_allowed R-014 || block R-014 "unguarded terraform destroy" ;;
    esac
    ;;
  *"docker system prune -a"*|*"docker system prune --all"*)
                                          _rule_allowed R-015 || block R-015 "docker prune -a" ;;
  *"git config --global"*)                _rule_allowed R-016 || block R-016 "mutation of global git config" ;;
  # R-017 chsh / passwd: require word-boundary (start, end, or surrounded by
  # whitespace / shell separators) so we don't catch `mypasswd-rotate.sh` etc.
  "chsh "*|"chsh"|"passwd "*|"passwd"|*" chsh "*|*" chsh"|*" passwd "*|*" passwd"|*"; chsh"*|*"; passwd"*|*"&& chsh"*|*"&& passwd"*)
                                          _rule_allowed R-017 || block R-017 "account modification" ;;
  *"dd "*"of=/dev/sd"*|*"dd "*"of=/dev/nvme"*|*"dd "*"of=/dev/hd"*|*"> /dev/sd"*|*"> /dev/nvme"*|*"> /dev/hd"*)
                                          _rule_allowed R-018 || block R-018 "disk-level write" ;;
  *"find "*" -delete"*)
    # R-019: find ... -delete must have a non-wildcard -path constraint.
    # `find / -path '*' -delete` would otherwise bypass — `-path` is present
    # but matches everything. Reject wildcard chars `*` and `?` inside the
    # -path value. POSIX case matching against the substring after -path.
    ALLOWED=0
    case "$CMD" in
      *"find "*" -path "*" -delete"*)
        # Pull the -path argument and check it's literal-ish. Wildcards or
        # absolute /-rooted globs are rejected.
        PARG=$(printf '%s' "$CMD" | sed -n 's/.*-path[[:space:]]*\([^[:space:]]*\).*/\1/p' | head -1)
        case "$PARG" in
          *"*"*|*"?"*|"'"*"*"*"'"|'"'*"*"*'"'|"/"*) ALLOWED=0 ;;
          "") ALLOWED=0 ;;
          *) ALLOWED=1 ;;
        esac
        ;;
    esac
    [ "$ALLOWED" -eq 0 ] && _rule_allowed R-019 || block R-019 "find -delete needs a literal (non-wildcard) -path constraint"
    ;;
  *": > .env"*|*": > "*"/.env"*|*"> .env"*|*"> "*"/.env"*|*"truncate "*".env"*|*": > "*".pem"*|*": > "*".key"*)
                                          _rule_allowed R-020 || block R-020 "truncation of credential file" ;;
esac

exit 0
