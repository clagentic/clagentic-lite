"""Argv validation shared by every stub `gh` used in tests.

A stub that accepts any argv lets a malformed real-gh invocation (a missing
space fusing two flags, a flag the subcommand does not have) pass every test
while failing for every real user. check() rejects any flag token that real gh
does not accept for the subcommand, with an explicit allowlist per subcommand
the adapter uses.
"""
import sys

_ALLOWED_FLAGS = {
    ("pr", "create"): {
        "--base", "-B", "--head", "-H", "--fill", "-f", "--fill-first",
        "--fill-verbose", "--body", "-b", "--body-file", "-F", "--title", "-t",
        "--draft", "-d", "--dry-run", "--web", "-w", "--recover",
    },
    ("pr", "list"): {
        "--head", "-H", "--base", "-B", "--state", "-s", "--json", "--jq", "-q",
        "--limit", "-L", "--author", "-A", "--label", "-l", "--search", "-S",
    },
    ("pr", "view"): {"--json", "--jq", "-q", "--comments", "-c", "--web", "-w"},
    ("pr", "comment"): {
        "--body", "-b", "--body-file", "-F", "--edit-last", "--create-if-none",
        "--web", "-w",
    },
}


def check(argv):
    """Exit 2 with an error on an unknown subcommand or an unknown flag."""
    key = tuple(argv[:2])
    allowed = _ALLOWED_FLAGS.get(key)
    if allowed is None:
        sys.stderr.write("fake gh: unknown command %r\n" % " ".join(argv[:2]))
        sys.exit(2)
    for tok in argv[2:]:
        if tok.startswith("-") and len(tok) > 1:
            flag = tok.split("=", 1)[0]
            if flag not in allowed:
                sys.stderr.write("fake gh: unknown flag %r for 'gh %s %s'\n" % (tok, key[0], key[1]))
                sys.exit(2)
