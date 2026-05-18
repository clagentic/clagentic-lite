#!/usr/bin/env python3
"""
clagentic-lite example: auth.py

Tiny single-file login() with one deliberately planted bug:
normalize_email() strips whitespace and lowercases, but does NOT reject
embedded null bytes or other control characters. On a backend that
compares the stored value lossy (e.g. SQLite TEXT vs C-strings used
elsewhere in the stack), an attacker registering "admin@example.com\\0evil"
can authenticate as "admin@example.com".

The Reviewer in clagentic-lite should flag this on /review.
"""

import sys


def normalize_email(email: str) -> str:
    # BUG: strip + lower does not reject embedded NUL or other control bytes.
    # Compare against normalize_email_safe() in tests/ for the fix.
    return email.strip().lower()


def login(email: str, password: str) -> bool:
    e = normalize_email(email)
    # Fake user store. In the demo, the password check is intentionally weak —
    # this file's purpose is the email-normalization bug, not auth completeness.
    users = {
        "admin@example.com": "hunter2",
        "user@example.com":  "hunter2",
    }
    return users.get(e) == password


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: auth.py <email> <password>", file=sys.stderr)
        return 2
    email, password = argv[1], argv[2]
    normalized = normalize_email(email)
    ok = login(email, password)
    print(f"normalized: {normalized!r}")
    print(f"login ok:   {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
