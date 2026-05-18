# clagentic-lite — examples

Tiny demo projects with **deliberately planted issues**, one per language:

| Project | Bug planted in code | Secret planted in `.env.example` |
|---|---|---|
| `python/` | `normalize_email` strips/lowercases but does not reject embedded null bytes | `AKIAIOSFODNN7EXAMPLE` (gitleaks fixture) |
| `node/`   | same null-byte issue in `normalizeEmail` | `AKIAIOSFODNN7EXAMPLE` |
| `go/`     | same null-byte issue in `NormalizeEmail` | `AKIAIOSFODNN7EXAMPLE` |

The token is the public gitleaks test fixture — it is NOT a real credential. It is the value gitleaks ships its tests with, so any properly-configured scanner will flag it.

## Why these exist

The 5-minute demo (`docs/DEMO-SCRIPT.md`) and the smoke test (`scripts/smoke.sh`) both need real code with real defects to gate on. Without these, every gate is exercised against an empty diff and the demo is a series of `pass — 0 findings` lines.

## Running

```sh
cd examples/python && python3 auth.py "user@example.com"        "hunter2"
cd examples/node   && node    auth.js "user@example.com"        "hunter2"
cd examples/go     && go run  auth.go "user@example.com"        "hunter2"
```

Each prints the normalized email and the (fake) "authenticated" result. The bug surfaces only on hostile input:

```sh
cd examples/python && python3 auth.py "admin@example.com\x00evil" "anything"
```

…which the current code accepts as `admin@example.com` after stripping. The Reviewer should flag this on `/review`.

## Don't commit the secrets

The `.env.example` files in each project intentionally contain the fixture token. If you copy one to `.env` and stage it, gitleaks at the pre-commit gate will block — that is the demo. Do not commit the `.env` files.
