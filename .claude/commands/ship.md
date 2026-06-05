---
description: Run all gates in sequence. If green, open a PR. Every decision logged to .clagentic/audit.db.
---

Run the full gate sequence and ship if green.

```sh
clagentic-lite gates ship
```

This runs, in order:

1. **secrets** — `gitleaks protect --staged` (blocking)
2. **deps** — `osv-scanner --recursive .` (blocking on critical)
3. **sast** — `semgrep --config=auto` (blocking on ERROR)
4. **review** — cross-vendor review (blocking if any finding ≥ `${CLAGENTIC_BLOCK_SEVERITY}`)
5. **adversarial** — non-blocking commentary, attached to the PR
6. **push** — `git push -u origin HEAD` (only if all blocking gates pass)
7. **pr** — `gh pr create` (if `gh` is available; otherwise print URL template)

Every gate run inserts one row into `.clagentic/audit.db`.

If any blocking gate fails, `/ship` exits non-zero and tells you which gate, with the tool's verbatim output. Fix the underlying issue and re-run.

There is no `--skip` flag for `/ship`. Per-gate overrides exist (see `docs/GATES.md`) and require a written justification.
