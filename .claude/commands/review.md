---
description: Cross-vendor review of the staged diff. Builder writes, Reviewer (different vendor) reads, structured findings returned.
argument-hint: "[--adversarial]"
---

Run a cross-vendor code review on the currently staged diff.

```sh
clagentic-lite gates review
```

This routes through the gate orchestrator so the audit row, severity-block decision, render, and `.clagentic/last-review.json` persistence all stay in one path. Direct calls to `scripts/llm-client.sh review` skip those — never call it directly from the slash command.

If `$ARGUMENTS` contains `--adversarial`, also run the non-blocking adversarial pass:

```sh
clagentic-lite gates adversarial
```

After reviewing the output:

- If `findings` contains any entries at severity `${CLAGENTIC_BLOCK_SEVERITY}` or above, `clagentic-lite gates review` already exited non-zero and printed the rendered review. Address the findings before suggesting `/ship`.
- If the review came back as a "degraded" envelope (every Reviewer chain step failed — auth, model availability, network, timeout), the gate also blocks. Run `clagentic-lite gates digest` to see the per-step error hint in the audit log.
- If `findings` is empty and the review was not degraded, you may proceed to `/ship`.
- Do **not** dismiss findings without addressing them. If you disagree with the Reviewer, say so explicitly in the next commit message.

Reviewer output schema is defined in `.claude/agents/reviewer.md`. Wrapper invocation surface lives in `scripts/llm-client.sh`.
