# CLAUDE.md

Claude Code does not yet natively support the `AGENTS.md` cross-tool convention. Until it does, this file exists to ensure Claude Code reads the same canonical agent instructions as every other tool that operates in this repo.

**The canonical instructions live in [`AGENTS.md`](./AGENTS.md). Read that file in full.** This pointer is the only thing that lives here.

The CLI binary was renamed from `bin/clagentic` to `bin/clagentic-lite` per the CLI Naming Standard (clagentic-brand/docs/CLI-NAMING-STANDARD.md, task lr-34da). The on-PATH command is now `clagentic-lite`. The `CLAGENTIC_HOME` env var is unchanged (env var renaming is tracked separately in lr-634d).

When this repo is opened by Claude Code, you should:

1. Read `AGENTS.md` completely.
2. Read `README.md` for product context.
3. Skim `docs/DESIGN.md` and `docs/GATES.md` for architectural context.
4. Then begin work.

Do not infer Claude-specific behavior from this file. If you need Claude-specific configuration, propose it in `AGENTS.md` under a clearly-marked section so other tools can ignore it consistently.
