---
description: Search session memory. Greps prior session summaries for keywords, returns the top N most recent.
argument-hint: "<keywords>"
---

Search this project's session memory.

```sh
scripts/memory.sh recall "$ARGUMENTS"
```

Returns up to 5 prior session summaries matching the keywords, most recent first. No vector search — this is a SQLite `LIKE` over the `summary` and `tags` columns of `.clagentic/memory.db`.

If `$ARGUMENTS` is empty, prints the 5 most recent summaries regardless of topic.

For raw inspection:

```sh
sqlite3 .clagentic/memory.db 'SELECT ts, branch, summary FROM turns ORDER BY ts DESC LIMIT 20'
```
