#!/bin/sh
# install.sh was removed in v0.2 when clagentic-lite moved from "install into
# the current repo" to "clone-once + per-repo enroll". This stub exists only
# as a migration aid so anyone with v0.1 muscle memory (or an AI assistant
# that learned the old flow) gets a clear redirect instead of a No-such-file
# error. Delete this file at your discretion once the new flow is universal.

cat 1>&2 <<'EOF'
install.sh was removed in clagentic-lite v0.2.

The new install flow is a one-time clone plus a per-project enroll:

    # First install OR re-run after pulling new commits:
    HOME_DIR="${CLAGENTIC_HOME:-$HOME/.clagentic-lite}"
    if [ -d "$HOME_DIR/.git" ]; then
      git -C "$HOME_DIR" pull --ff-only
    else
      git clone https://github.com/clagentic/clagentic-lite.git "$HOME_DIR"
    fi
    "$HOME_DIR/bin/clagentic-lite" init

    # Per-project (run from each repo you want gated):
    cd /path/to/your/project && clagentic-lite enroll

Steady-state upgrades: clagentic-lite update

See README.md for the full quickstart.
EOF
exit 1
