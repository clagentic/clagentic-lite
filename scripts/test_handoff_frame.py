"""Unit tests for the handoff frame extraction logic used in stop-summarize.sh.

The Python snippet in the Stop hook is an inline heredoc; this file extracts
the same logic into a testable module so regressions are caught without running
the full hook chain.
"""
import re
import unittest


# ---------------------------------------------------------------------------
# Extraction helpers — must mirror the heredoc in stop-summarize.sh exactly
# ---------------------------------------------------------------------------

def extract_active_task(summary: str) -> str:
    """Return the last 1-2 sentences of summary as the active-task line."""
    sentences = re.split(r'(?<=[.!?])\s+', summary.strip())
    if len(sentences) >= 2:
        return ' '.join(sentences[-2:])
    return summary.strip()


def extract_open_threads(summary: str) -> str:
    """Extract lines that start with recognised unresolved-item markers."""
    thread_lines = []
    for line in summary.splitlines():
        low = line.lower().strip()
        if low.startswith(('next:', 'todo:', 'follow-up:', 'followup:', '- [ ]', '* [ ]')):
            thread_lines.append(line.strip())
    return '\n'.join(thread_lines) if thread_lines else '(none extracted)'


_PATH_PATTERN = re.compile(
    r'(?:^|[\s`\'"])(/[\w./\-]+[\w./\-]|[\w./\-]+(?:/[\w./\-]+)+\.\w+)',
    re.MULTILINE,
)


def extract_key_files(last_turn: str, limit: int = 20) -> str:
    """Extract path-like tokens from the last assistant turn."""
    paths_seen: list = []
    for m in _PATH_PATTERN.finditer(last_turn):
        p = m.group(1)
        if p not in paths_seen:
            paths_seen.append(p)
    return '\n'.join(paths_seen[:limit]) if paths_seen else '(none extracted)'


def build_handoff(session_id: str, ts: str, summary: str, last_turn: str) -> str:
    """Assemble the full handoff.md content."""
    active_task = extract_active_task(summary)
    open_threads = extract_open_threads(summary)
    key_files = extract_key_files(last_turn)
    return (
        f"## Handoff Frame — {session_id} — {ts}\n\n"
        f"### Active task\n{active_task}\n\n"
        f"### Open threads\n{open_threads}\n\n"
        f"### Key files touched\n{key_files}\n\n"
        f"### Session notes\n{summary}\n"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestExtractActiveTask(unittest.TestCase):
    def test_two_or_more_sentences(self):
        summary = "Gate 3 ran clean. Next: bump version. TODO: add test."
        result = extract_active_task(summary)
        # Should return the last 2 sentences
        self.assertIn("Next: bump version.", result)
        self.assertIn("TODO: add test.", result)
        self.assertNotIn("Gate 3 ran clean.", result)

    def test_single_sentence(self):
        summary = "Single sentence summary."
        result = extract_active_task(summary)
        self.assertEqual(result, "Single sentence summary.")

    def test_empty_summary(self):
        result = extract_active_task("")
        self.assertEqual(result, "")


class TestExtractOpenThreads(unittest.TestCase):
    def test_next_and_todo_extracted(self):
        summary = (
            "Gate ran clean.\n"
            "Next: bump CLAUDE_CONTRACT_VERSION.\n"
            "TODO: add regression test.\n"
            "Unrelated line."
        )
        result = extract_open_threads(summary)
        self.assertIn("Next: bump CLAUDE_CONTRACT_VERSION.", result)
        self.assertIn("TODO: add regression test.", result)
        self.assertNotIn("Unrelated line.", result)

    def test_checkbox_markers(self):
        summary = "- [ ] Write docs\n* [ ] Run linter\nDone: shipped."
        result = extract_open_threads(summary)
        self.assertIn("- [ ] Write docs", result)
        self.assertIn("* [ ] Run linter", result)
        self.assertNotIn("Done:", result)

    def test_no_threads_returns_placeholder(self):
        result = extract_open_threads("Clean summary, no action items.")
        self.assertEqual(result, "(none extracted)")

    def test_followup_variant(self):
        summary = "follow-up: check the retry path."
        result = extract_open_threads(summary)
        self.assertIn("follow-up: check the retry path.", result)


class TestExtractKeyFiles(unittest.TestCase):
    def test_relative_paths_extracted(self):
        last_turn = (
            "Edited .claude/hooks/stop-summarize.sh and scripts/memory.sh "
            "to fix the issue. Also updated share/config.example."
        )
        result = extract_key_files(last_turn)
        self.assertIn(".claude/hooks/stop-summarize.sh", result)
        self.assertIn("scripts/memory.sh", result)
        self.assertIn("share/config.example", result)

    def test_absolute_paths_extracted(self):
        last_turn = "Modified /workspace/clagentic-lite/bin/clagentic-lite directly."
        result = extract_key_files(last_turn)
        self.assertIn("/workspace/clagentic-lite/bin/clagentic-lite", result)

    def test_deduplication(self):
        last_turn = "Touched scripts/memory.sh twice: scripts/memory.sh again."
        result = extract_key_files(last_turn)
        self.assertEqual(result.count("scripts/memory.sh"), 1)

    def test_no_paths_returns_placeholder(self):
        result = extract_key_files("No paths mentioned here at all.")
        self.assertEqual(result, "(none extracted)")


class TestBuildHandoff(unittest.TestCase):
    def test_structure(self):
        out = build_handoff(
            session_id="ses-abc123",
            ts="2026-06-23T10:00:00Z",
            summary="Gate ran. Next: bump version.",
            last_turn="Edited scripts/memory.sh.",
        )
        self.assertIn("## Handoff Frame — ses-abc123 — 2026-06-23T10:00:00Z", out)
        self.assertIn("### Active task", out)
        self.assertIn("### Open threads", out)
        self.assertIn("### Key files touched", out)
        self.assertIn("### Session notes", out)
        self.assertIn("Gate ran. Next: bump version.", out)


if __name__ == "__main__":
    unittest.main()
