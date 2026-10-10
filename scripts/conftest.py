"""
pytest wiring for the suite: the live-checkout guard (scripts/live_tree_guard.py)
runs for every test session so a test that writes into this checkout's
.clagentic/ or .claude/ fails the run and names the path.
"""
from live_tree_guard import make_guard_fixtures

live_tree_guard, live_tree_window = make_guard_fixtures()
