"""
pytest wiring for the suite: the live-checkout guard (scripts/live_tree_guard.py)
runs for every test session so a test that writes into this checkout's
.clagentic/ or .claude/ fails the run and names the path, and git-redirecting
variables are removed from the process before any test spawns git
(scripts/git_env_scrub.py).
"""
from git_env_scrub import scrub_git_env
from live_tree_guard import make_guard_fixtures

scrub_git_env()
live_tree_guard, live_tree_window = make_guard_fixtures()
