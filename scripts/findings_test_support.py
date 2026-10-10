"""
Shared fixtures for the tests of the standalone finding pipeline
(plugins/clagentic-lite/bin/findings.py): a throwaway git repository, a
subprocess runner with no CLAGENTIC_* environment, and an importable copy of the
module for unit-level assertions. Every path lives under a temp directory;
nothing here touches this checkout's own .clagentic state.
"""
import importlib.util
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from git_env_scrub import scrub_git_env  # noqa: E402
from module_identity import register  # noqa: E402

register(__name__, sys.modules[__name__])
# Covers a unittest run, which has no conftest.py; pytest also scrubs there.
scrub_git_env()

TOOL_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FINDINGS_PY = os.path.join(TOOL_HOME, "plugins", "clagentic-lite", "bin", "findings.py")

GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
}


def load_module():
    """findings.py imported as a module (its __main__ guard keeps it inert)."""
    spec = importlib.util.spec_from_file_location("findings_under_test", FINDINGS_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def clean_env(drop=("CLAGENTIC_", "GIT_")):
    """The caller's environment minus every variable whose name starts with a
    DROP prefix. GIT_DIR or GIT_INDEX_FILE exported by a hook would otherwise
    redirect a fixture's git call off its temp repository."""
    return {k: v for k, v in os.environ.items() if not k.startswith(tuple(drop))}


def run_findings(args, stdin=None, cwd=None, env=None):
    base = clean_env()
    base.update(env or {})
    return subprocess.run([sys.executable, FINDINGS_PY] + list(args), input=stdin,
                          capture_output=True, text=True, cwd=cwd, env=base, timeout=120)


def git(repo, *args, check=True):
    env = clean_env(drop=("GIT_",))
    env.update(GIT_IDENTITY)
    return subprocess.run(["git", "-C", repo] + list(args), check=check,
                          capture_output=True, text=True, env=env, timeout=60)


def make_repo(path, branch="main"):
    """A git repository with one commit on BRANCH."""
    os.makedirs(path, exist_ok=True)
    git(path, "init", "-q", "-b", branch)
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Test")
    write(os.path.join(path, "app.py"), "print('hi')\n")
    git(path, "add", "app.py")
    git(path, "commit", "-q", "-m", "initial")
    return path


def commit_file(repo, rel, content, message="change"):
    write(os.path.join(repo, rel), content)
    git(repo, "add", rel)
    git(repo, "commit", "-q", "-m", message)
    return head(repo)


def head(repo):
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(content if isinstance(content, str) else json.dumps(content))
    return path


def entry(**over):
    """A valid disposition entry; keyword arguments replace top-level keys."""
    base = {
        "id": "d1", "gates": ["review"],
        "match": {"path_glob": "app.py", "category": "security"},
        "kind": "by_design", "rationale": "intentional fixture",
        "by": "maintainer", "at": "2026-01-01",
    }
    base.update(over)
    return base


# Facts the rubric turns back into a given severity, off the security floor: the
# severity a fixture names is its claim, and the rubric decides from facts, so
# a fixture that means "a medium finding" has to say what makes it one.
_OFF_FLOOR_FACTS = {
    "critical": ("network", "code_exec"),
    "high": ("authenticated_user", "code_exec"),
    "medium": ("authenticated_user", "availability"),
    "low": ("authenticated_user", "quality_only"),
}


def with_facts(item):
    """ITEM with the closed-vocabulary facts its severity (and reachable) imply,
    unless it states some itself. Reachable at high or critical is the security
    floor (anyone, code execution); anything else is off it. A severity that is
    not one of the four (unrankable) gets no facts: the worst case."""
    if "attacker_precondition" in item or "impact" in item:
        return item
    severity = str(item.get("severity", "")).strip().lower()
    if item.get("reachable") == "yes" and severity in ("high", "critical"):
        facts = ("network", "code_exec")
    else:
        facts = _OFF_FLOOR_FACTS.get(severity)
    if facts is not None:
        item["attacker_precondition"], item["impact"] = facts
    return item


def finding(**over):
    base = {"severity": "high", "file": "app.py", "line": 2, "category": "security",
            "message": "unsanitized input reaches a sink"}
    base.update(over)
    return with_facts(base)


def adversarial_finding(**over):
    base = {"file": "app.py", "line": 2, "category": "CWE-78", "message": "shell injection",
            "severity": "high", "reachable": "yes", "tier": "blocking", "class": "durable"}
    base.update(over)
    return with_facts(base)
