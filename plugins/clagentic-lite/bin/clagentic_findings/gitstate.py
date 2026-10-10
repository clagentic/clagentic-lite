"""Reading repository state through git, and policy files through either the
working tree or a trusted revision. Every git call is pinned to the intended
repository, never an ancestor's."""
import os
import re
import subprocess

GIT_TIMEOUT_SEC = 60
MAX_FILE_BYTES = 1024 * 1024
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/~^-]+$")


def read_text_bounded(path):
    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise OSError("%s is larger than %d bytes" % (path, MAX_FILE_BYTES))
    return data.decode("utf-8")


def worktree_reader(root):
    """A reader of repo-relative files from the working tree: text, or None
    for an absent file. A path that resolves outside the repository is an
    error, not a file."""
    real_root = os.path.realpath(root)

    def read(rel):
        path = os.path.join(root, rel)
        if not os.path.lexists(path):
            return None
        real = os.path.realpath(path)
        if real != real_root and not real.startswith(real_root + os.sep):
            raise OSError("%s resolves outside the repository" % rel)
        return read_text_bounded(real)
    return read


def git_run(root, args):
    """A completed git process, or None when git cannot run or times out. The
    variables that redirect which repository git touches are dropped so
    '-C root' decides."""
    drop = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE")
    env = {k: v for k, v in os.environ.items() if k not in drop}
    try:
        return subprocess.run(["git", "-C", root] + list(args), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=GIT_TIMEOUT_SEC, env=env)
    except (OSError, subprocess.SubprocessError):
        return None


def git_reader(root, base):
    """A reader of repo-relative files as they were at commit BASE."""
    def read(rel):
        listing = git_run(root, ["ls-tree", base, "--", rel])
        if listing is None or listing.returncode != 0:
            raise OSError("cannot read %s at %s" % (rel, base[:12]))
        if not listing.stdout.strip():
            return None
        blob = git_run(root, ["cat-file", "blob", "%s:%s" % (base, rel)])
        if blob is None or blob.returncode != 0:
            raise OSError("cannot read %s at %s" % (rel, base[:12]))
        if len(blob.stdout) > MAX_FILE_BYTES:
            raise OSError("%s is larger than %d bytes" % (rel, MAX_FILE_BYTES))
        return blob.stdout.decode("utf-8")
    return read


def is_repo_toplevel(root):
    """Whether ROOT is itself the top level of a git repository. 'git -C' only
    changes directory before git walks upward looking for a repository, so a
    directory inside an ancestor's work tree would otherwise be answered with
    the ancestor's refs and files."""
    top = git_run(root, ["rev-parse", "--show-toplevel"])
    if top is None or top.returncode != 0:
        return False
    return os.path.realpath(top.stdout.decode("utf-8", "replace").strip()) == os.path.realpath(root)


def repo_head(root):
    """HEAD of the repository ROOT is the top level of, or None. The top level
    must be ROOT itself: an ancestor repository is not ROOT's."""
    if not is_repo_toplevel(root):
        return None
    head = git_run(root, ["rev-parse", "HEAD"])
    if head is None or head.returncode != 0:
        return None
    sha = head.stdout.decode("utf-8", "replace").strip()
    return sha if re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", sha) else None


def resolve_base(root, explicit, default_branch):
    """The commit the gated change is measured against, or None. An explicit
    ref wins; otherwise the merge base of HEAD with origin/<default> or
    <default>. None for a directory that is not itself a repository top level:
    git would answer with an ancestor's refs, and a base that is not ROOT's
    would let that ancestor's dispositions and stakes profile decide ROOT's
    verdict."""
    if not is_repo_toplevel(root):
        return None
    if explicit:
        if not _BRANCH_RE.match(explicit) or explicit.startswith("-"):
            return None
        proc = git_run(root, ["rev-parse", "--verify", "--quiet", explicit + "^{commit}"])
        if proc is None or proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace").strip() or None
    name = default_branch or os.environ.get("CLAGENTIC_DEFAULT_BRANCH") or "main"
    if not _BRANCH_RE.match(name) or name.startswith("-"):
        return None
    for ref in ("origin/" + name, name):
        proc = git_run(root, ["merge-base", "HEAD", ref])
        if proc is not None and proc.returncode == 0:
            sha = proc.stdout.decode("utf-8", "replace").strip()
            if sha:
                return sha
    return None
