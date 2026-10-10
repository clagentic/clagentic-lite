"""Stream, JSON and file primitives every other module of the finding pipeline
builds on: UTF-8 stream pinning, compact JSON output, atomic file replacement,
and environment-driven size caps."""
import io
import json
import os
import re
import sys
import tempfile

DEFAULT_MAX_FIELD_CHARS = 500


def setup_io():
    """Pin UTF-8 on every stream. A lone surrogate decoded from a JSON escape
    must reach a file or pipe byte-for-byte rather than abort the run."""
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="surrogatepass", newline="\n")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8",
                                  errors="backslashreplace", newline="\n",
                                  write_through=True)


def dumps(obj, indent=None, sort_keys=False):
    """Compact JSON, non-ASCII kept as-is: the shape the gates have always
    consumed from jq -c, so consumers and ledger lines stay byte-stable."""
    if indent:
        return json.dumps(obj, indent=indent, sort_keys=sort_keys,
                          ensure_ascii=False, separators=(",", ": "))
    return json.dumps(obj, sort_keys=sort_keys, ensure_ascii=False, separators=(",", ":"))


def read_stdin_text():
    return sys.stdin.buffer.read().decode("utf-8")


def load_json_file(path):
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def write_file_atomic(path, text):
    """Replace PATH with TEXT without ever exposing a half-written file."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".findings-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8", "surrogatepass"))
        if os.path.exists(path):
            os.chmod(tmp, os.stat(path).st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def warn(message):
    sys.stderr.write(message + "\n")


def positive_int_env(name, default):
    """Positive integer from the environment; a rejected value warns and falls
    back to DEFAULT (0 must never reach a cap or a timeout as 'unbounded')."""
    raw = os.environ.get(name, "")
    if raw == "":
        return default
    if re.fullmatch(r"[0-9]+", raw) and int(raw) > 0:
        return int(raw)
    warn("[clagentic-lite] WARN: %s=%s is not a positive integer; using the default (%s)."
         % (name, raw, default))
    return default


_MAX_FIELD_CHARS = []


def max_field_chars():
    """Per-field length cap; resolved once per process so a rejected
    environment value warns once, not once per sanitized field."""
    if not _MAX_FIELD_CHARS:
        _MAX_FIELD_CHARS.append(positive_int_env(
            "CLAGENTIC_INVARIANT_FEED_MAX_FIELD_CHARS", DEFAULT_MAX_FIELD_CHARS))
    return _MAX_FIELD_CHARS[0]
