"""Path globs matched by dynamic programming. The glob comes from a file the
matcher does not trust, so nothing here backtracks exponentially."""
import re

_GLOBSTAR = "**"


def compile_glob(glob):
    """A path glob as a list of path segments. A segment that is exactly '**'
    matches zero or more whole path segments; within any other segment '*'
    matches any run of characters and '?' one character, neither crossing a
    '/'; a backslash escapes the next character. Matching is by dynamic
    programming (see glob_matches), never by a backtracking regex, because the
    glob comes from a file the matcher does not trust."""
    segments, tokens, stars_only = [], [], True
    i = 0

    def close():
        segments.append(_GLOBSTAR if (stars_only and len(tokens) >= 2) else tokens[:])
        del tokens[:]

    while i < len(glob):
        char = glob[i]
        if char == "\\" and i + 1 < len(glob):
            tokens.append(("lit", glob[i + 1]))
            stars_only = False
            i += 2
            continue
        if char == "/":
            close()
            stars_only = True
            i += 1
            continue
        if char == "*":
            tokens.append(("star", char))
        else:
            stars_only = False
            tokens.append(("any", char) if char == "?" else ("lit", char))
        i += 1
    close()
    # '*' runs inside an ordinary segment collapse to one: they match the same.
    out = []
    for segment in segments:
        if segment is _GLOBSTAR:
            out.append(_GLOBSTAR)
            continue
        collapsed = []
        for token in segment:
            if token[0] == "star" and collapsed and collapsed[-1][0] == "star":
                continue
            collapsed.append(token)
        out.append(collapsed)
    return out


def _segment_matches(tokens, text):
    """Wildcard match of one path segment: linear in the text per backtrack
    point, no exponential case."""
    ti = si = 0
    star, mark = -1, 0
    while si < len(text):
        if ti < len(tokens) and (tokens[ti][0] == "any" or (tokens[ti][0] == "lit"
                                                              and tokens[ti][1] == text[si])):
            ti += 1
            si += 1
        elif ti < len(tokens) and tokens[ti][0] == "star":
            star, mark = ti, si
            ti += 1
        elif star != -1:
            ti = star + 1
            mark += 1
            si = mark
        else:
            return False
    while ti < len(tokens) and tokens[ti][0] == "star":
        ti += 1
    return ti == len(tokens)


def glob_match_compiled(segments, path):
    parts = path.split("/")
    count = len(parts)
    reachable = {0}
    for segment in segments:
        following = set()
        if segment is _GLOBSTAR:
            following = set(range(min(reachable), count + 1))
        else:
            for index in reachable:
                if index < count and _segment_matches(segment, parts[index]):
                    following.add(index + 1)
        if not following:
            return False
        reachable = following
    return count in reachable


def glob_matches(glob, path):
    return glob_match_compiled(compile_glob(glob), path)


# Paths of every shape a repository holds, dotted and hidden names included.
# '*' stays within one segment, so a catch-all is a glob that matches every
# top-level name or every nested path; the two probe sets test each.
_PROBE_TOP_LEVEL = ("a", "0", "z", "README.md", ".env", "x.y")
_PROBE_NESTED = ("a/b", "a/b/c", ".github/workflows/ci.yml", "src/app/main.go",
                 "docs/a.b/c.d.e", "deep/" * 8 + "file.txt")


def matches_every_probe(glob):
    """True when GLOB is a catch-all: it matches every top-level probe name or
    every nested probe path. Decided by the compiled matcher, so '*', '?*',
    '**', '**/*', '***', '**/**' and '*/*/**' are all caught however they are
    spelled."""
    compiled = compile_glob(glob)
    for probes in (_PROBE_TOP_LEVEL, _PROBE_NESTED):
        if all(glob_match_compiled(compiled, probe) for probe in probes):
            return True
    return False


def glob_escape(path):
    return re.sub(r"([*?\\])", r"\\\1", path)
