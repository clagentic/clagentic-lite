"""Path and text normalization, and the contained-read primitive for files a
repository holds."""
import os
import posixpath
import re


def norm_text(text):
    return " ".join(str(text).lower().split())


def norm_path(path):
    """A finding's file as a normalized relative path, so 'src/../auth.py' and
    './auth.py' cannot reach a glob that was written for another file."""
    text = str(path).strip().replace("\\", "/")
    normal = posixpath.normpath(text) if text else ""
    return "" if normal == "." else normal


def plain_relative_path(path):
    """PATH as a normalized repo-relative path when it is a plain one, else
    None: no '..' segment, not absolute, no NUL, not empty. Used for every path
    that is read from a file the repository holds and then opened, where
    norm_path's forgiving collapse of 'a/../b' would hide an escape attempt."""
    text = str(path).strip().replace("\\", "/")
    if not text or "\x00" in text or text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        return None
    if ".." in text.split("/"):
        return None
    normal = norm_path(text)
    return normal or None


def open_contained_regular(root, rel):
    """A binary read handle on REL under ROOT, or None when REL is not a plain
    relative path, resolves (through symlinks) outside ROOT, or is not a
    regular file. The kind check is made on the opened descriptor and the open
    does not block, so a FIFO or a device node can neither hang nor be read."""
    plain = plain_relative_path(rel)
    if plain is None:
        return None
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(real_root, plain))
    if real != real_root and not real.startswith(real_root + os.sep):
        return None
    try:
        fd = os.open(real, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        # 0o170000 is S_IFMT and 0o100000 is S_IFREG: spelled out so this
        # module keeps to the imports it already has.
        if os.fstat(fd).st_mode & 0o170000 != 0o100000:
            os.close(fd)
            return None
        return os.fdopen(fd, "rb")
    except OSError:
        os.close(fd)
        return None
