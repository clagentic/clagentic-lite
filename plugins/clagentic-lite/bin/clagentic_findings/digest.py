"""sha256 digests, the one place the pipeline hashes text or a stream."""
import hashlib


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def sha256_stream(handle, chunk=1024 * 1024):
    """sha256 hex digest of everything HANDLE yields, read in chunks."""
    digest = hashlib.sha256()
    for block in iter(lambda: handle.read(chunk), b""):
        digest.update(block)
    return digest.hexdigest()
