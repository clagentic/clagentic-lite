"""Neutralizing text before it reaches a file, a prompt a later model reads or
a terminal: escape and control stripping, fence-label defanging, length caps,
and the closed-schema field allowlist."""
import re

from .fileio import max_field_chars

TRUNCATION_SUFFIX = "...[truncated]"

# Fence labels any prompt-bound payload must not be able to forge. Defanged
# unconditionally: one planted payload can round-trip through any pipeline.
_FENCE_LABELS = (
    "INVARIANTS:", "DEFERRED FINDINGS:", "END INVARIANTS", "END DEFERRED FINDINGS",
    "===BEGIN INVARIANTS DATA===", "===END INVARIANTS DATA===",
    "===BEGIN ADVERSARIAL FINDINGS DATA===", "===END ADVERSARIAL FINDINGS DATA===",
    "===BEGIN CHANGE-CLASS HINT DATA===", "===END CHANGE-CLASS HINT DATA===",
    "===BEGIN DEFERRED FINDINGS DATA===", "===END DEFERRED FINDINGS DATA===",
    "===BEGIN DETERMINISTIC GATES DATA===", "===END DETERMINISTIC GATES DATA===",
    "===BEGIN REVIEW FINDINGS DATA===", "===END REVIEW FINDINGS DATA===",
    "===BEGIN ADVERSARIAL REPORT DATA===", "===END ADVERSARIAL REPORT DATA===",
    "===BEGIN CODE VERDICT DATA===", "===END CODE VERDICT DATA===",
)
_FENCE_PATTERNS = [re.compile(re.escape(label), re.IGNORECASE) for label in _FENCE_LABELS]
# Characters that never belong in text a person or a model reads as a finding:
# C0 controls, DEL, the C1 block (U+009B is a one-byte CSI on some terminals)
# and the bidirectional overrides and isolates that reorder what a reader sees.
# The one definition both text sanitizers below derive from.
_C1_AND_BIDI = ("\x7f-\x9f" + chr(0x202A) + "-" + chr(0x202E) + chr(0x2066) + "-" + chr(0x2069))
# Prompt text keeps tab and newline; terminal text keeps neither.
UNSAFE_RE = re.compile("[\x00-\x08\x0b-\x1f" + _C1_AND_BIDI + "]")
_CONTROL_RE = re.compile("[\x00-\x1f" + _C1_AND_BIDI + "]")
_CSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)")
_ESC_RE = re.compile(r"\x1b.")


def sanitize_text(text, limit=None):
    """Neutralize text before it is written to a file or interpolated into a
    prompt a later model reads: strip terminal escapes, control bytes, C1
    controls and bidirectional overrides (tab and newline stay), defang every
    fence label, cap the length."""
    if limit is None:
        limit = max_field_chars()
    text = _CSI_RE.sub("", text)
    text = _OSC_RE.sub("", text)
    text = _ESC_RE.sub("", text)
    text = UNSAFE_RE.sub("", text)
    for pattern in _FENCE_PATTERNS:
        text = pattern.sub(lambda m: " ".join(m.group(0)), text)
    if len(text) > limit:
        text = text[:max(limit - len(TRUNCATION_SUFFIX), 0)] + TRUNCATION_SUFFIX
    return text


def terminal_text(value, limit=None):
    """Model-authored text made safe to print on a terminal: every control
    byte (escape sequences, newlines that could forge a second finding line),
    C1 control and bidirectional override becomes a space. The one helper every
    renderer uses for such text."""
    text = _CONTROL_RE.sub(" ", "" if value is None else str(value))
    return text if limit is None else text[:limit]


def shell_value(text):
    """Trailing newlines are not part of a value the shell gates ever carried
    (command substitution strips them); keep that so output is unchanged."""
    return text.rstrip("\n")


def _parse_field_specs(fields):
    specs = {}
    for field in fields:
        if field.endswith(":number"):
            specs[field[:-len(":number")]] = "number"
        else:
            specs[field] = "string"
    return specs


def allowlist_fields(array, fields):
    """Reduce every object to the named fields, dropping every other key and
    every value of the wrong declared type. 'name:number' declares a number;
    a bare name declares a string. Booleans never pass as numbers."""
    if not fields:
        raise ValueError("empty field list")
    if not isinstance(array, list):
        raise ValueError("not an array")
    specs = _parse_field_specs(fields)
    reduced = []
    for item in array:
        if not isinstance(item, dict):
            reduced.append({})
            continue
        kept = {}
        for key, value in item.items():
            kind = specs.get(key)
            if kind is None or isinstance(value, bool):
                continue
            if kind == "string" and isinstance(value, str):
                kept[key] = value
            elif kind == "number" and isinstance(value, (int, float)):
                kept[key] = value
        reduced.append(kept)
    return reduced


def sanitize_fields_strict(array, fields):
    """Run sanitize_text over each named string field of every object. Fails
    closed: a non-array, a non-object element or an empty field list raises,
    so a caller can never mistake a failure for 'sanitized' or 'no entries'.
    Fields not named pass through untouched, so a caller whose field set an
    attacker can influence must allowlist first."""
    if not fields:
        raise ValueError("empty field list")
    if not isinstance(array, list):
        raise ValueError("not an array")
    cleaned = []
    for item in array:
        if not isinstance(item, dict):
            raise ValueError("array element is not an object")
        item = dict(item)
        for field in fields:
            value = item.get(field, "")
            raw = shell_value(value if isinstance(value, str) else "")
            clean = shell_value(sanitize_text(raw))
            if field in item:
                item[field] = clean
        cleaned.append(item)
    return cleaned


def sanitize_tree(value, limit=1000):
    """Every string in a JSON value, object keys included, sanitized for a
    prompt. A key reaches the prompt exactly as a value does, so it gets the
    same treatment."""
    if isinstance(value, str):
        return sanitize_text(value, limit)
    if isinstance(value, list):
        return [sanitize_tree(v, limit) for v in value]
    if isinstance(value, dict):
        return {sanitize_text(str(k), limit): sanitize_tree(v, limit) for k, v in value.items()}
    return value
