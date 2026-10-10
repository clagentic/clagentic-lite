"""Calendar dates: parsing the dates the policy files carry, and today's date
with a reproducible override."""
import datetime
import os
import re

from .errors import InputRefused

_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[T ].*)?$")


def parse_date(value):
    """The calendar date a string starts with (YYYY-MM-DD, optionally followed
    by a time), or None."""
    if not isinstance(value, str):
        return None
    match = _DATE_RE.match(value.strip())
    if not match:
        return None
    try:
        return datetime.date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def today_date(override=None):
    """Today, from OVERRIDE or CLAGENTIC_FINDINGS_TODAY when given (tests and
    reproducible runs), else the local date. An override that is not a date is
    refused rather than ignored."""
    text = override or os.environ.get("CLAGENTIC_FINDINGS_TODAY", "")
    if not text:
        return datetime.date.today()
    parsed = parse_date(text)
    if parsed is None:
        raise InputRefused("the date override %r is not YYYY-MM-DD" % text)
    return parsed
