"""Exceptions the stages raise to tell their caller why they stopped."""

KEYS_FAILED = 10
SPLICE_FAILED = 11


class StageFailure(Exception):
    """A stage step failed in a way the shell caller words differently; CODE
    is the exit status that tells it which."""

    def __init__(self, code):
        Exception.__init__(self, "stage failed with %d" % code)
        self.code = code


class InputRefused(Exception):
    """The input cannot be evaluated; the verdict is never computed from it."""


class StateError(Exception):
    """The accumulation state exists but cannot be trusted."""
