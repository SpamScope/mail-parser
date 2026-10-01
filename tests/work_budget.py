"""Deterministic work counters for adversarial parsing regressions.

Count text traversals, copied slices and collision probes, not elapsed time.
These guards cover the instrumented operations; they are not a benchmark or
an estimate of work inside the regex engine. Real parsing is always executed.
"""

from contextlib import ExitStack, contextmanager
from functools import wraps
from unittest.mock import patch


class WorkBudget:
    """Raise AssertionError when counted work exceeds the supplied limit."""

    def __init__(self, limit):
        self.limit = limit
        self.used = 0

    def spend(self, amount=1):
        """Charge amount units, failing before excessive work continues."""
        self.used += amount
        assert self.used <= self.limit, (
            f"work budget exceeded: {self.used} > {self.limit}"
        )


class CountedText(str):
    """Count Python character visits and slices against a shared budget."""

    budget: WorkBudget

    def __new__(cls, value, budget):
        result = super().__new__(cls, value)
        result.budget = budget
        return result

    def __iter__(self):
        for char in super().__iter__():
            self.budget.spend()
            yield char

    def __getitem__(self, key):
        result = super().__getitem__(key)
        self.budget.spend(max(1, len(result)))
        return CountedText(result, self.budget)


@contextmanager
def bounded_text_work(module, names, size, factor=64):
    """Bound input volume and Python scanning at named text functions.

    Each wrapped function receives its real input as a str subclass. The
    shared limit permits a constant number of passes over size characters.
    Native string/regex internals are not counted by this helper.
    """
    budget = WorkBudget(factor * size)

    def instrument(function):
        @wraps(function)
        def counted(value, *args, **kwargs):
            budget.spend(max(1, len(value)))
            return function(CountedText(value, budget), *args, **kwargs)

        return counted

    with ExitStack() as stack:
        for name in names:
            stack.enter_context(
                patch.object(module, name, instrument(getattr(module, name)))
            )
        yield budget
    assert budget.used, "instrumented parsing path was not exercised"


@contextmanager
def bounded_address_work(size):
    """Bound address scans and repeated candidate/display-name processing."""
    from mailparser import addresses

    names = ("_scan", "_name", "_mailbox", "_valid_phrase", "_display_source")
    with bounded_text_work(addresses, names, size) as budget:
        yield budget


@contextmanager
def bounded_encoded_word_work(count, size):
    """Bound match attempts and bytes passed to the real word decoder."""
    from mailparser import addresses

    attempts = WorkBudget(4 * count + 8)
    pattern = addresses._ENCODED_WORD

    class CountedPattern:
        def match(self, *args, **kwargs):
            attempts.spend()
            return pattern.match(*args, **kwargs)

    decoded = WorkBudget(4 * size)
    decode = addresses.decode_header

    def counted_decode(value):
        decoded.spend(len(value))
        return decode(value)

    with patch.object(addresses, "_ENCODED_WORD", CountedPattern()):
        with patch.object(addresses, "decode_header", counted_decode):
            yield attempts, decoded
    assert attempts.used, "encoded-word matcher was not exercised"


class CountedNames(dict):
    """Count collision probes in an attachment batch of the supplied size."""

    def __init__(self, count):
        super().__init__()
        self.budget = WorkBudget(4 * count)

    def __contains__(self, key):
        self.budget.spend()
        return super().__contains__(key)
