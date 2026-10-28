"""Bound repeated MIME container copies without changing original evidence."""

from __future__ import annotations

from email.generator import BytesGenerator, Generator
from io import BytesIO, StringIO
from typing import Literal, overload


class SerializationLimitError(Exception):
    """An optional container representation exceeded its work budget."""


class SerializationBudget:
    """Account for source-relative container work within one parse.

    Args:
        parts: MIME parts in parent-before-child order.

    The budget covers internal generator buffers, not just final payloads.
    It does not limit input parsing, leaf payloads or the original tree.
    """

    def __init__(self, parts):
        self.weights = {}
        source_size = 0
        for part in reversed(parts):
            size = 256
            for name, value in part.raw_items():
                size += len(name) + len(str(value)) + 4
            size += len(part.preamble or "") + len(part.epilogue or "")
            payload = part._payload
            if isinstance(payload, str):
                size += len(payload)
            source_size += size
            nodes = 1
            work = size
            if isinstance(payload, list):
                for child in payload:
                    child_size, child_nodes, child_work = self.weights[child]
                    size += child_size
                    nodes += child_nodes
                    work += child_work + 2 * child_size
            self.weights[part] = (size, nodes, work)
        self.characters = max(1024 * 1024, min(32 * source_size, 32 * 1024**2))
        self.nodes = max(1024, min(16 * len(parts), 100_000))

    def check(self, part):
        """Reject an expensive subtree before generating any copies.

        Raises:
            SerializationLimitError: if estimated work does not fit.
        """
        _, nodes, work = self.weights[part]
        if nodes > self.nodes or work > self.characters:
            raise SerializationLimitError("container preflight budget")

    def spend(self, characters=0, nodes=0):
        """Debit actual buffer writes and visits before they occur.

        Raises:
            SerializationLimitError: if the work does not fit.
        """
        if characters > self.characters or nodes > self.nodes:
            raise SerializationLimitError("container serialization budget")
        self.characters -= characters
        self.nodes -= nodes


class _TextBuffer(StringIO):
    def __init__(self, budget):
        self.budget = budget
        super().__init__()

    def write(self, data):
        self.budget.spend(characters=len(data))
        return super().write(data)


class _BytesBuffer(BytesIO):
    def __init__(self, budget):
        self.budget = budget
        super().__init__()

    def write(self, data):
        self.budget.spend(characters=len(data))
        return super().write(data)


class _BudgetGenerator(Generator):
    _fp: _TextBuffer | _BytesBuffer

    # Both generator families and every clone use budgeted output streams.
    def flatten(self, msg, unixfrom=False, linesep=None):
        self._fp.budget.spend(nodes=1)
        return super().flatten(msg, unixfrom=unixfrom, linesep=linesep)

    def _new_buffer(self):
        return type(self._fp)(self._fp.budget)


class _BytesGenerator(_BudgetGenerator, BytesGenerator):
    pass


@overload
def bounded_flatten(
    part,
    budget,
    *,
    binary: Literal[False] = False,
) -> str: ...


@overload
def bounded_flatten(part, budget, *, binary: Literal[True]) -> bytes: ...


def bounded_flatten(part, budget, *, binary=False):
    """Flatten with a shared budget on all nested generator buffers.

    Args:
        part: MIME part to serialize.
        budget: per-parse serialization budget.
        binary: use the byte-preserving generator fallback.

    Returns:
        The complete string or bytes generated for the part.

    Raises:
        SerializationLimitError: if generation would exceed the budget.
        LookupError: if the declared charset is unknown or not textual.
        UnicodeError: if the declared charset cannot encode the payload.
    """
    if binary:
        stream = _BytesBuffer(budget)
        generator = _BytesGenerator(stream, mangle_from_=False)
    else:
        stream = _TextBuffer(budget)
        generator = _BudgetGenerator(
            stream,
            mangle_from_=False,
            maxheaderlen=0,
        )
    generator.flatten(part)
    return stream.getvalue()
