"""Bounded lexical scanning of Received trace fields (RFC 5321/5322)."""

import re

from mailparser.const import _SENDGRID_DATE_RE
from mailparser.exceptions import MailParserReceivedParsingError

_KEYWORD = re.compile(
    r"(from|by|via|with|id|for|envelope-from|envelope-sender)"
    r"(?=[ \t\r\n])",
    re.I,
)
_FWS = " \t\r\n"


def helo_argument_spans(value, groups):
    """Return sender-controlled HELO tails within ordered comment spans.

    Args:
        value (str): the from clause, excluding its keyword.
        groups (list): structural spans from the trace scanner.

    Returns:
        list: ordered (start, end) exclusions, at most one per comment.

    A comment's first token can be a hostname literally named ``helo``
    followed by an MTA address group. Preserve that layout, while an
    equals sign explicitly marks an argument even when it is a literal.
    Neither a top-level hostname nor a domain literal introduces a marker.
    """
    spans = []
    for start, end in groups:
        if value[start - 1] != "(":
            continue
        initial = True
        escaped = False
        for index in range(start, end):
            char = value[index]
            if escaped:
                escaped = False
                initial = False
                continue
            if char == "\\":
                escaped = True
                initial = False
                continue
            if char == "(":
                initial = True
                continue
            if char in _FWS:
                continue
            first_token = initial
            initial = False
            if index > start and value[index - 1] not in _FWS + "(":
                continue
            width = 5 if value[index : index + 5].lower() == "ehelo" else 4
            if value[index : index + width].lower() not in ("helo", "ehelo"):
                continue
            argument = index + width
            if argument >= end or value[argument] not in _FWS + "=":
                continue
            while argument < end and value[argument] in _FWS:
                argument += 1
            explicit = argument < end and value[argument] == "="
            if explicit:
                argument += 1
                while argument < end and value[argument] in _FWS:
                    argument += 1
            if not explicit and (
                argument == end or (first_token and value[argument] in "([")
            ):
                continue
            spans.append((index, end))
            break
    return spans


def _clause_value(value):
    """Collapse formatting whitespace without rewriting quoted strings."""
    output = []
    quoted = False
    escaped = False
    whitespace = False
    for char in value.strip(_FWS):
        if char in _FWS and not quoted:
            whitespace = True
            continue
        if whitespace:
            output.append(" ")
            whitespace = False
        output.append(char)
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
    return "".join(output)


def split_received(value, *, defects=None, groups=None):
    """Split top-level clauses and date while preserving nested evidence.

    Args:
        value (str): complete raw Received field body.
        defects (list): optional destination for recovery reasons.
        groups (list): optional destination for comment/literal spans.

    Returns:
        tuple: ordered (keyword, value) pairs and a date string or None.

    Raises:
        MailParserReceivedParsingError: unbalanced lexical delimiters make
            the interpretation ambiguous. The message is a stable reason.

    Comments nest; quoted pairs are meaningful inside comments, quoted
    strings and domain literals. Neither clauses nor the stamp separator
    can begin inside those constructs or an angle address. Scanning is
    iterative and linear, including adversarial depth and whitespace.
    """
    boundaries = []
    comment = 0
    quote = False
    literal = False
    angle = False
    escaped = False
    separators = []
    group_start = 0
    sendgrid = None
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if comment:
            if char == "\\":
                escaped = True
            elif char == "(":
                comment += 1
            elif char == ")":
                comment -= 1
                if not comment and groups is not None:
                    groups.append((group_start, index))
            continue
        if quote or literal:
            if char == "\\":
                escaped = True
            elif quote and char == '"':
                quote = False
            elif literal and char == "]":
                literal = False
                if groups is not None:
                    groups.append((group_start, index))
            continue
        if char == "(":
            comment = 1
            group_start = index + 1
        elif char == ")":
            raise MailParserReceivedParsingError("unexpected-comment-close")
        elif char == '"':
            quote = True
        elif char == "[":
            literal = True
            group_start = index + 1
        elif char == "<":
            if angle:
                raise MailParserReceivedParsingError("nested-angle-address")
            angle = True
        elif char == ">":
            angle = False
        elif not angle:
            if char == ";":
                separators.append(index)
            elif not separators and (index == 0 or value[index - 1] in _FWS + ")"):
                match = _KEYWORD.match(value, index)
                if match:
                    keyword = match.group(1).lower()
                    end = match.end()
                    while end < len(value) and value[end] in _FWS:
                        end += 1
                    # Retain the established MTA TLS annotation exception.
                    if keyword != "with" or not value[end : end + 6].lower().startswith(
                        "cipher"
                    ):
                        boundaries.append((index, match.end(), keyword))
                elif char.isdigit() and sendgrid is None:
                    sendgrid = _SENDGRID_DATE_RE.match(value, index)

    if (comment or literal) and groups is not None:
        groups.append((group_start, len(value)))
    for unclosed, reason in (
        (comment, "unclosed-comment"),
        (quote, "unclosed-quoted-string"),
        (literal, "unclosed-domain-literal"),
        (angle, "unclosed-angle-address"),
    ):
        if unclosed:
            raise MailParserReceivedParsingError(reason)

    end = len(value)
    date = None
    extra_clause = None
    if separators:
        end = separators[0]
        date = value[end + 1 :].strip(_FWS)
        if len(separators) > 1:
            # A known MTA emits "id token; for <recipient>; date".
            # Recover only that shape, using already-scanned top-level
            # separators. Never use split(';') inside quoted recipients
            # or date comments, and retain the malformed raw evidence.
            middle = value[end + 1 : separators[1]].strip(_FWS)
            parts = middle.split(None, 1)
            if len(separators) != 2 or len(parts) != 2:
                raise MailParserReceivedParsingError("ambiguous-date-separators")
            if (
                not boundaries
                or boundaries[-1][2] != "id"
                or parts[0].lower() != "for"
                or not parts[1].startswith("<")
                or not parts[1].endswith(">")
            ):
                raise MailParserReceivedParsingError("ambiguous-date-separators")
            extra_clause = ("for", _clause_value(parts[1]))
            date = value[separators[1] + 1 :].strip(_FWS)
            if defects is not None:
                defects.append(
                    {
                        "reason": "misplaced-date-separator",
                        "recovered": True,
                    }
                )
    elif sendgrid is not None:
        end = sendgrid.start()
        date = sendgrid.group(1)
        boundaries = [item for item in boundaries if item[0] < end]

    clauses = []
    for position, (_, start, keyword) in enumerate(boundaries):
        stop = boundaries[position + 1][0] if position + 1 < len(boundaries) else end
        clauses.append((keyword, _clause_value(value[start:stop])))
    if extra_clause is not None:
        clauses.append(extra_clause)
    return clauses, date
