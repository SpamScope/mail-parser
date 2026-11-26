#!/usr/bin/env python

"""
Copyright 2016 Fedele Mantuano (https://twitter.com/fedelemantuano)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Draw the message structure of a parsed mail as text: its main headers,
its delivery path and its MIME tree.

Every value taken from the message reaches the output through
``_visible()`` and through nothing else.  The text is chosen by the sender
and is printed on an analyst's terminal: an ANSI escape in a file name can
erase the line above it, and a right-to-left override can reorder it.
"""

import re
import unicodedata
from collections import namedtuple
from functools import partial

from mailparser.const import ADDRESSES_HEADERS
from mailparser.utils import literal_text

# Parts nested deeper than this are counted, not drawn.  Nesting depth is
# chosen by the sender and each level costs three columns.
MAX_DRAWN_DEPTH = 32

_HEADER_VALUE_LIMIT = 100
_FIELD_LIMIT = 48
_LEFT_COLUMN_LIMIT = 64
_HOP_NAME_LIMIT = 36
_HOP_PROTOCOL_LIMIT = 24
# Width of an ISO 8601 UTC timestamp with offset.
_DATE_WIDTH = 25

# Headers of the MESSAGE section, in display order.
_MESSAGE_HEADERS = (
    ("from", "From"),
    ("reply-to", "Reply-To"),
    ("return-path", "Return-Path"),
    ("to", "To"),
    ("cc", "Cc"),
    ("subject", "Subject"),
    ("date", "Date"),
    ("message-id", "Message-ID"),
)
_LABEL_WIDTH = max(len(label) for _, label in _MESSAGE_HEADERS) + 1

_Style = namedtuple("_Style", "branch last pipe arrow warning ellipsis")
_UNICODE = _Style("├─ ", "└─ ", "│  ", "──▶", "⚠", "…")
_ASCII = _Style("|- ", "`- ", "|  ", "->", "!", "...")
_BLANK = "   "

# Characters a terminal or a reader does not see as themselves: controls
# (which include ANSI escapes), formatting characters (bidirectional
# overrides, zero-width joiners), line separators, odd spaces, and code
# points with no assigned or no agreed meaning.
_HIDDEN_CATEGORIES = frozenset(
    {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"}
)

# Characters of other categories that draw nothing or a blank: the rest of
# Unicode's Default_Ignorable_Code_Point (fillers, variation selectors)
# and the characters Unicode names as blanks, fillers or half-fill spaces.
# Marks that draw something are kept, so text in scripts that need them
# stays readable.
_INVISIBLE = frozenset(
    chr(code)
    for first, last in (
        (0x034F, 0x034F),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x2800, 0x2800),
        (0x303F, 0x303F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFFA0, 0xFFA0),
        (0x13441, 0x13442),
        (0x16FE4, 0x16FE4),
        (0x1D159, 0x1D159),
        (0xE0100, 0xE01EF),
    )
    for code in range(first, last + 1)
)

# RFC 5322 section 2.2.3: a line break before white space is a fold, not
# content.  A tab is then ordinary white space.
_FOLD = re.compile(r"\r?\n(?=[ \t])")

_LARGER_SIZE_UNITS = ("MB", "GB")
_DELAY_UNITS = ((86400, "d"), (3600, "h"), (60, "m"), (1, "s"))


def _escape(char):
    """Return the visible escape of one character."""
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def _visible(value, limit=_FIELD_LIMIT, *, ascii_only, ellipsis):
    """Make message text safe and bounded for display.

    Hidden characters become visible escapes and a backslash is doubled,
    so an escape in the output is never ambiguous.  Only a prefix sized
    by ``limit`` is examined: the cost does not grow with the length of
    a value the sender chose.

    Args:
        value: text taken from the message
        limit (int): maximum number of columns kept
        ascii_only (bool): also escape every non-ASCII character
        ellipsis (str): mark appended to a value that was cut

    Returns:
        str: printable text of at most ``limit`` columns plus the mark
    """
    pieces = []
    length = 0
    # A column consumes at most three characters (a fold and its white
    # space), so this prefix is enough to fill the limit and overflow it.
    prefix = str(value)[: 3 * (limit + 1)]
    for char in _FOLD.sub("", prefix).replace("\t", " "):
        if char == "\\":
            piece = "\\\\"
        elif " " <= char <= "~":
            piece = char
        elif (
            ascii_only
            or char in _INVISIBLE
            or unicodedata.category(char) in _HIDDEN_CATEGORIES
        ):
            piece = _escape(char)
        else:
            piece = char
        if length + len(piece) > limit:
            pieces.append(ellipsis)
            break
        pieces.append(piece)
        length += len(piece)
    return "".join(pieces)


def _size(octets):
    """Return a size in octets as a short human-readable string."""
    if octets < 1024:
        return f"{octets} B"
    value, unit = octets / 1024, "KB"
    for larger_unit in _LARGER_SIZE_UNITS:
        if value < 1024:
            break
        value, unit = value / 1024, larger_unit
    return f"{value:.1f} {unit}" if value < 10 else f"{value:.0f} {unit}"


def _delay(seconds):
    """Return a delay in seconds as its two largest units, signed."""
    remaining = int(abs(seconds))
    pieces = []
    for unit_seconds, unit in _DELAY_UNITS:
        count, remaining = divmod(remaining, unit_seconds)
        if count:
            pieces.append(f"{count}{unit}")
    sign = "-" if seconds < 0 else "+"
    return sign + (" ".join(pieces[:2]) or "0s")


def _literal_address_headers(mail):
    """Return the literal occurrences of the address headers shown.

    Read from the raw header list: the decoded view of the email package
    replaces octets it cannot decode.

    Returns:
        dict: lowercase header name to its literal values, in wire order
    """
    wanted = ADDRESSES_HEADERS.intersection(
        name for name, _ in _MESSAGE_HEADERS
    )
    found = {}
    for name, raw in mail.message.raw_items() if mail.message else ():
        header = name.lower()
        if header in wanted:
            found.setdefault(header, []).append(literal_text(raw))
    return found


def _message_lines(mail, show):
    """Return the lines of the MESSAGE section."""
    headers = {name.lower(): value for name, value in mail.headers.items()}
    literal = _literal_address_headers(mail)
    lines = []
    for name, label in _MESSAGE_HEADERS:
        if name not in headers:
            continue
        value = headers[name]
        note = ""
        if name not in ADDRESSES_HEADERS:
            # A repeated header is a list: show every occurrence.
            values = value if isinstance(value, list) else [value]
        else:
            # The mailboxes selected from the first occurrence.  A header
            # that yielded none, or that occurs again, must not vanish
            # from the drawing: both are evidence.
            occurrences = literal[name]
            if value:
                values = [
                    ", ".join(
                        f"{display} <{address}>" if display else address
                        for display, address in value
                    )
                ]
            else:
                values = [occurrences[0]]
                note = "  (no mailbox selected)"
            if len(occurrences) > 1:
                note += f"  (+{len(occurrences) - 1} more occurrences)"
        for item in values:
            text = show(item, _HEADER_VALUE_LIMIT)
            lines.append(f"  {label + ':':<{_LABEL_WIDTH}}  {text}{note}")
    if mail.defects_categories:
        categories = ", ".join(sorted(mail.defects_categories))
        lines.append(f"  {'Defects:':<{_LABEL_WIDTH}}  {categories}")
    return lines or ["  (no headers)"]


def _delivery_lines(mail, show, style):
    """Return the lines of the DELIVERY PATH section."""
    hops = mail.received
    if not hops:
        return ["  (no Received headers)"]

    # Defects name a trace header by its position on the wire, last hop
    # first; hops are numbered first hop first.
    flagged = {defect["occurrence"] for defect in mail.received_header_defects}
    flagged.update(
        defect["occurrence"]
        for defect in mail.date_header_defects
        if defect["header"] == "received"
    )
    names = {
        hop["hop"]: (
            show(hop.get("from", "?"), _HOP_NAME_LIMIT),
            show(hop.get("by", "?"), _HOP_NAME_LIMIT),
        )
        for hop in hops
        if "from" in hop or "by" in hop
    }
    number_width = len(str(len(hops)))
    from_width = max((len(sender) for sender, _ in names.values()), default=0)
    by_width = max(
        (len(receiver) for _, receiver in names.values()), default=0
    )

    lines = []
    for hop in hops:
        if hop["hop"] > 1:
            delay = _delay(hop.get("delay", 0))
            lines.append(f"  {style.pipe.strip():<{number_width}}  {delay}")
        pieces = [
            f"  {hop['hop']:<{number_width}}",
            f"{show(hop.get('date_utc') or '-'):<{_DATE_WIDTH}}",
        ]
        if "raw" in hop:
            # A trace header the parser could not split into clauses.
            # That alone is not a defect (RFC 5322 section 4.5.7).
            pieces.append(f"unparsed: {show(hop['raw'], _HEADER_VALUE_LIMIT)}")
        elif hop["hop"] in names:
            sender, receiver = names[hop["hop"]]
            pieces.append(
                f"{sender:<{from_width}} {style.arrow} {receiver:<{by_width}}"
            )
            if hop.get("with"):
                pieces.append(show(hop["with"], _HOP_PROTOCOL_LIMIT))
        else:
            pieces.append("(no from or by clause)")
        if len(hops) - hop["hop"] in flagged:
            pieces.append(style.warning)
        lines.append("  ".join(pieces).rstrip())
    return lines


def _node_summary(node, show):
    """Return the attributes shown beside a part's index and type."""
    pieces = [
        show(node[key])
        for key in ("content_transfer_encoding", "charset")
        if node[key]
    ]
    if node["size"] is not None:
        pieces.append(_size(node["size"]))
    pieces.append(f"[{'+'.join(node['roles']) or 'none'}]")
    if node["content_disposition"]:
        pieces.append(f"disposition:{show(node['content_disposition'])}")
    if node["filename"]:
        pieces.append(f'"{show(node["filename"])}"')
    return "  ".join(pieces)


def _node_details(node, show, style):
    """Return the lines drawn under a part."""
    details = []
    if node["defects"]:
        details.append(f"{style.warning} {', '.join(node['defects'])}")
    raw = node["content_type_raw"]
    if raw is None:
        details.append("no Content-Type header")
    elif raw.split(";")[0].strip().lower() != node["content_type"]:
        details.append(f"declared Content-Type: {show(raw)}")
    if node["embedded_headers"]:
        details.append("embedded message")
        details.extend(
            f"{name.capitalize()}: {show(value)}"
            for name, value in node["embedded_headers"].items()
            if value
        )
    if node["recovered"]:
        details.append("recovered from epilogue")
    return details


def _tree_lines(tree, show, style):
    """Return the lines of the MIME TREE section.

    The tree is a flat list in wire order, so one pass draws it: no
    recursion, whatever nesting the sender chose.
    """
    if not tree:
        return ["  (no parts)"]

    last_child = {node["parent"]: node["index"] for node in tree}
    deepest = max(node["depth"] for node in tree)
    # open_levels[d] tells whether the ancestor at depth d has siblings
    # still to come, i.e. whether its vertical line continues.
    open_levels = []
    rows = []
    skipped = 0

    def flush_skipped():
        nonlocal skipped
        if skipped:
            indent = "".join(
                style.pipe if is_open else _BLANK
                for is_open in open_levels[1 : MAX_DRAWN_DEPTH + 1]
            )
            rows.append(
                (
                    f"{indent}{style.ellipsis} {skipped} deeper parts not "
                    f"drawn (deepest level {deepest})",
                    "",
                )
            )
            skipped = 0

    for node in tree:
        depth = node["depth"]
        if depth > MAX_DRAWN_DEPTH:
            skipped += 1
            continue
        flush_skipped()
        is_last = last_child[node["parent"]] == node["index"]
        del open_levels[depth:]
        open_levels.append(not is_last)
        indent = "".join(
            style.pipe if is_open else _BLANK
            for is_open in open_levels[1:depth]
        )
        connector = (
            "" if depth == 0 else (style.last if is_last else style.branch)
        )
        left = (
            f"{indent}{connector}{node['index']} {show(node['content_type'])}"
        )
        rows.append((left, _node_summary(node, show)))

        below = indent
        if depth:
            below += _BLANK if is_last else style.pipe
        below += style.pipe if node["index"] in last_child else _BLANK
        rows.extend(
            (f"{below}{detail}", "")
            for detail in _node_details(node, show, style)
        )
    flush_skipped()

    width = min(
        max(len(left) for left, summary in rows if summary),
        _LEFT_COLUMN_LIMIT,
    )
    return [
        f"  {left:<{width}}  {summary}" if summary else f"  {left}"
        for left, summary in rows
    ]


def render_structure(mail, ascii_only=False):
    """Draw the message structure of a parsed mail as text.

    The drawing has three sections: the main headers, the delivery path
    (one line per hop, first hop first) and the MIME tree (one line per
    part, indented under its enclosing part).  A warning mark means a
    defect the parser recorded, never a judgement on the message.

    Text taken from the message is escaped and cut, so the result is safe
    to print on a terminal.  It is a view for people: read ``mime_tree``,
    ``received`` and ``headers`` for the complete values.

    Args:
        mail (MailParser): a parsed mail
        ascii_only (bool): use ASCII connectors and escape every
            non-ASCII character

    Returns:
        str: the drawing, without a trailing newline
    """
    style = _ASCII if ascii_only else _UNICODE
    show = partial(_visible, ascii_only=ascii_only, ellipsis=style.ellipsis)
    return "\n".join(
        [
            "MESSAGE",
            *_message_lines(mail, show),
            "",
            "DELIVERY PATH",
            *_delivery_lines(mail, show, style),
            "",
            "MIME TREE",
            *_tree_lines(mail.mime_tree, show, style),
        ]
    )
