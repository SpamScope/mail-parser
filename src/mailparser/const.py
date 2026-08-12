#!/usr/bin/env python

"""
Copyright 2018 Fedele Mantuano (https://twitter.com/fedelemantuano)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re

# IPv4 pattern - validates octet range (0-255) per RFC 791
REGXIP = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)

# IPv6 pattern - matches standard and common compressed forms per RFC 5952
# Alternation order matters: Python's ``re`` takes the first alternative
# that matches, not the longest.  The "trailing ::" branch therefore has to
# come *after* every branch that continues past the ``::`` — with it listed
# early, ``2a00:1450:4864:20::32`` matched only as ``2a00:1450:4864:20::``,
# reporting a different, valid, routable address as the sender.
REGXIP6 = re.compile(
    r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"  # full form
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"  # 6 groups after ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"  # 1 group after ::
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"  # ::x:x...
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"  # trailing ::
    r"|::)"  # just ::
)

# Normalize whitespace: collapse tabs and newlines to single space.
# Parenthesized comments and bracketed IPs are preserved.
JUNK_PATTERN = r"[\t\n]+"

# ------------------------------------------------------------------ #
# Received header parsing — RFC 5321 §4.4 grammar:
#
#   Received     = "Received:" *( received-token / comment ) ";" date-time
#   received-token = "from" domain / "by" domain / "via" atom
#                  / "with" atom  / "id"  atom   / "for" addr-spec
#
# Strategy: tokenize on clause keywords, then extract values per clause.
# This eliminates the duplicated boundary lookaheads of the old
# per-clause pattern list and matches the RFC grammar directly.
# ------------------------------------------------------------------ #

# Pattern that splits a received header into clause tokens.
# Matches each RFC 5321 keyword at a word boundary followed by its value,
# which extends up to the next keyword or semicolon.
# The keywords are: from, by, via, with (not "with cipher"), id, for,
# plus the non-standard envelope-from and envelope-sender.
_CLAUSE_SPLITTER = re.compile(
    r"(?:^|\s+)"
    r"(from|by|via|with(?!\s+cipher)|id|for|envelope-from|envelope-sender)"
    r"\s+",
    re.I,
)

# Collapses any run of whitespace to a single space.  Applied to a received
# header before ``_CLAUSE_SPLITTER`` so the splitter's ``\s+`` sub-patterns
# only ever match a single character.  Without it a long run of spaces with no
# following clause keyword drives the split into quadratic backtracking — an
# ordinary parse of an attacker-supplied Received header becomes a denial of
# service (CWE-1333).  Note the ``[\t\n]``-only normalization elsewhere does
# not collapse spaces, so this guard must live at the point of use.
_WS_RUN_RE = re.compile(r"\s+")

# Matches the HELO/EHLO name an MTA records inside the ``from`` clause,
# in the two shapes seen in the wild:
#   from evil.example ([203.0.113.9]:45321 helo=[8.8.8.8]) by ...   (Exim)
#   from [203.0.113.9] (account x@y HELO 8.8.8.8) by ...      (CommuniGate)
# The HELO argument is chosen by the sender and may be an RFC 5321 address
# literal, so it must be removed before scanning the clause for the sender
# IP — otherwise the sender simply appends the IP they want reported.
# Used to locate the span, never to delete it: the trailing \S+ would
# otherwise swallow whatever follows, and a sender whose rDNS or HELO is
# literally ``helo`` can place that word right before the MTA-written IP.
# Two guards keep the span off MTA-written text.  The lookbehind: the
# clause value *starts* with the HELO name, so at offset 0 the word is the
# name itself, not a label introducing one.  The ``(?![\[(])`` on the
# space-separated form: an MTA writes its own address inside brackets or
# parentheses, so a following group is never part of the HELO argument.
# Exim's ``helo=[8.8.8.8]`` is a genuine bracketed HELO argument and keeps
# no such guard.
_HELO_RE = re.compile(
    r"(?<=[(\s])e?helo\s*=\S*"  # Exim "helo=value": after "(" or space
    r"|(?<=\s)e?helo\s+\S+",  # space form: only after whitespace
    re.I,
)

# RFC 5321 §4.1.3 tags an IPv6 literal as ``[IPv6:2a00:...]``.  REGXIP6
# happily starts matching at the ``6`` of the tag and yields
# ``6:2a00:1450:4864:20::`` — a different, valid, routable address that an
# analyst would then act on.  Blank the tag before scanning.
_IPV6_TAG_RE = re.compile(r"IPv6:", re.I)

# Extracts envelope-from email: envelope-from <addr>
_ENVELOPE_FROM_RE = re.compile(r"<([^>]+)>")

# Date after semicolon (standard RFC 5321)
_DATE_RE = re.compile(r";\s*(.*)", re.DOTALL)

# SendGrid non-standard date format (no semicolon)
_SENDGRID_DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{9}\s+\+0000\s+UTC)"
    r"\s+m=\+\d+\.\d+",
    re.I,
)

EPILOGUE_DEFECTS = {"StartBoundaryNotFoundDefect"}

ADDRESSES_HEADERS = set(["bcc", "cc", "delivered-to", "from", "reply-to", "to"])

# These parts are always returned
OTHERS_PARTS = set(
    [
        "attachments",
        "body",
        "date",
        "message-id",
        "received",
        "subject",
        "timezone",
        "to_domains",
        "user-agent",
        "x-mailer",
        "x-original-to",
    ]
)

# Subset of OTHERS_PARTS that MailParser computes itself: each maps to a
# property, not to a header read off the wire.  ``_make_mail()`` resolves
# only these names through attribute access; every other key it handles is
# a header name chosen by the sender and goes through
# ``MailParser._header_value()``, which never touches an attribute.  Keep
# this set in sync with OTHERS_PARTS and with the properties in core.py.
#
# These names shadow a header of the same name in ``mail`` / ``mail_json``:
# a message carrying a literal ``Body:`` header reports the computed body
# there, not the header value.  The wire value is never lost — it is in
# ``headers`` / ``headers_json`` under its own name — but a consumer
# reading only ``mail_json`` will not see it.
COMPUTED_PARTS = set(
    [
        "attachments",
        "body",
        "date",
        "received",
        "timezone",
        "to_domains",
    ]
)
