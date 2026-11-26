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
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import email
import email.errors
import email.header
import email.message
import email.utils
import functools
import hashlib
import inspect
import json
import logging
import os
import random
import re
import string
import subprocess
import sys
import tempfile
import traceback
from collections import Counter, namedtuple
from email.errors import HeaderParseError, MessageError
from email.generator import Generator
from email.header import decode_header
from email.message import Message
from email.policy import Compat32
from unicodedata import normalize

from mailparser.addresses import parse_address_header
from mailparser.const import (
    _ENCODED_WORD_RE,
    ADDRESSES_HEADERS,
    OTHERS_PARTS,
)
from mailparser.dates import date_diagnostics, parse_mail_date
from mailparser.exceptions import (
    MailParserError,
    MailParserOSError,
    MailParserOutlookError,
    MailParserPathError,
    MailParserReceivedParsingError,
    MailParserRecursionError,
)
from mailparser.received import extract_envelope_address, split_received
from mailparser.serialization import bounded_flatten

log = logging.getLogger(__name__)

# Upper bound (seconds) for the external ``msgconvert`` conversion.  Without it
# a hung or malicious helper would block the calling worker indefinitely.
_MSGCONVERT_TIMEOUT = 60

# What a codec named by the sender raises when it cannot be applied: an
# unknown or non-text codec, an octet it refuses, a NUL in its name.
_CHARSET_ERRORS = (LookupError, UnicodeError, ValueError)
# What a generator raises for a part it cannot write: a charset that
# refuses the octets, or a header it will not fold. ``Header.encode()``
# takes a form feed for a line break, which the feed parser does not.
_FLATTEN_ERRORS = (*_CHARSET_ERRORS, MessageError)
# The two a header is refused with. ``HeaderWriteError`` came with the
# fix of CVE-2024-6923, which a release may lack.
_HEADER_ERRORS = (
    HeaderParseError,
    getattr(email.errors, "HeaderWriteError", HeaderParseError),
)

# The code of the call that flattens one part: the generator runs it for
# the message and, nested, for every sub-part.  ``msg`` is its part and
# ``policy`` the policy it writes that part under.
_FLATTEN_CODE = Generator.flatten.__code__

# The headers whose parameters the parser reads.
_PARAMETER_HEADERS = ("content-type", "content-disposition")

# Header values whose decoded parameters are kept while a message is
# parsed.  A part is asked for the same two values by several accessors
# in a row, and by the email package itself.
_PARAMS_CACHE_SIZE = 8

# True while ``as_string_safe()`` runs a generator over a part.
_FLATTENING = contextvars.ContextVar("mailparser_flattening", default=False)


# The ``strict`` keyword was added to ``email.utils.getaddresses`` in Python
# 3.13 (and backported only to later security patch releases of 3.9-3.12,
# e.g. 3.11.10).  mail-parser supports Python 3.9 and later, so on
# an earlier patch release the keyword is absent and passing it raises
# ``TypeError: getaddresses() got an unexpected keyword argument 'strict'``
# (parsedmarc #808).  The signature is fixed for the running interpreter, so
# detect support once at import time.
_GETADDRESSES_SUPPORTS_STRICT = (
    "strict" in inspect.signature(email.utils.getaddresses).parameters
)


def _getaddresses(fieldvalues: list[str]) -> list[tuple[str, str]]:
    """
    Call ``email.utils.getaddresses`` with strict parsing when available.

    Args:
        fieldvalues (list[str]): raw address header values to parse.

    Returns:
        list[tuple[str, str]]: list of ``(display_name, email_addr)`` tuples,
            as returned by ``email.utils.getaddresses``.
    """
    if _GETADDRESSES_SUPPORTS_STRICT:
        return email.utils.getaddresses(fieldvalues, strict=True)
    return email.utils.getaddresses(fieldvalues)


def get_addresses(
    raw_header: str | email.header.Header | None,
    *,
    defects: list | None = None,
    decode_names: bool = False,
) -> list[tuple[str, str]]:
    """Parse mailboxes with structural recovery for forensic input.

    RFC 5322 sections 3.2, 3.4 and 4 distinguish phrases, comments and
    angle-addrs. Unquoted email-like display names are recovered only when
    a single complete angle-addr establishes the mailbox. Ambiguous items
    are retained in diagnostics rather than promoted to mailbox identities.

    Args:
        raw_header: raw header string, email Header object, or None.
        defects: optional list to receive recovery/ambiguity evidence.
        decode_names: decode display words in their lexical context. The
            default retains encoded words for existing helper callers.

    Returns:
        List of (display_name, address) tuples. An absent/empty string
        retains the stdlib empty-result convention for existing callers.
    """
    if raw_header is None:
        return []
    if isinstance(raw_header, email.header.Header):
        # Address identity must not pass through ported_string's NFC
        # normalization, decode errors="ignore", or Unicode whitespace
        # stripping. Keep invalid octets as surrogates for the scanner to
        # flag, rather than joining their neighbours into a new mailbox.
        chunks = []
        for data, charset in decode_header(raw_header.encode()):
            if isinstance(data, bytes):
                charset = charset if charset != "unknown-8bit" else "utf-8"
                try:
                    data = data.decode(charset or "utf-8", "surrogateescape")
                except (LookupError, UnicodeError):
                    data = data.decode("utf-8", "surrogateescape")
            chunks.append(data)
        raw_header = "".join(chunks)
    elif not isinstance(raw_header, str):
        raw_header = str(raw_header)
    if not raw_header.strip(" \t\r\n"):
        return _getaddresses([raw_header])
    parsed, diagnostics = parse_address_header(
        raw_header, _getaddresses, decode_names=decode_names
    )
    if defects is not None:
        defects.extend(diagnostics)
    return parsed or [("", "")]


def custom_log(level="WARNING", name=None):  # pragma: no cover
    """
    This function returns a custom logger that writes to standard error,
    so that standard output holds only what the caller asked to print.
    :param level: logging level
    :type level: str
    :param name: logger name
    :type name: str
    :return: logger
    """
    if name:
        log = logging.getLogger(name)
    else:
        log = logging.getLogger()
    log.setLevel(level)
    ch = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        "%(asctime)s | "
        "%(name)s | "
        "%(module)s | "
        "%(funcName)s | "
        "%(lineno)d | "
        "%(levelname)s | "
        "%(message)s"
    )
    ch.setFormatter(formatter)
    log.addHandler(ch)
    return log


def sanitize(func):
    """NFC is the normalization form recommended by W3C."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return normalize("NFC", func(*args, **kwargs))

    return wrapper


@sanitize
def ported_string(raw_data, encoding="utf-8", errors="ignore"):
    """
    Give as input raw data and output a str in Python 3.

    Args:
        raw_data: bytes or str to convert to str
        encoding: string giving the name of an encoding
        errors: specifies the treatment of characters
            which are invalid in the input encoding

    Returns:
        str
    """

    if not raw_data:
        return str()

    if isinstance(raw_data, email.header.Header):
        return str(raw_data)

    if isinstance(raw_data, str):
        return raw_data

    # raw_data is bytes, decode it. The "undefined" codec raises a bare
    # UnicodeError rather than UnicodeDecodeError, so catch the base class.
    try:
        return str(raw_data, encoding)
    except (LookupError, UnicodeError):
        return str(raw_data, "utf-8", errors)


def _header_text_chunks(source):
    """Decode encoded tokens without recoding their literal Unicode spans."""
    position = 0
    for match in _ENCODED_WORD_RE.finditer(source):
        literal = source[position : match.start()]
        # Only ASCII folding whitespace between encoded words disappears.
        if not position or literal.strip(" \t\r\n"):
            yield literal
        for data, charset in decode_header(match.group()):
            if isinstance(data, bytes):
                # RFC 2231 language metadata is not part of the codec name.
                encoding = (charset or "utf-8").split("*", 1)[0]
                data = data.decode(encoding)
            yield data
        position = match.end()
    yield source[position:]


def literal_text(value):
    """Return a header value as text that is safe to serialize.

    Octets the email package carries as surrogate escapes are read back as
    UTF-8.  Octets that are not valid UTF-8 stay visible as ``\\xNN``
    escapes instead of being dropped or replaced.

    Args:
        value: raw header value

    Returns:
        str: text that encodes as UTF-8
    """
    text = str(value)
    try:
        octets = text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        # A caller parsing a str can supply surrogates that are not octets.
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return octets.decode("utf-8", "backslashreplace")


def decode_header_part(header, *, defects=None):
    """
    Given a raw header returns a decoded header

    Args:
        header (string): header to decode
        defects (list): optional destination for unsafe decoded text evidence

    Returns:
        str
    """
    if not header:
        return str()

    try:
        source = header
        if isinstance(source, str):
            # BytesParser stores valid UTF-8 as surrogateescaped ASCII.
            # Reconstruct its octets before judging Unicode validity.
            source = source.encode("utf-8", "surrogateescape").decode("utf-8")
        elif isinstance(source, email.header.Header):
            source = source.encode()
        output = ported_string("".join(_header_text_chunks(source)))
        output.encode("utf-8")
    except (HeaderParseError, LookupError, UnicodeError, ValueError) as exc:
        if defects is not None:
            defects.append(
                f"invalid-encoded-word: {type(exc).__name__}; raw={header!r}"
            )
        # Return the whole literal value, never a decoded prefix plus the
        # original. Escape surrogates so JSON/CLI sinks remain usable.
        return (
            str(header)
            .encode("utf-8", "backslashreplace")
            .decode("utf-8")
            .strip()
        )
    return output.strip()


def _renumbered(pairs):
    """Give the sections of malformed parameters numbers to sort by.

    RFC 2231 section 3 numbers the sections of a continued parameter
    from 0, each number once.  A parameter is malformed, on every
    Python, when its sections come with and without a number
    (``name*`` next to ``name*1``), repeat a number, or come more than
    once without one.  ``email.utils.decode_params`` raises on the
    first before Python 3.13.18, 3.14.10 and 3.15.2, and sorts equal
    numbers by value before those versions.

    Such a parameter is read as those versions read it: its unnumbered
    sections are section 0, or are dropped when it has a section 0, and
    equal numbers keep the order of the header.  Its sections are then
    numbered again from 0, which every version sorts the same way.

    A number with more digits than ``int()`` converts belongs to no
    section: that parameter keeps its literal name.

    Args:
        pairs (list): ``(name, value)`` pairs of a parameter list.

    Returns:
        tuple: the pairs to decode and the decoded literal pairs, or
        None when no parameter of the list is malformed
    """
    section = email.utils.rfc2231_continuation  # type: ignore[attr-defined]
    decodable, literal, sections = [], [], {}
    for name, text in pairs:
        match = section.match(name) if "*" in name else None
        if not match:
            decodable.append((name, text))
            continue
        try:
            number = int(match["num"]) if match["num"] else None
        except ValueError:
            text = email.utils.quote(email.utils.unquote(text))
            literal.append((name, f'"{text}"'))
        else:
            found = sections.setdefault(match["name"], [])
            found.append((number, name, text))
    malformed = bool(literal)
    for base, found in sections.items():
        numbers = {number for number, _, _ in found}
        repeated = len(numbers) < len(found)
        mixed = None in numbers and len(numbers) > 1
        if not (repeated or mixed):
            decodable.extend((name, text) for _, name, text in found)
            continue
        malformed = True
        if 0 in numbers:
            found = [item for item in found if item[0] is not None]
        found.sort(key=lambda item: item[0] or 0)
        for number, (_, name, text) in enumerate(found):
            encoded = "*" if name.endswith("*") else ""
            decodable.append((f"{base}*{number}{encoded}", text))
    return (decodable, literal) if malformed else None


@functools.lru_cache(maxsize=_PARAMS_CACHE_SIZE)
def _read_params(value):
    """Split and decode the parameters of a header value.

    The same steps as ``Message._get_params_preserve()``, so a well
    formed list is read as the email package reads it.  A malformed
    one is repaired first by ``_renumbered()``.

    The split and the syntax of a section name are the undocumented
    ones of the email package: a second splitter would be a second
    interpretation of the neighbours of a malformed parameter.

    The cache spares the split, quadratic in some Python releases, to
    the accessors that read the same value one after the other.  It is
    no memo of a message: a value read again after eight others is
    split again, and ``MailParser`` empties the cache when a parse
    ends, so that no header of a message outlives its parser here.

    Args:
        value (str): value of a header that carries parameters.

    Returns:
        tuple: the ``(name, value)`` pairs as ``decode_params`` returns
        them, in a tuple, and whether the list is malformed
    """
    split = email.message._parseparam  # type: ignore[attr-defined]
    first, *pairs = (
        (name.strip(), text.strip())
        for name, _, text in (item.partition("=") for item in split(value))
    )
    repaired = _renumbered(pairs) if "*" in value else None
    if repaired is None:
        return tuple(email.utils.decode_params([first, *pairs])), False
    pairs, literal = repaired
    return tuple(email.utils.decode_params([first, *pairs]) + literal), True


def _decoded_boundary(part, failobj=None, *, defects=None):
    """Read a boundary whose charset may be unable to decode it.

    ``Message.get_boundary()`` decodes an RFC 2231 value with the
    charset the sender names and guards only against an unknown one,
    for which it returns the percent-decoded octets as Latin-1 text.
    The same text is returned here for a charset that refuses them.

    Args:
        part (RecoveringMessage): MIME part or metadata view.
        failobj: value returned when the part declares no boundary.
        defects: optional destination for raw parameter evidence.

    Returns:
        The boundary, or failobj.
    """
    try:
        return Message.get_boundary(part, failobj)
    except _CHARSET_ERRORS:
        value = part.get_param("boundary")
        if defects is not None:
            defects.append(f"invalid-boundary-parameter: raw={value!r}")
        return email.utils.unquote(value[2]).rstrip()


class _DeclaredEmptyBoundary(str):
    """Empty boundary that a message declares: not a missing one.

    ``Generator._handle_multipart()`` tests the boundary for truth.  A
    false one it replaces with a boundary it invents, which it writes
    into the message with ``set_boundary()``.  This one is true: the
    generator writes the delimiters the message has, ``--`` and
    ``----``, and leaves the header as it is.
    """

    def __bool__(self):
        return True


@contextlib.contextmanager
def _keeping_empty_boundaries():
    """Have the generator write an empty boundary instead of replacing it.

    The pass runs in the frame of the caller: entering and leaving
    add no stack frame to it.
    """
    token = _FLATTENING.set(True)
    try:
        yield
    finally:
        _FLATTENING.reset(token)


class RecoveringMessage(Message):
    """Message whose parameters the email package can always use.

    The email package reads parameters on its own: ``get_boundary()``
    while it parses a multipart, ``get_boundary()``, ``get_param()`` and
    ``get_payload()`` while it flattens one.  No caller can catch what
    they raise there on an RFC 2231 value, so every message the parser
    builds is of this class.  A well formed value is read as
    ``Message`` reads it, a malformed one as ``Message`` of Python
    3.13.18, 3.14.10 and 3.15.2 reads it; it is diagnosed by
    ``mime_header_view()`` and ``mime_boundary()``, never recorded on
    the message.
    """

    @classmethod
    def reading(cls, part):
        """Return a message of this class with the parameters of a part.

        Args:
            part (email.message.Message): a part of any message class.

        Returns:
            RecoveringMessage: the part itself, or for a plain message
            of the caller a copy of its headers that carry parameters
        """
        if isinstance(part, cls):
            return part
        copy = cls()
        for name, value in part.raw_items():
            if name.lower() in _PARAMETER_HEADERS:
                copy[name] = value
        return copy

    def _get_params_preserve(self, failobj, header):
        # Not public, but the one method every parameter accessor of
        # Message reads through, on every supported Python.
        missing = object()
        value = self.get(header, missing)
        if value is missing:
            return failobj
        return list(_read_params(str(value))[0])

    def get_boundary(self, failobj=None):
        """Return the boundary, also when its charset cannot decode it.

        While ``as_string_safe()`` flattens the message, an empty
        boundary is returned as a string that is true: the generator
        would otherwise replace it in the header of the part.

        Args:
            failobj: value returned when the part declares no boundary.

        Returns:
            The boundary, or failobj.
        """
        boundary = _decoded_boundary(self, failobj)
        if boundary == "" and _FLATTENING.get():
            return _DeclaredEmptyBoundary()
        return boundary

    def get_payload(self, i=None, decode=False):  # type: ignore[override]
        """Return the payload, also for an RFC 2231 charset.

        Up to Python 3.11 the text of an 8-bit payload is decoded with
        what ``get_param()`` returns, a tuple for an RFC 2231 charset:
        ``TypeError``.  Later versions use ``get_content_charset()``.

        Args:
            i: index of a sub-part.
            decode: decode the transfer encoding.

        Returns:
            The payload, as ``Message.get_payload()`` returns it.
        """
        try:
            return super().get_payload(i, decode)
        except TypeError:
            if i is not None or decode:
                raise
            payload = self._payload  # type: ignore[attr-defined]
            octets = payload.encode("ascii", "surrogateescape")
            try:
                charset = self.get_content_charset("ascii")
                return octets.decode(charset, "replace")
            except LookupError:
                return octets.decode("ascii", "replace")

    def set_payload(self, payload, charset=None):
        """Set the payload, also for an RFC 2231 charset.

        The generator passes the charset ``get_param()`` returned to the
        copy of a part with an 8-bit body.  ``Message.set_payload()``
        needs the name of the codec, which is the charset of that copy.

        Args:
            payload: the new payload.
            charset: a charset, its name, or its RFC 2231 tuple.

        Raises:
            LookupError: if the tuple names no codec.
        """
        if isinstance(charset, tuple):
            charset = self.get_content_charset()
            if charset is None:
                # Without a charset the payload would be stored as it
                # is, and written with an empty transfer encoding.
                raise LookupError("RFC 2231 charset is not a codec name")
        super().set_payload(payload, charset)


def mime_header_view(part: Message) -> tuple[Message, list[str]]:
    """Return a UTF-8 MIME metadata view without changing the raw part.

    Args:
        part: original MIME part, retaining raw headers and payload.

    Returns:
        A header-only compat32 message and descriptions of invalid UTF-8
        metadata, including each header occurrence and its raw octets.
        Invalid bytes appear as replacement characters in the display
        view; exact evidence remains in the descriptions and original.
        A malformed parameter list is described too, with the header
        value.
    """
    view = RecoveringMessage()
    view.set_default_type(part.get_default_type())
    defects = []
    occurrences: Counter[str] = Counter()
    for name, raw in part.raw_items():
        header = name.lower()
        if header not in {
            "content-type",
            "content-disposition",
            "content-id",
            "content-transfer-encoding",
        }:
            continue
        occurrence = occurrences[header]
        occurrences[header] += 1
        value = str(raw)
        try:
            octets = value.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            # A direct string caller can supply non-octet surrogates.
            evidence = value.encode("utf-8", "backslashreplace").decode()
            value = re.sub(r"[\ud800-\udfff]", "\ufffd", value)
        else:
            try:
                value = octets.decode("utf-8")
            except UnicodeDecodeError:
                evidence = octets.decode("ascii", "backslashreplace")
                value = octets.decode("utf-8", "replace")
            else:
                evidence = None
        if evidence is not None:
            defects.append(
                f"{header}[{occurrence}]: invalid UTF-8; raw={evidence!r}"
            )
        view[name] = value
        if occurrence or header not in _PARAMETER_HEADERS:
            continue
        if _read_params(value)[1]:
            defects.append(
                f"{header}[0]: invalid-parameter-continuation; raw={value!r}"
            )
    return view, defects


def mime_filename(part, *, defects=None):
    """Read a filename while retaining malformed RFC 2231 charset evidence.

    Args:
        part: MIME part or metadata view.
        defects: optional destination for charset recovery diagnostics.

    Returns:
        The filename, its literal parameter text on failure, or None.
    """
    part = RecoveringMessage.reading(part)
    try:
        return part.get_filename()
    except _CHARSET_ERRORS:
        value = part.get_param("filename", header="content-disposition")
        if value is None:
            value = part.get_param("name", header="content-type")
        if defects is not None:
            defects.append(
                f"invalid-filename-charset: raw parameter={value!r}",
            )
        if isinstance(value, tuple):
            return email.utils.unquote(value[2])
        return value


def mime_boundary(part, *, defects=None):
    """Read a multipart boundary as text that is safe to serialize.

    An RFC 2231 boundary is decoded with the charset the sender names, and
    some codecs (``utf-7``, ``unicode_escape``) produce lone surrogates:
    a value that is not Unicode text and breaks UTF-8 JSON and CLI sinks.
    An empty boundary is returned as it is and reported as a defect.

    Args:
        part: MIME part or metadata view.
        defects: optional destination for the diagnostic.

    Returns:
        The boundary, with any surrogate shown as a ``\\udXXX`` escape,
        its percent-decoded octets as Latin-1 text when the charset
        cannot decode them, or None when the part declares none.
    """
    part = RecoveringMessage.reading(part)
    boundary = _decoded_boundary(part, defects=defects)
    if boundary == "" and defects is not None:
        # RFC 2046 section 5.1.1: a boundary is 1 to 70 characters.
        raw = part.get_param("boundary")
        defects.append(f"invalid-boundary-parameter: empty; raw={raw!r}")
    if boundary is None or boundary.isascii():
        return boundary
    escaped = boundary.encode("utf-8", "backslashreplace").decode("utf-8")
    if escaped != boundary and defects is not None:
        defects.append(f"invalid-boundary-parameter: decoded={escaped!r}")
    return escaped


def mime_charset(part, failobj=None, *, defects=None):
    """Read a MIME charset without crashing on a malformed encoded parameter.

    Args:
        part: MIME part or metadata view.
        failobj: value used when the encoded charset cannot be read.
        defects: optional destination for raw parameter evidence.

    Returns:
        The charset name or failobj after an explicitly diagnosed failure.
    """
    part = RecoveringMessage.reading(part)
    try:
        return part.get_content_charset(failobj)
    except _CHARSET_ERRORS:
        if defects is not None:
            value = part.get_param("charset")
            defects.append(f"invalid-charset-parameter: raw={value!r}")
        return failobj


def ported_open(file_):
    """Open a file with UTF-8 encoding and ignore errors.

    Args:
        file_: path to the file to open

    Returns:
        file object
    """
    return open(file_, encoding="utf-8", errors="ignore")


def find_between(text, first_token, last_token):
    try:
        start = text.index(first_token) + len(first_token)
        end = text.index(last_token, start)
        return text[start:end].strip()
    except ValueError:
        return


def fingerprints(data):
    """
    This function return the fingerprints of data.

    Args:
        data (string): raw data

    Returns:
        namedtuple: fingerprints md5, sha1, sha256, sha512
    """

    hashes = namedtuple("Hashes", "md5 sha1 sha256 sha512")

    if not isinstance(data, bytes):
        data = data.encode("utf-8")

    # md5
    md5 = hashlib.md5()
    md5.update(data)
    md5 = md5.hexdigest()

    # sha1
    sha1 = hashlib.sha1()
    sha1.update(data)
    sha1 = sha1.hexdigest()

    # sha256
    sha256 = hashlib.sha256()
    sha256.update(data)
    sha256 = sha256.hexdigest()

    # sha512
    sha512 = hashlib.sha512()
    sha512.update(data)
    sha512 = sha512.hexdigest()

    return hashes(md5, sha1, sha256, sha512)


def _safe_remove(path):
    """
    Remove a file, ignoring the error if it is already gone.

    Used to clean up a temporary conversion file on failure paths so a
    malformed or unconvertible Outlook message cannot slowly fill the
    filesystem with orphaned temp files.

    Args:
        path (str): filesystem path to remove
    """
    try:
        os.remove(path)
    except OSError:
        log.debug("Could not remove temp file %r", path)


def _new_outlook_tempfile():
    """
    Create an empty temporary file to hold a converted Outlook email.

    The OS-level file handle is closed immediately; callers write to the
    returned path with their own handle (a subprocess ``--outfile`` for
    ``msgconvert`` or a plain ``open`` for the pure-Python backend).

    Returns:
        str: path of the new temporary ``.eml`` file
    """
    handle, path = tempfile.mkstemp(prefix="outlook_")
    os.close(handle)
    return path


def extract_msg_convert(fp):
    """
    Convert an Outlook ``.msg`` file to ``.eml`` using the pure-Python
    ``extract-msg`` library (no external Perl tool required).

    The ``extract_msg`` import is performed lazily inside this function so
    that the package keeps importing with zero runtime dependencies when
    the optional ``outlook`` extra is not installed.

    Args:
        fp (string): file path of the Outlook ``.msg`` mail

    Returns:
        tuple: ``(eml_path, info)`` where ``eml_path`` is the path of the
        converted ``.eml`` file and ``info`` is a short descriptive string

    Raises:
        ImportError: if the ``extract-msg`` library is not installed
        MailParserOSError: if the ``.msg`` is not a convertible email
            message (e.g. a contact or calendar item)
        MailParserOutlookError: if the ``.msg`` is malformed or the
            library fails on it; the library error is ``__cause__``
        MailParserRecursionError: if the ``.msg`` is nested too deeply
            to convert
        OSError: if ``fp`` cannot be opened; this is the caller's
            mistake
    """
    import extract_msg  # lazy: keep package import stdlib-only

    log.debug("Started converting Outlook email with extract-msg")
    # The path is the caller's: opened here, its errors stay what they
    # are, and every error below is about the content of the file.
    with open(fp, "rb"):
        pass
    try:
        msg = extract_msg.openMsg(fp)
        try:
            # openMsg() may return a non-email MSGFile (contact, calendar,
            # task...) which cannot be rendered as an email message.
            as_email_message = getattr(msg, "asEmailMessage", None)
            if as_email_message is None:
                raise MailParserOSError(
                    f"Outlook file {fp!r} is not a convertible email "
                    f"message (type {type(msg).__name__})"
                )
            eml = as_email_message()
            info = f"{eml.get('From', '')} | {eml.get('Subject', '')}".strip()
            # Serialize before the temp file exists: a failure here must
            # not leave an empty ``.eml`` behind.
            data = eml.as_bytes()
        finally:
            msg.close()
    except (MailParserError, MemoryError):
        # Not a malformed file: our own errors, or the machine's.
        raise
    except RecursionError as e:
        raise MailParserRecursionError(
            "Outlook file nesting too deep to convert"
        ) from e
    except Exception as e:
        # The .msg is attacker-controlled and the libraries raise a wide,
        # unstable set (extract_msg, olefile.OleFileError which is an
        # OSError, ValueError, IndexError, ...), so no narrow tuple holds.
        # The message names the class only: the text of a decoding error
        # holds the whole stream it could not decode.
        raise MailParserOutlookError(
            f"Cannot convert Outlook file {fp!r}: {type(e).__name__}"
        ) from e

    temp = _new_outlook_tempfile()
    with open(temp, "wb") as f:
        f.write(data)
    return temp, info


def msgconvert(email):
    """
    Exec msgconvert tool, to convert msg Outlook
    mail in eml mail format

    Args:
        email (string): file path of Outlook msg mail

    Returns:
        tuple with file path of mail converted and
        standard output data (str)

    Raises:
        MailParserOSError: if the ``msgconvert`` tool is not installed
    """
    log.debug("Started converting Outlook email")
    temp = _new_outlook_tempfile()
    command = ["msgconvert", "--outfile", temp, email]

    try:
        out = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    except OSError as e:
        _safe_remove(temp)
        message = (
            "Cannot convert Outlook .msg: no conversion backend "
            "available. Install pure-Python support with "
            "'pip install mail-parser[outlook]', or install the "
            "'msgconvert' Perl tool "
            f"(libemail-outlook-message-perl). {e!r}"
        )
        log.exception(message)
        raise MailParserOSError(message)

    else:
        try:
            stdoutdata, _ = out.communicate(timeout=_MSGCONVERT_TIMEOUT)
        except subprocess.TimeoutExpired:
            out.kill()
            out.communicate()
            _safe_remove(temp)
            message = (
                f"msgconvert did not finish within {_MSGCONVERT_TIMEOUT}s; "
                "aborting Outlook conversion"
            )
            log.error(message)
            raise MailParserOSError(message)
        return temp, stdoutdata.decode("utf-8", errors="replace").strip()


def get_from_clause(received):
    """
    Return the value of the ``from`` clause of a Received header.

    The sender address lives in the ``from`` clause; the ``by`` clause
    names the *receiving* server and must never be mistaken for it.
    Clause boundaries use the same context-aware scanner as parsing,
    ignoring comments and quoted strings. This also matters because a plain
    ``received.find("by")`` also matches inside a hostname — ``derby``,
    ``nearby`` — and the hostname comes from the sender's HELO. A false
    match truncates the clause, extraction fails on the genuine hop, and
    the caller falls through to older attacker-forged Received headers
    (CWE-345). A word-boundary ``\\bby\\b`` is not enough either: ``.``
    is a non-word character, so it still matches in ``host.by.example``.

    Args:
        received (string): raw Received header value

    Returns:
        string with the ``from`` clause value, or an empty string when the
        header has no ``from`` clause
    """
    try:
        clauses, _ = split_received(received)
    except MailParserReceivedParsingError:
        # Ambiguous delimiters on the authoritative hop must stop the walk.
        return ""
    return next((value for key, value in clauses if key == "from"), "")


def group_spans(text):
    """
    Return the spans of ``text`` enclosed in a ``(`` or ``[`` group.

    A single left-to-right pass, so the caller can classify many positions
    without re-scanning the prefix for each one. Nesting is tracked with a
    depth counter and an unclosed group runs to the end of the string.

    Args:
        text (string): text to scan

    Returns:
        list of (start, end) tuples, in order, excluding the delimiters
    """
    spans = []
    try:
        split_received(text, groups=spans)
    except MailParserReceivedParsingError:
        # The helper also exposes incomplete groups for existing callers;
        # attribution only calls it after get_from_clause validated them.
        pass
    return spans


def in_spans(position, spans):
    """
    Return True when ``position`` falls inside one of ``spans``.

    Args:
        position (int): offset to test
        spans (list): (start, end) tuples

    Returns:
        bool
    """
    return any(start <= position < end for start, end in spans)


def parse_received(received, *, defects=None):
    """
    Parse a single received header by tokenizing on RFC 5321 §4.4 keywords.

    Uses a keyword-based splitter to divide the header into clauses
    (from, by, via, with, id, for, envelope-from, envelope-sender),
    then extracts the date from after the semicolon.

    Arguments:
        received {str} -- single received header
        defects {list} -- optional destination for recovery diagnostics

    Raises:
        MailParserReceivedParsingError -- Raised when a
            received header cannot be parsed

    Returns:
        dict -- values by clause
    """

    values_by_clause = {}
    envelope_defects = []

    clauses, date = split_received(received, defects=defects)
    if date is not None:
        values_by_clause["date"] = date

    for keyword, value in clauses:
        if keyword in ("envelope-from", "envelope-sender"):
            address = extract_envelope_address(value, defects=envelope_defects)
            if address is not None:
                values_by_clause[keyword.replace("-", "_")] = address
        elif keyword == "for":
            values_by_clause[keyword] = value
        elif keyword == "from":
            # RFC 5321: only one 'from' clause per received header.
            # Only accept the first occurrence; subsequent ones come from
            # IBM-style "for <addr> from <sender>" constructs.
            if "from" not in values_by_clause:
                values_by_clause[keyword] = value
        else:
            values_by_clause[keyword] = value

    # --- Step 3: Extract envelope-from/sender from within clause values ---
    # Some MTAs embed envelope-from inside parenthesized comments in the
    # 'by' clause, e.g.: "by host.com (envelope-from <addr>)"
    for clause_key in ("by", "from", "with"):
        clause_val = values_by_clause.get(clause_key, "")
        for env_key, env_name in (
            ("envelope_from", "envelope-from"),
            ("envelope_sender", "envelope-sender"),
        ):
            if env_key not in values_by_clause:
                address = extract_envelope_address(
                    clause_val, marker=env_name, defects=envelope_defects
                )
                if address is not None:
                    values_by_clause[env_key] = address

    if defects is not None:
        # Each diagnostic will carry the complete raw field. Aggregate
        # repeated reasons before that evidence is attached/serialized.
        reasons = {}
        for diagnostic in envelope_defects:
            reason = diagnostic["reason"]
            recovered = diagnostic["recovered"]
            reasons[reason] = reasons.get(reason, False) or recovered
        defects.extend(
            {"reason": reason, "recovered": recovered}
            for reason, recovered in reasons.items()
        )

    if not values_by_clause:
        msg = "Unable to match any clauses in %s" % (received)
        raise MailParserReceivedParsingError(msg)

    log.debug("Parsed clauses: %s", list(values_by_clause.keys()))
    return values_by_clause


def receiveds_parsing(receiveds, *, defects=None, date_defects=None):
    """
    This function parses the receiveds headers.

    Args:
        receiveds (list): list of raw receiveds headers
        defects (list): optional destination for occurrence diagnostics.
        date_defects (list): optional destination for timestamp diagnostics.

    Returns:
        a list of parsed receiveds headers with first hop in first position
    """

    parsed = []
    n = len(receiveds)
    log.debug(f"Nr. of receiveds. {n}")

    for idx, received in enumerate(receiveds):
        log.debug(f"Parsing received {idx + 1}/{n}")
        log.debug(f"Try to parse {received!r}")
        diagnostics = []
        raw_evidence = received.encode("utf-8", "backslashreplace").decode(
            "utf-8"
        )
        try:
            # BytesParser stores raw octets using surrogateescape. Decode
            # valid UTF-8 for display, retaining malformed octets losslessly.
            value = received.encode("utf-8", "surrogateescape").decode(
                "utf-8", "surrogateescape"
            )
        except UnicodeEncodeError:
            value = received
        try:
            values_by_clause = parse_received(value, defects=diagnostics)
        except MailParserReceivedParsingError as error:
            # Preserve original folding and delimiters, not normalized text.
            parsed.append({"raw": raw_evidence})
            reason = str(error)
            # Unrecognized but balanced obsolete trace tokens are not
            # necessarily invalid (RFC 5322 section 4.5.7).
            if not reason.startswith("Unable to match any clauses"):
                diagnostics.append({"reason": reason, "recovered": False})
        else:
            parsed.append(
                {
                    key: item.encode("utf-8", "backslashreplace").decode(
                        "utf-8"
                    )
                    for key, item in values_by_clause.items()
                }
            )
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            diagnostics.append(
                {
                    "reason": "invalid-utf8",
                    "recovered": "raw" not in parsed[-1],
                }
            )
        if defects is not None:
            for defect in diagnostics:
                defect.update(
                    raw=raw_evidence, header="received", occurrence=idx
                )
                defects.append(defect)

    log.debug(
        "len(receiveds) %s, len(parsed) %s" % (len(receiveds), len(parsed))
    )

    if len(receiveds) != len(parsed):  # pragma: no cover
        # something really bad happened,
        # so just return raw receiveds with hop indices
        log.error(
            "len(receiveds): %s, len(parsed): %s, receiveds: %s, \
            parsed: %s"
            % (len(receiveds), len(parsed), receiveds, parsed)
        )
        return receiveds_not_parsed(receiveds)

    else:
        # all's good! we have parsed or raw receiveds for each received header
        return receiveds_format(
            parsed, raw_headers=receiveds, date_defects=date_defects
        )


def convert_mail_date(date):
    """Convert a recoverable mail date to a UTC datetime and offset.

    Args:
        date (str): modern or obsolete RFC 5322 date-time value.

    Returns:
        tuple: UTC datetime and the legacy signed decimal-hour offset.
        An inconsistent weekday retains the numerical date; MailParser
        additionally exposes its occurrence-aware diagnostic.

    Raises:
        ValueError: syntax or components prevent a safe selected datetime.
    """
    result = parse_mail_date(date)
    if result.value is None:
        raise ValueError(f"Cannot parse date: {date!r}")
    return result.value, result.timezone


def receiveds_not_parsed(receiveds):
    """
    If receiveds are not parsed, makes a new structure with raw
    field. It's useful to have the same structure of receiveds
    parsed.

    Args:
        receiveds (list): list of raw receiveds headers

    Returns:
        a list of not parsed receiveds headers with first hop in first position
    """
    log.debug("Receiveds for this email are not parsed")

    output = []
    counter = Counter()

    for i in receiveds[::-1]:
        j = {"raw": i.strip()}
        j["hop"] = counter["hop"] + 1
        counter["hop"] += 1
        output.append(j)

    return output


def receiveds_format(receiveds, *, raw_headers=None, date_defects=None):
    """
    Given a list of receiveds hop, adds metadata and reformat
    field values

    Args:
        receiveds (list): list of receiveds hops already formatted
        raw_headers (list): optional original fields in wire order.
        date_defects (list): optional destination for timestamp diagnostics.

    Returns:
        list of receiveds reformated and with new fields
    """
    log.debug("Receiveds for this email are parsed")

    output = []
    counter = Counter()

    for occurrence in range(len(receiveds) - 1, -1, -1):
        i = receiveds[occurrence]
        # Clean strings
        j = {k: (v if k == "raw" else v.strip()) for k, v in i.items() if v}

        # Add hop
        j["hop"] = counter["hop"] + 1

        # Add UTC date
        if "date" in i:
            result = parse_mail_date(i["date"])
            j["date_utc"] = result.value
            if date_defects is not None:
                raw = raw_headers[occurrence] if raw_headers else i["date"]
                date_defects.extend(
                    date_diagnostics(result, raw, "received", occurrence)
                )

        # Add delay
        size = len(output)
        now = j.get("date_utc")

        if size and now:
            before = output[counter["hop"] - 1].get("date_utc")
            if before:
                j["delay"] = (now - before).total_seconds()
            else:
                j["delay"] = 0
        else:
            j["delay"] = 0

        # append result
        output.append(j)

        # new hop
        counter["hop"] += 1

    for i in output:
        if i.get("date_utc"):
            i["date_utc"] = i["date_utc"].isoformat()
    return output


def get_to_domains(to=[], reply_to=[]):
    domains = set()
    for i in to + reply_to:
        try:
            domains.add(i[1].split("@")[-1].lower().strip())
        except (KeyError, IndexError):
            pass

    return list(domains)


def decode_headers(headers):
    """
    Decode the raw values of a single header name with the correct charset.

    Args:
        headers (list): raw values of one header name, or None if absent

    Returns:
        str if there is one value
        list if there are more than one
        empty str if the header is absent
    """

    if not headers:
        return str()

    decoded = [decode_header_part(i) for i in headers]
    if len(decoded) == 1:
        # in this case return a string
        return decoded[0].strip()
    # in this case return a list
    return decoded


def get_header(message, name):
    """
    Gets an email.message.Message and a header name and returns
    the mail header decoded with the correct charset.

    Args:
        message (email.message.Message): email message object
        name (string): header to get

    Returns:
        str if there is an header
        list if there are more than one
    """

    headers = message.get_all(name)
    log.debug(f"Getting header {name!r}: {headers!r}")
    return decode_headers(headers)


def get_mail_keys(message, complete=True):
    """
    Given an email.message.Message, return a set with all email parts to get

    Args:
        message (email.message.Message): email message object
        complete (bool): if True returns all email headers

    Returns:
        set with all email parts
    """

    if complete:
        log.debug("Get all headers")
        all_headers_keys = {i.lower() for i in message.keys()}
        all_parts = ADDRESSES_HEADERS | OTHERS_PARTS | all_headers_keys
    else:
        log.debug("Get only mains headers")
        all_parts = ADDRESSES_HEADERS | OTHERS_PARTS

    log.debug("All parts to get: {}".format(", ".join(all_parts)))
    return all_parts


def safe_print(data):  # pragma: no cover
    try:
        print(data)
    except UnicodeEncodeError:
        print(data.encode("utf-8"))


def print_mail_fingerprints(data):  # pragma: no cover
    md5, sha1, sha256, sha512 = fingerprints(data)
    print(f"md5:\t{md5}")
    print(f"sha1:\t{sha1}")
    print(f"sha256:\t{sha256}")
    print(f"sha512:\t{sha512}")


def raw_payload(part):
    """
    Return a part's payload without decoding its transfer encoding.

    ``Message.get_payload(decode=False)`` applies the charset the sender
    declared. The email package guards that decode against an unknown
    charset name, but not against a codec that refuses the operation
    outright: ``charset="undefined"`` raises a bare ``UnicodeError``, which
    would abort the parse of the whole message.

    ``TypeError`` is caught for a plain ``Message`` of the caller only;
    a ``RecoveringMessage`` does not raise it.  Up to Python 3.11 the
    charset comes from ``get_param()``, a tuple for an RFC 2231 value,
    and before 3.13.18, 3.14.10 and 3.15.2 reading the parameters at all
    raises it for sections with and without a number.

    Args:
        part (email.message.Message): part to read

    Returns:
        the payload as the email package returns it, or the undecoded bytes
        when the declared charset cannot be applied
    """
    try:
        return part.get_payload(decode=False)
    except (*_CHARSET_ERRORS, TypeError):
        log.warning("Cannot apply the declared charset, reading raw bytes")
        return part.get_payload(decode=True)


def _refusing_parts(error, root):
    """
    Name the parts whose flattening a charset error ended.

    The generator flattens every sub-part with a nested ``flatten()``
    call, so the error leaves one frame for each part it passed
    through: the part that refused its charset and every container
    around it.  Flattening one of them alone ends in the same error
    only if it repeats the same steps, so a part is named when it has
    the class and the policy of ``root`` and was written with the line
    length ``root`` was.  Below ``multipart/signed`` the generator
    writes headers without a length limit, and a policy may refuse a
    header there that it folds when the part is flattened alone;
    ``compat32`` writes or refuses a header whatever the limit is.

    A frame without the expected locals names no part, and that part
    is flattened again: the cost of a pass, never another output.

    Args:
        error (Exception): charset error raised while flattening root
        root (email.message.Message): part the flattening started from

    Returns:
        set of the parts that raise the same error when flattened alone
    """
    passes = [
        (
            frame.f_locals.get("msg"),
            getattr(frame.f_locals.get("policy"), "max_line_length", None),
        )
        for frame, _ in traceback.walk_tb(error.__traceback__)
        if frame.f_code is _FLATTEN_CODE
    ]
    if not passes:
        return set()
    any_length = type(root.policy) is Compat32
    root_length = passes[0][1]
    return {
        part
        for part, length in passes
        if type(part) is type(root)
        and getattr(part, "policy", None) is root.policy
        and (any_length or (length is not None and length == root_length))
    }


def as_string_safe(part, *, budget=None, _known=None):
    """
    Flatten a part back to its textual form.

    ``Message.as_string()`` re-encodes an 8-bit body with the charset the
    sender declared, so a charset that cannot represent those bytes —
    ``utf-16``, ``idna``, or a non-text codec such as ``base64`` — raises
    out of the parse. Fall back to the raw bytes, which every codec
    survives, rather than losing the whole message.

    Args:
        part (email.message.Message): part to flatten
        budget: optional per-parse budget for container representations
        _known: private, for the calls this function makes to itself
            on the sub-parts: the parts already known to refuse
            ``as_string()`` and the ones known to refuse
            ``as_bytes()``, as a pair of sets

    Returns:
        the flattened part as a string
    """
    if _known is None:
        _known = (set(), set())
    text_refusing, bytes_refusing = _known

    # The part that refuses its charset fails every container around
    # it.  Flattened alone, each of them would flatten all that comes
    # before that part only to fail again: size times depth.  The first
    # failure names them, and none is flattened a second time.  With a
    # budget every pass is debited, also one that fails, so none is
    # skipped there: that would move the resource limit.
    header_refused = False
    if part not in text_refusing:
        try:
            with _keeping_empty_boundaries():
                if budget is None:
                    return part.as_string()
                return bounded_flatten(part, budget)
        except _FLATTEN_ERRORS as error:
            log.warning("Cannot flatten part with the declared charset")
            # The bytes generator of some releases writes a header the
            # text generator refuses, line break included: a part
            # refused for a header is not given to it.
            header_refused = isinstance(error, _HEADER_ERRORS)
            if budget is None:
                refusing = _refusing_parts(error, part)
                text_refusing.update(refusing)
                if header_refused:
                    bytes_refusing.update(refusing)

    if not header_refused and part not in bytes_refusing:
        try:
            with _keeping_empty_boundaries():
                data = (
                    part.as_bytes()
                    if budget is None
                    else bounded_flatten(part, budget, binary=True)
                )
            return data.decode("utf-8", "surrogateescape")
        except _FLATTEN_ERRORS as error:
            # BytesGenerator bypasses the charset only for text parts. A
            # part whose type is multipart but which carries no boundary
            # is routed to the generic multipart handler, which decodes
            # with the declared charset just like as_string() did.
            if budget is None:
                bytes_refusing.update(_refusing_parts(error, part))

    log.warning("Cannot flatten part, using its raw headers and body")
    header_chunks = []
    for k, v in part.raw_items():
        try:
            chunk = f"{k}: {part.policy.header_fetch_parse(k, v)}\n"
        except UnicodeEncodeError:
            # A value with surrogates comes back as an unknown-8bit Header,
            # whose str() reads them as escaped octets. A lone surrogate
            # outside that range, or a non-ASCII character next to one,
            # can only come from a str: write the value as it was parsed,
            # as the body is.
            chunk = f"{k}: {v}\n"
        if budget is not None:
            budget.spend(characters=len(chunk))
        header_chunks.append(chunk)
    headers = "".join(header_chunks)
    body = raw_payload(part)
    if isinstance(body, list):
        # A conforming multipart: flatten each sub-part the same way, since
        # the one that refused its charset may be nested any depth down.
        body = "".join(
            as_string_safe(sub, budget=budget, _known=_known) for sub in body
        )
    elif isinstance(body, bytes):
        # The charset was refused above, so raw_payload() fell back to the
        # undecoded bytes.  A part refused for a header keeps its text.
        body = body.decode("utf-8", "surrogateescape")
    if budget is not None:
        budget.spend(characters=len(headers) + len(body) + 1, nodes=1)
    return f"{headers}\n{body}"


def decode_base64_payload(payload):
    """
    Decode a base64 attachment payload the way a mail client would.

    ``base64.b64decode()`` rejects padding and alphabet errors that every
    MUA silently repairs, so a sender can strip one padding character to
    make an attachment undecodable here while it still reaches the
    recipient intact.

    Args:
        payload (string): base64 payload of an attachment

    Returns:
        the decoded bytes
    """
    data = re.sub(rb"[^A-Za-z0-9+/=]", b"", payload.encode("ascii", "ignore"))
    # Padding ends the stream, as RFC 2045 requires and every client does.
    # Splicing what follows onto the payload let a sender append bytes that
    # only this tool sees, changing the hash it reports for the attachment.
    data = data.split(b"=", 1)[0]
    if len(data) % 4 == 1:
        # A lone trailing character carries no complete byte. Padding it is
        # impossible, so drop it as every lenient decoder does: otherwise
        # adding one character is enough to make an attachment vanish from
        # the extraction directory while it still reaches the recipient.
        data = data[:-1]
    return base64.b64decode(data + b"=" * (-len(data) % 4))


def print_attachments(attachments, flag_hash):  # pragma: no cover
    if flag_hash:
        for i in attachments:
            if i.get("content_transfer_encoding") == "base64":
                payload = decode_base64_payload(i["payload"])
            else:
                payload = i["payload"]

            i["md5"], i["sha1"], i["sha256"], i["sha512"] = fingerprints(
                payload
            )

    for i in attachments:
        safe_print(json.dumps(i, ensure_ascii=False, indent=4))


def write_attachments(attachments, base_path):  # pragma: no cover
    """
    Write attachments with unique filenames for this attachment batch.

    A single hostile attachment must not cost the rest of the batch, so an
    unusable filename, an undecodable payload and a failing write are all
    logged and skipped. ``MailParserPathError`` is deliberately not caught:
    a containment failure is not a per-attachment problem.

    Args:
        attachments (list): attachments as returned by MailParser
        base_path (string): directory the attachments are written to

    Raises:
        MailParserPathError: if an attachment escapes ``base_path``
    """
    used_filenames = {}

    for a in attachments:
        try:
            filename = _safe_attachment_filename(a["filename"])
        except ValueError:
            log.warning(
                f"Skipped attachment with invalid filename: {a['filename']!r}"
            )
            continue

        filename = _deduplicate_filename(filename, used_filenames)

        try:
            write_sample(
                binary=a["binary"],
                payload=a["payload"],
                path=base_path,
                filename=filename,
            )
        except (OSError, ValueError):
            log.warning(f"Skipped attachment {filename!r}", exc_info=True)


def _safe_attachment_filename(filename):
    """Return an attachment filename without any directory components."""
    if not isinstance(filename, str) or "\x00" in filename:
        raise ValueError("Invalid attachment filename")

    # Treat both POSIX and Windows separators as directory separators on every
    # OS.
    filename = os.path.basename(filename.replace("\\", "/"))
    if filename in ("", ".", ".."):
        raise ValueError("Invalid attachment filename")

    return _truncate_filename(filename)


_COMPOUND_ATTACHMENT_EXTENSIONS = (
    ".tar.bz2",
    ".tar.gz",
    ".tar.lz",
    ".tar.lzma",
    ".tar.xz",
    ".tar.z",
    ".tar.zst",
)


def _split_attachment_extension(filename):
    """Split a filename while preserving common compressed-tar extensions."""
    lower_filename = filename.lower()
    for extension in _COMPOUND_ATTACHMENT_EXTENSIONS:
        if lower_filename.endswith(extension) and len(filename) > len(
            extension
        ):
            return filename[: -len(extension)], filename[-len(extension) :]
    return os.path.splitext(filename)


# NAME_MAX is 255 bytes on Linux and macOS. Leave room for the "_1", "_2"
# suffixes _deduplicate_filename() appends after this truncation.
_MAX_FILENAME_BYTES = 240

# Room reserved inside the budget for the "_1", "_2" deduplication marker.
# Eight bytes would under-reserve from suffix 10**7 on, letting the marker
# push the name past the limit again.
_MAX_MARKER_BYTES = 11


def _split_within_budget(filename):
    """
    Split a basename into root and extension, both short enough to keep.

    An extension long enough to eat the whole budget is not an extension:
    keeping it would leave no room for the root, and a negative budget
    would slice the root from the wrong end.

    Args:
        filename (str): sanitized basename

    Returns:
        a (root, extension) tuple whose extension is at most half the budget
    """
    root, extension = _split_attachment_extension(filename)
    if len(extension.encode("utf-8")) > _MAX_FILENAME_BYTES // 2:
        return filename, ""
    return root, extension


def _clamp_to_budget(text, budget):
    """
    Cut a string to at most ``budget`` UTF-8 bytes.

    A partial multi-byte character left by the cut is dropped.

    Args:
        text (str): string to shorten
        budget (int): maximum length in UTF-8 bytes

    Returns:
        the string, at most ``budget`` bytes long
    """
    return text.encode("utf-8")[: max(0, budget)].decode("utf-8", "ignore")


def _truncate_filename(filename):
    """
    Shorten a basename so it fits NAME_MAX, keeping its extension.

    The limit is measured in UTF-8 bytes, not characters, because that is
    what the filesystem enforces.

    Args:
        filename (str): sanitized basename

    Returns:
        the basename, at most _MAX_FILENAME_BYTES bytes long
    """
    if len(filename.encode("utf-8")) <= _MAX_FILENAME_BYTES:
        return filename

    root, extension = _split_within_budget(filename)
    budget = _MAX_FILENAME_BYTES - len(extension.encode("utf-8"))
    return _clamp_to_budget(root, budget) + extension


def _deduplicate_filename(filename, used_filenames):
    """
    Return a unique filename within one write_attachments() operation.

    Names are compared case-insensitively. ``os.path.normcase()`` is the
    identity on POSIX, so two attachments differing only in case were
    treated as distinct while APFS, exFAT and SMB collapse them onto one
    file: the second attachment silently overwrote the first. Folding
    always costs at most a ``_1`` suffix; not folding costs evidence.

    Args:
        filename (str): sanitized basename
        used_filenames (dict): folded name -> last suffix already handed
            out for it, updated in place

    Returns:
        a basename not yet used in this batch
    """
    root, extension = _split_within_budget(filename)

    # Reserve room for the marker instead of appending past the limit:
    # write_sample() sanitizes again, and the clamp there would cut the
    # marker back off, collapsing distinct attachments onto one file.
    budget = (
        _MAX_FILENAME_BYTES
        - len(extension.encode("utf-8"))
        - _MAX_MARKER_BYTES
    )
    stem = _clamp_to_budget(root, budget)

    # Key on the stem the candidates are built from, not on the name as
    # sent. Long names differing only past the clamp share one candidate
    # namespace, so keying on the full name made each of them rescan the
    # whole occupied range: quadratic in the number of attachments.
    key = (stem + extension).casefold()
    suffix = used_filenames.get(key, 0)
    candidate = filename

    while candidate.casefold() in used_filenames:
        suffix += 1
        candidate = f"{stem}_{suffix}{extension}"

    used_filenames[key] = suffix
    used_filenames.setdefault(candidate.casefold(), 0)
    return candidate


def write_sample(binary, payload, path, filename):  # pragma: no cover
    """
    This function writes a sample on file system.

    Args:
        binary (bool): True if it's a binary file
        payload: payload of sample, in base64 if it's a binary
        path (string): path of file
        filename (string): name of file

    Raises:
        ValueError: if a binary payload is not valid base64
        MailParserPathError: if the file would land outside ``path``
    """
    # Resolve the bytes before creating the file, so a payload that cannot
    # be decoded or encoded leaves no truncated stub behind. Surrogates
    # produced by decoding the part are mapped back to the bytes they came
    # from rather than dropped.
    if binary:
        content = decode_base64_payload(payload)
    else:
        content = payload.encode("utf-8", "surrogateescape")

    filename = _safe_attachment_filename(filename)
    os.makedirs(path, exist_ok=True)

    base_path = os.path.realpath(path)
    sample = os.path.join(base_path, filename)
    resolved_sample = os.path.realpath(sample)

    try:
        contained = (
            os.path.commonpath((base_path, resolved_sample)) == base_path
        )
    except ValueError:
        contained = False

    if not contained or os.path.islink(sample):
        raise MailParserPathError(
            "Attachment path escapes the output directory"
        )

    with open(sample, "wb") as f:
        f.write(content)


def random_string(string_length=10):
    """Generate a random string of fixed length

    Keyword Arguments:
        string_length {int} -- String length (default: {10})

    Returns:
        str -- Random string
    """
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(string_length))
