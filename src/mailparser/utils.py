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
import datetime
import email
import email.header
import email.utils
import functools
import hashlib
import json
import logging
import os
import random
import re
import string
import subprocess
import sys
import tempfile
from collections import Counter, namedtuple
from email.errors import HeaderParseError
from email.header import decode_header
from unicodedata import normalize

from mailparser.const import (
    _CLAUSE_SPLITTER,
    _DATE_RE,
    _ENVELOPE_FROM_RE,
    _SENDGRID_DATE_RE,
    ADDRESSES_HEADERS,
    JUNK_PATTERN,
    OTHERS_PARTS,
)
from mailparser.exceptions import MailParserOSError, MailParserReceivedParsingError

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 5322 address parsing — fallback for non-compliant display names
# ---------------------------------------------------------------------------
# RFC 5322 §3.4 defines the display-name as a "phrase", which must not contain
# unquoted special characters such as "@".  A header like
#
#     From: alice@example.com <bob@example.com>
#
# is therefore *technically non-conforming*: the display name contains an
# unquoted "@".  Python's ``email.utils.getaddresses`` with ``strict=True``
# (hardened against CVE-2023-27043) correctly rejects this and returns
# ``[('', '')]``, leaving the real address invisible.
#
# mail-parser is a security / forensics tool, not an MTA.  Silently hiding an
# address because its display-name looks like an e-mail address defeats the
# purpose of the tool — analysts *need* to see those values.  We therefore
# bypass strict compliance with a regex fallback whenever strict parsing yields
# an empty address, always surfacing the value that is actually in the header.
_ADDR_FALLBACK_RE = re.compile(
    r'"([^"]*?)"\s*<([^>]+)>'  # "Quoted Name" <email@addr>
    r"|([^<,]*?)\s*<([^>]+)>"  # Any Name <email@addr>  (incl. email-as-name)
    r"|([^\s,<>]+@[^\s,<>]+)"  # bare email@addr
)


def get_addresses(
    raw_header: str | email.header.Header | None,
) -> list[tuple[str, str]]:
    """
    Parse email addresses from a raw address header with a fallback for
    RFC-non-compliant but real-world-common formats.

    RFC 5322 §3.4 requires the display name (phrase) before an angle-bracket
    address to consist only of printable ASCII characters that are *not*
    special.  The ``@`` character is special, so a header such as::

        From: alice@example.com <bob@example.com>

    is technically non-conforming because the display name contains an
    unquoted ``@``.  Python's ``email.utils.getaddresses`` with
    ``strict=True`` (hardened against CVE-2023-27043) correctly returns
    ``[('', '')]`` for this input, making the real sender invisible.

    mail-parser is a *security / forensics* tool, not an MTA.  Silently
    discarding an address because its display name happens to look like an
    e-mail address would hide relevant forensic information from analysts —
    the very opposite of what the tool is for.  We therefore bypass strict
    RFC compliance by applying a regex-based fallback whenever the strict
    parser yields only empty addresses, so that analysts always see the value
    that was actually present in the header.

    Args:
        raw_header (str | email.header.Header | None): raw value of an
            address header (e.g. ``From``, ``To``, ``CC`` …). Accepts a
            plain ``str``, an ``email.header.Header`` instance (returned
            by ``email.message.Message.get`` for headers containing
            RFC 2047 encoded-words such as non-ASCII display names), or
            ``None``.

    Returns:
        list[tuple[str, str]]: list of ``(display_name, email_addr)`` tuples.
            ``display_name`` is an empty string when absent.
    """
    # ``Message.get(name)`` returns an ``email.header.Header`` for any header
    # whose value contains RFC 2047 encoded-words (typical for non-ASCII
    # display names like ``=?utf-8?q?=C3=81rp=C3=A1d?=``). ``Header`` does
    # not implement string methods such as ``.strip()`` and is not a valid
    # input to ``email.utils.getaddresses``.
    #
    # Important: decode ``Header`` values into a plain parseable string first.
    # In practice, strict address parsing can treat raw encoded-word tokens like
    # ``=?unknown-8bit?...?=`` as the *address* itself, producing output such as
    # ``To: =?unknown-8bit?...?=``.  Decoding first gives
    # ``Álpám Longsom <recipient@example.com>`` so getaddresses() can split
    # name/address correctly.
    if raw_header is None:
        return []
    if isinstance(raw_header, email.header.Header):
        raw_header = decode_header_part(raw_header.encode())
    elif not isinstance(raw_header, str):
        raw_header = str(raw_header)

    parsed = email.utils.getaddresses([raw_header], strict=True)

    # If every result from the strict parser has an empty address — while the
    # raw header is non-empty — fall back to regex extraction so that the
    # actual address values are not silently lost.
    if raw_header.strip() and all(not addr for _, addr in parsed):
        results = []
        for m in _ADDR_FALLBACK_RE.finditer(raw_header):
            if m.group(2):  # "Quoted Name" <email>
                results.append((m.group(1).strip(), m.group(2).strip()))
            elif m.group(4):  # Any Name <email>  (incl. email-as-display-name)
                results.append((m.group(3).strip(), m.group(4).strip()))
            elif m.group(5):  # bare email  # pragma: no branch
                results.append(("", m.group(5).strip()))
        if results:
            log.debug(
                "Strict address parsing yielded empty results for %r; "
                "regex fallback recovered %d address(es)",
                raw_header,
                len(results),
            )
            return results

    return parsed


def custom_log(level="WARNING", name=None):  # pragma: no cover
    """
    This function returns a custom logger.
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
    ch = logging.StreamHandler(sys.stdout)
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

    # raw_data is bytes, decode it
    try:
        return str(raw_data, encoding)
    except (LookupError, UnicodeDecodeError):
        return str(raw_data, "utf-8", errors)


def decode_header_part(header):
    """
    Given a raw header returns a decoded header

    Args:
        header (string): header to decode

    Returns:
        str
    """
    if not header:
        return str()

    output = str()

    try:
        for d, c in decode_header(header):
            c = c if c else "utf-8"
            output += ported_string(d, c, "ignore")

    # Header parsing failed, when header has charset Shift_JIS
    except (HeaderParseError, UnicodeError):
        log.error(f"Failed decoding header part: {header}")
        output += header

    return output.strip()


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
    """
    import extract_msg  # lazy: keep package import stdlib-only

    log.debug("Started converting Outlook email with extract-msg")
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
        temp = _new_outlook_tempfile()
        with open(temp, "wb") as f:
            f.write(eml.as_bytes())
        return temp, info
    finally:
        msg.close()


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
        stdoutdata, _ = out.communicate()
        return temp, stdoutdata.decode("utf-8").strip()


def parse_received(received):
    """
    Parse a single received header by tokenizing on RFC 5321 §4.4 keywords.

    Uses a keyword-based splitter to divide the header into clauses
    (from, by, via, with, id, for, envelope-from, envelope-sender),
    then extracts the date from after the semicolon.

    Arguments:
        received {str} -- single received header

    Raises:
        MailParserReceivedParsingError -- Raised when a
            received header cannot be parsed

    Returns:
        dict -- values by clause
    """

    values_by_clause = {}

    # --- Step 1: Extract date (after semicolon, or SendGrid format) ---
    date_match = _DATE_RE.search(received)
    if date_match:
        values_by_clause["date"] = date_match.group(1)
        # Work only on the part before the semicolon for clause parsing
        header_body = received[: date_match.start()]
    else:
        # Try SendGrid non-standard date
        sg_match = _SENDGRID_DATE_RE.search(received)
        if sg_match:
            values_by_clause["date"] = sg_match.group(1)
            header_body = received[: sg_match.start()]
        else:
            header_body = received

    # --- Step 2: Tokenize on clause keywords ---
    # _CLAUSE_SPLITTER.split gives: [preamble, kw1, val1, kw2, val2, ...]
    parts = _CLAUSE_SPLITTER.split(header_body)

    # parts[0] is preamble (before first keyword), then alternating kw/value
    i = 1  # skip preamble
    while i + 1 < len(parts):
        keyword = parts[i].lower()
        value = parts[i + 1].strip()
        i += 2

        if keyword in ("envelope-from", "envelope-sender"):
            # Extract email from angle brackets
            m = _ENVELOPE_FROM_RE.search(value)
            if m:
                values_by_clause[keyword.replace("-", "_")] = m.group(1)
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
            if env_key not in values_by_clause and env_name in clause_val.lower():
                m = re.search(
                    r"(?i)" + re.escape(env_name) + r"\s+<([^>]+)>",
                    clause_val,
                )
                if m:
                    values_by_clause[env_key] = m.group(1)

    if not values_by_clause:
        msg = "Unable to match any clauses in %s" % (received)
        raise MailParserReceivedParsingError(msg)

    log.debug("Parsed clauses: %s", list(values_by_clause.keys()))
    return values_by_clause


def receiveds_parsing(receiveds):
    """
    This function parses the receiveds headers.

    Args:
        receiveds (list): list of raw receiveds headers

    Returns:
        a list of parsed receiveds headers with first hop in first position
    """

    parsed = []
    receiveds = [re.sub(JUNK_PATTERN, " ", i).strip() for i in receiveds]
    n = len(receiveds)
    log.debug(f"Nr. of receiveds. {n}")

    for idx, received in enumerate(receiveds):
        log.debug(f"Parsing received {idx + 1}/{n}")
        log.debug(f"Try to parse {received!r}")
        try:
            # try to parse the current received header...
            values_by_clause = parse_received(received)
        except MailParserReceivedParsingError:
            # if we can't, let's append the raw
            parsed.append({"raw": received})
        else:
            # otherwise append the full values_by_clause dict
            parsed.append(values_by_clause)

    log.debug("len(receiveds) %s, len(parsed) %s" % (len(receiveds), len(parsed)))

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
        return receiveds_format(parsed)


def convert_mail_date(date):
    """
    Convert a mail date in a datetime object.
    """
    log.debug(f"Date to parse: {date!r}")
    d = email.utils.parsedate_tz(date)
    if d is None:
        raise ValueError(f"Cannot parse date: {date!r}")
    log.debug(f"Date parsed: {d!r}")
    t = email.utils.mktime_tz(d)
    log.debug(f"Date parsed in timestamp: {t!r}")
    date_utc = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    timezone = d[9] / 3600.0 if d[9] else 0
    timezone = f"{timezone:+.1f}"
    log.debug(f"Calculated timezone: {timezone!r}")
    return date_utc, timezone


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


def receiveds_format(receiveds):
    """
    Given a list of receiveds hop, adds metadata and reformat
    field values

    Args:
        receiveds (list): list of receiveds hops already formatted

    Returns:
        list of receiveds reformated and with new fields
    """
    log.debug("Receiveds for this email are parsed")

    output = []
    counter = Counter()

    for i in receiveds[::-1]:
        # Clean strings
        j = {k: v.strip() for k, v in i.items() if v}

        # Add hop
        j["hop"] = counter["hop"] + 1

        # Add UTC date
        if i.get("date"):
            # Modify date to manage strange header like:
            # "for <eboktor@romolo.com>; Tue, 7 Mar 2017 14:29:24 -0800",
            i["date"] = i["date"].split(";")[-1]
            # Strip leading RFC 2822 comments like:
            # "(version=TLSv1/SSLv3 cipher=AES128-GCM-SHA256 bits=128/128) Wed, ..."
            i["date"] = re.sub(r"^\s*(?:\([^)]*\)\s*)+", "", i["date"])
            try:
                j["date_utc"], _ = convert_mail_date(i["date"])
            except (TypeError, ValueError):
                j["date_utc"] = None

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
    if headers:
        headers = [decode_header_part(i) for i in headers]
        if len(headers) == 1:
            # in this case return a string
            return headers[0].strip()
        # in this case return a list
        return headers
    return str()


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


def print_attachments(attachments, flag_hash):  # pragma: no cover
    if flag_hash:
        for i in attachments:
            if i.get("content_transfer_encoding") == "base64":
                payload = base64.b64decode(i["payload"])
            else:
                payload = i["payload"]

            i["md5"], i["sha1"], i["sha256"], i["sha512"] = fingerprints(payload)

    for i in attachments:
        safe_print(json.dumps(i, ensure_ascii=False, indent=4))


def write_attachments(attachments, base_path):  # pragma: no cover
    for a in attachments:
        write_sample(
            binary=a["binary"],
            payload=a["payload"],
            path=base_path,
            filename=a["filename"],
        )


def write_sample(binary, payload, path, filename):  # pragma: no cover
    """
    This function writes a sample on file system.

    Args:
        binary (bool): True if it's a binary file
        payload: payload of sample, in base64 if it's a binary
        path (string): path of file
        filename (string): name of file
        hash_ (string): file hash
    """
    if not os.path.exists(path):
        os.makedirs(path)
    sample = os.path.join(path, filename)

    if binary:
        with open(sample, "wb") as f:
            f.write(base64.b64decode(payload))
    else:
        with open(sample, "w") as f:
            f.write(payload)


def random_string(string_length=10):
    """Generate a random string of fixed length

    Keyword Arguments:
        string_length {int} -- String length (default: {10})

    Returns:
        str -- Random string
    """
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for _ in range(string_length))
