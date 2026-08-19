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

import base64
import email
import importlib.util
import ipaddress
import json
import logging

from mailparser.const import (
    _HELO_RE,
    _IPV6_TAG_RE,
    ADDRESSES_HEADERS,
    COMPUTED_PARTS,
    EPILOGUE_DEFECTS,
    REGXIP,
    REGXIP6,
)
from mailparser.exceptions import MailParserRecursionError
from mailparser.utils import (
    _safe_attachment_filename,
    _safe_remove,
    as_string_safe,
    convert_mail_date,
    decode_header_part,
    decode_headers,
    extract_msg_convert,
    find_between,
    get_addresses,
    get_from_clause,
    get_mail_keys,
    get_to_domains,
    group_spans,
    in_spans,
    msgconvert,
    ported_open,
    ported_string,
    random_string,
    raw_payload,
    receiveds_parsing,
    write_attachments,
)

log = logging.getLogger(__name__)

# Keys ``_make_mail()`` sets itself after walking the headers.  A sender can
# name a header after any of them, so they are skipped while collecting
# headers: otherwise ``mail["defects"]`` would hold a string from the wire
# instead of the list of parsed defects.
_RESERVED_MAIL_KEYS = frozenset({"defects", "defects_categories", "has_defects"})


def parse_from_file_obj(fp):
    """
    Parsing email from a file-like object.

    Args:
        fp (file-like object): file-like object of raw email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_file_obj(fp)


def parse_from_file(fp):
    """
    Parsing email from file.

    Args:
        fp (string): file path of raw email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_file(fp)


def parse_from_file_msg(fp):
    """
    Parsing email from file Outlook msg.

    Args:
        fp (string): file path of raw Outlook email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_file_msg(fp)


def parse_from_string(s):
    """
    Parsing email from string.

    Args:
        s (string): raw email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_string(s)


def parse_from_bytes(bt):
    """
    Parsing email from bytes. Only for Python 3

    Args:
        bt (bytes-like object): raw email as bytes-like object

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_bytes(bt)


class MailParser:
    """
    MailParser package provides a standard parser that understands
    most email document structures like official email package.
    MailParser handles the encoding of email and split the raw email for you.

    Headers:
    https://www.iana.org/assignments/message-headers/message-headers.xhtml
    """

    def __init__(self, message=None):
        """
        Init a new object from a message object structure.
        """
        self._message = message
        # Set before parse() so that __getattr__ is never reached for this
        # attribute — it resolves unknown names as headers instead of
        # raising AttributeError, which would recurse.
        self._header_index = {}
        if message is not None:
            log.debug("All headers of emails: {}".format(", ".join(message.keys())))
        self.parse()

    def __str__(self) -> str:
        if self.message:
            return str(self.subject)
        else:
            return str()

    @classmethod
    def _parse_guarded(cls, build_message):
        """
        Build the email message and parse it, converting a ``RecursionError``
        into ``MailParserRecursionError``.

        Python's ``email`` parser recurses once per ``multipart/*`` nesting
        level, so a crafted deeply nested message would otherwise raise a bare
        ``RecursionError`` that escapes the ``MailParser*`` hierarchy and can
        crash the calling worker (an availability DoS on attacker-supplied
        input).

        Args:
            build_message (callable): zero-argument callable returning the
                ``email.message.Message`` to parse.

        Returns:
            Instance of MailParser.

        Raises:
            MailParserRecursionError: if the message is nested too deeply.
        """
        try:
            message = build_message()
            return cls(message)
        except RecursionError as exc:
            raise MailParserRecursionError(
                "Message nesting too deep to parse "
                "(possible malicious multipart structure)"
            ) from exc

    @classmethod
    def from_file_obj(cls, fp):
        """
        Init a new object from a file-like object.
        Not for Outlook msg.

        Args:
            fp (file-like object): file-like object of raw email

        Returns:
            Instance of MailParser
        """
        log.debug("Parsing email from file object")
        try:
            fp.seek(0)
        except OSError:
            # When stdout is a TTY it's a character device
            # and it's not seekable, you cannot seek in a TTY.
            pass
        finally:
            s = fp.read()

        return cls.from_string(s)

    @classmethod
    def from_file(cls, fp, is_outlook=False):
        """
        Init a new object from a file path.

        Args:
            fp (string): file path of raw email
            is_outlook (boolean): if True is an Outlook email

        Returns:
            Instance of MailParser
        """
        log.debug(f"Parsing email from file {fp!r}")

        def _build():
            try:
                with ported_open(fp) as f:
                    return email.message_from_file(f)
            finally:
                # ``fp`` is a temp file produced by the Outlook conversion;
                # remove it even if parsing raises, so failures do not leak
                # temp files.
                if is_outlook:
                    log.debug(f"Removing temp converted Outlook email {fp!r}")
                    _safe_remove(fp)

        return cls._parse_guarded(_build)

    @classmethod
    def from_file_msg(cls, fp):
        """
        Init a new object from a Outlook message file,
        mime type: application/vnd.ms-outlook

        Conversion backend precedence:
          1. ``extract-msg`` (pure Python, optional ``outlook`` extra).
          2. ``msgconvert`` external Perl tool — **deprecated** fallback,
             used only when ``extract-msg`` is not installed.

        Args:
            fp (string): file path of raw Outlook email

        Returns:
            Instance of MailParser

        Raises:
            MailParserOSError: if no conversion backend is available
        """
        log.debug("Parsing email from file Outlook")

        if importlib.util.find_spec("extract_msg") is not None:
            f, _ = extract_msg_convert(fp)
        else:
            log.warning(
                "msgconvert backend is deprecated and will be removed "
                "in a future release. Install the pure-Python Outlook "
                "support with 'pip install mail-parser[outlook]'."
            )
            f, _ = msgconvert(fp)

        return cls.from_file(f, True)

    @classmethod
    def from_string(cls, s):
        """
        Init a new object from a string.

        Args:
            s (string): raw email

        Returns:
            Instance of MailParser
        """

        log.debug("Parsing email from string")
        return cls._parse_guarded(lambda: email.message_from_string(s))

    @classmethod
    def from_bytes(cls, bt):
        """
        Init a new object from bytes.

        Args:
            bt (bytes-like object): raw email as bytes-like object

        Returns:
            Instance of MailParser
        """
        log.debug("Parsing email from bytes")
        return cls._parse_guarded(lambda: email.message_from_bytes(bt))

    def _reset(self):
        """
        Reset the state of mail object.
        """
        log.debug("Reset all variables")

        self._attachments = []
        self._text_plain = []
        self._text_html = []
        self._text_not_managed = []
        self._defects = []
        self._defects_categories = set()
        self._has_defects = False
        self._mail = {}
        self._mail_partial = {}
        self._header_index = self._build_header_index()

    def _build_header_index(self):
        """
        Build a lowercased name -> list of raw values map of every header.

        ``Message.get_all()`` is a linear scan of the header list, so the
        one call per distinct header name made by ``_make_mail()`` and
        ``headers`` costs O(distinct x total).  Header names are chosen by
        the sender and are free to generate, which turns that quadratic
        term into a denial of service (CWE-407): before this index, 16,000
        distinct names cost ~5.8 s of CPU against ~0.06 s for 32,000
        repeats of a single name.  Indexing once makes every lookup O(1).

        Returns:
            dict mapping a lowercased header name to its list of raw values
        """
        index = {}
        if self.message:
            for name, value in self.message.items():
                index.setdefault(name.lower(), []).append(value)
        return index

    def _header_value(self, name):
        """
        Return the value of a header named exactly ``name``.

        This is the resolver for names that come off the wire.
        ``_make_mail()`` and ``headers`` iterate the sender's header names,
        so it does two things that ``__getattr__`` must not do here.

        It performs **no attribute lookup**.  ``getattr(self, name)`` would
        let the sender choose which attribute is read, because Python
        resolves real class attributes before ``__getattr__``: a ``Parse:``
        header stored a bound method in the parsed mail and ``mail_json``
        raised ``TypeError`` (CWE-407), and a ``Headers_json:`` header
        re-entered the ``headers`` property until the stack was exhausted.

        It also performs **no name rewriting**: the name is looked up
        literally, with no ``_``/``-`` folding and no ``_json`` / ``_raw``
        suffix handling.  Those conveniences exist for the caller's benefit
        and are actively harmful on a sender-chosen name — ``Subject_json:``
        would report the value of ``Subject`` and drop its own (CWE-436),
        and each ``_json`` suffix re-serialized the previous result, so
        ``X_json_json...`` bought one doubling of the output per five input
        bytes: a 148-byte header produced a 536 MB string (CWE-405).

        Args:
            name (string): header name exactly as it appears in the message

        Returns:
            list of (name, address) tuples for the address headers,
            otherwise the decoded header value (str, or list when the
            header repeats), or an empty str when the header is absent
        """
        name_header = name.lower()

        # object headers
        if name_header in ADDRESSES_HEADERS:
            values = self._header_index.get(name_header)
            # ``Message.get()`` semantics: only the first occurrence
            raw_header = values[0] if values else ""
            # Parse addresses. RFC 5322 §3.4 does not allow unquoted "@" in
            # display names, so a strict parser correctly rejects headers like
            #   From: alice@example.com <bob@example.com>
            # and returns ('', '').  mail-parser is a security/forensics tool,
            # not an MTA: hiding addresses from analysts is worse than accepting
            # non-conforming input.  get_addresses() applies a regex fallback
            # when strict parsing yields only empty results — see its docstring
            # in utils.py for the full rationale.
            parsed_addresses = get_addresses(raw_header)

            # decoded addresses — skip entries with no address (absent header)
            return [
                (
                    (
                        ""
                        if (decoded_name := decode_header_part(name)) == email_addr
                        else decoded_name
                    ),
                    email_addr,
                )
                for name, email_addr in parsed_addresses
                if email_addr
            ]

        # others headers
        return decode_headers(self._header_index.get(name_header))

    def _append_defects(self, part, part_content_type):
        """
        Add new defects and defects categories to object attributes.

        The defects are a list of all the problems found
        when parsing this message.

        Args:
            part (string): mail part
            part_content_type (string): content type of part
        """

        part_defects = {}

        for e in part.defects:
            defects = f"{e.__class__.__name__}: {e.__doc__}"
            self._defects_categories.add(e.__class__.__name__)
            part_defects.setdefault(part_content_type, []).append(defects)
            log.debug(f"Added defect {defects!r}")

        # Tag mail with defect
        if part_defects:
            self._has_defects = True

            # Save all defects
            self._defects.append(part_defects)

    def _make_mail(self, complete=True):
        """
        This method assigns the right values to all tokens of email.
        Returns a parsed object

        Keyword Arguments:
            complete {bool} -- If True returns all mails parts
                                (default: {True})

        Returns:
            dict -- Parsed email object
        """

        mail = {}
        keys = get_mail_keys(self.message, complete)

        for i in keys:
            log.debug(f"Getting header or part {i!r}")
            if i in _RESERVED_MAIL_KEYS:
                # A header of this name would shadow the defect metadata
                # below with a value of a different type.  Still reachable
                # by the caller as ``parser.<name>_raw``.
                continue
            # Only the computed parts are our own names and may be reached
            # through attribute access; every other key is a header name
            # chosen by the sender — see _header_value().
            value = getattr(self, i) if i in COMPUTED_PARTS else self._header_value(i)
            if value:
                mail[i] = value

        # add defects
        mail["has_defects"] = self.has_defects
        if self.has_defects:
            mail["defects"] = self.defects
            mail["defects_categories"] = list(self.defects_categories)

        return mail

    def parse(self):
        """
        This method parses the raw email and makes the tokens.

        Returns:
            Instance of MailParser with raw email parsed
        """

        # Reset first, so every attribute exists even when there is nothing
        # to parse.  Otherwise a property reading an unset attribute raises
        # AttributeError, which __getattr__ silently answers as an absent
        # header, and the caller sees "" instead of a failure.
        self._reset()

        # ``Message.__len__`` is the header count, so a message with no
        # headers at all is falsy: test against None, or a body-only
        # message parses to nothing and reports no defect.
        if self.message is None:
            return self

        parts = []  # Normal parts plus defects

        # walk all mail parts to search defects
        for p in self.message.walk():
            part_content_type = p.get_content_type()
            self._append_defects(p, part_content_type)
            parts.append(p)

        # If defects are in epilogue defects get epilogue
        if self.defects_categories & EPILOGUE_DEFECTS:
            log.debug("Found defects in emails")
            epilogue = find_between(
                self.message.epilogue,
                "{}".format("--" + self.message.get_boundary()),
                "{}".format("--" + self.message.get_boundary() + "--"),
            )

            if epilogue is not None:
                try:
                    p = email.message_from_string(epilogue)
                    parts.append(p)
                except Exception:
                    log.error("Failed to get epilogue part. Check raw mail.")

        # walk all mail parts
        for i, p in enumerate(parts):
            if (
                not p.is_multipart()
                or ported_string(p.get_content_disposition()).lower() == "attachment"
            ):
                charset = p.get_content_charset("utf-8")
                charset_raw = p.get_content_charset()
                log.debug(f"Charset {charset!r} part {i!r}")
                content_disposition = ported_string(p.get_content_disposition()).lower()
                log.debug(f"content-disposition {content_disposition!r} part {i!r}")
                content_id = ported_string(p.get("content-id"))
                log.debug(f"content-id {content_id!r} part {i!r}")
                content_subtype = ported_string(p.get_content_subtype())
                log.debug(f"content subtype {content_subtype!r} part {i!r}")
                filename = decode_header_part(p.get_filename())

                is_attachment = False
                if filename:
                    is_attachment = True
                else:
                    if content_id and content_subtype not in ("html", "plain"):
                        is_attachment = True
                        filename = content_id
                    elif content_subtype in ("rtf"):
                        is_attachment = True
                        filename = f"{random_string()}.rtf"
                    elif content_disposition == "attachment":
                        is_attachment = True
                        filename = f"{random_string()}.txt"

                # this is an attachment
                if is_attachment:
                    log.debug(f"Email part {i!r} is an attachment")
                    log.debug(f"Filename {filename!r} part {i!r}")
                    binary = False
                    mail_content_type = ported_string(p.get_content_type())
                    log.debug(f"Mail content type {mail_content_type!r} part {i!r}")
                    # Strip before comparing, exactly as email's own
                    # get_payload() does: a trailing space made every
                    # encoding branch below miss and the raw bytes fall
                    # through the text path, which drops the non-UTF-8 ones.
                    transfer_encoding = (
                        ported_string(p.get("content-transfer-encoding", ""))
                        .strip()
                        .lower()
                    )
                    log.debug(f"Transfer encoding {transfer_encoding!r} part {i!r}")
                    content_disposition = ported_string(p.get("content-disposition"))
                    log.debug(f"content-disposition {content_disposition!r} part {i!r}")

                    if p.is_multipart():
                        payload = "".join(
                            [as_string_safe(m) for m in p.get_payload(decode=False)]
                        )
                        binary = False
                        log.debug(f"Filename {filename!r} part {i!r} is multipart")
                    elif transfer_encoding == "base64":
                        payload = raw_payload(p)
                        if not isinstance(payload, str):
                            # The declared charset could not be applied, so
                            # the wire text is not recoverable: re-encode the
                            # decoded bytes to keep the payload base64.
                            payload = base64.b64encode(payload).decode("ascii")
                        binary = True
                        log.debug(f"Filename {filename!r} part {i!r} is binary")
                    else:
                        # Every other encoding — uuencode, quoted-printable,
                        # 7bit, 8bit, binary — is re-encoded to base64 from
                        # the decoded bytes.  An attachment is a file, not
                        # text: reading it back through a charset dropped
                        # every byte that charset cannot represent (half of a
                        # binary payload), so the extracted file was neither
                        # the attachment nor the bytes on the wire, and its
                        # hash never matched what the recipient received.
                        payload = base64.b64encode(p.get_payload(decode=True)).decode(
                            "ascii"
                        )
                        binary = True
                        log.debug(
                            f"Filename {filename!r} part {i!r} is binary"
                            f" ({transfer_encoding!r} re-encoded to base64)"
                        )
                        transfer_encoding = "base64"

                    try:
                        safe_filename = _safe_attachment_filename(filename)
                    except ValueError:
                        safe_filename = None

                    self._attachments.append(
                        {
                            "filename": filename,
                            "safe_filename": safe_filename,
                            "payload": payload,
                            "binary": binary,
                            "mail_content_type": mail_content_type,
                            "content-id": content_id,
                            "content-disposition": content_disposition,
                            "charset": charset_raw,
                            "content_transfer_encoding": transfer_encoding,
                        }
                    )

                # this isn't an attachments
                else:
                    log.debug(f"Email part {i!r} is not an attachment")

                    payload = p.get_payload(decode=True)
                    # Strip as well, for the same reason as the attachment
                    # branch above: a trailing space sent the part down the
                    # else branch, which re-reads the text through
                    # raw-unicode-escape and turns it into literal escapes.
                    cte = (
                        ported_string(p.get("Content-Transfer-Encoding", ""))
                        .strip()
                        .lower()
                    )

                    if not cte or cte in ["7bit", "8bit"]:
                        # message_from_bytes stores non-ASCII body bytes via
                        # ascii+surrogateescape, producing surrogates in the
                        # payload string.  message_from_string stores a proper
                        # Unicode str (no surrogates).  Detect which case we
                        # have via get_payload(decode=False) and decode
                        # accordingly so the declared charset is honoured.
                        raw_str = raw_payload(p)
                        if isinstance(raw_str, str):
                            try:
                                # Raises if surrogates present (from_bytes path)
                                raw_str.encode("utf-8")
                                payload = raw_str
                            except UnicodeEncodeError:
                                # These encodings are not transformed by
                                # get_payload(decode=True), so ``payload``
                                # already holds the original bytes.
                                payload = ported_string(payload, encoding=charset)
                        else:
                            payload = ported_string(payload, encoding=charset)
                    else:
                        payload = ported_string(payload, encoding=charset)

                    if payload:
                        if p.get_content_subtype() == "html":
                            self._text_html.append(payload)
                        elif p.get_content_subtype() == "plain":
                            self._text_plain.append(payload)
                        else:
                            log.warning(
                                f"Email content {p.get_content_subtype()!r} not handled"
                            )
                            self._text_not_managed.append(payload)

        # Parsed object mail with all parts
        self._mail = self._make_mail()

        # Parsed object mail with mains parts
        self._mail_partial = self._make_mail(complete=False)

    def get_server_ipaddress(self, trust):
        """
        Return the ip address of sender

        Overview:
        Extract a reliable sender IP address heuristically for each message.
        Although the message format dictates a chain of relaying IP
        addresses in each message, a malicious relay can easily alter that.
        Therefore we cannot simply take the first IP in
        the chain. Instead, our method is as follows.
        First we trust the sender IP reported by our mail server in the
        Received headers, and if the previous relay IP address is on our trust
        list (e.g. other well-known mail services), we continue to
        follow the previous Received line, till we reach the first unrecognized
        IP address in the email header.

        From article Characterizing Botnets from Email Spam Records:
            Li Zhuang, J. D. Tygar

        In our case we trust only our mail server with the trust string.

        The walk continues only while a trusted hop names a *private* IP,
        which marks an internal relay.  A trusted hop naming no IP at all
        ends the search with ``None``: extraction failing there used to
        drop the loop into older Received headers, which the sender wrote,
        so every trick that defeats extraction on the genuine hop returned
        an attacker-chosen IP instead of nothing (CWE-345).

        Args:
            trust (string): String that identify our mail server

        Returns:
            string with the ip address, or None when no trusted hop names
            a public sender IP
        """
        log.debug(f"Trust string is {trust!r}")

        if not trust.strip():
            return

        if not self.message:
            return

        received = self.message.get_all("received", [])

        for i in received:
            i = ported_string(i)
            if trust not in i:
                continue

            log.debug(f"Trust string {trust!r} is in {i!r}")
            candidates = self._sender_ip_candidates(i)
            if not candidates:
                # Nothing to read on an authoritative hop: stop, never fall
                # through to a header the sender controls.
                log.debug("Trusted hop names no sender IP, stopping")
                return None

            ip_str = self._public_ip(candidates)
            if ip_str:
                return ip_str
            # Private IP: an internal relay, keep following the chain.

    def _sender_ip_candidates(self, received_header):
        """
        Return the IP addresses named in the ``from`` clause of a header.

        Only the ``from`` clause is searched: the ``by`` clause holds the
        receiving server, whose IP must never be reported as the sender's.
        The clause is isolated with ``get_from_clause()``, which anchors on
        the RFC 5321 keywords — see its docstring for why a substring
        search for ``"by"`` is spoofable (CWE-345).

        Within the clause exactly two regions are sender-written, and both
        are excluded rather than trusted to look harmless:

        * **the first token** — the HELO name.  It may be an address
          literal (``EHLO [8.8.8.8]``, the form RFC 5321 §4.1.3 requires of
          a client with no FQDN), so it is never a candidate.
        * **an explicit HELO argument** inside a comment — Exim's
          ``(helo=x)``, CommuniGate's ``(account a@b HELO x)``.

        Everything else was written by the receiving MTA, and a candidate
        must additionally sit inside a ``(``/``[`` group, which is where an
        MTA puts its own findings.  That last rule is what makes a
        truncated clause fail closed: a multi-word HELO can end the clause
        early, but whatever it leaves behind is bare and so is not a
        candidate.

        The one concession is the Exim/CommuniGate layout ``from [ip]
        (helo=x)``, where the MTA writes the address as the first token
        precisely because it recorded the HELO name separately.  It is
        accepted only when no other candidate exists and the HELO marker
        is itself inside a group — the residual is a sender who writes
        comment syntax into their own HELO name *and* whose MTA records it
        verbatim, on a hop naming no other address.

        Args:
            received_header (string): The received header string

        Returns:
            list of IP address strings, in the order they appear
        """
        # Blank the "IPv6:" tag with a non-space filler of the same width:
        # offsets stay aligned, and no new token boundary or _HELO_RE
        # lookbehind position is created inside the sender's own token.
        from_part = _IPV6_TAG_RE.sub("_____", get_from_clause(received_header))
        if not from_part:
            return []

        groups = group_spans(from_part)
        helo_spans = [
            m.span()
            for m in _HELO_RE.finditer(from_part)
            if in_spans(m.start(), groups)
        ]
        first_token_end = len(from_part.split(" ", 1)[0])

        # Merge both families positionally.  Choosing IPv4 over IPv6 by
        # family let one private literal at EHLO suppress the IPv6 scan and
        # hide the real sender.
        matches = sorted(
            list(REGXIP.finditer(from_part)) + list(REGXIP6.finditer(from_part)),
            key=lambda m: m.start(),
        )
        matches = [m for m in matches if not in_spans(m.start(), helo_spans)]

        candidates = [
            m.group()
            for m in matches
            if m.start() >= first_token_end and in_spans(m.start(), groups)
        ]
        if candidates:
            return candidates

        if helo_spans:
            # Exim/CommuniGate: the address is the first token because the
            # HELO name was recorded in the comment instead.
            return [m.group() for m in matches if m.start() < first_token_end]

        return []

    def _public_ip(self, check):
        """
        Return the last candidate address, if it parses and is public.

        Args:
            check (list): IP address strings from a ``from`` clause

        Returns:
            string with the ip address or None
        """
        if check:
            try:
                ip_str = str(check[-1])
                log.debug(f"Found sender IP {ip_str!r}")
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                return None
            else:
                if not ip.is_private:
                    log.debug(f"IP {ip_str!r} not private")
                    return ip_str
        return None

    def _extract_ip(self, received_header):
        """
        Extract the sender IP from a received header if it is not private.
        Supports both IPv4 (RFC 791) and IPv6 (RFC 5952) addresses.

        Args:
            received_header (string): The received header string

        Returns:
            string with the ip address or None
        """
        return self._public_ip(self._sender_ip_candidates(received_header))

    def write_attachments(self, base_path):
        """This method writes the attachments of mail on disk

        Arguments:
            base_path {str} -- Base path where write the attachments
        """
        write_attachments(attachments=self.attachments, base_path=base_path)

    def __getattr__(self, name):
        """
        Expose any header dynamically as ``X``, ``X_json`` or ``X_raw``.

        Underscores in ``name`` stand for dashes, so ``mail.X_MSMail_Priority``
        reads the ``X-MSMail-Priority`` header.  Only reached for names the
        *caller* asks for, so ``X_json`` may resolve through ``getattr`` and
        reach the computed parts — ``attachments_json`` and friends.  Names
        taken from a parsed message must never come through here;
        ``_header_value()`` serves those, and its docstring explains why.

        Raises:
            AttributeError: for private names.  Without this, an unset
                internal attribute is answered as an absent header and a
                bug inside a property is silently reported as "".
        """
        if name.startswith("_"):
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute {name!r}"
            )

        name = name.rstrip("_").lower()

        if name.endswith("_json"):
            return json.dumps(getattr(self, name[:-5]), ensure_ascii=False)

        if name.endswith("_raw"):
            raw = self._header_index.get(name[:-4].replace("_", "-")) or []
            # Values are ``email.header.Header`` when the header carries
            # 8-bit bytes (the from_bytes path); dumping one raises
            # TypeError and kills the parse, so coerce to str first.
            return json.dumps([ported_string(i) for i in raw], ensure_ascii=False)

        return self._header_value(name.replace("_", "-"))

    @property
    def attachments(self):
        """
        Return a list of all attachments in the mail.

        The ``filename`` value is decoded from untrusted email metadata and
        must not be used directly to construct filesystem paths. Use
        ``write_attachments()`` when saving attachments. ``safe_filename``
        contains a sanitized basename, or ``None`` if no usable basename exists.
        """
        return self._attachments

    @property
    def received(self):
        """
        Return a list of all received headers parsed
        """
        output = self.received_raw
        return receiveds_parsing(output)

    @property
    def received_json(self):
        """
        Return a JSON of all received headers
        """
        return json.dumps(self.received, ensure_ascii=False, indent=2)

    @property
    def received_raw(self):
        """
        Return a list of all received headers in raw format
        """
        output = []
        for i in self.message.get_all("received", []) if self.message else []:
            output.append(decode_header_part(i))
        return output

    @property
    def body(self):
        """
        Return all text plain and text html parts of mail delimited from string
        "--- mail_boundary ---"
        """
        return "\n--- mail_boundary ---\n".join(
            self.text_plain + self.text_html + self.text_not_managed
        )

    @property
    def headers(self) -> dict:
        """
        Return only the headers as Python object.

        Values resolve through ``_header_value()``, never ``getattr``: the
        keys come straight from the sender, so attribute lookup on them
        returns bound methods (``Parse:``) or re-enters this very property
        (``Headers_json:``).  Excluding single names from the key set is
        not a fix — it is what let ``Headers_json`` through after
        ``Headers`` was excluded.
        """
        # Dedupe case-insensitively, keeping the first spelling seen as the
        # key.  Header names are compared case-insensitively, so _header_value
        # returns every occurrence for each of them: deduping on the exact
        # spelling instead would emit one full value list per casing, and a
        # sender repeating one 20-char name in n casings would get an n x n
        # blowup (CWE-407) — 271 KB of headers cost 7.6 s and 540 MB of JSON.
        names = {}
        for i in self.message.keys() if self.message else []:
            names.setdefault(i.lower(), i)
        return {i: self._header_value(i) for i in names.values()}

    @property
    def headers_json(self):
        """
        Return the JSON of headers
        """
        return json.dumps(self.headers, ensure_ascii=False, indent=2)

    @property
    def text_plain(self):
        """
        Return a list of all text plain parts of email.
        """
        return self._text_plain

    @property
    def text_html(self):
        """
        Return a list of all text html parts of email.
        """
        return self._text_html

    @property
    def text_not_managed(self):
        """
        Return a list of all text not managed of email.
        """
        return self._text_not_managed

    @property
    def date(self):
        """
        Return the mail date in datetime.datetime format and UTC.
        """
        date = self.message.get("date") if self.message else None
        conv = None

        try:
            conv, _ = convert_mail_date(date)
        except Exception:
            pass
        return conv

    @property
    def timezone(self):
        """
        Return timezone. Offset from UTC.
        """
        date = self.message.get("date") if self.message else None
        timezone = 0

        try:
            _, timezone = convert_mail_date(date)
        except Exception:
            pass
        return timezone

    @property
    def date_json(self):
        """
        Return the JSON of date
        """
        if self.date:
            return json.dumps(self.date.isoformat(), ensure_ascii=False)

    @property
    def mail(self):
        """
        Return the Python object of mail parsed
        """
        return self._mail

    @property
    def mail_json(self):
        """
        Return the JSON of mail parsed
        """
        if self.mail.get("date") and self.date:
            self._mail["date"] = self.date.isoformat()
        return json.dumps(self.mail, ensure_ascii=False, indent=2)

    @property
    def mail_partial(self):
        """
        Return the Python object of mail parsed
        with only the mains headers
        """
        return self._mail_partial

    @property
    def mail_partial_json(self):
        """
        Return the JSON of mail parsed partial
        """
        if self.mail_partial.get("date") and self.date:
            self._mail_partial["date"] = self.date.isoformat()
        return json.dumps(self.mail_partial, ensure_ascii=False, indent=2)

    @property
    def defects(self):
        """
        The defects property contains a list of
        all the problems found when parsing this message.
        """
        return self._defects

    @property
    def defects_categories(self):
        """
        Return a set with only defects categories.
        """
        return self._defects_categories

    @property
    def has_defects(self):
        """
        Return a boolean: True if mail has defects.
        """
        return self._has_defects

    @property
    def message(self):
        """
        email.message.Message class.
        """
        return self._message

    @property
    def message_as_string(self):
        """
        Return the entire message flattened as a string.
        """
        return as_string_safe(self.message) if self.message else ""

    @property
    def to_domains(self):
        """
        Return all domain of 'to' and 'reply-to' email addresses
        """
        return get_to_domains(self.to, self.reply_to)
