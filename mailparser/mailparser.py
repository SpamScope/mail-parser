#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

from __future__ import unicode_literals
import base64
import email
import logging
import os

import uuid
import ipaddress
import six
import simplejson as json

from .const import (
    ADDRESSES_HEADERS,
    EPILOGUE_DEFECTS,
    REGXIP)

from .utils import (
    convert_mail_date,
    decode_header_part,
    find_between,
    get_header,
    get_mail_keys,
    get_to_domains,
    msgconvert,
    ported_open,
    ported_string,
    random_string,
    receiveds_parsing,
    write_attachments,
)

from .exceptions import MailParserEnvironmentError


log = logging.getLogger(__name__)


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


class MailParser(object):
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
        log.debug(
            "All headers of emails: {}".format(", ".join(message.keys())))
        self.parse()

    def __str__(self):
        if self.message:
            return self.subject
        else:
            return six.text_type()

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
        except IOError:
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
        log.debug("Parsing email from file {!r}".format(fp))

        with ported_open(fp) as f:
            message = email.message_from_file(f)

        if is_outlook:
            log.debug("Removing temp converted Outlook email {!r}".format(fp))
            os.remove(fp)

        return cls(message)

    @classmethod
    def from_file_msg(cls, fp):
        """
        Init a new object from a Outlook message file,
        mime type: application/vnd.ms-outlook

        Args:
            fp (string): file path of raw Outlook email

        Returns:
            Instance of MailParser
        """
        log.debug("Parsing email from file Outlook")
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
        message = email.message_from_string(s)
        return cls(message)

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
        if six.PY2:
            raise MailParserEnvironmentError(
                "Parsing from bytes is valid only for Python 3.x version")
        message = email.message_from_bytes(bt)
        return cls(message)

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
            defects = "{}: {}".format(e.__class__.__name__, e.__doc__)
            self._defects_categories.add(e.__class__.__name__)
            part_defects.setdefault(part_content_type, []).append(defects)
            log.debug("Added defect {!r}".format(defects))

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
            log.debug("Getting header or part {!r}".format(i))
            value = getattr(self, i)
            if value:
                mail[i] = value

        # add defects
        mail["has_defects"] = self.has_defects
        if self.has_defects:
            mail["defects"] = self.defects
            mail["defects_categories"] = list(self.defects_categories)

        return mail
    

    def walk(self, msg, parent=None):
        if not parent or parent.get_content_type() != "message/rfc822":
            yield msg
            if msg.is_multipart():
                for subpart in msg.get_payload():
                    yield from self.walk(subpart, parent=msg)        


    def parse(self):
        """
        This method parses the raw email and makes the tokens.

        Returns:
            Instance of MailParser with raw email parsed
        """

        if not self.message:
            return self

        # reset and start parsing
        self._reset()
        parts = []  # Normal parts plus defects

        # walk all mail parts to search defects
        for p in self.walk(self.message):
            part_content_type = p.get_content_type()
            self._append_defects(p, part_content_type)
            parts.append(p)

        # If defects are in epilogue defects get epilogue
        if self.defects_categories & EPILOGUE_DEFECTS:
            log.debug("Found defects in emails")
            epilogue = find_between(
                self.message.epilogue,
                "{}".format("--" + self.message.get_boundary()),
                "{}".format("--" + self.message.get_boundary() + "--"))

            try:
                p = email.message_from_string(epilogue)
                parts.append(p)
            except TypeError:
                log.debug("Failed to get epilogue part for TypeError")
            except Exception:
                log.error("Failed to get epilogue part. Check raw mail.")

        # walk all mail parts
        for i, p in enumerate(parts):
            if not p.is_multipart():
                charset = p.get_content_charset('utf-8')
                charset_raw = p.get_content_charset()
                log.debug("Charset {!r} part {!r}".format(charset, i))
                content_disposition = ported_string(
                    p.get('content-disposition'))
                log.debug("content-disposition {!r} part {!r}".format(
                    content_disposition, i))
                content_id = ported_string(p.get('content-id'))
                log.debug("content-id {!r} part {!r}".format(
                    content_id, i))
                content_subtype = ported_string(p.get_content_subtype())
                log.debug("content subtype {!r} part {!r}".format(
                    content_subtype, i))
                filename = decode_header_part(p.get_filename())

                is_attachment = False
                if filename:
                    is_attachment = True
                else:
                    if content_id and content_subtype not in ('html', 'plain'):
                        is_attachment = True
                        filename = content_id
                    elif content_subtype in ('rtf'):
                        is_attachment = True
                        filename = "{}.rtf".format(random_string())

                # this is an attachment
                if is_attachment:
                    log.debug("Email part {!r} is an attachment".format(i))
                    log.debug("Filename {!r} part {!r}".format(filename, i))
                    binary = False
                    mail_content_type = ported_string(p.get_content_type())
                    log.debug("Mail content type {!r} part {!r}".format(
                        mail_content_type, i))
                    transfer_encoding = ported_string(
                        p.get('content-transfer-encoding', '')).lower()
                    log.debug("Transfer encoding {!r} part {!r}".format(
                        transfer_encoding, i))
                    content_disposition = ported_string(
                        p.get('content-disposition'))
                    log.debug("content-disposition {!r} part {!r}".format(
                        content_disposition, i))

                    if transfer_encoding == "base64" or (
                       transfer_encoding == "quoted-\
                       printable" and "application" in mail_content_type):

                        payload = p.get_payload(decode=False)
                        binary = True
                        log.debug("Filename {!r} part {!r} is binary".format(
                            filename, i))
                    elif "uuencode" in transfer_encoding:
                        # Re-encode in base64
                        payload = base64.b64encode(
                            p.get_payload(decode=True)).decode('ascii')
                        binary = True
                        transfer_encoding = "base64"
                        log.debug("Filename {!r} part {!r} is binary (uuencode"
                                  " re-encoded to base64)".format(filename, i))
                    else:
                        payload = ported_string(
                            p.get_payload(decode=True), encoding=charset)
                        log.debug(
                            "Filename {!r} part {!r} is not binary".format(
                                filename, i))

                    self._attachments.append({
                        "filename": filename,
                        "payload": payload,
                        "binary": binary,
                        "mail_content_type": mail_content_type,
                        "content-id": content_id,
                        "content-disposition": content_disposition,
                        "charset": charset_raw,
                        "content_transfer_encoding": transfer_encoding})

                # this isn't an attachments
                else:
                    log.debug("Email part {!r} is not an attachment".format(i))

                    # Get the payload using get_payload method with decode=True
                    # As Python truly decodes only 'base64',
                    # 'quoted-printable', 'x-uuencode',
                    # 'uuencode', 'uue', 'x-uue'
                    # And for other encodings it breaks the characters so
                    # we need to decode them with encoding python is appying
                    # To maintain the characters
                    payload = p.get_payload(decode=True)
                    cte = p.get('Content-Transfer-Encoding')
                    if cte:
                        cte = cte.lower()
                    if not cte or cte in ['7bit', '8bit']:
                        payload = payload.decode('raw-unicode-escape')
                    else:
                        payload = ported_string(payload, encoding=charset)

                    if payload:
                        if p.get_content_subtype() == 'html':
                            self._text_html.append(payload)
                        elif p.get_content_subtype() == 'plain':
                            self._text_plain.append(payload)
                        else:
                            log.warning(
                                'Email content {!r} not handled'.format(
                                    p.get_content_subtype()))
                            self._text_not_managed.append(payload)
            elif p.get_content_type() in ["message/rfc822"]:
                content_id = ported_string(p.get('content-id'))
                content_disposition = ported_string(p.get('content-disposition'))
                charset_raw = p.get_content_charset()
                filename = decode_header_part(p.get_filename("{}".format(content_id)))
                transfer_encoding = ported_string(p.get('content-transfer-encoding', '')).lower()
                payload = p.get_payload(decode=False)[0]
                mail_content_type = ported_string(p.get_content_type())
                self._attachments.append({
                    "filename": filename if filename else str(uuid.uuid4()),
                    "payload": payload,
                    "mail_content_type": mail_content_type,
                    "content-id": content_id,
                    "content-disposition": content_disposition,
                    "charset": charset_raw,
                    "content_transfer_encoding": transfer_encoding,
                    "message": True})
        else:
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

        Args:
            trust (string): String that identify our mail server

        Returns:
            string with the ip address
        """
        log.debug("Trust string is {!r}".format(trust))

        if not trust.strip():
            return

        received = self.message.get_all("received", [])

        for i in received:
            i = ported_string(i)
            if trust in i:
                log.debug("Trust string {!r} is in {!r}".format(trust, i))
                check = REGXIP.findall(i[0:i.find("by")])

                if check:
                    try:
                        ip_str = six.text_type(check[-1])
                        log.debug("Found sender IP {!r} in {!r}".format(
                            ip_str, i))
                        ip = ipaddress.ip_address(ip_str)
                    except ValueError:
                        return
                    else:
                        if not ip.is_private:
                            log.debug("IP {!r} not private".format(ip_str))
                            return ip_str

    def write_attachments(self, base_path):
        """ This method writes the attachments of mail on disk

        Arguments:
            base_path {str} -- Base path where write the attachments
        """
        write_attachments(
            attachments=self.attachments,
            base_path=base_path)

    def __getattr__(self, name):
        name = name.strip("_").lower()
        name_header = name.replace("_", "-")

        # json headers
        if name.endswith("_json"):
            name = name[:-5]
            return json.dumps(getattr(self, name), ensure_ascii=False)

        # raw headers
        elif name.endswith("_raw"):
            name = name[:-4]
            raw = self.message.get_all(name)
            return json.dumps(raw, ensure_ascii=False)

        # object headers
        elif name_header in ADDRESSES_HEADERS:
            h = decode_header_part(self.message.get(
                name_header, six.text_type()))
            return email.utils.getaddresses([h])

        # others headers
        else:
            return get_header(self.message, name_header)

    @property
    def attachments(self):
        """
        Return a list of all attachments in the mail
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
        for i in self.message.get_all("received", []):
            output.append(decode_header_part(i))
        return output

    @property
    def body(self):
        """
        Return all text plain and text html parts of mail delimited from string
        "--- mail_boundary ---"
        """
        return "\n--- mail_boundary ---\n".join(
            self.text_plain + self.text_html + self.text_not_managed)

    @property
    def headers(self):
        """
        Return only the headers as Python object
        """
        d = {}
        for i in self.message.keys():
            d[i] = getattr(self, i)
        return d

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
        date = self.message.get('date')
        conv = None

        try:
            conv, _ = convert_mail_date(date)
        finally:
            return conv

    @property
    def timezone(self):
        """
        Return timezone. Offset from UTC.
        """
        date = self.message.get('date')
        timezone = 0

        try:
            _, timezone = convert_mail_date(date)
        finally:
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
        if self.mail.get("date"):
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
        if self.mail_partial.get("date"):
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
        return self.message.as_string()

    @property
    def to_domains(self):
        """
        Return all domain of 'to' and 'reply-to' email addresses
        """
        return get_to_domains(self.to, self.reply_to)
