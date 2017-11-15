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
import datetime
import email
import logging
import os
import re

import ipaddress
import six
import simplejson as json

from .utils import (
    ported_string, decode_header_part, ported_open,
    find_between, msgconvert)


log = logging.getLogger(__name__)

REGXIP = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
EPILOGUE_DEFECTS = {"StartBoundaryNotFoundDefect"}


def parse_from_file_obj(fp):
    """Parsing email from a file-like object.

    Args:
        fp (file-like object): file-like object of raw email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_file_obj(fp).parse()


def parse_from_file(fp):
    """Parsing email from file.

    Args:
        fp (string): file path of raw email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_file(fp).parse()


def parse_from_file_msg(fp):
    """Parsing email from file Outlook msg.

    Args:
        fp (string): file path of raw Outlook email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_file_msg(fp).parse()


def parse_from_string(s):
    """Parsing email from string.

    Args:
        s (string): raw email

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_string(s).parse()


def parse_from_bytes(bt):
    """Parsing email from bytes. Only for Python 3

    Args:
        bt (bytes-like object): raw email as bytes-like object

    Returns:
        Instance of MailParser with raw email parsed
    """
    return MailParser.from_bytes(bt).parse()


class MailParser(object):
    """
    MailParser package provides a standard parser that understands
    most email document structures like official email package.
    MailParser handles the enconding of email and split the raw email for you.
    """

    def __init__(self, message=None):
        """Init a new object from a message object structure. """
        self._message = message

    @classmethod
    def from_file_obj(cls, fp):
        """Init a new object from a file-like object.
        Not for Outlook msg.

        Args:
            fp (file-like object): file-like object of raw email

        Returns:
            Instance of MailParser
        """

        message = email.message_from_file(fp)

        return cls(message)

    @classmethod
    def from_file(cls, fp, is_outlook=False):
        """Init a new object from a file path.

        Args:
            fp (string): file path of raw email
            is_outlook (boolean): if True is an Outlook email

        Returns:
            Instance of MailParser
        """

        with ported_open(fp) as f:
            message = email.message_from_file(f)

        if is_outlook:
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
        f, _ = msgconvert(fp)
        return cls.from_file(f, True)

    @classmethod
    def from_string(cls, s):
        """Init a new object from a string.

        Args:
            s (string): raw email

        Returns:
            Instance of MailParser
        """

        message = email.message_from_string(s)
        return cls(message)

    @classmethod
    def from_bytes(cls, bt):
        """Init a new object from bytes.

        Args:
            bt (bytes-like object): raw email as bytes-like object

        Returns:
            Instance of MailParser
        """
        if six.PY2:
            raise EnvironmentError(
                "Parsing from bytes is valid only for Python 3.x version")

        message = email.message_from_bytes(bt)
        return cls(message)

    def parse_from_file_obj(self, fp):
        """Parse the raw email from a file path.

        Args:
            fp (file-like object): file-like object of raw email

        Returns:
            Instance of MailParser
        """

        self._message = email.message_from_file(fp)
        return self.parse()

    def parse_from_file(self, fp):
        """Parse the raw email from a file path.

        Args:
            fp (string): file path of raw email

        Returns:
            Instance of MailParser
        """

        with ported_open(fp) as f:
            self._message = email.message_from_file(f)
        return self.parse()

    def parse_from_file_msg(self, fp):
        """Parse the raw email from a file path Outlook.

        Args:
            fp (string): file path of raw email

        Returns:
            Instance of MailParser
        """
        t, _ = msgconvert(fp)
        with ported_open(t) as f:
            self._message = email.message_from_file(f)
        os.remove(t)
        return self.parse()

    def parse_from_string(self, s):
        """Parse the raw email from a string.

        Args:
            s (string): raw email

        Returns:
            Instance of MailParser
        """

        self._message = email.message_from_string(s)
        return self.parse()

    def parse_from_bytes(self, bt):
        """Parse the raw mail from bytes.

        Args:
            bt (bytes-like object): raw email as bytes-like object

        Returns:
            Instance of MailParser
        """
        if six.PY2:
            raise EnvironmentError(
                "Parsing from bytes is valid only for Python 3.x version")

        self._message = email.message_from_bytes(bt)
        return self.parse()

    def _append_defects(self, part, part_content_type):
        """The defects attribute contains a list of all the problems found
        when parsing this message.
        """

        part_defects = {}

        for e in part.defects:
            defects = "{}: {}".format(e.__class__.__name__, e.__doc__)
            self._defects_category.add(e.__class__.__name__)
            part_defects.setdefault(part_content_type, []).append(defects)

        # Tag mail with defect
        if part_defects:
            self._has_defects = True

            # Save all defects
            self._defects.append(part_defects)

    def _reset(self):
        """Reset the state of object. """

        self._to = list()
        self._attachments = list()
        self._text_plain = list()
        self._defects = list()
        self._defects_category = set()
        self._has_defects = False
        self._has_anomalies = False
        self._anomalies = list()

    def _make_mail(self):
        """This method assigns the right values to all tokens of email. """

        # mail object
        self._mail = {
            "attachments": self.attachments_list,
            "body": self.body,
            "date": self.date_mail,
            "from": self.from_,
            "headers": self.headers,
            "message_id": self.message_id,
            "subject": self.subject,
            "to": email.utils.getaddresses([self.to_]),
            "receiveds": self.receiveds_obj,
            "has_defects": self.has_defects,
            "has_anomalies": self.has_anomalies}

        # Add defects
        if self.has_defects:
            self._mail["defects"] = self.defects
            self._mail["defects_category"] = list(self._defects_category)

        # Add anomalies
        if self.has_anomalies:
            self._mail["anomalies"] = self.anomalies

    def parse(self):
        """This method parses the raw email and makes the tokens.

        Returns:
            Instance of MailParser with raw email parsed
        """

        if not self.message.keys():
            raise ValueError("This email doesn't have headers")

        # Reset for new mail
        self._reset()
        parts = []  # Normal parts plus defects

        # walk all mail parts to search defects
        for p in self.message.walk():
            part_content_type = p.get_content_type()
            self._append_defects(p, part_content_type)
            parts.append(p)

        # If defects are in epilogue defects get epilogue
        if self.defects_category & EPILOGUE_DEFECTS:
            epilogue = find_between(
                self.message.epilogue,
                "{}".format("--" + self.message.get_boundary()),
                "{}".format("--" + self.message.get_boundary() + "--"))

            try:
                p = email.message_from_string(epilogue)
                parts.append(p)
            except TypeError:
                log.warning(
                    "Failed to get epilogue part. Probably malformed.")
            except:
                log.error(
                    "Failed to get epilogue part. Should check raw mail.")

        # walk all mail parts
        for p in parts:
            if not p.is_multipart():
                filename = ported_string(p.get_filename())
                charset = p.get_content_charset('utf-8')

                if filename:
                    binary = False
                    mail_content_type = ported_string(p.get_content_type())
                    transfer_encoding = ported_string(
                        p.get('content-transfer-encoding', '')).lower()

                    if transfer_encoding == "base64" or \
                            (transfer_encoding == "quoted-printable" and
                             "application" in mail_content_type):
                        payload = p.get_payload(decode=False)
                        binary = True
                    else:
                        payload = ported_string(
                            p.get_payload(decode=True), encoding=charset)

                    self._attachments.append({
                        "filename": filename,
                        "payload": payload,
                        "binary": binary,
                        "mail_content_type": mail_content_type,
                        "content_transfer_encoding": transfer_encoding})
                else:
                    payload = ported_string(
                        p.get_payload(decode=True), encoding=charset)
                    if payload:
                        self._text_plain.append(payload)

        # Parsed object mail
        self._make_mail()
        return self

    def get_server_ipaddress(self, trust):
        """Return the ip address of sender

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

        Return:
            string with the ip address
        """

        if not trust.strip():
            return

        received = self.message.get_all("received", [])

        for i in received:
            if trust in i:
                check = REGXIP.findall(i[0:i.find("by")])

                if check:
                    try:
                        ip = ipaddress.ip_address(six.text_type(check[-1]))
                    except ValueError:
                        return

                    if not ip.is_private:
                        return six.text_type(check[-1])

    @property
    def receiveds_obj(self):
        """Return all headers receiveds as object

        Return:
            list of receiveds
        """

        output = []
        receiveds = self.message.get_all("received", [])

        for i in receiveds:
            output.append(decode_header_part(i))

        return output

    @property
    def receiveds(self):
        """Return all headers receiveds as json

        Return:
            string of all receiveds
        """
        s = ""
        for i in self.receiveds_obj:
            s += "Received: " + i + "\n"
        return s.strip()

    @property
    def message(self):
        """email.message.Message class. """
        return self._message

    @property
    def message_as_string(self):
        """Return the entire message flattened as a string. """
        return self.message.as_string()

    @property
    def body(self):
        """Return the only the body. """
        return "\n".join(self.text_plain_list)

    @property
    def headers(self):
        """Return the only the headers. """
        s = ""
        for k, v in self.message.items():
            v_u = re.sub(" +", " ", decode_header_part(v))
            s += k + ": " + v_u + "\n"
        return s

    @property
    def message_id(self):
        """Return the message id. """
        message_id = self.message.get('message-id', None)
        if not message_id:
            self._anomalies.append('mail_without_message-id')
            return None
        else:
            return ported_string(message_id)

    @property
    def to_(self):
        """Return the receiver of message. """
        return decode_header_part(
            self.message.get('to', self.message.get('delivered-to', '')))

    @property
    def from_(self):
        """Return the sender of message. """
        return decode_header_part(
            self.message.get('from', ''))

    @property
    def subject(self):
        """Return the subject of message. """
        return decode_header_part(
            self.message.get('subject', ''))

    @property
    def text_plain_list(self):
        """Return a list of all text plain part of email. """
        return self._text_plain

    @property
    def attachments_list(self):
        """Return the attachments list of email. """
        return self._attachments

    @property
    def date_mail(self):
        """Return the date of email as datetime.datetime. """
        date_ = self.message.get('date')

        if not date_:
            self._anomalies.append('mail_without_date')
            return None

        try:
            d = email.utils.parsedate_tz(date_)
            t = email.utils.mktime_tz(d)
            return datetime.datetime.utcfromtimestamp(t)
        except:
            return None

    @property
    def parsed_mail_obj(self):
        """Return an Python object with all tokens of email. """
        return self._mail

    @property
    def parsed_mail_json(self):
        """Return a json with all tokens of email. """
        self._mail["date"] = self.date_mail.isoformat() \
            if self.date_mail else ""
        return json.dumps(
            self._mail, ensure_ascii=False, indent=None)

    @property
    def defects(self):
        """The defects property contains a list of
        all the problems found when parsing this message.
        """
        return self._defects

    @property
    def defects_category(self):
        """Return a list with only defects categories. """
        return self._defects_category

    @property
    def has_defects(self):
        """Return a boolean: True if mail has defects. """
        return self._has_defects

    @property
    def anomalies(self):
        """The anomalies property contains a list of
        all anomalies in mail:
            - mail_without_date
            - mail_without_message-id
        """
        return self._anomalies

    @property
    def has_anomalies(self):
        """Return a boolean: True if mail has anomalies. """
        return True if self.anomalies else False
