#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright 2018 Fedele Mantuano (https://www.linkedin.com/in/fmantuano/)

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


__all__ = (
    "MailParserError",
    "MailParserOutlookError",
    "MailParserEnvironmentError",
    "MailParserOSError",
    "MailParserReceivedParsingError"
)


class MailParserError(Exception):
    """
    Base MailParser Exception
    """
    pass


class MailParserOutlookError(MailParserError):
    """
    Raised when there is an error with Outlook integration
    """
    pass


class MailParserEnvironmentError(MailParserError):
    """
    Raised when the environment is not correct
    """
    pass


class MailParserOSError(MailParserError):
    """
    Raised when there is an OS error
    """
    pass


class MailParserReceivedParsingError(MailParserError):
    """
    Raised when a received header cannot be parsed
    """
    pass
