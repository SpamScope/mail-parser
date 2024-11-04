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

from mailparser.core import (
    MailParser,
    parse_from_bytes,
    parse_from_file,
    parse_from_file_msg,
    parse_from_file_obj,
    parse_from_string,
)

from mailparser.utils import get_header

__all__ = [
    "MailParser",
    "parse_from_bytes",
    "parse_from_file",
    "parse_from_file_msg",
    "parse_from_file_obj",
    "parse_from_string",
    "get_header",
]
