#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright 2017 Fedele Mantuano (https://twitter.com/fedelemantuano)

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

from unittest.mock import MagicMock, patch
import pytest
from mailparser.__main__ import get_args, process_output


@pytest.fixture
def parser():
    return get_args()


class TestMain:
    def test_required(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["--file", "test", "--string", "test"])

        with pytest.raises(SystemExit):
            parser.parse_args(["--file", "test", "--stdin"])

        with pytest.raises(SystemExit):
            parser.parse_args(["--file"])

        with pytest.raises(SystemExit):
            parser.parse_args(["--string"])

    def test_options(self, parser):
        args = parser.parse_args(["--file", "mail.eml"])
        assert args.file == "mail.eml"

        args = parser.parse_args(["--string", "mail.str"])
        assert args.string == "mail.str"

        args = parser.parse_args(["--file", "mail.eml", "--json"])
        assert args.json

        args = parser.parse_args(["--file", "mail.eml", "--body"])
        assert args.body

        args = parser.parse_args(["--file", "mail.eml", "-a"])
        assert args.attachments

        args = parser.parse_args(["--file", "mail.eml", "-r"])
        assert args.headers

        args = parser.parse_args(["--file", "mail.eml", "--to"])
        assert args.to

        args = parser.parse_args(["--file", "mail.eml", "--from"])
        assert args.from_

        args = parser.parse_args(["--file", "mail.eml", "-u"])
        assert args.subject

        args = parser.parse_args(["--file", "mail.eml", "-d"])
        assert args.defects

        args = parser.parse_args(["--file", "mail.eml", "--senderip", "trust"])
        assert args.senderip

        args = parser.parse_args(["--file", "mail.eml", "-p"])
        assert args.mail_hash

        args = parser.parse_args(["--file", "mail.eml", "--attachments-hash"])
        assert args.attachments_hash

        args = parser.parse_args(["--file", "mail.eml", "-c"])
        assert args.receiveds

    @pytest.mark.parametrize(
        "args, patch_process_output, mocked",
        [
            (
                ["--file", "mail.eml", "--json"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--body"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--headers"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--to"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--delivered-to"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--from"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--subject"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--receiveds"],
                "mailparser.__main__.safe_print",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--defects"],
                "mailparser.__main__.print_defects",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--senderip", "server"],
                "mailparser.__main__.print_sender_ip",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--attachments"],
                "mailparser.__main__.print_attachments_details",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--attachments-hash"],
                "mailparser.__main__.print_attachments_details",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--mail-hash"],
                "mailparser.__main__.print_mail_fingerprints",
                MagicMock(),
            ),
            (
                ["--file", "mail.eml", "--store-attachments"],
                "mailparser.__main__.write_attachments",
                MagicMock(),
            ),
        ],
    )
    def test_process_output(
        self,
        args,
        patch_process_output,
        mocked,
        parser,
    ):
        args = parser.parse_args(args)
        with patch(patch_process_output) as mock:
            process_output(args, mocked)
            mock.assert_called_once()
