#!/usr/bin/env python

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

    def test_main_success(self, parser, tmp_path):
        """Test main function with successful execution"""
        import mailparser.__main__ as main_module

        # Create a test mail file
        test_mail = tmp_path / "test.eml"
        test_mail.write_text("From: test@example.com\nSubject: Test\n\nBody")

        with patch("sys.argv", ["mail-parser", "--file", str(test_mail), "--json"]):
            with patch("mailparser.__main__.safe_print") as mock_print:
                # main() doesn't necessarily exit, it just processes
                main_module.main()
                # Verify that safe_print was called (output was produced)
                assert mock_print.called

    def test_main_with_exception(self):
        """Test main function when an exception occurs"""
        import mailparser.__main__ as main_module

        with patch("sys.argv", ["mail-parser", "--file", "nonexistent.eml"]):
            with pytest.raises(SystemExit) as exc_info:
                main_module.main()
            assert exc_info.value.code == 1

    def test_get_parser_with_file(self, parser, tmp_path):
        """Test get_parser with file input"""
        from mailparser.__main__ import get_parser

        test_mail = tmp_path / "test.eml"
        test_mail.write_text("From: test@example.com\nSubject: Test\n\nBody")

        args = parser.parse_args(["--file", str(test_mail)])
        result = get_parser(args)
        assert result is not None
        assert result.subject == "Test"

    def test_get_parser_with_string(self, parser):
        """Test get_parser with string input"""
        from mailparser.__main__ import get_parser

        args = parser.parse_args(
            ["--string", "From: test@example.com\nSubject: Test\n\nBody"]
        )
        result = get_parser(args)
        assert result is not None
        assert result.subject == "Test"

    def test_get_parser_with_no_input(self, parser):
        """Test get_parser raises ValueError when no input provided"""
        from unittest.mock import Mock

        from mailparser.__main__ import get_parser

        # Create mock args with no input source
        args = Mock()
        args.file = None
        args.string = None
        args.stdin = None

        with pytest.raises(ValueError, match="No input source provided"):
            get_parser(args)

    def test_parse_file_outlook(self, parser, tmp_path):
        """Test parse_file with Outlook flag"""
        from unittest.mock import patch

        from mailparser.__main__ import parse_file
        from mailparser.exceptions import MailParserOSError

        # Create a non-existent file path
        non_existent_file = str(tmp_path / "non_existent.msg")
        args = parser.parse_args(["--file", non_existent_file, "--outlook"])

        # Force the deprecated msgconvert fallback (extract-msg absent) and
        # mock msgconvert to raise OSError (simulating msgconvert unavailable)
        with (
            patch(
                "mailparser.core.importlib.util.find_spec",
                return_value=None,
            ),
            patch(
                "mailparser.utils.subprocess.Popen",
                side_effect=OSError("msgconvert not found"),
            ),
        ):
            with pytest.raises(MailParserOSError, match="msgconvert"):
                parse_file(args)

    def test_parse_stdin(self, parser):
        """Test parse_stdin function"""
        import io

        from mailparser.__main__ import parse_stdin

        test_content = "From: test@example.com\nSubject: Test from stdin\n\nBody"

        args = parser.parse_args(["--stdin"])

        with patch("sys.stdin", io.StringIO(test_content)):
            result = parse_stdin(args)
            assert result is not None
            assert result.subject == "Test from stdin"

    def test_parse_stdin_outlook_error(self, parser):
        """Test parse_stdin raises error for Outlook files"""
        from mailparser.__main__ import parse_stdin
        from mailparser.exceptions import MailParserOutlookError

        args = parser.parse_args(["--stdin", "--outlook"])

        with pytest.raises(
            MailParserOutlookError, match="You can't use stdin with msg Outlook"
        ):
            parse_stdin(args)

    def test_print_defects(self, parser, tmp_path):
        """Test print_defects function"""
        import mailparser
        from mailparser.__main__ import print_defects

        # Use a malformed email to get defects
        test_mail = tmp_path / "malformed.eml"
        test_mail.write_text(
            "Content-Type: multipart/mixed; boundary=boundary\n\n"
            "--wrongboundary\n"
            "Content-Type: text/plain\n\n"
            "Test\n"
        )

        mail = mailparser.parse_from_file(str(test_mail))

        with patch("mailparser.__main__.safe_print") as mock_print:
            print_defects(mail)
            assert mock_print.called

    def test_print_sender_ip(self, parser):
        """Test print_sender_ip function"""
        from unittest.mock import Mock

        from mailparser.__main__ import print_sender_ip

        mock_parser = Mock()
        mock_parser.get_server_ipaddress.return_value = "192.168.1.1"

        args = parser.parse_args(["--file", "test.eml", "--senderip", "trust"])

        with patch("mailparser.__main__.safe_print") as mock_print:
            print_sender_ip(mock_parser, args)
            mock_print.assert_called_once_with("192.168.1.1")

    def test_print_sender_ip_not_found(self, parser):
        """Test print_sender_ip when IP not found"""
        from unittest.mock import Mock

        from mailparser.__main__ import print_sender_ip

        mock_parser = Mock()
        mock_parser.get_server_ipaddress.return_value = None

        args = parser.parse_args(["--file", "test.eml", "--senderip", "trust"])

        with patch("mailparser.__main__.safe_print") as mock_print:
            print_sender_ip(mock_parser, args)
            mock_print.assert_called_once_with("Not Found")

    def test_print_attachments_details(self, parser):
        """Test print_attachments_details function"""
        from unittest.mock import Mock

        from mailparser.__main__ import print_attachments_details

        mock_parser = Mock()
        mock_parser.attachments = [{"filename": "test.txt", "payload": "data"}]

        args = parser.parse_args(["--file", "test.eml", "--attachments"])

        with patch("mailparser.__main__.print_attachments") as mock_print:
            print_attachments_details(mock_parser, args)
            mock_print.assert_called_once_with(mock_parser.attachments, False)

    def test_get_parser_with_stdin(self, parser):
        """Test get_parser returns parse_stdin result when args.stdin is True"""
        import io

        from mailparser.__main__ import get_parser

        test_content = "From: test@example.com\nSubject: Stdin Test\n\nBody"
        args = parser.parse_args(["--stdin"])

        with patch("sys.stdin", io.StringIO(test_content)):
            result = get_parser(args)
            assert result is not None
            assert result.subject == "Stdin Test"
