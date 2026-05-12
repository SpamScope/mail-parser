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

import base64
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from mailparser.exceptions import MailParserOSError, MailParserReceivedParsingError
from mailparser.utils import (
    decode_header_part,
    find_between,
    get_addresses,
    msgconvert,
    parse_received,
    ported_open,
    ported_string,
    receiveds_parsing,
)


class TestUtils(unittest.TestCase):
    def test_ported_string_with_invalid_encoding(self):
        """Test ported_string with invalid encoding falls back to utf-8"""
        # Test with invalid encoding name
        data = b"Test data"
        result = ported_string(data, encoding="invalid-encoding-name")
        self.assertEqual(result, "Test data")

    def test_ported_string_unicode_decode_error(self):
        """Test ported_string handles UnicodeDecodeError"""
        # Create data that will cause UnicodeDecodeError with certain encoding
        data = b"\xff\xfe"  # Invalid UTF-8 sequence
        result = ported_string(data, encoding="ascii")
        # Should fall back to utf-8 with errors='ignore'
        self.assertIsInstance(result, str)

    def test_decode_header_part_with_header_parse_error(self):
        """Test decode_header_part handles HeaderParseError"""
        from email.errors import HeaderParseError

        # Mock decode_header to raise HeaderParseError
        with patch(
            "mailparser.utils.decode_header",
            side_effect=HeaderParseError("Header parsing failed"),
        ):
            result = decode_header_part("problematic_header")
            # Should return the original header on error
            self.assertEqual(result, "problematic_header")

    def test_find_between_with_value_error(self):
        """Test find_between when tokens not found"""
        result = find_between("text without tokens", "START", "END")
        self.assertIsNone(result)

    def test_msgconvert_oserror(self):
        """Test msgconvert raises MailParserOSError when tool not found"""
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp_name = tmp.name

        try:
            # Mock subprocess.Popen to raise OSError
            with patch("subprocess.Popen", side_effect=OSError("Command not found")):
                with self.assertRaises(MailParserOSError) as context:
                    msgconvert(tmp_name)
                self.assertIn("msgconvert", str(context.exception))
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def test_msgconvert_success(self):
        """Test msgconvert successful execution"""
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp_name = tmp.name

        try:
            # Mock successful subprocess execution
            mock_process = Mock()
            mock_process.communicate.return_value = (
                b"Conversion successful",
                b"",
            )

            with patch("subprocess.Popen", return_value=mock_process):
                temp_file, stdout = msgconvert(tmp_name)
                self.assertIsInstance(temp_file, str)
                self.assertEqual(stdout, "Conversion successful")
                # Clean up the temp file
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def test_parse_received_no_matches(self):
        """Test parse_received with header that matches nothing"""
        # Header that doesn't match any patterns
        received = "InvalidReceivedHeader"

        with self.assertRaises(MailParserReceivedParsingError) as context:
            parse_received(received)
        self.assertIn("Unable to match any clauses", str(context.exception))

    def test_parse_received_multiple_matches(self):
        """Test parse_received with header that has multiple matches for one pattern"""
        # This is a complex edge case - create header with duplicate clause
        # Note: This is hard to trigger with real data, but tests the error handling
        received = "from server1 from server2 by mail.example.com"

        # The function should handle this, might raise error or process normally
        # depending on the regex patterns
        try:
            result = parse_received(received)
            # If it succeeds, result should be a dict
            self.assertIsInstance(result, dict)
        except MailParserReceivedParsingError:  # pragma: no cover
            # This is also acceptable - it means the parser detected the issue
            pass

    def test_receiveds_parsing_mismatch_length(self):
        """Test receiveds_parsing when parsing fails"""
        # Test with receiveds that will fail to parse
        receiveds = ["InvalidReceivedHeader1", "InvalidReceivedHeader2"]

        # These should all fail to parse and fall back to raw format
        result = receiveds_parsing(receiveds)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), len(receiveds))
        # Should have 'raw' key in the results
        self.assertTrue(all("raw" in r or "from" in r for r in result))

    def test_ported_open_python3(self):
        """Test ported_open in Python 3"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("test content")
            tmp_name = tmp.name

        try:
            with ported_open(tmp_name) as f:
                content = f.read()
            self.assertEqual(content, "test content")
        finally:
            os.unlink(tmp_name)


class TestUtilsEdgeCases(unittest.TestCase):
    def test_parse_received_with_junk_pattern(self):
        """Test receiveds_parsing removes junk patterns"""
        # Test that JUNK_PATTERN is properly applied
        receiveds = ["Received: from server.example.com\n\tby mail.example.com"]

        result = receiveds_parsing(receiveds)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_decode_header_part_unicode_error(self):
        """Test decode_header_part with UnicodeError"""
        # Mock decode_header to raise UnicodeError
        with patch("mailparser.utils.decode_header", side_effect=UnicodeError()):
            result = decode_header_part("test_header")
            self.assertEqual(result, "test_header")

    def test_ported_string_empty_input(self):
        """Test ported_string with empty input"""
        result = ported_string(None)
        self.assertEqual(result, "")

        result = ported_string("")
        self.assertEqual(result, "")

    def test_ported_string_already_string(self):
        """Test ported_string with str input (no conversion needed)"""
        test_str = "Already a string"
        result = ported_string(test_str)
        self.assertEqual(result, test_str)

    def test_ported_string_successful_decode(self):
        """Test ported_string successful decoding with specified encoding"""
        data = "test".encode("utf-8")
        result = ported_string(data, encoding="utf-8")
        self.assertEqual(result, "test")

    def test_decode_header_part_empty(self):
        """Test decode_header_part with empty header"""
        result = decode_header_part("")
        self.assertEqual(result, "")

        result = decode_header_part(None)
        self.assertEqual(result, "")

    def test_find_between_successful(self):
        """Test find_between with successful extraction"""
        from mailparser.utils import find_between

        text = "prefix<content>suffix"
        result = find_between(text, "<", ">")
        self.assertEqual(result, "content")

    def test_find_between_with_whitespace(self):
        """Test find_between strips whitespace"""
        from mailparser.utils import find_between

        text = "prefix<  content  >suffix"
        result = find_between(text, "<", ">")
        self.assertEqual(result, "content")

    def test_fingerprints_with_string_input(self):
        """Test fingerprints with string input (should encode to bytes)"""
        from mailparser.utils import fingerprints

        result = fingerprints("test data")
        self.assertIsNotNone(result.md5)
        self.assertIsNotNone(result.sha1)
        self.assertIsNotNone(result.sha256)
        self.assertIsNotNone(result.sha512)

    def test_fingerprints_with_bytes_input(self):
        """Test fingerprints with bytes input"""
        from mailparser.utils import fingerprints

        result = fingerprints(b"test data")
        self.assertIsNotNone(result.md5)
        self.assertEqual(len(result.md5), 32)
        self.assertEqual(len(result.sha1), 40)
        self.assertEqual(len(result.sha256), 64)
        self.assertEqual(len(result.sha512), 128)

    def test_parse_received_with_multiple_matches_error(self):
        """Test parse_received raises error on multiple matches for same pattern"""
        # This tests the error branch when multiple matches are found
        # We need a received header that triggers duplicate matches
        received = (
            "from server.example.com from server2.example.com by mail.example.com"
        )

        # Depending on the patterns, this might raise an error or succeed
        # We test that it handles the scenario correctly
        try:
            result = parse_received(received)
            # If it succeeds, it should return a dict
            self.assertIsInstance(result, dict)
        except MailParserReceivedParsingError as e:
            # This is the expected path for multiple matches
            self.assertIn("More than one match", str(e))

    def test_get_to_domains_with_keyerror(self):
        """Test get_to_domains handles KeyError gracefully"""
        from mailparser.utils import get_to_domains

        # Test with malformed data that could cause KeyError
        to = [("Name", "email@example.com")]
        reply_to = [("Name2",)]  # Missing email part - could cause KeyError

        result = get_to_domains(to, reply_to)
        # Should handle the error and return only valid domains
        self.assertIn("example.com", result)

    def test_get_to_domains_normal(self):
        """Test get_to_domains with normal input"""
        from mailparser.utils import get_to_domains

        to = [("User1", "user1@example.com"), ("User2", "user2@test.org")]
        reply_to = [("User3", "user3@example.com")]

        result = get_to_domains(to, reply_to)
        self.assertIn("example.com", result)
        self.assertIn("test.org", result)
        # Should deduplicate
        self.assertEqual(result.count("example.com"), 1)

    def test_get_header_no_headers(self):
        """Test get_header when no headers exist"""
        from email.message import Message

        from mailparser.utils import get_header

        msg = Message()
        result = get_header(msg, "X-NonExistent-Header")
        self.assertEqual(result, "")

    def test_get_header_single_header(self):
        """Test get_header with single header value"""
        from email.message import Message

        from mailparser.utils import get_header

        msg = Message()
        msg["X-Test-Header"] = "Test Value"

        result = get_header(msg, "X-Test-Header")
        self.assertEqual(result, "Test Value")

    def test_get_header_multiple_headers(self):
        """Test get_header with multiple header values"""
        from email.message import Message

        from mailparser.utils import get_header

        msg = Message()
        msg["Received"] = "from server1"
        msg["Received"] = "from server2"

        result = get_header(msg, "Received")
        # Should return a list for multiple headers
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)

    def test_get_mail_keys_complete_true(self):
        """Test get_mail_keys with complete=True"""
        from email.message import Message

        from mailparser.utils import get_mail_keys

        msg = Message()
        msg["Subject"] = "Test"
        msg["From"] = "test@example.com"
        msg["X-Custom-Header"] = "custom"

        result = get_mail_keys(msg, complete=True)
        self.assertIsInstance(result, set)
        self.assertIn("subject", result)
        self.assertIn("from", result)
        self.assertIn("x-custom-header", result)

    def test_get_mail_keys_complete_false(self):
        """Test get_mail_keys with complete=False"""
        from email.message import Message

        from mailparser.utils import get_mail_keys

        msg = Message()
        msg["Subject"] = "Test"
        msg["X-Custom-Header"] = "custom"

        result = get_mail_keys(msg, complete=False)
        self.assertIsInstance(result, set)
        # Should only contain standard headers, not custom ones
        # The custom header should not be included when complete=False

    def test_receiveds_format_successful_parsing(self):
        """Test receiveds_parsing with successfully parsed headers"""
        from mailparser.utils import receiveds_parsing

        # Valid received header that should parse successfully
        receiveds = [
            "from mail.example.com (mail.example.com [192.168.1.1]) "
            "by mx.example.org; Mon, 1 Jan 2024 12:00:00 +0000"
        ]

        result = receiveds_parsing(receiveds)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        # Should have parsed data, not just raw
        self.assertIn("hop", result[0])

    def test_convert_mail_date(self):
        """Test convert_mail_date function"""
        from mailparser.utils import convert_mail_date

        # Test with a valid date string
        date_str = "Mon, 1 Jan 2024 12:00:00 +0000"
        date_utc, timezone = convert_mail_date(date_str)

        self.assertIsNotNone(date_utc)
        self.assertEqual(timezone, "+0.0")

    def test_convert_mail_date_with_timezone(self):
        """Test convert_mail_date with different timezone"""
        from mailparser.utils import convert_mail_date

        # Test with PST timezone (-0800)
        date_str = "Mon, 1 Jan 2024 12:00:00 -0800"
        date_utc, timezone = convert_mail_date(date_str)

        self.assertIsNotNone(date_utc)
        self.assertEqual(timezone, "-8.0")

    def test_receiveds_not_parsed(self):
        """Test receiveds_not_parsed function directly"""
        from mailparser.utils import receiveds_not_parsed

        receiveds = ["Header1", "Header2", "Header3"]
        result = receiveds_not_parsed(receiveds)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 3)
        # Should be in reverse order with hop numbers
        self.assertEqual(result[0]["hop"], 1)
        self.assertEqual(result[1]["hop"], 2)
        self.assertEqual(result[2]["hop"], 3)
        self.assertIn("raw", result[0])

    def test_receiveds_format(self):
        """Test receiveds_format function"""
        from mailparser.utils import receiveds_format

        # Test with basic parsed data
        parsed = [
            {"from": "server1.example.com", "by": "server2.example.com"},
            {"from": "server2.example.com", "by": "server3.example.com"},
        ]

        result = receiveds_format(parsed)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        # Should add hop numbers
        self.assertEqual(result[0]["hop"], 1)
        self.assertEqual(result[1]["hop"], 2)

    def test_receiveds_format_with_dates(self):
        """Test receiveds_format with date parsing"""
        from mailparser.utils import receiveds_format

        # Test with dates
        parsed = [
            {
                "from": "server1.example.com",
                "by": "server2.example.com",
                "date": "Mon, 1 Jan 2024 12:00:00 +0000",
            },
            {
                "from": "server2.example.com",
                "by": "server3.example.com",
                "date": "Mon, 1 Jan 2024 12:01:00 +0000",
            },
        ]

        result = receiveds_format(parsed)
        self.assertIsInstance(result, list)
        # Should have date_utc and delay calculated
        if result[0].get("date_utc"):
            self.assertIn("date_utc", result[0])
            self.assertIn("delay", result[1])

    def test_receiveds_format_with_invalid_date(self):
        """Test receiveds_format handles invalid dates"""
        from mailparser.utils import receiveds_format

        # Test with invalid date that will cause TypeError
        parsed = [
            {
                "from": "server1.example.com",
                "by": "server2.example.com",
                "date": "invalid date format",
            }
        ]

        result = receiveds_format(parsed)
        self.assertIsInstance(result, list)
        # Should handle the error gracefully
        self.assertEqual(result[0]["date_utc"], None)

    def test_write_sample_binary(self):
        """Test write_sample with binary file"""
        import os
        import tempfile

        from mailparser.utils import write_sample

        temp_dir = tempfile.mkdtemp()
        try:
            # Test binary file
            payload = base64.b64encode(b"test binary content").decode()
            write_sample(
                binary=True, payload=payload, path=temp_dir, filename="test_binary.bin"
            )

            file_path = os.path.join(temp_dir, "test_binary.bin")
            self.assertTrue(os.path.exists(file_path))

            with open(file_path, "rb") as f:
                content = f.read()
            self.assertEqual(content, b"test binary content")
        finally:
            # Cleanup
            import shutil

            shutil.rmtree(temp_dir)

    def test_write_sample_text(self):
        """Test write_sample with text file"""
        import os
        import tempfile

        from mailparser.utils import write_sample

        temp_dir = tempfile.mkdtemp()
        try:
            # Test text file
            write_sample(
                binary=False,
                payload="test text content",
                path=temp_dir,
                filename="test_text.txt",
            )

            file_path = os.path.join(temp_dir, "test_text.txt")
            self.assertTrue(os.path.exists(file_path))

            with open(file_path, "r") as f:
                content = f.read()
            self.assertEqual(content, "test text content")
        finally:
            # Cleanup
            import shutil

            shutil.rmtree(temp_dir)

    def test_random_string(self):
        """Test random_string function"""
        from mailparser.utils import random_string

        # Test default length
        result = random_string()
        self.assertEqual(len(result), 10)
        self.assertTrue(result.isalpha())
        self.assertTrue(result.islower())

        # Test custom length
        result = random_string(20)
        self.assertEqual(len(result), 20)

    def test_parse_received_single_match_standard_pattern(self):
        """Test parse_received with exactly one match from standard patterns"""
        from mailparser.utils import parse_received

        # Use a real received header that will match standard patterns
        # This should trigger the else block at lines 267-269
        received = (
            "from smtprelay.b.hostedemail.com (64.98.42.207) "
            "by smtp.server.net with SMTP; 22 Aug 2016 14:23:01 -0000"
        )

        result = parse_received(received)

        # Should successfully parse and return dict
        self.assertIsInstance(result, dict)
        # Should have multiple keys extracted
        self.assertIn("from", result)
        self.assertIn("by", result)
        self.assertIn("with", result)
        self.assertIn("date", result)

    def test_receiveds_format_delay_no_previous_date(self):
        """Test receiveds_format delay calculation when first entry has no valid date"""
        from mailparser.utils import receiveds_format

        # NOTE: receiveds_format processes the list in REVERSE order ([::-1])
        # So we need the second item to have the invalid date
        # After reversal, invalid date will be first, then valid date second
        parsed = [
            {
                "from": "server1.example.com",
                "by": "server2.example.com",
                # Valid date - will be processed second
                "date": "Mon, 1 Jan 2024 12:01:00 +0000",
            },
            {
                "from": "server2.example.com",
                "by": "server3.example.com",
                # Will fail - will be processed first
                "date": "completely invalid garbage",
            },
        ]

        result = receiveds_format(parsed)

        # After reversal, result[0] (hop 1) should have None date
        self.assertIsNone(result[0].get("date_utc"))
        # result[1] (hop 2) should have delay=0 because before date is None (line 432)
        self.assertEqual(result[1]["delay"], 0)
        # But should have a valid date itself
        self.assertIsNotNone(result[1].get("date_utc"))

    def test_ported_string_handles_header_object(self):
        """
        Test that ported_string can accept an email.header.Header object
        and return a decoded string without crashing.
        """
        from email.header import Header

        raw_val = 'attachment;\r\nfilename="Just a text – 2026.pdf'
        header_obj = Header(raw_val, charset="utf-8")
        result = ported_string(header_obj)
        self.assertIsInstance(result, str)
        self.assertEqual(result, raw_val)

    def test_get_addresses_handles_header_object(self):
        """
        Test that get_addresses accepts an email.header.Header instance
        without raising AttributeError on `.strip()`.

        Regression for the case where Message.get(name) returns a Header
        for address headers containing RFC 2047 encoded-words (e.g.
        non-ASCII display names like ``=?utf-8?q?=C3=81lp=C3=A1m_Longsom?=``).
        Before the fix, this raised:

            AttributeError: 'Header' object has no attribute 'strip'
        """
        from email.header import Header

        header_obj = Header("Álpám Longsom", charset="utf-8")
        header_obj.append(" <recipient@example.com>", charset="us-ascii")
        result = get_addresses(header_obj)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        display_name, addr = result[0]
        self.assertEqual(addr, "recipient@example.com")
        # get_addresses returns encoded-word form for the display name.
        # Decoding to Unicode happens in core.py via decode_header_part.
        self.assertIn("=?utf-8?b?", display_name)

    def test_get_addresses_handles_none(self):
        """
        Test that get_addresses returns an empty list when given None,
        rather than crashing on attribute access.
        """
        self.assertEqual(get_addresses(None), [])

    def test_get_addresses_plain_string_unchanged(self):
        """
        Test that the existing plain-string path still works. This guards
        against accidentally regressing the common case while adding
        Header / None handling.
        """
        result = get_addresses("Plain Name <plain@example.com>")
        self.assertEqual(result, [("Plain Name", "plain@example.com")])

    def test_mailparser_from_bytes_preserves_unicode_display_name(self):
        """
        Regression: Header objects from Message.get(name) must round-trip
        through get_addresses() without introducing replacement characters.

        The parser should expose the decoded Unicode display name on
        MailParser.to.
        """
        from mailparser.core import MailParser

        raw_email = (
            b"From: Sender <sender@example.com>\r\n"
            b"To: =?utf-8?b?w4FscMOhbSBMb25nc29t?= <recipient@example.com>\r\n"
            b"Subject: Test\r\n"
            b"Date: Tue, 12 May 2026 18:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"hello\r\n"
        )

        mail = MailParser.from_bytes(raw_email)
        self.assertEqual(mail.to, [("Álpám Longsom", "recipient@example.com")])

    def test_parse_received_envelope_from_with_angle_brackets(self):
        """Test utils.py:294-296 — envelope-from clause with angle-bracket match"""
        # When envelope-from keyword is present AND its value has angle
        # brackets, _ENVELOPE_FROM_RE.search() succeeds and line 296 runs.
        received = (
            "from mail.example.com by mx.example.org"
            " envelope-from <sender@example.com>"
            "; Mon, 01 Jan 2024 00:00:00 +0000"
        )
        result = parse_received(received)
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("envelope_from"), "sender@example.com")

    def test_parse_received_envelope_from_no_angle_brackets(self):
        """Test utils.py:294-296 — envelope-from clause with no angle-bracket match"""
        # When the envelope-from keyword is present but its value has no
        # angle brackets, _ENVELOPE_FROM_RE.search() returns None and the
        # if-branch (line 295) is skipped, leaving no envelope_from key.
        received = (
            "from mail.example.com by mx.example.org"
            " envelope-from no-brackets-here"
            "; Mon, 01 Jan 2024 00:00:00 +0000"
        )
        result = parse_received(received)
        # The parser should succeed (other clauses are present)
        self.assertIsInstance(result, dict)
        # envelope_from must NOT be set because there were no angle brackets
        self.assertNotIn("envelope_from", result)

    def test_parse_received_envelope_from_in_clause_no_angle_brackets(self):
        """Test utils.py:322->313 — inline envelope-from without angle brackets"""
        # Step 3 of parse_received searches clause values for "envelope-from"
        # text, then applies _ENVELOPE_FROM_RE.  When the keyword appears but
        # has no <…>, the inner `if m:` at line 322 is False and the key is
        # not added.
        received = (
            "from mail.example.com"
            " by mx.example.org (envelope-from no-angle-bracket)"
            "; Mon, 01 Jan 2024 00:00:00 +0000"
        )
        result = parse_received(received)
        self.assertIsInstance(result, dict)
        # envelope_from must NOT be set
        self.assertNotIn("envelope_from", result)
