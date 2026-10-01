"""Guard public outputs and MIME evidence for the existing mail corpus.

The initial outputs were recorded from revision 522e1f3 before any fixes.
The fixture records deliberate changes reviewed against the original
outputs; do not regenerate it simply to make a failing test pass.
Large text and decoded attachment content are compared by SHA-256.
Only unordered category/domain sets and generated names are stabilized.
"""

import base64
import hashlib
import json
import random
import sys
from pathlib import Path

import pytest

import mailparser


def digest(data):
    """Return a length and SHA-256 fingerprint of exact bytes."""
    return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def compact(value):
    """Keep evidence compact while stabilizing unordered API collections."""
    if isinstance(value, str) and len(value) > 160:
        return digest(value.encode("utf-8", "surrogatepass"))
    if isinstance(value, dict):
        return {
            key: sorted(item)
            if key in ("defects_categories", "to_domains")
            else compact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [compact(item) for item in value]
    return value


def snapshot(mail):
    """Capture public views, attachment octets and original MIME structure."""
    parts = []
    for part in mail.message.walk():
        payload = part.get_payload(decode=True)
        parts.append(
            {
                "headers": compact(list(part.raw_items())),
                "type": part.get_content_type(),
                "multipart": part.is_multipart(),
                "payload": digest(payload) if isinstance(payload, bytes) else None,
                "preamble": compact(part.preamble),
                "epilogue": compact(part.epilogue),
            }
        )
    attachments = []
    for attachment in mail.attachments:
        data = attachment["payload"]
        data = (
            base64.b64decode(data)
            if attachment["binary"]
            else data.encode("utf-8", "surrogatepass")
        )
        attachments.append(
            {
                "metadata": compact(
                    {k: v for k, v in attachment.items() if k != "payload"}
                ),
                "decoded_payload": digest(data),
            }
        )
    return {
        "mail": compact(json.loads(mail.mail_json)),
        "partial": compact(json.loads(mail.mail_partial_json)),
        "headers": compact(json.loads(mail.headers_json)),
        "text_plain": compact(mail.text_plain),
        "text_html": compact(mail.text_html),
        "text_other": compact(mail.text_not_managed),
        "attachments": attachments,
        "mime": parts,
    }


_CORPUS = Path(__file__).parent / "mails"
_EXPECTATIONS = json.loads(
    (Path(__file__).parent / "fixtures" / "corpus_expected.json").read_text()
)


def _fingerprints(mail):
    """Fingerprint each public output group independently."""
    return {
        key: hashlib.sha256(
            json.dumps(value, sort_keys=True, ensure_ascii=True).encode()
        ).hexdigest()
        for key, value in snapshot(mail).items()
    }


@pytest.mark.parametrize("case", sorted(_EXPECTATIONS["cases"]))
def test_existing_corpus_outputs(case):
    """Every previously parsed fixture retains its reviewed semantics."""
    filename, route = case.split("/")
    path = _CORPUS / filename
    raw = path.read_bytes()
    state = random.getstate()
    try:
        random.seed(1234)
        if route == "bytes":
            mail = mailparser.parse_from_bytes(raw)
        elif route == "file":
            mail = mailparser.parse_from_file(path)
        else:
            try:
                mail = mailparser.parse_from_string(
                    raw.decode("utf-8", "surrogateescape")
                )
            except UnicodeEncodeError:
                if sys.version_info < (3, 11) and filename == "mail_outlook_1":
                    pytest.xfail(
                        "Baseline stdlib string-parser failure on Python 3.9/3.10"
                    )
                raise
    finally:
        random.setstate(state)
    expected = dict(_EXPECTATIONS["cases"][case])
    if sys.version_info < (3, 12):
        expected.update(_EXPECTATIONS["legacy_mime"].get(case, {}))
    assert _fingerprints(mail) == expected
