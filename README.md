[![PyPI - Version](https://img.shields.io/pypi/v/mail-parser)](https://pypi.org/project/mail-parser/)
[![Coverage Status](https://coveralls.io/repos/github/SpamScope/mail-parser/badge.svg?branch=develop)](https://coveralls.io/github/SpamScope/mail-parser?branch=develop)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mail-parser?color=blue)](https://pypistats.org/packages/mail-parser)
[![Sponsor](https://img.shields.io/badge/Sponsor-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/SpamScope/mail-parser#support-mail-parser)

![SpamScope](https://raw.githubusercontent.com/SpamScope/spamscope/develop/docs/logo/spamscope.png)

# mail-parser

**Project website:** [spamscope.ai/en/mail-parser/](https://spamscope.ai/en/mail-parser/)

mail-parser is a **production-grade, RFC-compliant email parsing library** that goes far beyond a
simple wrapper for Python's [email module](https://docs.python.org/2/library/email.message.html).
It transforms raw email messages into richly structured Python objects with unparalleled precision,
making complex email processing accessible and reliable.

As the **battle-tested foundation of [SpamScope](https://github.com/SpamScope/spamscope)**—a
powerful email security and threat analysis platform—mail-parser has proven itself in demanding
production environments where accuracy and security matter most.

## Why Choose mail-parser?

**🔒 Security-First Design**: Built specifically for email security analysis and digital forensics,
mail-parser excels at detecting malformed structures, hidden content, and RFC non-compliance that
could indicate malicious intent.

**🎯 Comprehensive Parsing**: Extracts every component of an email—headers, bodies (plain text and
HTML), attachments, metadata, routing information, and even subtle defects that other parsers miss.

**🔍 Multi-Format Access**: Every parsed element is accessible in three formats (Python object, raw
string, and JSON), enabling seamless integration with any workflow or downstream system.

**🛡️ Defect Detection**: Identifies and categorizes RFC violations, malformed MIME boundaries, and
structural anomalies that could hide malicious payloads or bypass security filters.

**📧 Outlook Support**: Native handling of Microsoft Outlook .msg files alongside standard email
formats, making it versatile for diverse email ecosystems.

**⚡ Production-Ready**: Trusted by security professionals and developers worldwide, with extensive
test coverage and proven reliability in high-stakes environments.

mail-parser is fully compatible with Python 3, ensuring modern performance and reliability.

## Parsing Outlook `.msg` files

mail-parser converts Outlook `.msg` files to standard `.eml` before parsing.
Two conversion backends are supported:

1. **`extract-msg` (recommended, pure Python).** No external tools required.
   Install the optional extra:

   ```bash
   pip install mail-parser[outlook]
   ```

1. **`msgconvert` (deprecated, external Perl tool).** Requires the
   `libemail-outlook-message-perl` system package:

   ```bash
   apt-get install libemail-outlook-message-perl   # Debian-based systems
   apt-cache show libemail-outlook-message-perl     # package details
   ```

**Backend precedence:** when `extract-msg` is installed it is used first.
Only when it is *not* available does mail-parser fall back to the `msgconvert`
external tool, logging a deprecation warning. If neither backend is available,
`parse_from_file_msg()` raises `MailParserOSError` telling you to install
either path. A malformed `.msg` (not OLE, truncated, corrupt) read with
`extract-msg` raises `MailParserOutlookError`, with the library's exception as
`__cause__`.

> **⚠️ Deprecated:** the `msgconvert` external-tool backend is deprecated and
> will be removed in a future release. Migrate to the pure-Python backend with
> `pip install mail-parser[outlook]`.

**💥 BREAKING CHANGE:** the default `.msg` conversion backend changed.
When `extract-msg` is installed it is now preferred over `msgconvert`. The two
converters produce different intermediate `.eml` output, so some parsed fields
(header ordering, encoding edge cases, attachment naming) can differ from the
previous `msgconvert`-only behavior. Downstream code asserting on exact
`.msg`-derived output may need updating.

# Apache 2 Open Source License

mail-parser can be downloaded, used, and modified free of charge. It is available under the Apache 2 license.

# Support mail-parser

<p align="center">
  <a href="https://github.com/sponsors/fedelemantuano"><img
    src="https://img.shields.io/badge/GitHub%20Sponsors-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white"
    alt="Sponsor on GitHub"></a>
  <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=VEPXYP745KJF2"><img
    src="https://img.shields.io/badge/PayPal-003087?style=for-the-badge&logo=paypal&logoColor=white"
    alt="Donate with PayPal"></a>
  <a href="https://github.com/SpamScope/mail-parser/blob/develop/docs/images/Bitcoin%20SpamScope.jpg?raw=true"><img
    src="https://img.shields.io/badge/Bitcoin-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white"
    alt="Donate with Bitcoin"></a>
</p>

mail-parser is free and open source. Thousands of developers and security professionals rely on it
for email processing and threat analysis. Every donation, whether $5 or $500, funds development
time and infrastructure: detection of new evasion techniques, RFC compliance, performance, and
tested releases you can trust in production.

**Bitcoin address:** `bc1qxhz3tghztpjqdt7atey68s344wvmugtl55tm32`

<details>
<summary>Show Bitcoin QR code</summary>

<img src="https://github.com/SpamScope/mail-parser/blob/develop/docs/images/Bitcoin%20SpamScope.jpg?raw=true"
alt="Bitcoin QR code" width="200">

</details>

Thank you for supporting mail-parser!

# mail-parser in the ecosystem

## Packages and distributions

Find mail-parser in these package repositories and security toolkits:

- **[FreeBSD](https://www.freshports.org/mail/py-mail-parser/)**: available as the
  `mail/py-mail-parser` port.
- **[Arch User Repository (AUR)](https://aur.archlinux.org/packages/mailparser/)**:
  community-maintained `mailparser` package for Arch Linux.
- **[Debian](https://packages.debian.org/source/sid/mail-parser)**: `mail-parser`
  source package in Debian unstable (sid).
- **[REMnux](https://docs.remnux.org/discover-the-tools/analyze+documents/email+messages#mail-parser)**:
  included in the REMnux malware analysis toolkit for analyzing email messages.

## Integrations

- **[IBM Security QRadar SOAR — Parse Utilities](https://github.com/ibmresilient/resilient-community-apps/blob/main/fn_parse_utilities/README.md)**:
  uses mail-parser to extract headers, body parts, and attachments from `.eml`
  and `.msg` files for incident response workflows.

## Research use

mail-parser is also used in academic research:

- **[A Large-Scale Empirical Study of Modern Phishing Email Content](https://arxiv.org/abs/2609.30683)**
  — Jaehwan Park et al., arXiv preprint, September 2026.
  The study analyzes 2.9 million phishing emails and uses mail-parser to extract
  PDF, image, and calendar invitation attachments from their MIME structure
  (Section III-A, reference 34).

# Description

mail-parser transforms raw email messages into comprehensive, RFC-compliant Python objects that
faithfully mirror the structure defined by [IETF email protocol standards](https://www.iana.org/assignments/message-headers/message-headers.xhtml).
Each property of the parsed object directly corresponds to standard RFC headers—"From", "To", "Cc",
"Bcc", "Subject", and many more—providing intuitive, Pythonic access to every email component.

## Core Parsing Capabilities

The library extracts and structures every aspect of an email message:

- **Multi-format Bodies**: Both plain text and HTML body content, cleanly separated and accessible.
- **Complete Attachments**: Full metadata extraction including filename, content type, encoding,
  content disposition, content-ID, charset, and base64-encoded payloads.
- **Routing Intelligence**: Parsed "Received" headers revealing the complete email journey,
  including hop-by-hop analysis with timestamps, delays, server information, and envelope data.
- **Advanced Diagnostics**: Timestamp parsing with timezone detection, defect identification for
  RFC non-compliance, and structural anomaly detection.
- **Custom Headers**: Full support for non-standard and vendor-specific headers using intuitive
  underscore substitution for hyphenated names.

## Triple-Format Property Access

Every parsed element offers **three distinct access patterns** for maximum flexibility:

- **Native Python objects**: Structured, typed data ready for immediate programmatic use
  (`mail.to`, `mail.date`, `mail.attachments`).
- **Raw strings**: Original, unprocessed header content preserving exact formatting
  (`mail.to_raw`, `mail.subject_raw`).
- **JSON serialization**: Clean, standardized JSON representations for easy integration with APIs,
  databases, or other tools (`mail.to_json`, `mail.headers_json`).

This versatile architecture makes mail-parser exceptionally powerful for diverse use cases—from
security analysis and forensics to email migration, compliance auditing, and automated processing
pipelines.

`mail.subject` removes folding CRLF followed by a space or tab, as specified
by [RFC 5322 §2.2.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-2.2.3),
before decoding encoded words. LF-only folds are also accepted for local
message copies; this is a tolerance extension to the CRLF unfolding rule.
Surrounding spaces and tabs are preserved; bare CR is not unfolded.
The same value appears in `headers` and parsed mail/JSON output; other headers
retain their existing behavior. `mail.subject_raw` (a JSON list) and
`mail.message` preserve the original folding. If encoded-word decoding fails,
the complete literal Subject is retained with `header_decoding_defects`.

**Standard RFC Headers** (directly accessible as properties):

- `bcc` - Blind carbon copy recipients
- `cc` - Carbon copy recipients
- `date` - Parsed timestamp with timezone support
- `delivered_to` - Final delivery address
- `from_` - Sender address (underscore used since `from` is a Python keyword)
- `message_id` - Unique message identifier
- `received` - Parsed routing chain with hop-by-hop details
- `reply_to` - Reply-to address
- `subject` - Email subject line
- `to` - Primary recipients

**Additional Parsed Components**:

- `body` - Complete message body
- `text_html` - HTML body parts (list)
- `text_plain` - Plain text body parts (list)
- `headers` - All headers as a structured object. Keys are the header names exactly as they
  appear in the message, and every header is reported — including names that match a
  `MailParser` method or property (`Parse`, `Message`, `Headers_json`) and names containing
  underscores (`X_Spam_Flag`). Such names are always resolved as headers, never as attributes,
  and are never rewritten.
- `attachments` - Complete attachment metadata and payloads
- `get_server_ipaddress()` - Reliable sender IP extraction with trust levels. Only the `from`
  clause of the first trusted `Received` header is searched, with the sender-supplied HELO name
  removed, and the result is `None` when that hop names no public IP. Attribution never falls
  back to older `Received` headers, which the sender is free to forge.
- `to_domains` - Extracted recipient domains for analysis
- `timezone` - Detected timezone information
- `defects` - RFC compliance issues for security analysis
- `defects_categories` - Categorized defect types

The `attachments` property returns a list of dictionaries, each containing comprehensive metadata:

- `binary` - Boolean flag indicating binary content
- `charset` - Character encoding of the attachment
- `content_transfer_encoding` - Transfer encoding method (e.g., base64, quoted-printable)
- `content-disposition` - Disposition type (attachment, inline, etc.)
- `content-id` - Content identifier for referencing within HTML bodies
- `filename` - Original decoded filename from the email. This is untrusted input; never use it
  directly to construct a filesystem path.
- `safe_filename` - Filename with directory components removed and truncated to fit the
  filesystem name limit, or `None` when the original has no usable basename. When saving
  attachments, prefer `write_attachments()` for full validation and collision handling.
- `mail_content_type` - MIME content type
- `payload` - Base64-encoded attachment data, ready for decoding or storage. An attachment is
  kept as bytes: whatever encoding it was sent with, it is re-encoded to base64 and reports
  `base64` as its `content_transfer_encoding`, so the payload always matches the encoding it
  declares and hashes like the file the recipient received. Only `base64` parts keep their
  original wire text, which is already lossless

To access custom or vendor-specific headers, replace hyphens with underscores. For example, to
access the `X-MSMail-Priority` header:

```python
mail.X_MSMail_Priority
```

This underscore-for-hyphen convenience, and the `_json` / `_raw` suffixes, apply only to
attribute access written by you. Names read out of a message — the keys of `mail` and `headers` —
are looked up literally, so a header genuinely named `X_Spam_Flag` or `Subject_json` keeps its own
name and its own value. Attribute names beginning with an underscore are not headers and raise
`AttributeError`.

The `received` header is intelligently parsed into individual hops, revealing the complete email
routing path. Each hop contains structured fields:

- `by` - Receiving mail server
- `date` - Timestamp of receipt (original timezone)
- `date_utc` - Normalized UTC timestamp
- `delay` - Time elapsed between consecutive hops
- `envelope_from` - SMTP envelope sender
- `envelope_sender` - Alternative envelope sender field
- `for` - Intended recipient
- `from` - Sending mail server
- `hop` - Sequential hop number
- `with` - Protocol used for transmission (SMTP, ESMTP, etc.)

> **Critical Security Feature**: mail-parser detects and reports structural defects in email
> messages.

The [defects](https://docs.python.org/3/library/email.message.html#email.message.Message.defects)
property identifies RFC non-compliance issues that may indicate malformed or malicious emails—a
crucial capability for security analysis and threat detection.

**Multi-Format Property Access Pattern**:

All parsed properties provide three access variants using intuitive suffixes:

- `property_name` - Returns structured Python object
- `property_name_json` - Returns JSON-serialized representation
- `property_name_raw` - Returns original, unprocessed header string

Example usage:

```python
mail.to  # Python list of recipient objects
mail.to_json  # JSON string representation
mail.to_raw  # Original "To:" header string as it appears in the email
```

The command-line tool outputs parsed emails in JSON format by default for easy integration with
other tools and pipelines.

### Address recovery and ambiguous headers

Address properties such as `from_`, `to`, and `reply_to` retain their list of
`(display_name, address)` tuples. Mailbox selection respects quoted strings,
escapes, nested comments, groups, and folding whitespace. For example:

```python
mail = mailparser.parse_from_string(
    "From: billing@trusted.example < billing@vendor.example >\r\n\r\n"
)
mail.from_
# [('billing@trusted.example', 'billing@vendor.example')]
mail.has_defects
# True
mail.address_header_defects[0]["reason"]
# 'invalid-display-name'
```

RFC 5322 permits whitespace around the mailbox inside `<...>`; the unquoted
`@` in this example's display name requires forensic recovery. A complete,
unambiguous angle-address takes precedence over its display name. Addresses
inside comments or quoted display names are never mailbox candidates.

Internationalized mailbox local parts and domains are accepted under
[RFC 6532 §3.2](https://www.rfc-editor.org/rfc/rfc6532.html#section-3.2):
`José <josé@example.com>`, `user@exämple.com`, and `山田 <yamada@例え.jp>`
parse without address defects. UTF-8 atoms are supported alongside quoted
local parts, comments, groups, and obsolete source routes. Unicode alone is
not an anomaly; ASCII delimiters and ambiguity checks still apply.

Mailbox code points are preserved: parsing does not apply NFC/NFKC, IDNA
conversion, or trim non-ASCII characters that resemble whitespace. This
preserves forensic identity rather than silently equating different inputs.
Malformed UTF-8 does not become a different valid address by dropping bytes.
It produces `invalid-utf8` evidence; undecodable bytes appear in diagnostic
`raw` as escaped surrogate code points (for example `\udcff` represents
byte `FF`). Valid neighbouring mailboxes remain available.

`address_header_defects` exposes recovery and ambiguity evidence. Each entry
contains `header`, zero-based `occurrence`, the original `raw` list item,
`reason`, `recovered`, and `candidates` (display-name/address dictionaries).
It is included in `mail`, `mail_partial`, and their JSON output when nonempty,
and also sets `has_defects` and the `AddressHeaderDefect` category. Diagnostics
are computed once per parse, including repeated header occurrences; address
properties retain their existing first-occurrence semantics.

Ambiguous or incomplete items are omitted from address tuples, with their
raw evidence and any structurally identified candidates retained in diagnostics.
Valid neighbouring items are parsed independently. Consumers making filtering
or attribution decisions should inspect these diagnostics: an empty address
list does not establish that the original header contained no addresses.
`structural-recovery` means the stdlib's interpretation could not be used; it
is not by itself proof of an RFC violation. This recovery policy is not a full
RFC validator or a guarantee of how every mail client displays malformed mail.
The complete original header values remain available through `from_raw`,
`to_raw`, etc.; literal headers colliding with computed metadata remain in
`headers` and `message.get_all(...)`.

Display names decode RFC 2047 encoded words only where the header grammar
permits them. For example, an unquoted `=?utf-8?Q?Alice?=` becomes `Alice`,
whereas the same text inside a quoted display name remains literal. Decoded
punctuation cannot introduce another mailbox, and decoding happens only once.
Recoverable encoded words longer than 75 characters remain readable and
produce an `overlong-encoded-word` address diagnostic.

### Trace recovery

`Received` clause boundaries and the timestamp separator respect comments,
quoted strings, domain literals and angle addresses. Ambiguous delimiters keep
the original field in `received[*]["raw"]` and produce
`received_header_defects` entries with `reason`, `raw`, `recovered`, `header`
and zero-based `occurrence`. These diagnostics set `has_defects` and the
`ReceivedHeaderDefect` category and appear in full and partial JSON output.
An ambiguous trusted hop stops sender-IP attribution; older headers cannot
supply a replacement IP. Balanced, unrecognized obsolete trace syntax remains
raw without being declared invalid solely because it is obsolete.

Envelope annotations (`envelope-from` and `envelope-sender`) are scanned
without regex backtracking, preserving quoted delimiters, comments, domain
literals and obsolete routes. Nested or unterminated envelope paths are not
selected as addresses: `nested-envelope-address` or
`unclosed-envelope-address` diagnostics retain the complete original field,
including folding, while other trace clauses remain available. For these
diagnostics, `recovered` indicates whether a later complete path was recovered
from an affected clause after the outer path closes. Markers use ASCII
case equivalence only; Unicode lookalikes remain literal evidence.
Repeated reasons are aggregated per header to avoid
duplicating the raw evidence for every malformed fragment. These annotations
are lexical extractions, not full SMTP mailbox validation; the existing output
for the valid null sender `<>` remains an absent envelope value.

### Date diagnostics

Impossible calendar dates, clock components and numeric timezone minutes no
longer normalize silently into different timestamps. They return `None` and
set `has_defects`. A mismatched weekday retains the numerical calendar date
and records the inconsistency. `date_header_defects` covers every `Date`,
`Resent-Date` and parsed `Received` timestamp, with `reason`, `raw`,
`recovered`, selected ISO `value` (or `None`), `header` and zero-based
`occurrence`. It appears in full/partial JSON and uses `DateHeaderDefect`.

Valid obsolete comments, short years and alphabetic zones remain supported.
Leap seconds map to the next representable Python datetime; the raw field
retains `:60`. The historical UTC representation for `-0000` and unknown
alphabetic zones does not establish the sender's local timezone. Dates outside
Python's datetime range carry `date-out-of-range` diagnostics.

### Inline text and charset recovery

A named `text/plain` or `text/html` part with explicit
`Content-Disposition: inline` appears in both the corresponding text collection
and `attachments`. The attachment retains its filename, metadata and payload
bytes. This additional body view is excluded for binary content, explicit
attachments and named inline parts inside an attached MIME container. HTML is
returned as text; parsing does not render it or fetch referenced resources.

Body decoding tries the declared charset against the original bytes. When that
fails, UTF-8 recovery keeps mislabeled readable text available and records a
`CharsetDecodeDefect`, including the part index, charset and recovery outcome.
If UTF-8 also fails, the text view uses replacement characters and reports that
loss; the original bytes remain available in the MIME part and any attachment.
Recovery sets `has_defects` even when the recovered text is readable.

Raw UTF-8 filenames and MIME metadata remain readable without changing the
original headers or payload. Invalid metadata bytes produce `MimeHeaderDefect`
with escaped raw evidence, the header occurrence and MIME part index. A charset
decoder that produces a non-Unicode scalar also triggers recovery: names retain
their literal encoded form and text retains a safe byte-derived view, keeping
JSON and CLI output encodable as UTF-8.

A malformed RFC 2231 parameter does not stop the parse, whatever Python's
`email` package does with it. A multipart boundary whose charset refuses the
octets (`boundary*=undefined''%41%42`) is read as the package reads a value
with an unknown charset, the percent-decoded octets as Latin-1 (`AB`), so its
parts are still found. A parameter with numbered and unnumbered sections
(`filename*0=report; filename*=utf-8''evil.exe; filename*1=.pdf`), or with a
section given twice (`filename*0=b.exe; filename*0=a`), is read on every
Python as the current releases read it: an unnumbered section is section 0,
or is dropped when section 0 exists (`report.pdf`), and equal sections keep
the order of the header (`b.exea`). A section number too long to be a number
leaves that parameter under its literal name.
The other parameters of the header are read as usual. Each case is a
`MimeHeaderDefect` of that MIME part, with the value as evidence:
`invalid-boundary-parameter` or `invalid-parameter-continuation`.

A multipart whose boundary is empty (`boundary=""`, `boundary*=utf-8''`, a
value of only white space) is still read with the delimiters `--` and `----`,
and its header is kept as received. RFC 2046 section 5.1.1 requires a boundary
of 1 to 70 characters, so the part reports the `MimeHeaderDefect`
`invalid-boundary-parameter: empty` with the raw parameter value.

Header decoding is strict. An unknown charset, invalid byte sequence or
non-Unicode scalar leaves the complete original header value literal instead
of dropping bytes or mixing a decoded prefix with the original. A
`HeaderDecodeDefect` sets `has_defects`; `mail.header_decoding_defects` contains
`reason`, `raw`, `header`, zero-based `occurrence`, zero-based MIME `part` and
`recovered`. Here `recovered=True` means the literal evidence is available,
not that decoding succeeded. This also covers nested non-address headers;
address display names retain their existing context-aware diagnostics.
Malformed encoded attachment names remain literal with `MimeHeaderDefect`.
Raw Unicode text remains readable alongside encoded-words; decoding leaves
literal spans intact and removes only ASCII folding whitespace between
adjacent encoded-words. The optional RFC 2231 language suffix, such as
`UTF-8*en`, is separated from the charset before strict decoding.

### Resource limits for container representations

Attached multipart containers and forwarded messages can repeat the same
descendant payloads many times. Their optional textual representations share
a per-message serialization budget. Preflight estimates reject expensive
subtrees before copying; actual generator visits and writes to all internal
text/byte buffers are also charged, including failed charset fallbacks.
The character-work budget is 32 times the original tree's estimated size,
with a floor of 1 Mi characters and a ceiling of 32 Mi characters. The estimate
includes raw header/payload lengths and 256 characters of overhead per part.
The node-visit budget is 16 times the number of MIME parts, with a floor of
1,024 and a ceiling of 100,000. These are work units, not an input-size limit
or an exact process-memory allowance.

When a representation cannot fit, it is omitted entirely from `attachments`;
no empty or truncated file is invented. `ResourceLimitDefect` sets
`has_defects`, and `mail.resource_limit_defects` records its `reason`, MIME
`part`, `filename` and `recovered=False`. Child attachments and neighboring
body parts continue to be recovered under the existing disposition rules.
The original container remains accessible at
`list(mail.message.walk())[defect["part"]]` for ordinary MIME-tree parts.
Recovered epilogue parts have indices after that original tree and remain
traceable to the original epilogue text. Neither a resource limit nor a
recovery diagnostic establishes malicious intent or invalid MIME syntax.

Both new diagnostic properties always return lists. Nonempty lists appear
in full and partial JSON output; literal wire headers colliding with those
names remain accessible through `headers` and `message`. The serialization
budget applies during parsing to container copies, not to input ingestion,
individual leaf payloads, or an explicit later `message_as_string` request.
Applications processing untrusted mail should still bound input size and
isolate workers according to their own resource constraints.

`message_as_string` raises `MailParserRecursionError` when the message is
nested too deeply to flatten. Flattening needs more stack per MIME nesting
level than parsing, so this can happen for a message that parsed without
error: with the default interpreter recursion limit, at roughly 250 levels.
Deep nesting is not a MIME syntax violation and sets no defect. `mail.message`
and `mail.mime_tree` still expose the original tree.

## Message structure

`mail.mime_tree` describes the MIME tree: one entry per MIME part, in the
order of the wire, containers included. Entry `i` is part `i`, the number
defect messages quote as `part N`. Each entry names its enclosing part in
`parent`, so the list is flat however deeply a sender nests the message.

```python
import mailparser

mail = mailparser.parse_from_file("example_mail")
for part in mail.mime_tree:
    print(
        "  " * part["depth"],
        part["index"],
        part["content_type"],
        part["roles"],
    )

print(mailparser.render_structure(mail))
```

| Key                         | Meaning                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| `index`, `parent`, `depth`  | Position in the list, position of the enclosing part (`None` for the root), nesting level. |
| `content_type`              | The type the parser acted on. Absent or unusable headers get the RFC 2045/2046 default.    |
| `content_type_raw`          | The literal `Content-Type` value, `None` when the part has none.                           |
| `content_transfer_encoding` | Declared encoding, `None` when absent.                                                     |
| `charset`, `boundary`       | Declared parameters.                                                                       |
| `content_disposition`       | Declared disposition type.                                                                 |
| `filename`, `content_id`    | Declared file name (decoded) and `Content-ID`.                                             |
| `size`                      | Octets of a leaf after transfer decoding; `None` for a container.                          |
| `roles`                     | How the part was classified: any of `container`, `body`, `attachment`.                     |
| `attachment`                | Position of the matching entry in `mail.attachments`.                                      |
| `defects`                   | Defect categories recorded against this part.                                              |
| `recovered`                 | `True` for a part recovered from an epilogue.                                              |
| `embedded_headers`          | Literal `from`, `subject` and `date` of a message enclosed in a `message/*` part.          |

The tree is the structure on the wire annotated with the parser's
interpretation, so the two can be compared: named inline text has the roles
`attachment` and `body`, an attached multipart has `container` and
`attachment`, and a leaf with no role was exposed neither as body text nor as
an attachment. Values are the ones the message declares; apart from
`content_type`, an absent header is `None`, never a default. A part whose
container representation was omitted for the
[resource limit](#resource-limits-for-container-representations) keeps the
`attachment` role, has `attachment` set to `None` and carries
`ResourceLimitDefect`.

`mail.mime_tree_json` is the same list as JSON. The tree is not part of
`mail.mail` or `mail.mail_json`, which are unchanged. `mime_tree` is a
computed name: a wire header called `Mime-Tree` stays readable through
`mail.headers`.

The tree is built the first time it is read. It has one entry per part, and
the number of parts is chosen by the sender: about 400 bytes of JSON per
entry, so a 2.7 MiB message made of 400,000 empty parts yields a 159 MiB
tree. Bound the input size, or the number of entries you keep, when the tree
of untrusted mail is stored or sent on. A boundary that an RFC 2231 charset
decodes to something that is not text is shown with `\udXXX` escapes and
reported as `MimeHeaderDefect`; one the charset cannot decode at all is shown
as its percent-decoded octets read as Latin-1, with the same defect.

`mailparser.render_structure(mail)` draws the message structure as text:

```text
MESSAGE
  From:         meteo@regione.vda.it
  Reply-To:     meteo@regione.vda.it
  Return-Path:  <meteo@regione.vda.it>
  To:           echo@tu-berlin.de, Porcile, M. <mporcile@server_mail.it>
  Subject:      Bollettino Meteorologico del 29/11/2015
  Date:         Sun, 29 Nov 2015 09:45:18 +0100
  Message-ID:   <4516257BC5774408ADC1263EEBBBB73F@ad.regione.vda.it>
  Defects:      CharsetDecodeDefect

DELIVERY PATH
  1  2015-11-29T08:45:17+00:00  WWWGESTIONE3 ([172.30.104.243])       ──▶ aspam2-ravda.regione.vda.it      Microsoft SMTPSVC(6.0.37…
  │  -3s
  2  2015-11-29T08:45:14+00:00  aspam2-ravda.regione.vda.it (unknown… ──▶ Websense Email Security Gateway  ESMTP
  │  +48s
  3  2015-11-29T08:46:02+00:00  smtp2.regione.vda.it (217.76.210.112… ──▶ smtp.customers.net               SMTP
  │  +0s
  4  2015-11-29T08:46:02+00:00  (no from or by clause)

MIME TREE
  0 multipart/mixed              [container]
  ├─ 1 multipart/related         [container]
  │  ├─ 2 multipart/alternative  [container]
  │  │  ├─ 3 text/plain          quoted-printable  iso-8859-1  2.2 KB  [body]
  │  │  └─ 4 text/html           8bit  4.0 KB  [body]
  │  │        ⚠ CharsetDecodeDefect
  │  ├─ 5 image/jpeg             base64  9.7 KB  [attachment]  disposition:inline  "intestazione.jpg"
  │  └─ 6 image/jpeg             base64  7.1 KB  [attachment]  disposition:inline  "logometeo.jpg"
  └─ 7 application/octet-stream  base64  1.0 MB  [attachment]  disposition:attachment  "Bollettino.pdf"
```

A warning mark means a defect the parser recorded for that hop or part; a
delay is printed as a number and never judged. Parts nested deeper than 32
levels are counted on one line instead of being drawn. Pass `ascii_only=True`
for ASCII connectors.

The drawing is safe to print: text taken from the message is cut to a bounded
width, and control characters, ANSI escapes, bidirectional and zero-width
formatting characters, and characters that draw nothing, are shown as visible
escapes such as `\x1b`. Letters of different scripts that merely look alike
are not detected. The values
in `mime_tree`, `headers` and `received` are not escaped. They are untrusted
text chosen by the sender: escape them before putting them in HTML, a terminal
or a diagram language.

## Defects and Their Critical Role in Email Security

### Inspecting defects and recovered evidence

A defect is a parsing anomaly, an inconsistent value, or a recovery/ambiguity
diagnostic; it does not by itself establish malicious intent or an RFC violation.
During parsing, mail-parser collects Python `email` defects from the MIME tree
and adds its own address, trace, date, charset and MIME-metadata diagnostics:
`mail.has_defects` becomes `True`, `mail.defects_categories` contains the category
names, and `mail.defects` contains a list of dictionaries mapping a content type
(for example `multipart/mixed`) or a diagnostic group (`address-headers`,
`received-headers`, `date-headers`, `mime-headers`) to lists of textual
descriptions. `AddressHeaderDefect`, `ReceivedHeaderDefect` and `DateHeaderDefect`
also populate `mail.address_header_defects`, `mail.received_header_defects` and
`mail.date_header_defects`, respectively; these properties always exist and are
empty lists when there are no corresponding diagnostics. Their entries contain
`reason`, `raw`, `header`, zero-based `occurrence` and `recovered`, plus address
`candidates` or the selected ISO date `value` where applicable. All occurrences
are examined, including repeated headers, while address properties and `mail.date`
retain first-occurrence semantics. `recovered=True` means a value was recovered,
not that the original input was valid; ambiguous address candidates remain
evidence rather than selected mailboxes, and valid neighbours remain available.
`CharsetDecodeDefect`, `MimeHeaderDefect` and collected standard-library defects
have textual entries in `mail.defects`, without dedicated structured properties;
the standard-library categories are described in
[Python's defect reference](https://docs.python.org/3/library/email.errors.html),
but this is not a guarantee that every defect Python can detect is collected
(for example, transfer-decoding defects added after the MIME-tree collection may
remain only in a part's `defects`). Full and partial output always include
`has_defects`; when defects exist they include `defects` and
`defects_categories`, with structured header diagnostics included when nonempty
(JSON represents the category set as a list). Original evidence remains accessible
through header properties such as `mail.from_raw`, `mail.message`, and individual
MIME parts. A "bad epilogue" has no separate category or `epilogue_defects`
property: `StartBoundaryNotFoundDefect` activates an attempt to recover a part
between the declared boundary markers in the top-level `mail.message.epilogue`,
and recovered content enters the usual text/attachment outputs without a separate
recovery-success diagnostic. This is a limited recovery path, not a scan of every
nested epilogue; an exception during this attempt is logged. An ordinary epilogue
is permitted by [RFC 2046 section 5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1)
and is not itself a defect. The examples below cover each reporting family,
successful and unsuccessful recovery, repeated headers, multiple simultaneous
defects and valid controls; `has_defects=False` only means the implemented checks
found no anomalies, not that the email passed a complete RFC validation.

```python
import base64
import json
import mailparser

# 1. Recovered address: all four diagnostic views describe the same problem.
mail = mailparser.parse_from_string(
    "From: billing@trusted.example < billing@vendor.example >\r\n\r\n"
)
assert mail.from_ == [("billing@trusted.example", "billing@vendor.example")]
assert mail.has_defects is True
assert "AddressHeaderDefect" in mail.defects_categories
assert mail.defects == [
    {"address-headers": ["AddressHeaderDefect: from[0]: invalid-display-name"]}
]
assert mail.address_header_defects == [
    {
        "reason": "invalid-display-name",
        "raw": "billing@trusted.example < billing@vendor.example >",
        "recovered": True,
        "candidates": [
            {
                "display_name": "billing@trusted.example",
                "address": "billing@vendor.example",
            }
        ],
        "header": "from",
        "occurrence": 0,
    }
]
assert json.loads(mail.mail_json)["address_header_defects"] == (
    mail.address_header_defects
)

# 2. Incomplete address: no selected mailbox; a valid neighbouring field survives.
mail = mailparser.parse_from_string(
    "From: Alice <alice@example.com\r\nTo: Bob <bob@example.com>\r\n\r\n"
)
assert mail.from_ == []
assert mail.to == [("Bob", "bob@example.com")]
assert mail.address_header_defects[0]["reason"] == "unclosed-delimiter"
assert mail.address_header_defects[0]["recovered"] is False

# 3. Repeated headers: diagnostics also cover occurrences after the first.
mail = mailparser.parse_from_string(
    "From: Alice <alice@example.com>\r\n"
    "From: billing@trusted.example <billing@vendor.example>\r\n\r\n"
)
assert mail.from_ == [("Alice", "alice@example.com")]
assert mail.address_header_defects[0]["occurrence"] == 1

# 4. Received: ambiguous trace syntax stays raw, with structured diagnostics.
trace = (
    "from sender.example (unclosed; by mx.example; 1 Jan 2024 12:00:00 +0000"
)
mail = mailparser.parse_from_string(f"Received: {trace}\r\n\r\n")
assert "ReceivedHeaderDefect" in mail.defects_categories
assert mail.received_header_defects[0]["reason"] == "unclosed-comment"
assert mail.received_header_defects[0]["recovered"] is False
assert mail.received[0]["raw"] == trace
assert "received-headers" in mail.defects[0]
trace = (
    "from sender.example by mx.example with ESMTP id token; "
    "for <bob@example.com>; 1 Jan 2024 12:00:00 +0000"
)
mail = mailparser.parse_from_string(f"Received: {trace}\r\n\r\n")
assert mail.received_header_defects[0]["reason"] == "misplaced-date-separator"
assert mail.received_header_defects[0]["recovered"] is True
assert mail.received[0]["for"] == "<bob@example.com>"

# 5. Dates: an impossible date is not selected; a wrong weekday is recoverable.
mail = mailparser.parse_from_string("Date: 31 Feb 2024 12:00:00 +0000\r\n\r\n")
assert "DateHeaderDefect" in mail.defects_categories
assert mail.date is None
assert mail.date_header_defects[0]["reason"] == "invalid-calendar-date"
assert mail.date_header_defects[0]["recovered"] is False
assert "date-headers" in mail.defects[0]
mail = mailparser.parse_from_string(
    "Date: Tue, 1 Jan 2024 12:00:00 +0000\r\n\r\n"
)
assert mail.date.isoformat() == "2024-01-01T12:00:00+00:00"
assert mail.date_header_defects[0]["reason"] == "weekday-mismatch"
assert mail.date_header_defects[0]["recovered"] is True
# Date diagnostics also cover Resent-Date and timestamps inside Received.
mail = mailparser.parse_from_string(
    "Resent-Date: 31 Feb 2024 12:00:00 +0000\r\n"
    "Received: from sender.example by mx.example; "
    "1 Jan 2024 25:00:00 +0000\r\n\r\n"
)
assert {d["header"] for d in mail.date_header_defects} == {
    "resent-date",
    "received",
}

# 6. Charset: failed declared decoding, then readable UTF-8 or replacement text.
for payload, expected in [(b"caf\xc3\xa9", "café"), (b"a\xffb", "a\ufffdb")]:
    mail = mailparser.parse_from_bytes(
        b"Content-Type: text/plain; charset=ascii\r\n\r\n" + payload
    )
    assert "CharsetDecodeDefect" in mail.defects_categories
    assert expected in mail.body
    assert "CharsetDecodeDefect:" in mail.defects[0]["text/plain"][0]
    assert mail.message.get_payload(decode=True) == payload

# 7. MIME metadata: damaged filename bytes are retained in textual evidence.
mail = mailparser.parse_from_bytes(
    b"Content-Type: application/octet-stream\r\n"
    b'Content-Disposition: attachment; filename="a\xffb.bin"\r\n'
    b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8="
)
assert "MimeHeaderDefect" in mail.defects_categories
assert "\\xff" in " ".join(mail.defects[0]["mime-headers"])
assert base64.b64decode(mail.attachments[0]["payload"]) == b"Hello"

# 8. Standard-library structure defects: missing parameter/start/closing boundary.
for raw, category in [
    (
        "Content-Type: multipart/mixed\r\n\r\nHello",
        "NoBoundaryInMultipartDefect",
    ),
    (
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\nHello',
        "StartBoundaryNotFoundDefect",
    ),
    (
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n",
        "CloseBoundaryNotFoundDefect",
    ),
    (
        "Subject: example\r\ninvalid header line\r\n\r\nHello",
        "MissingHeaderBodySeparatorDefect",
    ),
]:
    mail = mailparser.parse_from_string(raw)
    assert mail.has_defects
    assert category in mail.defects_categories
    assert any(
        category in text
        for entry in mail.defects
        for texts in entry.values()
        for text in texts
    )

# 9. Bad epilogue: reusing the parent's boundary corrupts nested MIME structure.
# The attachment after the first closing boundary lands in the outer epilogue.
raw = (
    'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
    '--b\r\nContent-Type: multipart/alternative; boundary="b"\r\n\r\n'
    "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n--b--\r\n"
    '--b\r\nContent-Type: application/octet-stream; name="evidence.txt"\r\n'
    'Content-Disposition: attachment; filename="evidence.txt"\r\n'
    "Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n--b--\r\n"
)
mail = mailparser.parse_from_string(raw)
assert mail.has_defects
assert "StartBoundaryNotFoundDefect" in mail.defects_categories
assert "multipart/alternative" in mail.defects[0]
assert "evidence.txt" in mail.message.epilogue
assert mail.attachments[0]["filename"] == "evidence.txt"
assert base64.b64decode(mail.attachments[0]["payload"]) == b"Hello"

# 10. Multiple families coexist; inspect every entry rather than only defects[0].
mail = mailparser.parse_from_string(
    "From: billing@trusted.example <billing@vendor.example>\r\n"
    "Date: 31 Feb 2024 12:00:00 +0000\r\n\r\n"
)
assert {"AddressHeaderDefect", "DateHeaderDefect"} <= mail.defects_categories
assert mail.address_header_defects and mail.date_header_defects

# 11. Valid controls: obsolete date syntax and an ordinary epilogue are accepted.
for raw in [
    "From: Alice <alice@example.com>\r\n"
    "Date: 1 Jan 24 12:00:00 GMT\r\n\r\nHello",
    'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
    "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n"
    "--b--\r\nOrdinary epilogue\r\n",
]:
    mail = mailparser.parse_from_string(raw)
    assert mail.has_defects is False
    assert mail.defects_categories == set()
    assert mail.defects == []
    assert mail.address_header_defects == []
    assert mail.received_header_defects == []
    assert mail.date_header_defects == []
```

Email structural defects are not merely technical curiosities—they represent **potential security
vulnerabilities** that sophisticated attackers actively exploit to bypass spam filters, antivirus
scanners, and email security gateways.

### Real-World Threat Scenarios

Malformed MIME boundaries, for example, can conceal illegitimate epilogue sections containing:

- **Malware Payloads**: Executable files or scripts hidden in non-standard message parts
- **Phishing Links**: Obfuscated URLs that bypass pattern-matching filters
- **Command-and-Control Data**: Encoded instructions for compromised systems
- **Data Exfiltration**: Steganographically hidden sensitive information

### mail-parser's Security Advantage

mail-parser was **specifically engineered for security analysis and digital forensics**, with defect
detection as a core feature rather than an afterthought. The library captures and categorizes even
subtle structural anomalies that other parsers silently ignore or mishandle.

By leveraging mail-parser's defect detection, security teams can:

- **Expose Hidden Content**: Discover deliberately obfuscated message parts that may contain
  malicious payloads.
- **Identify Attack Patterns**: Recognize non-standard formatting techniques used by threat actors
  to evade detection.
- **Enable Deep Forensics**: Conduct thorough structural analysis of suspicious emails during
  incident response.
- **Strengthen Defenses**: Build more resilient email security rules based on identified defect
  patterns.
- **Ensure Compliance**: Verify that outbound emails meet RFC standards to avoid delivery issues.

This robust defect detection mechanism has made mail-parser the **trusted choice for security
platforms like SpamScope**, where identifying malicious intent hidden in structural anomalies can
mean the difference between a blocked threat and a successful attack.

# Reporting Security Issues

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md) for supported
versions, private reporting channels and the disclosure process.

# Authors

## Main Author

**Fedele Mantuano**: [LinkedIn](https://www.linkedin.com/in/fmantuano/)

# Installation

mail-parser requires Python 3 and can be installed in seconds using pip. Follow these steps:

Use the latest patch release of your Python series. mail-parser parses with
Python's `email` package, and older patch releases take quadratic time on a
header with many parameters: an 80 KB `Content-Type` value takes more than a
second to parse on Python 3.9.6, 3.11.11, 3.12.8 and 3.13.2, and under 0.1
seconds on 3.10.22, 3.12.16, 3.13.18, 3.14.10 and 3.15.2.

## Quick Install

1. Ensure Python 3 is installed on your system.
1. Open your terminal or command prompt.
1. Install mail-parser from PyPI:

```bash
pip install mail-parser
```

1. (Optional) Verify the installation:

```bash
pip show mail-parser
```

## Development Installation

For contributors and developers who want to work with the source code, we recommend using `uv` for
dependency management:

```bash
git clone https://github.com/SpamScope/mail-parser.git
cd mail-parser
uv sync
```

This setup installs all development and testing dependencies in an isolated virtual environment,
ensuring a clean and reproducible development workflow.

For comprehensive documentation about `uv`, visit the [official uv documentation](https://docs.astral.sh/uv/).

# Usage in a Project

## Basic Usage

Import the `mailparser` module and use the convenient factory functions:

```python
import mailparser

mail = mailparser.parse_from_bytes(byte_mail)  # Parse from bytes object
mail = mailparser.parse_from_file(f)  # Parse from file path
mail = mailparser.parse_from_file_msg(outlook_mail)  # Parse Outlook .msg file
mail = mailparser.parse_from_file_obj(fp)  # Parse from file object
mail = mailparser.parse_from_string(raw_mail)  # Parse from string
```

File paths are read as bytes, preserving undecodable octets and original MIME
line endings just like `parse_from_bytes()`. This can expose defects that text
decoding previously hid. Declared charsets now also apply to file input: a
message mislabeled with a charset that successfully decodes its bytes can
display differently from the previous unconditional UTF-8 file read. UTF-8
recovery applies when the declared decode fails, not by guessing which valid
interpretation the sender intended. For byte-level forensic evidence, inspect the parsed
`message` and its `raw_items()`; undecodable header octets use Python's
surrogateescape representation. The string API accepts text already decoded
by its caller.

## Accessing Parsed Components

Once parsed, access all email components through intuitive properties:

```python
mail.attachments  # List of all attachments with metadata
mail.body  # Complete message body
mail.date  # Parsed datetime object (UTC)
mail.defects  # List of RFC compliance defects
mail.defects_categories  # Categorized defect types
mail.delivered_to  # Delivery address
mail.from_  # Sender information
mail.get_server_ipaddress(trust="my_server_mail_trust")  # Reliable sender IP
mail.headers  # All headers as structured object
mail.mail  # Fully tokenized mail object
mail.message  # Underlying email.message.Message object
mail.message_as_string  # Reconstructed message as string
mail.message_id  # Unique message identifier
mail.mime_tree  # One entry per MIME part, with its enclosing part
mail.received  # Parsed routing information (hop-by-hop)
mail.subject  # Email subject
mail.text_plain  # Plain text body parts (list)
mail.text_html  # HTML body parts (list)
mail.text_not_managed  # Unprocessed text parts (check logs for subtypes)
mail.to  # Recipient information
mail.to_domains  # Extracted recipient domains
mail.timezone  # Timezone information (offset from UTC)
mail.mail_partial  # Partial mail object (main parts only)
```

## Saving Attachments to Disk

Write all attachments to a specified directory:

```python
mail.write_attachments(base_path)
```

Attachment filenames are supplied by the email sender. The `filename` value in
`mail.attachments` intentionally preserves that untrusted metadata for analysis and display. Do
not pass it directly to `open()` or join it to a directory. The `safe_filename` field provides a
sanitized basename when one exists, but applications saving files should prefer
`write_attachments()`, which also validates containment, rejects symlink destinations, and
deduplicates names within the attachment batch. Deduplication is case-insensitive, because
APFS, exFAT and SMB collapse `Invoice.pdf` and `invoice.pdf` onto a single file.

A single unusable attachment never costs the rest of the batch: `write_attachments()` logs a
warning and moves on when a filename cannot be sanitized, a payload cannot be decoded, or the
write itself fails, so the remaining attachments are still saved. A containment failure is not
treated this way: it raises `MailParserPathError` and stops the batch.

# Usage from Command Line

After installing mail-parser with pip, you can use the `mail-parser` command-line tool for quick
email analysis, batch processing, or integration with shell scripts and pipelines.

## Command-Line Options

```text
usage: mail-parser [-h] (-f FILE | -s STRING | -k)
                   [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}] [-j] [-b]
                   [-a] [-r] [-t] [-dt] [-m] [-u] [-c] [-d] [-o]
                   [-i Trust mail server string] [-p] [-z] [-sa]
                   [-ap ATTACHMENTS_PATH] [-st] [--mime-tree] [-v]

Wrapper for email Python Standard Library

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Raw email file (default: None)
  -s, --string STRING   Raw email string (default: None)
  -k, --stdin           Enable parsing from stdin (default: False)
  -l, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}
                        Set log level (default: WARNING)
  -j, --json            Show the JSON of parsed mail (default: False)
  -b, --body            Print the body of mail (default: False)
  -a, --attachments     Print the attachments of mail (default: False)
  -r, --headers         Print the headers of mail (default: False)
  -t, --to              Print the to of mail (default: False)
  -dt, --delivered-to   Print the delivered-to of mail (default: False)
  -m, --from            Print the from of mail (default: False)
  -u, --subject         Print the subject of mail (default: False)
  -c, --receiveds       Print all receiveds of mail (default: False)
  -d, --defects         Print the defects of mail (default: False)
  -o, --outlook         Analyze Outlook msg (default: False)
  -i, --senderip Trust mail server string
                        Extract a reliable sender IP address heuristically
                        (default: None)
  -p, --mail-hash       Print mail fingerprints without headers (default:
                        False)
  -z, --attachments-hash
                        Print attachments with fingerprints (default: False)
  -sa, --store-attachments
                        Store attachments on disk (default: False)
  -ap, --attachments-path ATTACHMENTS_PATH
                        Path where store attachments (default: /tmp)
  -st, --structure      Draw the message structure: headers, delivery path,
                        MIME tree (default: False)
  --mime-tree           Print the MIME tree of mail as JSON (default: False)
  -v, --version         show program's version number and exit

It takes as input a raw mail and generates a parsed object.
```

## Examples

Parse an email file and output as formatted JSON:

```shell
mail-parser -f example_mail -j
```

Extract only the subject and sender:

```shell
mail-parser -f example_mail -u -m
```

Analyze an Outlook .msg file with defect detection:

```shell
mail-parser -f email.msg -o -d -j
```

Draw the message structure: main headers, delivery path and MIME tree:

```shell
mail-parser -f example_mail -st
```

Print the parsed mail and its MIME tree as two consecutive JSON documents:

```shell
mail-parser -f example_mail -j --mime-tree
```

Log messages go to standard error, so standard output holds only the output
you asked for and can be read as JSON:

```shell
mail-parser -f example_mail -j > example_mail.json
```

Parse from stdin (useful for pipelines):

```shell
cat raw_email.eml | mail-parser -k -j
```

See the transformation from [raw email](https://gist.github.com/fedelemantuano/5dd702004c25a46b2bd60de21e67458e)
to [beautifully parsed JSON output](https://gist.github.com/fedelemantuano/e958aa2813c898db9d2d09469db8e6f6).

# Exception Hierarchy

mail-parser uses a well-structured exception hierarchy for precise error handling:

```text
MailParserError: Base MailParser Exception
|
\── MailParserOutlookError: Raised with Outlook integration errors
|
\── MailParserEnvironmentError: Raised when the environment is not correct
|
\── MailParserOSError: Raised when there is an OS error
|
\── MailParserPathError: Raised when an attachment escapes the output directory
|
\── MailParserReceivedParsingError: Raised when a received header cannot be parsed
|
\── MailParserRecursionError: Raised when a message is nested too deeply to parse or flatten
```

# Docker Deployment

A pre-built Docker image is available for easy deployment and containerized workflows. Find the
[official image on Docker Hub](https://hub.docker.com/r/fmantuano/spamscope-mail-parser/).

## Quick Start with Docker

After installing Docker, run the containerized mail-parser:

```shell
sudo docker run -it --rm -v ~/mails:/mails fmantuano/spamscope-mail-parser
```

This command mounts your local `~/mails` directory into the container at `/mails`, allowing
mail-parser to access your email files. You can pass any command-line options supported by
mail-parser.

## Using Docker Compose

For more complex setups, a `docker-compose.yml` file is included in the repository. Run it with:

```shell
sudo docker-compose up
```

The default configuration includes:

- Read-only mount of your local `~/mails` directory to `/mails` in the container.
- A test command demonstrating mail-parser functionality.

Customize the `docker-compose.yml` file to adjust mount points, command-line options, or
environment variables for your specific use case.

# Working with coding agents

[AGENTS.md](AGENTS.md) is the shared source of development commands, coding
conventions, architecture notes, and security review requirements.
[Codex reads it automatically](https://developers.openai.com/codex/guides/agents-md).
[CLAUDE.md](CLAUDE.md) imports the same file using
[Claude Code's import syntax](https://code.claude.com/docs/en/memory#import-additional-files),
so updates to shared guidance belong in `AGENTS.md`.

The existing [security reviewer](.claude/agents/security-reviewer.md) remains
available as a Claude Code sub-agent. Codex follows the same review procedure
as described in `AGENTS.md`.

Two repository skills provide RFC parsing reviews: `mail-rfc-diff` for changed
code and `mail-rfc-assessment` for the entire repository. Both report demonstrated
issues with RFC references, runnable examples, and suggested resolutions. See
[installation and usage](docs/rfc-review-skills.md) for Codex and Claude Code.
