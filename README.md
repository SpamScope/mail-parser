[![PyPI - Version](https://img.shields.io/pypi/v/mail-parser)](https://pypi.org/project/mail-parser/)
[![Coverage Status](https://coveralls.io/repos/github/SpamScope/mail-parser/badge.svg?branch=develop)](https://coveralls.io/github/SpamScope/mail-parser?branch=develop)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/mail-parser?color=blue)](https://pypistats.org/packages/mail-parser)

![SpamScope](https://raw.githubusercontent.com/SpamScope/spamscope/develop/docs/logo/spamscope.png)

# mail-parser

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
either path.

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

# Support the Future of mail-parser

mail-parser is a **labor of love and commitment to the open-source community**. Thousands of
developers and security professionals worldwide rely on this library for critical email processing
and threat analysis. Your support directly fuels continued innovation and excellence.

## Invest in Innovation

Your contribution—no matter the size—makes a real difference. By supporting mail-parser, you enable us to:

- **Advance Security Capabilities**: Develop cutting-edge detection mechanisms for emerging email
  threats and attack vectors.
- **Expand Format Support**: Add compatibility with new email formats and standards as they evolve.
- **Enhance Performance**: Optimize parsing speed and memory efficiency for large-scale deployments.
- **Maintain Excellence**: Ensure comprehensive testing, documentation, and bug-free releases that
  you can trust in production.
- **Foster Community**: Respond to issues, review contributions, and build a thriving ecosystem
  around email security.
- **Stay RFC-Compliant**: Keep pace with evolving email standards and specifications to ensure
  maximum compatibility.

Every donation, whether $5 or $500, directly funds development time and infrastructure costs. Join
the community of supporters who believe in **accessible, reliable, and secure email parsing for
everyone**.

[![Donate](https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif "Donate")](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=VEPXYP745KJF2)

Or contribute with Bitcoin:

<a href="bitcoin:bc1qxhz3tghztpjqdt7atey68s344wvmugtl55tm32">
  <img src="https://github.com/SpamScope/mail-parser/blob/develop/docs/images/Bitcoin%20SpamScope.jpg?raw=true"
       alt="Bitcoin" width="200">
</a>

**Bitcoin Address:** `bc1qxhz3tghztpjqdt7atey68s344wvmugtl55tm32`

Thank you for supporting the evolution of mail-parser!

# mail-parser on Web

Explore mail-parser on these platforms:

- **[FreeBSD port](https://www.freshports.org/mail/py-mail-parser/)**
- **[Arch User Repository](https://aur.archlinux.org/packages/mailparser/)**
- **[REMnux](https://docs.remnux.org/discover-the-tools/analyze+documents/email+messages#mail-parser)**

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
- `headers` - All headers as a structured object
- `attachments` - Complete attachment metadata and payloads
- `get_server_ipaddress()` - Reliable sender IP extraction with trust levels
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
- `filename` - Original filename of the attachment
- `mail_content_type` - MIME content type
- `payload` - Base64-encoded attachment data, ready for decoding or storage

To access custom or vendor-specific headers, replace hyphens with underscores. For example, to
access the `X-MSMail-Priority` header:

```python
mail.X_MSMail_Priority
```

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
mail.to          # Python list of recipient objects
mail.to_json     # JSON string representation
mail.to_raw      # Original "To:" header string as it appears in the email
```

The command-line tool outputs parsed emails in JSON format by default for easy integration with
other tools and pipelines.

## Defects and Their Critical Role in Email Security

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

# Authors

## Main Author

**Fedele Mantuano**: [LinkedIn](https://www.linkedin.com/in/fmantuano/)

# Installation

mail-parser requires Python 3 and can be installed in seconds using pip. Follow these steps:

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

mail = mailparser.parse_from_bytes(byte_mail)      # Parse from bytes object
mail = mailparser.parse_from_file(f)               # Parse from file path
mail = mailparser.parse_from_file_msg(outlook_mail) # Parse Outlook .msg file
mail = mailparser.parse_from_file_obj(fp)          # Parse from file object
mail = mailparser.parse_from_string(raw_mail)      # Parse from string
```

## Accessing Parsed Components

Once parsed, access all email components through intuitive properties:

```python
mail.attachments              # List of all attachments with metadata
mail.body                     # Complete message body
mail.date                     # Parsed datetime object (UTC)
mail.defects                  # List of RFC compliance defects
mail.defects_categories       # Categorized defect types
mail.delivered_to             # Delivery address
mail.from_                    # Sender information
mail.get_server_ipaddress(trust="my_server_mail_trust")  # Reliable sender IP
mail.headers                  # All headers as structured object
mail.mail                     # Fully tokenized mail object
mail.message                  # Underlying email.message.Message object
mail.message_as_string        # Reconstructed message as string
mail.message_id               # Unique message identifier
mail.received                 # Parsed routing information (hop-by-hop)
mail.subject                  # Email subject
mail.text_plain               # Plain text body parts (list)
mail.text_html                # HTML body parts (list)
mail.text_not_managed         # Unprocessed text parts (check logs for subtypes)
mail.to                       # Recipient information
mail.to_domains               # Extracted recipient domains
mail.timezone                 # Timezone information (offset from UTC)
mail.mail_partial             # Partial mail object (main parts only)
```

## Saving Attachments to Disk

Write all attachments to a specified directory:

```python
mail.write_attachments(base_path)
```

# Usage from Command Line

After installing mail-parser with pip, you can use the `mailparser` command-line tool for quick
email analysis, batch processing, or integration with shell scripts and pipelines.

## Command-Line Options

```text
usage: mailparser [-h] (-f FILE | -s STRING | -k)
                   [-l {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}] [-j] [-b]
                   [-a] [-r] [-t] [-dt] [-m] [-u] [-c] [-d] [-o]
                   [-i Trust mail server string] [-p] [-z] [-v]

Wrapper for email Python Standard Library

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Raw email file (default: None)
  -s STRING, --string STRING
                        Raw email string (default: None)
  -k, --stdin           Enable parsing from stdin (default: False)
  -l {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}, --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG,NOTSET}
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
  -i Trust mail server string, --senderip Trust mail server string
                        Extract a reliable sender IP address heuristically
                        (default: None)
  -p, --mail-hash       Print mail fingerprints without headers (default:
                        False)
  -z, --attachments-hash
                        Print attachments with fingerprints (default: False)
  -sa, --store-attachments
                        Store attachments on disk (default: False)
  -ap ATTACHMENTS_PATH, --attachments-path ATTACHMENTS_PATH
                        Path where store attachments (default: /tmp)
  -v, --version         show program's version number and exit

It takes as input a raw mail and generates a parsed object.
```

## Examples

Parse an email file and output as formatted JSON:

```shell
mailparser -f example_mail -j
```

Extract only the subject and sender:

```shell
mailparser -f example_mail -u -m
```

Analyze an Outlook .msg file with defect detection:

```shell
mailparser -f email.msg -o -d -j
```

Parse from stdin (useful for pipelines):

```shell
cat raw_email.eml | mailparser -k -j
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
\── MailParserReceivedParsingError: Raised when a received header cannot be parsed
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
