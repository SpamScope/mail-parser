# Copilot Instructions for mail-parser

mail-parser is a **production-grade email parsing library** for Python that transforms raw email messages into
structured Python objects. Originally built as the foundation for [SpamScope](https://github.com/SpamScope/spamscope),
it excels at security analysis, forensics, and RFC-compliant email processing.

## Core Architecture

### Factory-Based API Pattern

**Always use factory functions** instead of direct `MailParser()` instantiation:

```python
import mailparser
mail = mailparser.parse_from_file(filepath)       # Standard email files
mail = mailparser.parse_from_string(raw_email)    # Email as string
mail = mailparser.parse_from_bytes(email_bytes)   # Email as bytes
mail = mailparser.parse_from_file_msg(msg_file)   # Outlook .msg files
```

### Triple-Format Property Access

Every parsed component offers **three access patterns** (`src/mailparser/core.py:550-570`):

```python
mail.subject          # Python object (decoded string)
mail.subject_raw      # Raw header value (JSON list)
mail.subject_json     # JSON-serialized version
```

This pattern applies to all properties via `__getattr__` magic in `core.py`.

### Property Naming Convention

Headers with hyphens use **underscore substitution** (`core.py:__getattr__`):

```python
mail.X_MSMail_Priority      # Accesses "X-MSMail-Priority" header
mail.Content_Type           # Accesses "Content-Type" header
```

## Development Workflows

### Dependency Management with uv

The project uses **[uv](https://github.com/astral-sh/uv)** (modern pip/virtualenv replacement) exclusively:

```bash
uv sync           # Install all dev/test dependencies (defined in pyproject.toml)
make install      # Alias for uv sync
```

Never use `pip` directly—all commands in Makefile use `uv run` prefix.

### Testing Patterns

```bash
make test         # pytest with coverage (generates coverage.xml, junit.xml, htmlcov/)
make lint         # ruff check .
make format       # ruff format .
make check        # lint + test
make pre-commit   # Run all pre-commit hooks
```

When adding features or fixing bugs you MUST follow these steps:

1. Add relevant test email to `tests/mails/` if demonstrating new case
2. Write tests in the corresponding test file following existing patterns, under `tests/`
3. Run `make test` to verify all tests pass before committing
4. Run `uv run mail-parser -f tests/mails/mail_test_11 -j` to manually verify JSON output and that new changes
   work as expected
5. Run `make pre-commit` to ensure code style compliance before pushing

**Test data location**: `tests/mails/` contains malformed emails, Outlook files, and various encodings
(`mail_test_1` through `mail_test_17`, `mail_malformed_1-3`, `mail_outlook_1`).

**Critical testing rule**: When modifying parsing logic, test against malformed emails to ensure security defect
detection still works.

### Build & Release Process

```bash
make build        # uv build → creates dist/*.tar.gz and dist/*.whl
make release      # build + twine upload to PyPI
```

Version is **dynamically loaded** from `src/mailparser/version.py` (see
`pyproject.toml:tool.hatch.version`).

## Security-First Parsing

### Defect Detection System

The parser identifies RFC violations that could indicate malicious intent (`core.py:240-268`):

```python
mail.has_defects          # Boolean flag
mail.defects              # List of defect dicts by content type
mail.defects_categories   # Set of defect class names (e.g., "StartBoundaryNotFoundDefect")
```

**Epilogue defect handling** (`core.py:320-335`): When `EPILOGUE_DEFECTS` are detected, parser extracts hidden
content between MIME boundaries that could contain malicious payloads.

### IP Address Extraction

`get_server_ipaddress(trust)` method (`core.py:487-528`) extracts sender IPs with **trust-level validation**:

```python
# Finds first non-private IP in trusted headers
mail.get_server_ipaddress(trust="Received")
```

Filters out private IP ranges using Python's `ipaddress` module.

### Received Header Parsing

Complex regex-based parsing (`utils.py:302-360`, patterns in `const.py:24-73`) extracts hop-by-hop routing:

```python
# Returns list of dicts with: by, from, date, date_utc, delay, envelope_from, hop, with
mail.received
```

**Key pattern**: `RECEIVED_COMPILED_LIST` contains pre-compiled regexes for "from", "by", "with", "id", "for",
"via", "envelope-from", "envelope-sender", and date patterns. Recent fixes addressed IBM gateway duplicate matches
(see comments in `const.py:26-38`).

If parsing fails, falls back to `receiveds_not_parsed()` returning `{"raw": <header>, "hop": <n>}`
structure.

## Project Structure Specifics

### src/ Layout

Package uses modern **src-layout** (`src/mailparser/`) for cleaner imports and testing isolation:

```text
src/mailparser/
├── __init__.py      # Exports factory functions
├── __main__.py      # CLI entry point (mail-parser command)
├── core.py          # MailParser class (760 lines)
├── utils.py         # Parsing utilities (582 lines)
├── const.py         # Regex patterns and constants
├── exceptions.py    # Exception hierarchy
└── version.py       # Version string
```

### External Dependency: Outlook Support

Outlook `.msg` file parsing requires **system-level Perl module**:

```bash
apt-get install libemail-outlook-message-perl  # Debian/Ubuntu
```

Triggered via `msgconvert()` function in `utils.py` that shells out to Perl script. Raises `MailParserOutlookError`
if unavailable.

### CLI Tool Pattern

`__main__.py` provides production CLI with mutually exclusive input modes (`-f`, `-s`, `-k`), JSON output (`-j`),
and selective printing (`-b`, `-a`, `-r`, `-t`).

**Entry point defined** in `pyproject.toml:project.scripts`:

```toml
[project.scripts]
mail-parser = "mailparser.__main__:main"
```

## Code Style & Tooling

### Ruff Configuration

Single linter/formatter (replaces black, isort, flake8):

```toml
[tool.ruff.lint]
select = ["E", "F", "I"]  # pycodestyle, pyflakes, isort
# "UP", "B", "SIM", "S", "PT" commented out in pyproject.toml
```

### Pytest Configuration

Key markers in `pyproject.toml:tool.pytest.ini_options`:

- `integration`: marks integration tests
- Coverage outputs: XML (for CI), HTML (for local), terminal
- JUnit XML for CI integration

## Common Pitfalls

1. **Don't instantiate `MailParser()` directly**—use factory functions from `__init__.py`
2. **Don't use `pip`**—always use `uv` or Makefile targets
3. **Don't ignore defects**—they're critical for security analysis
4. **Don't assume headers exist**—use `.get()` pattern or handle `None`
5. **Test against malformed emails**—`tests/mails/mail_malformed_*` files exist for this reason

## Docker Development

Dockerfile uses **Python 3.10-slim-bookworm** with Outlook dependencies pre-installed. Container runs as non-root
`mailparser` user.

```bash
docker build -t mail-parser .
docker run mail-parser -f /path/to/email
```

## Key Reference Points

- **Property implementation**: `core.py:540-730` (all `@property` decorators)
- **Attachment extraction**: `core.py:355-475` (walks multipart, handles encoding)
- **Received parsing logic**: `utils.py:302-455` + `const.py:24-73` (regex patterns)
- **CLI implementation**: `__main__.py:30-347` (argparse + output formatting)
- **Exception hierarchy**: `exceptions.py:20-60` (5 exception types)

## Testing Strategy

When adding features:

1. Add test email to `tests/mails/` if demonstrating new case
2. Write tests in `tests/test_mail_parser.py` following existing patterns
3. Test both normal and `_raw`/`_json` property variants
4. Verify defect detection for security-relevant changes
5. Run `make check` before committing
