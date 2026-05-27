# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Engineering Principles

- **DRY** — extract repeated logic; no copy-paste code.
- **KISS** — simplest solution that works; no clever tricks.
- **YAGNI** — no code for hypothetical future needs.
- **SRP** — one function/class, one responsibility.
- **Fail fast** — validate at boundaries; trust internal code.
- No dead code, commented-out blocks, or unused imports.
- Every third-party import must have an explicit entry in `pyproject.toml`. Use extras when the
  runtime feature requires them (e.g. `elasticsearch[async]`).

## Python Style

- Follow PEP 8. Use 4 spaces, never tabs.
- Lines: 79 chars for code, 72 for comments/docstrings.
- `snake_case` for functions/variables, `CapWords` for classes, `UPPER_CASE` for constants.
- Imports order: stdlib → third-party → local.
- Add docstrings to all public functions, methods, classes, and modules (params, return values,
  exceptions).

## Commands

```bash
uv sync                  # install all dependencies
uv run pytest            # run all tests
uv run pytest tests/test_mail_parser.py::TestMailParser::test_name  # single test
uv run ruff check .      # lint
uv run ruff format .     # format
make check               # lint + tests
make build               # clean + build wheel/sdist
```

## Architecture

**Package layout**: `src/mailparser/` (src layout, no runtime deps — stdlib only).

### Module responsibilities

| Module          | Role                                                                  |
| --------------- | --------------------------------------------------------------------- |
| `core.py`       | `MailParser` class + `parse_from_*` factory functions                 |
| `utils.py`      | Stateless parsing helpers (address, received headers, date, encoding) |
| `const.py`      | Compiled regexes, header sets, clause splitter                        |
| `exceptions.py` | Custom exception hierarchy                                            |
| `__main__.py`   | CLI entry point (`mail-parser` command)                               |
| `__init__.py`   | Re-exports public API                                                 |

### Key design patterns

**Dynamic attribute access via `__getattr__`**: `MailParser` exposes every header dynamically.
Three access modes are supported for any attribute `X`:

- `parser.X` → Python object (str or list)
- `parser.X_json` → JSON string
- `parser.X_raw` → raw JSON via `message.get_all()`

Address headers listed in `const.ADDRESSES_HEADERS` (`from`, `to`, `cc`, `bcc`, `reply-to`,
`delivered-to`) return `list[tuple[str, str]]` (display_name, email) instead of plain strings.

**RFC non-compliance fallback in `get_addresses()`**: Python's
`email.utils.getaddresses(strict=True)` (hardened against CVE-2023-27043) rejects headers where
the display name contains `@`. Since this is a forensics tool, `utils.py` applies
`_ADDR_FALLBACK_RE` whenever strict parsing returns empty results — always surfacing what is
actually in the header.

**Received header parsing**: `utils.receiveds_parsing()` tokenizes on RFC 5321 clause keywords
(`from`, `by`, `via`, `with`, `id`, `for`, `envelope-from`) using `const._CLAUSE_SPLITTER`.
Output list is ordered first-hop first. Unparseable headers fall back to `{"raw": ...}`.

**Defect detection**: During `parse()`, every MIME part is walked and `_append_defects()` records
RFC violations. `EPILOGUE_DEFECTS` triggers special epilogue extraction to recover hidden payloads
in malformed boundaries.

**Outlook support**: `parse_from_file_msg()` shells out to the system `msgconvert` Perl tool
(`libemail-outlook-message-perl`) to convert `.msg` → `.eml`, then parses normally.

**Partial vs full mail**: `_make_mail(complete=True)` includes all headers found in the message;
`complete=False` restricts to `const.ADDRESSES_HEADERS | const.OTHERS_PARTS` (the "main" headers).
Accessible as `parser.mail` / `parser.mail_partial`.

### Adding new headers

To make a header always appear in partial output, add its lowercase name to `OTHERS_PARTS` in
`const.py`. Address-type headers (returning parsed name/email tuples) go in `ADDRESSES_HEADERS`.

## Workflow

After every change:

1. Add/update unittests to cover the change.
1. Update README.md if the change affects usage, API, or setup.
1. Stage changes and run pre-commit; fix all reported issues before proceeding.
1. Run full test suite; fix all failures before reporting done.

### Test fixtures

Raw email files in `tests/mails/` are the fixtures. `mail_malformed_*` files exercise defect
detection; `mail_outlook_*` require `msgconvert` installed. Tests that need the Outlook tool should
be marked `@pytest.mark.integration`.
