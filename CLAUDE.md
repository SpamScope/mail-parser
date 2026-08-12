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

**Never resolve a header name with `getattr`, and never rewrite it**: `__getattr__` serves names
the *caller* types, so it may fold `_`→`-`, honour the `_json`/`_raw` suffixes, and use `getattr`
to reach computed parts (`attachments_json`). Names taken from a parsed message must go through
`MailParser._header_value()`, which looks the name up literally in the header index and never
touches a Python attribute. Both halves matter:

- Python looks up real class attributes before `__getattr__`, so a sender naming a header `Parse`
  or `Headers_json` otherwise picks which attribute is read — a bound method lands in the parsed
  mail, or a property re-enters itself. Excluding individual names from a key set is not a fix;
  that is what let `Headers_json` through after `headers` was excluded.
- Suffix handling on a wire name is an amplifier and an evasion: each `_json` re-serializes the
  previous result (five input bytes per doubling of the output), and `Subject_json:` reports the
  value of `Subject` while silently dropping its own.

**Header index**: `_build_header_index()` maps lowercased name → list of raw values once per
parse. `Message.get_all()` is a linear scan, so the one call per distinct name previously made by
`_make_mail()` cost O(distinct × total) on attacker-chosen names. Look up via the index inside any
loop over header names.

**RFC non-compliance fallback in `get_addresses()`**: Python's
`email.utils.getaddresses(strict=True)` (hardened against CVE-2023-27043) rejects headers where
the display name contains `@`. Since this is a forensics tool, `utils.py` applies
`_ADDR_FALLBACK_RE` whenever strict parsing returns empty results — always surfacing what is
actually in the header.

**Received header parsing**: `utils.receiveds_parsing()` tokenizes on RFC 5321 clause keywords
(`from`, `by`, `via`, `with`, `id`, `for`, `envelope-from`) using `const._CLAUSE_SPLITTER`.
Output list is ordered first-hop first. Unparseable headers fall back to `{"raw": ...}`.

**Sender-IP attribution fails closed**: `get_server_ipaddress()` walks trust-matching `Received`
headers only while a hop names a *private* IP (an internal relay); a hop naming **no** IP ends the
search with `None`. Never resume the walk on that case — older `Received` headers are written by
the sender, so "extraction failed" would become "returns the sender's chosen IP".

Candidate addresses come only from the `from` clause (`utils.get_from_clause()`, which ends at the
next RFC 5321 keyword). Inside it, `_sender_ip_candidates()` applies one positional rule, because
**text cannot be classified by what it looks like** — a closed `[...]` pair the sender wrote is
byte-identical to one the MTA wrote, and `EHLO [8.8.8.8]` is a form RFC 5321 §4.1.3 requires:

- the **first token** is the HELO name, whatever its shape, and is never a candidate;
- an explicit **HELO marker inside a comment group** (`(helo=x)`, `(account a@b HELO x)`) is
  sender text and is excluded, located with `const._HELO_RE`;
- a candidate must sit **inside a `(`/`[` group** (`utils.group_spans()`), which is what makes a
  clause truncated by a multi-word HELO fail closed — what it leaves behind is bare;
- IPv4 and IPv6 matches are merged **positionally**, never family-first: choosing IPv4 first let
  one private literal at EHLO suppress the IPv6 scan and hide the real sender.

Only concession: `from [ip] (helo=x)` (Exim/CommuniGate), accepted when there is no other
candidate and the marker is in a group. Do not add lookbehind guards to `_HELO_RE` to patch new
cases — three rounds of that each reopened a hole the previous one closed.

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

If the new part is computed by a `MailParser` property rather than read off the wire, add it to
`COMPUTED_PARTS` as well — that set is exactly what `_make_mail()` is allowed to resolve through
attribute access.

## Workflow

After every change:

1. Add/update unittests to cover the change.
1. Update README.md if the change affects usage, API, or setup.
1. Stage changes and run pre-commit; fix all reported issues before proceeding.
1. Run full test suite; fix all failures before reporting done.
1. Run a security review of the change with the `security-reviewer` sub-agent
   (`.claude/agents/security-reviewer.md`). All parsed input is
   attacker-controlled, so any change to parsing, regexes, subprocess, temp
   files, or attachment handling must be reviewed. Reproduce and fix every
   High/Medium finding (with a regression test) before reporting done.
