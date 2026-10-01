"""Structural address recovery for RFC 5322 / RFC 6532 header values.

The scanner owns lexical boundaries and checks complete addr-specs against
bounded grammar patterns. The stdlib supplies conventional display names for
structurally consistent items. Recovery never searches a display name or
comment for a convenient email substring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.header import decode_header

_FOLD = re.compile(r"\r?\n[ \t]+")
_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=")
# Anchored grammar checks: atom, quote and delimiter character sets do not
# overlap. In particular, do not search for bare addresses in arbitrary text
# or hand long malformed word sequences to headerregistry's quadratic parser.
# RFC 6532 section 3.2 extends atext with UTF8-non-ascii. These are
# Unicode scalar values (RFC 3629), not \w or all code points >= 128:
# surrogates cannot occur in valid UTF-8 and must remain defect evidence.
_UTF8_NON_ASCII = r"\x80-\ud7ff\ue000-\U0010ffff"
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
_ATOM = rf"[a-zA-Z0-9!#$%&'*+/=?^_`{{|}}~{_UTF8_NON_ASCII}-]+"
_QUOTED = r'"(?:[^"\\\r\n]|\\[^\r\n])*"'
_WORD = rf"(?:{_ATOM}|{_QUOTED})"
_LOCAL = rf"{_WORD}(?:[ \t]*\.[ \t]*{_WORD})*"
_DOMAIN = rf"{_ATOM}(?:[ \t]*\.[ \t]*{_ATOM})*"
_LITERAL = r"\[(?:[^\[\]\\\r\n]|\\[^\r\n])*\]"
_ADDR_SPEC = re.compile(rf"{_LOCAL}[ \t]*@[ \t]*(?:{_DOMAIN}|{_LITERAL})")


@dataclass
class _Item:
    raw: str
    text: str
    angles: list[tuple[int, int]]
    problems: list[str] = field(default_factory=list)
    comment_depth: int = 0


def _scan(raw: str) -> list[_Item]:
    """Split only at structural delimiters; bound work per input character."""
    items: list[_Item] = []
    buf: list[str] = []
    angles: list[tuple[int, int]] = []
    problems: list[str] = []
    start = 0
    angle = None
    comment = max_comment = 0
    quote = literal = escaped = group = False

    def emit(end):
        nonlocal buf, angles, problems, start, max_comment
        text = "".join(buf)
        raw_item = raw[start:end]
        if text.strip(" \t\r\n") or problems or _SURROGATE_RE.search(raw_item):
            items.append(_Item(raw_item, text, angles, problems, max_comment))
        buf, angles, problems = [], [], []
        start = end + 1
        max_comment = 0

    for i, ch in enumerate(raw):
        if escaped:
            if not comment:
                buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and (quote or comment or literal):
            escaped = True
            if not comment:
                buf.append(ch)
            continue
        if comment:
            if ch == "(":
                comment += 1
                max_comment = max(max_comment, comment)
            elif ch == ")":
                comment -= 1
            continue
        if quote:
            buf.append(ch)
            if ch == '"':
                quote = False
            continue
        if literal:
            buf.append(ch)
            if ch == "]":
                literal = False
            continue
        if ch == "(":
            comment = 1
            max_comment = max(max_comment, 1)
            buf.append(" ")
        elif ch == '"':
            quote = True
            buf.append(ch)
        elif ch == "[":
            literal = True
            buf.append(ch)
        elif ch == "<":
            if angle is not None:
                problems.append("nested-angle")
            else:
                angle = len(buf)
            buf.append(ch)
        elif ch == ">":
            if angle is None:
                problems.append("unmatched-angle")
            else:
                angles.append((angle, len(buf)))
                angle = None
            buf.append(ch)
        elif angle is None and ch == ",":
            emit(i)
        elif angle is None and ch == ":":
            if group or angles:
                problems.append("invalid-group-boundary")
                buf.append(ch)
            else:
                group = True
                # Preserve malformed labels as diagnostics, never mailboxes.
                if not _valid_phrase("".join(buf)) or _SURROGATE_RE.search(
                    raw[start:i]
                ):
                    problems.append("invalid-group-name")
                    emit(i)
                buf = []
                start = i + 1
        elif angle is None and ch == ";":
            if not group:
                problems.append("unmatched-group")
            emit(i)
            group = False
        else:
            if ch in ")]":
                problems.append("unmatched-delimiter")
            buf.append(ch)

    if quote or comment or literal or angle is not None or escaped:
        problems.append("unclosed-delimiter")
    if group:
        problems.append("unclosed-group")
    emit(len(raw))
    return items


def _mailbox(value: str) -> str | None:
    """Validate the whole addr-spec, including quoted local parts and CFWS."""
    value = _FOLD.sub(" ", value).strip(" \t\r\n")
    if _SURROGATE_RE.search(value):
        return None
    # RFC 5322 section 4.4: obsolete source routes precede the addr-spec.
    if value.startswith(("@", ",")):
        literal = escaped = False
        domains = []
        start = 0
        for i, ch in enumerate(value):
            if escaped:
                escaped = False
            elif ch == "\\" and literal:
                escaped = True
            elif ch == "[":
                literal = True
            elif ch == "]":
                literal = False
            elif not literal and ch in ",:":
                domain = value[start:i].strip(" \t\r\n")
                if domain:
                    domains.append(domain)
                start = i + 1
                if ch == ":":
                    break
        else:
            return None
        if not domains or any(
            not domain.startswith("@") or not _ADDR_SPEC.fullmatch("route" + domain)
            for domain in domains
        ):
            return None
        value = value[start:].strip(" \t\r\n")
    if not _ADDR_SPEC.fullmatch(value):
        return None
    # CFWS is not part of an atom. Retain spaces and escapes inside quoted
    # local parts and domain literals, but remove token-separating FWS.
    normalized = []
    quoted = literal = escaped = False
    for ch in value:
        if escaped:
            escaped = False
        elif ch == "\\" and (quoted or literal):
            escaped = True
        elif ch == '"' and not literal:
            quoted = not quoted
        elif ch == "[" and not quoted:
            literal = True
        elif ch == "]" and literal:
            literal = False
        if ch not in " \t" or quoted or literal:
            normalized.append(ch)
    return "".join(normalized)


def _valid_phrase(value: str) -> bool:
    """Check label specials outside quoted strings (period is obs-phrase)."""
    quoted = escaped = False
    for ch in _FOLD.sub(" ", value).strip(" \t\r\n"):
        if ord(ch) < 32 and ch != "\t":
            return False
        if escaped:
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif not quoted and ch in "@<>[]:;,\\":
            return False
    return bool(value.strip(" \t\r\n")) and not (quoted or escaped)


def _name(value: str) -> str:
    """Recover a display phrase, unquoting quoted pairs without regexes."""
    result = []
    quoted = escaped = False
    for ch in _FOLD.sub(" ", value).strip(" \t\r\n"):
        if escaped:
            result.append(ch)
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
        else:
            result.append(ch)
    return _escape_surrogates("".join(result).strip(" \t\r\n"))


def _decoded_word(
    value: str, start: int, comment: bool, problems: set[str]
) -> tuple[str, int] | None:
    """Recover one lexical word, reporting RFC 2047's length violation.

    Each regex component stops at whitespace or a question mark. Attempts
    only start at word boundaries, so even a failed match scans its token
    a constant number of times, rather than rescanning the whole suffix.
    """
    match = _ENCODED_WORD.match(value, start)
    if not match:
        return None
    end = match.end()
    if end < len(value) and value[end] not in (" \t)" if comment else " \t"):
        return None
    if end - start > 75:
        problems.add("overlong-encoded-word")
    try:
        pieces = []
        for data, charset in decode_header(match.group()):
            if isinstance(data, bytes):
                encoding = (charset or "ascii").split("*", 1)[0]
                if encoding == "unknown-8bit":
                    encoding = "utf-8"
                data = data.decode(encoding)
            if _SURROGATE_RE.search(data):
                problems.add("invalid-encoded-word")
                return None
            # Never inject control characters into the structural parser.
            if any(ord(ch) < 32 and ch != "\t" for ch in data):
                return None
            pieces.append(data)
    except (LookupError, UnicodeError, ValueError):
        return None
    return "".join(pieces), end


def _display_source(value: str, phrase: bool, problems: set[str]) -> str:
    """Decode lexical display words into safely quoted parser input.

    Structural mailbox checks use the original input. RFC 2047 words may
    be decoded in a phrase or comment, never inside quotes or addr-specs.
    Escape the rendered text before the conventional-name parser sees it,
    so decoded commas, angles and comments cannot become delimiters.
    """
    value = _FOLD.sub(" ", value)
    output = []
    comment = 0
    quoted = escaped = False
    i = 0
    while i < len(value):
        ch = value[i]
        if escaped:
            escaped = False
        elif ch == "\\" and (quoted or comment):
            escaped = True
        elif comment and ch == ")":
            comment -= 1
        elif not quoted and ch == "(":
            comment += 1
        elif not comment and ch == '"':
            quoted = not quoted
        elif not quoted and not comment and ch == "<":
            phrase = False
        elif (
            not quoted
            and (comment or phrase)
            and ch == "="
            and (i == 0 or value[i - 1] in (" \t(" if comment else " \t"))
        ):
            word = _decoded_word(value, i, bool(comment), problems)
            if word:
                pieces = [word[0]]
                end = word[1]
                # Adjacent encoded words discard intervening FWS. Join
                # once, rather than repeatedly copying an expanding name.
                while end < len(value):
                    next_start = end
                    while next_start < len(value) and value[next_start] in " \t":
                        next_start += 1
                    if next_start == end:
                        break
                    word = _decoded_word(value, next_start, bool(comment), problems)
                    if not word:
                        break
                    pieces.append(word[0])
                    end = word[1]
                text = "".join(pieces).replace("\\", "\\\\")
                if comment:
                    text = text.replace("(", "\\(").replace(")", "\\)")
                else:
                    text = '"' + text.replace('"', '\\"') + '"'
                output.append(text)
                i = end
                continue
        output.append(ch)
        i += 1
    return "".join(output)


def _escape_surrogates(value: str) -> str:
    """Keep invalid code points visible without emitting invalid UTF-8 JSON."""
    return value.encode("utf-8", "backslashreplace").decode("utf-8")


def parse_address_header(raw: str, strict_parser, *, decode_names=False):
    """Return mailbox tuples and evidence for recovery or ambiguity.

    ``strict_parser`` is the runtime-compatible email.utils adapter. Each
    list member is parsed independently so a malformed member cannot change
    the interpretation of a neighbouring, valid quoted name. Set
    ``decode_names`` to render display words after structural validation.
    """
    results = []
    diagnostics = []
    for item in _scan(raw):
        candidates = []
        display_problems: set[str] = set()
        # Derive the prefix once: repeating it for every angle-addr would
        # copy quadratically much text on a long ambiguous item.
        prefix = item.text[: item.angles[0][0]] if item.angles else ""
        name = _name(
            _display_source(prefix, True, display_problems) if decode_names else prefix
        )
        for index, (left, right) in enumerate(item.angles):
            address = _mailbox(item.text[left + 1 : right])
            if address:
                candidates.append((name if index == 0 else "", address))
        reason = None
        selected = []
        if item.problems:
            reason = ",".join(sorted(set(item.problems)))
        elif item.angles:
            left, right = item.angles[0]
            if len(item.angles) != 1 or item.text[right + 1 :].strip(" \t\r\n"):
                reason = "ambiguous-angle-address"
            elif not candidates:
                reason = "invalid-angle-address"
            else:
                selected = candidates
                if item.text[:left].strip(" \t\r\n") and not _valid_phrase(
                    item.text[:left]
                ):
                    reason = "invalid-display-name"
        else:
            address = _mailbox(item.text)
            if address:
                selected = [("", address)]
                candidates = selected
            else:
                reason = "invalid-or-ambiguous-address"

        invalid_utf8 = bool(_SURROGATE_RE.search(item.raw))
        if invalid_utf8:
            reason = "invalid-utf8"
        if selected and not invalid_utf8:
            # Deep comments are stripped by the iterative scanner before
            # reaching the stdlib's recursive comment parser.
            source = item.raw if item.comment_depth < 16 else item.text
            if decode_names:
                source = _display_source(source, bool(item.angles), display_problems)
            parsed = strict_parser([source])
            if [addr for _, addr in parsed if addr] == [a for _, a in selected]:
                selected = [(name, addr) for name, addr in parsed if addr]
            else:
                # Parsing can reject legal CFWS too. This records recovery,
                # not a claim that every rejection proves RFC noncompliance.
                reason = reason or "structural-recovery"
        if display_problems:
            reason = ",".join(filter(None, [reason, *sorted(display_problems)]))
        results.extend(selected)
        if reason:
            diagnostics.append(
                {
                    "reason": reason,
                    "raw": _escape_surrogates(item.raw),
                    "recovered": bool(selected),
                    "candidates": [
                        {"display_name": name, "address": addr}
                        for name, addr in candidates
                    ],
                }
            )
    return results, diagnostics
