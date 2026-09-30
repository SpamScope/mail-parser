"""Structural address recovery for untrusted RFC 5322 header values.

The scanner owns lexical boundaries and checks complete addr-specs against
bounded grammar patterns. The stdlib supplies conventional display names for
structurally consistent items. Recovery never searches a display name or
comment for a convenient email substring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FOLD = re.compile(r"\r?\n[ \t]+")
# Anchored grammar checks: atom, quote and delimiter character sets do not
# overlap. In particular, do not search for bare addresses in arbitrary text
# or hand long malformed word sequences to headerregistry's quadratic parser.
_ATOM = r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+"
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
        if text.strip() or problems:
            items.append(_Item(raw[start:end], text, angles, problems, max_comment))
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
                if not _valid_phrase("".join(buf)):
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
    value = _FOLD.sub(" ", value).strip()
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
                domain = value[start:i].strip()
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
        value = value[start:].strip()
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
    for ch in _FOLD.sub(" ", value).strip():
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
    return bool(value.strip()) and not (quoted or escaped)


def _name(value: str) -> str:
    """Recover a display phrase, unquoting quoted pairs without regexes."""
    result = []
    quoted = escaped = False
    for ch in _FOLD.sub(" ", value).strip():
        if escaped:
            result.append(ch)
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
        else:
            result.append(ch)
    return "".join(result).strip()


def parse_address_header(raw: str, strict_parser):
    """Return mailbox tuples and evidence for recovery or ambiguity.

    ``strict_parser`` is the runtime-compatible email.utils adapter. Each
    list member is parsed independently so a malformed member cannot change
    the interpretation of a neighbouring, valid quoted name.
    """
    results = []
    diagnostics = []
    for item in _scan(raw):
        candidates = []
        # Derive the prefix once: repeating it for every angle-addr would
        # copy quadratically much text on a long ambiguous item.
        name = _name(item.text[: item.angles[0][0]]) if item.angles else ""
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
            if len(item.angles) != 1 or item.text[right + 1 :].strip():
                reason = "ambiguous-angle-address"
            elif not candidates:
                reason = "invalid-angle-address"
            else:
                selected = candidates
                if item.text[:left].strip() and not _valid_phrase(item.text[:left]):
                    reason = "invalid-display-name"
        else:
            address = _mailbox(item.text)
            if address:
                selected = [("", address)]
                candidates = selected
            else:
                reason = "invalid-or-ambiguous-address"

        if selected:
            # Deep comments are stripped by the iterative scanner before
            # reaching the stdlib's recursive comment parser.
            source = item.raw if item.comment_depth < 16 else item.text
            parsed = strict_parser([source])
            if [addr for _, addr in parsed if addr] == [a for _, a in selected]:
                selected = [(name, addr) for name, addr in parsed if addr]
            else:
                # Parsing can reject legal CFWS too. This records recovery,
                # not a claim that every rejection proves RFC noncompliance.
                reason = reason or "structural-recovery"
        results.extend(selected)
        if reason:
            diagnostics.append(
                {
                    "reason": reason,
                    "raw": item.raw,
                    "recovered": bool(selected),
                    "candidates": [
                        {"display_name": name, "address": addr}
                        for name, addr in candidates
                    ],
                }
            )
    return results, diagnostics
