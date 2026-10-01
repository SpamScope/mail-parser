"""RFC 5322 date interpretation with explicit forensic diagnostics."""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

_MONTHS: tuple[str, ...] = tuple(
    "jan feb mar apr may jun jul aug sep oct nov dec".split()
)
_WEEKDAYS: tuple[str, ...] = tuple("mon tue wed thu fri sat sun".split())
_ZONES = {
    "UT": 0,
    "GMT": 0,
    "EST": -300,
    "EDT": -240,
    "CST": -360,
    "CDT": -300,
    "MST": -420,
    "MDT": -360,
    "PST": -480,
    "PDT": -420,
}
# CFWS is removed in a bounded scan first. The remaining repetitions do
# not overlap: digits, spaces and fixed delimiters have separate roles.
_DATE = re.compile(
    r"(?:(?P<weekday>mon|tue|wed|thu|fri|sat|sun) *, *)?"
    r"(?P<day>[0-9]{1,2}) *(?P<month>" + "|".join(_MONTHS) + r") *"
    r"(?P<year>[0-9]{2,}) *(?P<hour>[0-9]{2}) *: *"
    r"(?P<minute>[0-9]{2})(?: *: *(?P<second>[0-9]{2}))?"
    r"(?P<zone_space> *)(?P<zone>[+-][0-9]+|[a-z]+)",
    re.I | re.ASCII,
)


@dataclass(frozen=True)
class DateResult:
    """A selected UTC value/offset and the reasons requiring diagnostics.

    ``value`` is None when no safe timestamp can be selected. ``timezone``
    retains the legacy numeric-string format, or 0 for no selected value.
    The original zone token, including unknown-local-zone forms, remains
    in the caller's raw field. ``reasons`` never labels obsolete syntax or
    representable leap seconds invalid merely because Python lacks them.
    """

    value: datetime.datetime | None = None
    timezone: str | int = 0
    reasons: tuple[str, ...] = ()


def _date_tokens(raw):
    """Replace nested comments and FWS with spaces without joining tokens."""
    output = []
    depth = 0
    escaped = False
    gap = False
    for char in raw:
        if depth:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            continue
        if char == "(":
            depth = 1
            gap = True
        elif char == ")":
            return None
        elif char in " \t\r\n":
            gap = True
        else:
            if gap and output:
                output.append(" ")
            gap = False
            output.append(char)
    return None if depth else "".join(output)


def parse_mail_date(raw):
    """Interpret modern/obsolete date-time without normalizing violations.

    Args:
        raw (str or None): unmodified date-time field value; None is absent.

    Returns:
        DateResult: safe selected UTC datetime and explicit defect reasons.
        A wrong weekday is recoverable from the numerical calendar date.
        Invalid day/time/zone components produce no selected datetime.

    RFC 5322 sections 3.3/4.3 and erratum 6639 permit obsolete CFWS, short
    years and alphabetic zones. Unknown alphabetic zones have -0000
    semantics. A leap second maps to the next representable datetime,
    preserving the existing API convention; the raw field keeps :60.
    """
    if raw is None:
        return DateResult()
    invalid_utf8 = False
    try:
        raw.encode("utf-8", "surrogateescape").decode("utf-8")
    except UnicodeError:
        invalid_utf8 = True
    tokens = _date_tokens(raw)
    match = _DATE.fullmatch(tokens) if tokens is not None else None
    if match is None:
        return DateResult(reasons=("invalid-date-syntax",))

    year_text = match["year"]
    # Check magnitude before int(), avoiding integer digit-limit failures.
    if len(year_text.lstrip("0")) > 4:
        return DateResult(reasons=("date-out-of-range",))
    year = int(year_text.lstrip("0") or "0")
    if len(year_text) == 2:
        year += 2000 if year < 50 else 1900
    elif len(year_text) == 3:
        year += 1900
    month = _MONTHS.index(match["month"].lower()) + 1
    day = int(match["day"])
    try:
        calendar_date = datetime.date(year, month, day)
    except ValueError:
        return DateResult(reasons=("invalid-calendar-date",))
    if year < 1900:
        return DateResult(reasons=("invalid-calendar-date",))

    hour, minute = int(match["hour"]), int(match["minute"])
    second = int(match["second"] or "0")
    if hour > 23 or minute > 59 or second > 60:
        return DateResult(reasons=("invalid-time",))
    zone = match["zone"].upper()
    if zone[0] in "+-":
        if len(zone) != 5 or int(zone[-2:]) > 59:
            return DateResult(reasons=("invalid-zone",))
        if not match["zone_space"]:
            return DateResult(reasons=("invalid-date-syntax",))
        offset = int(zone[1:3]) * 60 + int(zone[3:])
        offset *= -1 if zone[0] == "-" else 1
    else:
        if zone == "J":
            return DateResult(reasons=("invalid-zone",))
        # RFC 5322 section 4.3: unknown alphabetic zones, including military
        # letters, carry unknown-local-zone semantics, as does -0000.
        offset = _ZONES.get(zone, 0)

    try:
        value = datetime.datetime(
            year,
            month,
            day,
            hour,
            minute,
            min(second, 59),
            tzinfo=datetime.timezone.utc,
        ) - datetime.timedelta(minutes=offset)
        if second == 60:
            value += datetime.timedelta(seconds=1)
    except (OverflowError, ValueError):
        return DateResult(reasons=("date-out-of-range",))
    weekday = match["weekday"]
    reasons = ("invalid-utf8",) if invalid_utf8 else ()
    if weekday and _WEEKDAYS.index(weekday.lower()) != calendar_date.weekday():
        reasons += ("weekday-mismatch",)
    return DateResult(value, f"{offset / 60:+.1f}", reasons)


def date_diagnostics(result, raw, header, occurrence):
    """Return occurrence-aware diagnostic entries for one interpretation.

    Args:
        result (DateResult): parsed timestamp and defect reasons.
        raw (str): entire original field body, including trace clauses.
            Surrogates become visible escapes, as in address diagnostics;
            unmodified octets remain available through Message.raw_items().
        header (str): lowercased date-bearing field name.
        occurrence (int): zero-based occurrence within that field name.

    Returns:
        list[dict]: reasons with raw evidence and any selected ISO value.
    """
    return [
        {
            "reason": reason,
            "raw": raw.encode("utf-8", "backslashreplace").decode("utf-8"),
            "recovered": result.value is not None,
            "value": result.value.isoformat() if result.value else None,
            "header": header,
            "occurrence": occurrence,
        }
        for reason in result.reasons
    ]
