"""Python port of auth/packages/gateway-identity/src/index.ts identityFrom.

Decode only: the loopback Common Auth gateway must strip caller-supplied
identity headers and attach its own. No credentials are validated here.
The percent-utf8 marker and all four nonempty fields are required; decoding
matches decodeURIComponent (strict escapes/UTF-8, literal plus, no normalization).
Duplicate ASGI headers are joined as WHATWG Headers.get joins them.
"""
from __future__ import annotations

import re
from urllib.parse import unquote


def header_values(raw: list[tuple[bytes, bytes]]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in raw:
        name = key.decode('latin1').lower()
        value = value.decode('latin1')
        values[name] = values[name] + ', ' + value if name in values else value
    return values


def decode_percent_utf8(value: str | None) -> str | None:
    if not value or re.search(r'%(?![0-9a-fA-F]{2})', value):
        return None
    try:
        return unquote(value, encoding='utf-8', errors='strict')
    except UnicodeError:
        return None


def decode_subject(value: str | None) -> str | None:
    """X-Passage-Subject uses encodeURIComponent's ASCII wire representation."""
    if value is None or not value.isascii():
        return None
    return decode_percent_utf8(value)


def identity_from(headers: dict[str, str]) -> dict[str, str] | None:
    if headers.get('x-lost-plus-encoding') != 'percent-utf8':
        return None
    result = {}
    for field in ('sub', 'email', 'name', 'role'):
        value = decode_percent_utf8(headers.get('x-lost-plus-' + field))
        if value is None:
            return None
        result[field] = value
    return result
