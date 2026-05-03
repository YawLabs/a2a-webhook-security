"""AWSP header parsing and serialization.

X-A2A-Signature has the form:
    t=<unix-seconds>,v1=<hex>[,v1=<hex>...],n=<nonce-b64url>,kid=<keyId>

Order of fields is NOT significant. Multiple v* values are allowed
(algorithm rotation); receivers MUST accept the request if any one of
them validates against any known secret.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

ParseErrorReason = Literal[
    "malformed_header",
    "missing_timestamp",
    "missing_signature",
    "missing_nonce",
    "unknown_algorithm",
]


@dataclass(frozen=True)
class ParsedSignatureHeader:
    """Parsed contents of an X-A2A-Signature header value."""

    timestamp: int
    """Unix timestamp in seconds (signer's clock)."""
    v1: tuple[str, ...]
    """All v1 (HMAC-SHA256, lowercase hex) signatures present, in order."""
    nonce: str
    """Base64url-encoded nonce."""
    kid: str
    """Key identifier (opaque string). REQUIRED in v1."""


class HeaderParseError(Exception):
    """Raised when an X-A2A-Signature header cannot be parsed."""

    def __init__(self, reason: ParseErrorReason, message: str) -> None:
        super().__init__(message)
        self.reason: ParseErrorReason = reason


_TIMESTAMP_RE = re.compile(r"^[0-9]{1,15}$")
_V1_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_KEY_RE = re.compile(r"^v[0-9]+$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")
_KID_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

_MAX_HEADER_LEN = 4096


def parse_signature_header(raw: str) -> ParsedSignatureHeader:
    """Parse the X-A2A-Signature header value.

    Raises:
        HeaderParseError: on malformed input.
    """
    if not isinstance(raw, str) or len(raw) == 0:
        raise HeaderParseError("malformed_header", "empty header")
    if len(raw) > _MAX_HEADER_LEN:
        raise HeaderParseError("malformed_header", "header too long")

    timestamp: int | None = None
    v1_list: list[str] = []
    nonce: str | None = None
    kid: str | None = None
    saw_unknown_version = False

    for part in raw.split(","):
        eq = part.find("=")
        if eq <= 0 or eq == len(part) - 1:
            raise HeaderParseError("malformed_header", f"bad pair: {part}")
        key = part[:eq].strip()
        value = part[eq + 1 :].strip()
        if len(key) == 0 or len(value) == 0:
            raise HeaderParseError("malformed_header", f"empty key or value: {part}")

        if key == "t":
            if timestamp is not None:
                raise HeaderParseError("malformed_header", "duplicate t=")
            if not _TIMESTAMP_RE.match(value):
                raise HeaderParseError("malformed_header", "bad timestamp")
            timestamp = int(value, 10)
            if timestamp < 0:
                raise HeaderParseError("malformed_header", "bad timestamp")
        elif key == "v1":
            if not _V1_RE.match(value):
                raise HeaderParseError(
                    "malformed_header", "bad v1 (must be 64 lowercase hex)"
                )
            v1_list.append(value)
        elif _VERSION_KEY_RE.match(key):
            # Future signature versions: receivers ignore unknown versions.
            saw_unknown_version = True
        elif key == "n":
            if nonce is not None:
                raise HeaderParseError("malformed_header", "duplicate n=")
            if not _NONCE_RE.match(value):
                raise HeaderParseError(
                    "malformed_header",
                    "bad nonce (must be base64url, 1-256 chars)",
                )
            nonce = value
        elif key == "kid":
            if kid is not None:
                raise HeaderParseError("malformed_header", "duplicate kid=")
            if not _KID_RE.match(value):
                raise HeaderParseError("malformed_header", "bad kid")
            kid = value
        # Unknown field: ignore for forward compatibility.

    if timestamp is None:
        raise HeaderParseError("missing_timestamp", "t= required")
    if nonce is None:
        raise HeaderParseError("missing_nonce", "n= required")
    if len(v1_list) == 0:
        if saw_unknown_version:
            raise HeaderParseError(
                "unknown_algorithm", "no supported signature version"
            )
        raise HeaderParseError("missing_signature", "v1= required")
    if kid is None:
        # v1 mandates kid for forward-compatible rotation; receivers MUST
        # reject missing kid.
        raise HeaderParseError("malformed_header", "kid= required")

    return ParsedSignatureHeader(
        timestamp=timestamp,
        v1=tuple(v1_list),
        nonce=nonce,
        kid=kid,
    )


def serialize_signature_header(parsed: ParsedSignatureHeader) -> str:
    """Serialize a parsed signature header.

    Field order is t, v1..., n, kid. Returned value is the raw string suitable
    for placement in the X-A2A-Signature HTTP header.
    """
    fields: list[str] = [f"t={parsed.timestamp}"]
    for v in parsed.v1:
        fields.append(f"v1={v}")
    fields.append(f"n={parsed.nonce}")
    fields.append(f"kid={parsed.kid}")
    return ",".join(fields)
