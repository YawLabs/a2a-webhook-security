"""HMAC-SHA256 canonical-string assembly and constant-time hex compare.

The canonical string is the byte concatenation of:

    <timestamp-decimal-ascii> + 0x2E (".") + <body-bytes>

This is encoding-agnostic: the body is the literal bytes the sender wrote
on the wire, with no transformation.
"""

from __future__ import annotations

import hmac
from hashlib import sha256


def compute_v1(secret: bytes, timestamp: int, body: bytes) -> str:
    """Compute the v1 signature -- HMAC-SHA256 lowercase hex over the
    canonical string for a (timestamp, body) pair against a single secret.

    Exposed so test vectors and other-language implementations can
    cross-check the canonical-string concatenation.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("compute_v1: secret must be bytes")
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("compute_v1: body must be bytes")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        raise TypeError("compute_v1: timestamp must be int")

    ts_bytes = str(timestamp).encode("ascii")
    canonical = ts_bytes + b"." + bytes(body)
    return hmac.new(bytes(secret), canonical, sha256).hexdigest()


def timing_safe_equal_hex(a: str, b: str) -> bool:
    """Constant-time comparison of two lowercase hex strings.

    Returns False (does not raise) when lengths differ or when either side
    contains non-hex characters. Both arguments are decoded and compared
    via hmac.compare_digest.

    Why we wrap compare_digest: callers compare two strings that should be
    valid lowercase hex. If one isn't, decoding to bytes silently drops the
    bad input, which would defeat constant-time intent. We validate first.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    if len(a) != len(b):
        return False
    if len(a) == 0:
        return True
    if not _is_lower_hex(a) or not _is_lower_hex(b):
        return False
    a_bytes = bytes.fromhex(a)
    b_bytes = bytes.fromhex(b)
    if len(a_bytes) != len(b_bytes):
        return False
    return hmac.compare_digest(a_bytes, b_bytes)


def _is_lower_hex(s: str) -> bool:
    for ch in s:
        c = ord(ch)
        is_digit = 0x30 <= c <= 0x39
        is_lower_af = 0x61 <= c <= 0x66
        if not is_digit and not is_lower_af:
            return False
    return True
