"""AWSP -- A2A Webhook Security Profile reference implementation (Python).

This package implements the v1 signing/verification algorithm defined in
SPEC.md at the AWSP package root. It is dependency-free (Python stdlib
only) and has no I/O of its own; replay storage is a hook supplied by the
caller.

See SPEC.md for the wire format. Test vectors are at test-vectors.json.
"""

from __future__ import annotations

import os
import secrets as _secrets
import time
from dataclasses import dataclass
from typing import Literal, Mapping, Sequence

from ._headers import (
    HeaderParseError,
    ParsedSignatureHeader,
    ParseErrorReason,
    parse_signature_header,
    serialize_signature_header,
)
from ._replay import InMemoryReplayStore, ReplayStore
from ._signer import compute_v1, timing_safe_equal_hex

__all__ = [
    "AwspError",
    "HeaderParseError",
    "InMemoryReplayStore",
    "ParsedSignatureHeader",
    "ParseErrorReason",
    "ReplayStore",
    "SecretEntry",
    "SignedHeaders",
    "VerifyErrorReason",
    "VerifyFailure",
    "VerifyResult",
    "VerifySuccess",
    "compute_v1",
    "parse_signature_header",
    "serialize_signature_header",
    "sign",
    "timing_safe_equal_hex",
    "verify",
]

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretEntry:
    """A (kid, secret) pair the receiver knows about."""

    kid: str
    """Key identifier matching the kid= field on incoming signatures."""
    secret: bytes
    """Raw secret bytes."""


VerifyErrorReason = Literal[
    "malformed_header",
    "unknown_algorithm",
    "stale",
    "future",
    "replayed",
    "unknown_kid",
    "bad_hmac",
]


@dataclass(frozen=True)
class VerifySuccess:
    """Successful verify() result."""

    kid: str
    """Which kid validated."""
    timestamp: int
    """Signer's timestamp (seconds)."""
    nonce: str
    """Nonce from the header."""
    ok: Literal[True] = True


@dataclass(frozen=True)
class VerifyFailure:
    """Failed verify() result.

    `message` is a human-readable diagnostic. NEVER include this in 401
    response bodies; it can leak internal state. Use `reason` for the
    response and `message` for logs only.
    """

    reason: VerifyErrorReason
    message: str
    ok: Literal[False] = False


VerifyResult = VerifySuccess | VerifyFailure


class AwspError(Exception):
    """Generic AWSP error.

    Reserved for callers that want to translate VerifyFailure into an
    exception (verify() itself returns VerifyResult; it does not raise on
    invalid signatures).
    """


# Headers returned by sign().
SignedHeaders = dict[str, str]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_REPLAY_WINDOW_SECONDS = 300
MIN_REPLAY_WINDOW_SECONDS = 60
MAX_REPLAY_WINDOW_SECONDS = 600
REPLAY_STORE_TTL_BUFFER_SECONDS = 60


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def sign(
    *,
    secret: bytes,
    body: bytes,
    key_id: str,
    event_type: str,
    timestamp: int | None = None,
    nonce: str | None = None,
    webhook_id: str | None = None,
) -> SignedHeaders:
    """Produce the four AWSP headers for a payload.

    The HMAC is computed over `timestamp + "." + body-bytes`. The timestamp
    is formatted as decimal ASCII with no leading zeros.

    Args:
        secret: Raw secret bytes. Must be non-empty.
        body: Raw payload bytes. The HMAC is computed over `<timestamp>.<body>`.
        key_id: Identifier for `secret`; placed in the kid= field.
        event_type: Event-type label, placed in X-A2A-Event-Type.
        timestamp: Optional unix-seconds timestamp. Defaults to int(time.time()).
        nonce: Optional base64url nonce. Defaults to a random 18-byte nonce
            (24 base64url chars).
        webhook_id: Optional UUID for this delivery. Defaults to a generated
            UUIDv4.

    Returns:
        Dict of the four headers, ready to attach to an HTTP request:
        X-A2A-Signature, X-A2A-Webhook-Id, X-A2A-Event-Type, X-A2A-Timestamp.
    """
    if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
        raise TypeError("sign: secret must be non-empty bytes")
    if not isinstance(key_id, str) or len(key_id) == 0:
        raise TypeError("sign: key_id required")
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("sign: body must be bytes")
    if not isinstance(event_type, str) or len(event_type) == 0:
        raise TypeError("sign: event_type required")

    ts: int = timestamp if timestamp is not None else int(time.time())
    n: str = nonce if nonce is not None else _generate_nonce()
    wid: str = webhook_id if webhook_id is not None else _generate_uuid_v4()

    v1_hex = compute_v1(bytes(secret), ts, bytes(body))

    signature_header = serialize_signature_header(
        ParsedSignatureHeader(
            timestamp=ts,
            v1=(v1_hex,),
            nonce=n,
            kid=key_id,
        )
    )

    return {
        "X-A2A-Signature": signature_header,
        "X-A2A-Webhook-Id": wid,
        "X-A2A-Event-Type": event_type,
        "X-A2A-Timestamp": str(ts),
    }


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify(
    *,
    headers: Mapping[str, str],
    body: bytes,
    secrets: Sequence[SecretEntry],
    replay_store: ReplayStore | None = None,
    replay_window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
    now: int | None = None,
) -> VerifyResult:
    """Verify an incoming AWSP-signed request.

    Steps:
      1. Parse X-A2A-Signature.
      2. Window check: |now - t| <= replay_window_seconds.
      3. Recompute HMAC for each candidate secret (filtered by kid); reject
         if no candidate matches in constant time.
      4. Replay check: ask replay_store.check_and_store(nonce, window+60).
         Reject if it returns False.

    The order matters: cheap rejections (window) first, then HMAC, then
    replay. Replay is last because we don't want to consume nonce-storage
    capacity for forged requests.

    Args:
        headers: HTTP headers (case-insensitive lookup).
        body: Raw request body bytes.
        secrets: All (kid, secret) entries the receiver currently accepts.
        replay_store: Optional replay store; without one, replay protection
            is skipped.
        replay_window_seconds: Default 300; spec allows 60-600.
        now: Default int(time.time()); override for deterministic tests.

    Returns:
        VerifySuccess or VerifyFailure.
    """
    if (
        not isinstance(replay_window_seconds, int)
        or isinstance(replay_window_seconds, bool)
        or replay_window_seconds < MIN_REPLAY_WINDOW_SECONDS
        or replay_window_seconds > MAX_REPLAY_WINDOW_SECONDS
    ):
        raise ValueError(
            "verify: replay_window_seconds must be an integer in "
            f"[{MIN_REPLAY_WINDOW_SECONDS}, {MAX_REPLAY_WINDOW_SECONDS}]"
        )

    raw_header = _lookup_header(headers, "X-A2A-Signature")
    if raw_header is None:
        return VerifyFailure(
            reason="malformed_header", message="missing X-A2A-Signature"
        )

    try:
        parsed = parse_signature_header(raw_header)
    except HeaderParseError as err:
        reason: VerifyErrorReason = (
            "unknown_algorithm" if err.reason == "unknown_algorithm" else "malformed_header"
        )
        return VerifyFailure(reason=reason, message=str(err))

    current = now if now is not None else int(time.time())
    skew = current - parsed.timestamp
    if skew > replay_window_seconds:
        return VerifyFailure(reason="stale", message=f"timestamp {skew}s old")
    if skew < -replay_window_seconds:
        return VerifyFailure(reason="future", message=f"timestamp {-skew}s in the future")

    # Filter candidate secrets by kid (required in v1).
    candidates = [s for s in secrets if s.kid == parsed.kid]

    if len(candidates) == 0:
        return VerifyFailure(
            reason="unknown_kid", message=f"no secret for kid={parsed.kid}"
        )

    matched_kid: str | None = None
    for entry in candidates:
        expected = compute_v1(entry.secret, parsed.timestamp, body)
        for candidate in parsed.v1:
            # timing_safe_equal_hex is constant-time across equal-length
            # inputs and false-fast on length mismatch (impossible here --
            # both are guaranteed 64 hex chars by parse_signature_header --
            # but keeping the pattern makes future signature versions safer).
            if timing_safe_equal_hex(expected, candidate):
                matched_kid = entry.kid
                break
        if matched_kid is not None:
            break

    if matched_kid is None:
        return VerifyFailure(reason="bad_hmac", message="no signature matched")

    if replay_store is not None:
        ttl = replay_window_seconds + REPLAY_STORE_TTL_BUFFER_SECONDS
        fresh = replay_store.check_and_store(parsed.nonce, ttl)
        if not fresh:
            return VerifyFailure(reason="replayed", message="nonce already seen")

    return VerifySuccess(kid=matched_kid, timestamp=parsed.timestamp, nonce=parsed.nonce)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lookup_header(headers: Mapping[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            if isinstance(value, list):
                return value[0] if len(value) > 0 else None
            return value
    return None


def _generate_nonce() -> str:
    # 18 bytes -> 24 base64url chars, no padding.
    import base64

    raw = _secrets.token_bytes(18)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generate_uuid_v4() -> str:
    raw = bytearray(os.urandom(16))
    # Set version (4) and variant (10xx) per RFC 4122.
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    h = raw.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
