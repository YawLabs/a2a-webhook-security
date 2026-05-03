"""Header parsing edge cases and round-trip tests.

These cover behavior the test-vectors.json doesn't exercise directly:
    - Round-tripping serialize -> parse.
    - Field-order independence.
    - Multi-v1 acceptance.
    - Whitespace tolerance around keys/values.
    - Unknown forward-compat fields ignored.
    - Edge length checks (>4096 byte header).
    - sign() public surface basics.
"""

from __future__ import annotations

import pytest

from yawlabs_awsp import (
    HeaderParseError,
    InMemoryReplayStore,
    ParsedSignatureHeader,
    SecretEntry,
    compute_v1,
    parse_signature_header,
    serialize_signature_header,
    sign,
    timing_safe_equal_hex,
    verify,
)


# ---------------------------------------------------------------------------
# Header parser
# ---------------------------------------------------------------------------


def test_parse_basic() -> None:
    raw = "t=1777248000,v1=" + "a" * 64 + ",n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k_2026_05"
    parsed = parse_signature_header(raw)
    assert parsed.timestamp == 1777248000
    assert parsed.v1 == ("a" * 64,)
    assert parsed.nonce == "AAAAAAAAAAAAAAAAAAAAAAAA"
    assert parsed.kid == "k_2026_05"


def test_parse_field_order_insignificant() -> None:
    sig = "a" * 64
    raw = f"kid=k_x,n=NNNN,v1={sig},t=1234567890"
    parsed = parse_signature_header(raw)
    assert parsed.timestamp == 1234567890
    assert parsed.v1 == (sig,)
    assert parsed.nonce == "NNNN"
    assert parsed.kid == "k_x"


def test_parse_multi_v1() -> None:
    a = "a" * 64
    b = "b" * 64
    raw = f"t=1,v1={a},v1={b},n=N,kid=k"
    parsed = parse_signature_header(raw)
    assert parsed.v1 == (a, b)


def test_parse_unknown_field_ignored() -> None:
    sig = "a" * 64
    raw = f"t=1,v1={sig},n=N,kid=k,extra=ignored"
    parsed = parse_signature_header(raw)
    assert parsed.kid == "k"


def test_parse_unknown_version_alone_is_unknown_algorithm() -> None:
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header("t=1,v99=somefuture,n=N,kid=k")
    assert exc_info.value.reason == "unknown_algorithm"


def test_parse_unknown_version_alongside_v1_is_accepted() -> None:
    sig = "a" * 64
    raw = f"t=1,v1={sig},v99=future,n=N,kid=k"
    parsed = parse_signature_header(raw)
    assert parsed.v1 == (sig,)


def test_parse_empty_header() -> None:
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header("")
    assert exc_info.value.reason == "malformed_header"


def test_parse_header_too_long() -> None:
    raw = "x" * 5000
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header(raw)
    assert exc_info.value.reason == "malformed_header"


def test_parse_uppercase_hex_rejected() -> None:
    raw = "t=1,v1=" + "A" * 64 + ",n=N,kid=k"
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header(raw)
    assert exc_info.value.reason == "malformed_header"


def test_parse_short_v1_rejected() -> None:
    raw = "t=1,v1=" + "a" * 63 + ",n=N,kid=k"
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header(raw)
    assert exc_info.value.reason == "malformed_header"


def test_parse_negative_timestamp_rejected() -> None:
    sig = "a" * 64
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header(f"t=-1,v1={sig},n=N,kid=k")
    assert exc_info.value.reason == "malformed_header"


def test_parse_missing_kid_rejected() -> None:
    sig = "a" * 64
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header(f"t=1,v1={sig},n=N")
    assert exc_info.value.reason == "malformed_header"


def test_parse_whitespace_in_pairs_tolerated() -> None:
    sig = "a" * 64
    parsed = parse_signature_header(f" t = 1 , v1 = {sig} , n = N , kid = k ")
    assert parsed.timestamp == 1


def test_parse_kid_with_dots_dashes_underscores() -> None:
    sig = "a" * 64
    parsed = parse_signature_header(
        f"t=1,v1={sig},n=N,kid=k_2026.05-rotation"
    )
    assert parsed.kid == "k_2026.05-rotation"


def test_parse_duplicate_t_rejected() -> None:
    sig = "a" * 64
    with pytest.raises(HeaderParseError) as exc_info:
        parse_signature_header(f"t=1,t=2,v1={sig},n=N,kid=k")
    assert exc_info.value.reason == "malformed_header"


# ---------------------------------------------------------------------------
# Header serializer round-trip
# ---------------------------------------------------------------------------


def test_serialize_round_trip() -> None:
    sig = "a" * 64
    parsed = ParsedSignatureHeader(
        timestamp=1777248000, v1=(sig,), nonce="N", kid="k_2026_05"
    )
    raw = serialize_signature_header(parsed)
    assert raw == f"t=1777248000,v1={sig},n=N,kid=k_2026_05"
    re_parsed = parse_signature_header(raw)
    assert re_parsed == parsed


def test_serialize_multi_v1() -> None:
    a = "a" * 64
    b = "b" * 64
    parsed = ParsedSignatureHeader(timestamp=1, v1=(a, b), nonce="N", kid="k")
    raw = serialize_signature_header(parsed)
    assert raw == f"t=1,v1={a},v1={b},n=N,kid=k"


# ---------------------------------------------------------------------------
# timing_safe_equal_hex
# ---------------------------------------------------------------------------


def test_timing_safe_equal_hex_matches_equal() -> None:
    assert timing_safe_equal_hex("abc123", "abc123") is True


def test_timing_safe_equal_hex_unequal_lengths() -> None:
    assert timing_safe_equal_hex("ab", "abcd") is False


def test_timing_safe_equal_hex_uppercase_rejected() -> None:
    assert timing_safe_equal_hex("ABC123", "abc123") is False


def test_timing_safe_equal_hex_non_hex_rejected() -> None:
    assert timing_safe_equal_hex("zzzzzz", "zzzzzz") is False


def test_timing_safe_equal_hex_empty_strings() -> None:
    assert timing_safe_equal_hex("", "") is True


# ---------------------------------------------------------------------------
# sign() public surface
# ---------------------------------------------------------------------------


def test_sign_produces_all_four_headers() -> None:
    secret = b"\x00" * 32
    headers = sign(
        secret=secret,
        key_id="k_test",
        body=b'{"a":1}',
        event_type="test.created",
        timestamp=1777248000,
        nonce="AAAAAAAAAAAAAAAAAAAAAAAA",
        webhook_id="00000000-0000-4000-8000-000000000000",
    )
    assert "X-A2A-Signature" in headers
    assert "X-A2A-Webhook-Id" in headers
    assert "X-A2A-Event-Type" in headers
    assert "X-A2A-Timestamp" in headers
    parsed = parse_signature_header(headers["X-A2A-Signature"])
    assert parsed.timestamp == 1777248000
    assert parsed.kid == "k_test"
    assert len(parsed.v1) == 1


def test_sign_default_timestamp_nonce_webhook_id_populated() -> None:
    headers = sign(
        secret=b"\x01\x02\x03\x04",
        key_id="k",
        body=b"",
        event_type="e",
    )
    parsed = parse_signature_header(headers["X-A2A-Signature"])
    assert parsed.timestamp > 1700000000
    assert all(
        c.isalnum() or c in "_-" for c in parsed.nonce
    ), "nonce must be base64url"
    # UUIDv4 string format check
    wid = headers["X-A2A-Webhook-Id"]
    assert len(wid) == 36
    assert wid.count("-") == 4


def test_sign_rejects_zero_length_secret() -> None:
    with pytest.raises(TypeError):
        sign(secret=b"", key_id="k", body=b"", event_type="e")


def test_sign_rejects_empty_key_id() -> None:
    with pytest.raises(TypeError):
        sign(secret=b"x", key_id="", body=b"", event_type="e")


def test_sign_rejects_empty_event_type() -> None:
    with pytest.raises(TypeError):
        sign(secret=b"x", key_id="k", body=b"", event_type="")


# ---------------------------------------------------------------------------
# verify() edge cases
# ---------------------------------------------------------------------------


def test_verify_missing_header_is_malformed() -> None:
    r = verify(
        headers={},
        body=b"",
        secrets=[SecretEntry(kid="k", secret=b"\x00" * 32)],
        now=1777248000,
    )
    assert not r.ok
    assert r.reason == "malformed_header"


def test_verify_replay_window_out_of_range_low() -> None:
    with pytest.raises(ValueError):
        verify(
            headers={"x-a2a-signature": "t=1,v1=" + "0" * 64 + ",n=A,kid=k"},
            body=b"",
            secrets=[],
            replay_window_seconds=30,
        )


def test_verify_replay_window_out_of_range_high() -> None:
    with pytest.raises(ValueError):
        verify(
            headers={"x-a2a-signature": "t=1,v1=" + "0" * 64 + ",n=A,kid=k"},
            body=b"",
            secrets=[],
            replay_window_seconds=700,
        )


def test_verify_multi_v1_validates_if_any_matches() -> None:
    secret = bytes(range(16))
    t = 1777248000
    body = b"hi"
    good_sig = compute_v1(secret, t, body)
    bad_sig = "0" * 64
    header = serialize_signature_header(
        ParsedSignatureHeader(
            timestamp=t,
            v1=(bad_sig, good_sig),
            nonce="AAAAAAAAAAAAAAAAAAAAAAAA",
            kid="k",
        )
    )
    r = verify(
        headers={"x-a2a-signature": header},
        body=body,
        secrets=[SecretEntry(kid="k", secret=secret)],
        now=t,
    )
    assert r.ok


def test_verify_rotation_old_and_new_secrets_both_accepted() -> None:
    old_secret = b"\x01" * 16
    new_secret = b"\x02" * 16
    t = 1777248000
    body = b"payload"

    headers = sign(
        secret=old_secret,
        key_id="k_old",
        body=body,
        event_type="e",
        timestamp=t,
        nonce="AAAAAAAAAAAAAAAAAAAAAAAA",
        webhook_id="00000000-0000-4000-8000-000000000000",
    )

    r = verify(
        headers={"x-a2a-signature": headers["X-A2A-Signature"]},
        body=body,
        secrets=[
            SecretEntry(kid="k_old", secret=old_secret),
            SecretEntry(kid="k_new", secret=new_secret),
        ],
        now=t,
    )
    assert r.ok
    assert r.kid == "k_old"


def test_verify_replay_store_returns_false_on_second_call() -> None:
    secret = b"\x07" * 16
    t = 1777248000
    body = b""
    headers = sign(
        secret=secret,
        key_id="k",
        body=body,
        event_type="e",
        timestamp=t,
        nonce="AAAAAAAAAAAAAAAAAAAAAAAA",
        webhook_id="00000000-0000-4000-8000-000000000000",
    )
    store = InMemoryReplayStore(clock=lambda: t)
    r1 = verify(
        headers={"x-a2a-signature": headers["X-A2A-Signature"]},
        body=body,
        secrets=[SecretEntry(kid="k", secret=secret)],
        replay_store=store,
        now=t,
    )
    assert r1.ok
    r2 = verify(
        headers={"x-a2a-signature": headers["X-A2A-Signature"]},
        body=body,
        secrets=[SecretEntry(kid="k", secret=secret)],
        replay_store=store,
        now=t,
    )
    assert not r2.ok
    assert r2.reason == "replayed"


def test_in_memory_replay_store_evicts_after_ttl() -> None:
    state = {"now": 1000}
    store = InMemoryReplayStore(clock=lambda: state["now"])
    assert store.check_and_store("n1", 60) is True
    assert store.check_and_store("n1", 60) is False
    state["now"] = 1061
    assert store.check_and_store("n1", 60) is True
