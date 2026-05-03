"""Run every vector from packages/awsp/test-vectors.json against the
reference sign / verify implementation. All 50 vectors must pass.
"""

from __future__ import annotations

from typing import Any

import pytest

from yawlabs_awsp import (
    InMemoryReplayStore,
    SecretEntry,
    VerifySuccess,
    compute_v1,
    verify,
)


def _hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def _build_header(t: int, v1_hex: str, n: str, kid: str) -> str:
    return f"t={t},v1={v1_hex},n={n},kid={kid}"


def test_50_vectors_loaded(vectors: list[dict[str, Any]], vectors_file: dict[str, Any]) -> None:
    assert len(vectors) == 50
    assert vectors_file["vector_count"] == 50


def _vector_id(v: dict[str, Any]) -> str:
    name = v.get("name", "<no-name>")
    return str(name)


def _all_vectors() -> list[dict[str, Any]]:
    # Loaded eagerly so pytest can parametrize cleanly.
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parent.parent.parent.parent / "test-vectors.json"
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    result: list[dict[str, Any]] = data["vectors"]
    return result


@pytest.mark.parametrize("v", _all_vectors(), ids=_vector_id)
def test_vector(v: dict[str, Any]) -> None:
    secret = _hex_to_bytes(v["secret_hex"])
    body = _hex_to_bytes(v["body_hex"]) if "body_hex" in v else b""

    # Always exercise computeV1 so canonical-string concatenation is covered
    # for every body. For valid vectors, assert it matches the published
    # expected hex.
    computed = compute_v1(secret, v["timestamp"], body)
    if "expected_signature_hex" in v:
        assert computed == v["expected_signature_hex"], (
            f"compute_v1 mismatch for {v['name']}: "
            f"expected {v['expected_signature_hex']}, got {computed}"
        )

    # Build the headers presented to verify().
    # Use is-None checks (not truthiness) to match the TS test's ?? operator:
    # an empty raw_signature_header ("") is a valid presentation for the
    # malformed_empty_header vector and must NOT fall through to a built one.
    sig_hex = v.get("expected_signature_hex")
    if sig_hex is None:
        sig_hex = v.get("presented_signature_hex")
    if sig_hex is None:
        sig_hex = computed
    if "raw_signature_header" in v:
        header_value = v["raw_signature_header"]
    else:
        header_value = _build_header(
            v["timestamp"], sig_hex, v["nonce_b64url"], v["kid"]
        )
    headers = {
        "x-a2a-signature": header_value,
        "x-a2a-webhook-id": "00000000-0000-4000-8000-000000000000",
        "x-a2a-event-type": "test.event",
        "x-a2a-timestamp": str(v["timestamp"]),
    }

    # Receiver secret list. Most vectors use the kid in the vector itself.
    # The unknown_kid vector specifies which kid the receiver actually knows.
    receiver_kid = v.get("receiver_known_kid", v["kid"])
    secrets = [SecretEntry(kid=receiver_kid, secret=secret)]

    # Replay setup: if the vector seeds nonces, use a store and pre-seed it.
    replay_setup = v.get("replay_setup")
    replay_store: InMemoryReplayStore | None
    if replay_setup is not None:
        now_value = v["now"]
        replay_store = InMemoryReplayStore(clock=lambda: now_value)
        for n in replay_setup["seed_nonces"]:
            replay_store.check_and_store(n, 360)
    else:
        replay_store = None

    result = verify(
        headers=headers,
        body=body,
        secrets=secrets,
        replay_store=replay_store,
        replay_window_seconds=300,
        now=v["now"],
    )

    expected = v["expected_verify"]
    if expected == "ok":
        assert isinstance(result, VerifySuccess), (
            f"{v['name']} expected ok, got reason="
            f"{getattr(result, 'reason', '?')} message="
            f"{getattr(result, 'message', '?')}"
        )
    else:
        assert not result.ok, f"{v['name']} expected error, got ok"
        assert result.reason == expected["error"], (
            f"{v['name']} expected reason={expected['error']}, "
            f"got {result.reason}: {getattr(result, 'message', '?')}"
        )
