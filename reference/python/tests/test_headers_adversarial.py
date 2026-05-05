"""Adversarial / fuzz tests for parse_signature_header.

The contract: the parser MUST EITHER return a well-formed
ParsedSignatureHeader OR raise HeaderParseError. It MUST NOT crash with
any other exception type, return malformed data, or leak
implementation-detail exceptions.

Two layers of fuzz:

1. Hypothesis property-based fuzz across arbitrary text, byte-truncated
   variants of valid headers, and structured field permutations. Used
   only if hypothesis is installed (it's in the test extra in
   pyproject.toml; CI installs it).
2. A seedable random.Random fuzz loop that runs unconditionally, so the
   adversarial coverage holds even in environments without hypothesis.

Plus targeted regression cases for every spec-defined error reason.
"""

from __future__ import annotations

import random
import string
from typing import Optional

import pytest

from yawlabs_awsp import HeaderParseError, parse_signature_header

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    _HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover - skip path
    _HAS_HYPOTHESIS = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SIG = "a" * 64
_VALID_HEADER = f"t=1777248000,v1={_SIG},n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k_2026_05"


def _safe_parse(raw: str) -> Optional[HeaderParseError]:
    """Run the parser. Return None on success, the HeaderParseError on
    expected failure. Re-raise any OTHER exception type so pytest reports
    it -- those are bugs.
    """
    try:
        parsed = parse_signature_header(raw)
    except HeaderParseError as exc:
        return exc
    # Success -- assert structural invariants the parser promises.
    assert isinstance(parsed.timestamp, int)
    assert parsed.timestamp >= 0
    assert isinstance(parsed.v1, tuple)
    assert len(parsed.v1) >= 1
    for sig in parsed.v1:
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)
    assert isinstance(parsed.nonce, str)
    assert 1 <= len(parsed.nonce) <= 256
    assert isinstance(parsed.kid, str)
    assert 1 <= len(parsed.kid) <= 128
    return None


# ---------------------------------------------------------------------------
# Targeted regression cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("trunc_at", list(range(0, len(_VALID_HEADER) + 1)))
def test_truncated_at_every_byte_boundary(trunc_at: int) -> None:
    """Truncating the valid header at any byte boundary either parses
    (rare -- only if the truncation happens to leave a complete valid
    structure) or raises HeaderParseError. Never crashes."""
    raw = _VALID_HEADER[:trunc_at]
    _safe_parse(raw)  # raises on bug


def test_oversized_header_rejected() -> None:
    raw = "x" * 5000
    err = _safe_parse(raw)
    assert err is not None
    assert err.reason == "malformed_header"


def test_exactly_at_max_len_does_not_crash() -> None:
    # 4096 chars exactly -- at the boundary the parser tolerates
    raw = "x" * 4096
    err = _safe_parse(raw)
    assert err is not None  # garbage at any size still raises


def test_duplicate_t_rejected() -> None:
    raw = f"t=1,t=2,v1={_SIG},n=N,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_duplicate_n_rejected() -> None:
    raw = f"t=1,v1={_SIG},n=A,n=B,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_duplicate_kid_rejected() -> None:
    raw = f"t=1,v1={_SIG},n=N,kid=a,kid=b"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_multiple_v1_accumulates() -> None:
    a = "a" * 64
    b = "b" * 64
    c = "c" * 64
    raw = f"t=1,v1={a},v1={b},v1={c},n=N,kid=k"
    err = _safe_parse(raw)
    assert err is None


def test_mixed_case_v1_key_not_recognized() -> None:
    # Spec keys are lowercase; "V1" is unknown and gets ignored, which
    # leaves the header with no v1=, which is missing_signature ->
    # malformed_header surface.
    raw = f"t=1,V1={_SIG},n=N,kid=k"
    err = _safe_parse(raw)
    assert err is not None
    # missing_signature is a parser-level reason; verify() collapses it
    # to malformed_header. Either at this layer is acceptable per spec.
    assert err.reason in ("missing_signature", "malformed_header")


def test_mixed_case_kid_value_accepted() -> None:
    # kid CASING in value is allowed (kid charset is alphanum + ._-)
    raw = f"t=1,v1={_SIG},n=N,kid=K_Mixed-Case.05"
    err = _safe_parse(raw)
    assert err is None


def test_whitespace_around_keys_and_values_tolerated() -> None:
    raw = f" t = 1 , v1 = {_SIG} , n = N , kid = k "
    err = _safe_parse(raw)
    assert err is None


def test_tab_in_value_rejected() -> None:
    # Tab is not in the kid/nonce charset; reject.
    raw = f"t=1,v1={_SIG},n=N,kid=k\tx"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_non_printable_in_value_rejected() -> None:
    raw = f"t=1,v1={_SIG},n=N\x01,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_very_high_timestamp_post_2_53_rejected_by_format() -> None:
    # _TIMESTAMP_RE caps at 15 digits (1e15 == 2001-09-09 in ms, but in
    # seconds is far in the future -- still acceptable per regex).
    # 16+ digits should be rejected.
    raw = f"t=1234567890123456,v1={_SIG},n=N,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_15_digit_timestamp_accepted() -> None:
    # Boundary: exactly 15 digits is acceptable per the regex.
    raw = f"t=999999999999999,v1={_SIG},n=N,kid=k"
    err = _safe_parse(raw)
    assert err is None


def test_negative_timestamp_rejected() -> None:
    raw = f"t=-1,v1={_SIG},n=N,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_empty_value_rejected() -> None:
    raw = f"t=,v1={_SIG},n=N,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_bare_key_rejected() -> None:
    raw = f"t=1,v1,n=N,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_bare_equals_rejected() -> None:
    raw = "=,t=1,v1=" + _SIG + ",n=N,kid=k"
    err = _safe_parse(raw)
    assert err is not None and err.reason == "malformed_header"


def test_only_equals_rejected() -> None:
    err = _safe_parse("=")
    assert err is not None and err.reason == "malformed_header"


def test_empty_header_rejected() -> None:
    err = _safe_parse("")
    assert err is not None and err.reason == "malformed_header"


# ---------------------------------------------------------------------------
# Spec-defined error reasons all reachable
# ---------------------------------------------------------------------------


def test_reason_malformed_header_reachable() -> None:
    err = _safe_parse("garbage")
    assert err is not None and err.reason == "malformed_header"


def test_reason_missing_timestamp_reachable() -> None:
    err = _safe_parse(f"v1={_SIG},n=N,kid=k")
    assert err is not None and err.reason == "missing_timestamp"


def test_reason_missing_signature_reachable() -> None:
    err = _safe_parse("t=1,n=N,kid=k")
    assert err is not None and err.reason == "missing_signature"


def test_reason_missing_nonce_reachable() -> None:
    err = _safe_parse(f"t=1,v1={_SIG},kid=k")
    assert err is not None and err.reason == "missing_nonce"


def test_reason_unknown_algorithm_reachable() -> None:
    err = _safe_parse("t=1,v99=future,n=N,kid=k")
    assert err is not None and err.reason == "unknown_algorithm"


# ---------------------------------------------------------------------------
# Seedable random.Random fuzz (unconditional)
# ---------------------------------------------------------------------------


_FUZZ_ALPHABET = string.printable + "\x00\x01\x7f\xff"


def _random_input(rng: random.Random) -> str:
    """Generate one fuzz input. Strategy mix:
        - 40%: completely random characters of length 0..200
        - 30%: mutated copy of _VALID_HEADER (insert / delete / substitute)
        - 20%: structured but malformed (extra commas, equals, dup keys)
        - 10%: very long (up to 8000 chars) to exercise the size guard
    """
    r = rng.random()
    if r < 0.40:
        n = rng.randint(0, 200)
        return "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(n))
    if r < 0.70:
        s = list(_VALID_HEADER)
        ops = rng.randint(1, 8)
        for _ in range(ops):
            mode = rng.choice(("insert", "delete", "substitute"))
            if mode == "delete" and len(s) > 0:
                idx = rng.randrange(len(s))
                del s[idx]
            elif mode == "insert":
                idx = rng.randint(0, len(s))
                s.insert(idx, rng.choice(_FUZZ_ALPHABET))
            else:  # substitute
                if len(s) > 0:
                    idx = rng.randrange(len(s))
                    s[idx] = rng.choice(_FUZZ_ALPHABET)
        return "".join(s)
    if r < 0.90:
        # Structured trash: random k=v pairs
        n = rng.randint(1, 12)
        parts: list[str] = []
        for _ in range(n):
            key_len = rng.randint(1, 6)
            val_len = rng.randint(0, 20)
            key = "".join(rng.choice(string.ascii_letters + "0123456789") for _ in range(key_len))
            val = "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(val_len))
            parts.append(f"{key}={val}")
        return ",".join(parts)
    # 10%: very long
    n = rng.randint(4097, 8000)
    return "".join(rng.choice(_FUZZ_ALPHABET) for _ in range(n))


def test_random_fuzz_1000_iterations_no_crash() -> None:
    """Run 1000 fuzz iterations with a fixed seed. Every input either
    parses to a well-formed header (with structural invariants checked
    inside _safe_parse) or raises HeaderParseError. Any other exception
    type is a parser bug and fails this test."""
    rng = random.Random(0xA2A_AB5)  # arbitrary stable seed
    for i in range(1000):
        raw = _random_input(rng)
        try:
            _safe_parse(raw)
        except HeaderParseError:
            # Already caught inside _safe_parse; only re-raised when an
            # OTHER exception type leaks. Belt-and-braces here.
            pass
        except Exception as exc:  # pragma: no cover - bug surface
            pytest.fail(
                f"iteration {i} input={raw!r} raised non-HeaderParseError "
                f"{type(exc).__name__}: {exc}"
            )


# ---------------------------------------------------------------------------
# Hypothesis property-based fuzz (skipped if hypothesis not installed)
# ---------------------------------------------------------------------------

if _HAS_HYPOTHESIS:

    @given(st.text(max_size=5000))
    @settings(max_examples=500, deadline=None)
    def test_hypothesis_parser_never_crashes(raw: str) -> None:
        """The parser EITHER returns a structurally-valid result OR
        raises HeaderParseError. Any other exception is a bug."""
        try:
            _safe_parse(raw)
        except HeaderParseError:
            pass

    @given(
        st.lists(
            st.tuples(
                st.text(
                    alphabet=string.ascii_letters + string.digits,
                    min_size=1,
                    max_size=8,
                ),
                st.text(max_size=80),
            ),
            min_size=0,
            max_size=10,
        )
    )
    @settings(max_examples=300, deadline=None)
    def test_hypothesis_structured_pairs_never_crash(
        pairs: list[tuple[str, str]],
    ) -> None:
        """Build a comma-joined k=v header from random pair lists --
        guaranteed to look more like a header, exercising the field
        dispatch / dup detection logic."""
        raw = ",".join(f"{k}={v}" for k, v in pairs)
        try:
            _safe_parse(raw)
        except HeaderParseError:
            pass

else:  # pragma: no cover - environments without hypothesis

    @pytest.mark.skip(reason="hypothesis not installed; skipping property tests")
    def test_hypothesis_skipped() -> None:
        pass
