"""Replay-protection storage hook.

The Receiver MUST keep a store of recently-seen nonces. On each verification,
the store is asked: "was this nonce seen recently?" If yes, the request is
rejected as replayed; if no, the nonce is recorded with a TTL.

`InMemoryReplayStore` is a reference implementation suitable for tests and
single-process receivers. Production multi-replica deployments should use a
shared store (Redis SET NX EX, Memcached add, etc.) so a nonce seen on
replica A is also rejected on replica B.
"""

from __future__ import annotations

import time
from typing import Callable, Protocol, runtime_checkable


@runtime_checkable
class ReplayStore(Protocol):
    """Replay-protection storage hook contract.

    Implementations atomically record-or-reject. Returning True means the
    nonce was unseen and has now been recorded with TTL = ttl_seconds.
    Returning False means the nonce was already seen within its TTL window
    and the caller MUST reject the request as replayed.
    """

    def check_and_store(self, nonce: str, ttl_seconds: int) -> bool:
        """Atomically: if `nonce` has been seen within `ttl_seconds`, return
        False. Otherwise record `nonce` with TTL = `ttl_seconds` and return
        True.
        """
        ...


class InMemoryReplayStore:
    """Reference in-memory replay store.

    Suitable for tests and single-process receivers; production multi-replica
    deployments should use Redis (SET NX EX) or equivalent so replay state is
    shared.

    Memory bound: in steady state, the store holds at most one entry per
    in-flight nonce. Eviction sweeps run at most every 256 check_and_store
    calls past the soft threshold of 8192 entries, so worst-case occupancy
    between sweeps is roughly threshold + (256 * peak insert rate per call)
    -- in practice well under 9000 nonces. The threshold trades a slightly
    larger working set for amortized O(1) eviction cost: the previous
    "sweep every call past threshold" strategy was O(n) per call once
    crossed, pathological under load.
    """

    # Soft cap. Below this, no sweeping. Above this, sweep every
    # _EVICT_INTERVAL calls. Sized for low-traffic receivers; production
    # multi-replica deployments use Redis where this code path doesn't run.
    _EVICT_THRESHOLD = 8192
    _EVICT_INTERVAL = 256

    def __init__(self, clock: Callable[[], int] | None = None) -> None:
        self._clock: Callable[[], int] = clock or (lambda: int(time.time()))
        self._seen: dict[str, int] = {}
        self._calls: int = 0

    def check_and_store(self, nonce: str, ttl_seconds: int) -> bool:
        self._calls += 1
        now = self._clock()
        self._maybe_evict(now)
        expires_at = self._seen.get(nonce)
        if expires_at is not None and expires_at > now:
            return False
        self._seen[nonce] = now + ttl_seconds
        return True

    def _maybe_evict(self, now: int) -> None:
        # Amortized O(1): the O(n) sweep happens once every 256 calls, and
        # only after the dict has grown past _EVICT_THRESHOLD. n is bounded
        # by the time window since entries past their TTL get removed on
        # each sweep. For higher-throughput use, swap to a TTL-aware data
        # structure (heap, sorted set, etc.).
        if (
            len(self._seen) > self._EVICT_THRESHOLD
            and self._calls % self._EVICT_INTERVAL == 0
        ):
            expired = [k for k, v in self._seen.items() if v <= now]
            for k in expired:
                del self._seen[k]
