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
    """

    def __init__(self, clock: Callable[[], int] | None = None) -> None:
        self._clock: Callable[[], int] = clock or (lambda: int(time.time()))
        self._seen: dict[str, int] = {}

    def check_and_store(self, nonce: str, ttl_seconds: int) -> bool:
        now = self._clock()
        self._evict(now)
        expires_at = self._seen.get(nonce)
        if expires_at is not None and expires_at > now:
            return False
        self._seen[nonce] = now + ttl_seconds
        return True

    def _evict(self, now: int) -> None:
        # Cheap incremental sweep; O(n) on size, but n is bounded by the
        # time window. For higher-throughput use, swap to a TTL-aware data
        # structure.
        if len(self._seen) > 4096:
            expired = [k for k, v in self._seen.items() if v <= now]
            for k in expired:
                del self._seen[k]
