// AWSP replay storage hook.
//
// AWSP requires the receiver to reject Deliveries whose nonce was already
// seen within the replay window (plus a 60s buffer). The storage layer is
// pluggable: production multi-replica receivers should back this with Redis
// (`SET key NX EX <ttl>`) or an equivalent atomic data store. The
// InMemoryReplayStore here is suitable for tests and single-process
// receivers.

package awsp

import (
	"sync"
	"time"
)

// ReplayStore is the interface AWSP uses to enforce nonce uniqueness.
//
// CheckAndStore atomically:
//
//   - If nonce has been recorded for configID within the past ttlSeconds,
//     return (false, nil).
//   - Otherwise record it (with TTL = ttlSeconds) and return (true, nil).
//
// configID lets a single store partition replay state per webhook
// configuration. Receivers that share state across configurations may pass
// the empty string -- nonce uniqueness is global to the receiver per spec
// section 7.2, but operators sometimes want a tighter scope to bound
// storage growth. Both behaviors satisfy the spec.
//
// Implementations MUST be safe for concurrent use across goroutines.
type ReplayStore interface {
	CheckAndStore(configID string, nonce []byte, ttlSeconds int) (firstSeen bool, err error)
}

// evictThreshold is the map size above which we may sweep. Below this,
// CheckAndStore is O(1). Above it, we sweep at most every evictStride
// calls -- the amortized cost per call stays O(1) because n grows
// proportionally to the steady-state arrival rate within the TTL window.
//
// Bound: in steady state, len(seen) is at most one TTL-window's worth
// of arrivals. With the default replayWindow=300s and a 60s buffer
// (ttl=360s), a Receiver doing 100 verifies/sec sees ~36000 entries
// at peak before eviction kicks in -- well above evictThreshold, so
// sweeps run on every evictStride'th call. At 10 verifies/sec, peak
// is ~3600 -- below threshold, no sweep needed.
const (
	evictThreshold = 8192
	evictStride    = 256
)

// InMemoryReplayStore is a simple ReplayStore for tests and single-replica
// receivers. It is safe for concurrent use.
//
// Production multi-replica deployments should swap this for a Redis-backed
// store; nonce state held in process memory does not survive restarts and
// is not shared across pods.
type InMemoryReplayStore struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	clock     func() time.Time
	callCount uint64 // call counter for stride-based eviction; mod evictStride
}

// NewInMemoryReplayStore returns a fresh in-memory ReplayStore using the
// real wall clock.
func NewInMemoryReplayStore() *InMemoryReplayStore {
	return &InMemoryReplayStore{
		seen:  make(map[string]time.Time),
		clock: time.Now,
	}
}

// newInMemoryReplayStoreWithClock is an internal helper for tests that
// need deterministic time.
func newInMemoryReplayStoreWithClock(clock func() time.Time) *InMemoryReplayStore {
	return &InMemoryReplayStore{
		seen:  make(map[string]time.Time),
		clock: clock,
	}
}

// CheckAndStore implements ReplayStore.
func (s *InMemoryReplayStore) CheckAndStore(configID string, nonce []byte, ttlSeconds int) (bool, error) {
	now := s.clock()
	key := configID + ":" + string(nonce)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.callCount++
	s.evictLocked(now)

	if expiresAt, ok := s.seen[key]; ok && expiresAt.After(now) {
		return false, nil
	}

	s.seen[key] = now.Add(time.Duration(ttlSeconds) * time.Second)
	return true, nil
}

// evictLocked sweeps expired entries from the map. To keep CheckAndStore
// amortized O(1), we only sweep every evictStride calls once the map has
// grown past evictThreshold. The callCount modulo gate avoids the
// pathological "sweep on every call past threshold" pattern under
// sustained high load. Callers must hold s.mu.
func (s *InMemoryReplayStore) evictLocked(now time.Time) {
	if len(s.seen) <= evictThreshold {
		return
	}
	if s.callCount%evictStride != 0 {
		return
	}
	for k, exp := range s.seen {
		if !exp.After(now) {
			delete(s.seen, k)
		}
	}
}
