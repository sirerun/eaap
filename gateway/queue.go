package main

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// ActionQueue serializes browser-bound actions per target host and applies
// randomized human-like jitter (RFC 6.2: 2000ms-5000ms default).
type ActionQueue struct {
	mu       sync.Mutex
	minDelay time.Duration
	maxDelay time.Duration
	rng      *rand.Rand
}

func NewActionQueue(cfg *Config) *ActionQueue {
	return &ActionQueue{
		minDelay: time.Duration(cfg.JitterMinMs) * time.Millisecond,
		maxDelay: time.Duration(cfg.JitterMaxMs) * time.Millisecond,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Enqueue blocks until the action's turn arrives (including jitter delay),
// then runs fn. Returns fn's result or ctx error.
func (q *ActionQueue) Enqueue(ctx context.Context, fn func() error) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	delay := q.minDelay
	if q.maxDelay > q.minDelay {
		delay += time.Duration(q.rng.Int63n(int64(q.maxDelay - q.minDelay)))
	}

	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	return fn()
}
