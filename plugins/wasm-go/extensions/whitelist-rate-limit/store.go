package main

import (
	"sync"
	"time"
)

type store struct {
	tokens   uint64
	interval time.Duration

	sweepInterval time.Duration
	sweepMinTTL   uint64

	data     map[string]*bucket
	dataLock sync.RWMutex
}

type storeConfig func(*store)

func withTokens(tokens uint64) storeConfig {
	return func(s *store) {
		s.tokens = tokens
	}
}

func withInterval(interval time.Duration) storeConfig {
	return func(s *store) {
		s.interval = interval
	}
}

func withSweepInterval(interval time.Duration) storeConfig {
	return func(s *store) {
		s.sweepInterval = interval
	}
}

func withSweepMinTTL(ttl time.Duration) storeConfig {
	return func(s *store) {
		s.sweepMinTTL = uint64(ttl)
	}
}

func withInitialAlloc(alloc int) storeConfig {
	return func(s *store) {
		s.data = make(map[string]*bucket, alloc)
	}
}

func newStore(conf ...storeConfig) *store {
	s := &store{
		tokens:        1,
		interval:      time.Second,
		sweepInterval: 5 * time.Minute,
		sweepMinTTL:   uint64(10 * time.Second),
	}

	for _, c := range conf {
		c(s)
	}

	go s.purge()
	return s
}
func (s *store) Take(key string) (uint64, uint64, uint64, bool) {
	s.dataLock.RLock()
	if b, ok := s.data[key]; ok {
		s.dataLock.RUnlock()
		return b.take(s.tokens)
	}
	s.dataLock.RUnlock()

	s.dataLock.Lock()
	if b, ok := s.data[key]; ok {
		s.dataLock.Unlock()
		return b.take(s.tokens)
	}

	b := newBucket(s.tokens, s.interval)

	s.data[key] = b
	s.dataLock.Unlock()
	return b.take(s.tokens)
}

func (s *store) purge() {
	ticker := time.NewTicker(s.sweepInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.dataLock.Lock()
		now := uint64(time.Now().UnixNano())
		for k, b := range s.data {
			b.lock.Lock()
			lastTime := b.startTime + (b.lastTick * uint64(b.interval))
			b.lock.Unlock()

			if now-lastTime > s.sweepMinTTL {
				delete(s.data, k)
			}
		}
		s.dataLock.Unlock()
	}
}

type bucket struct {
	startTime       uint64
	interval        time.Duration
	availableTokens uint64
	lastTick        uint64
	lock            sync.Mutex
}

func newBucket(tokens uint64, interval time.Duration) *bucket {
	b := &bucket{
		startTime:       uint64(time.Now().UnixNano()),
		availableTokens: tokens,
		interval:        interval,
	}
	return b
}

func (b *bucket) take(maxTokens uint64) (tokens uint64, remaining uint64, reset uint64, ok bool) {
	now := uint64(time.Now().UnixNano())

	b.lock.Lock()
	defer b.lock.Unlock()

	if now < b.startTime {
		b.startTime = now
		b.lastTick = 0
	}

	currTick := tick(b.startTime, now, b.interval)

	tokens = maxTokens
	reset = b.startTime + ((currTick + 1) * uint64(b.interval))

	if b.lastTick < currTick {
		b.availableTokens = maxTokens
		b.lastTick = currTick
	}

	if b.availableTokens > 0 {
		b.availableTokens--
		ok = true
		remaining = b.availableTokens
	}

	return
}

func tick(start, curr uint64, interval time.Duration) uint64 {
	return (curr - start) / uint64(interval.Nanoseconds())
}
