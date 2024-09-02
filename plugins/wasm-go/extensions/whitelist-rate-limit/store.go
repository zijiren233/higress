package main

import (
	"container/list"
	"sync"
	"time"
)

type store struct {
	tokens   uint64
	interval time.Duration

	capacity int

	data     map[string]*list.Element
	dataLock sync.RWMutex
	lruList  *list.List
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

func withCapacity(capacity int) storeConfig {
	return func(s *store) {
		s.capacity = capacity
	}
}

func newStore(conf ...storeConfig) *store {
	s := &store{
		tokens:   1,
		interval: time.Second,
		capacity: 1000,
		data:     make(map[string]*list.Element),
		lruList:  list.New(),
	}

	for _, c := range conf {
		c(s)
	}

	return s
}

func (s *store) Take(key string) (uint64, uint64, uint64, bool) {
	s.dataLock.RLock()
	if elem, ok := s.data[key]; ok {
		s.lruList.MoveToFront(elem)
		b := elem.Value.(*bucket)
		s.dataLock.RUnlock()
		return b.take(s.tokens)
	}
	s.dataLock.RUnlock()

	s.dataLock.Lock()
	if elem, ok := s.data[key]; ok {
		s.lruList.MoveToFront(elem)
		b := elem.Value.(*bucket)
		s.dataLock.Unlock()
		return b.take(s.tokens)
	}

	b := newBucket(s.tokens, s.interval)
	elem := s.lruList.PushFront(b)
	s.data[key] = elem

	if s.lruList.Len() > s.capacity {
		oldest := s.lruList.Back()
		s.lruList.Remove(oldest)
		delete(s.data, oldest.Value.(*bucket).key)
	}

	s.dataLock.Unlock()
	return b.take(s.tokens)
}

type bucket struct {
	key             string
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
