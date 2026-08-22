package ratelimit

import (
	"context"
	"hash/maphash"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const defaultShardCount = 32

type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type MemoryLimiter struct {
	shards      []*shard
	seed        maphash.Seed
	now         Clock
	idleTTL     time.Duration
	janitorStop chan struct{}
	janitorDone chan struct{}
	closeOnce   sync.Once
}

type MemoryOptions struct {
	Shards       int
	IdleTTL      time.Duration
	SweepEvery   time.Duration
	Clock        Clock
	StartJanitor bool
}

func NewMemoryLimiter(opts MemoryOptions) *MemoryLimiter {
	shardCount := opts.Shards
	if shardCount <= 0 {
		shardCount = defaultShardCount
	}
	idleTTL := opts.IdleTTL
	if idleTTL <= 0 {
		idleTTL = 10 * time.Minute
	}
	sweepEvery := opts.SweepEvery
	if sweepEvery <= 0 {
		sweepEvery = time.Minute
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	shards := make([]*shard, shardCount)
	for i := range shards {
		shards[i] = &shard{buckets: make(map[string]*bucket)}
	}

	l := &MemoryLimiter{
		shards:      shards,
		seed:        maphash.MakeSeed(),
		now:         clock,
		idleTTL:     idleTTL,
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
	}

	if opts.StartJanitor {
		go l.janitor(sweepEvery)
	} else {
		close(l.janitorDone)
	}
	return l
}

func (l *MemoryLimiter) Allow(_ context.Context, key string, rule Rule) (Decision, error) {
	if !rule.Valid() {
		return allowedDecision(rule, rule.Limit, 0), nil
	}

	now := l.now()
	composite := rule.Name + "|" + key
	sh := l.shardFor(composite)

	sh.mu.Lock()
	b, ok := sh.buckets[composite]
	if !ok {
		refill := rate.Limit(float64(rule.Limit) / rule.Window.Seconds())
		b = &bucket{limiter: rate.NewLimiter(refill, rule.Limit)}
		sh.buckets[composite] = b
	}
	b.lastSeen = now
	reservation := b.limiter.AllowN(now, 1)
	tokens := b.limiter.TokensAt(now)
	perToken := time.Duration(float64(rule.Window) / float64(rule.Limit))
	sh.mu.Unlock()

	if !reservation {
		deficit := 1 - tokens
		if deficit < 0 {
			deficit = 0
		}
		retry := time.Duration(deficit * float64(perToken))
		if retry <= 0 {
			retry = perToken
		}
		return deniedDecision(rule, retry), nil
	}

	remaining := int(math.Floor(tokens))
	if remaining < 0 {
		remaining = 0
	}
	missing := float64(rule.Limit) - tokens
	if missing < 0 {
		missing = 0
	}
	return allowedDecision(rule, remaining, time.Duration(missing*float64(perToken))), nil
}

func (l *MemoryLimiter) Close() error {
	l.closeOnce.Do(func() {
		close(l.janitorStop)
		<-l.janitorDone
	})
	return nil
}

func (l *MemoryLimiter) Len() int {
	total := 0
	for _, sh := range l.shards {
		sh.mu.Lock()
		total += len(sh.buckets)
		sh.mu.Unlock()
	}
	return total
}

func (l *MemoryLimiter) Sweep() int {
	cutoff := l.now().Add(-l.idleTTL)
	evicted := 0
	for _, sh := range l.shards {
		sh.mu.Lock()
		for key, b := range sh.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(sh.buckets, key)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	return evicted
}

func (l *MemoryLimiter) janitor(every time.Duration) {
	defer close(l.janitorDone)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-l.janitorStop:
			return
		case <-ticker.C:
			l.Sweep()
		}
	}
}

func (l *MemoryLimiter) shardFor(key string) *shard {
	var h maphash.Hash
	h.SetSeed(l.seed)
	// maphash.Hash.WriteString never returns an error.
	_, _ = h.WriteString(key)
	return l.shards[h.Sum64()%uint64(len(l.shards))]
}
