package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var fixedWindowScript = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {current, ttl}
`)

type RedisLimiter struct {
	client redis.UniversalClient
	prefix string
	owned  bool
}

type RedisOptions struct {
	URL    string
	Prefix string
}

func NewRedisLimiter(opts RedisOptions) (*RedisLimiter, error) {
	parsed, err := redis.ParseURL(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("ratelimit: parse redis url: %w", err)
	}
	prefix := opts.Prefix
	if prefix == "" {
		prefix = "rl"
	}
	return &RedisLimiter{client: redis.NewClient(parsed), prefix: prefix, owned: true}, nil
}

func NewRedisLimiterWithClient(client redis.UniversalClient, prefix string) *RedisLimiter {
	if prefix == "" {
		prefix = "rl"
	}
	return &RedisLimiter{client: client, prefix: prefix}
}

func (l *RedisLimiter) Ping(ctx context.Context) error {
	return l.client.Ping(ctx).Err()
}

func (l *RedisLimiter) Allow(ctx context.Context, key string, rule Rule) (Decision, error) {
	if !rule.Valid() {
		return allowedDecision(rule, rule.Limit, 0), nil
	}

	redisKey := fmt.Sprintf("%s:%s:%s", l.prefix, rule.Name, key)
	res, err := fixedWindowScript.Run(ctx, l.client, []string{redisKey}, rule.Window.Milliseconds()).Slice()
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimit: redis script: %w", err)
	}
	if len(res) != 2 {
		return Decision{}, fmt.Errorf("ratelimit: unexpected redis reply length %d", len(res))
	}

	count, ok := res[0].(int64)
	if !ok {
		return Decision{}, fmt.Errorf("ratelimit: unexpected redis count type %T", res[0])
	}
	ttlMS, ok := res[1].(int64)
	if !ok {
		return Decision{}, fmt.Errorf("ratelimit: unexpected redis ttl type %T", res[1])
	}
	ttl := time.Duration(ttlMS) * time.Millisecond

	if count > int64(rule.Limit) {
		return deniedDecision(rule, ttl), nil
	}
	return allowedDecision(rule, rule.Limit-int(count), ttl), nil
}

func (l *RedisLimiter) Close() error {
	if !l.owned {
		return nil
	}
	return l.client.Close()
}
