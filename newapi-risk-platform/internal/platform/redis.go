package platform

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	redislib "github.com/redis/go-redis/v9"
)

const tokenBucketScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local values = redis.call('HMGET', key, 'tokens', 'timestamp')
local tokens = tonumber(values[1])
local timestamp = tonumber(values[2])
if tokens == nil then tokens = burst end
if timestamp == nil then timestamp = now end
local elapsed = math.max(0, now - timestamp) / 1000.0
tokens = math.min(burst, tokens + elapsed * rate)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HSET', key, 'tokens', tokens, 'timestamp', now)
redis.call('PEXPIRE', key, ttl)
return allowed
`

const acquireSemaphoreScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local expires = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local token = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
local count = redis.call('ZCARD', key)
if count >= limit then return 0 end
redis.call('ZADD', key, expires, token)
redis.call('PEXPIRE', key, math.max(1000, expires-now))
return 1
`

type localBucket struct {
	tokens float64
	last   time.Time
}

type RedisGuard struct {
	client     *redislib.Client
	streamMax  int64
	log        *slog.Logger
	available  atomic.Bool
	mu         sync.Mutex
	buckets    map[string]*localBucket
	semaphores map[string]int
	operations uint64
}

func NewRedisGuard(ctx context.Context, cfg Config, log *slog.Logger) *RedisGuard {
	guard := &RedisGuard{
		streamMax:  cfg.RedisStreamMaxLen,
		log:        log,
		buckets:    make(map[string]*localBucket),
		semaphores: make(map[string]int),
	}
	if cfg.RedisURL == "" {
		log.Warn("Redis is disabled; distributed controls use process-local fallback")
		return guard
	}
	options, err := redislib.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Error("invalid REDIS_URL; using process-local fallback", "error", err)
		return guard
	}
	options.PoolSize = 200
	options.MinIdleConns = 10
	options.DialTimeout = 3 * time.Second
	options.ReadTimeout = 2 * time.Second
	options.WriteTimeout = 2 * time.Second
	guard.client = redislib.NewClient(options)
	pingContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := guard.client.Ping(pingContext).Err(); err != nil {
		log.Warn("Redis is unavailable at startup; using fallback until it recovers", "error", err)
		return guard
	}
	guard.available.Store(true)
	return guard
}

func (g *RedisGuard) Close() error {
	if g.client == nil {
		return nil
	}
	return g.client.Close()
}

func (g *RedisGuard) Available() bool {
	return g.available.Load()
}

func (g *RedisGuard) Allow(ctx context.Context, key string, rate float64, burst int) bool {
	if rate <= 0 || burst <= 0 {
		return true
	}
	if g.client != nil {
		ttlMilliseconds := int64(float64(burst)/rate*2000) + 1000
		result, err := g.client.Eval(
			ctx,
			tokenBucketScript,
			[]string{"risk:rate:" + key},
			time.Now().UnixMilli(),
			rate,
			burst,
			ttlMilliseconds,
		).Int64()
		if err == nil {
			g.available.Store(true)
			return result == 1
		}
		g.available.Store(false)
		g.log.Debug("Redis rate limit failed; using local fallback", "error", err)
	}
	return g.allowLocal(key, rate, burst)
}

func (g *RedisGuard) allowLocal(key string, rate float64, burst int) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.operations++
	if g.operations%1024 == 0 {
		cutoff := now.Add(-10 * time.Minute)
		for bucketKey, bucket := range g.buckets {
			if bucket.last.Before(cutoff) {
				delete(g.buckets, bucketKey)
			}
		}
	}
	bucket := g.buckets[key]
	if bucket == nil {
		bucket = &localBucket{tokens: float64(burst), last: now}
		g.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.last).Seconds()
	bucket.tokens += elapsed * rate
	if bucket.tokens > float64(burst) {
		bucket.tokens = float64(burst)
	}
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (g *RedisGuard) Acquire(ctx context.Context, key string, limit int, ttl time.Duration) (func(), bool) {
	if limit <= 0 {
		return func() {}, true
	}
	token := NewRequestID()
	if g.client != nil {
		now := time.Now().UnixMilli()
		result, err := g.client.Eval(
			ctx,
			acquireSemaphoreScript,
			[]string{"risk:sem:" + key},
			now,
			now+ttl.Milliseconds(),
			limit,
			token,
		).Int64()
		if err == nil {
			g.available.Store(true)
			if result != 1 {
				return nil, false
			}
			var once sync.Once
			return func() {
				once.Do(func() {
					releaseContext, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					_ = g.client.ZRem(releaseContext, "risk:sem:"+key, token).Err()
				})
			}, true
		}
		g.available.Store(false)
		g.log.Debug("Redis semaphore failed; using local fallback", "error", err)
	}

	g.mu.Lock()
	if g.semaphores[key] >= limit {
		g.mu.Unlock()
		return nil, false
	}
	g.semaphores[key]++
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if g.semaphores[key] > 1 {
				g.semaphores[key]--
			} else {
				delete(g.semaphores, key)
			}
			g.mu.Unlock()
		})
	}, true
}

func (g *RedisGuard) UseNonce(
	ctx context.Context,
	keyID string,
	nonce string,
	ttl time.Duration,
	store *Store,
) (bool, error) {
	if g.client != nil {
		ok, err := g.client.SetNX(ctx, "risk:nonce:"+keyID+":"+nonce, "1", ttl).Result()
		if err == nil {
			g.available.Store(true)
			return ok, nil
		}
		g.available.Store(false)
		g.log.Warn("Redis nonce check failed; using PostgreSQL fallback", "error", err)
	}
	return store.UseNonceFallback(ctx, keyID, nonce, time.Now().UTC().Add(ttl))
}

func (g *RedisGuard) PushDLQ(ctx context.Context, stream string, fields map[string]any) error {
	if g.client == nil {
		return fmt.Errorf("Redis is disabled")
	}
	arguments := &redislib.XAddArgs{
		Stream: "risk:dlq:" + stream,
		MaxLen: g.streamMax,
		Approx: true,
		Values: fields,
	}
	if err := g.client.XAdd(ctx, arguments).Err(); err != nil {
		g.available.Store(false)
		return err
	}
	g.available.Store(true)
	return nil
}

func (g *RedisGuard) SetStreamMaxLen(value int64) {
	if value > 0 {
		g.streamMax = value
	}
}

func (g *RedisGuard) Status() map[string]string {
	status := "disabled"
	if g.client != nil && g.Available() {
		status = "available"
	} else if g.client != nil {
		status = "degraded"
	}
	return map[string]string{
		"status":         status,
		"stream_max_len": strconv.FormatInt(g.streamMax, 10),
	}
}
