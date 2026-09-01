package pipeline

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/events"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
)

type Pipeline struct {
	cfg     config.Config
	store   *store.Store
	redis   *cache.Redis
	kafka   *events.Kafka
	log     *slog.Logger
	queue   chan core.Trace
	policy  atomic.Value // core.StoragePolicy
	started sync.Once
}

func New(cfg config.Config, st *store.Store, rc *cache.Redis, kafkaClient *events.Kafka, log *slog.Logger) *Pipeline {
	p := &Pipeline{
		cfg: cfg, store: st, redis: rc, kafka: kafkaClient, log: log,
		queue: make(chan core.Trace, cfg.TraceQueueSize),
	}
	p.policy.Store(core.StoragePolicy{
		RetentionDays: cfg.DefaultRetentionDays, PostgresEnabled: true,
		RedisBufferEnabled: true, RedisBufferTTLHours: 72,
		KafkaEnabled: cfg.KafkaEnabled(), KafkaRetentionHours: cfg.KafkaRetentionHours,
	})
	return p
}

func (p *Pipeline) Start(ctx context.Context) {
	p.started.Do(func() {
		p.refreshPolicy(ctx)
		for i := 0; i < p.cfg.TraceWorkers; i++ {
			go p.traceWorker(ctx, i)
		}
		for i := 0; i < p.cfg.OutboxWorkers; i++ {
			go p.outboxWorker(ctx, i)
		}
		go p.policyWorker(ctx)
		go p.retentionWorker(ctx)
		if p.redis.Enabled() {
			if err := p.redis.EnsureTraceDLQGroup(ctx, "riskgate-trace-replay"); err != nil {
				p.log.Warn("create trace Redis consumer group failed", "error", err)
			} else {
				go p.dlqWorker(ctx)
			}
		}
	})
}

func (p *Pipeline) Emit(trace core.Trace) {
	if trace.ID == "" {
		trace.ID = security.NewUUID()
	}
	if trace.CreatedAt.IsZero() {
		trace.CreatedAt = time.Now().UTC()
	}
	select {
	case p.queue <- trace:
		return
	default:
	}

	policy := p.currentPolicy()
	if policy.RedisBufferEnabled && p.redis.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := p.redis.PushTraceDLQ(ctx, trace, time.Duration(policy.RedisBufferTTLHours)*time.Hour)
		cancel()
		if err == nil {
			return
		}
		p.log.Error("trace queue saturated and Redis fallback failed", "error", err, "request_id", trace.ID)
		return
	}
	p.log.Error("trace queue saturated; event dropped because no durable fallback is enabled", "request_id", trace.ID)
}

func (p *Pipeline) traceWorker(ctx context.Context, worker int) {
	batch := make([]core.Trace, 0, 500)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		copyBatch := append([]core.Trace(nil), batch...)
		batch = batch[:0]
		p.persist(ctx, copyBatch)
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case trace := <-p.queue:
			batch = append(batch, trace)
			if len(batch) >= 500 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (p *Pipeline) persist(ctx context.Context, traces []core.Trace) {
	policy := p.currentPolicy()
	if policy.PostgresEnabled {
		if err := p.store.InsertTraceBatch(ctx, traces, policy.KafkaEnabled && p.kafka.Enabled(), p.kafka.Topic()); err == nil {
			return
		} else {
			p.log.Error("trace batch PostgreSQL write failed", "error", err, "count", len(traces))
		}
	} else if policy.KafkaEnabled && p.kafka.Enabled() {
		allPublished := true
		for _, trace := range traces {
			raw, _ := json.Marshal(trace)
			if err := p.kafka.Publish(ctx, trace.ID, raw, map[string]string{"schema": "riskgate.trace.v1"}); err != nil {
				allPublished = false
				p.log.Warn("direct Kafka trace publish failed", "error", err, "request_id", trace.ID)
				break
			}
		}
		if allPublished {
			return
		}
	}

	if policy.RedisBufferEnabled && p.redis.Enabled() {
		ttl := time.Duration(policy.RedisBufferTTLHours) * time.Hour
		for _, trace := range traces {
			writeCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			err := p.redis.PushTraceDLQ(writeCtx, trace, ttl)
			cancel()
			if err != nil {
				p.log.Error("trace Redis DLQ write failed", "error", err, "request_id", trace.ID)
			}
		}
	}
}

func (p *Pipeline) dlqWorker(ctx context.Context) {
	consumer := "consumer-" + security.NewUUID()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		items, err := p.redis.ReadTraceDLQ(ctx, "riskgate-trace-replay", consumer, 100, 2*time.Second)
		if err != nil {
			p.log.Warn("trace Redis DLQ read failed", "error", err)
			sleep(ctx, time.Second)
			continue
		}
		for _, item := range items {
			policy := p.currentPolicy()
			persisted := false
			if policy.PostgresEnabled {
				persisted = p.store.InsertTraceBatch(ctx, []core.Trace{item.Trace}, policy.KafkaEnabled && p.kafka.Enabled(), p.kafka.Topic()) == nil
			} else if policy.KafkaEnabled && p.kafka.Enabled() {
				raw, _ := json.Marshal(item.Trace)
				persisted = p.kafka.Publish(ctx, item.Trace.ID, raw, map[string]string{"schema": "riskgate.trace.v1"}) == nil
			}
			if persisted {
				if err := p.redis.AckTraceDLQ(ctx, "riskgate-trace-replay", item.ID); err != nil {
					p.log.Warn("trace Redis DLQ acknowledgement failed", "error", err, "message_id", item.ID)
				}
			} else {
				sleep(ctx, 250*time.Millisecond)
			}
		}
	}
}

func (p *Pipeline) outboxWorker(ctx context.Context, worker int) {
	owner := "outbox-" + security.NewUUID()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		policy := p.currentPolicy()
		if !policy.KafkaEnabled || !p.kafka.Enabled() {
			sleep(ctx, time.Second)
			continue
		}
		batch, err := p.store.LeaseOutbox(ctx, owner, 200, 30*time.Second)
		if err != nil {
			p.log.Warn("Kafka outbox lease failed", "error", err)
			sleep(ctx, time.Second)
			continue
		}
		if len(batch) == 0 {
			sleep(ctx, 250*time.Millisecond)
			continue
		}
		for _, event := range batch {
			publishCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			err := p.kafka.Publish(publishCtx, event.Key, event.Payload, event.Headers)
			cancel()
			if err == nil {
				if markErr := p.store.MarkOutboxPublished(ctx, event.ID, owner); markErr != nil {
					p.log.Warn("mark Kafka outbox event published failed", "error", markErr, "event_id", event.ID)
				}
			} else if markErr := p.store.MarkOutboxFailed(ctx, event.ID, owner, err.Error(), event.Attempts); markErr != nil {
				p.log.Warn("mark Kafka outbox event failed", "error", markErr, "event_id", event.ID)
			}
		}
	}
}

func (p *Pipeline) policyWorker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	lastRetention := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refreshPolicy(ctx)
			policy := p.currentPolicy()
			if p.cfg.KafkaAutoConfigureTopic && policy.KafkaEnabled && p.kafka.Enabled() && policy.KafkaRetentionHours != lastRetention {
				configureCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				err := p.kafka.ConfigureRetention(configureCtx, policy.KafkaRetentionHours)
				cancel()
				if err != nil {
					p.log.Warn("Kafka retention configuration failed", "error", err)
				} else {
					lastRetention = policy.KafkaRetentionHours
				}
			}
		}
	}
}

func (p *Pipeline) refreshPolicy(ctx context.Context) {
	policy, err := p.store.GetStoragePolicy(ctx)
	if err != nil {
		p.log.Warn("storage policy refresh failed", "error", err)
		return
	}
	p.policy.Store(policy)
}
func (p *Pipeline) currentPolicy() core.StoragePolicy {
	return p.policy.Load().(core.StoragePolicy)
}

func (p *Pipeline) retentionWorker(ctx context.Context) {
	run := func() {
		policy := p.currentPolicy()
		jobCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if err := p.store.EnsureTracePartitions(jobCtx, time.Now(), policy.RetentionDays); err != nil {
			p.log.Error("ensure trace partitions failed", "error", err)
			return
		}
		if err := p.store.PurgeExpiredTraces(jobCtx, policy.RetentionDays, time.Now()); err != nil {
			p.log.Error("trace retention cleanup failed", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func sleep(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
