package platform

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type TraceWriter struct {
	store         *Store
	redis         *RedisGuard
	events        *EventSink
	queue         chan TraceEvent
	batchSize     int
	flushInterval time.Duration
	log           *slog.Logger
	waitGroup     sync.WaitGroup
	dropped       atomic.Int64
}

func NewTraceWriter(
	cfg Config,
	store *Store,
	redis *RedisGuard,
	events *EventSink,
	log *slog.Logger,
) *TraceWriter {
	return &TraceWriter{
		store:         store,
		redis:         redis,
		events:        events,
		queue:         make(chan TraceEvent, cfg.TraceQueueSize),
		batchSize:     cfg.TraceBatchSize,
		flushInterval: cfg.TraceFlushInterval,
		log:           log,
	}
}

func (w *TraceWriter) Start(ctx context.Context) {
	const workers = 4
	for index := 0; index < workers; index++ {
		w.waitGroup.Add(1)
		go w.worker(ctx)
	}
}

func (w *TraceWriter) Wait() {
	w.waitGroup.Wait()
}

func (w *TraceWriter) Depth() int {
	return len(w.queue)
}

func (w *TraceWriter) Dropped() int64 {
	return w.dropped.Load()
}

func (w *TraceWriter) Submit(event TraceEvent) bool {
	if event.RequestID == "" {
		event.RequestID = NewRequestID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	select {
	case w.queue <- event:
		return true
	default:
		w.dropped.Add(1)
		payload, _ := json.Marshal(event)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := w.redis.PushDLQ(ctx, "trace-queue-overflow", map[string]any{
			"request_id": event.RequestID,
			"payload":    string(payload),
			"created_at": event.CreatedAt.Format(time.RFC3339Nano),
		}); err != nil {
			w.log.Error(
				"trace queue overflow and Redis DLQ write failed",
				"request_id", event.RequestID,
				"error", err,
			)
		}
		return false
	}
}

func (w *TraceWriter) worker(ctx context.Context) {
	defer w.waitGroup.Done()
	timer := time.NewTimer(w.flushInterval)
	defer timer.Stop()
	batch := make([]TraceEvent, 0, w.batchSize)

	flush := func(flushContext context.Context) {
		if len(batch) == 0 {
			return
		}
		pending := append([]TraceEvent(nil), batch...)
		batch = batch[:0]
		if err := w.store.InsertTraceBatch(flushContext, pending); err != nil {
			w.log.Error("PostgreSQL trace batch failed", "events", len(pending), "error", err)
			for _, event := range pending {
				payload, _ := json.Marshal(event)
				dlqContext, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
				dlqError := w.redis.PushDLQ(dlqContext, "postgres-traces", map[string]any{
					"request_id": event.RequestID,
					"payload":    string(payload),
					"error":      err.Error(),
				})
				cancel()
				if dlqError != nil {
					w.dropped.Add(1)
					w.log.Error(
						"PostgreSQL and Redis DLQ trace persistence failed",
						"request_id", event.RequestID,
						"error", dlqError,
					)
				}
			}
			return
		}
		if w.events != nil {
			for _, event := range pending {
				w.events.PublishTrace(event)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			for {
				select {
				case event := <-w.queue:
					batch = append(batch, event)
					if len(batch) >= w.batchSize {
						flush(shutdownContext)
					}
				default:
					flush(shutdownContext)
					cancel()
					return
				}
			}
		case event := <-w.queue:
			batch = append(batch, event)
			if len(batch) >= w.batchSize {
				flush(ctx)
				resetTimer(timer, w.flushInterval)
			}
		case <-timer.C:
			flush(ctx)
			timer.Reset(w.flushInterval)
		}
	}
}
