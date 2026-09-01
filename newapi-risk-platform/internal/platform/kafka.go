package platform

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

type kafkaEnvelope struct {
	Version     int        `json:"version"`
	Type        string     `json:"type"`
	PublishedAt time.Time  `json:"published_at"`
	Trace       TraceEvent `json:"trace"`
}

type queuedKafkaEvent struct {
	key     string
	payload []byte
}

type EventSink struct {
	enabled   bool
	topic     string
	brokers   []string
	writer    *kafka.Writer
	transport *kafka.Transport
	store     *Store
	queue     chan queuedKafkaEvent
	log       *slog.Logger
	waitGroup sync.WaitGroup
}

func NewEventSink(cfg Config, store *Store, log *slog.Logger) (*EventSink, error) {
	sink := &EventSink{
		enabled: cfg.KafkaEnabled,
		topic:   cfg.KafkaTopic,
		brokers: append([]string(nil), cfg.KafkaBrokers...),
		store:   store,
		queue:   make(chan queuedKafkaEvent, cfg.KafkaQueueSize),
		log:     log,
	}
	if !cfg.KafkaEnabled {
		return sink, nil
	}
	mechanism, err := kafkaSASLMechanism(cfg)
	if err != nil {
		return nil, err
	}
	transport := &kafka.Transport{
		ClientID:    cfg.KafkaClientID,
		DialTimeout: 5 * time.Second,
		SASL:        mechanism,
	}
	if cfg.KafkaTLS {
		transport.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	sink.transport = transport
	sink.writer = &kafka.Writer{
		Addr:         kafka.TCP(cfg.KafkaBrokers...),
		Topic:        cfg.KafkaTopic,
		Balancer:     &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
		BatchSize:    200,
		BatchBytes:   1024 * 1024,
		BatchTimeout: 50 * time.Millisecond,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Async:        false,
		Transport:    transport,
	}
	return sink, nil
}

func kafkaSASLMechanism(cfg Config) (sasl.Mechanism, error) {
	switch strings.ToLower(cfg.KafkaSASLMechanism) {
	case "":
		return nil, nil
	case "plain":
		return plain.Mechanism{Username: cfg.KafkaUsername, Password: cfg.KafkaPassword}, nil
	case "scram-sha-256":
		return scram.Mechanism(scram.SHA256, cfg.KafkaUsername, cfg.KafkaPassword)
	case "scram-sha-512":
		return scram.Mechanism(scram.SHA512, cfg.KafkaUsername, cfg.KafkaPassword)
	default:
		return nil, fmt.Errorf("unsupported Kafka SASL mechanism %q", cfg.KafkaSASLMechanism)
	}
}

func (s *EventSink) Start(ctx context.Context) {
	if !s.enabled {
		return
	}
	s.waitGroup.Add(2)
	go s.writeWorker(ctx)
	go s.outboxWorker(ctx)
}

func (s *EventSink) Wait() {
	s.waitGroup.Wait()
}

func (s *EventSink) Enabled() bool {
	return s.enabled
}

func (s *EventSink) QueueDepth() int {
	return len(s.queue)
}

func (s *EventSink) Close() error {
	var writerError error
	if s.writer != nil {
		writerError = s.writer.Close()
	}
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return writerError
}

func (s *EventSink) PublishTrace(trace TraceEvent) {
	if !s.enabled {
		return
	}
	payload, err := json.Marshal(kafkaEnvelope{
		Version:     1,
		Type:        "request_trace",
		PublishedAt: time.Now().UTC(),
		Trace:       trace,
	})
	if err != nil {
		s.log.Error("marshal Kafka event failed", "request_id", trace.RequestID, "error", err)
		return
	}
	event := queuedKafkaEvent{key: trace.RequestID, payload: payload}
	select {
	case s.queue <- event:
	default:
		s.enqueueOutbox(event, errors.New("Kafka in-process queue is full"))
	}
}

func (s *EventSink) writeWorker(ctx context.Context) {
	defer s.waitGroup.Done()
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	batch := make([]queuedKafkaEvent, 0, 200)
	flush := func(flushContext context.Context) {
		if len(batch) == 0 {
			return
		}
		pending := append([]queuedKafkaEvent(nil), batch...)
		batch = batch[:0]
		messages := make([]kafka.Message, 0, len(pending))
		for _, event := range pending {
			messages = append(messages, kafka.Message{
				Key:   []byte(event.key),
				Value: event.payload,
				Time:  time.Now().UTC(),
				Headers: []kafka.Header{
					{Key: "schema-version", Value: []byte("1")},
					{Key: "source", Value: []byte("newapi-risk-platform")},
				},
			})
		}
		if err := s.writer.WriteMessages(flushContext, messages...); err != nil {
			s.log.Error(
				"Kafka batch publish failed; moving events to PostgreSQL outbox",
				"count", len(pending),
				"error", err,
			)
			for _, event := range pending {
				s.enqueueOutbox(event, err)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			for {
				select {
				case event := <-s.queue:
					batch = append(batch, event)
					if len(batch) >= 200 {
						flush(shutdownContext)
					}
				default:
					flush(shutdownContext)
					cancel()
					return
				}
			}
		case event := <-s.queue:
			batch = append(batch, event)
			if len(batch) >= 200 {
				flush(ctx)
				resetTimer(timer, 50*time.Millisecond)
			}
		case <-timer.C:
			flush(ctx)
			timer.Reset(50 * time.Millisecond)
		}
	}
}

func (s *EventSink) enqueueOutbox(event queuedKafkaEvent, publishError error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.store.EnqueueOutbox(ctx, s.topic, event.key, event.payload, publishError.Error()); err != nil {
		s.log.Error("Kafka outbox write failed", "event_key", event.key, "error", err)
	}
}

func (s *EventSink) outboxWorker(ctx context.Context) {
	defer s.waitGroup.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := s.store.ClaimOutbox(ctx, 100)
			if err != nil {
				s.log.Warn("claim Kafka outbox failed", "error", err)
				continue
			}
			for _, event := range events {
				message := kafka.Message{
					Key:   []byte(event.Key),
					Value: event.Payload,
					Time:  time.Now().UTC(),
				}
				writeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := s.writer.WriteMessages(writeContext, message)
				cancel()
				if err != nil {
					s.store.MarkOutboxFailed(ctx, event.ID, event.Attempts, err)
					continue
				}
				s.store.MarkOutboxPublished(ctx, event.ID)
			}
		}
	}
}

func (s *EventSink) ApplyRetention(ctx context.Context, days int) error {
	if !s.enabled {
		return errors.New("Kafka is disabled")
	}
	if days < 1 || days > 3650 {
		return errors.New("Kafka retention must be between 1 and 3650 days")
	}
	client := &kafka.Client{Addr: kafka.TCP(s.brokers...), Transport: s.transport}
	_, err := client.IncrementalAlterConfigs(ctx, &kafka.IncrementalAlterConfigsRequest{
		Resources: []kafka.IncrementalAlterConfigsRequestResource{
			{
				ResourceType: kafka.ResourceTypeTopic,
				ResourceName: s.topic,
				Configs: []kafka.IncrementalAlterConfigsRequestConfig{
					{
						Name:            "retention.ms",
						Value:           strconv.FormatInt(int64(days)*24*60*60*1000, 10),
						ConfigOperation: kafka.ConfigOperationSet,
					},
				},
			},
		},
	})
	return err
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
}
