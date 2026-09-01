package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Store) InsertTraceBatch(ctx context.Context, events []TraceEvent) error {
	if len(events) == 0 {
		return nil
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer transaction.Rollback(ctx)

	for _, event := range events {
		if event.CreatedAt.IsZero() {
			event.CreatedAt = time.Now().UTC()
		}
		if event.ExternalEventID != "" {
			var inserted string
			err := transaction.QueryRow(ctx, `INSERT INTO request_dedupe(event_id,expires_at)
				VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING event_id`,
				event.ExternalEventID, event.CreatedAt.Add(48*time.Hour)).Scan(&inserted)
			if err == pgx.ErrNoRows {
				continue
			}
			if err != nil {
				return err
			}
		}
		metadata, err := json.Marshal(event.Metadata)
		if err != nil {
			metadata = []byte(`{}`)
		}
		_, err = transaction.Exec(ctx, `INSERT INTO request_traces
			(request_id,external_event_id,source,route_slug,newapi_request_id,external_user_id,
			model,endpoint,decision,risk_code,http_status,upstream_status,latency_ms,
			audit_latency_ms,request_bytes,response_bytes,prompt_hmac,metadata,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			event.RequestID, event.ExternalEventID, event.Source, event.RouteSlug,
			event.NewAPIRequestID, event.ExternalUserID, event.Model, event.Endpoint,
			event.Decision, event.RiskCode, event.HTTPStatus, event.UpstreamStatus,
			event.LatencyMS, event.AuditLatencyMS, event.RequestBytes, event.ResponseBytes,
			event.PromptHMAC, metadata, event.CreatedAt)
		if err != nil {
			return err
		}
	}
	return transaction.Commit(ctx)
}

func (s *Store) QueryTraces(ctx context.Context, filter TraceFilter) ([]TraceEvent, error) {
	if filter.Limit <= 0 {
		filter.Limit = 200
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}
	if filter.To.IsZero() {
		filter.To = time.Now().UTC()
	}
	if filter.From.IsZero() {
		filter.From = filter.To.Add(-24 * time.Hour)
	}
	clauses := []string{"created_at >= $1", "created_at <= $2"}
	arguments := []any{filter.From, filter.To}
	add := func(column string, value string) {
		if value == "" {
			return
		}
		arguments = append(arguments, value)
		clauses = append(clauses, column+" = $"+strconv.Itoa(len(arguments)))
	}
	add("route_slug", filter.RouteSlug)
	add("decision", filter.Decision)
	add("risk_code", filter.RiskCode)
	add("external_user_id", filter.UserID)
	arguments = append(arguments, filter.Limit)
	query := `SELECT request_id,external_event_id,source,route_slug,newapi_request_id,
		external_user_id,model,endpoint,decision,risk_code,http_status,upstream_status,
		latency_ms,audit_latency_ms,request_bytes,response_bytes,prompt_hmac,metadata,created_at
		FROM request_traces WHERE ` + strings.Join(clauses, " AND ") +
		" ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(arguments))
	rows, err := s.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []TraceEvent
	for rows.Next() {
		var event TraceEvent
		var metadata []byte
		if err := rows.Scan(
			&event.RequestID, &event.ExternalEventID, &event.Source, &event.RouteSlug,
			&event.NewAPIRequestID, &event.ExternalUserID, &event.Model, &event.Endpoint,
			&event.Decision, &event.RiskCode, &event.HTTPStatus, &event.UpstreamStatus,
			&event.LatencyMS, &event.AuditLatencyMS, &event.RequestBytes, &event.ResponseBytes,
			&event.PromptHMAC, &metadata, &event.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metadata, &event.Metadata)
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) Dashboard(ctx context.Context, window time.Duration) (DashboardStats, error) {
	if window <= 0 {
		window = 24 * time.Hour
	}
	stats := DashboardStats{
		WindowHours: int64(window.Hours()),
		ByRiskCode:  map[string]int64{},
		ByRoute:     map[string]int64{},
	}
	from := time.Now().UTC().Add(-window)
	if err := s.pool.QueryRow(ctx, `SELECT
		count(*),
		count(*) FILTER (WHERE decision='allow'),
		count(*) FILTER (WHERE decision='block'),
		count(*) FILTER (WHERE decision='error'),
		COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms),0)::double precision
		FROM request_traces WHERE created_at >= $1`, from).Scan(
		&stats.TotalRequests, &stats.AllowedRequests, &stats.BlockedRequests,
		&stats.ErrorRequests, &stats.P95LatencyMS,
	); err != nil {
		return stats, err
	}
	if stats.TotalRequests > 0 {
		stats.BlockRate = float64(stats.BlockedRequests) / float64(stats.TotalRequests)
	}

	rows, err := s.pool.Query(ctx, `SELECT risk_code,count(*) FROM request_traces
		WHERE created_at >= $1 AND risk_code<>'' GROUP BY risk_code
		ORDER BY count(*) DESC LIMIT 20`, from)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.ByRiskCode[key] = count
	}
	rows.Close()

	rows, err = s.pool.Query(ctx, `SELECT route_slug,count(*) FROM request_traces
		WHERE created_at >= $1 GROUP BY route_slug ORDER BY count(*) DESC LIMIT 20`, from)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			rows.Close()
			return stats, err
		}
		stats.ByRoute[key] = count
	}
	rows.Close()
	_ = s.pool.QueryRow(ctx,
		"SELECT count(*) FROM routes WHERE deleted_at IS NULL").Scan(&stats.ConfiguredRoutes)
	stats.PostgresHealthy = s.Health(ctx) == nil
	return stats, nil
}

func (s *Store) GetIntSetting(ctx context.Context, key string, fallback int) int {
	var raw []byte
	if err := s.pool.QueryRow(ctx, "SELECT value FROM settings WHERE key=$1", key).Scan(&raw); err != nil {
		return fallback
	}
	var value int
	if json.Unmarshal(raw, &value) != nil {
		return fallback
	}
	return value
}

func (s *Store) GetSettings(ctx context.Context) (map[string]any, error) {
	rows, err := s.pool.Query(ctx, "SELECT key,value FROM settings ORDER BY key")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]any{}
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			value = string(raw)
		}
		result[key] = value
	}
	return result, rows.Err()
}

func (s *Store) SetSetting(ctx context.Context, key string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO settings(key,value,updated_at)
		VALUES($1,$2,now()) ON CONFLICT(key) DO UPDATE
		SET value=EXCLUDED.value,updated_at=now()`, key, payload)
	return err
}

func (s *Store) MaintainPartitions(ctx context.Context, retentionDays int) error {
	if retentionDays < 1 {
		retentionDays = 7
	}
	connection, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer connection.Release()

	const lockID int64 = 55520260902
	var locked bool
	if err := connection.QueryRow(ctx,
		"SELECT pg_try_advisory_lock($1)", lockID).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", lockID)
	}()

	now := time.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	for offset := -1; offset <= 3; offset++ {
		start := midnight.AddDate(0, 0, offset)
		end := start.AddDate(0, 0, 1)
		name := "request_traces_" + start.Format("20060102")
		statement := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF request_traces
			FOR VALUES FROM ('%s') TO ('%s')`,
			name, start.Format(time.RFC3339), end.Format(time.RFC3339))
		if _, err := connection.Exec(ctx, statement); err != nil {
			return fmt.Errorf("create trace partition %s: %w", name, err)
		}
	}

	rows, err := connection.Query(ctx, `SELECT child.relname
		FROM pg_inherits
		JOIN pg_class parent ON pg_inherits.inhparent=parent.oid
		JOIN pg_class child ON pg_inherits.inhrelid=child.oid
		WHERE parent.relname='request_traces'`)
	if err != nil {
		return err
	}
	var partitions []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		partitions = append(partitions, name)
	}
	rows.Close()

	validName := regexp.MustCompile(`^request_traces_[0-9]{8}$`)
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	for _, name := range partitions {
		if !validName.MatchString(name) {
			continue
		}
		partitionStart, err := time.Parse("20060102", strings.TrimPrefix(name, "request_traces_"))
		if err != nil || partitionStart.AddDate(0, 0, 1).After(cutoff) {
			continue
		}
		if _, err := connection.Exec(ctx, "DROP TABLE IF EXISTS "+name); err != nil {
			return fmt.Errorf("drop trace partition %s: %w", name, err)
		}
		s.log.Info("expired trace partition dropped", "partition", name)
	}
	if _, err := connection.Exec(ctx,
		"DELETE FROM request_traces WHERE created_at < $1", cutoff); err != nil {
		return fmt.Errorf("trim cutoff trace rows: %w", err)
	}
	_, _ = connection.Exec(ctx, "DELETE FROM request_dedupe WHERE expires_at < now()")
	_, _ = connection.Exec(ctx, "DELETE FROM tracking_nonces WHERE expires_at < now()")
	_, _ = connection.Exec(ctx,
		"DELETE FROM admin_audit_logs WHERE created_at < now() - interval '180 days'")
	_, _ = connection.Exec(ctx,
		"DELETE FROM outbox_events WHERE published_at < now() - interval '7 days'")
	return nil
}

func (s *Store) EnqueueOutbox(ctx context.Context, topic string, key string, payload []byte, lastError string) error {
	if len(lastError) > 1000 {
		lastError = lastError[:1000]
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO outbox_events(topic,event_key,payload,last_error)
		VALUES($1,$2,$3,$4)`, topic, key, payload, lastError)
	return err
}

func (s *Store) ClaimOutbox(ctx context.Context, limit int) ([]OutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `WITH picked AS (
		SELECT id FROM outbox_events
		WHERE published_at IS NULL AND next_attempt_at<=now()
		AND (locked_until IS NULL OR locked_until<now())
		ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1
	) UPDATE outbox_events AS event
	SET locked_until=now()+interval '30 seconds',attempts=event.attempts+1
	FROM picked WHERE event.id=picked.id
	RETURNING event.id,event.topic,event.event_key,event.payload,event.attempts`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OutboxEvent
	for rows.Next() {
		var event OutboxEvent
		if err := rows.Scan(
			&event.ID, &event.Topic, &event.Key, &event.Payload, &event.Attempts,
		); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) MarkOutboxPublished(ctx context.Context, id int64) {
	_, _ = s.pool.Exec(ctx, `UPDATE outbox_events
		SET published_at=now(),locked_until=NULL,last_error='' WHERE id=$1`, id)
}

func (s *Store) MarkOutboxFailed(ctx context.Context, id int64, attempts int, publishErr error) {
	message := publishErr.Error()
	if len(message) > 1000 {
		message = message[:1000]
	}
	backoffSeconds := attempts * attempts
	if backoffSeconds > 3600 {
		backoffSeconds = 3600
	}
	_, _ = s.pool.Exec(ctx, `UPDATE outbox_events SET locked_until=NULL,last_error=$2,
		next_attempt_at=now()+($3*interval '1 second') WHERE id=$1`,
		id, message, backoffSeconds)
}
