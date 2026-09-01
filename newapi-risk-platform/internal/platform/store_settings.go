package platform

import (
	"context"
	"encoding/json"
)

func (s *Store) SaveStorageSettings(
	ctx context.Context,
	retentionDays int,
	kafkaRetentionDays int,
	redisStreamMaxLen int64,
) error {
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer transaction.Rollback(ctx)
	values := map[string]any{
		"retention_days":       retentionDays,
		"kafka_retention_days": kafkaRetentionDays,
		"redis_stream_maxlen":  redisStreamMaxLen,
		"store_raw_prompts":    false,
	}
	for key, value := range values {
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO settings(key,value,updated_at)
			VALUES($1,$2,now()) ON CONFLICT(key) DO UPDATE
			SET value=EXCLUDED.value,updated_at=now()`, key, payload); err != nil {
			return err
		}
	}
	return transaction.Commit(ctx)
}
