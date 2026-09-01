package platform

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var ErrNotFound = errors.New("not found")

type Store struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

type rowScanner interface {
	Scan(dest ...any) error
}

func NewStore(ctx context.Context, cfg Config, log *slog.Logger) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	poolCfg.MaxConns = cfg.PostgresMaxConns
	poolCfg.MinConns = cfg.PostgresMinConns
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool, log: log}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Health(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	const lockID int64 = 55520260901
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", lockID)
	}()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", entry.Name()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		data, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		for _, statement := range strings.Split(string(data), "-- statement-breakpoint") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if _, err := tx.Exec(ctx, statement); err != nil {
				_ = tx.Rollback(ctx)
				return fmt.Errorf("migration %s: %w", entry.Name(), err)
			}
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", entry.Name()); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		s.log.Info("database migration applied", "version", entry.Name())
	}
	return nil
}

func (s *Store) Bootstrap(ctx context.Context, cfg Config, sec *Security) error {
	passwordHash, err := HashPassword(cfg.BootstrapAdminPassword)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO admin_users(username,password_hash,role,enabled)
		VALUES($1,$2,'admin',TRUE) ON CONFLICT(username) DO NOTHING`, cfg.BootstrapAdminUsername, passwordHash); err != nil {
		return fmt.Errorf("bootstrap administrator: %w", err)
	}

	if cfg.BootstrapTrackingSecret != "" {
		ciphertext, err := sec.Encrypt("tracking-client-secret-v1", []byte(cfg.BootstrapTrackingSecret))
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO tracking_clients(key_id,name,secret_ciphertext,enabled)
			VALUES($1,$2,$3,TRUE) ON CONFLICT(key_id) DO NOTHING`, cfg.BootstrapTrackingKeyID, "Bootstrap New API client", ciphertext); err != nil {
			return fmt.Errorf("bootstrap tracking client: %w", err)
		}
	}

	if cfg.DefaultAuditEndpoint != "" {
		ciphertext, err := sec.Encrypt("audit-profile-api-key-v1", []byte(cfg.DefaultAuditAPIKey))
		if err != nil {
			return err
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO audit_profiles
			(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,enabled,fail_closed,is_default)
			VALUES($1,$2,$3,$4,$5,$6,$7,TRUE,TRUE,TRUE)
			ON CONFLICT(name) DO NOTHING`,
			"Default small-model audit", cfg.DefaultAuditEndpoint, cfg.DefaultAuditModel, ciphertext,
			DefaultAuditSystemPrompt, int(cfg.DefaultAuditTimeout.Milliseconds()), cfg.DefaultAuditBlockThreshold)
		if err != nil && !strings.Contains(err.Error(), "audit_profiles_one_default_idx") {
			return fmt.Errorf("bootstrap audit profile: %w", err)
		}
	}
	return nil
}

const routeColumns = `id,slug,name,base_url,provider,auth_mode,secret_header,audit_profile_id,
	enabled,fail_closed,request_timeout_ms,max_concurrency,rate_limit_rps,rate_limit_burst,
	upstream_secret_ciphertext,inbound_key_digest,created_at,updated_at,deleted_at`

func scanRoute(row rowScanner) (Route, error) {
	var route Route
	err := row.Scan(&route.ID, &route.Slug, &route.Name, &route.BaseURL, &route.Provider, &route.AuthMode,
		&route.SecretHeader, &route.AuditProfileID, &route.Enabled, &route.FailClosed, &route.RequestTimeoutMS,
		&route.MaxConcurrency, &route.RateLimitRPS, &route.RateLimitBurst, &route.UpstreamSecretCiphertext,
		&route.InboundKeyDigest, &route.CreatedAt, &route.UpdatedAt, &route.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	return route, err
}

func (s *Store) GetRouteBySlug(ctx context.Context, slug string) (Route, error) {
	return scanRoute(s.pool.QueryRow(ctx, `SELECT `+routeColumns+` FROM routes WHERE slug=$1 AND deleted_at IS NULL`, slug))
}

func (s *Store) GetRouteByID(ctx context.Context, id int64) (Route, error) {
	return scanRoute(s.pool.QueryRow(ctx, `SELECT `+routeColumns+` FROM routes WHERE id=$1 AND deleted_at IS NULL`, id))
}

func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+routeColumns+` FROM routes WHERE deleted_at IS NULL ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Route
	for rows.Next() {
		route, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, route)
	}
	return result, rows.Err()
}

func (s *Store) SaveRoute(ctx context.Context, input RouteInput, sec *Security) (Route, error) {
	if input.RequestTimeoutMS == 0 {
		input.RequestTimeoutMS = 120000
	}
	if input.MaxConcurrency == 0 {
		input.MaxConcurrency = 256
	}
	if input.RateLimitRPS == 0 {
		input.RateLimitRPS = 100
	}
	if input.RateLimitBurst == 0 {
		input.RateLimitBurst = 200
	}
	if input.Provider == "" {
		input.Provider = "openai"
	}
	if input.AuthMode == "" {
		input.AuthMode = "bearer"
	}

	var ciphertext []byte
	var inboundDigest string
	if input.ID > 0 {
		existing, err := s.GetRouteByID(ctx, input.ID)
		if err != nil {
			return Route{}, err
		}
		ciphertext = existing.UpstreamSecretCiphertext
		inboundDigest = existing.InboundKeyDigest
	}
	if input.UpstreamSecret != "" {
		var err error
		ciphertext, err = sec.Encrypt("route-upstream-secret-v1", []byte(input.UpstreamSecret))
		if err != nil {
			return Route{}, err
		}
	}
	if input.InboundKey != "" {
		inboundDigest = sec.Digest("route-inbound-key-v1", input.InboundKey)
	}
	if inboundDigest == "" {
		return Route{}, errors.New("inbound_key is required for a new route")
	}

	if input.ID == 0 {
		return scanRoute(s.pool.QueryRow(ctx, `INSERT INTO routes
			(slug,name,base_url,provider,auth_mode,secret_header,upstream_secret_ciphertext,inbound_key_digest,
			audit_profile_id,enabled,fail_closed,request_timeout_ms,max_concurrency,rate_limit_rps,rate_limit_burst)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			RETURNING `+routeColumns,
			input.Slug, input.Name, input.BaseURL, input.Provider, input.AuthMode, input.SecretHeader,
			ciphertext, inboundDigest, input.AuditProfileID, input.Enabled, input.FailClosed,
			input.RequestTimeoutMS, input.MaxConcurrency, input.RateLimitRPS, input.RateLimitBurst))
	}
	return scanRoute(s.pool.QueryRow(ctx, `UPDATE routes SET slug=$2,name=$3,base_url=$4,provider=$5,auth_mode=$6,
		secret_header=$7,upstream_secret_ciphertext=$8,inbound_key_digest=$9,audit_profile_id=$10,enabled=$11,
		fail_closed=$12,request_timeout_ms=$13,max_concurrency=$14,rate_limit_rps=$15,rate_limit_burst=$16,updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL RETURNING `+routeColumns,
		input.ID, input.Slug, input.Name, input.BaseURL, input.Provider, input.AuthMode, input.SecretHeader,
		ciphertext, inboundDigest, input.AuditProfileID, input.Enabled, input.FailClosed,
		input.RequestTimeoutMS, input.MaxConcurrency, input.RateLimitRPS, input.RateLimitBurst))
}

func (s *Store) DeleteRoute(ctx context.Context, id int64) error {
	command, err := s.pool.Exec(ctx, "UPDATE routes SET deleted_at=now(),enabled=FALSE,updated_at=now() WHERE id=$1 AND deleted_at IS NULL", id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const profileColumns = `id,name,endpoint,model,system_prompt,timeout_ms,block_threshold,enabled,fail_closed,is_default,
	extra,api_key_ciphertext,created_at,updated_at`

func scanProfile(row rowScanner) (AuditProfile, error) {
	var profile AuditProfile
	var extra []byte
	err := row.Scan(&profile.ID, &profile.Name, &profile.Endpoint, &profile.Model, &profile.SystemPrompt,
		&profile.TimeoutMS, &profile.BlockThreshold, &profile.Enabled, &profile.FailClosed, &profile.IsDefault,
		&extra, &profile.APIKeyCiphertext, &profile.CreatedAt, &profile.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditProfile{}, ErrNotFound
	}
	profile.Extra = append([]byte(nil), extra...)
	return profile, err
}

func (s *Store) ListAuditProfiles(ctx context.Context) ([]AuditProfile, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+profileColumns+` FROM audit_profiles ORDER BY is_default DESC,id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AuditProfile
	for rows.Next() {
		profile, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, profile)
	}
	return result, rows.Err()
}

func (s *Store) GetAuditProfile(ctx context.Context, id *int64) (AuditProfile, error) {
	if id != nil && *id > 0 {
		return scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColumns+` FROM audit_profiles WHERE id=$1`, *id))
	}
	return scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColumns+` FROM audit_profiles WHERE is_default=TRUE ORDER BY id LIMIT 1`))
}

func (s *Store) SaveAuditProfile(ctx context.Context, input AuditProfileInput, sec *Security) (AuditProfile, error) {
	if input.TimeoutMS == 0 {
		input.TimeoutMS = 8000
	}
	if input.BlockThreshold == 0 {
		input.BlockThreshold = 0.65
	}
	if len(input.Extra) == 0 {
		input.Extra = json.RawMessage(`{}`)
	}
	if !json.Valid(input.Extra) {
		return AuditProfile{}, errors.New("extra must be valid JSON")
	}
	var ciphertext []byte
	if input.ID > 0 {
		existing, err := s.GetAuditProfile(ctx, &input.ID)
		if err != nil {
			return AuditProfile{}, err
		}
		ciphertext = existing.APIKeyCiphertext
	}
	if input.APIKey != "" {
		var err error
		ciphertext, err = sec.Encrypt("audit-profile-api-key-v1", []byte(input.APIKey))
		if err != nil {
			return AuditProfile{}, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AuditProfile{}, err
	}
	defer tx.Rollback(ctx)
	if input.IsDefault {
		if _, err := tx.Exec(ctx, "UPDATE audit_profiles SET is_default=FALSE,updated_at=now() WHERE is_default=TRUE AND id<>$1", input.ID); err != nil {
			return AuditProfile{}, err
		}
	}
	var profile AuditProfile
	if input.ID == 0 {
		profile, err = scanProfile(tx.QueryRow(ctx, `INSERT INTO audit_profiles
			(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,enabled,fail_closed,is_default,extra)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+profileColumns,
			input.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,
			input.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.Extra))
	} else {
		profile, err = scanProfile(tx.QueryRow(ctx, `UPDATE audit_profiles SET name=$2,endpoint=$3,model=$4,
			api_key_ciphertext=$5,system_prompt=$6,timeout_ms=$7,block_threshold=$8,enabled=$9,fail_closed=$10,
			is_default=$11,extra=$12,updated_at=now() WHERE id=$1 RETURNING `+profileColumns,
			input.ID, input.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,
			input.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.Extra))
	}
	if err != nil {
		return AuditProfile{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AuditProfile{}, err
	}
	return profile, nil
}

func (s *Store) DeleteAuditProfile(ctx context.Context, id int64) error {
	command, err := s.pool.Exec(ctx, "DELETE FROM audit_profiles WHERE id=$1 AND is_default=FALSE", id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return errors.New("profile not found or is the active default")
	}
	return nil
}

func (s *Store) ListCyberRules(ctx context.Context, enabledOnly bool) ([]CyberRule, error) {
	query := `SELECT id,code,name,description,category,pattern,pattern_type,action,priority,enabled,created_at,updated_at FROM cyber_rules`
	if enabledOnly {
		query += " WHERE enabled=TRUE"
	}
	query += " ORDER BY priority DESC,id ASC"
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []CyberRule
	for rows.Next() {
		var rule CyberRule
		if err := rows.Scan(&rule.ID, &rule.Code, &rule.Name, &rule.Description, &rule.Category, &rule.Pattern,
			&rule.PatternType, &rule.Action, &rule.Priority, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, rule)
	}
	return result, rows.Err()
}

func (s *Store) SaveCyberRule(ctx context.Context, rule CyberRule) (CyberRule, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO cyber_rules(id,code,name,description,category,pattern,pattern_type,action,priority,enabled)
		VALUES(NULLIF($1,0),$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT(id) DO UPDATE SET code=EXCLUDED.code,name=EXCLUDED.name,description=EXCLUDED.description,
		category=EXCLUDED.category,pattern=EXCLUDED.pattern,pattern_type=EXCLUDED.pattern_type,
		action=EXCLUDED.action,priority=EXCLUDED.priority,enabled=EXCLUDED.enabled,updated_at=now()
		RETURNING id,code,name,description,category,pattern,pattern_type,action,priority,enabled,created_at,updated_at`,
		rule.ID, rule.Code, rule.Name, rule.Description, rule.Category, rule.Pattern, rule.PatternType,
		rule.Action, rule.Priority, rule.Enabled)
	if err := row.Scan(&rule.ID, &rule.Code, &rule.Name, &rule.Description, &rule.Category, &rule.Pattern,
		&rule.PatternType, &rule.Action, &rule.Priority, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
		return CyberRule{}, err
	}
	return rule, nil
}

func (s *Store) DeleteCyberRule(ctx context.Context, id int64) error {
	command, err := s.pool.Exec(ctx, "DELETE FROM cyber_rules WHERE id=$1", id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetAdminUser(ctx context.Context, username string) (AdminUser, error) {
	var user AdminUser
	err := s.pool.QueryRow(ctx, `SELECT id,username,password_hash,role,enabled,created_at,updated_at
		FROM admin_users WHERE username=$1`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role,
		&user.Enabled, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminUser{}, ErrNotFound
	}
	return user, err
}

func (s *Store) WriteAdminAudit(ctx context.Context, user *AdminClaims, action, resourceType, resourceID, requestID, clientIP string, details any) {
	payload, _ := json.Marshal(details)
	var userID any
	var username string
	if user != nil {
		userID = user.UserID
		username = user.Username
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO admin_audit_logs
		(admin_user_id,username,action,resource_type,resource_id,request_id,client_ip,details)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, userID, username, action, resourceType, resourceID, requestID, clientIP, payload)
	if err != nil {
		s.log.Warn("failed to write admin audit log", "error", err, "action", action)
	}
}

func (s *Store) GetTrackingClient(ctx context.Context, keyID string) (TrackingClient, error) {
	var client TrackingClient
	err := s.pool.QueryRow(ctx, `SELECT id,key_id,name,secret_ciphertext,enabled,created_at,updated_at
		FROM tracking_clients WHERE key_id=$1`, keyID).Scan(&client.ID, &client.KeyID, &client.Name,
		&client.SecretCiphertext, &client.Enabled, &client.CreatedAt, &client.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TrackingClient{}, ErrNotFound
	}
	return client, err
}

func (s *Store) ListTrackingClients(ctx context.Context) ([]TrackingClient, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,key_id,name,secret_ciphertext,enabled,created_at,updated_at
		FROM tracking_clients ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []TrackingClient
	for rows.Next() {
		var client TrackingClient
		if err := rows.Scan(&client.ID, &client.KeyID, &client.Name, &client.SecretCiphertext,
			&client.Enabled, &client.CreatedAt, &client.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, client)
	}
	return result, rows.Err()
}

func (s *Store) SaveTrackingClient(ctx context.Context, keyID, name, secret string, enabled bool, sec *Security) (TrackingClient, error) {
	ciphertext, err := sec.Encrypt("tracking-client-secret-v1", []byte(secret))
	if err != nil {
		return TrackingClient{}, err
	}
	var client TrackingClient
	err = s.pool.QueryRow(ctx, `INSERT INTO tracking_clients(key_id,name,secret_ciphertext,enabled)
		VALUES($1,$2,$3,$4) ON CONFLICT(key_id) DO UPDATE SET name=EXCLUDED.name,
		secret_ciphertext=EXCLUDED.secret_ciphertext,enabled=EXCLUDED.enabled,updated_at=now()
		RETURNING id,key_id,name,secret_ciphertext,enabled,created_at,updated_at`, keyID, name, ciphertext, enabled).
		Scan(&client.ID, &client.KeyID, &client.Name, &client.SecretCiphertext, &client.Enabled, &client.CreatedAt, &client.UpdatedAt)
	return client, err
}

func (s *Store) UseNonceFallback(ctx context.Context, keyID, nonce string, expiresAt time.Time) (bool, error) {
	var inserted string
	err := s.pool.QueryRow(ctx, `INSERT INTO tracking_nonces(key_id,nonce,expires_at) VALUES($1,$2,$3)
		ON CONFLICT DO NOTHING RETURNING nonce`, keyID, nonce, expiresAt).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) InsertTraceBatch(ctx context.Context, events []TraceEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, event := range events {
		if event.CreatedAt.IsZero() {
			event.CreatedAt = time.Now().UTC()
		}
		if event.ExternalEventID != "" {
			var inserted string
			err := tx.QueryRow(ctx, `INSERT INTO request_dedupe(event_id,expires_at) VALUES($1,$2)
				ON CONFLICT DO NOTHING RETURNING event_id`, event.ExternalEventID, event.CreatedAt.Add(48*time.Hour)).Scan(&inserted)
			if errors.Is(err, pgx.ErrNoRows) {
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
		_, err = tx.Exec(ctx, `INSERT INTO request_traces
			(request_id,external_event_id,source,route_slug,newapi_request_id,external_user_id,model,endpoint,
			decision,risk_code,http_status,upstream_status,latency_ms,audit_latency_ms,request_bytes,response_bytes,
			prompt_hmac,metadata,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
			event.RequestID, event.ExternalEventID, event.Source, event.RouteSlug, event.NewAPIRequestID,
			event.ExternalUserID, event.Model, event.Endpoint, event.Decision, event.RiskCode, event.HTTPStatus,
			event.UpstreamStatus, event.LatencyMS, event.AuditLatencyMS, event.RequestBytes, event.ResponseBytes,
			event.PromptHMAC, metadata, event.CreatedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
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
	args := []any{filter.From, filter.To}
	add := func(column, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		clauses = append(clauses, column+" = $"+strconv.Itoa(len(args)))
	}
	add("route_slug", filter.RouteSlug)
	add("decision", filter.Decision)
	add("risk_code", filter.RiskCode)
	add("external_user_id", filter.UserID)
	args = append(args, filter.Limit)
	query := `SELECT request_id,external_event_id,source,route_slug,newapi_request_id,external_user_id,model,endpoint,
		decision,risk_code,http_status,upstream_status,latency_ms,audit_latency_ms,request_bytes,response_bytes,
		prompt_hmac,metadata,created_at FROM request_traces WHERE ` + strings.Join(clauses, " AND ") +
		" ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(args))
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []TraceEvent
	for rows.Next() {
		var event TraceEvent
		var metadata []byte
		if err := rows.Scan(&event.RequestID, &event.ExternalEventID, &event.Source, &event.RouteSlug,
			&event.NewAPIRequestID, &event.ExternalUserID, &event.Model, &event.Endpoint, &event.Decision,
			&event.RiskCode, &event.HTTPStatus, &event.UpstreamStatus, &event.LatencyMS, &event.AuditLatencyMS,
			&event.RequestBytes, &event.ResponseBytes, &event.PromptHMAC, &metadata, &event.CreatedAt); err != nil {
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
	stats := DashboardStats{WindowHours: int64(window.Hours()), ByRiskCode: map[string]int64{}, ByRoute: map[string]int64{}}
	from := time.Now().UTC().Add(-window)
	var p95 *float64
	err := s.pool.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE decision='allow'),
		count(*) FILTER (WHERE decision='block'),
		count(*) FILTER (WHERE decision='error'),
		percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)
		FROM request_traces WHERE created_at >= $1`, from).
		Scan(&stats.TotalRequests, &stats.AllowedRequests, &stats.BlockedRequests, &stats.ErrorRequests, &p95)
	if err != nil {
		return stats, err
	}
	if p95 != nil {
		stats.P95LatencyMS = *p95
	}
	if stats.TotalRequests > 0 {
		stats.BlockRate = float64(stats.BlockedRequests) / float64(stats.TotalRequests)
	}
	rows, err := s.pool.Query(ctx, `SELECT risk_code,count(*) FROM request_traces
		WHERE created_at >= $1 AND risk_code<>'' GROUP BY risk_code ORDER BY count(*) DESC LIMIT 20`, from)
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
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM routes WHERE deleted_at IS NULL").Scan(&stats.ConfiguredRoutes)
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
	_, err = s.pool.Exec(ctx, `INSERT INTO settings(key,value,updated_at) VALUES($1,$2,now())
		ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()`, key, payload)
	return err
}

func (s *Store) MaintainPartitions(ctx context.Context, retentionDays int) error {
	now := time.Now().UTC().Truncate(24 * time.Hour)
	for offset := -1; offset <= 3; offset++ {
		start := now.AddDate(0, 0, offset)
		end := start.AddDate(0, 0, 1)
		name := "request_traces_" + start.Format("20060102")
		statement := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF request_traces
			FOR VALUES FROM ('%s') TO ('%s')`, name, start.Format(time.RFC3339), end.Format(time.RFC3339))
		if _, err := s.pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("create trace partition %s: %w", name, err)
		}
	}

	rows, err := s.pool.Query(ctx, `SELECT child.relname
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
	cutoff := now.AddDate(0, 0, -retentionDays)
	for _, name := range partitions {
		if !validName.MatchString(name) {
			continue
		}
		date, err := time.Parse("20060102", strings.TrimPrefix(name, "request_traces_"))
		if err != nil || !date.Before(cutoff) {
			continue
		}
		if _, err := s.pool.Exec(ctx, "DROP TABLE IF EXISTS "+name); err != nil {
			return fmt.Errorf("drop trace partition %s: %w", name, err)
		}
		s.log.Info("expired trace partition dropped", "partition", name)
	}
	_, _ = s.pool.Exec(ctx, "DELETE FROM request_dedupe WHERE expires_at < now()")
	_, _ = s.pool.Exec(ctx, "DELETE FROM tracking_nonces WHERE expires_at < now()")
	_, _ = s.pool.Exec(ctx, "DELETE FROM admin_audit_logs WHERE created_at < now() - interval '180 days'")
	_, _ = s.pool.Exec(ctx, "DELETE FROM outbox_events WHERE published_at < now() - interval '7 days'")
	return nil
}

func (s *Store) EnqueueOutbox(ctx context.Context, topic, key string, payload []byte, lastError string) error {
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
		SELECT id FROM outbox_events WHERE published_at IS NULL AND next_attempt_at<=now()
		AND (locked_until IS NULL OR locked_until<now()) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $1
	) UPDATE outbox_events o SET locked_until=now()+interval '30 seconds',attempts=o.attempts+1
	FROM picked WHERE o.id=picked.id RETURNING o.id,o.topic,o.event_key,o.payload,o.attempts`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OutboxEvent
	for rows.Next() {
		var event OutboxEvent
		if err := rows.Scan(&event.ID, &event.Topic, &event.Key, &event.Payload, &event.Attempts); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) MarkOutboxPublished(ctx context.Context, id int64) {
	_, _ = s.pool.Exec(ctx, "UPDATE outbox_events SET published_at=now(),locked_until=NULL,last_error='' WHERE id=$1", id)
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
		next_attempt_at=now()+make_interval(secs=>$3) WHERE id=$1`, id, message, backoffSeconds)
}
