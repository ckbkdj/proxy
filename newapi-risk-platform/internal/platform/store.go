package platform

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
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
	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	poolConfig.MaxConns = cfg.PostgresMaxConns
	poolConfig.MinConns = cfg.PostgresMinConns
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return &Store{pool: pool, log: log}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) Health(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *Store) Migrate(ctx context.Context) error {
	connection, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer connection.Release()

	const lockID int64 = 55520260901
	if _, err := connection.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = connection.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", lockID)
	}()

	if _, err := connection.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
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
		if err := connection.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", entry.Name()).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		data, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return err
		}
		transaction, err := connection.Begin(ctx)
		if err != nil {
			return err
		}
		for _, statement := range strings.Split(string(data), "-- statement-breakpoint") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if _, err := transaction.Exec(ctx, statement); err != nil {
				_ = transaction.Rollback(ctx)
				return fmt.Errorf("migration %s: %w", entry.Name(), err)
			}
		}
		if _, err := transaction.Exec(ctx,
			"INSERT INTO schema_migrations(version) VALUES($1)", entry.Name()); err != nil {
			_ = transaction.Rollback(ctx)
			return err
		}
		if err := transaction.Commit(ctx); err != nil {
			return err
		}
		s.log.Info("database migration applied", "version", entry.Name())
	}
	return nil
}

func (s *Store) Bootstrap(ctx context.Context, cfg Config, security *Security) error {
	passwordHash, err := HashPassword(cfg.BootstrapAdminPassword)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO admin_users(username,password_hash,role,enabled)
		VALUES($1,$2,'admin',TRUE) ON CONFLICT(username) DO NOTHING`,
		cfg.BootstrapAdminUsername, passwordHash); err != nil {
		return fmt.Errorf("bootstrap administrator: %w", err)
	}

	if cfg.BootstrapTrackingSecret != "" {
		ciphertext, err := security.Encrypt("tracking-client-secret-v1", []byte(cfg.BootstrapTrackingSecret))
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO tracking_clients(key_id,name,secret_ciphertext,enabled)
			VALUES($1,$2,$3,TRUE) ON CONFLICT(key_id) DO NOTHING`,
			cfg.BootstrapTrackingKeyID, "Bootstrap New API client", ciphertext); err != nil {
			return fmt.Errorf("bootstrap tracking client: %w", err)
		}
	}

	if cfg.DefaultAuditEndpoint != "" {
		ciphertext, err := security.Encrypt("audit-profile-api-key-v1", []byte(cfg.DefaultAuditAPIKey))
		if err != nil {
			return err
		}
		var defaultExists bool
		if err := s.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM audit_profiles WHERE is_default=TRUE)").Scan(&defaultExists); err != nil {
			return err
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO audit_profiles
			(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,enabled,fail_closed,is_default)
			VALUES($1,$2,$3,$4,$5,$6,$7,TRUE,TRUE,$8)
			ON CONFLICT(name) DO NOTHING`,
			"Default small-model audit", cfg.DefaultAuditEndpoint, cfg.DefaultAuditModel, ciphertext,
			DefaultAuditSystemPrompt, int(cfg.DefaultAuditTimeout.Milliseconds()),
			cfg.DefaultAuditBlockThreshold, !defaultExists)
		if err != nil {
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
	err := row.Scan(
		&route.ID, &route.Slug, &route.Name, &route.BaseURL, &route.Provider, &route.AuthMode,
		&route.SecretHeader, &route.AuditProfileID, &route.Enabled, &route.FailClosed,
		&route.RequestTimeoutMS, &route.MaxConcurrency, &route.RateLimitRPS, &route.RateLimitBurst,
		&route.UpstreamSecretCiphertext, &route.InboundKeyDigest,
		&route.CreatedAt, &route.UpdatedAt, &route.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	return route, err
}

func (s *Store) GetRouteBySlug(ctx context.Context, slug string) (Route, error) {
	return scanRoute(s.pool.QueryRow(ctx,
		`SELECT `+routeColumns+` FROM routes WHERE slug=$1 AND deleted_at IS NULL`, slug))
}

func (s *Store) GetRouteByID(ctx context.Context, id int64) (Route, error) {
	return scanRoute(s.pool.QueryRow(ctx,
		`SELECT `+routeColumns+` FROM routes WHERE id=$1 AND deleted_at IS NULL`, id))
}

func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+routeColumns+` FROM routes WHERE deleted_at IS NULL ORDER BY id DESC`)
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

func (s *Store) SaveRoute(ctx context.Context, input RouteInput, security *Security) (Route, error) {
	if input.RequestTimeoutMS == 0 {
		input.RequestTimeoutMS = 120000
	}
	if input.MaxConcurrency == 0 {
		input.MaxConcurrency = 256
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
		ciphertext, err = security.Encrypt("route-upstream-secret-v1", []byte(input.UpstreamSecret))
		if err != nil {
			return Route{}, err
		}
	}
	if input.InboundKey != "" {
		inboundDigest = security.Digest("route-inbound-key-v1", input.InboundKey)
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
	return scanRoute(s.pool.QueryRow(ctx, `UPDATE routes SET slug=$2,name=$3,base_url=$4,provider=$5,
		auth_mode=$6,secret_header=$7,upstream_secret_ciphertext=$8,inbound_key_digest=$9,
		audit_profile_id=$10,enabled=$11,fail_closed=$12,request_timeout_ms=$13,max_concurrency=$14,
		rate_limit_rps=$15,rate_limit_burst=$16,updated_at=now()
		WHERE id=$1 AND deleted_at IS NULL RETURNING `+routeColumns,
		input.ID, input.Slug, input.Name, input.BaseURL, input.Provider, input.AuthMode, input.SecretHeader,
		ciphertext, inboundDigest, input.AuditProfileID, input.Enabled, input.FailClosed,
		input.RequestTimeoutMS, input.MaxConcurrency, input.RateLimitRPS, input.RateLimitBurst))
}

func (s *Store) DeleteRoute(ctx context.Context, id int64) error {
	command, err := s.pool.Exec(ctx,
		"UPDATE routes SET deleted_at=now(),enabled=FALSE,updated_at=now() WHERE id=$1 AND deleted_at IS NULL", id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const profileColumns = `id,name,endpoint,model,system_prompt,timeout_ms,block_threshold,enabled,
	fail_closed,is_default,extra,api_key_ciphertext,created_at,updated_at`

func scanProfile(row rowScanner) (AuditProfile, error) {
	var profile AuditProfile
	var extra []byte
	err := row.Scan(
		&profile.ID, &profile.Name, &profile.Endpoint, &profile.Model, &profile.SystemPrompt,
		&profile.TimeoutMS, &profile.BlockThreshold, &profile.Enabled, &profile.FailClosed,
		&profile.IsDefault, &extra, &profile.APIKeyCiphertext, &profile.CreatedAt, &profile.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuditProfile{}, ErrNotFound
	}
	profile.Extra = append([]byte(nil), extra...)
	return profile, err
}

func (s *Store) ListAuditProfiles(ctx context.Context) ([]AuditProfile, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+profileColumns+` FROM audit_profiles ORDER BY is_default DESC,id DESC`)
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
		return scanProfile(s.pool.QueryRow(ctx,
			`SELECT `+profileColumns+` FROM audit_profiles WHERE id=$1`, *id))
	}
	return scanProfile(s.pool.QueryRow(ctx,
		`SELECT `+profileColumns+` FROM audit_profiles WHERE is_default=TRUE ORDER BY id LIMIT 1`))
}

func (s *Store) SaveAuditProfile(ctx context.Context, input AuditProfileInput, security *Security) (AuditProfile, error) {
	if input.TimeoutMS == 0 {
		input.TimeoutMS = 8000
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
		ciphertext, err = security.Encrypt("audit-profile-api-key-v1", []byte(input.APIKey))
		if err != nil {
			return AuditProfile{}, err
		}
	}

	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return AuditProfile{}, err
	}
	defer transaction.Rollback(ctx)
	if input.IsDefault {
		if _, err := transaction.Exec(ctx,
			"UPDATE audit_profiles SET is_default=FALSE,updated_at=now() WHERE is_default=TRUE AND id<>$1", input.ID); err != nil {
			return AuditProfile{}, err
		}
	}
	var profile AuditProfile
	if input.ID == 0 {
		profile, err = scanProfile(transaction.QueryRow(ctx, `INSERT INTO audit_profiles
			(name,endpoint,model,api_key_ciphertext,system_prompt,timeout_ms,block_threshold,
			enabled,fail_closed,is_default,extra)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+profileColumns,
			input.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,
			input.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.Extra))
	} else {
		profile, err = scanProfile(transaction.QueryRow(ctx, `UPDATE audit_profiles SET name=$2,
			endpoint=$3,model=$4,api_key_ciphertext=$5,system_prompt=$6,timeout_ms=$7,
			block_threshold=$8,enabled=$9,fail_closed=$10,is_default=$11,extra=$12,updated_at=now()
			WHERE id=$1 RETURNING `+profileColumns,
			input.ID, input.Name, input.Endpoint, input.Model, ciphertext, input.SystemPrompt, input.TimeoutMS,
			input.BlockThreshold, input.Enabled, input.FailClosed, input.IsDefault, input.Extra))
	}
	if err != nil {
		return AuditProfile{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return AuditProfile{}, err
	}
	return profile, nil
}

func (s *Store) DeleteAuditProfile(ctx context.Context, id int64) error {
	command, err := s.pool.Exec(ctx,
		"DELETE FROM audit_profiles WHERE id=$1 AND is_default=FALSE", id)
	if err != nil {
		return err
	}
	if command.RowsAffected() == 0 {
		return errors.New("profile not found or is the active default")
	}
	return nil
}

func scanCyberRule(row rowScanner) (CyberRule, error) {
	var rule CyberRule
	err := row.Scan(
		&rule.ID, &rule.Code, &rule.Name, &rule.Description, &rule.Category, &rule.Pattern,
		&rule.PatternType, &rule.Action, &rule.Priority, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return CyberRule{}, ErrNotFound
	}
	return rule, err
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
		rule, err := scanCyberRule(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, rule)
	}
	return result, rows.Err()
}

func (s *Store) UpsertCyberRule(ctx context.Context, rule CyberRule) (CyberRule, error) {
	const columns = `id,code,name,description,category,pattern,pattern_type,action,priority,enabled,created_at,updated_at`
	if rule.ID == 0 {
		return scanCyberRule(s.pool.QueryRow(ctx, `INSERT INTO cyber_rules
			(code,name,description,category,pattern,pattern_type,action,priority,enabled)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+columns,
			rule.Code, rule.Name, rule.Description, rule.Category, rule.Pattern,
			rule.PatternType, rule.Action, rule.Priority, rule.Enabled))
	}
	return scanCyberRule(s.pool.QueryRow(ctx, `UPDATE cyber_rules SET code=$2,name=$3,
		description=$4,category=$5,pattern=$6,pattern_type=$7,action=$8,priority=$9,
		enabled=$10,updated_at=now() WHERE id=$1 RETURNING `+columns,
		rule.ID, rule.Code, rule.Name, rule.Description, rule.Category, rule.Pattern,
		rule.PatternType, rule.Action, rule.Priority, rule.Enabled))
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
		FROM admin_users WHERE username=$1`, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Role,
		&user.Enabled, &user.CreatedAt, &user.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdminUser{}, ErrNotFound
	}
	return user, err
}

func (s *Store) WriteAdminAudit(
	ctx context.Context,
	user *AdminClaims,
	action string,
	resourceType string,
	resourceID string,
	requestID string,
	clientIP string,
	details any,
) {
	payload := []byte(`{}`)
	if details != nil {
		if encoded, err := json.Marshal(details); err == nil {
			payload = encoded
		}
	}
	var userID any
	var username string
	if user != nil {
		userID = user.UserID
		username = user.Username
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO admin_audit_logs
		(admin_user_id,username,action,resource_type,resource_id,request_id,client_ip,details)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		userID, username, action, resourceType, resourceID, requestID, clientIP, payload)
	if err != nil {
		s.log.Warn("failed to write admin audit log", "error", err, "action", action)
	}
}

func (s *Store) GetTrackingClient(ctx context.Context, keyID string) (TrackingClient, error) {
	var client TrackingClient
	err := s.pool.QueryRow(ctx, `SELECT id,key_id,name,secret_ciphertext,enabled,created_at,updated_at
		FROM tracking_clients WHERE key_id=$1`, keyID).Scan(
		&client.ID, &client.KeyID, &client.Name, &client.SecretCiphertext,
		&client.Enabled, &client.CreatedAt, &client.UpdatedAt,
	)
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
		if err := rows.Scan(
			&client.ID, &client.KeyID, &client.Name, &client.SecretCiphertext,
			&client.Enabled, &client.CreatedAt, &client.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, client)
	}
	return result, rows.Err()
}

func (s *Store) SaveTrackingClient(
	ctx context.Context,
	keyID string,
	name string,
	secret string,
	enabled bool,
	security *Security,
) (TrackingClient, error) {
	ciphertext, err := security.Encrypt("tracking-client-secret-v1", []byte(secret))
	if err != nil {
		return TrackingClient{}, err
	}
	var client TrackingClient
	err = s.pool.QueryRow(ctx, `INSERT INTO tracking_clients(key_id,name,secret_ciphertext,enabled)
		VALUES($1,$2,$3,$4) ON CONFLICT(key_id) DO UPDATE SET name=EXCLUDED.name,
		secret_ciphertext=EXCLUDED.secret_ciphertext,enabled=EXCLUDED.enabled,updated_at=now()
		RETURNING id,key_id,name,secret_ciphertext,enabled,created_at,updated_at`,
		keyID, name, ciphertext, enabled).Scan(
		&client.ID, &client.KeyID, &client.Name, &client.SecretCiphertext,
		&client.Enabled, &client.CreatedAt, &client.UpdatedAt,
	)
	return client, err
}

func (s *Store) UseNonceFallback(ctx context.Context, keyID string, nonce string, expiresAt time.Time) (bool, error) {
	var inserted string
	err := s.pool.QueryRow(ctx, `INSERT INTO tracking_nonces(key_id,nonce,expires_at) VALUES($1,$2,$3)
		ON CONFLICT DO NOTHING RETURNING nonce`, keyID, nonce, expiresAt).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
