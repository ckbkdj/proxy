package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

type TraceFilter struct {
	RequestID string
	RouteSlug string
	Outcome   string
	Model     string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}

type OutboxEvent struct {
	ID       string
	Topic    string
	Key      string
	Payload  []byte
	Headers  map[string]string
	Attempts int
}

type RuntimeStats struct {
	RoutesEnabled     int64 `json:"routes_enabled"`
	RulesEnabled      int64 `json:"rules_enabled"`
	TracesLastHour    int64 `json:"traces_last_hour"`
	BlockedLastHour   int64 `json:"blocked_last_hour"`
	OutboxPending     int64 `json:"outbox_pending"`
	OutboxDead        int64 `json:"outbox_dead"`
	DefaultPartition  int64 `json:"default_partition_rows"`
}

func New(ctx context.Context, cfg config.Config) (*Store, error) {
	pc, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil { return nil, fmt.Errorf("parse DATABASE_URL: %w", err) }
	pc.MaxConns = cfg.DBMaxConns
	pc.MinConns = cfg.DBMinConns
	pc.MaxConnIdleTime = 10 * time.Minute
	pc.MaxConnLifetime = 60 * time.Minute
	pc.MaxConnLifetimeJitter = 5 * time.Minute
	connectCtx, cancel := context.WithTimeout(ctx, cfg.DBConnectTimeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(connectCtx, pc)
	if err != nil { return nil, fmt.Errorf("open PostgreSQL: %w", err) }
	if err := pool.Ping(connectCtx); err != nil { pool.Close(); return nil, fmt.Errorf("ping PostgreSQL: %w", err) }
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) Migrate(ctx context.Context, migrationPath string) error {
	body, err := os.ReadFile(migrationPath)
	if err != nil { return fmt.Errorf("read migration %s: %w", migrationPath, err) }
	conn, err := s.pool.Acquire(ctx)
	if err != nil { return err }
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(742019260901)`); err != nil { return err }
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(742019260901)`) }()
	if _, err = conn.Exec(ctx, string(body)); err != nil { return fmt.Errorf("apply database migration: %w", err) }
	return nil
}

func (s *Store) EnsureTracePartitions(ctx context.Context, now time.Time, retentionDays int) error {
	if retentionDays < 1 { retentionDays = 7 }
	start := now.UTC().Truncate(24 * time.Hour).AddDate(0, 0, -retentionDays-1)
	end := now.UTC().Truncate(24 * time.Hour).AddDate(0, 0, 3)
	for day := start; day.Before(end); day = day.AddDate(0, 0, 1) {
		name := "request_traces_" + day.Format("20060102")
		next := day.AddDate(0, 0, 1)
		sql := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF request_traces FOR VALUES FROM ('%s') TO ('%s')`,
			pgx.Identifier{name}.Sanitize(), day.Format("2006-01-02"), next.Format("2006-01-02"),
		)
		if _, err := s.pool.Exec(ctx, sql); err != nil { return fmt.Errorf("create trace partition %s: %w", name, err) }
		idx := []string{
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s(created_at DESC)`, pgx.Identifier{"idx_" + name + "_created"}.Sanitize(), pgx.Identifier{name}.Sanitize()),
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s(external_request_id)`, pgx.Identifier{"idx_" + name + "_external"}.Sanitize(), pgx.Identifier{name}.Sanitize()),
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s(route_slug, created_at DESC)`, pgx.Identifier{"idx_" + name + "_route"}.Sanitize(), pgx.Identifier{name}.Sanitize()),
			fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s(outcome, created_at DESC)`, pgx.Identifier{"idx_" + name + "_outcome"}.Sanitize(), pgx.Identifier{name}.Sanitize()),
		}
		for _, statement := range idx { if _, err := s.pool.Exec(ctx, statement); err != nil { return err } }
	}
	return nil
}

var partitionPattern = regexp.MustCompile(`^request_traces_(\d{8})$`)

func (s *Store) PurgeExpiredTraces(ctx context.Context, retentionDays int, now time.Time) error {
	if retentionDays < 1 { retentionDays = 7 }
	cutoff := now.UTC().AddDate(0, 0, -retentionDays)
	rows, err := s.pool.Query(ctx, `
		SELECT child.relname
		FROM pg_inherits
		JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
		JOIN pg_class child ON pg_inherits.inhrelid = child.oid
		WHERE parent.relname = 'request_traces'`)
	if err != nil { return err }
	var names []string
	for rows.Next() { var n string; if err := rows.Scan(&n); err != nil { rows.Close(); return err }; names = append(names, n) }
	rows.Close()
	for _, name := range names {
		m := partitionPattern.FindStringSubmatch(name)
		if len(m) != 2 { continue }
		day, err := time.Parse("20060102", m[1]); if err != nil { continue }
		if day.AddDate(0, 0, 1).Before(cutoff) {
			if _, err := s.pool.Exec(ctx, `DROP TABLE IF EXISTS `+pgx.Identifier{name}.Sanitize()); err != nil { return err }
		}
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM request_traces_default WHERE created_at < $1`, cutoff)
	return err
}

func (s *Store) BootstrapAdmin(ctx context.Context, username, passwordHash, role string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_users(username, password_hash, role, enabled)
		VALUES ($1,$2,$3,true)
		ON CONFLICT (username) DO NOTHING`, username, passwordHash, role)
	return err
}

func (s *Store) FindAdmin(ctx context.Context, username string) (core.AdminUser, error) {
	var u core.AdminUser
	err := s.pool.QueryRow(ctx, `SELECT id::text, username, password_hash, role, enabled, created_at, updated_at FROM admin_users WHERE username=$1`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

const routeSelect = `SELECT id::text, slug, name, upstream_base_url, upstream_kind, upstream_api_key_cipher,
	client_token_hash, COALESCE(audit_profile_id::text,''), enabled, rate_limit_rps, rate_limit_burst,
	max_inflight, request_timeout_ms, allow_private_upstream, upstream_error_policy, extra_headers_cipher,
	created_at, updated_at FROM routes`

func scanRoute(row pgx.Row) (core.Route, error) {
	var r core.Route
	var profileID string
	var policy []byte
	err := row.Scan(&r.ID, &r.Slug, &r.Name, &r.UpstreamBaseURL, &r.UpstreamKind, &r.UpstreamAPIKeyCipher,
		&r.ClientTokenHash, &profileID, &r.Enabled, &r.RateLimitRPS, &r.RateLimitBurst, &r.MaxInflight,
		&r.RequestTimeoutMS, &r.AllowPrivateUpstream, &policy, &r.ExtraHeadersEncrypted, &r.CreatedAt, &r.UpdatedAt)
	if profileID != "" { r.AuditProfileID = &profileID }
	r.UpstreamErrorPolicy = json.RawMessage(policy)
	return r, err
}

func (s *Store) GetRouteBySlug(ctx context.Context, slug string) (core.Route, error) {
	return scanRoute(s.pool.QueryRow(ctx, routeSelect+` WHERE slug=$1`, slug))
}
func (s *Store) GetRouteByID(ctx context.Context, id string) (core.Route, error) {
	return scanRoute(s.pool.QueryRow(ctx, routeSelect+` WHERE id=$1`, id))
}
func (s *Store) ListRoutes(ctx context.Context) ([]core.Route, error) {
	rows, err := s.pool.Query(ctx, routeSelect+` ORDER BY name, slug`)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []core.Route
	for rows.Next() { r, err := scanRoute(rows); if err != nil { return nil, err }; out = append(out, r) }
	return out, rows.Err()
}
func (s *Store) UpsertRoute(ctx context.Context, r core.Route) (core.Route, error) {
	profile := interface{}(nil); if r.AuditProfileID != nil && *r.AuditProfileID != "" { profile = *r.AuditProfileID }
	policy := r.UpstreamErrorPolicy; if len(policy) == 0 { policy = json.RawMessage(`{}`) }
	if r.ID == "" {
		row := s.pool.QueryRow(ctx, `INSERT INTO routes(slug,name,upstream_base_url,upstream_kind,upstream_api_key_cipher,
			client_token_hash,audit_profile_id,enabled,rate_limit_rps,rate_limit_burst,max_inflight,request_timeout_ms,
			allow_private_upstream,upstream_error_policy,extra_headers_cipher)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id::text`,
			r.Slug,r.Name,r.UpstreamBaseURL,r.UpstreamKind,r.UpstreamAPIKeyCipher,r.ClientTokenHash,profile,r.Enabled,
			r.RateLimitRPS,r.RateLimitBurst,r.MaxInflight,r.RequestTimeoutMS,r.AllowPrivateUpstream,policy,r.ExtraHeadersEncrypted)
		if err := row.Scan(&r.ID); err != nil { return core.Route{}, err }
	} else {
		_, err := s.pool.Exec(ctx, `UPDATE routes SET slug=$2,name=$3,upstream_base_url=$4,upstream_kind=$5,
			upstream_api_key_cipher=$6,client_token_hash=$7,audit_profile_id=$8,enabled=$9,rate_limit_rps=$10,
			rate_limit_burst=$11,max_inflight=$12,request_timeout_ms=$13,allow_private_upstream=$14,
			upstream_error_policy=$15,extra_headers_cipher=$16,updated_at=now() WHERE id=$1`,
			r.ID,r.Slug,r.Name,r.UpstreamBaseURL,r.UpstreamKind,r.UpstreamAPIKeyCipher,r.ClientTokenHash,profile,r.Enabled,
			r.RateLimitRPS,r.RateLimitBurst,r.MaxInflight,r.RequestTimeoutMS,r.AllowPrivateUpstream,policy,r.ExtraHeadersEncrypted)
		if err != nil { return core.Route{}, err }
	}
	return s.GetRouteByID(ctx, r.ID)
}
func (s *Store) DeleteRoute(ctx context.Context, id string) error { _, err := s.pool.Exec(ctx, `DELETE FROM routes WHERE id=$1`, id); return err }

const profileSelect = `SELECT id::text,name,endpoint,model,api_key_cipher,enabled,fail_mode,block_threshold,
	timeout_ms,max_input_chars,cache_ttl_seconds,system_prompt,created_at,updated_at FROM audit_profiles`

func scanProfile(row pgx.Row) (core.AuditProfile, error) {
	var p core.AuditProfile
	err := row.Scan(&p.ID,&p.Name,&p.Endpoint,&p.Model,&p.APIKeyCipher,&p.Enabled,&p.FailMode,&p.BlockThreshold,
		&p.TimeoutMS,&p.MaxInputChars,&p.CacheTTLSeconds,&p.SystemPrompt,&p.CreatedAt,&p.UpdatedAt)
	return p, err
}
func (s *Store) GetAuditProfile(ctx context.Context, id string) (core.AuditProfile, error) { return scanProfile(s.pool.QueryRow(ctx, profileSelect+` WHERE id=$1`, id)) }
func (s *Store) ListAuditProfiles(ctx context.Context) ([]core.AuditProfile, error) {
	rows, err := s.pool.Query(ctx, profileSelect+` ORDER BY name`); if err != nil { return nil, err }; defer rows.Close()
	var out []core.AuditProfile
	for rows.Next() { p, err := scanProfile(rows); if err != nil { return nil, err }; out = append(out,p) }
	return out, rows.Err()
}
func (s *Store) UpsertAuditProfile(ctx context.Context, p core.AuditProfile) (core.AuditProfile, error) {
	if p.ID == "" {
		err := s.pool.QueryRow(ctx, `INSERT INTO audit_profiles(name,endpoint,model,api_key_cipher,enabled,fail_mode,
			block_threshold,timeout_ms,max_input_chars,cache_ttl_seconds,system_prompt)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id::text`, p.Name,p.Endpoint,p.Model,p.APIKeyCipher,
			p.Enabled,p.FailMode,p.BlockThreshold,p.TimeoutMS,p.MaxInputChars,p.CacheTTLSeconds,p.SystemPrompt).Scan(&p.ID)
		if err != nil { return core.AuditProfile{}, err }
	} else {
		_, err := s.pool.Exec(ctx, `UPDATE audit_profiles SET name=$2,endpoint=$3,model=$4,api_key_cipher=$5,
			enabled=$6,fail_mode=$7,block_threshold=$8,timeout_ms=$9,max_input_chars=$10,cache_ttl_seconds=$11,
			system_prompt=$12,updated_at=now() WHERE id=$1`, p.ID,p.Name,p.Endpoint,p.Model,p.APIKeyCipher,p.Enabled,
			p.FailMode,p.BlockThreshold,p.TimeoutMS,p.MaxInputChars,p.CacheTTLSeconds,p.SystemPrompt)
		if err != nil { return core.AuditProfile{}, err }
	}
	return s.GetAuditProfile(ctx,p.ID)
}
func (s *Store) DeleteAuditProfile(ctx context.Context, id string) error { _, err := s.pool.Exec(ctx, `DELETE FROM audit_profiles WHERE id=$1`, id); return err }

func (s *Store) ListRules(ctx context.Context, enabledOnly bool) ([]core.RiskRule, error) {
	q := `SELECT id::text,name,category,pattern,action,score,priority,enabled,builtin,created_at,updated_at FROM risk_rules`
	if enabledOnly { q += ` WHERE enabled` }
	q += ` ORDER BY priority DESC, name`
	rows, err := s.pool.Query(ctx,q); if err != nil { return nil,err }; defer rows.Close()
	var out []core.RiskRule
	for rows.Next() { var r core.RiskRule; if err:=rows.Scan(&r.ID,&r.Name,&r.Category,&r.Pattern,&r.Action,&r.Score,&r.Priority,&r.Enabled,&r.Builtin,&r.CreatedAt,&r.UpdatedAt); err!=nil{return nil,err}; out=append(out,r) }
	return out,rows.Err()
}
func (s *Store) GetRule(ctx context.Context,id string)(core.RiskRule,error){
	var r core.RiskRule
	err:=s.pool.QueryRow(ctx,`SELECT id::text,name,category,pattern,action,score,priority,enabled,builtin,created_at,updated_at FROM risk_rules WHERE id=$1`,id).
		Scan(&r.ID,&r.Name,&r.Category,&r.Pattern,&r.Action,&r.Score,&r.Priority,&r.Enabled,&r.Builtin,&r.CreatedAt,&r.UpdatedAt)
	return r,err
}
func (s *Store) UpsertRule(ctx context.Context,r core.RiskRule)(core.RiskRule,error){
	if r.ID==""{
		err:=s.pool.QueryRow(ctx,`INSERT INTO risk_rules(name,category,pattern,action,score,priority,enabled,builtin)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text`,r.Name,r.Category,r.Pattern,r.Action,r.Score,r.Priority,r.Enabled,r.Builtin).Scan(&r.ID)
		if err!=nil{return core.RiskRule{},err}
	}else{
		_,err:=s.pool.Exec(ctx,`UPDATE risk_rules SET name=$2,category=$3,pattern=$4,action=$5,score=$6,priority=$7,
			enabled=$8,updated_at=now() WHERE id=$1`,r.ID,r.Name,r.Category,r.Pattern,r.Action,r.Score,r.Priority,r.Enabled)
		if err!=nil{return core.RiskRule{},err}
	}
	return s.GetRule(ctx,r.ID)
}
func (s *Store) DeleteRule(ctx context.Context,id string)error{_,err:=s.pool.Exec(ctx,`DELETE FROM risk_rules WHERE id=$1 AND builtin=false`,id);return err}

func (s *Store) GetStoragePolicy(ctx context.Context)(core.StoragePolicy,error){
	var p core.StoragePolicy
	err:=s.pool.QueryRow(ctx,`SELECT retention_days,postgres_enabled,redis_buffer_enabled,redis_buffer_ttl_hours,
		kafka_enabled,kafka_retention_hours,store_raw_prompt,updated_at FROM storage_policy WHERE singleton=true`).
		Scan(&p.RetentionDays,&p.PostgresEnabled,&p.RedisBufferEnabled,&p.RedisBufferTTLHours,&p.KafkaEnabled,&p.KafkaRetentionHours,&p.StoreRawPrompt,&p.UpdatedAt)
	return p,err
}
func (s *Store) SetStoragePolicy(ctx context.Context,p core.StoragePolicy)(core.StoragePolicy,error){
	if p.StoreRawPrompt{return core.StoragePolicy{},errors.New("raw prompt storage is intentionally disabled")}
	_,err:=s.pool.Exec(ctx,`UPDATE storage_policy SET retention_days=$1,postgres_enabled=$2,redis_buffer_enabled=$3,
		redis_buffer_ttl_hours=$4,kafka_enabled=$5,kafka_retention_hours=$6,store_raw_prompt=false,updated_at=now() WHERE singleton=true`,
		p.RetentionDays,p.PostgresEnabled,p.RedisBufferEnabled,p.RedisBufferTTLHours,p.KafkaEnabled,p.KafkaRetentionHours)
	if err!=nil{return core.StoragePolicy{},err};return s.GetStoragePolicy(ctx)
}

func (s *Store) InsertTraceBatch(ctx context.Context,traces []core.Trace,kafkaEnabled bool,topic string)error{
	if len(traces)==0{return nil}
	tx,err:=s.pool.Begin(ctx);if err!=nil{return err};defer func(){_ = tx.Rollback(context.Background())}()
	rows:=make([][]interface{},0,len(traces))
	for _,t:=range traces{
		var routeID interface{};if t.RouteID!=nil&&*t.RouteID!=""{routeID=*t.RouteID}
		created:=t.CreatedAt;if created.IsZero(){created=time.Now().UTC()}
		rows=append(rows,[]interface{}{t.ID,t.ExternalRequestID,t.ParentRequestID,routeID,t.RouteSlug,t.TenantID,t.UserIDHash,
			t.APIKeyHash,t.Model,t.Provider,t.Method,t.Path,t.RequestBytes,t.ResponseBytes,t.HTTPStatus,t.NormalizedCode,t.Outcome,
			t.RiskCategory,t.RiskScore,t.RiskReasonCode,t.PromptHash,t.AuditLatencyMS,t.UpstreamLatencyMS,t.TotalLatencyMS,t.Stream,
			t.ClientIPHash,t.UserAgentHash,t.Metadata,created})
	}
	cols:=[]string{"id","external_request_id","parent_request_id","route_id","route_slug","tenant_id","user_id_hash","api_key_hash",
		"model","provider","method","path","request_bytes","response_bytes","http_status","normalized_code","outcome","risk_category",
		"risk_score","risk_reason_code","prompt_hash","audit_latency_ms","upstream_latency_ms","total_latency_ms","stream","client_ip_hash",
		"user_agent_hash","metadata","created_at"}
	if _,err=tx.CopyFrom(ctx,pgx.Identifier{"request_traces"},cols,pgx.CopyFromRows(rows));err!=nil{return err}
	if kafkaEnabled{
		batch:=&pgx.Batch{}
		for _,t:=range traces{
			payload,_:=json.Marshal(t)
			batch.Queue(`INSERT INTO event_outbox(topic,event_key,payload,headers) VALUES($1,$2,$3,$4)`,topic,t.ID,payload,json.RawMessage(`{"schema":"riskgate.trace.v1"}`))
		}
		br:=tx.SendBatch(ctx,batch)
		for range traces{if _,err=br.Exec();err!=nil{_ = br.Close();return err}}
		if err=br.Close();err!=nil{return err}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListTraces(ctx context.Context,f TraceFilter)([]core.Trace,error){
	where:=[]string{"1=1"};args:=[]interface{}{}
	add:=func(clause string,v interface{}){args=append(args,v);where=append(where,fmt.Sprintf(clause,len(args)))}
	if f.RequestID!=""{add("(external_request_id=$%d OR id::text=$%d)",f.RequestID)}
	if f.RouteSlug!=""{add("route_slug=$%d",f.RouteSlug)}
	if f.Outcome!=""{add("outcome=$%d",f.Outcome)}
	if f.Model!=""{add("model=$%d",f.Model)}
	if !f.From.IsZero(){add("created_at >= $%d",f.From)}
	if !f.To.IsZero(){add("created_at <= $%d",f.To)}
	limit:=f.Limit;if limit<1||limit>1000{limit=100};offset:=f.Offset;if offset<0{offset=0}
	args=append(args,limit,offset)
	q:=`SELECT id::text,external_request_id,parent_request_id,COALESCE(route_id::text,''),route_slug,tenant_id,user_id_hash,
		api_key_hash,model,provider,method,path,request_bytes,response_bytes,http_status,normalized_code,outcome,risk_category,risk_score,
		risk_reason_code,prompt_hash,audit_latency_ms,upstream_latency_ms,total_latency_ms,stream,client_ip_hash,user_agent_hash,metadata,created_at
		FROM request_traces WHERE `+strings.Join(where," AND ")+fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,len(args)-1,len(args))
	rows,err:=s.pool.Query(ctx,q,args...);if err!=nil{return nil,err};defer rows.Close()
	var out []core.Trace
	for rows.Next(){var t core.Trace;var routeID string;var meta []byte
		if err:=rows.Scan(&t.ID,&t.ExternalRequestID,&t.ParentRequestID,&routeID,&t.RouteSlug,&t.TenantID,&t.UserIDHash,&t.APIKeyHash,
			&t.Model,&t.Provider,&t.Method,&t.Path,&t.RequestBytes,&t.ResponseBytes,&t.HTTPStatus,&t.NormalizedCode,&t.Outcome,
			&t.RiskCategory,&t.RiskScore,&t.RiskReasonCode,&t.PromptHash,&t.AuditLatencyMS,&t.UpstreamLatencyMS,&t.TotalLatencyMS,
			&t.Stream,&t.ClientIPHash,&t.UserAgentHash,&meta,&t.CreatedAt);err!=nil{return nil,err}
		if routeID!=""{t.RouteID=&routeID};t.Metadata=json.RawMessage(meta);out=append(out,t)}
	return out,rows.Err()
}

func (s *Store) LeaseOutbox(ctx context.Context,owner string,limit int,lease time.Duration)([]OutboxEvent,error){
	if limit<1{limit=100}
	rows,err:=s.pool.Query(ctx,`WITH selected AS (
		SELECT id FROM event_outbox WHERE (status='pending' AND available_at<=now()) OR (status='leased' AND lease_until<now())
		ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT $1)
		UPDATE event_outbox e SET status='leased',lease_owner=$2,lease_until=now()+$3::interval,attempts=attempts+1
		FROM selected WHERE e.id=selected.id
		RETURNING e.id::text,e.topic,e.event_key,e.payload,e.headers,e.attempts`,limit,owner,lease.String())
	if err!=nil{return nil,err};defer rows.Close();var out []OutboxEvent
	for rows.Next(){var e OutboxEvent;var headersJSON []byte;if err:=rows.Scan(&e.ID,&e.Topic,&e.Key,&e.Payload,&headersJSON,&e.Attempts);err!=nil{return nil,err};_ = json.Unmarshal(headersJSON,&e.Headers);out=append(out,e)}
	return out,rows.Err()
}
func (s *Store) MarkOutboxPublished(ctx context.Context,id,owner string)error{_,err:=s.pool.Exec(ctx,`UPDATE event_outbox SET status='published',published_at=now(),lease_owner='',lease_until=NULL WHERE id=$1 AND lease_owner=$2`,id,owner);return err}
func (s *Store) MarkOutboxFailed(ctx context.Context,id,owner,msg string,attempts int)error{
	if len(msg)>2000{msg=msg[:2000]};delay:=time.Duration(1<<min(attempts,10))*time.Second;status:="pending";if attempts>=20{status="dead"}
	_,err:=s.pool.Exec(ctx,`UPDATE event_outbox SET status=$3,last_error=$4,available_at=now()+$5::interval,lease_owner='',lease_until=NULL WHERE id=$1 AND lease_owner=$2`,id,owner,status,msg,delay.String());return err
}

func (s *Store) WriteAdminAudit(ctx context.Context,actorID,username,role,action,resourceType,resourceID,requestID,clientIPHash string,before,after interface{})error{
	var b,a interface{}
	if before!=nil{raw,_:=json.Marshal(before);b=raw};if after!=nil{raw,_:=json.Marshal(after);a=raw}
	_,err:=s.pool.Exec(ctx,`INSERT INTO admin_audit_logs(actor_id,actor_username,actor_role,action,resource_type,resource_id,request_id,client_ip_hash,before_value,after_value)
		VALUES(NULLIF($1,'')::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,actorID,username,role,action,resourceType,resourceID,requestID,clientIPHash,b,a)
	return err
}

func (s *Store) Stats(ctx context.Context)(RuntimeStats,error){
	var st RuntimeStats
	queries:=[]struct{q string;dest *int64}{
		{`SELECT count(*) FROM routes WHERE enabled`,&st.RoutesEnabled},
		{`SELECT count(*) FROM risk_rules WHERE enabled`,&st.RulesEnabled},
		{`SELECT count(*) FROM request_traces WHERE created_at>=now()-interval '1 hour'`,&st.TracesLastHour},
		{`SELECT count(*) FROM request_traces WHERE created_at>=now()-interval '1 hour' AND normalized_code=555`,&st.BlockedLastHour},
		{`SELECT count(*) FROM event_outbox WHERE status IN ('pending','leased')`,&st.OutboxPending},
		{`SELECT count(*) FROM event_outbox WHERE status='dead'`,&st.OutboxDead},
		{`SELECT count(*) FROM request_traces_default`,&st.DefaultPartition},
	}
	for _,item:=range queries{if err:=s.pool.QueryRow(ctx,item.q).Scan(item.dest);err!=nil{return RuntimeStats{},err}}
	return st,nil
}

func (s *Store) SeedBuiltinRules(ctx context.Context,rules []core.RiskRule)error{
	sort.SliceStable(rules,func(i,j int)bool{return rules[i].Priority>rules[j].Priority})
	batch:=&pgx.Batch{}
	for _,r:=range rules{batch.Queue(`INSERT INTO risk_rules(name,category,pattern,action,score,priority,enabled,builtin)
		VALUES($1,$2,$3,$4,$5,$6,true,true) ON CONFLICT(name) DO UPDATE SET category=EXCLUDED.category,pattern=EXCLUDED.pattern,
		action=EXCLUDED.action,score=EXCLUDED.score,priority=EXCLUDED.priority,builtin=true,updated_at=now()`,r.Name,r.Category,r.Pattern,r.Action,r.Score,r.Priority)}
	br:=s.pool.SendBatch(ctx,batch);defer br.Close();for range rules{if _,err:=br.Exec();err!=nil{return err}};return br.Close()
}

func ParseLimit(raw string, fallback int) int { n,err:=strconv.Atoi(raw);if err!=nil{return fallback};return n }
func min(a,b int)int{if a<b{return a};return b}
