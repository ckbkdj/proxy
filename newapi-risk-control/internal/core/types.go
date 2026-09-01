package core

import (
	"encoding/json"
	"time"
)

type Route struct {
	ID                    string          `json:"id"`
	Slug                  string          `json:"slug"`
	Name                  string          `json:"name"`
	UpstreamBaseURL       string          `json:"upstream_base_url"`
	UpstreamKind          string          `json:"upstream_kind"`
	UpstreamAPIKeyCipher  string          `json:"-"`
	ClientTokenHash       string          `json:"-"`
	AuditProfileID        *string         `json:"audit_profile_id,omitempty"`
	Enabled               bool            `json:"enabled"`
	RateLimitRPS          float64         `json:"rate_limit_rps"`
	RateLimitBurst        int             `json:"rate_limit_burst"`
	MaxInflight           int             `json:"max_inflight"`
	RequestTimeoutMS      int             `json:"request_timeout_ms"`
	AllowPrivateUpstream  bool            `json:"allow_private_upstream"`
	UpstreamErrorPolicy   json.RawMessage `json:"upstream_error_policy"`
	ExtraHeadersEncrypted string          `json:"-"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

type RouteWrite struct {
	ID                   string            `json:"id,omitempty"`
	Slug                 string            `json:"slug"`
	Name                 string            `json:"name"`
	UpstreamBaseURL      string            `json:"upstream_base_url"`
	UpstreamKind         string            `json:"upstream_kind"`
	UpstreamAPIKey       string            `json:"upstream_api_key,omitempty"`
	ClientToken          string            `json:"client_token,omitempty"`
	AuditProfileID       *string           `json:"audit_profile_id,omitempty"`
	Enabled              bool              `json:"enabled"`
	RateLimitRPS         float64           `json:"rate_limit_rps"`
	RateLimitBurst       int               `json:"rate_limit_burst"`
	MaxInflight          int               `json:"max_inflight"`
	RequestTimeoutMS     int               `json:"request_timeout_ms"`
	AllowPrivateUpstream bool               `json:"allow_private_upstream"`
	UpstreamErrorPolicy  json.RawMessage   `json:"upstream_error_policy,omitempty"`
	ExtraHeaders         map[string]string `json:"extra_headers,omitempty"`
}

type AuditProfile struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Endpoint             string    `json:"endpoint"`
	Model                string    `json:"model"`
	APIKeyCipher         string    `json:"-"`
	Enabled              bool      `json:"enabled"`
	FailMode             string    `json:"fail_mode"`
	BlockThreshold       float64   `json:"block_threshold"`
	TimeoutMS            int       `json:"timeout_ms"`
	MaxInputChars        int       `json:"max_input_chars"`
	CacheTTLSeconds      int       `json:"cache_ttl_seconds"`
	SystemPrompt         string    `json:"system_prompt"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type AuditProfileWrite struct {
	ID              string  `json:"id,omitempty"`
	Name            string  `json:"name"`
	Endpoint        string  `json:"endpoint"`
	Model           string  `json:"model"`
	APIKey          string  `json:"api_key,omitempty"`
	Enabled         bool    `json:"enabled"`
	FailMode        string  `json:"fail_mode"`
	BlockThreshold  float64 `json:"block_threshold"`
	TimeoutMS       int     `json:"timeout_ms"`
	MaxInputChars   int     `json:"max_input_chars"`
	CacheTTLSeconds int     `json:"cache_ttl_seconds"`
	SystemPrompt    string  `json:"system_prompt"`
}

type RiskRule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Category  string    `json:"category"`
	Pattern   string    `json:"pattern"`
	Action    string    `json:"action"`
	Score     float64   `json:"score"`
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Decision struct {
	Allowed       bool     `json:"allowed"`
	Action        string   `json:"action"`
	Category      string   `json:"category"`
	Score         float64  `json:"score"`
	ReasonCode    string   `json:"reason_code"`
	RuleID        string   `json:"rule_id,omitempty"`
	Model         string   `json:"model,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	Degraded      bool     `json:"degraded"`
	AuditLatency  int64    `json:"audit_latency_ms"`
	SafeSummary   string   `json:"safe_summary,omitempty"`
}

type Trace struct {
	ID                    string          `json:"id"`
	ExternalRequestID     string          `json:"external_request_id,omitempty"`
	ParentRequestID       string          `json:"parent_request_id,omitempty"`
	RouteID               *string         `json:"route_id,omitempty"`
	RouteSlug             string          `json:"route_slug,omitempty"`
	TenantID              string          `json:"tenant_id,omitempty"`
	UserIDHash            string          `json:"user_id_hash,omitempty"`
	APIKeyHash            string          `json:"api_key_hash,omitempty"`
	Model                 string          `json:"model,omitempty"`
	Provider              string          `json:"provider,omitempty"`
	Method                string          `json:"method"`
	Path                  string          `json:"path"`
	RequestBytes          int64           `json:"request_bytes"`
	ResponseBytes         int64           `json:"response_bytes"`
	HTTPStatus            int             `json:"http_status"`
	NormalizedCode        int             `json:"normalized_code"`
	Outcome               string          `json:"outcome"`
	RiskCategory          string          `json:"risk_category,omitempty"`
	RiskScore             float64         `json:"risk_score"`
	RiskReasonCode        string          `json:"risk_reason_code,omitempty"`
	PromptHash            string          `json:"prompt_hash,omitempty"`
	AuditLatencyMS        int64           `json:"audit_latency_ms"`
	UpstreamLatencyMS     int64           `json:"upstream_latency_ms"`
	TotalLatencyMS        int64           `json:"total_latency_ms"`
	Stream                bool            `json:"stream"`
	ClientIPHash          string          `json:"client_ip_hash,omitempty"`
	UserAgentHash         string          `json:"user_agent_hash,omitempty"`
	Metadata              json.RawMessage `json:"metadata,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
}

type TraceIngest struct {
	ExternalRequestID string                 `json:"external_request_id"`
	ParentRequestID   string                 `json:"parent_request_id,omitempty"`
	RouteSlug         string                 `json:"route_slug,omitempty"`
	TenantID          string                 `json:"tenant_id,omitempty"`
	UserID            string                 `json:"user_id,omitempty"`
	APIKeyFingerprint string                 `json:"api_key_fingerprint,omitempty"`
	Model             string                 `json:"model,omitempty"`
	Provider          string                 `json:"provider,omitempty"`
	Method            string                 `json:"method,omitempty"`
	Path              string                 `json:"path,omitempty"`
	HTTPStatus        int                    `json:"http_status,omitempty"`
	Outcome           string                 `json:"outcome,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	OccurredAt        *time.Time             `json:"occurred_at,omitempty"`
}

type StoragePolicy struct {
	RetentionDays       int       `json:"retention_days"`
	PostgresEnabled     bool      `json:"postgres_enabled"`
	RedisBufferEnabled  bool      `json:"redis_buffer_enabled"`
	RedisBufferTTLHours int       `json:"redis_buffer_ttl_hours"`
	KafkaEnabled        bool      `json:"kafka_enabled"`
	KafkaRetentionHours int       `json:"kafka_retention_hours"`
	StoreRawPrompt      bool      `json:"store_raw_prompt"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type AdminUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type UpstreamErrorPolicy struct {
	NormalizeStatuses []int    `json:"normalize_statuses"`
	NormalizeCodes    []string `json:"normalize_codes"`
	MessagePatterns   []string `json:"message_patterns"`
	PassStatuses      []int    `json:"pass_statuses"`
}

func DefaultUpstreamErrorPolicy() UpstreamErrorPolicy {
	return UpstreamErrorPolicy{
		NormalizeStatuses: []int{401, 403, 404, 408, 409, 429, 500, 502, 503, 504},
		NormalizeCodes: []string{
			"model_not_found", "insufficient_quota", "rate_limit_exceeded", "overloaded_error",
			"authentication_error", "permission_error", "upstream_unavailable",
		},
		MessagePatterns: []string{
			`(?i)model.{0,24}(not found|unavailable|overloaded)`,
			`(?i)(quota|rate limit|capacity|temporarily unavailable|upstream timeout)`,
		},
		PassStatuses: []int{400, 422},
	}
}
