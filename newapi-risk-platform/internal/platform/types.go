package platform

import (
	"encoding/json"
	"time"
)

const (
	DecisionAllow  = "allow"
	DecisionBlock  = "block"
	DecisionReview = "review"
)

type Route struct {
	ID                       int64      `json:"id"`
	Slug                     string     `json:"slug"`
	Name                     string     `json:"name"`
	BaseURL                  string     `json:"base_url"`
	Provider                 string     `json:"provider"`
	AuthMode                 string     `json:"auth_mode"`
	SecretHeader             string     `json:"secret_header,omitempty"`
	AuditProfileID           *int64     `json:"audit_profile_id,omitempty"`
	Enabled                  bool       `json:"enabled"`
	FailClosed               bool       `json:"fail_closed"`
	RequestTimeoutMS         int        `json:"request_timeout_ms"`
	MaxConcurrency           int        `json:"max_concurrency"`
	RateLimitRPS             float64    `json:"rate_limit_rps"`
	RateLimitBurst           int        `json:"rate_limit_burst"`
	UpstreamSecretCiphertext []byte     `json:"-"`
	InboundKeyDigest         string     `json:"-"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	DeletedAt                *time.Time `json:"-"`
}

type RouteInput struct {
	ID               int64   `json:"id"`
	Slug             string  `json:"slug"`
	Name             string  `json:"name"`
	BaseURL          string  `json:"base_url"`
	Provider         string  `json:"provider"`
	AuthMode         string  `json:"auth_mode"`
	SecretHeader     string  `json:"secret_header"`
	UpstreamSecret   string  `json:"upstream_secret"`
	InboundKey       string  `json:"inbound_key"`
	AuditProfileID   *int64  `json:"audit_profile_id"`
	Enabled          bool    `json:"enabled"`
	FailClosed       bool    `json:"fail_closed"`
	RequestTimeoutMS int     `json:"request_timeout_ms"`
	MaxConcurrency   int     `json:"max_concurrency"`
	RateLimitRPS     float64 `json:"rate_limit_rps"`
	RateLimitBurst   int     `json:"rate_limit_burst"`
}

type AuditProfile struct {
	ID               int64           `json:"id"`
	Name             string          `json:"name"`
	Endpoint         string          `json:"endpoint"`
	Model            string          `json:"model"`
	SystemPrompt     string          `json:"system_prompt"`
	TimeoutMS        int             `json:"timeout_ms"`
	BlockThreshold   float64         `json:"block_threshold"`
	Enabled          bool            `json:"enabled"`
	FailClosed       bool            `json:"fail_closed"`
	IsDefault        bool            `json:"is_default"`
	Extra            json.RawMessage `json:"extra,omitempty"`
	APIKeyCiphertext []byte          `json:"-"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

type AuditProfileInput struct {
	ID             int64           `json:"id"`
	Name           string          `json:"name"`
	Endpoint       string          `json:"endpoint"`
	Model          string          `json:"model"`
	APIKey         string          `json:"api_key"`
	SystemPrompt   string          `json:"system_prompt"`
	TimeoutMS      int             `json:"timeout_ms"`
	BlockThreshold float64         `json:"block_threshold"`
	Enabled        bool            `json:"enabled"`
	FailClosed     bool            `json:"fail_closed"`
	IsDefault      bool            `json:"is_default"`
	Extra          json.RawMessage `json:"extra"`
}

type CyberRule struct {
	ID          int64     `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Pattern     string    `json:"pattern"`
	PatternType string    `json:"pattern_type"`
	Action      string    `json:"action"`
	Priority    int       `json:"priority"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AuditDecision struct {
	Decision   string  `json:"decision"`
	RiskCode   string  `json:"risk_code,omitempty"`
	Category   string  `json:"category,omitempty"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason,omitempty"`
	Source     string  `json:"source"`
	RuleID     int64   `json:"rule_id,omitempty"`
}

type AuditResult struct {
	AuditDecision
	PromptHMAC string        `json:"prompt_hmac"`
	TextBytes  int           `json:"text_bytes"`
	Latency    time.Duration `json:"-"`
	Model      string        `json:"model,omitempty"`
}

type TraceEvent struct {
	RequestID       string         `json:"request_id"`
	ExternalEventID string         `json:"external_event_id,omitempty"`
	Source          string         `json:"source"`
	RouteSlug       string         `json:"route_slug,omitempty"`
	NewAPIRequestID string         `json:"newapi_request_id,omitempty"`
	ExternalUserID  string         `json:"external_user_id,omitempty"`
	Model           string         `json:"model,omitempty"`
	Endpoint        string         `json:"endpoint,omitempty"`
	Decision        string         `json:"decision"`
	RiskCode        string         `json:"risk_code,omitempty"`
	HTTPStatus      int            `json:"http_status"`
	UpstreamStatus  int            `json:"upstream_status,omitempty"`
	LatencyMS       int64          `json:"latency_ms"`
	AuditLatencyMS  int64          `json:"audit_latency_ms"`
	RequestBytes    int64          `json:"request_bytes"`
	ResponseBytes   int64          `json:"response_bytes"`
	PromptHMAC      string         `json:"prompt_hmac,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

type TrackingEvent struct {
	EventID         string         `json:"event_id"`
	RequestID       string         `json:"request_id"`
	RouteSlug       string         `json:"route_slug"`
	NewAPIRequestID string         `json:"newapi_request_id"`
	ExternalUserID  string         `json:"external_user_id"`
	Model           string         `json:"model"`
	Endpoint        string         `json:"endpoint"`
	Decision        string         `json:"decision"`
	RiskCode        string         `json:"risk_code"`
	HTTPStatus      int            `json:"http_status"`
	UpstreamStatus  int            `json:"upstream_status"`
	LatencyMS       int64          `json:"latency_ms"`
	AuditLatencyMS  int64          `json:"audit_latency_ms"`
	RequestBytes    int64          `json:"request_bytes"`
	ResponseBytes   int64          `json:"response_bytes"`
	PromptHMAC      string         `json:"prompt_hmac"`
	OccurredAt      time.Time      `json:"occurred_at"`
	Metadata        map[string]any `json:"metadata"`
}

type TrackingEnvelope struct {
	Events []TrackingEvent `json:"events"`
}

type AdminUser struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type TrackingClient struct {
	ID               int64     `json:"id"`
	KeyID            string    `json:"key_id"`
	Name             string    `json:"name"`
	SecretCiphertext []byte    `json:"-"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type DashboardStats struct {
	WindowHours      int64            `json:"window_hours"`
	TotalRequests    int64            `json:"total_requests"`
	AllowedRequests  int64            `json:"allowed_requests"`
	BlockedRequests  int64            `json:"blocked_requests"`
	ErrorRequests    int64            `json:"error_requests"`
	P95LatencyMS     float64          `json:"p95_latency_ms"`
	BlockRate        float64          `json:"block_rate"`
	ByRiskCode       map[string]int64 `json:"by_risk_code"`
	ByRoute          map[string]int64 `json:"by_route"`
	TraceQueueDepth  int              `json:"trace_queue_depth"`
	KafkaQueueDepth  int              `json:"kafka_queue_depth"`
	RedisAvailable   bool             `json:"redis_available"`
	KafkaEnabled     bool             `json:"kafka_enabled"`
	PostgresHealthy  bool             `json:"postgres_healthy"`
	ConfiguredRoutes int64            `json:"configured_routes"`
}

type TraceFilter struct {
	RouteSlug string
	Decision  string
	RiskCode  string
	UserID    string
	From      time.Time
	To        time.Time
	Limit     int
}

type OutboxEvent struct {
	ID       int64
	Topic    string
	Key      string
	Payload  []byte
	Attempts int
}
