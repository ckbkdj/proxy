package platform

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment                  string
	HTTPAddr                     string
	DatabaseURL                  string
	PostgresMaxConns             int32
	PostgresMinConns             int32
	RedisURL                     string
	RedisStreamMaxLen            int64
	KafkaEnabled                 bool
	KafkaBrokers                 []string
	KafkaTopic                   string
	KafkaClientID                string
	KafkaTLS                     bool
	KafkaSASLMechanism           string
	KafkaUsername                string
	KafkaPassword                string
	KafkaQueueSize               int
	KafkaTopicPartitions         int
	KafkaTopicReplicationFactor  int
	MasterKey                    []byte
	JWTSecret                    []byte
	JWTIssuer                    string
	JWTTTL                       time.Duration
	BootstrapAdminUsername       string
	BootstrapAdminPassword       string
	BootstrapTrackingKeyID       string
	BootstrapTrackingSecret      string
	DefaultAuditEndpoint         string
	DefaultAuditModel            string
	DefaultAuditAPIKey           string
	DefaultAuditTimeout          time.Duration
	DefaultAuditBlockThreshold   float64
	RetentionDays                int
	ErrorHTTPStatus              int
	RequestMaxBytes              int64
	ResponseInspectMaxBytes      int64
	AuditTextMaxBytes            int
	SSELineMaxBytes              int
	TraceQueueSize               int
	TraceBatchSize               int
	TraceFlushInterval           time.Duration
	AllowPrivateUpstreams        bool
	UpstreamTLSMinVersion        uint16
	GlobalMaxConcurrency         int
	TrackingClockSkew            time.Duration
	TrackingNonceTTL             time.Duration
	RouteCacheTTL                time.Duration
	RulesRefreshInterval         time.Duration
	PartitionMaintenanceInterval time.Duration
	ShutdownTimeout              time.Duration
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Environment:                  envString("APP_ENV", "production"),
		HTTPAddr:                     envString("HTTP_ADDR", ":8080"),
		DatabaseURL:                  strings.TrimSpace(os.Getenv("DATABASE_URL")),
		PostgresMaxConns:             int32(envInt("POSTGRES_MAX_CONNS", 80)),
		PostgresMinConns:             int32(envInt("POSTGRES_MIN_CONNS", 5)),
		RedisURL:                     strings.TrimSpace(os.Getenv("REDIS_URL")),
		RedisStreamMaxLen:            int64(envInt("REDIS_STREAM_MAXLEN", 100000)),
		KafkaEnabled:                 envBool("KAFKA_ENABLED", false),
		KafkaBrokers:                 splitCSV(os.Getenv("KAFKA_BROKERS")),
		KafkaTopic:                   envString("KAFKA_TOPIC", "risk.request.events.v1"),
		KafkaClientID:                envString("KAFKA_CLIENT_ID", "newapi-risk-platform"),
		KafkaTLS:                     envBool("KAFKA_TLS", false),
		KafkaSASLMechanism:           strings.ToLower(envString("KAFKA_SASL_MECHANISM", "")),
		KafkaUsername:                os.Getenv("KAFKA_USERNAME"),
		KafkaPassword:                os.Getenv("KAFKA_PASSWORD"),
		KafkaQueueSize:               envInt("KAFKA_QUEUE_SIZE", 8192),
		KafkaTopicPartitions:         envInt("KAFKA_TOPIC_PARTITIONS", 12),
		KafkaTopicReplicationFactor:  envInt("KAFKA_TOPIC_REPLICATION_FACTOR", 1),
		JWTIssuer:                    envString("JWT_ISSUER", "newapi-risk-platform"),
		JWTTTL:                       envDuration("JWT_TTL", 8*time.Hour),
		BootstrapAdminUsername:       envString("BOOTSTRAP_ADMIN_USERNAME", "admin"),
		BootstrapAdminPassword:       os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),
		BootstrapTrackingKeyID:       envString("BOOTSTRAP_TRACKING_KEY_ID", "newapi-default"),
		BootstrapTrackingSecret:      os.Getenv("BOOTSTRAP_TRACKING_SECRET"),
		DefaultAuditEndpoint:         strings.TrimRight(strings.TrimSpace(os.Getenv("AUDIT_DEFAULT_ENDPOINT")), "/"),
		DefaultAuditModel:            envString("AUDIT_DEFAULT_MODEL", "audit-small"),
		DefaultAuditAPIKey:           os.Getenv("AUDIT_DEFAULT_API_KEY"),
		DefaultAuditTimeout:          envDuration("AUDIT_DEFAULT_TIMEOUT", 8*time.Second),
		DefaultAuditBlockThreshold:   envFloat("AUDIT_DEFAULT_BLOCK_THRESHOLD", 0.65),
		RetentionDays:                envInt("POSTGRES_RETENTION_DAYS", 7),
		ErrorHTTPStatus:              envInt("ERROR_HTTP_STATUS", 555),
		RequestMaxBytes:              int64(envInt("REQUEST_MAX_BYTES", 8*1024*1024)),
		ResponseInspectMaxBytes:      int64(envInt("RESPONSE_INSPECT_MAX_BYTES", 2*1024*1024)),
		AuditTextMaxBytes:            envInt("AUDIT_TEXT_MAX_BYTES", 256*1024),
		SSELineMaxBytes:              envInt("SSE_LINE_MAX_BYTES", 1024*1024),
		TraceQueueSize:               envInt("TRACE_QUEUE_SIZE", 32768),
		TraceBatchSize:               envInt("TRACE_BATCH_SIZE", 256),
		TraceFlushInterval:           envDuration("TRACE_FLUSH_INTERVAL", 250*time.Millisecond),
		AllowPrivateUpstreams:        envBool("ALLOW_PRIVATE_UPSTREAMS", false),
		GlobalMaxConcurrency:         envInt("GLOBAL_MAX_CONCURRENCY", 4096),
		TrackingClockSkew:            envDuration("TRACKING_CLOCK_SKEW", 5*time.Minute),
		TrackingNonceTTL:             envDuration("TRACKING_NONCE_TTL", 10*time.Minute),
		RouteCacheTTL:                envDuration("ROUTE_CACHE_TTL", 10*time.Second),
		RulesRefreshInterval:         envDuration("RULES_REFRESH_INTERVAL", 15*time.Second),
		PartitionMaintenanceInterval: envDuration("PARTITION_MAINTENANCE_INTERVAL", time.Hour),
		ShutdownTimeout:              envDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
	}
	master, err := decodeSecret32("MASTER_KEY_B64", os.Getenv("MASTER_KEY_B64"))
	if err != nil {
		return Config{}, err
	}
	cfg.MasterKey = master
	cfg.JWTSecret = []byte(os.Getenv("JWT_SECRET"))
	if envString("UPSTREAM_TLS_MIN_VERSION", "1.2") == "1.3" {
		cfg.UpstreamTLSMinVersion = tls.VersionTLS13
	} else {
		cfg.UpstreamTLSMinVersion = tls.VersionTLS12
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	var problems []string
	if c.DatabaseURL == "" {
		problems = append(problems, "DATABASE_URL is required")
	}
	if len(c.MasterKey) != 32 {
		problems = append(problems, "MASTER_KEY_B64 must decode to exactly 32 bytes")
	}
	if len(c.JWTSecret) < 32 {
		problems = append(problems, "JWT_SECRET must contain at least 32 bytes")
	}
	if c.BootstrapAdminUsername == "" || len(c.BootstrapAdminPassword) < 14 {
		problems = append(problems, "bootstrap administrator username and a password of at least 14 characters are required")
	}
	if c.RetentionDays < 1 || c.RetentionDays > 365 {
		problems = append(problems, "POSTGRES_RETENTION_DAYS must be between 1 and 365")
	}
	if c.ErrorHTTPStatus < 400 || c.ErrorHTTPStatus > 599 {
		problems = append(problems, "ERROR_HTTP_STATUS must be between 400 and 599")
	}
	if c.PostgresMaxConns < 2 || c.PostgresMaxConns > 1000 || c.PostgresMinConns < 0 || c.PostgresMinConns > c.PostgresMaxConns {
		problems = append(problems, "PostgreSQL connection pool settings are invalid")
	}
	if c.RequestMaxBytes < 1024 || c.RequestMaxBytes > 64*1024*1024 {
		problems = append(problems, "REQUEST_MAX_BYTES must be between 1 KiB and 64 MiB")
	}
	if c.ResponseInspectMaxBytes < 64*1024 || c.ResponseInspectMaxBytes > 16*1024*1024 {
		problems = append(problems, "RESPONSE_INSPECT_MAX_BYTES must be between 64 KiB and 16 MiB")
	}
	if c.AuditTextMaxBytes < 4096 || c.AuditTextMaxBytes > 2*1024*1024 {
		problems = append(problems, "AUDIT_TEXT_MAX_BYTES must be between 4 KiB and 2 MiB")
	}
	if c.SSELineMaxBytes < 64*1024 || c.SSELineMaxBytes > 8*1024*1024 {
		problems = append(problems, "SSE_LINE_MAX_BYTES must be between 64 KiB and 8 MiB")
	}
	if c.TraceQueueSize < 100 || c.TraceQueueSize > 1000000 || c.TraceBatchSize < 1 || c.TraceBatchSize > 5000 {
		problems = append(problems, "trace queue or batch settings are invalid")
	}
	if c.GlobalMaxConcurrency < 1 || c.GlobalMaxConcurrency > 100000 {
		problems = append(problems, "GLOBAL_MAX_CONCURRENCY must be between 1 and 100000")
	}
	if c.DefaultAuditBlockThreshold < 0 || c.DefaultAuditBlockThreshold > 1 {
		problems = append(problems, "AUDIT_DEFAULT_BLOCK_THRESHOLD must be between 0 and 1")
	}
	if c.KafkaEnabled {
		if len(c.KafkaBrokers) == 0 || c.KafkaTopic == "" {
			problems = append(problems, "Kafka brokers and topic are required when Kafka is enabled")
		}
		if c.KafkaSASLMechanism != "" && c.KafkaSASLMechanism != "plain" && c.KafkaSASLMechanism != "scram-sha-256" && c.KafkaSASLMechanism != "scram-sha-512" {
			problems = append(problems, "KAFKA_SASL_MECHANISM is invalid")
		}
		if c.KafkaSASLMechanism != "" && (c.KafkaUsername == "" || c.KafkaPassword == "") {
			problems = append(problems, "Kafka username and password are required when SASL is enabled")
		}
		if c.KafkaTopicPartitions < 1 || c.KafkaTopicPartitions > 10000 || c.KafkaTopicReplicationFactor < 1 || c.KafkaTopicReplicationFactor > 20 {
			problems = append(problems, "Kafka topic partition or replication settings are invalid")
		}
	}
	if strings.EqualFold(c.Environment, "production") && c.AllowPrivateUpstreams && !envBool("ACK_PRIVATE_UPSTREAM_SSRF_RISK", false) {
		problems = append(problems, "ACK_PRIVATE_UPSTREAM_SSRF_RISK=true is required with private upstreams in production")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func decodeSecret32(name, value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("%s must be base64 for exactly 32 bytes", name)
	}
	return decoded, nil
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
func envFloat(name string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}
