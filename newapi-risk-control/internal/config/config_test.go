package config

import (
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{
		AppEnv: "development", DatabaseURL: "postgres://example",
		DBMaxConns: 20, DBMinConns: 2, DefaultRetentionDays: 7,
		MaxRequestBytes: 8 << 20, MaxResponseBytes: 32 << 20,
		MaxSSEFrameBytes: 1 << 20, StreamGateBytes: 64 << 10,
		TraceWorkers: 4, OutboxWorkers: 2,
		MasterEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		BootstrapAdminRole: "admin", BootstrapAdminPassword: strings.Repeat("p", 40),
		AdminJWTSecret: strings.Repeat("j", 40), TraceHMACSecret: strings.Repeat("t", 40),
		PromptHashSecret: strings.Repeat("h", 40), FailClosed: true,
		KafkaTopic: "riskgate.audit.events.v1", KafkaRetentionHours: 720,
	}
}

func TestDevelopmentConfiguration(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionRejectsWeakSecrets(t *testing.T) {
	cfg := validConfig()
	cfg.AppEnv = "production"
	cfg.AdminJWTSecret = "change-me"
	if err := cfg.Validate(); err == nil {
		t.Fatal("production accepted a weak JWT secret")
	}
}

func TestProductionRejectsFailOpenProcessMode(t *testing.T) {
	cfg := validConfig()
	cfg.AppEnv = "production"
	cfg.FailClosed = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("production accepted FAIL_CLOSED=false")
	}
}

func TestKafkaSASLRequiresCredentials(t *testing.T) {
	cfg := validConfig()
	cfg.KafkaBrokers = []string{"kafka:9092"}
	cfg.KafkaSASLMechanism = "scram-sha-512"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Kafka SASL was enabled without credentials")
	}
}
