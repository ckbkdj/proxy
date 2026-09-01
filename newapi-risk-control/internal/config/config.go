package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv                  string
	ListenAddr              string
	PublicBaseURL           string
	DatabaseURL             string
	DBMaxConns              int32
	DBMinConns              int32
	DBConnectTimeout        time.Duration
	RedisURL                string
	RedisRequired           bool
	RedisPrefix             string
	AdminJWTSecret          string
	TraceHMACSecret         string
	MasterEncryptionKey     []byte
	PromptHashSecret        string
	BootstrapAdminUsername  string
	BootstrapAdminPassword  string
	BootstrapAdminRole      string
	DefaultRetentionDays    int
	MaxRequestBytes         int64
	MaxResponseBytes        int64
	MaxSSEFrameBytes        int
	StreamGateBytes         int
	StreamGateTimeout       time.Duration
	UpstreamHeaderTimeout   time.Duration
	UpstreamIdleTimeout     time.Duration
	AuditDefaultTimeout     time.Duration
	AuditMaxTextBytes       int
	AuditCacheTTL           time.Duration
	TraceQueueSize          int
	TraceWorkers            int
	OutboxWorkers           int
	FailClosed              bool
	AllowPrivateUpstreams   bool
	TrustProxyHeaders       bool
	KafkaBrokers            []string
	KafkaTopic              string
	KafkaClientID           string
	KafkaTLS                bool
	KafkaSASLMechanism      string
	KafkaSASLUsername       string
	KafkaSASLPassword       string
	KafkaRetentionHours     int
	KafkaAutoConfigureTopic bool
	LogLevel                string
}

func Load() (Config, error) {
	key, err := decodeKey(get("MASTER_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	if err != nil { return Config{}, err }
	cfg := Config{
		AppEnv:get("APP_ENV","development"), ListenAddr:get("LISTEN_ADDR",":8080"), PublicBaseURL:get("PUBLIC_BASE_URL","http://localhost:8080"),
		DatabaseURL:get("DATABASE_URL","postgres://riskgate:riskgate@localhost:5432/riskgate?sslmode=disable"), DBMaxConns:int32(getInt("DB_MAX_CONNS",80)), DBMinConns:int32(getInt("DB_MIN_CONNS",10)), DBConnectTimeout:getDuration("DB_CONNECT_TIMEOUT",5*time.Second),
		RedisURL:get("REDIS_URL","redis://localhost:6379/0"), RedisRequired:getBool("REDIS_REQUIRED",false), RedisPrefix:get("REDIS_PREFIX","riskgate"),
		AdminJWTSecret:get("ADMIN_JWT_SECRET","change-me-to-at-least-32-random-bytes"), TraceHMACSecret:get("TRACE_HMAC_SECRET","change-me-to-at-least-32-random-bytes"), MasterEncryptionKey:key, PromptHashSecret:get("PROMPT_HASH_SECRET","change-me-to-at-least-32-random-bytes"),
		BootstrapAdminUsername:get("BOOTSTRAP_ADMIN_USERNAME","admin"), BootstrapAdminPassword:get("BOOTSTRAP_ADMIN_PASSWORD","ChangeThisPasswordNow!123"), BootstrapAdminRole:get("BOOTSTRAP_ADMIN_ROLE","admin"),
		DefaultRetentionDays:getInt("DEFAULT_RETENTION_DAYS",7), MaxRequestBytes:getInt64("MAX_REQUEST_BYTES",8<<20), MaxResponseBytes:getInt64("MAX_RESPONSE_BYTES",32<<20), MaxSSEFrameBytes:getInt("MAX_SSE_FRAME_BYTES",1<<20), StreamGateBytes:getInt("STREAM_GATE_BYTES",64<<10), StreamGateTimeout:getDuration("STREAM_GATE_TIMEOUT",1200*time.Millisecond),
		UpstreamHeaderTimeout:getDuration("UPSTREAM_HEADER_TIMEOUT",60*time.Second), UpstreamIdleTimeout:getDuration("UPSTREAM_IDLE_TIMEOUT",120*time.Second), AuditDefaultTimeout:getDuration("AUDIT_DEFAULT_TIMEOUT",8*time.Second), AuditMaxTextBytes:getInt("AUDIT_MAX_TEXT_BYTES",128<<10), AuditCacheTTL:getDuration("AUDIT_CACHE_TTL",10*time.Minute),
		TraceQueueSize:getInt("TRACE_QUEUE_SIZE",32768), TraceWorkers:getInt("TRACE_WORKERS",8), OutboxWorkers:getInt("OUTBOX_WORKERS",4), FailClosed:getBool("FAIL_CLOSED",true), AllowPrivateUpstreams:getBool("ALLOW_PRIVATE_UPSTREAMS",false), TrustProxyHeaders:getBool("TRUST_PROXY_HEADERS",false),
		KafkaBrokers:splitCSV(get("KAFKA_BROKERS","")), KafkaTopic:get("KAFKA_TOPIC","riskgate.audit.events.v1"), KafkaClientID:get("KAFKA_CLIENT_ID","riskgate"), KafkaTLS:getBool("KAFKA_TLS",false), KafkaSASLMechanism:strings.ToLower(get("KAFKA_SASL_MECHANISM","")), KafkaSASLUsername:get("KAFKA_SASL_USERNAME",""), KafkaSASLPassword:get("KAFKA_SASL_PASSWORD",""), KafkaRetentionHours:getInt("KAFKA_RETENTION_HOURS",720), KafkaAutoConfigureTopic:getBool("KAFKA_AUTO_CONFIGURE_TOPIC",false), LogLevel:get("LOG_LEVEL","info"),
	}
	if err:=cfg.Validate();err!=nil{return Config{},err};return cfg,nil
}
func(c Config)Production()bool{return strings.EqualFold(c.AppEnv,"production")}
func(c Config)KafkaEnabled()bool{return len(c.KafkaBrokers)>0}
func(c Config)Validate()error{
	if c.DatabaseURL==""{return errors.New("DATABASE_URL is required")}
	if c.DBMinConns<0||c.DBMaxConns<1||c.DBMinConns>c.DBMaxConns{return errors.New("invalid PostgreSQL connection pool bounds")}
	if c.DefaultRetentionDays<1||c.DefaultRetentionDays>3650{return errors.New("DEFAULT_RETENTION_DAYS must be between 1 and 3650")}
	if c.MaxRequestBytes<1024||c.MaxRequestBytes>64<<20{return errors.New("MAX_REQUEST_BYTES must be between 1 KiB and 64 MiB")}
	if c.MaxResponseBytes<1024||c.MaxResponseBytes>256<<20{return errors.New("MAX_RESPONSE_BYTES must be between 1 KiB and 256 MiB")}
	if c.MaxSSEFrameBytes<4096||c.MaxSSEFrameBytes>8<<20{return errors.New("MAX_SSE_FRAME_BYTES must be between 4 KiB and 8 MiB")}
	if c.StreamGateBytes<0||c.StreamGateBytes>c.MaxSSEFrameBytes{return errors.New("STREAM_GATE_BYTES must be between 0 and MAX_SSE_FRAME_BYTES")}
	if c.TraceWorkers<1||c.TraceWorkers>256||c.OutboxWorkers<1||c.OutboxWorkers>128{return errors.New("worker count is outside safe bounds")}
	if len(c.MasterEncryptionKey)!=32{return errors.New("MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes")}
	if c.BootstrapAdminRole!="admin"&&c.BootstrapAdminRole!="operator"&&c.BootstrapAdminRole!="auditor"&&c.BootstrapAdminRole!="viewer"{return errors.New("invalid BOOTSTRAP_ADMIN_ROLE")}
	if c.KafkaEnabled(){if c.KafkaTopic==""{return errors.New("KAFKA_TOPIC is required when Kafka is enabled")};switch c.KafkaSASLMechanism{case "","plain","scram-sha-256","scram-sha-512":default:return fmt.Errorf("unsupported KAFKA_SASL_MECHANISM %q",c.KafkaSASLMechanism)};if c.KafkaSASLMechanism!=""&&(c.KafkaSASLUsername==""||c.KafkaSASLPassword==""){return errors.New("Kafka SASL username and password are required")}}
	if c.Production(){for _,secret:=range []string{c.AdminJWTSecret,c.TraceHMACSecret,c.PromptHashSecret,c.BootstrapAdminPassword}{if len(secret)<32||strings.Contains(strings.ToLower(secret),"change-me")||strings.Contains(secret,"ChangeThis"){return errors.New("production secrets must be unique random values of at least 32 bytes")}};if allZero(c.MasterEncryptionKey){return errors.New("production MASTER_ENCRYPTION_KEY cannot be the example key")};if !c.FailClosed{return errors.New("production must start with FAIL_CLOSED=true")}}
	return nil
}
func decodeKey(raw string)([]byte,error){b,err:=base64.StdEncoding.DecodeString(raw);if err!=nil{return nil,fmt.Errorf("decode MASTER_ENCRYPTION_KEY: %w",err)};return b,nil}
func allZero(b []byte)bool{for _,v:=range b{if v!=0{return false}};return true}
func get(k,fallback string)string{if v,ok:=os.LookupEnv(k);ok{return strings.TrimSpace(v)};return fallback}
func getInt(k string,fallback int)int{v:=get(k,"");if v==""{return fallback};n,err:=strconv.Atoi(v);if err!=nil{return fallback};return n}
func getInt64(k string,fallback int64)int64{v:=get(k,"");if v==""{return fallback};n,err:=strconv.ParseInt(v,10,64);if err!=nil{return fallback};return n}
func getBool(k string,fallback bool)bool{v:=get(k,"");if v==""{return fallback};b,err:=strconv.ParseBool(v);if err!=nil{return fallback};return b}
func getDuration(k string,fallback time.Duration)time.Duration{v:=get(k,"");if v==""{return fallback};d,err:=time.ParseDuration(v);if err!=nil{return fallback};return d}
func splitCSV(raw string)[]string{var out []string;for _,item:=range strings.Split(raw,","){if item=strings.TrimSpace(item);item!=""{out=append(out,item)}};return out}
