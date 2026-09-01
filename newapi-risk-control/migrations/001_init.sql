CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_profiles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    endpoint text NOT NULL,
    model text NOT NULL,
    api_key_cipher text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    fail_mode text NOT NULL DEFAULT 'closed' CHECK (fail_mode IN ('closed','open','shadow')),
    block_threshold double precision NOT NULL DEFAULT 0.72 CHECK (block_threshold >= 0 AND block_threshold <= 1),
    timeout_ms integer NOT NULL DEFAULT 8000 CHECK (timeout_ms BETWEEN 100 AND 120000),
    max_input_chars integer NOT NULL DEFAULT 32000 CHECK (max_input_chars BETWEEN 256 AND 262144),
    cache_ttl_seconds integer NOT NULL DEFAULT 600 CHECK (cache_ttl_seconds BETWEEN 0 AND 86400),
    system_prompt text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS routes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
    name text NOT NULL,
    upstream_base_url text NOT NULL,
    upstream_kind text NOT NULL DEFAULT 'openai' CHECK (upstream_kind IN ('openai','anthropic','gemini','custom')),
    upstream_api_key_cipher text NOT NULL DEFAULT '',
    client_token_hash text NOT NULL,
    audit_profile_id uuid REFERENCES audit_profiles(id) ON DELETE SET NULL,
    enabled boolean NOT NULL DEFAULT true,
    rate_limit_rps double precision NOT NULL DEFAULT 100 CHECK (rate_limit_rps > 0 AND rate_limit_rps <= 1000000),
    rate_limit_burst integer NOT NULL DEFAULT 200 CHECK (rate_limit_burst > 0 AND rate_limit_burst <= 10000000),
    max_inflight integer NOT NULL DEFAULT 1000 CHECK (max_inflight > 0 AND max_inflight <= 1000000),
    request_timeout_ms integer NOT NULL DEFAULT 300000 CHECK (request_timeout_ms BETWEEN 1000 AND 3600000),
    allow_private_upstream boolean NOT NULL DEFAULT false,
    upstream_error_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    extra_headers_cipher text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes(enabled) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_routes_audit_profile ON routes(audit_profile_id);

CREATE TABLE IF NOT EXISTS risk_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    category text NOT NULL,
    pattern text NOT NULL,
    action text NOT NULL DEFAULT 'block' CHECK (action IN ('block','review','allow')),
    score double precision NOT NULL DEFAULT 1 CHECK (score >= 0 AND score <= 1),
    priority integer NOT NULL DEFAULT 100,
    enabled boolean NOT NULL DEFAULT true,
    builtin boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_risk_rules_active ON risk_rules(priority DESC, updated_at DESC) WHERE enabled;

CREATE TABLE IF NOT EXISTS storage_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    retention_days integer NOT NULL DEFAULT 7 CHECK (retention_days BETWEEN 1 AND 3650),
    postgres_enabled boolean NOT NULL DEFAULT true,
    redis_buffer_enabled boolean NOT NULL DEFAULT true,
    redis_buffer_ttl_hours integer NOT NULL DEFAULT 72 CHECK (redis_buffer_ttl_hours BETWEEN 1 AND 8760),
    kafka_enabled boolean NOT NULL DEFAULT false,
    kafka_retention_hours integer NOT NULL DEFAULT 720 CHECK (kafka_retention_hours BETWEEN 1 AND 87600),
    store_raw_prompt boolean NOT NULL DEFAULT false CHECK (store_raw_prompt = false),
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO storage_policy(singleton) VALUES (true) ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS admin_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','operator','auditor','viewer')),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tracking_clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    key_id text NOT NULL UNIQUE,
    hmac_secret_cipher text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS request_traces (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    external_request_id text NOT NULL DEFAULT '',
    parent_request_id text NOT NULL DEFAULT '',
    route_id uuid NULL,
    route_slug text NOT NULL DEFAULT '',
    tenant_id text NOT NULL DEFAULT '',
    user_id_hash text NOT NULL DEFAULT '',
    api_key_hash text NOT NULL DEFAULT '',
    model text NOT NULL DEFAULT '',
    provider text NOT NULL DEFAULT '',
    method text NOT NULL DEFAULT '',
    path text NOT NULL DEFAULT '',
    request_bytes bigint NOT NULL DEFAULT 0,
    response_bytes bigint NOT NULL DEFAULT 0,
    http_status integer NOT NULL DEFAULT 0,
    normalized_code integer NOT NULL DEFAULT 0,
    outcome text NOT NULL DEFAULT '',
    risk_category text NOT NULL DEFAULT '',
    risk_score double precision NOT NULL DEFAULT 0,
    risk_reason_code text NOT NULL DEFAULT '',
    prompt_hash text NOT NULL DEFAULT '',
    audit_latency_ms bigint NOT NULL DEFAULT 0,
    upstream_latency_ms bigint NOT NULL DEFAULT 0,
    total_latency_ms bigint NOT NULL DEFAULT 0,
    stream boolean NOT NULL DEFAULT false,
    client_ip_hash text NOT NULL DEFAULT '',
    user_agent_hash text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);
CREATE TABLE IF NOT EXISTS request_traces_default PARTITION OF request_traces DEFAULT;
CREATE INDEX IF NOT EXISTS idx_traces_default_created_at ON request_traces_default(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_traces_default_external_id ON request_traces_default(external_request_id);
CREATE INDEX IF NOT EXISTS idx_traces_default_route_time ON request_traces_default(route_slug, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_traces_default_outcome_time ON request_traces_default(outcome, created_at DESC);

CREATE TABLE IF NOT EXISTS event_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    topic text NOT NULL,
    event_key text NOT NULL,
    payload jsonb NOT NULL,
    headers jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','published','dead')),
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_owner text NOT NULL DEFAULT '',
    lease_until timestamptz NULL,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz NULL
);
CREATE INDEX IF NOT EXISTS idx_outbox_ready ON event_outbox(status, available_at, created_at) WHERE status IN ('pending','leased');

CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id uuid NULL,
    actor_username text NOT NULL DEFAULT '',
    actor_role text NOT NULL DEFAULT '',
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL DEFAULT '',
    request_id text NOT NULL DEFAULT '',
    client_ip_hash text NOT NULL DEFAULT '',
    before_value jsonb NULL,
    after_value jsonb NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_time ON admin_audit_logs(created_at DESC);

INSERT INTO schema_migrations(version) VALUES ('001_init') ON CONFLICT DO NOTHING;
