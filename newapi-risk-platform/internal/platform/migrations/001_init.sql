CREATE TABLE IF NOT EXISTS audit_profiles (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    endpoint TEXT NOT NULL,
    model TEXT NOT NULL,
    api_key_ciphertext BYTEA,
    system_prompt TEXT NOT NULL DEFAULT '',
    timeout_ms INTEGER NOT NULL DEFAULT 8000 CHECK (timeout_ms BETWEEN 250 AND 120000),
    block_threshold DOUBLE PRECISION NOT NULL DEFAULT 0.65 CHECK (block_threshold BETWEEN 0 AND 1),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    fail_closed BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    extra JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS audit_profiles_one_default_idx
ON audit_profiles (is_default) WHERE is_default = TRUE;
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS routes (
    id BIGSERIAL PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT 'openai',
    auth_mode TEXT NOT NULL DEFAULT 'bearer',
    secret_header TEXT NOT NULL DEFAULT '',
    upstream_secret_ciphertext BYTEA,
    inbound_key_digest TEXT NOT NULL,
    audit_profile_id BIGINT REFERENCES audit_profiles(id) ON DELETE SET NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    fail_closed BOOLEAN NOT NULL DEFAULT TRUE,
    request_timeout_ms INTEGER NOT NULL DEFAULT 120000 CHECK (request_timeout_ms BETWEEN 1000 AND 3600000),
    max_concurrency INTEGER NOT NULL DEFAULT 256 CHECK (max_concurrency BETWEEN 1 AND 100000),
    rate_limit_rps DOUBLE PRECISION NOT NULL DEFAULT 100 CHECK (rate_limit_rps BETWEEN 0 AND 1000000),
    rate_limit_burst INTEGER NOT NULL DEFAULT 200 CHECK (rate_limit_burst BETWEEN 1 AND 1000000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS routes_enabled_slug_idx
ON routes (slug) WHERE enabled = TRUE AND deleted_at IS NULL;
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS cyber_rules (
    id BIGSERIAL PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    pattern TEXT NOT NULL,
    pattern_type TEXT NOT NULL DEFAULT 'regex' CHECK (pattern_type IN ('regex', 'contains', 'exact')),
    action TEXT NOT NULL DEFAULT 'block' CHECK (action IN ('block', 'allow', 'review')),
    priority INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS cyber_rules_active_priority_idx
ON cyber_rules (priority DESC, id ASC) WHERE enabled = TRUE;
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS request_traces (
    request_id TEXT NOT NULL,
    external_event_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'gateway',
    route_slug TEXT NOT NULL DEFAULT '',
    newapi_request_id TEXT NOT NULL DEFAULT '',
    external_user_id TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    endpoint TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '',
    risk_code TEXT NOT NULL DEFAULT '',
    http_status INTEGER NOT NULL DEFAULT 0,
    upstream_status INTEGER NOT NULL DEFAULT 0,
    latency_ms BIGINT NOT NULL DEFAULT 0,
    audit_latency_ms BIGINT NOT NULL DEFAULT 0,
    request_bytes BIGINT NOT NULL DEFAULT 0,
    response_bytes BIGINT NOT NULL DEFAULT 0,
    prompt_hmac TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
) PARTITION BY RANGE (created_at);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_created_at_idx ON request_traces (created_at DESC);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_request_id_idx ON request_traces (request_id);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_route_created_idx ON request_traces (route_slug, created_at DESC);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_user_created_idx
ON request_traces (external_user_id, created_at DESC) WHERE external_user_id <> '';
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_decision_created_idx ON request_traces (decision, created_at DESC);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_traces_risk_created_idx
ON request_traces (risk_code, created_at DESC) WHERE risk_code <> '';
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS request_dedupe (
    event_id TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS request_dedupe_expiry_idx ON request_dedupe (expires_at);
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS tracking_clients (
    id BIGSERIAL PRIMARY KEY,
    key_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS tracking_nonces (
    key_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (key_id, nonce)
);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS tracking_nonces_expiry_idx ON tracking_nonces (expires_at);
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS admin_users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'operator', 'viewer')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    admin_user_id BIGINT,
    username TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    client_ip TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS admin_audit_logs_created_idx ON admin_audit_logs (created_at DESC);
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- statement-breakpoint
CREATE TABLE IF NOT EXISTS outbox_events (
    id BIGSERIAL PRIMARY KEY,
    topic TEXT NOT NULL,
    event_key TEXT NOT NULL DEFAULT '',
    payload BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);
-- statement-breakpoint
CREATE INDEX IF NOT EXISTS outbox_events_pending_idx
ON outbox_events (next_attempt_at, id) WHERE published_at IS NULL;
-- statement-breakpoint
INSERT INTO settings (key, value) VALUES
    ('retention_days', '7'::jsonb),
    ('kafka_retention_days', '30'::jsonb),
    ('redis_stream_maxlen', '100000'::jsonb),
    ('store_raw_prompts', 'false'::jsonb)
ON CONFLICT (key) DO NOTHING;
-- statement-breakpoint
INSERT INTO cyber_rules
(code, name, description, category, pattern, pattern_type, action, priority, enabled)
VALUES
(
    'CYBER_CREDENTIAL_THEFT',
    'Credential theft or secret exfiltration',
    'High-confidence requests to steal, dump, harvest, or exfiltrate credentials and secrets.',
    'credential_theft',
    '(?is)\b(?:steal|dump|extract|exfiltrat(?:e|ing)|harvest)\b.{0,120}\b(?:passwords?|credentials?|session cookies?|access tokens?|seed phrases?|private keys?)\b',
    'regex', 'block', 1000, TRUE
),
(
    'CYBER_MALWARE_CREATION',
    'Malware construction',
    'Requests to construct ransomware, keyloggers, credential stealers, rootkits, botnets, or remote access trojans.',
    'malware',
    '(?is)\b(?:write|build|generate|create|develop)\b.{0,120}\b(?:ransomware|keylogger|credential stealer|rootkit|botnet|remote access trojan|rat payload)\b',
    'regex', 'block', 990, TRUE
),
(
    'CYBER_SECURITY_EVASION',
    'Security control evasion',
    'High-confidence attempts to bypass or disable endpoint and monitoring controls.',
    'defense_evasion',
    '(?is)\b(?:bypass|disable|evade|blind)\b.{0,120}\b(?:edr|antivirus|endpoint protection|defender|siem|security controls?)\b',
    'regex', 'block', 980, TRUE
),
(
    'CYBER_PHISHING_KIT',
    'Phishing kit or credential-harvesting page',
    'Requests to build phishing kits, cloned login pages, or credential-harvesting campaigns.',
    'phishing',
    '(?is)\b(?:create|build|generate|clone)\b.{0,120}\b(?:phishing|credential harvesting|fake login|spoofed login)\b.{0,120}\b(?:page|template|campaign|kit)\b',
    'regex', 'block', 970, TRUE
),
(
    'CYBER_EXPLOIT_WEAPONIZATION',
    'Exploit weaponization',
    'Requests to weaponize a vulnerability into reliable exploit code against a target.',
    'exploit_weaponization',
    '(?is)\b(?:weaponize|turn into a working exploit|generate exploit code|reliable remote code execution)\b.{0,160}\b(?:cve-\d{4}-\d{4,7}|vulnerability|target)\b',
    'regex', 'block', 960, TRUE
),
(
    'CYBER_DESTRUCTIVE_ACTION',
    'Destructive system or data action',
    'Explicit destructive commands that would wipe a root filesystem, disk, or database.',
    'destructive',
    '(?is)(?:rm\s+-rf\s+/(?:\s|$)|format\s+[a-z]:|del\s+/[sq]\s+[a-z]:\\|drop\s+database\s+[a-z0-9_]+)',
    'regex', 'block', 950, TRUE
)
ON CONFLICT (code) DO NOTHING;
