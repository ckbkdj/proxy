# RiskGate Security Operations

## Supported versions

Until a tagged release exists, only the latest commit on the maintained release branch is supported. Production deployments should pin an immutable Git commit and container digest rather than `latest`.

## Reporting a vulnerability

Do not open a public issue containing credentials, prompt data, tenant identifiers, exploit details, or production endpoint information. Use the repository owner's private security-reporting channel or GitHub private vulnerability reporting when enabled. Include:

- affected commit or image digest;
- deployment topology and relevant non-secret configuration;
- reproducible impact using synthetic data;
- whether authentication is required;
- evidence that no third-party system was accessed without authorization.

## Secret handling

Production requires independent random values for:

- `ADMIN_JWT_SECRET`;
- `TRACE_HMAC_SECRET`;
- `PROMPT_HASH_SECRET`;
- `MASTER_ENCRYPTION_KEY`;
- bootstrap administrator password;
- PostgreSQL, Redis, Kafka and provider credentials.

Never commit `.env`, Kubernetes Secret values, provider keys, trace HMAC material or decrypted database backups. Store secrets in a managed secret service and restrict read access to the RiskGate workload identity.

`MASTER_ENCRYPTION_KEY` rotation requires decrypting and re-encrypting all encrypted provider and audit-model secrets. Back up the database and test rollback before rotating it. Rotating `PROMPT_HASH_SECRET` invalidates route client-token hashes and changes all pseudonymous trace identifiers; issue new route tokens as part of the same maintenance event.

## Exposure model

Only the gateway path required by New API should be Internet-reachable. Keep these endpoints on an internal or strongly authenticated network whenever possible:

- `/admin/` and `/admin/api/v1/*`;
- `/metrics`;
- `/readyz`;
- PostgreSQL, Redis and Kafka.

Terminate TLS at a trusted load balancer or Ingress, remove untrusted forwarding headers at the edge, and enable `TRUST_PROXY_HEADERS` only behind that trusted component.

## Upstream network policy

Public upstreams are checked before configuration is saved and again when the TCP connection is opened. Private and reserved destinations are denied unless private upstream access is explicitly enabled. When private access is necessary, use Kubernetes NetworkPolicy, a dedicated egress gateway or equivalent controls to allow only approved model endpoints; the global private-upstream switch is not a substitute for network segmentation.

Environment HTTP proxy variables are not used for model-channel or audit-model requests, and upstream redirects are not followed.

## Data protection

RiskGate intentionally does not persist raw prompts. It stores keyed hashes, risk decisions, timing data and recursively sanitized metadata. Maintain database encryption at rest, TLS in transit, least-privilege roles, backup encryption, retention enforcement and access logging.

Kafka is an event transport, not an authorization boundary. Downstream consumers must apply the same tenant, retention and data-minimization requirements.

## Operational response

For a suspected compromise:

1. Isolate public and administrative ingress while preserving evidence.
2. Rotate administrator JWT, trace HMAC, provider, database, Redis and Kafka credentials.
3. Revoke and reissue every route client token when the prompt-hash secret may be exposed.
4. Review `admin_audit_logs`, request traces, load-balancer logs, Kafka consumer activity and secret-manager audit records.
5. Validate PostgreSQL backups and rebuild workloads from pinned, verified images.
6. Re-enable traffic gradually while monitoring HTTP 555 rate, authentication failures, audit degradation and outbox backlog.

## Pre-production security gates

Before handling commercial traffic, complete an independent review covering:

- authentication and RBAC;
- SSRF and DNS-rebinding resistance;
- non-standard HTTP 555 handling by every proxy and CDN;
- SSE error behavior;
- rate-limit bypass under multi-replica failure;
- database and Kafka retention;
- backup restoration;
- secret and encryption-key rotation;
- audit-model false-positive and false-negative evaluation;
- dependency and container vulnerability scanning;
- load, soak and fault-injection tests.
