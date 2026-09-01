package httpapi

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/audit"
	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/events"
	"github.com/ckbkdj/newapi-risk-control/internal/gateway"
	"github.com/ckbkdj/newapi-risk-control/internal/pipeline"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
)

//go:embed web/*
var webAssets embed.FS

type claimsKey struct{}

type loginBucket struct {
	tokens float64
	last   time.Time
}

type Server struct {
	cfg     config.Config
	store   *store.Store
	redis   *cache.Redis
	kafka   *events.Kafka
	cipher  *security.Cipher
	audit   *audit.Engine
	gateway *gateway.Gateway
	traces  *pipeline.Pipeline
	log     *slog.Logger

	nonceMu sync.Mutex
	nonces  map[string]time.Time
	loginMu sync.Mutex
	logins  map[string]*loginBucket
}

func New(
	cfg config.Config,
	st *store.Store,
	rc *cache.Redis,
	kafkaClient *events.Kafka,
	cipher *security.Cipher,
	auditEngine *audit.Engine,
	gw *gateway.Gateway,
	traces *pipeline.Pipeline,
	log *slog.Logger,
) *Server {
	return &Server{
		cfg: cfg, store: st, redis: rc, kafka: kafkaClient, cipher: cipher,
		audit: auditEngine, gateway: gw, traces: traces, log: log,
		nonces: make(map[string]time.Time), logins: make(map[string]*loginBucket),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", s.ready)
	mux.HandleFunc("/metrics", s.metrics)
	mux.Handle("/gateway/", s.gateway)
	mux.HandleFunc("/api/v1/traces/ingest", s.ingestTraces)
	mux.HandleFunc("/admin/api/v1/login", s.login)
	mux.Handle("/admin/api/v1/", s.withAdminAuth(http.HandlerFunc(s.adminDispatch)))

	assets, _ := fs.Sub(webAssets, "web")
	mux.Handle("/admin/", http.StripPrefix("/admin/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
	})

	return s.securityHeaders(s.recoverPanics(s.accessLog(mux)))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"ok": true, "service": "riskgate", "time": time.Now().UTC(),
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		jsonError(w, http.StatusServiceUnavailable, "postgres_unavailable")
		return
	}
	if s.cfg.RedisRequired {
		if err := s.redis.Ping(ctx); err != nil {
			jsonError(w, http.StatusServiceUnavailable, "redis_unavailable")
			return
		}
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"ok": true, "postgres": true, "redis": s.redis.Enabled(), "kafka": s.kafka.Enabled(),
	})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	stats, err := s.store.Stats(ctx)
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w,
		"# TYPE riskgate_routes_enabled gauge\nriskgate_routes_enabled %d\n"+
			"# TYPE riskgate_rules_enabled gauge\nriskgate_rules_enabled %d\n"+
			"# TYPE riskgate_traces_last_hour gauge\nriskgate_traces_last_hour %d\n"+
			"# TYPE riskgate_blocks_last_hour gauge\nriskgate_blocks_last_hour %d\n"+
			"# TYPE riskgate_outbox_pending gauge\nriskgate_outbox_pending %d\n"+
			"# TYPE riskgate_outbox_dead gauge\nriskgate_outbox_dead %d\n"+
			"# TYPE riskgate_default_partition_rows gauge\nriskgate_default_partition_rows %d\n",
		stats.RoutesEnabled, stats.RulesEnabled, stats.TracesLastHour,
		stats.BlockedLastHour, stats.OutboxPending, stats.OutboxDead, stats.DefaultPartition,
	)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	ip := s.clientIP(r)
	if !s.allowLogin(r.Context(), ip) {
		jsonError(w, http.StatusTooManyRequests, "too_many_login_attempts")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, 64<<10, &input) {
		return
	}
	user, err := s.store.FindAdmin(r.Context(), strings.TrimSpace(input.Username))
	if err != nil || !user.Enabled || !security.VerifyPassword(user.PasswordHash, input.Password) {
		time.Sleep(150 * time.Millisecond)
		jsonError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	token, err := security.IssueJWT(s.cfg.AdminJWTSecret, user.ID, user.Username, user.Role, 8*time.Hour)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "token_issue_failed")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"token": token, "expires_in": int((8 * time.Hour).Seconds()),
		"user": map[string]string{"id": user.ID, "username": user.Username, "role": user.Role},
	})
}

func (s *Server) allowLogin(ctx context.Context, ip string) bool {
	if s.redis.Enabled() {
		allowed, err := s.redis.Allow(ctx, "login:"+ip, .2, 10)
		if err == nil {
			return allowed
		}
	}
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	now := time.Now()
	bucket := s.logins[ip]
	if bucket == nil {
		bucket = &loginBucket{tokens: 10, last: now}
		s.logins[ip] = bucket
	}
	bucket.tokens += now.Sub(bucket.last).Seconds() * .2
	if bucket.tokens > 10 {
		bucket.tokens = 10
	}
	bucket.last = now
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	if len(s.logins) > 10000 {
		for key, item := range s.logins {
			if now.Sub(item.last) > time.Hour {
				delete(s.logins, key)
			}
		}
	}
	return true
}

func (s *Server) withAdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			jsonError(w, http.StatusUnauthorized, "missing_bearer_token")
			return
		}
		claims, err := security.ParseJWT(s.cfg.AdminJWTSecret, strings.TrimSpace(auth[7:]))
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}

func claimsFrom(ctx context.Context) *security.Claims {
	claims, _ := ctx.Value(claimsKey{}).(*security.Claims)
	return claims
}

func requireRole(w http.ResponseWriter, r *http.Request, roles ...string) bool {
	claims := claimsFrom(r.Context())
	if claims == nil {
		jsonError(w, http.StatusUnauthorized, "invalid_token")
		return false
	}
	for _, role := range roles {
		if claims.Role == role {
			return true
		}
	}
	jsonError(w, http.StatusForbidden, "insufficient_role")
	return false
}

func (s *Server) ingestTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		jsonError(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
	timestamp, err := strconv.ParseInt(r.Header.Get("X-Risk-Timestamp"), 10, 64)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid_timestamp")
		return
	}
	nonce := r.Header.Get("X-Risk-Nonce")
	signature := r.Header.Get("X-Risk-Signature")
	keyID := r.Header.Get("X-Risk-Key-ID")
	if keyID == "" {
		keyID = "newapi"
	}
	if err := security.VerifyTraceSignature(s.cfg.TraceHMACSecret, timestamp, nonce, signature, body, time.Now(), 5*time.Minute); err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid_signature")
		return
	}
	if !s.claimNonce(r.Context(), keyID, nonce) {
		jsonError(w, http.StatusConflict, "replayed_nonce")
		return
	}

	var wrapper struct {
		Events []core.TraceIngest `json:"events"`
	}
	var incoming []core.TraceIngest
	if json.Unmarshal(body, &wrapper) == nil && len(wrapper.Events) > 0 {
		incoming = wrapper.Events
	} else {
		var one core.TraceIngest
		if json.Unmarshal(body, &one) != nil {
			jsonError(w, http.StatusBadRequest, "invalid_json")
			return
		}
		incoming = []core.TraceIngest{one}
	}
	if len(incoming) > 1000 {
		jsonError(w, http.StatusBadRequest, "too_many_events")
		return
	}

	now := time.Now().UTC()
	accepted := 0
	for _, event := range incoming {
		createdAt := now
		if event.OccurredAt != nil && !event.OccurredAt.Before(now.AddDate(0, 0, -30)) && !event.OccurredAt.After(now.Add(5*time.Minute)) {
			createdAt = event.OccurredAt.UTC()
		}
		method := event.Method
		if method == "" {
			method = http.MethodPost
		}
		traceID := security.NewUUID()
		externalRequestID := bounded(event.ExternalRequestID, 256)
		if externalRequestID == "" {
			externalRequestID = traceID
		}
		trace := core.Trace{
			ID: traceID, ExternalRequestID: externalRequestID,
			ParentRequestID: bounded(event.ParentRequestID, 256), RouteSlug: bounded(event.RouteSlug, 64),
			TenantID: bounded(event.TenantID, 128), UserIDHash: security.HashOpaque(s.cfg.PromptHashSecret, event.UserID),
			APIKeyHash: security.HashOpaque(s.cfg.PromptHashSecret, event.APIKeyFingerprint),
			Model: bounded(event.Model, 256), Provider: bounded(event.Provider, 64),
			Method: bounded(method, 16), Path: bounded(event.Path, 1024),
			HTTPStatus: event.HTTPStatus, Outcome: bounded(event.Outcome, 64),
			Metadata: security.SanitizeMetadata(event.Metadata, 64<<10), CreatedAt: createdAt,
			ClientIPHash: security.HashOpaque(s.cfg.PromptHashSecret, s.clientIP(r)),
		}
		s.traces.Emit(trace)
		accepted++
	}
	jsonResponse(w, http.StatusAccepted, map[string]interface{}{"accepted": accepted})
}

func (s *Server) claimNonce(ctx context.Context, keyID, nonce string) bool {
	if nonce == "" || len(nonce) > 256 || len(keyID) > 128 {
		return false
	}
	if s.redis.Enabled() {
		claimed, err := s.redis.ClaimNonce(ctx, keyID, nonce, 10*time.Minute)
		if err == nil {
			return claimed
		}
	}
	now := time.Now()
	key := keyID + ":" + nonce
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	for existing, expiry := range s.nonces {
		if expiry.Before(now) {
			delete(s.nonces, existing)
		}
	}
	if _, exists := s.nonces[key]; exists {
		return false
	}
	s.nonces[key] = now.Add(10 * time.Minute)
	return true
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		if s.cfg.Production() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.log.Error("HTTP handler panic", "panic", recovered, "method", r.Method, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		if r.URL.Path != "/healthz" {
			s.log.Info("http request", "method", r.Method, "path", r.URL.Path,
				"status", wrapped.status, "duration_ms", time.Since(started).Milliseconds())
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}
func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if raw := r.Header.Get("X-Forwarded-For"); raw != "" {
			return strings.TrimSpace(strings.Split(raw, ",")[0])
		}
		if raw := r.Header.Get("X-Real-IP"); raw != "" {
			return raw
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) auditAdmin(r *http.Request, action, resourceType, resourceID string, before, after interface{}) {
	claims := claimsFrom(r.Context())
	if claims == nil {
		return
	}
	requestID := bounded(r.Header.Get("X-Request-ID"), 256)
	ipHash := security.HashOpaque(s.cfg.PromptHashSecret, s.clientIP(r))
	if err := s.store.WriteAdminAudit(r.Context(), claims.Subject, claims.Username, claims.Role,
		action, resourceType, resourceID, requestID, ipHash, before, after); err != nil {
		s.log.Warn("admin audit write failed", "error", err)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, max int64, out interface{}) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, max))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		jsonError(w, http.StatusBadRequest, "multiple_json_values")
		return false
	}
	return true
}

func jsonResponse(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func jsonError(w http.ResponseWriter, status int, code string) {
	jsonResponse(w, status, map[string]interface{}{
		"error": map[string]interface{}{"code": code, "message": code},
	})
}
func methodNotAllowed(w http.ResponseWriter) {
	jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed")
}
func bounded(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}
func parseTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}
