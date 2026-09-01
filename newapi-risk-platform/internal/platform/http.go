package platform

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed web/index.html
var webAssets embed.FS

type contextKey string

const adminClaimsKey contextKey = "admin-claims"

type HTTPService struct {
	cfg      Config
	store    *Store
	security *Security
	redis    *RedisGuard
	events   *EventSink
	audit    *AuditEngine
	gateway  *Gateway
	traces   *TraceWriter
	log      *slog.Logger
}

func NewHTTPService(
	cfg Config,
	store *Store,
	security *Security,
	redis *RedisGuard,
	events *EventSink,
	audit *AuditEngine,
	gateway *Gateway,
	traces *TraceWriter,
	log *slog.Logger,
) *HTTPService {
	return &HTTPService{
		cfg:      cfg,
		store:    store,
		security: security,
		redis:    redis,
		events:   events,
		audit:    audit,
		gateway:  gateway,
		traces:   traces,
		log:      log,
	}
}

func (s *HTTPService) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(s.securityHeaders)
	router.Use(s.accessLog)

	router.Get("/healthz", s.health)
	router.Get("/readyz", s.ready)
	router.Handle("/metrics", promhttp.Handler())
	router.Handle("/gateway/{route}", s.gateway)
	router.Handle("/gateway/{route}/*", s.gateway)
	router.Post("/api/v1/track/events", s.ingestTrackingEvents)
	router.Post("/api/admin/v1/login", s.login)

	router.Group(func(admin chi.Router) {
		admin.Use(s.requireAdmin)
		admin.Get("/api/admin/v1/me", s.me)
		admin.Get("/api/admin/v1/dashboard", s.adminDashboard)
		admin.Get("/api/admin/v1/runtime", s.adminRuntime)
		admin.Get("/api/admin/v1/routes", s.adminListRoutes)
		admin.With(s.requireRole("operator")).Post("/api/admin/v1/routes", s.adminSaveRoute)
		admin.With(s.requireRole("admin")).Delete("/api/admin/v1/routes/{id}", s.adminDeleteRoute)
		admin.Get("/api/admin/v1/audit-profiles", s.adminListAuditProfiles)
		admin.With(s.requireRole("operator")).Post("/api/admin/v1/audit-profiles", s.adminSaveAuditProfile)
		admin.With(s.requireRole("admin")).Delete("/api/admin/v1/audit-profiles/{id}", s.adminDeleteAuditProfile)
		admin.Get("/api/admin/v1/cyber-rules", s.adminListCyberRules)
		admin.With(s.requireRole("operator")).Post("/api/admin/v1/cyber-rules", s.adminSaveCyberRule)
		admin.With(s.requireRole("admin")).Delete("/api/admin/v1/cyber-rules/{id}", s.adminDeleteCyberRule)
		admin.With(s.requireRole("operator")).Post("/api/admin/v1/audit/dry-run", s.adminAuditDryRun)
		admin.Get("/api/admin/v1/traces", s.adminListTraces)
		admin.Get("/api/admin/v1/settings", s.adminGetSettings)
		admin.With(s.requireRole("admin")).Put("/api/admin/v1/settings/storage", s.adminSaveStorageSettings)
		admin.Get("/api/admin/v1/tracking-clients", s.adminListTrackingClients)
		admin.With(s.requireRole("admin")).Post("/api/admin/v1/tracking-clients", s.adminSaveTrackingClient)
	})

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
	})
	router.Get("/admin", s.serveAdmin)
	router.Get("/admin/*", s.serveAdmin)
	return router
}

func (s *HTTPService) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *HTTPService) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wrapped, r)
		path := r.URL.Path
		if strings.HasPrefix(path, "/healthz") || strings.HasPrefix(path, "/readyz") {
			return
		}
		s.log.Info(
			"http request",
			"request_id", middleware.GetReqID(r.Context()),
			"method", r.Method,
			"path", truncateString(path, 500),
			"status", wrapped.Status(),
			"bytes", wrapped.BytesWritten(),
			"duration_ms", time.Since(started).Milliseconds(),
			"remote_ip", remoteIP(r),
		)
	})
}

func (s *HTTPService) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func (s *HTTPService) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Health(ctx); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "postgres_unavailable", "service is not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *HTTPService) serveAdmin(w http.ResponseWriter, _ *http.Request) {
	data, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "ui_unavailable", "admin UI is unavailable")
		return
	}
	nonce, err := GenerateSecret(18)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "ui_unavailable", "admin UI is unavailable")
		return
	}
	page := strings.ReplaceAll(string(data), "{{NONCE}}", nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; "+
			"connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	)
	_, _ = io.WriteString(w, page)
}

func (s *HTTPService) login(w http.ResponseWriter, r *http.Request) {
	loginKey := s.security.Digest("admin-login-rate-v1", remoteIP(r))[:32]
	if !s.redis.Allow(r.Context(), loginKey, 0.2, 5) {
		writeAPIError(w, http.StatusTooManyRequests, "login_rate_limited", "too many login attempts")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(w, r, 64*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	user, err := s.store.GetAdminUser(r.Context(), strings.TrimSpace(input.Username))
	if err != nil || !user.Enabled || !VerifyPassword(user.PasswordHash, input.Password) {
		time.Sleep(150 * time.Millisecond)
		s.store.WriteAdminAudit(
			r.Context(),
			nil,
			"login_failed",
			"session",
			"",
			middleware.GetReqID(r.Context()),
			remoteIP(r),
			map[string]any{"username": truncateString(input.Username, 100)},
		)
		writeAPIError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	token, err := s.security.IssueAdminToken(user)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "token_error", "could not create access token")
		return
	}
	claims := &AdminClaims{UserID: user.ID, Username: user.Username, Role: user.Role}
	s.store.WriteAdminAudit(
		r.Context(),
		claims,
		"login",
		"session",
		"",
		middleware.GetReqID(r.Context()),
		remoteIP(r),
		nil,
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(s.cfg.JWTTTL.Seconds()),
		"user":         user,
	})
}

func (s *HTTPService) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "administrator authentication is required")
			return
		}
		claims, err := s.security.ParseAdminToken(strings.TrimSpace(header[7:]))
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "access token is invalid or expired")
			return
		}
		ctx := context.WithValue(r.Context(), adminClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *HTTPService) requireRole(required string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsFromContext(r.Context())
			if claims == nil || roleRank(claims.Role) < roleRank(required) {
				writeAPIError(w, http.StatusForbidden, "forbidden", "insufficient administrator role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func claimsFromContext(ctx context.Context) *AdminClaims {
	claims, _ := ctx.Value(adminClaimsKey).(*AdminClaims)
	return claims
}

func roleRank(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}

func (s *HTTPService) me(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
	})
}

func (s *HTTPService) ingestTrackingEvents(w http.ResponseWriter, r *http.Request) {
	bodyReader := http.MaxBytesReader(w, r.Body, 2*1024*1024)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "tracking payload is too large")
		return
	}
	keyID := strings.TrimSpace(r.Header.Get("X-Risk-Key-Id"))
	timestampText := strings.TrimSpace(r.Header.Get("X-Risk-Timestamp"))
	nonce := strings.TrimSpace(r.Header.Get("X-Risk-Nonce"))
	signature := strings.TrimSpace(r.Header.Get("X-Risk-Signature"))
	if keyID == "" || timestampText == "" || nonce == "" || signature == "" || len(nonce) > 200 {
		writeAPIError(w, http.StatusUnauthorized, "invalid_signature", "signed tracking headers are required")
		return
	}
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || time.Since(time.Unix(timestamp, 0)).Abs() > s.cfg.TrackingClockSkew {
		writeAPIError(w, http.StatusUnauthorized, "stale_signature", "tracking signature timestamp is outside the allowed window")
		return
	}
	client, err := s.store.GetTrackingClient(r.Context(), keyID)
	if err != nil || !client.Enabled {
		writeAPIError(w, http.StatusUnauthorized, "invalid_signature", "tracking client is not authorized")
		return
	}
	secret, err := s.security.Decrypt("tracking-client-secret-v1", client.SecretCiphertext)
	if err != nil || !VerifyTrackingSignature(string(secret), timestampText, nonce, body, signature) {
		writeAPIError(w, http.StatusUnauthorized, "invalid_signature", "tracking signature is invalid")
		return
	}
	fresh, err := s.redis.UseNonce(r.Context(), keyID, nonce, s.cfg.TrackingNonceTTL, s.store)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "nonce_store_unavailable", "tracking replay protection is unavailable")
		return
	}
	if !fresh {
		writeAPIError(w, http.StatusConflict, "replayed_request", "tracking nonce has already been used")
		return
	}

	var envelope TrackingEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope.Events) == 0 {
		var single TrackingEvent
		if singleError := json.Unmarshal(body, &single); singleError != nil || single.RequestID == "" {
			writeAPIError(w, http.StatusBadRequest, "invalid_payload", "payload must contain one event or an events array")
			return
		}
		envelope.Events = []TrackingEvent{single}
	}
	if len(envelope.Events) > 1000 {
		writeAPIError(w, http.StatusBadRequest, "batch_too_large", "a tracking batch may contain at most 1000 events")
		return
	}

	now := time.Now().UTC()
	accepted := 0
	deferredOrDropped := 0
	for _, event := range envelope.Events {
		requestID := normalizeRequestID(event.RequestID)
		if requestID == "" {
			requestID = NewRequestID()
		}
		decision := strings.ToLower(strings.TrimSpace(event.Decision))
		if decision != DecisionAllow && decision != DecisionBlock && decision != "error" && decision != DecisionReview {
			decision = "unknown"
		}
		metadata := sanitizeMetadata(event.Metadata)
		if !event.OccurredAt.IsZero() {
			metadata["occurred_at"] = event.OccurredAt.UTC().Format(time.RFC3339Nano)
		}
		externalEventID := truncateString(firstNonEmpty(event.EventID, requestID), 200)
		queued := s.traces.Submit(TraceEvent{
			RequestID:       requestID,
			ExternalEventID: keyID + ":" + externalEventID,
			Source:          "newapi",
			RouteSlug:       truncateString(event.RouteSlug, 100),
			NewAPIRequestID: normalizeRequestID(event.NewAPIRequestID),
			ExternalUserID:  normalizeIdentifier(event.ExternalUserID),
			Model:           truncateString(event.Model, 200),
			Endpoint:        truncateString(event.Endpoint, 300),
			Decision:        decision,
			RiskCode:        truncateString(event.RiskCode, 200),
			HTTPStatus:      event.HTTPStatus,
			UpstreamStatus:  event.UpstreamStatus,
			LatencyMS:       event.LatencyMS,
			AuditLatencyMS:  event.AuditLatencyMS,
			RequestBytes:    event.RequestBytes,
			ResponseBytes:   event.ResponseBytes,
			PromptHMAC:      truncateString(event.PromptHMAC, 128),
			Metadata:        metadata,
			CreatedAt:       now,
		})
		if queued {
			accepted++
		} else {
			deferredOrDropped++
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":            accepted,
		"deferred_or_dropped": deferredOrDropped,
		"received_at":         now,
	})
}

func sanitizeMetadata(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	blocked := map[string]struct{}{
		"prompt": {}, "messages": {}, "content": {}, "input": {}, "instructions": {},
		"system_prompt": {}, "request_body": {}, "response_body": {}, "api_key": {},
		"apikey": {}, "authorization": {}, "password": {}, "secret": {}, "cookie": {},
		"set-cookie": {}, "access_token": {}, "refresh_token": {},
	}
	var clean func(value any, depth int) any
	clean = func(value any, depth int) any {
		if depth > 5 {
			return nil
		}
		switch typed := value.(type) {
		case map[string]any:
			result := map[string]any{}
			for key, child := range typed {
				lowerKey := strings.ToLower(strings.TrimSpace(key))
				_, denied := blocked[lowerKey]
				if denied || metadataKeyLooksSensitive(lowerKey) || len(key) > 100 {
					continue
				}
				result[key] = clean(child, depth+1)
			}
			return result
		case []any:
			if len(typed) > 100 {
				typed = typed[:100]
			}
			result := make([]any, 0, len(typed))
			for _, child := range typed {
				result = append(result, clean(child, depth+1))
			}
			return result
		case string:
			return truncateString(typed, 500)
		case float64, bool, nil:
			return typed
		default:
			return fmt.Sprint(typed)
		}
	}
	result, _ := clean(input, 0).(map[string]any)
	encoded, _ := json.Marshal(result)
	if len(encoded) > 32*1024 {
		return map[string]any{
			"metadata_truncated": true,
			"original_bytes":     len(encoded),
		}
	}
	return result
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, limit int64, target any) error {
	reader := http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
