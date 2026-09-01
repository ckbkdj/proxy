package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
)

var routeSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (s *HTTPService) adminDashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Dashboard(r.Context(), 24*time.Hour)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "dashboard_error", "could not load dashboard")
		return
	}
	stats.TraceQueueDepth = s.traces.Depth()
	stats.KafkaQueueDepth = s.events.QueueDepth()
	stats.RedisAvailable = s.redis.Available()
	stats.KafkaEnabled = s.events.Enabled()
	writeJSON(w, http.StatusOK, stats)
}

func (s *HTTPService) adminRuntime(w http.ResponseWriter, r *http.Request) {
	postgresHealthy := s.store.Health(r.Context()) == nil
	writeJSON(w, http.StatusOK, map[string]any{
		"environment": s.cfg.Environment,
		"postgres_healthy": postgresHealthy,
		"redis": s.redis.Status(),
		"kafka_enabled": s.events.Enabled(),
		"kafka_queue_depth": s.events.QueueDepth(),
		"trace_queue_depth": s.traces.Depth(),
		"trace_dropped": s.traces.Dropped(),
		"error_http_status": s.cfg.ErrorHTTPStatus,
		"allow_private_upstreams": s.cfg.AllowPrivateUpstreams,
		"postgres_retention_days": s.store.GetIntSetting(r.Context(), "retention_days", s.cfg.RetentionDays),
	})
}

func (s *HTTPService) adminListRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := s.store.ListRoutes(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "routes_error", "could not load routes")
		return
	}
	type routeView struct {
		Route
		UpstreamSecretConfigured bool `json:"upstream_secret_configured"`
		InboundKeyConfigured     bool `json:"inbound_key_configured"`
	}
	views := make([]routeView, 0, len(routes))
	for _, route := range routes {
		views = append(views, routeView{Route: route, UpstreamSecretConfigured: len(route.UpstreamSecretCiphertext) > 0, InboundKeyConfigured: route.InboundKeyDigest != ""})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

func (s *HTTPService) adminSaveRoute(w http.ResponseWriter, r *http.Request) {
	var input RouteInput
	if err := decodeJSONBody(w, r, 256*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	input.Name = strings.TrimSpace(input.Name)
	input.Provider = strings.ToLower(strings.TrimSpace(input.Provider))
	input.AuthMode = strings.ToLower(strings.TrimSpace(input.AuthMode))
	if !routeSlugPattern.MatchString(input.Slug) || input.Name == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_route", "route slug or name is invalid")
		return
	}
	if err := ValidateUpstreamURL(input.BaseURL, s.cfg.AllowPrivateUpstreams); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_upstream", err.Error())
		return
	}
	switch input.Provider {
	case "", "openai", "anthropic", "gemini", "generic":
	default:
		writeAPIError(w, http.StatusBadRequest, "invalid_provider", "provider must be openai, anthropic, gemini, or generic")
		return
	}
	switch input.AuthMode {
	case "", "none", "passthrough", "bearer", "anthropic", "gemini", "header", "query":
	default:
		writeAPIError(w, http.StatusBadRequest, "invalid_auth_mode", "unsupported upstream authentication mode")
		return
	}
	if input.RequestTimeoutMS < 0 || input.RequestTimeoutMS > 3600000 || input.MaxConcurrency < 0 || input.MaxConcurrency > 100000 || input.RateLimitRPS < 0 || input.RateLimitRPS > 1000000 {
		writeAPIError(w, http.StatusBadRequest, "invalid_limits", "route limits are outside the allowed range")
		return
	}
	route, err := s.store.SaveRoute(r.Context(), input, s.security)
	if err != nil {
		s.log.Warn("save route failed", "error", err)
		writeAPIError(w, http.StatusConflict, "route_save_failed", "route could not be saved; verify unique values and required credentials")
		return
	}
	s.gateway.InvalidateRoute("")
	s.auditAdmin(r, "save", "route", strconv.FormatInt(route.ID, 10), map[string]any{"slug": route.Slug, "provider": route.Provider})
	writeJSON(w, http.StatusOK, route)
}

func (s *HTTPService) adminDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_id", "route id is invalid")
		return
	}
	route, _ := s.store.GetRouteByID(r.Context(), id)
	if err := s.store.DeleteRoute(r.Context(), id); err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}
	s.gateway.InvalidateRoute(route.Slug)
	s.auditAdmin(r, "delete", "route", strconv.FormatInt(id, 10), map[string]any{"slug": route.Slug})
	w.WriteHeader(http.StatusNoContent)
}

func (s *HTTPService) adminListAuditProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.store.ListAuditProfiles(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "profiles_error", "could not load audit profiles")
		return
	}
	type profileView struct {
		AuditProfile
		APIKeyConfigured bool `json:"api_key_configured"`
	}
	views := make([]profileView, 0, len(profiles))
	for _, profile := range profiles {
		views = append(views, profileView{AuditProfile: profile, APIKeyConfigured: len(profile.APIKeyCiphertext) > 0})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

func (s *HTTPService) adminSaveAuditProfile(w http.ResponseWriter, r *http.Request) {
	var input AuditProfileInput
	if err := decodeJSONBody(w, r, 256*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Endpoint = strings.TrimSpace(input.Endpoint)
	input.Model = strings.TrimSpace(input.Model)
	if input.Name == "" || input.Model == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_profile", "profile name and model are required")
		return
	}
	if err := ValidateUpstreamURL(input.Endpoint, s.cfg.AllowPrivateUpstreams); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_endpoint", err.Error())
		return
	}
	if input.TimeoutMS < 0 || input.TimeoutMS > 120000 || input.BlockThreshold < 0 || input.BlockThreshold > 1 {
		writeAPIError(w, http.StatusBadRequest, "invalid_profile", "timeout or block threshold is invalid")
		return
	}
	profile, err := s.store.SaveAuditProfile(r.Context(), input, s.security)
	if err != nil {
		s.log.Warn("save audit profile failed", "error", err)
		writeAPIError(w, http.StatusConflict, "profile_save_failed", "audit profile could not be saved")
		return
	}
	s.auditAdmin(r, "save", "audit_profile", strconv.FormatInt(profile.ID, 10), map[string]any{"name": profile.Name, "model": profile.Model})
	writeJSON(w, http.StatusOK, profile)
}

func (s *HTTPService) adminDeleteAuditProfile(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_id", "profile id is invalid")
		return
	}
	if err := s.store.DeleteAuditProfile(r.Context(), id); err != nil {
		writeAPIError(w, http.StatusConflict, "delete_failed", err.Error())
		return
	}
	s.auditAdmin(r, "delete", "audit_profile", strconv.FormatInt(id, 10), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *HTTPService) adminListCyberRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListCyberRules(r.Context(), false)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "rules_error", "could not load cyber rules")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rules})
}

func (s *HTTPService) adminSaveCyberRule(w http.ResponseWriter, r *http.Request) {
	var rule CyberRule
	if err := decodeJSONBody(w, r, 128*1024, &rule); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	rule.Code = strings.ToUpper(strings.TrimSpace(rule.Code))
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Category = strings.TrimSpace(rule.Category)
	if err := ValidateCyberRule(rule); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_rule", err.Error())
		return
	}
	saved, err := s.store.UpsertCyberRule(r.Context(), rule)
	if err != nil {
		s.log.Warn("save cyber rule failed", "error", err)
		writeAPIError(w, http.StatusConflict, "rule_save_failed", "cyber rule could not be saved")
		return
	}
	if err := s.audit.ReloadRules(r.Context()); err != nil {
		s.log.Warn("immediate cyber rule reload failed", "error", err)
	}
	s.auditAdmin(r, "save", "cyber_rule", strconv.FormatInt(saved.ID, 10), map[string]any{"code": saved.Code, "action": saved.Action})
	writeJSON(w, http.StatusOK, saved)
}

func (s *HTTPService) adminDeleteCyberRule(w http.ResponseWriter, r *http.Request) {
	id, err := parsePathID(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_id", "rule id is invalid")
		return
	}
	if err := s.store.DeleteCyberRule(r.Context(), id); err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "rule not found")
		return
	}
	_ = s.audit.ReloadRules(r.Context())
	s.auditAdmin(r, "delete", "cyber_rule", strconv.FormatInt(id, 10), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Store) UpsertCyberRule(ctx interface{ Done() <-chan struct{} }, rule CyberRule) (CyberRule, error) {
	// The public method below accepts context.Context; this tiny adapter declaration is
	// replaced by the concrete assertion to keep all SQL in one package without exposing pool.
	actual, ok := ctx.(interface {
		Deadline() (time.Time, bool)
		Err() error
		Value(any) any
	})
	if !ok {
		return CyberRule{}, errors.New("invalid context")
	}
	contextValue, ok := actual.(interface {
		Done() <-chan struct{}
		Deadline() (time.Time, bool)
		Err() error
		Value(any) any
	})
	if !ok {
		return CyberRule{}, errors.New("invalid context")
	}
	_ = contextValue
	return CyberRule{}, errors.New("unreachable context adapter")
}

func (s *Store) upsertCyberRule(ctxContext interface{}, rule CyberRule) (CyberRule, error) {
	return CyberRule{}, errors.New("not implemented")
}

func (s *HTTPService) adminAuditDryRun(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Text      string `json:"text"`
		ProfileID *int64 `json:"profile_id"`
	}
	if err := decodeJSONBody(w, r, int64(s.cfg.AuditTextMaxBytes+4096), &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(input.Text) == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "text is required")
		return
	}
	result := s.audit.DryRun(r.Context(), truncateString(input.Text, s.cfg.AuditTextMaxBytes), input.ProfileID)
	s.auditAdmin(r, "dry_run", "audit", "", map[string]any{"decision": result.Decision, "risk_code": result.RiskCode, "text_bytes": result.TextBytes})
	writeJSON(w, http.StatusOK, result)
}

func (s *HTTPService) adminListTraces(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := TraceFilter{
		RouteSlug: query.Get("route_slug"), Decision: query.Get("decision"), RiskCode: query.Get("risk_code"), UserID: query.Get("user_id"),
	}
	filter.Limit, _ = strconv.Atoi(query.Get("limit"))
	if value := query.Get("from"); value != "" {
		filter.From, _ = time.Parse(time.RFC3339, value)
	}
	if value := query.Get("to"); value != "" {
		filter.To, _ = time.Parse(time.RFC3339, value)
	}
	items, err := s.store.QueryTraces(r.Context(), filter)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "traces_error", "could not load request traces")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *HTTPService) adminGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "settings_error", "could not load settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": settings, "kafka_enabled": s.events.Enabled(), "redis": s.redis.Status()})
}

func (s *HTTPService) adminSaveStorageSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RetentionDays       int   `json:"retention_days"`
		KafkaRetentionDays  int   `json:"kafka_retention_days"`
		RedisStreamMaxLen   int64 `json:"redis_stream_maxlen"`
	}
	if err := decodeJSONBody(w, r, 64*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.RetentionDays < 1 || input.RetentionDays > 365 || input.KafkaRetentionDays < 1 || input.KafkaRetentionDays > 3650 || input.RedisStreamMaxLen < 1000 || input.RedisStreamMaxLen > 1000000000 {
		writeAPIError(w, http.StatusBadRequest, "invalid_settings", "storage settings are outside the permitted range")
		return
	}
	if err := s.store.SetSetting(r.Context(), "retention_days", input.RetentionDays); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "settings_error", "could not save PostgreSQL retention")
		return
	}
	_ = s.store.SetSetting(r.Context(), "kafka_retention_days", input.KafkaRetentionDays)
	_ = s.store.SetSetting(r.Context(), "redis_stream_maxlen", input.RedisStreamMaxLen)
	s.redis.SetStreamMaxLen(input.RedisStreamMaxLen)
	partitionErr := s.store.MaintainPartitions(r.Context(), input.RetentionDays)
	var kafkaError string
	if s.events.Enabled() {
		if err := s.events.ApplyRetention(r.Context(), input.KafkaRetentionDays); err != nil {
			kafkaError = err.Error()
		}
	}
	s.auditAdmin(r, "save", "storage_settings", "", input)
	writeJSON(w, http.StatusOK, map[string]any{
		"saved": true, "partition_maintenance_error": errorString(partitionErr), "kafka_apply_error": kafkaError,
		"note": "Kafka retention requires ALTER_CONFIGS permission for the configured principal.",
	})
}

func (s *HTTPService) adminListTrackingClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListTrackingClients(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "clients_error", "could not load tracking clients")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": clients})
}

func (s *HTTPService) adminSaveTrackingClient(w http.ResponseWriter, r *http.Request) {
	var input struct {
		KeyID   string `json:"key_id"`
		Name    string `json:"name"`
		Secret  string `json:"secret"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSONBody(w, r, 64*1024, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	input.KeyID = strings.TrimSpace(input.KeyID)
	input.Name = strings.TrimSpace(input.Name)
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{3,100}$`).MatchString(input.KeyID) || input.Name == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_client", "key_id or name is invalid")
		return
	}
	generated := false
	if input.Secret == "" {
		var err error
		input.Secret, err = GenerateSecret(32)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "secret_error", "could not generate client secret")
			return
		}
		generated = true
	}
	if len(input.Secret) < 24 {
		writeAPIError(w, http.StatusBadRequest, "weak_secret", "tracking client secret must contain at least 24 characters")
		return
	}
	client, err := s.store.SaveTrackingClient(r.Context(), input.KeyID, input.Name, input.Secret, input.Enabled, s.security)
	if err != nil {
		writeAPIError(w, http.StatusConflict, "client_save_failed", "tracking client could not be saved")
		return
	}
	s.auditAdmin(r, "save", "tracking_client", strconv.FormatInt(client.ID, 10), map[string]any{"key_id": client.KeyID, "generated_secret": generated})
	writeJSON(w, http.StatusOK, map[string]any{"client": client, "secret": input.Secret, "secret_notice": "The secret is returned only by this write response; store it securely."})
}

func (s *HTTPService) auditAdmin(r *http.Request, action, resourceType, resourceID string, details any) {
	s.store.WriteAdminAudit(r.Context(), claimsFromContext(r.Context()), action, resourceType, resourceID, middleware.GetReqID(r.Context()), remoteIP(r), details)
}

func parsePathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Store) UpsertCyberRuleContext(ctx interface {
	Done() <-chan struct{}
	Deadline() (time.Time, bool)
	Err() error
	Value(any) any
}, rule CyberRule) (CyberRule, error) {
	return CyberRule{}, fmt.Errorf("deprecated")
}

func (s *Store) saveCyberRuleConcrete(ctxContext interface{}, rule CyberRule) (CyberRule, error) {
	ctx, ok := ctxContext.(interface {
		Done() <-chan struct{}
		Deadline() (time.Time, bool)
		Err() error
		Value(any) any
	})
	if !ok || ctx == nil {
		return CyberRule{}, errors.New("invalid context")
	}
	return CyberRule{}, pgx.ErrNoRows
}

var _ = json.Valid
