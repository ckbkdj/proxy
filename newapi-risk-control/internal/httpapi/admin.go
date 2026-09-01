package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/gateway"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
	"github.com/jackc/pgx/v5"
)

func (s *Server) adminDispatch(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/api/v1/"), "/")
	switch {
	case path == "runtime":
		s.handleRuntime(w, r)
	case path == "routes":
		s.handleRoutes(w, r)
	case strings.HasPrefix(path, "routes/"):
		s.handleRoute(w, r, strings.TrimPrefix(path, "routes/"))
	case path == "audit-profiles":
		s.handleProfiles(w, r)
	case strings.HasPrefix(path, "audit-profiles/"):
		s.handleProfile(w, r, strings.TrimPrefix(path, "audit-profiles/"))
	case path == "rules":
		s.handleRules(w, r)
	case strings.HasPrefix(path, "rules/"):
		s.handleRule(w, r, strings.TrimPrefix(path, "rules/"))
	case path == "traces":
		s.handleTraces(w, r)
	case path == "storage-policy":
		s.handleStoragePolicy(w, r)
	case path == "audit/dry-run":
		s.handleAuditDryRun(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !requireRole(w, r, "admin", "operator", "auditor", "viewer") {
		return
	}
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "runtime_stats_unavailable")
		return
	}
	policy, err := s.store.GetStoragePolicy(r.Context())
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "storage_policy_unavailable")
		return
	}
	redisHealthy := false
	if s.redis.Enabled() {
		ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
		redisHealthy = s.redis.Ping(ctx) == nil
		cancel()
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"stats":          stats,
		"storage_policy": policy,
		"components": map[string]interface{}{
			"postgres": true, "redis_enabled": s.redis.Enabled(),
			"redis_healthy": redisHealthy, "kafka_enabled": s.kafka.Enabled(),
		},
		"limits": map[string]interface{}{
			"max_request_bytes": s.cfg.MaxRequestBytes, "max_response_bytes": s.cfg.MaxResponseBytes,
			"max_sse_frame_bytes": s.cfg.MaxSSEFrameBytes,
		},
	})
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, "admin", "operator", "auditor", "viewer") {
			return
		}
		routes, err := s.store.ListRoutes(r.Context())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "list_routes_failed")
			return
		}
		items := make([]map[string]interface{}, 0, len(routes))
		for _, route := range routes {
			items = append(items, routeView(route, s.cfg.PublicBaseURL))
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"items": items})
	case http.MethodPost:
		if !requireRole(w, r, "admin", "operator") {
			return
		}
		var input core.RouteWrite
		if !decodeJSON(w, r, 1<<20, &input) {
			return
		}
		route, token, err := s.prepareRoute(r, input, nil)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := s.store.UpsertRoute(r.Context(), route)
		if err != nil {
			jsonError(w, http.StatusConflict, "save_route_failed")
			return
		}
		s.gateway.InvalidateRoute(saved.Slug)
		s.auditAdmin(r, "create", "route", saved.ID, nil, saved)
		view := routeView(saved, s.cfg.PublicBaseURL)
		if token != "" {
			view["client_token"] = token
			view["client_token_note"] = "shown_once"
		}
		jsonResponse(w, http.StatusCreated, view)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, id string) {
	id = bounded(id, 64)
	if id == "" {
		http.NotFound(w, r)
		return
	}
	before, err := s.store.GetRouteByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			jsonError(w, http.StatusInternalServerError, "route_lookup_failed")
		}
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !requireRole(w, r, "admin", "operator") {
			return
		}
		var input core.RouteWrite
		if !decodeJSON(w, r, 1<<20, &input) {
			return
		}
		input.ID = id
		route, token, err := s.prepareRoute(r, input, &before)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := s.store.UpsertRoute(r.Context(), route)
		if err != nil {
			jsonError(w, http.StatusConflict, "save_route_failed")
			return
		}
		s.gateway.InvalidateRoute(before.Slug)
		s.gateway.InvalidateRoute(saved.Slug)
		s.auditAdmin(r, "update", "route", id, before, saved)
		view := routeView(saved, s.cfg.PublicBaseURL)
		if token != "" {
			view["client_token"] = token
			view["client_token_note"] = "shown_once"
		}
		jsonResponse(w, http.StatusOK, view)
	case http.MethodDelete:
		if !requireRole(w, r, "admin") {
			return
		}
		if err := s.store.DeleteRoute(r.Context(), id); err != nil {
			jsonError(w, http.StatusConflict, "delete_route_failed")
			return
		}
		s.gateway.InvalidateRoute(before.Slug)
		s.auditAdmin(r, "delete", "route", id, before, nil)
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) prepareRoute(r *http.Request, input core.RouteWrite, current *core.Route) (core.Route, string, error) {
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	if ok, _ := regexp.MatchString(`^[a-z0-9][a-z0-9_-]{1,62}$`, input.Slug); !ok {
		return core.Route{}, "", errors.New("invalid_route_slug")
	}
	if strings.TrimSpace(input.Name) == "" {
		return core.Route{}, "", errors.New("route_name_required")
	}
	kind := strings.ToLower(strings.TrimSpace(input.UpstreamKind))
	switch kind {
	case "openai", "anthropic", "gemini", "custom":
	default:
		return core.Route{}, "", errors.New("unsupported_upstream_kind")
	}

	parsed, err := url.Parse(strings.TrimSpace(input.UpstreamBaseURL))
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return core.Route{}, "", errors.New("invalid_upstream_url")
	}
	allowPrivate := s.cfg.AllowPrivateUpstreams && input.AllowPrivateUpstream
	if err := gateway.ValidateUpstreamURL(r.Context(), input.UpstreamBaseURL, allowPrivate); err != nil {
		return core.Route{}, "", errors.New("invalid_or_unsafe_upstream_url")
	}
	if s.cfg.Production() && !allowPrivate && parsed.Scheme != "https" {
		return core.Route{}, "", errors.New("production_upstream_requires_https")
	}

	if input.RateLimitRPS <= 0 {
		input.RateLimitRPS = 100
	}
	if input.RateLimitBurst <= 0 {
		input.RateLimitBurst = 200
	}
	if input.MaxInflight <= 0 {
		input.MaxInflight = 1000
	}
	if input.RequestTimeoutMS <= 0 {
		input.RequestTimeoutMS = 300000
	}
	if input.RateLimitRPS > 1000000 || input.RateLimitBurst > 10000000 ||
		input.MaxInflight > 1000000 || input.RequestTimeoutMS > 3600000 {
		return core.Route{}, "", errors.New("route_limit_out_of_range")
	}

	var policy json.RawMessage
	if len(input.UpstreamErrorPolicy) == 0 && current != nil {
		policy = current.UpstreamErrorPolicy
	} else {
		policy, err = normalizeErrorPolicy(input.UpstreamErrorPolicy)
		if err != nil {
			return core.Route{}, "", err
		}
	}
	route := core.Route{
		ID: input.ID, Slug: input.Slug, Name: bounded(input.Name, 256),
		UpstreamBaseURL: strings.TrimRight(strings.TrimSpace(input.UpstreamBaseURL), "/"),
		UpstreamKind: kind, AuditProfileID: input.AuditProfileID, Enabled: input.Enabled,
		RateLimitRPS: input.RateLimitRPS, RateLimitBurst: input.RateLimitBurst,
		MaxInflight: input.MaxInflight, RequestTimeoutMS: input.RequestTimeoutMS,
		AllowPrivateUpstream: input.AllowPrivateUpstream, UpstreamErrorPolicy: policy,
	}
	if current != nil {
		route.UpstreamAPIKeyCipher = current.UpstreamAPIKeyCipher
		route.ClientTokenHash = current.ClientTokenHash
		route.ExtraHeadersEncrypted = current.ExtraHeadersEncrypted
	}
	if input.UpstreamAPIKey != "" {
		route.UpstreamAPIKeyCipher, err = s.cipher.EncryptString(input.UpstreamAPIKey)
		if err != nil {
			return core.Route{}, "", errors.New("encrypt_upstream_key_failed")
		}
	}
	if current == nil && route.UpstreamAPIKeyCipher == "" && kind != "custom" {
		return core.Route{}, "", errors.New("upstream_api_key_required")
	}

	shownToken := input.ClientToken
	if shownToken == "" && current == nil {
		shownToken, err = security.RandomToken(32)
		if err != nil {
			return core.Route{}, "", errors.New("generate_client_token_failed")
		}
	}
	if shownToken != "" {
		route.ClientTokenHash = security.HashOpaque(s.cfg.PromptHashSecret, shownToken)
	}
	if current == nil && route.ClientTokenHash == "" {
		return core.Route{}, "", errors.New("client_token_required")
	}
	if input.ExtraHeaders != nil {
		raw, _ := json.Marshal(input.ExtraHeaders)
		route.ExtraHeadersEncrypted, err = s.cipher.EncryptString(string(raw))
		if err != nil {
			return core.Route{}, "", errors.New("encrypt_headers_failed")
		}
	}
	return route, shownToken, nil
}

func routeView(route core.Route, publicBase string) map[string]interface{} {
	raw, _ := json.Marshal(route)
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	out["newapi_base_url"] = strings.TrimRight(publicBase, "/") + "/gateway/" + route.Slug
	out["has_upstream_api_key"] = route.UpstreamAPIKeyCipher != ""
	out["has_client_token"] = route.ClientTokenHash != ""
	out["has_extra_headers"] = route.ExtraHeadersEncrypted != ""
	return out
}

func normalizeErrorPolicy(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return json.Marshal(core.DefaultUpstreamErrorPolicy())
	}
	var policy core.UpstreamErrorPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, errors.New("invalid_upstream_error_policy")
	}
	if len(policy.NormalizeStatuses) > 100 || len(policy.NormalizeCodes) > 100 ||
		len(policy.MessagePatterns) > 50 || len(policy.PassStatuses) > 100 {
		return nil, errors.New("upstream_error_policy_too_large")
	}
	for _, pattern := range policy.MessagePatterns {
		if len(pattern) > 1024 {
			return nil, errors.New("error_pattern_too_long")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, errors.New("invalid_error_pattern")
		}
	}
	return json.Marshal(policy)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, "admin", "operator", "auditor", "viewer") {
			return
		}
		items, err := s.store.ListAuditProfiles(r.Context())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "list_profiles_failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"items": items})
	case http.MethodPost:
		if !requireRole(w, r, "admin", "operator") {
			return
		}
		var input core.AuditProfileWrite
		if !decodeJSON(w, r, 1<<20, &input) {
			return
		}
		profile, err := s.prepareProfile(r, input, nil)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := s.store.UpsertAuditProfile(r.Context(), profile)
		if err != nil {
			jsonError(w, http.StatusConflict, "save_profile_failed")
			return
		}
		s.auditAdmin(r, "create", "audit_profile", saved.ID, nil, saved)
		jsonResponse(w, http.StatusCreated, saved)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request, id string) {
	before, err := s.store.GetAuditProfile(r.Context(), bounded(id, 64))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			jsonError(w, http.StatusInternalServerError, "profile_lookup_failed")
		}
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !requireRole(w, r, "admin", "operator") {
			return
		}
		var input core.AuditProfileWrite
		if !decodeJSON(w, r, 1<<20, &input) {
			return
		}
		input.ID = before.ID
		profile, err := s.prepareProfile(r, input, &before)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := s.store.UpsertAuditProfile(r.Context(), profile)
		if err != nil {
			jsonError(w, http.StatusConflict, "save_profile_failed")
			return
		}
		s.auditAdmin(r, "update", "audit_profile", saved.ID, before, saved)
		jsonResponse(w, http.StatusOK, saved)
	case http.MethodDelete:
		if !requireRole(w, r, "admin") {
			return
		}
		if err := s.store.DeleteAuditProfile(r.Context(), before.ID); err != nil {
			jsonError(w, http.StatusConflict, "delete_profile_failed")
			return
		}
		s.auditAdmin(r, "delete", "audit_profile", before.ID, before, nil)
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) prepareProfile(r *http.Request, input core.AuditProfileWrite, current *core.AuditProfile) (core.AuditProfile, error) {
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Model) == "" {
		return core.AuditProfile{}, errors.New("profile_name_and_model_required")
	}
	parsed, err := url.Parse(strings.TrimSpace(input.Endpoint))
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return core.AuditProfile{}, errors.New("invalid_audit_endpoint")
	}
	if err := gateway.ValidateUpstreamURL(r.Context(), input.Endpoint, s.cfg.AllowPrivateUpstreams); err != nil {
		return core.AuditProfile{}, errors.New("invalid_or_unsafe_audit_endpoint")
	}
	if s.cfg.Production() && !s.cfg.AllowPrivateUpstreams && parsed.Scheme != "https" {
		return core.AuditProfile{}, errors.New("production_audit_endpoint_requires_https")
	}
	if input.FailMode == "" {
		input.FailMode = "closed"
	}
	if input.FailMode != "closed" && input.FailMode != "open" && input.FailMode != "shadow" {
		return core.AuditProfile{}, errors.New("invalid_fail_mode")
	}
	if input.BlockThreshold <= 0 {
		input.BlockThreshold = .72
	}
	if input.BlockThreshold > 1 {
		return core.AuditProfile{}, errors.New("invalid_block_threshold")
	}
	if input.TimeoutMS <= 0 {
		input.TimeoutMS = 8000
	}
	if input.TimeoutMS > 120000 {
		return core.AuditProfile{}, errors.New("invalid_timeout")
	}
	if input.MaxInputChars <= 0 {
		input.MaxInputChars = 32000
	}
	if input.MaxInputChars > 262144 {
		return core.AuditProfile{}, errors.New("max_input_too_large")
	}
	if input.CacheTTLSeconds < 0 || input.CacheTTLSeconds > 86400 {
		return core.AuditProfile{}, errors.New("invalid_cache_ttl")
	}
	if len(input.SystemPrompt) > 32768 {
		return core.AuditProfile{}, errors.New("system_prompt_too_large")
	}
	profile := core.AuditProfile{
		ID: input.ID, Name: bounded(input.Name, 256),
		Endpoint: strings.TrimRight(strings.TrimSpace(input.Endpoint), "/"),
		Model: bounded(input.Model, 256), Enabled: input.Enabled,
		FailMode: input.FailMode, BlockThreshold: input.BlockThreshold,
		TimeoutMS: input.TimeoutMS, MaxInputChars: input.MaxInputChars,
		CacheTTLSeconds: input.CacheTTLSeconds, SystemPrompt: input.SystemPrompt,
	}
	if current != nil {
		profile.APIKeyCipher = current.APIKeyCipher
	}
	if input.APIKey != "" {
		profile.APIKeyCipher, err = s.cipher.EncryptString(input.APIKey)
		if err != nil {
			return core.AuditProfile{}, errors.New("encrypt_audit_key_failed")
		}
	}
	return profile, nil
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, "admin", "operator", "auditor", "viewer") {
			return
		}
		items, err := s.store.ListRules(r.Context(), false)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "list_rules_failed")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]interface{}{"items": items})
	case http.MethodPost:
		if !requireRole(w, r, "admin", "operator") {
			return
		}
		var rule core.RiskRule
		if !decodeJSON(w, r, 256<<10, &rule) {
			return
		}
		if err := validateRule(&rule); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		rule.ID = ""
		rule.Builtin = false
		saved, err := s.store.UpsertRule(r.Context(), rule)
		if err != nil {
			jsonError(w, http.StatusConflict, "save_rule_failed")
			return
		}
		_ = s.audit.Refresh(r.Context())
		s.auditAdmin(r, "create", "risk_rule", saved.ID, nil, saved)
		jsonResponse(w, http.StatusCreated, saved)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleRule(w http.ResponseWriter, r *http.Request, id string) {
	before, err := s.store.GetRule(r.Context(), bounded(id, 64))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			jsonError(w, http.StatusInternalServerError, "rule_lookup_failed")
		}
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !requireRole(w, r, "admin", "operator") {
			return
		}
		if before.Builtin && claimsFrom(r.Context()).Role != "admin" {
			jsonError(w, http.StatusForbidden, "builtin_rule_requires_admin")
			return
		}
		var rule core.RiskRule
		if !decodeJSON(w, r, 256<<10, &rule) {
			return
		}
		if err := validateRule(&rule); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		rule.ID = before.ID
		rule.Builtin = before.Builtin
		saved, err := s.store.UpsertRule(r.Context(), rule)
		if err != nil {
			jsonError(w, http.StatusConflict, "save_rule_failed")
			return
		}
		_ = s.audit.Refresh(r.Context())
		s.auditAdmin(r, "update", "risk_rule", saved.ID, before, saved)
		jsonResponse(w, http.StatusOK, saved)
	case http.MethodDelete:
		if !requireRole(w, r, "admin") {
			return
		}
		if before.Builtin {
			jsonError(w, http.StatusConflict, "builtin_rule_cannot_be_deleted")
			return
		}
		if err := s.store.DeleteRule(r.Context(), before.ID); err != nil {
			jsonError(w, http.StatusConflict, "delete_rule_failed")
			return
		}
		_ = s.audit.Refresh(r.Context())
		s.auditAdmin(r, "delete", "risk_rule", before.ID, before, nil)
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func validateRule(rule *core.RiskRule) error {
	rule.Name = bounded(rule.Name, 256)
	rule.Category = bounded(rule.Category, 128)
	if rule.Name == "" || rule.Category == "" || rule.Pattern == "" {
		return errors.New("rule_fields_required")
	}
	if len(rule.Pattern) > 4096 {
		return errors.New("rule_pattern_too_large")
	}
	if _, err := regexp.Compile(rule.Pattern); err != nil {
		return errors.New("invalid_rule_regex")
	}
	if rule.Action == "" {
		rule.Action = "block"
	}
	if rule.Action != "block" && rule.Action != "review" && rule.Action != "allow" {
		return errors.New("invalid_rule_action")
	}
	if rule.Score < 0 || rule.Score > 1 {
		return errors.New("invalid_rule_score")
	}
	return nil
}

func (s *Server) handleTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !requireRole(w, r, "admin", "operator", "auditor", "viewer") {
		return
	}
	from, err := parseTime(r.URL.Query().Get("from"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_from_time")
		return
	}
	to, err := parseTime(r.URL.Query().Get("to"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_to_time")
		return
	}
	items, err := s.store.ListTraces(r.Context(), store.TraceFilter{
		RequestID: bounded(r.URL.Query().Get("request_id"), 256),
		RouteSlug: bounded(r.URL.Query().Get("route"), 64),
		Outcome:   bounded(r.URL.Query().Get("outcome"), 64),
		Model:     bounded(r.URL.Query().Get("model"), 256),
		From: from, To: to,
		Limit: store.ParseLimit(r.URL.Query().Get("limit"), 100),
		Offset: store.ParseLimit(r.URL.Query().Get("offset"), 0),
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "list_traces_failed")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"items": items})
}

func (s *Server) handleStoragePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, "admin", "operator", "auditor", "viewer") {
			return
		}
		policy, err := s.store.GetStoragePolicy(r.Context())
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "get_storage_policy_failed")
			return
		}
		jsonResponse(w, http.StatusOK, policy)
	case http.MethodPut:
		if !requireRole(w, r, "admin") {
			return
		}
		var input core.StoragePolicy
		if !decodeJSON(w, r, 128<<10, &input) {
			return
		}
		if input.StoreRawPrompt {
			jsonError(w, http.StatusBadRequest, "raw_prompt_storage_forbidden")
			return
		}
		if input.RetentionDays < 1 || input.RetentionDays > 3650 ||
			input.RedisBufferTTLHours < 1 || input.RedisBufferTTLHours > 8760 ||
			input.KafkaRetentionHours < 1 || input.KafkaRetentionHours > 87600 {
			jsonError(w, http.StatusBadRequest, "storage_policy_out_of_range")
			return
		}
		if input.KafkaEnabled && !s.kafka.Enabled() {
			jsonError(w, http.StatusBadRequest, "kafka_not_configured")
			return
		}
		if !input.PostgresEnabled && !input.RedisBufferEnabled && !input.KafkaEnabled {
			jsonError(w, http.StatusBadRequest, "at_least_one_storage_sink_required")
			return
		}
		before, _ := s.store.GetStoragePolicy(r.Context())
		saved, err := s.store.SetStoragePolicy(r.Context(), input)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "save_storage_policy_failed")
			return
		}
		s.auditAdmin(r, "update", "storage_policy", "singleton", before, saved)
		jsonResponse(w, http.StatusOK, saved)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleAuditDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !requireRole(w, r, "admin", "operator", "auditor") {
		return
	}
	var input struct {
		ProfileID *string         `json:"profile_id"`
		Payload   json.RawMessage `json:"payload"`
		Text      string          `json:"text"`
	}
	if !decodeJSON(w, r, 2<<20, &input) {
		return
	}
	payload := input.Payload
	if len(payload) == 0 {
		payload, _ = json.Marshal(map[string]interface{}{
			"messages": []map[string]string{{"role": "user", "content": input.Text}},
		})
	}
	decision, hash := s.audit.Audit(r.Context(), input.ProfileID, payload)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"decision": decision, "prompt_hash": hash,
	})
}
