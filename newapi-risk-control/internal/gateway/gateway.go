package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/audit"
	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/pipeline"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
	"github.com/jackc/pgx/v5"
)

const RiskHTTPStatus = 555

type cachedRoute struct {
	route   core.Route
	expires time.Time
}

type Gateway struct {
	cfg         config.Config
	store       *store.Store
	redis       *cache.Redis
	cipher      *security.Cipher
	audit       *audit.Engine
	traces      *pipeline.Pipeline
	log         *slog.Logger
	publicHTTP  *http.Client
	privateHTTP *http.Client
	routeMu     sync.RWMutex
	routes      map[string]cachedRoute
	limiter     *localLimiter
	inflight    *localInflight
}

func New(
	cfg config.Config,
	st *store.Store,
	rc *cache.Redis,
	cipher *security.Cipher,
	auditEngine *audit.Engine,
	traces *pipeline.Pipeline,
	log *slog.Logger,
) *Gateway {
	return &Gateway{
		cfg: cfg, store: st, redis: rc, cipher: cipher, audit: auditEngine,
		traces: traces, log: log, routes: make(map[string]cachedRoute),
		limiter: newLocalLimiter(), inflight: newLocalInflight(),
		publicHTTP:  newHTTPClient(cfg, false),
		privateHTTP: newHTTPClient(cfg, true),
	}
}

func (g *Gateway) InvalidateRoute(slug string) {
	g.routeMu.Lock()
	delete(g.routes, slug)
	g.routeMu.Unlock()
	g.redis.DeleteRoute(context.Background(), slug)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := requestID(r)
	trace := core.Trace{
		ID:                security.NewUUID(),
		ExternalRequestID: requestID,
		ParentRequestID:   boundedHeader(r.Header.Get("X-NewAPI-Parent-Request-ID"), 256),
		Method:            r.Method,
		Path:              r.URL.Path,
		CreatedAt:         started.UTC(),
		ClientIPHash:      security.HashOpaque(g.cfg.PromptHashSecret, g.clientIP(r)),
		UserAgentHash:     security.HashOpaque(g.cfg.PromptHashSecret, r.UserAgent()),
	}
	w.Header().Set("X-Risk-Request-ID", requestID)
	defer func() {
		trace.TotalLatencyMS = time.Since(started).Milliseconds()
		g.traces.Emit(trace)
	}()

	slug, upstreamPath, ok := parseGatewayPath(r.URL.Path)
	if !ok {
		trace.Outcome = "route_not_found"
		trace.HTTPStatus = http.StatusNotFound
		http.NotFound(w, r)
		return
	}
	trace.RouteSlug = slug

	route, err := g.getRoute(r.Context(), slug)
	if err != nil {
		trace.Outcome = "route_not_found"
		trace.HTTPStatus = http.StatusNotFound
		if !errors.Is(err, pgx.ErrNoRows) {
			g.log.Error("route lookup failed", "error", err, "slug", slug, "request_id", requestID)
		}
		http.NotFound(w, r)
		return
	}
	trace.RouteID = &route.ID
	trace.Provider = route.UpstreamKind
	if !route.Enabled {
		trace.Outcome = "route_disabled"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		write555(w, requestID, "ROUTE_DISABLED")
		return
	}

	clientToken := extractClientToken(r)
	trace.APIKeyHash = security.HashOpaque(g.cfg.PromptHashSecret, clientToken)
	if clientToken == "" || !security.EqualHash(g.cfg.PromptHashSecret, clientToken, route.ClientTokenHash) {
		trace.Outcome = "gateway_auth_failed"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		write555(w, requestID, "GATEWAY_AUTH_FAILED")
		return
	}
	trace.TenantID = boundedHeader(r.Header.Get("X-NewAPI-Tenant-ID"), 128)
	trace.UserIDHash = security.HashOpaque(g.cfg.PromptHashSecret, boundedHeader(r.Header.Get("X-NewAPI-User-ID"), 512))

	limitScope := route.ID + ":" + trace.APIKeyHash
	allowed, rateSource := g.allow(r.Context(), limitScope, route.RateLimitRPS, route.RateLimitBurst)
	if !allowed {
		trace.Outcome = "rate_limited"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		w.Header().Set("Retry-After", "1")
		w.Header().Set("X-Risk-Limit-Source", rateSource)
		write555(w, requestID, "GATEWAY_RATE_LIMITED")
		return
	}

	timeout := time.Duration(route.RequestTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	semaphoreToken := security.NewUUID()
	release, acquired := g.acquire(r.Context(), route.ID, semaphoreToken, route.MaxInflight, timeout+30*time.Second)
	if !acquired {
		trace.Outcome = "concurrency_limited"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		write555(w, requestID, "GATEWAY_BUSY")
		return
	}
	defer release()

	body, err := readLimited(r.Body, g.cfg.MaxRequestBytes)
	if err != nil {
		trace.Outcome = "request_too_large"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		write555(w, requestID, "REQUEST_TOO_LARGE")
		return
	}
	trace.RequestBytes = int64(len(body))
	trace.Model, trace.Stream = extractModelAndStream(body)

	decision, promptHash := g.audit.Audit(r.Context(), route.AuditProfileID, body)
	trace.PromptHash = promptHash
	trace.RiskCategory = decision.Category
	trace.RiskScore = decision.Score
	trace.RiskReasonCode = decision.ReasonCode
	trace.AuditLatencyMS = decision.AuditLatency
	if !decision.Allowed {
		trace.Outcome = "risk_blocked"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		write555(w, requestID, "RISK_POLICY_BLOCKED")
		return
	}

	upstreamURL, err := buildUpstreamURL(route.UpstreamBaseURL, upstreamPath, r.URL.RawQuery)
	if err != nil {
		trace.Outcome = "invalid_upstream"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		g.log.Error("build upstream URL failed", "error", err, "route", slug, "request_id", requestID)
		write555(w, requestID, "UPSTREAM_CONFIGURATION_ERROR")
		return
	}
	if err := ValidateUpstreamURL(r.Context(), upstreamURL, g.allowPrivate(route)); err != nil {
		trace.Outcome = "invalid_upstream"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		g.log.Error("upstream validation failed", "error", err, "route", slug, "request_id", requestID)
		write555(w, requestID, "UPSTREAM_CONFIGURATION_ERROR")
		return
	}

	requestCtx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	upstreamRequest, err := http.NewRequestWithContext(requestCtx, r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		trace.Outcome = "upstream_request_error"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		write555(w, requestID, "UPSTREAM_REQUEST_ERROR")
		return
	}
	copyRequestHeaders(upstreamRequest.Header, r.Header)
	upstreamRequest.Header.Set("X-Risk-Request-ID", requestID)
	if err := g.applyUpstreamCredentials(upstreamRequest, route); err != nil {
		trace.Outcome = "credential_error"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		g.log.Error("decrypt upstream credentials failed", "error", err, "route", slug, "request_id", requestID)
		write555(w, requestID, "UPSTREAM_CONFIGURATION_ERROR")
		return
	}

	upstreamStarted := time.Now()
	client := g.publicHTTP
	if g.allowPrivate(route) {
		client = g.privateHTTP
	}
	response, err := client.Do(upstreamRequest)
	trace.UpstreamLatencyMS = time.Since(upstreamStarted).Milliseconds()
	if err != nil {
		trace.Outcome = "upstream_transport_error"
		trace.HTTPStatus = RiskHTTPStatus
		trace.NormalizedCode = RiskHTTPStatus
		g.log.Warn("upstream transport error", "error", err, "route", slug, "request_id", requestID)
		write555(w, requestID, "UPSTREAM_UNAVAILABLE")
		return
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		trace.ResponseBytes = int64(len(raw))
		if shouldNormalize(route.UpstreamErrorPolicy, response.StatusCode, raw) {
			trace.Outcome = "upstream_error_normalized"
			trace.HTTPStatus = RiskHTTPStatus
			trace.NormalizedCode = RiskHTTPStatus
			write555(w, requestID, "UPSTREAM_MODEL_ERROR")
			return
		}
		copyResponseHeaders(w.Header(), response.Header)
		trace.Outcome = "upstream_client_error"
		trace.HTTPStatus = response.StatusCode
		w.WriteHeader(response.StatusCode)
		n, _ := w.Write(raw)
		trace.ResponseBytes = int64(n)
		return
	}

	if isSSE(response.Header.Get("Content-Type"), trace.Stream) {
		result := proxySSE(w, response, requestID, g.cfg.MaxSSEFrameBytes, g.cfg.StreamGateBytes, g.cfg.StreamGateTimeout)
		trace.ResponseBytes = result.Bytes
		trace.HTTPStatus = result.Status
		trace.NormalizedCode = result.NormalizedCode
		trace.Outcome = result.Outcome
		return
	}

	copyResponseHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	counter := &countingWriter{writer: w}
	_, copyErr := io.Copy(counter, io.LimitReader(response.Body, g.cfg.MaxResponseBytes+1))
	trace.ResponseBytes = counter.n
	trace.HTTPStatus = response.StatusCode
	trace.Outcome = "allowed"
	if counter.n > g.cfg.MaxResponseBytes {
		trace.Outcome = "response_too_large_after_commit"
		g.log.Warn("upstream response exceeded configured limit", "route", slug, "request_id", requestID, "bytes", counter.n)
	} else if copyErr != nil {
		trace.Outcome = "response_stream_error"
		g.log.Warn("response copy ended early", "error", copyErr, "route", slug, "request_id", requestID)
	}
}

func (g *Gateway) getRoute(ctx context.Context, slug string) (core.Route, error) {
	now := time.Now()
	g.routeMu.RLock()
	entry, ok := g.routes[slug]
	g.routeMu.RUnlock()
	if ok && entry.expires.After(now) {
		return entry.route, nil
	}
	route, err := g.store.GetRouteBySlug(ctx, slug)
	if err != nil {
		return core.Route{}, err
	}
	g.routeMu.Lock()
	g.routes[slug] = cachedRoute{route: route, expires: now.Add(5 * time.Second)}
	g.routeMu.Unlock()
	return route, nil
}

func (g *Gateway) allowPrivate(route core.Route) bool {
	return g.cfg.AllowPrivateUpstreams && route.AllowPrivateUpstream
}

func (g *Gateway) allow(ctx context.Context, scope string, rate float64, burst int) (bool, string) {
	if g.redis.Enabled() {
		allowed, err := g.redis.Allow(ctx, scope, rate, burst)
		if err == nil {
			return allowed, "redis"
		}
	}
	return g.limiter.Allow(scope, rate, burst), "local"
}

func (g *Gateway) acquire(ctx context.Context, scope, token string, limit int, ttl time.Duration) (func(), bool) {
	if limit < 1 {
		limit = 1
	}
	if g.redis.Enabled() {
		acquired, err := g.redis.Acquire(ctx, scope, token, limit, ttl)
		if err == nil {
			if !acquired {
				return func() {}, false
			}
			return func() {
				releaseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = g.redis.Release(releaseCtx, scope, token)
			}, true
		}
	}
	if !g.inflight.Acquire(scope, limit) {
		return func() {}, false
	}
	return func() { g.inflight.Release(scope) }, true
}

func (g *Gateway) applyUpstreamCredentials(req *http.Request, route core.Route) error {
	for _, header := range []string{
		"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key", "X-Goog-Api-Key",
	} {
		req.Header.Del(header)
	}
	apiKey, err := g.cipher.DecryptString(route.UpstreamAPIKeyCipher)
	if err != nil {
		return err
	}
	switch route.UpstreamKind {
	case "anthropic":
		if apiKey != "" {
			req.Header.Set("x-api-key", apiKey)
		}
		if req.Header.Get("anthropic-version") == "" {
			req.Header.Set("anthropic-version", "2023-06-01")
		}
	case "gemini":
		if apiKey != "" {
			req.Header.Set("x-goog-api-key", apiKey)
		}
		query := req.URL.Query()
		query.Del("key")
		req.URL.RawQuery = query.Encode()
	default:
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	if route.ExtraHeadersEncrypted == "" {
		return nil
	}
	raw, err := g.cipher.DecryptString(route.ExtraHeadersEncrypted)
	if err != nil {
		return err
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return err
	}
	for name, value := range headers {
		if safeExtraHeader(name) {
			req.Header.Set(name, value)
		}
	}
	return nil
}

func parseGatewayPath(path string) (slug, rest string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/gateway/")
	if trimmed == path || trimmed == "" {
		return "", "", false
	}
	parts := strings.SplitN(trimmed, "/", 2)
	slug = parts[0]
	if len(parts) == 1 {
		rest = "/"
	} else {
		rest = "/" + parts[1]
	}
	return slug, rest, true
}

func buildUpstreamURL(base, rest, rawQuery string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	basePath := strings.TrimRight(u.Path, "/")
	restPath := "/" + strings.TrimLeft(rest, "/")
	if strings.HasSuffix(basePath, "/v1") && strings.HasPrefix(restPath, "/v1/") {
		restPath = strings.TrimPrefix(restPath, "/v1")
	}
	u.Path = basePath + restPath
	u.RawPath = ""
	u.RawQuery = rawQuery
	return u.String(), nil
}

func ValidateUpstreamURL(ctx context.Context, raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("only http and https upstreams are allowed")
	}
	if u.Hostname() == "" {
		return errors.New("upstream hostname is required")
	}
	if allowPrivate {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return errors.New("private hostname is not allowed")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return errors.New("upstream hostname resolved to no addresses")
	}
	for _, address := range addresses {
		if forbiddenIP(address.IP) {
			return errors.New("upstream resolves to a private or reserved address")
		}
	}
	return nil
}

func forbiddenIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func newHTTPClient(cfg config.Config, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2048,
		MaxIdleConnsPerHost:   512,
		IdleConnTimeout:       cfg.UpstreamIdleTimeout,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: cfg.UpstreamHeaderTimeout,
	}
	if !allowPrivate {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, candidate := range addresses {
				if forbiddenIP(candidate.IP) {
					continue
				}
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errors.New("no permitted upstream address")
		}
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func extractClientToken(r *http.Request) string {
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	for _, name := range []string{"x-api-key", "api-key", "x-goog-api-key"} {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func extractModelAndStream(body []byte) (string, bool) {
	var payload struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &payload)
	return boundedHeader(payload.Model, 256), payload.Stream
}

func requestID(r *http.Request) string {
	for _, header := range []string{"X-Request-ID", "X-NewAPI-Request-ID", "Traceparent"} {
		if value := boundedHeader(r.Header.Get(header), 256); value != "" {
			return value
		}
	}
	return security.NewUUID()
}

func boundedHeader(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}

func (g *Gateway) clientIP(r *http.Request) string {
	if g.cfg.TrustProxyHeaders {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
			return forwarded
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func readLimited(body io.ReadCloser, max int64) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, errors.New("request body too large")
	}
	return raw, nil
}

type countingWriter struct {
	writer io.Writer
	n      int64
}
func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	c.n += int64(n)
	return n, err
}

var hopHeaders = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true,
	"proxy-authenticate": true, "proxy-authorization": true,
	"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
}

func copyRequestHeaders(dst, src http.Header) {
	for name, values := range src {
		lower := strings.ToLower(name)
		if hopHeaders[lower] || lower == "host" || lower == "content-length" || lower == "accept-encoding" {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
func copyResponseHeaders(dst, src http.Header) {
	for name, values := range src {
		if hopHeaders[strings.ToLower(name)] || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
func safeExtraHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower != "" && !hopHeaders[lower] && lower != "host" && lower != "content-length" &&
		lower != "authorization" && lower != "x-api-key" && lower != "api-key" && lower != "x-goog-api-key"
}

func shouldNormalize(raw json.RawMessage, status int, body []byte) bool {
	policy := core.DefaultUpstreamErrorPolicy()
	if len(raw) > 2 {
		var configured core.UpstreamErrorPolicy
		if json.Unmarshal(raw, &configured) == nil {
			if len(configured.NormalizeStatuses) > 0 {
				policy.NormalizeStatuses = configured.NormalizeStatuses
			}
			if len(configured.NormalizeCodes) > 0 {
				policy.NormalizeCodes = configured.NormalizeCodes
			}
			if len(configured.MessagePatterns) > 0 {
				policy.MessagePatterns = configured.MessagePatterns
			}
			if len(configured.PassStatuses) > 0 {
				policy.PassStatuses = configured.PassStatuses
			}
		}
	}
	for _, passStatus := range policy.PassStatuses {
		if status == passStatus {
			return false
		}
	}
	for _, normalizeStatus := range policy.NormalizeStatuses {
		if status == normalizeStatus {
			return true
		}
	}
	lower := strings.ToLower(string(body))
	for _, code := range policy.NormalizeCodes {
		if strings.Contains(lower, strings.ToLower(code)) {
			return true
		}
	}
	for _, pattern := range policy.MessagePatterns {
		if re, err := regexp.Compile(pattern); err == nil && re.Match(body) {
			return true
		}
	}
	return false
}

func write555(w http.ResponseWriter, requestID, class string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Risk-Error-Code", strconv.Itoa(RiskHTTPStatus))
	w.Header().Set("X-Risk-Error-Class", class)
	w.WriteHeader(RiskHTTPStatus)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": "Request rejected by the risk-control gateway.",
			"type":    "risk_control_error",
			"param":   nil,
			"code":    RiskHTTPStatus,
		},
		"request_id": requestID,
	})
}

type bucket struct {
	tokens float64
	last   time.Time
}
type localLimiter struct {
	mu        sync.Mutex
	items     map[string]*bucket
	lastSweep time.Time
}
func newLocalLimiter() *localLimiter {
	return &localLimiter{items: make(map[string]*bucket), lastSweep: time.Now()}
}
func (l *localLimiter) Allow(key string, rate float64, burst int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	item := l.items[key]
	if item == nil {
		item = &bucket{tokens: float64(burst), last: now}
		l.items[key] = item
	}
	elapsed := now.Sub(item.last).Seconds()
	item.tokens = minFloat(float64(burst), item.tokens+elapsed*rate)
	item.last = now
	allowed := item.tokens >= 1
	if allowed {
		item.tokens--
	}
	if now.Sub(l.lastSweep) > time.Minute {
		for itemKey, value := range l.items {
			if now.Sub(value.last) > 10*time.Minute {
				delete(l.items, itemKey)
			}
		}
		l.lastSweep = now
	}
	return allowed
}
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

type localInflight struct {
	mu     sync.Mutex
	counts map[string]int
}
func newLocalInflight() *localInflight {
	return &localInflight{counts: make(map[string]int)}
}
func (l *localInflight) Acquire(key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] >= limit {
		return false
	}
	l.counts[key]++
	return true
}
func (l *localInflight) Release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] <= 1 {
		delete(l.counts, key)
	} else {
		l.counts[key]--
	}
}
