package platform

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	gatewayRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "newapi_risk",
			Name:      "gateway_requests_total",
			Help:      "Gateway requests by route and outcome.",
		},
		[]string{"route", "outcome"},
	)
	gatewayDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "newapi_risk",
			Name:      "gateway_duration_seconds",
			Help:      "End-to-end gateway latency.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"route"},
	)
	auditDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "newapi_risk",
			Name:      "audit_duration_seconds",
			Help:      "Rule and model audit latency.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"route"},
	)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

func init() {
	prometheus.MustRegister(gatewayRequests, gatewayDuration, auditDuration)
}

type cachedRoute struct {
	route     Route
	expiresAt time.Time
}

type Gateway struct {
	cfg        Config
	store      *Store
	security   *Security
	redis      *RedisGuard
	audit      *AuditEngine
	traces     *TraceWriter
	client     *http.Client
	global     chan struct{}
	log        *slog.Logger
	cacheMu    sync.RWMutex
	routeCache map[string]cachedRoute
}

func NewGateway(
	cfg Config,
	store *Store,
	security *Security,
	redis *RedisGuard,
	audit *AuditEngine,
	traces *TraceWriter,
	log *slog.Logger,
) *Gateway {
	return &Gateway{
		cfg:      cfg,
		store:    store,
		security: security,
		redis:    redis,
		audit:    audit,
		traces:   traces,
		client: &http.Client{
			Transport: NewSafeTransport(cfg.AllowPrivateUpstreams, cfg.UpstreamTLSMinVersion),
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("upstream redirects are disabled")
			},
		},
		global:     make(chan struct{}, cfg.GlobalMaxConcurrency),
		log:        log,
		routeCache: make(map[string]cachedRoute),
	}
}

func (g *Gateway) InvalidateRoute(slug string) {
	g.cacheMu.Lock()
	defer g.cacheMu.Unlock()
	if slug == "" {
		clear(g.routeCache)
		return
	}
	delete(g.routeCache, slug)
}

func (g *Gateway) getRoute(ctx context.Context, slug string) (Route, error) {
	now := time.Now()
	g.cacheMu.RLock()
	cached, ok := g.routeCache[slug]
	g.cacheMu.RUnlock()
	if ok && cached.expiresAt.After(now) {
		return cached.route, nil
	}
	route, err := g.store.GetRouteBySlug(ctx, slug)
	if err != nil {
		return Route{}, err
	}
	g.cacheMu.Lock()
	g.routeCache[slug] = cachedRoute{route: route, expiresAt: now.Add(g.cfg.RouteCacheTTL)}
	g.cacheMu.Unlock()
	return route, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := normalizeRequestID(r.Header.Get("X-Request-ID"))
	if requestID == "" {
		requestID = NewRequestID()
	}
	w.Header().Set("X-Risk-Request-ID", requestID)

	if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
		writeGatewayError(w, http.StatusMethodNotAllowed, requestID, "METHOD_NOT_ALLOWED", "method is not allowed")
		return
	}
	slug := chi.URLParam(r, "route")
	if slug == "" {
		writeGatewayError(w, http.StatusNotFound, requestID, "ROUTE_NOT_FOUND", "risk route not found")
		return
	}
	trace := TraceEvent{
		RequestID:       requestID,
		Source:          "gateway",
		RouteSlug:       slug,
		NewAPIRequestID: normalizeRequestID(r.Header.Get("X-NewAPI-Request-ID")),
		ExternalUserID: normalizeIdentifier(firstNonEmpty(
			r.Header.Get("X-NewAPI-User-ID"),
			r.Header.Get("X-User-ID"),
		)),
		Endpoint:  truncateString(chi.URLParam(r, "*"), 300),
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]any{},
	}
	finished := false
	finish := func(decision string, riskCode string, status int, upstreamStatus int, responseBytes int64) {
		if finished {
			return
		}
		finished = true
		trace.Decision = decision
		trace.RiskCode = riskCode
		trace.HTTPStatus = status
		trace.UpstreamStatus = upstreamStatus
		trace.ResponseBytes = responseBytes
		trace.LatencyMS = time.Since(started).Milliseconds()
		g.traces.Submit(trace)
		gatewayRequests.WithLabelValues(slug, decision).Inc()
		gatewayDuration.WithLabelValues(slug).Observe(time.Since(started).Seconds())
	}

	route, err := g.getRoute(r.Context(), slug)
	if err != nil || !route.Enabled {
		finish("error", "ROUTE_NOT_FOUND", http.StatusNotFound, 0, 0)
		writeGatewayError(w, http.StatusNotFound, requestID, "ROUTE_NOT_FOUND", "risk route not found")
		return
	}
	inboundCredential := strings.TrimSpace(r.Header.Get("X-Risk-Gateway-Key"))
	if inboundCredential == "" {
		inboundCredential = bearerToken(r.Header.Get("Authorization"))
	}
	if !g.security.VerifyDigest("route-inbound-key-v1", inboundCredential, route.InboundKeyDigest) {
		finish("error", "GATEWAY_AUTH_FAILED", http.StatusUnauthorized, 0, 0)
		writeGatewayError(w, http.StatusUnauthorized, requestID, "GATEWAY_AUTH_FAILED", "invalid gateway credential")
		return
	}

	clientIdentity := firstNonEmpty(trace.ExternalUserID, remoteIP(r))
	rateDigest := g.security.Digest("rate-limit-key-v1", slug+"|"+clientIdentity)
	if !g.redis.Allow(r.Context(), rateDigest[:32], route.RateLimitRPS, route.RateLimitBurst) {
		finish("error", "RATE_LIMITED", http.StatusTooManyRequests, 0, 0)
		w.Header().Set("Retry-After", "1")
		writeGatewayError(w, http.StatusTooManyRequests, requestID, "RATE_LIMITED", "request rate limit exceeded")
		return
	}
	select {
	case g.global <- struct{}{}:
		defer func() { <-g.global }()
	default:
		finish("error", "GATEWAY_OVERLOADED", http.StatusServiceUnavailable, 0, 0)
		writeGatewayError(w, http.StatusServiceUnavailable, requestID, "GATEWAY_OVERLOADED", "gateway concurrency limit reached")
		return
	}

	bodyReader := http.MaxBytesReader(w, r.Body, g.cfg.RequestMaxBytes)
	body, err := io.ReadAll(bodyReader)
	if err != nil {
		finish("error", "REQUEST_TOO_LARGE", g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "REQUEST_TOO_LARGE", "request body exceeds the configured limit")
		return
	}
	trace.RequestBytes = int64(len(body))
	trace.Model = ExtractRequestedModel(body)

	auditResult := g.audit.Audit(r.Context(), route, body)
	trace.AuditLatencyMS = auditResult.Latency.Milliseconds()
	trace.PromptHMAC = auditResult.PromptHMAC
	trace.Metadata["audit_source"] = auditResult.Source
	trace.Metadata["audit_category"] = auditResult.Category
	if auditResult.Model != "" {
		trace.Metadata["audit_model"] = auditResult.Model
	}
	auditDuration.WithLabelValues(slug).Observe(auditResult.Latency.Seconds())
	if auditResult.Decision == DecisionBlock {
		riskCode := firstNonEmpty(auditResult.RiskCode, "CYBER_POLICY_BLOCK")
		finish(DecisionBlock, riskCode, g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, "request rejected by risk control")
		return
	}

	timeout := time.Duration(route.RequestTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	release, ok := g.redis.Acquire(
		r.Context(),
		"route:"+slug,
		route.MaxConcurrency,
		timeout+30*time.Second,
	)
	if !ok {
		finish("error", "ROUTE_CONCURRENCY_LIMITED", http.StatusServiceUnavailable, 0, 0)
		writeGatewayError(w, http.StatusServiceUnavailable, requestID, "ROUTE_CONCURRENCY_LIMITED", "route concurrency limit reached")
		return
	}
	defer release()

	upstreamRequest, err := g.buildUpstreamRequest(r, route, body, requestID)
	if err != nil {
		g.log.Warn("route configuration rejected at request time", "route", slug, "error", err)
		trace.Metadata["error_class"] = "route_configuration"
		finish("error", "GATEWAY_CONFIG_ERROR", g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "GATEWAY_CONFIG_ERROR", "gateway route configuration is invalid")
		return
	}
	requestContext, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	upstreamRequest = upstreamRequest.WithContext(requestContext)
	response, err := g.client.Do(upstreamRequest)
	if err != nil {
		riskCode := "UPSTREAM_CONNECTION_ERROR"
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(requestContext.Err(), context.DeadlineExceeded) {
			riskCode = "UPSTREAM_TIMEOUT"
		}
		trace.Metadata["error_class"] = riskCode
		finish("error", riskCode, g.cfg.ErrorHTTPStatus, 0, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, riskCode, "upstream model request failed")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		trace.Metadata["error_class"] = "upstream_http_error"
		finish("error", "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus, response.StatusCode, 0)
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
		return
	}

	if strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		bytesWritten, riskCode, status := g.proxySSE(w, response, requestID)
		if riskCode != "" {
			trace.Metadata["stream_error_semantics"] = "logical_555_after_headers"
			finish("error", riskCode, status, response.StatusCode, bytesWritten)
			return
		}
		finish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
		return
	}

	bytesWritten, riskCode, status := g.proxyBuffered(w, response, requestID)
	if riskCode != "" {
		finish("error", riskCode, status, response.StatusCode, bytesWritten)
		return
	}
	finish(DecisionAllow, "", status, response.StatusCode, bytesWritten)
}

func (g *Gateway) buildUpstreamRequest(
	inbound *http.Request,
	route Route,
	body []byte,
	requestID string,
) (*http.Request, error) {
	base, err := url.Parse(route.BaseURL)
	if err != nil {
		return nil, err
	}
	wildcard := chi.URLParam(inbound, "*")
	if wildcard == "" {
		wildcard = "/"
	}
	base.Path = joinURLPath(base.Path, wildcard)
	base.RawQuery = inbound.URL.RawQuery
	request, err := http.NewRequest(inbound.Method, base.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyRequestHeaders(request.Header, inbound.Header)
	inboundAuthorization := request.Header.Get("Authorization")
	for _, key := range []string{
		"Authorization",
		"X-API-Key",
		"X-Goog-Api-Key",
		"Api-Key",
		"X-Risk-Gateway-Key",
		"X-NewAPI-User-ID",
		"X-User-ID",
		"Cookie",
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Accept-Encoding",
	} {
		request.Header.Del(key)
	}
	request.Header.Set("X-Risk-Request-ID", requestID)
	if inbound.Header.Get("X-Request-ID") == "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	secret, err := g.security.Decrypt("route-upstream-secret-v1", route.UpstreamSecretCiphertext)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(route.AuthMode) {
	case "", "none":
		request.Header.Del("Authorization")
	case "passthrough":
		if inbound.Header.Get("X-Risk-Gateway-Key") == "" || inboundAuthorization == "" {
			return nil, errors.New("passthrough auth requires X-Risk-Gateway-Key and an Authorization header")
		}
		request.Header.Set("Authorization", inboundAuthorization)
	case "bearer":
		request.Header.Set("Authorization", "Bearer "+string(secret))
	case "anthropic":
		request.Header.Del("Authorization")
		request.Header.Set("X-API-Key", string(secret))
		if request.Header.Get("Anthropic-Version") == "" {
			request.Header.Set("Anthropic-Version", "2023-06-01")
		}
	case "gemini":
		request.Header.Del("Authorization")
		request.Header.Set("X-Goog-Api-Key", string(secret))
	case "header":
		if route.SecretHeader == "" {
			return nil, errors.New("secret_header is required for header auth mode")
		}
		request.Header.Set(route.SecretHeader, string(secret))
	case "query":
		parameter := route.SecretHeader
		if parameter == "" {
			parameter = "key"
		}
		query := request.URL.Query()
		query.Set(parameter, string(secret))
		request.URL.RawQuery = query.Encode()
	default:
		return nil, fmt.Errorf("unsupported auth mode %q", route.AuthMode)
	}
	return request, nil
}

func (g *Gateway) proxyBuffered(
	w http.ResponseWriter,
	response *http.Response,
	requestID string,
) (int64, string, int) {
	prefix, err := io.ReadAll(io.LimitReader(response.Body, g.cfg.ResponseInspectMaxBytes+1))
	if err != nil {
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_READ_ERROR", "upstream model response failed")
		return 0, "UPSTREAM_READ_ERROR", g.cfg.ErrorHTTPStatus
	}
	if int64(len(prefix)) <= g.cfg.ResponseInspectMaxBytes && responseContainsErrorEnvelope(prefix) {
		writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_MODEL_ERROR", "upstream model returned an error")
		return 0, "UPSTREAM_MODEL_ERROR", g.cfg.ErrorHTTPStatus
	}
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.WriteHeader(response.StatusCode)
	written, writeError := w.Write(prefix)
	total := int64(written)
	if writeError == nil && int64(len(prefix)) > g.cfg.ResponseInspectMaxBytes {
		copied, copyError := io.Copy(w, response.Body)
		total += copied
		writeError = copyError
	}
	if writeError != nil {
		return total, "CLIENT_DISCONNECT", response.StatusCode
	}
	return total, "", response.StatusCode
}

func (g *Gateway) proxySSE(
	w http.ResponseWriter,
	response *http.Response,
	requestID string,
) (int64, string, int) {
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 64*1024), g.cfg.SSELineMaxBytes)
	buffered := make([][]string, 0, 4)
	bufferedBytes := 0
	for len(buffered) < 16 && bufferedBytes < 64*1024 {
		event, ok, err := nextSSEEvent(scanner)
		if err != nil {
			writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_STREAM_ERROR", "upstream stream failed before starting")
			return 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus
		}
		if !ok {
			break
		}
		if isSSEErrorEvent(event) {
			writeRiskError(w, g.cfg.ErrorHTTPStatus, requestID, "UPSTREAM_STREAM_ERROR", "upstream model returned a stream error")
			return 0, "UPSTREAM_STREAM_ERROR", g.cfg.ErrorHTTPStatus
		}
		buffered = append(buffered, event)
		bufferedBytes += sseEventSize(event)
		if isMeaningfulSSEEvent(event) {
			break
		}
	}

	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.WriteHeader(response.StatusCode)
	flusher, canFlush := w.(http.Flusher)
	var total int64
	writeEvent := func(lines []string) error {
		for _, line := range lines {
			count, err := io.WriteString(w, line+"\n")
			total += int64(count)
			if err != nil {
				return err
			}
		}
		if canFlush {
			flusher.Flush()
		}
		return nil
	}
	for _, event := range buffered {
		if err := writeEvent(event); err != nil {
			return total, "CLIENT_DISCONNECT", response.StatusCode
		}
	}
	for {
		event, hasEvent, readError := nextSSEEvent(scanner)
		if readError != nil {
			written, _ := writeSSELogicalError(w, requestID, "UPSTREAM_STREAM_INTERRUPTED")
			total += written
			if canFlush {
				flusher.Flush()
			}
			return total, "UPSTREAM_STREAM_INTERRUPTED", response.StatusCode
		}
		if !hasEvent {
			break
		}
		if isSSEErrorEvent(event) {
			written, _ := writeSSELogicalError(w, requestID, "UPSTREAM_STREAM_ERROR")
			total += written
			if canFlush {
				flusher.Flush()
			}
			return total, "UPSTREAM_STREAM_ERROR", response.StatusCode
		}
		if err := writeEvent(event); err != nil {
			return total, "CLIENT_DISCONNECT", response.StatusCode
		}
	}
	return total, "", response.StatusCode
}

func nextSSEEvent(scanner *bufio.Scanner) ([]string, bool, error) {
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
		if line == "" {
			return lines, true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	if len(lines) > 0 {
		lines = append(lines, "")
		return lines, true, nil
	}
	return nil, false, nil
}

func isMeaningfulSSEEvent(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") || strings.HasPrefix(trimmed, "event:") {
			return true
		}
	}
	return false
}

func sseEventSize(lines []string) int {
	total := 0
	for _, line := range lines {
		total += len(line) + 1
	}
	return total
}

func isSSEErrorEvent(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(trimmed, "event: error") {
			return true
		}
		if !strings.HasPrefix(trimmed, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		var payload map[string]any
		if json.Unmarshal([]byte(data), &payload) != nil {
			continue
		}
		if value, exists := payload["error"]; exists && value != nil {
			return true
		}
		if value, _ := payload["type"].(string); strings.EqualFold(value, "error") {
			return true
		}
	}
	return false
}

func writeSSELogicalError(w io.Writer, requestID string, riskCode string) (int64, error) {
	payload := map[string]any{
		"error": map[string]any{
			"message":    "upstream model stream failed",
			"type":       "upstream_error",
			"code":       555,
			"risk_code":  riskCode,
			"request_id": requestID,
		},
	}
	encoded, _ := json.Marshal(payload)
	count, err := fmt.Fprintf(w, "event: error\ndata: %s\n\n", encoded)
	return int64(count), err
}

func responseContainsErrorEnvelope(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	var payload map[string]any
	if json.Unmarshal(trimmed, &payload) != nil {
		return false
	}
	if value, exists := payload["error"]; exists && value != nil {
		return true
	}
	if value, _ := payload["type"].(string); strings.EqualFold(value, "error") || strings.HasSuffix(strings.ToLower(value), "_error") {
		return true
	}
	if success, ok := payload["success"].(bool); ok && !success {
		if _, hasMessage := payload["message"]; hasMessage {
			return true
		}
	}
	return false
}

func writeRiskError(w http.ResponseWriter, status int, requestID string, riskCode string, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.Header().Set("X-Risk-Error-Code", "555")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message":    message,
			"type":       "risk_control_error",
			"code":       555,
			"risk_code":  riskCode,
			"request_id": requestID,
		},
	})
}

func writeGatewayError(w http.ResponseWriter, status int, requestID string, code string, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Risk-Request-ID", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message":    message,
			"type":       "gateway_error",
			"code":       code,
			"request_id": requestID,
		},
	})
}

func copyRequestHeaders(destination http.Header, source http.Header) {
	for key, values := range source {
		if isHopByHopHeader(key) || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func copyResponseHeaders(destination http.Header, source http.Header) {
	for key, values := range source {
		if isHopByHopHeader(key) ||
			strings.EqualFold(key, "Content-Length") ||
			strings.EqualFold(key, "Set-Cookie") ||
			strings.EqualFold(key, "Server") ||
			strings.EqualFold(key, "Alt-Svc") {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func isHopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func joinURLPath(basePath string, requestPath string) string {
	if basePath == "" {
		basePath = "/"
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}

func normalizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || !requestIDPattern.MatchString(value) {
		return ""
	}
	return value
}

func normalizeIdentifier(value string) string {
	return truncateString(strings.TrimSpace(value), 200)
}

func truncateString(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func ValidateUpstreamURL(rawURL string, allowPrivate bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("upstream URL scheme must be http or https")
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("upstream URL must contain a host and must not contain userinfo or a fragment")
	}
	if parsed.Scheme == "http" && !allowPrivate {
		return errors.New("plain HTTP upstreams require explicitly enabled private-upstream mode")
	}
	if allowPrivate {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, parsed.Hostname())
	if err != nil {
		return fmt.Errorf("resolve upstream host: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("upstream host did not resolve")
	}
	for _, address := range addresses {
		if isForbiddenIP(address.IP) {
			return fmt.Errorf("upstream host resolves to forbidden address %s", address.IP)
		}
	}
	return nil
}

func NewSafeTransport(allowPrivate bool, minimumTLSVersion uint16) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4096,
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: minimumTLSVersion},
	}
	transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastError error
		for _, candidate := range addresses {
			if !allowPrivate && isForbiddenIP(candidate.IP) {
				lastError = fmt.Errorf("dial blocked for forbidden address %s", candidate.IP)
				continue
			}
			connection, err := dialer.DialContext(
				ctx,
				network,
				net.JoinHostPort(candidate.IP.String(), port),
			)
			if err == nil {
				return connection, nil
			}
			lastError = err
		}
		if lastError == nil {
			lastError = errors.New("host did not resolve to a usable address")
		}
		return nil, lastError
	}
	return transport
}

var forbiddenNetworks = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
		"240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10",
		"ff00::/8", "2001:db8::/32",
	}
	result := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}()

func isForbiddenIP(ip net.IP) bool {
	if ip == nil ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() {
		return true
	}
	for _, network := range forbiddenNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
