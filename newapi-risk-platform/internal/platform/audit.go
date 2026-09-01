package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

const DefaultAuditSystemPrompt = `You are the policy classifier for a commercial LLM gateway.
Classify only the user's requested outcome, not quoted material or defensive context.
Block high-confidence requests that meaningfully enable credential theft, malware creation or delivery,
phishing, destructive disruption, unauthorized exploitation, persistence, command-and-control, or
security-control evasion. Allow benign development, defensive security, incident response, education,
CTF/sandbox work, authorized testing, and high-level discussion unless the request supplies harmful
operational capability. Return one compact JSON object only:
{"decision":"allow|block|review","risk_code":"CYBER_* or empty","category":"...","confidence":0.0,"reason":"brief"}`

type compiledRule struct {
	CyberRule
	regex *regexp.Regexp
	text  string
}

type AuditEngine struct {
	store           *Store
	security        *Security
	client          *http.Client
	maxTextBytes    int
	refreshInterval time.Duration
	log             *slog.Logger
	rules           atomic.Value
}

func NewAuditEngine(cfg Config, store *Store, security *Security, log *slog.Logger) *AuditEngine {
	engine := &AuditEngine{
		store:           store,
		security:        security,
		client:          &http.Client{Transport: NewSafeTransport(cfg.AllowPrivateUpstreams, cfg.UpstreamTLSMinVersion), Timeout: 30 * time.Second},
		maxTextBytes:    cfg.AuditTextMaxBytes,
		refreshInterval: cfg.RulesRefreshInterval,
		log:             log,
	}
	engine.rules.Store([]compiledRule{})
	return engine
}

func (e *AuditEngine) Start(ctx context.Context) error {
	if err := e.ReloadRules(ctx); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(e.refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := e.ReloadRules(ctx); err != nil {
					e.log.Warn("cyber rule refresh failed", "error", err)
				}
			}
		}
	}()
	return nil
}

func (e *AuditEngine) ReloadRules(ctx context.Context) error {
	rules, err := e.store.ListCyberRules(ctx, true)
	if err != nil {
		return err
	}
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		item := compiledRule{CyberRule: rule, text: strings.ToLower(strings.TrimSpace(rule.Pattern))}
		switch rule.PatternType {
		case "regex":
			item.regex, err = regexp.Compile(rule.Pattern)
			if err != nil {
				e.log.Error("invalid cyber rule skipped", "rule_id", rule.ID, "code", rule.Code, "error", err)
				continue
			}
		case "contains", "exact":
			if item.text == "" {
				continue
			}
		default:
			continue
		}
		compiled = append(compiled, item)
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].Priority == compiled[j].Priority {
			return compiled[i].ID < compiled[j].ID
		}
		return compiled[i].Priority > compiled[j].Priority
	})
	e.rules.Store(compiled)
	return nil
}

func ValidateCyberRule(rule CyberRule) error {
	if strings.TrimSpace(rule.Code) == "" || strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Category) == "" {
		return errors.New("code, name, and category are required")
	}
	if len(rule.Pattern) == 0 || len(rule.Pattern) > 8192 {
		return errors.New("pattern must contain between 1 and 8192 bytes")
	}
	switch rule.PatternType {
	case "regex":
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("invalid regular expression: %w", err)
		}
	case "contains", "exact":
	default:
		return errors.New("pattern_type must be regex, contains, or exact")
	}
	switch rule.Action {
	case DecisionAllow, DecisionBlock, DecisionReview:
	default:
		return errors.New("action must be allow, block, or review")
	}
	return nil
}

func (e *AuditEngine) matchRules(text string) *AuditDecision {
	rules, _ := e.rules.Load().([]compiledRule)
	lower := strings.ToLower(text)
	var review *AuditDecision
	for _, rule := range rules {
		matched := false
		switch rule.PatternType {
		case "regex":
			matched = rule.regex != nil && rule.regex.MatchString(text)
		case "contains":
			matched = strings.Contains(lower, rule.text)
		case "exact":
			matched = strings.EqualFold(strings.TrimSpace(text), rule.text)
		}
		if !matched {
			continue
		}
		decision := AuditDecision{
			Decision:   rule.Action,
			RiskCode:   rule.Code,
			Category:   rule.Category,
			Confidence: 1,
			Reason:     "matched configured cyber rule",
			Source:     "rule",
			RuleID:     rule.ID,
		}
		if rule.Action == DecisionReview {
			if review == nil {
				copy := decision
				review = &copy
			}
			continue
		}
		return &decision
	}
	return review
}

func (e *AuditEngine) Audit(ctx context.Context, route Route, body []byte) AuditResult {
	started := time.Now()
	text := ExtractAuditText(body, e.maxTextBytes)
	result := AuditResult{
		AuditDecision: AuditDecision{Decision: DecisionAllow, Confidence: 1, Source: "empty"},
		PromptHMAC:   e.security.PromptHMAC(text),
		TextBytes:    len(text),
	}
	defer func() { result.Latency = time.Since(started) }()
	if strings.TrimSpace(text) == "" {
		result.Latency = time.Since(started)
		return result
	}
	matched := e.matchRules(text)
	if matched != nil && (matched.Decision == DecisionBlock || matched.Decision == DecisionAllow) {
		result.AuditDecision = *matched
		result.Latency = time.Since(started)
		return result
	}

	profile, err := e.store.GetAuditProfile(ctx, route.AuditProfileID)
	if err != nil || !profile.Enabled {
		if route.FailClosed {
			result.AuditDecision = AuditDecision{
				Decision: DecisionBlock, RiskCode: "AUDIT_MODEL_UNAVAILABLE", Category: "audit_infrastructure",
				Confidence: 1, Reason: "no enabled audit model is available", Source: "platform",
			}
		} else if matched != nil {
			result.AuditDecision = *matched
		} else {
			result.AuditDecision = AuditDecision{Decision: DecisionAllow, Confidence: 0, Source: "fail_open"}
		}
		result.Latency = time.Since(started)
		return result
	}

	decision, err := e.callModel(ctx, profile, text)
	result.Model = profile.Model
	if err != nil {
		if route.FailClosed || profile.FailClosed {
			result.AuditDecision = AuditDecision{
				Decision: DecisionBlock, RiskCode: "AUDIT_MODEL_ERROR", Category: "audit_infrastructure",
				Confidence: 1, Reason: err.Error(), Source: "platform",
			}
		} else if matched != nil {
			result.AuditDecision = *matched
		} else {
			result.AuditDecision = AuditDecision{Decision: DecisionAllow, Confidence: 0, Source: "fail_open"}
		}
		result.Latency = time.Since(started)
		return result
	}
	if decision.Decision == DecisionBlock && decision.Confidence < profile.BlockThreshold {
		decision.Decision = DecisionReview
		if decision.RiskCode == "" {
			decision.RiskCode = "AUDIT_LOW_CONFIDENCE"
		}
	}
	if decision.Decision == DecisionReview && (route.FailClosed || profile.FailClosed) {
		decision.Decision = DecisionBlock
		if decision.RiskCode == "" {
			decision.RiskCode = "AUDIT_REVIEW_REQUIRED"
		}
	}
	result.AuditDecision = decision
	result.Latency = time.Since(started)
	return result
}

func (e *AuditEngine) DryRun(ctx context.Context, text string, profileID *int64) AuditResult {
	body, _ := json.Marshal(map[string]any{"input": text})
	return e.Audit(ctx, Route{AuditProfileID: profileID, FailClosed: false}, body)
}

type modelAuditResponse struct {
	Decision   string  `json:"decision"`
	RiskCode   string  `json:"risk_code"`
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

func (e *AuditEngine) callModel(ctx context.Context, profile AuditProfile, text string) (AuditDecision, error) {
	endpoint := strings.TrimRight(profile.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	systemPrompt := strings.TrimSpace(profile.SystemPrompt)
	if systemPrompt == "" {
		systemPrompt = DefaultAuditSystemPrompt
	}
	payload := map[string]any{
		"model":       profile.Model,
		"temperature": 0,
		"max_tokens":  300,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": text},
		},
	}
	if len(profile.Extra) > 0 {
		var extra map[string]any
		if json.Unmarshal(profile.Extra, &extra) == nil {
			for key, value := range extra {
				switch key {
				case "model", "messages", "stream":
					continue
				default:
					payload[key] = value
				}
			}
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return AuditDecision{}, err
	}
	timeout := time.Duration(profile.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return AuditDecision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(profile.APIKeyCiphertext) > 0 {
		key, err := e.security.Decrypt("audit-profile-api-key-v1", profile.APIKeyCiphertext)
		if err != nil {
			return AuditDecision{}, fmt.Errorf("decrypt audit API key: %w", err)
		}
		if len(key) > 0 {
			req.Header.Set("Authorization", "Bearer "+string(key))
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return AuditDecision{}, fmt.Errorf("audit model request failed: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return AuditDecision{}, fmt.Errorf("read audit model response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AuditDecision{}, fmt.Errorf("audit model returned HTTP %d", resp.StatusCode)
	}
	content, err := extractChatCompletionContent(responseBody)
	if err != nil {
		return AuditDecision{}, err
	}
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)
	var modelResult modelAuditResponse
	if err := json.Unmarshal([]byte(content), &modelResult); err != nil {
		return AuditDecision{}, fmt.Errorf("audit model did not return valid JSON: %w", err)
	}
	modelResult.Decision = strings.ToLower(strings.TrimSpace(modelResult.Decision))
	switch modelResult.Decision {
	case DecisionAllow, DecisionBlock, DecisionReview:
	default:
		return AuditDecision{}, fmt.Errorf("audit model returned invalid decision %q", modelResult.Decision)
	}
	if modelResult.Confidence < 0 {
		modelResult.Confidence = 0
	}
	if modelResult.Confidence > 1 {
		modelResult.Confidence = 1
	}
	if len(modelResult.Reason) > 500 {
		modelResult.Reason = modelResult.Reason[:500]
	}
	return AuditDecision{
		Decision: modelResult.Decision, RiskCode: strings.TrimSpace(modelResult.RiskCode),
		Category: strings.TrimSpace(modelResult.Category), Confidence: modelResult.Confidence,
		Reason: modelResult.Reason, Source: "model",
	}, nil
}

func extractChatCompletionContent(body []byte) (string, error) {
	var envelope struct {
		Choices []struct {
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("decode audit model response: %w", err)
	}
	if len(envelope.Choices) == 0 {
		return "", errors.New("audit model response has no choices")
	}
	var text string
	if json.Unmarshal(envelope.Choices[0].Message.Content, &text) == nil {
		return text, nil
	}
	var parts []map[string]any
	if json.Unmarshal(envelope.Choices[0].Message.Content, &parts) == nil {
		var builder strings.Builder
		for _, part := range parts {
			if value, ok := part["text"].(string); ok {
				builder.WriteString(value)
			}
		}
		if builder.Len() > 0 {
			return builder.String(), nil
		}
	}
	return "", errors.New("audit model response content is not text")
}

func ExtractAuditText(body []byte, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		if len(body) > maxBytes {
			body = body[:maxBytes]
		}
		return string(bytes.ToValidUTF8(body, []byte("�")))
	}
	var builder strings.Builder
	appendText := func(value string) {
		if value == "" || builder.Len() >= maxBytes {
			return
		}
		remaining := maxBytes - builder.Len()
		if len(value) > remaining {
			value = value[:remaining]
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(value)
	}
	var walk func(value any, key string)
	walk = func(value any, key string) {
		if builder.Len() >= maxBytes {
			return
		}
		lowerKey := strings.ToLower(key)
		switch lowerKey {
		case "image_url", "url", "audio", "file", "data", "image", "video", "base64", "api_key", "authorization":
			return
		}
		switch typed := value.(type) {
		case string:
			switch lowerKey {
			case "content", "text", "input", "prompt", "instructions", "description", "system_instruction", "query":
				appendText(typed)
			}
		case []any:
			for _, item := range typed {
				walk(item, key)
			}
		case map[string]any:
			for childKey, child := range typed {
				if childKey == "parameters" || childKey == "schema" {
					if encoded, err := json.Marshal(child); err == nil {
						appendText(string(encoded))
					}
					continue
				}
				walk(child, childKey)
			}
		}
	}
	walk(root, "root")
	return builder.String()
}

func ExtractRequestedModel(body []byte) string {
	var payload struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	if len(payload.Model) > 200 {
		return payload.Model[:200]
	}
	return payload.Model
}
