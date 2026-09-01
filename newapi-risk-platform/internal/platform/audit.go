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
Classify the requested outcome, not quoted material, defensive context, or an assistant refusal.
Block high-confidence requests that meaningfully enable credential theft, malware creation or delivery,
phishing, destructive disruption, unauthorized exploitation, persistence, command-and-control, or
security-control evasion. Allow benign development, defensive security, incident response, education,
CTF or sandbox work, authorized testing, and high-level discussion unless the request supplies harmful
operational capability. Return one compact JSON object only:
{"decision":"allow|block|review","risk_code":"CYBER_* or empty","category":"...","confidence":0.0,"reason":"brief"}`

type compiledRule struct {
	CyberRule
	regularExpression *regexp.Regexp
	lowerPattern      string
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

func NewAuditEngine(
	cfg Config,
	store *Store,
	security *Security,
	log *slog.Logger,
) *AuditEngine {
	engine := &AuditEngine{
		store:    store,
		security: security,
		client: &http.Client{
			Transport: NewSafeTransport(cfg.AllowPrivateUpstreams, cfg.UpstreamTLSMinVersion),
			Timeout:   30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("audit endpoint redirects are disabled")
			},
		},
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
		item := compiledRule{
			CyberRule:    rule,
			lowerPattern: strings.ToLower(strings.TrimSpace(rule.Pattern)),
		}
		switch rule.PatternType {
		case "regex":
			item.regularExpression, err = regexp.Compile(rule.Pattern)
			if err != nil {
				e.log.Error(
					"invalid cyber rule skipped",
					"rule_id", rule.ID,
					"code", rule.Code,
					"error", err,
				)
				continue
			}
		case "contains", "exact":
			if item.lowerPattern == "" {
				continue
			}
		default:
			continue
		}
		compiled = append(compiled, item)
	}
	sort.SliceStable(compiled, func(i int, j int) bool {
		if compiled[i].Priority == compiled[j].Priority {
			return compiled[i].ID < compiled[j].ID
		}
		return compiled[i].Priority > compiled[j].Priority
	})
	e.rules.Store(compiled)
	return nil
}

func ValidateCyberRule(rule CyberRule) error {
	if strings.TrimSpace(rule.Code) == "" ||
		strings.TrimSpace(rule.Name) == "" ||
		strings.TrimSpace(rule.Category) == "" {
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
	lowerText := strings.ToLower(text)
	var review *AuditDecision
	for _, rule := range rules {
		matched := false
		switch rule.PatternType {
		case "regex":
			matched = rule.regularExpression != nil && rule.regularExpression.MatchString(text)
		case "contains":
			matched = strings.Contains(lowerText, rule.lowerPattern)
		case "exact":
			matched = strings.EqualFold(strings.TrimSpace(text), rule.lowerPattern)
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
				copyOfDecision := decision
				review = &copyOfDecision
			}
			continue
		}
		return &decision
	}
	return review
}

func (e *AuditEngine) Audit(ctx context.Context, route Route, body []byte) (result AuditResult) {
	started := time.Now()
	text := ExtractAuditText(body, e.maxTextBytes)
	result = AuditResult{
		AuditDecision: AuditDecision{
			Decision:   DecisionAllow,
			Confidence: 1,
			Source:     "empty",
		},
		PromptHMAC: e.security.PromptHMAC(text),
		TextBytes:  len(text),
	}
	defer func() {
		result.Latency = time.Since(started)
	}()
	if strings.TrimSpace(text) == "" {
		return result
	}

	matched := e.matchRules(text)
	if matched != nil && (matched.Decision == DecisionBlock || matched.Decision == DecisionAllow) {
		result.AuditDecision = *matched
		return result
	}

	profile, err := e.getAuditProfile(ctx, route.AuditProfileID)
	if err != nil || !profile.Enabled {
		if route.FailClosed {
			result.AuditDecision = AuditDecision{
				Decision:   DecisionBlock,
				RiskCode:   "AUDIT_MODEL_UNAVAILABLE",
				Category:   "audit_infrastructure",
				Confidence: 1,
				Reason:     "no enabled audit model is available",
				Source:     "platform",
			}
		} else if matched != nil {
			result.AuditDecision = *matched
		} else {
			result.AuditDecision = AuditDecision{
				Decision: DecisionAllow,
				Source:   "fail_open",
			}
		}
		return result
	}

	decision, err := e.callModel(ctx, profile, text)
	result.Model = profile.Model
	if err != nil {
		if route.FailClosed || profile.FailClosed {
			result.AuditDecision = AuditDecision{
				Decision:   DecisionBlock,
				RiskCode:   "AUDIT_MODEL_ERROR",
				Category:   "audit_infrastructure",
				Confidence: 1,
				Reason:     err.Error(),
				Source:     "platform",
			}
		} else if matched != nil {
			result.AuditDecision = *matched
		} else {
			result.AuditDecision = AuditDecision{
				Decision: DecisionAllow,
				Source:   "fail_open",
			}
		}
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

func (e *AuditEngine) callModel(
	ctx context.Context,
	profile AuditProfile,
	text string,
) (AuditDecision, error) {
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
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		endpoint,
		bytes.NewReader(encoded),
	)
	if err != nil {
		return AuditDecision{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if len(profile.APIKeyCiphertext) > 0 {
		key, err := e.security.Decrypt("audit-profile-api-key-v1", profile.APIKeyCiphertext)
		if err != nil {
			return AuditDecision{}, fmt.Errorf("decrypt audit API key: %w", err)
		}
		if len(key) > 0 {
			request.Header.Set("Authorization", "Bearer "+string(key))
		}
	}
	response, err := e.client.Do(request)
	if err != nil {
		return AuditDecision{}, fmt.Errorf("audit model request failed: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return AuditDecision{}, fmt.Errorf("read audit model response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return AuditDecision{}, fmt.Errorf("audit model returned HTTP %d", response.StatusCode)
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
		return AuditDecision{}, fmt.Errorf(
			"audit model returned invalid decision %q",
			modelResult.Decision,
		)
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
		Decision:   modelResult.Decision,
		RiskCode:   strings.TrimSpace(modelResult.RiskCode),
		Category:   strings.TrimSpace(modelResult.Category),
		Confidence: modelResult.Confidence,
		Reason:     modelResult.Reason,
		Source:     "model",
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
		return strings.ToValidUTF8(string(body), "�")
	}

	var builder strings.Builder
	appendText := func(value string) {
		value = strings.ToValidUTF8(value, "�")
		if value == "" || builder.Len() >= maxBytes {
			return
		}
		separatorBytes := 0
		if builder.Len() > 0 {
			separatorBytes = 1
		}
		remaining := maxBytes - builder.Len() - separatorBytes
		if remaining <= 0 {
			return
		}
		if len(value) > remaining {
			value = value[:remaining]
			value = strings.ToValidUTF8(value, "�")
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
		case "image_url", "url", "audio", "file", "data", "image", "video",
			"base64", "api_key", "authorization", "password", "secret":
			return
		}
		switch typed := value.(type) {
		case string:
			switch lowerKey {
			case "content", "text", "input", "prompt", "instructions", "description",
				"system", "system_instruction", "query", "arguments":
				appendText(typed)
			}
		case []any:
			for _, item := range typed {
				walk(item, key)
			}
		case map[string]any:
			if role, ok := typed["role"].(string); ok {
				appendText("ROLE=" + strings.ToUpper(truncateString(role, 30)))
			}
			keys := make([]string, 0, len(typed))
			for childKey := range typed {
				keys = append(keys, childKey)
			}
			sort.Strings(keys)
			for _, childKey := range keys {
				if childKey == "role" {
					continue
				}
				child := typed[childKey]
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
	return truncateString(payload.Model, 200)
}
