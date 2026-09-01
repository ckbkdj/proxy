package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ckbkdj/newapi-risk-control/internal/cache"
	"github.com/ckbkdj/newapi-risk-control/internal/config"
	"github.com/ckbkdj/newapi-risk-control/internal/core"
	"github.com/ckbkdj/newapi-risk-control/internal/security"
	"github.com/ckbkdj/newapi-risk-control/internal/store"
)

type compiledRule struct {
	core.RiskRule
	re *regexp.Regexp
}

type Engine struct {
	store      *store.Store
	cache      *cache.Redis
	cipher     *security.Cipher
	hashSecret string
	maxText    int
	defaultTTL time.Duration
	defaultTO  time.Duration
	client     *http.Client
	rules      atomic.Value // []compiledRule
}

func New(cfg config.Config, st *store.Store, rc *cache.Redis, cipher *security.Cipher) *Engine {
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	e := &Engine{
		store:      st,
		cache:      rc,
		cipher:     cipher,
		hashSecret: cfg.PromptHashSecret,
		maxText:    cfg.AuditMaxTextBytes,
		defaultTTL: cfg.AuditCacheTTL,
		defaultTO:  cfg.AuditDefaultTimeout,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	e.rules.Store([]compiledRule{})
	return e
}

// BuiltinRules intentionally detects clearly harmful intent and avoids matching
// ordinary defensive research, authorized testing, or software engineering.
func BuiltinRules() []core.RiskRule {
	return []core.RiskRule{
		{
			Name: "builtin-credential-theft", Category: "credential_theft",
			Pattern: `(?is)\b(build|write|generate|deploy|create)\b.{0,100}\b(credential stealer|password stealer|session cookie stealer|phishing kit)\b`,
			Action: "block", Score: 1, Priority: 1000, Builtin: true, Enabled: true,
		},
		{
			Name: "builtin-malware-delivery", Category: "malware",
			Pattern: `(?is)\b(build|write|generate|deploy|create)\b.{0,100}\b(ransomware|wiper malware|botnet agent|malware loader|c2 implant)\b`,
			Action: "block", Score: 1, Priority: 990, Builtin: true, Enabled: true,
		},
		{
			Name: "builtin-security-evasion", Category: "security_evasion",
			Pattern: `(?is)\b(bypass|disable|evade)\b.{0,80}\b(edr|antivirus|endpoint detection|security monitoring)\b.{0,80}\b(on victim|without permission|undetected|stealth)\b`,
			Action: "block", Score: .98, Priority: 980, Builtin: true, Enabled: true,
		},
		{
			Name: "builtin-data-exfiltration", Category: "data_exfiltration",
			Pattern: `(?is)\b(exfiltrate|steal|harvest)\b.{0,100}\b(passwords?|tokens?|cookies?|private keys?|customer data|database)\b.{0,100}\b(without permission|victim|silently|undetected)\b`,
			Action: "block", Score: .98, Priority: 970, Builtin: true, Enabled: true,
		},
		{
			Name: "builtin-destructive-action", Category: "destructive_action",
			Pattern: `(?is)\b(delete|wipe|encrypt|destroy)\b.{0,100}\b(all|entire|production|victim)\b.{0,100}\b(data|servers?|backups?|files?)\b.{0,80}\b(without permission|ransom|irrecoverable)\b`,
			Action: "block", Score: .98, Priority: 960, Builtin: true, Enabled: true,
		},
		{
			Name: "builtin-unauthorized-exploitation", Category: "unauthorized_exploitation",
			Pattern: `(?is)\b(exploit|compromise|take over|gain access)\b.{0,120}\b(target|victim|public server|third.party)\b.{0,100}\b(without permission|unauthorized|no authorization)\b`,
			Action: "block", Score: .97, Priority: 950, Builtin: true, Enabled: true,
		},
		{
			Name: "builtin-mass-abuse", Category: "mass_abuse",
			Pattern: `(?is)\b(scan|attack|exploit|brute.force)\b.{0,100}\b(thousands|millions|internet.wide|mass|bulk)\b.{0,100}\b(hosts?|accounts?|targets?)\b`,
			Action: "review", Score: .9, Priority: 900, Builtin: true, Enabled: true,
		},
	}
}

func (e *Engine) Start(ctx context.Context) {
	_ = e.Refresh(ctx)
	ticker := time.NewTicker(15 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = e.Refresh(ctx)
			}
		}
	}()
}

func (e *Engine) Refresh(ctx context.Context) error {
	rules, err := e.store.ListRules(ctx, true)
	if err != nil {
		return err
	}
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledRule{RiskRule: rule, re: re})
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].Priority > compiled[j].Priority
	})
	e.rules.Store(compiled)
	return nil
}

func (e *Engine) Audit(ctx context.Context, profileID *string, body []byte) (core.Decision, string) {
	started := time.Now()
	text := ExtractAuditText(body, e.maxText)
	hash := security.HashOpaque(e.hashSecret, text)
	finish := func(d core.Decision) (core.Decision, string) {
		d.AuditLatency = time.Since(started).Milliseconds()
		return d, hash
	}
	if text == "" {
		return finish(core.Decision{Allowed: true, Action: "allow", ReasonCode: "EMPTY_INPUT"})
	}

	for _, rule := range e.rules.Load().([]compiledRule) {
		if !rule.re.MatchString(text) {
			continue
		}
		allowed := rule.Action == "allow"
		return finish(core.Decision{
			Allowed: allowed, Action: rule.Action, Category: rule.Category,
			Score: rule.Score, ReasonCode: "CYBER_RULE_MATCH", RuleID: rule.ID,
			SafeSummary: "request matched a configured cyber-risk rule",
		})
	}

	if profileID == nil || *profileID == "" {
		return finish(core.Decision{Allowed: true, Action: "allow", ReasonCode: "RULES_CLEAR"})
	}
	profile, err := e.store.GetAuditProfile(ctx, *profileID)
	if err != nil {
		return finish(core.Decision{
			Allowed: false, Action: "block", Category: "audit_unavailable",
			Score: 1, ReasonCode: "AUDIT_PROFILE_ERROR", Degraded: true,
		})
	}
	if !profile.Enabled {
		return finish(core.Decision{Allowed: true, Action: "allow", ReasonCode: "AUDIT_PROFILE_DISABLED"})
	}

	cacheKey := profile.ID + ":" + hash
	if decision, ok := e.cache.GetDecision(ctx, cacheKey); ok {
		return finish(decision)
	}

	decision, err := e.callModel(ctx, profile, text)
	if err != nil {
		switch profile.FailMode {
		case "open":
			decision = core.Decision{Allowed: true, Action: "allow", Category: "audit_unavailable", ReasonCode: "AUDIT_FAIL_OPEN", Degraded: true}
		case "shadow":
			decision = core.Decision{Allowed: true, Action: "allow", Category: "audit_unavailable", ReasonCode: "AUDIT_SHADOW_ERROR", Degraded: true}
		default:
			decision = core.Decision{Allowed: false, Action: "block", Category: "audit_unavailable", Score: 1, ReasonCode: "AUDIT_FAIL_CLOSED", Degraded: true}
		}
	} else {
		decision.Model = profile.Model
		if profile.FailMode == "shadow" {
			decision.Allowed = true
			decision.Action = "allow"
			decision.ReasonCode = "AUDIT_SHADOW_" + decision.ReasonCode
		} else if decision.Action == "block" || (decision.Action == "review" && decision.Score >= profile.BlockThreshold) {
			decision.Allowed = false
		} else {
			decision.Allowed = true
		}
	}

	ttl := time.Duration(profile.CacheTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = e.defaultTTL
	}
	e.cache.PutDecision(ctx, cacheKey, decision, ttl)
	return finish(decision)
}

func (e *Engine) callModel(parent context.Context, profile core.AuditProfile, text string) (core.Decision, error) {
	apiKey, err := e.cipher.DecryptString(profile.APIKeyCipher)
	if err != nil {
		return core.Decision{}, err
	}
	limit := profile.MaxInputChars
	if limit <= 0 || limit > e.maxText {
		limit = e.maxText
	}
	if len(text) > limit {
		text = text[:limit]
	}
	timeout := time.Duration(profile.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = e.defaultTO
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	endpoint, err := completionURL(profile.Endpoint)
	if err != nil {
		return core.Decision{}, err
	}
	systemPrompt := profile.SystemPrompt
	if strings.TrimSpace(systemPrompt) == "" {
		systemPrompt = defaultClassifierPrompt
	}
	payload := map[string]interface{}{
		"model":       profile.Model,
		"temperature": 0,
		"max_tokens":  300,
		"response_format": map[string]string{
			"type": "json_object",
		},
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": text},
		},
	}
	requestBody, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return core.Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return core.Decision{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return core.Decision{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return core.Decision{}, fmt.Errorf("audit model status %d", resp.StatusCode)
	}

	var envelope struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Choices) == 0 {
		return core.Decision{}, errors.New("invalid audit model response")
	}
	content := extractJSONObject(envelope.Choices[0].Message.Content)
	var out struct {
		Action     string   `json:"action"`
		Category   string   `json:"category"`
		Score      float64  `json:"score"`
		ReasonCode string   `json:"reason_code"`
		Labels     []string `json:"labels"`
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
		return core.Decision{}, errors.New("audit model did not return valid JSON")
	}
	out.Action = strings.ToLower(strings.TrimSpace(out.Action))
	if out.Action != "allow" && out.Action != "review" && out.Action != "block" {
		return core.Decision{}, errors.New("invalid audit action")
	}
	if out.Score < 0 {
		out.Score = 0
	}
	if out.Score > 1 {
		out.Score = 1
	}
	if out.Category == "" {
		out.Category = "unknown"
	}
	if out.ReasonCode == "" {
		out.ReasonCode = "MODEL_CLASSIFICATION"
	}
	return core.Decision{
		Action: out.Action, Category: out.Category, Score: out.Score,
		ReasonCode: out.ReasonCode, Labels: out.Labels,
		SafeSummary: "request was classified by the configured audit model",
	}, nil
}

func completionURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid audit endpoint")
	}
	path := strings.TrimRight(u.Path, "/")
	if strings.HasSuffix(path, "/chat/completions") {
		return u.String(), nil
	}
	if strings.HasSuffix(path, "/v1") {
		u.Path = path + "/chat/completions"
	} else {
		u.Path = path + "/v1/chat/completions"
	}
	return u.String(), nil
}

func ExtractAuditText(body []byte, max int) string {
	if max <= 0 {
		max = 128 << 10
	}
	if len(body) > 8<<20 {
		body = body[:8<<20]
	}
	var value interface{}
	if json.Unmarshal(body, &value) != nil {
		return truncate(strings.TrimSpace(string(body)), max)
	}
	parts := make([]string, 0, 16)
	var walk func(interface{}, string)
	walk = func(node interface{}, key string) {
		if totalLen(parts) >= max {
			return
		}
		switch typed := node.(type) {
		case string:
			lowerKey := strings.ToLower(key)
			switch lowerKey {
			case "content", "text", "prompt", "input", "instructions", "description", "arguments", "name":
				parts = append(parts, typed)
			}
		case []interface{}:
			for _, item := range typed {
				walk(item, key)
			}
		case map[string]interface{}:
			for childKey, item := range typed {
				walk(item, childKey)
			}
		}
	}
	walk(value, "")
	return truncate(strings.Join(parts, "\n"), max)
}

func totalLen(parts []string) int {
	total := 0
	for _, part := range parts {
		total += len(part) + 1
	}
	return total
}
func truncate(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}
func extractJSONObject(value string) string {
	start := strings.Index(value, "{")
	end := strings.LastIndex(value, "}")
	if start >= 0 && end > start {
		return value[start : end+1]
	}
	return value
}

const defaultClassifierPrompt = `You are a security policy classifier for an API gateway. Return JSON only:
{"action":"allow|review|block","category":"short_category","score":0.0,"reason_code":"UPPER_SNAKE_CASE","labels":[]}
Block requests that materially enable credential theft, malware deployment, destructive disruption, unauthorized exploitation, security-control evasion, data exfiltration, botnets, or mass abuse. Allow benign education, defensive analysis, authorized testing, remediation, and ordinary software development. Judge intent, capability, authorization context, and likely harm. Do not reproduce or transform the request.`
