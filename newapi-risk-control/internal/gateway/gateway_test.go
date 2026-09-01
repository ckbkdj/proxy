package gateway

import (
	"context"
	"encoding/json"
	"testing"
)

func TestParseGatewayPath(t *testing.T) {
	slug, rest, ok := parseGatewayPath("/gateway/openai/v1/chat/completions")
	if !ok || slug != "openai" || rest != "/v1/chat/completions" {
		t.Fatalf("unexpected parse result: %q %q %v", slug, rest, ok)
	}
	if _, _, ok := parseGatewayPath("/gateway/"); ok {
		t.Fatal("empty route slug was accepted")
	}
}

func TestBuildUpstreamURLAvoidsDuplicateV1(t *testing.T) {
	actual, err := buildUpstreamURL("https://api.example/v1", "/v1/chat/completions", "stream=true")
	if err != nil {
		t.Fatal(err)
	}
	if actual != "https://api.example/v1/chat/completions?stream=true" {
		t.Fatalf("unexpected upstream URL %q", actual)
	}
}

func TestValidateUpstreamURLRejectsPrivateTargets(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:8080/v1",
		"http://[::1]:8080/v1",
		"http://localhost:8080/v1",
		"ftp://example.com/file",
	} {
		if err := ValidateUpstreamURL(context.Background(), target, false); err == nil {
			t.Fatalf("unsafe target was accepted: %s", target)
		}
	}
	if err := ValidateUpstreamURL(context.Background(), "http://127.0.0.1:8080/v1", true); err != nil {
		t.Fatalf("explicit private upstream was rejected: %v", err)
	}
}

func TestShouldNormalizeUpstreamModelErrors(t *testing.T) {
	if !shouldNormalize(nil, 429, []byte(`{"error":{"code":"rate_limit_exceeded"}}`)) {
		t.Fatal("429 should be normalized")
	}
	if shouldNormalize(nil, 400, []byte(`{"error":{"code":"invalid_request_error"}}`)) {
		t.Fatal("ordinary client 400 should be passed through")
	}
	if !shouldNormalize(nil, 400, []byte(`{"error":{"code":"model_not_found"}}`)) {
		t.Fatal("model_not_found should be normalized even when the HTTP status is 400")
	}
}

func TestCustomErrorPolicy(t *testing.T) {
	policy, _ := json.Marshal(map[string]interface{}{
		"normalize_statuses": []int{418},
		"normalize_codes":    []string{"custom_model_error"},
		"message_patterns":   []string{"(?i)capacity exhausted"},
		"pass_statuses":      []int{429},
	})
	if !shouldNormalize(policy, 418, nil) {
		t.Fatal("custom status was not normalized")
	}
	if shouldNormalize(policy, 429, []byte("capacity exhausted")) {
		t.Fatal("pass_statuses must take precedence")
	}
	if !shouldNormalize(policy, 400, []byte("capacity exhausted")) {
		t.Fatal("custom message pattern was not normalized")
	}
}
