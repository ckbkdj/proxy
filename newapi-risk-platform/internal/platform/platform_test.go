package platform

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSecurity() *Security {
	return NewSecurity(Config{
		MasterKey: []byte("0123456789abcdef0123456789abcdef"),
		JWTSecret: []byte("abcdef0123456789abcdef0123456789"),
		JWTIssuer: "test-issuer",
		JWTTTL:    time.Hour,
	})
}

func TestEncryptionUsesScopeAsAssociatedData(t *testing.T) {
	security := testSecurity()
	ciphertext, err := security.Encrypt("route-secret", []byte("sensitive-value"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := security.Decrypt("route-secret", ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "sensitive-value" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
	if _, err := security.Decrypt("another-scope", ciphertext); err == nil {
		t.Fatal("expected decryption with a different scope to fail")
	}
}

func TestDigestAndTrackingSignatures(t *testing.T) {
	security := testSecurity()
	digest := security.Digest("gateway-key", "secret")
	if !security.VerifyDigest("gateway-key", "secret", digest) {
		t.Fatal("expected digest verification to pass")
	}
	if security.VerifyDigest("gateway-key", "wrong", digest) {
		t.Fatal("expected digest verification to fail")
	}
	body := []byte(`{"request_id":"req-1"}`)
	signature := SignTracking("tracking-secret", "1700000000", "nonce-1", body)
	if !VerifyTrackingSignature("tracking-secret", "1700000000", "nonce-1", body, signature) {
		t.Fatal("expected tracking signature verification to pass")
	}
	if VerifyTrackingSignature("tracking-secret", "1700000000", "nonce-2", body, signature) {
		t.Fatal("expected tracking signature verification to fail for another nonce")
	}
}

func TestAdminJWT(t *testing.T) {
	security := testSecurity()
	token, err := security.IssueAdminToken(AdminUser{ID: 7, Username: "operator", Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := security.ParseAdminToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != 7 || claims.Username != "operator" || claims.Role != "operator" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("a-strong-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "a-strong-test-password") {
		t.Fatal("expected password verification to pass")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("expected password verification to fail")
	}
	if _, err := HashPassword("too-short"); err == nil {
		t.Fatal("expected short password to be rejected")
	}
}

func TestExtractAuditTextOmitsBinaryURLsAndIsDeterministic(t *testing.T) {
	body := []byte(`{
		"model":"demo",
		"messages":[
			{"role":"system","content":"Follow product policy"},
			{"role":"user","content":[{"type":"text","text":"Explain defensive logging"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}
		],
		"tools":[{"type":"function","function":{"name":"scan","parameters":{"type":"object","properties":{"target":{"type":"string"}}}}}]
	}`)
	first := ExtractAuditText(body, 64*1024)
	second := ExtractAuditText(body, 64*1024)
	if first != second {
		t.Fatalf("expected deterministic extraction\nfirst=%q\nsecond=%q", first, second)
	}
	if !strings.Contains(first, "Explain defensive logging") || !strings.Contains(first, "ROLE=USER") {
		t.Fatalf("expected textual content and role labels, got %q", first)
	}
	if strings.Contains(first, "data:image") || strings.Contains(first, "AAAA") {
		t.Fatalf("expected binary URL content to be omitted, got %q", first)
	}
}

func TestValidateCyberRule(t *testing.T) {
	valid := CyberRule{
		Code:        "CYBER_TEST",
		Name:        "Test",
		Category:    "test",
		Pattern:     `(?i)credential`,
		PatternType: "regex",
		Action:      DecisionBlock,
	}
	if err := ValidateCyberRule(valid); err != nil {
		t.Fatal(err)
	}
	valid.Pattern = "["
	if err := ValidateCyberRule(valid); err == nil {
		t.Fatal("expected invalid regular expression to be rejected")
	}
}

func TestProviderErrorEnvelopeDetection(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"error":{"message":"provider failed"}}`),
		[]byte(`{"type":"error","message":"failed"}`),
		[]byte(`{"success":false,"message":"failed"}`),
	}
	for _, body := range cases {
		if !responseContainsErrorEnvelope(body) {
			t.Fatalf("expected error envelope for %s", body)
		}
	}
	if responseContainsErrorEnvelope([]byte(`{"choices":[{"message":{"content":"ok"}}]}`)) {
		t.Fatal("normal completion must not be classified as an error envelope")
	}
}

func TestSSEErrorDetection(t *testing.T) {
	if !isSSEErrorEvent([]string{"event: error", `data: {"message":"failed"}`, ""}) {
		t.Fatal("expected event:error to be detected")
	}
	if !isSSEErrorEvent([]string{`data: {"error":{"message":"failed"}}`, ""}) {
		t.Fatal("expected JSON error payload to be detected")
	}
	if isSSEErrorEvent([]string{`data: {"choices":[{"delta":{"content":"ok"}}]}`, ""}) {
		t.Fatal("normal SSE event must not be classified as an error")
	}
}

func TestRiskErrorUsesHTTPAndLogical555(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeRiskError(recorder, 555, "req-1", "CYBER_TEST", "blocked")
	if recorder.Code != 555 {
		t.Fatalf("expected HTTP 555, got %d", recorder.Code)
	}
	var payload struct {
		Error struct {
			Code      int    `json:"code"`
			RiskCode  string `json:"risk_code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != 555 || payload.Error.RiskCode != "CYBER_TEST" || payload.Error.RequestID != "req-1" {
		t.Fatalf("unexpected error payload: %#v", payload)
	}
}

func TestForbiddenAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"} {
		if !isForbiddenIP(net.ParseIP(address)) {
			t.Fatalf("expected %s to be forbidden", address)
		}
	}
	if isForbiddenIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("expected public address to be allowed")
	}
}

func TestBearerToken(t *testing.T) {
	if value := bearerToken("Bearer gateway-secret"); value != "gateway-secret" {
		t.Fatalf("unexpected bearer token %q", value)
	}
	if value := bearerToken("Basic abc"); value != "" {
		t.Fatalf("unexpected non-bearer token %q", value)
	}
}

func BenchmarkExtractAuditText(b *testing.B) {
	body := []byte(`{"model":"demo","messages":[{"role":"user","content":"Explain how to improve defensive monitoring and incident response."}]}`)
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		_ = ExtractAuditText(body, 256*1024)
	}
}
