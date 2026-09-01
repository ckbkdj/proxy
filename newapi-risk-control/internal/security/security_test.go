package security

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCipherRoundTripAndTamperDetection(t *testing.T) {
	cipher, err := NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cipher.EncryptString("provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cipher.DecryptString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != "provider-secret" {
		t.Fatalf("unexpected plaintext %q", decoded)
	}
	tampered := encoded[:len(encoded)-1] + "A"
	if tampered == encoded {
		tampered = encoded[:len(encoded)-1] + "B"
	}
	if _, err := cipher.DecryptString(tampered); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestJWTClaims(t *testing.T) {
	secret := strings.Repeat("j", 40)
	token, err := IssueJWT(secret, "user-id", "admin", "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ParseJWT(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-id" || claims.Username != "admin" || claims.Role != "admin" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if _, err := ParseJWT(strings.Repeat("x", 40), token); err == nil {
		t.Fatal("token verified with the wrong secret")
	}
}

func TestTraceSignature(t *testing.T) {
	secret := strings.Repeat("s", 40)
	body := []byte(`{"external_request_id":"req-1"}`)
	now := time.Now().UTC()
	nonce := "nonce-1"
	signature := CanonicalTraceSignature(secret, now.Unix(), nonce, body)
	if err := VerifyTraceSignature(secret, now.Unix(), nonce, signature, body, now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTraceSignature(secret, now.Add(-10*time.Minute).Unix(), nonce, signature, body, now, 5*time.Minute); err == nil {
		t.Fatal("stale timestamp was accepted")
	}
	if err := VerifyTraceSignature(secret, now.Unix(), nonce, signature, []byte(`{"changed":true}`), now, 5*time.Minute); err == nil {
		t.Fatal("signature accepted a modified body")
	}
}

func TestSanitizeMetadataRemovesSensitiveFields(t *testing.T) {
	cleaned := SanitizeMetadata(map[string]interface{}{
		"request_id":    "req-1",
		"authorization": "Bearer secret",
		"nested": map[string]interface{}{
			"prompt": "private prompt",
			"region": "us-east",
		},
	}, 64<<10)
	var value map[string]interface{}
	if err := json.Unmarshal(cleaned, &value); err != nil {
		t.Fatal(err)
	}
	if _, exists := value["authorization"]; exists {
		t.Fatal("authorization survived metadata sanitization")
	}
	nested := value["nested"].(map[string]interface{})
	if _, exists := nested["prompt"]; exists {
		t.Fatal("prompt survived metadata sanitization")
	}
	if nested["region"] != "us-east" || value["request_id"] != "req-1" {
		t.Fatalf("safe metadata was lost: %s", cleaned)
	}
}

func TestUUIDShapeAndUniqueness(t *testing.T) {
	first := NewUUID()
	second := NewUUID()
	if first == second {
		t.Fatal("UUID collision")
	}
	if len(first) != 36 || first[14] != '4' {
		t.Fatalf("invalid UUIDv4 shape: %q", first)
	}
}
