package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Cipher struct{ aead cipher.AEAD }

func NewCipher(key []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	aead, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) EncryptString(value string) (string, error) {
	if value == "" { return "", nil }
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return "", err }
	sealed := c.aead.Seal(nil, nonce, []byte(value), nil)
	blob := append(nonce, sealed...)
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

func (c *Cipher) DecryptString(encoded string) (string, error) {
	if encoded == "" { return "", nil }
	blob, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil { return "", fmt.Errorf("decode ciphertext: %w", err) }
	if len(blob) < c.aead.NonceSize() { return "", errors.New("ciphertext is too short") }
	plain, err := c.aead.Open(nil, blob[:c.aead.NonceSize()], blob[c.aead.NonceSize():], nil)
	if err != nil { return "", errors.New("decrypt secret: authentication failed") }
	return string(plain), nil
}

func RandomToken(bytes int) (string, error) {
	if bytes < 16 { bytes = 16 }
	b := make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashOpaque(secret, value string) string {
	if value == "" { return "" }
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func EqualHash(secret, value, expected string) bool {
	actual := HashOpaque(secret, value)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

func HashPassword(password string) (string, error) {
	if len(password) < 12 { return "", errors.New("password must contain at least 12 characters") }
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
}
func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func IssueJWT(secret, subject, username, role string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Username: username,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "riskgate",
			Subject: subject,
			Audience: jwt.ClaimStrings{"riskgate-admin"},
			IssuedAt: jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func ParseJWT(secret, tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 { return nil, errors.New("unexpected JWT signing method") }
		return []byte(secret), nil
	}, jwt.WithAudience("riskgate-admin"), jwt.WithIssuer("riskgate"), jwt.WithExpirationRequired())
	if err != nil || !token.Valid { return nil, errors.New("invalid or expired token") }
	return claims, nil
}

func CanonicalTraceSignature(secret string, timestamp int64, nonce string, body []byte) string {
	digest := sha256.Sum256(body)
	payload := strconv.FormatInt(timestamp, 10) + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyTraceSignature(secret string, timestamp int64, nonce, signature string, body []byte, now time.Time, skew time.Duration) error {
	if nonce == "" || len(nonce) > 256 { return errors.New("invalid nonce") }
	if skew <= 0 { skew = 5 * time.Minute }
	ts := time.Unix(timestamp, 0)
	if ts.Before(now.Add(-skew)) || ts.After(now.Add(skew)) { return errors.New("timestamp outside allowed window") }
	expected := CanonicalTraceSignature(secret, timestamp, nonce, body)
	got, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil { return errors.New("malformed signature") }
	want, _ := hex.DecodeString(expected)
	if subtle.ConstantTimeCompare(got, want) != 1 { return errors.New("signature mismatch") }
	return nil
}

var sensitiveFragments = []string{
	"authorization", "api_key", "apikey", "access_token", "refresh_token", "token", "secret",
	"password", "credential", "cookie", "prompt", "messages", "input", "instructions", "content",
}

func SanitizeMetadata(in map[string]interface{}, maxBytes int) json.RawMessage {
	clean := sanitizeMap(in, 0)
	b, err := json.Marshal(clean)
	if err != nil { return json.RawMessage(`{}`) }
	if maxBytes > 0 && len(b) > maxBytes {
		return json.RawMessage(`{"truncated":true}`)
	}
	return b
}

func sanitizeMap(in map[string]interface{}, depth int) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	if depth > 6 { return map[string]interface{}{"truncated": true} }
	for k, v := range in {
		lower := strings.ToLower(k)
		blocked := false
		for _, frag := range sensitiveFragments {
			if strings.Contains(lower, frag) { blocked = true; break }
		}
		if blocked { continue }
		switch typed := v.(type) {
		case map[string]interface{}:
			out[k] = sanitizeMap(typed, depth+1)
		case []interface{}:
			if len(typed) > 100 { typed = typed[:100] }
			clean := make([]interface{}, 0, len(typed))
			for _, item := range typed {
				if m, ok := item.(map[string]interface{}); ok { clean = append(clean, sanitizeMap(m, depth+1)) } else { clean = append(clean, item) }
			}
			out[k] = clean
		case string:
			if len(typed) > 1024 { typed = typed[:1024] }
			out[k] = typed
		default:
			out[k] = typed
		}
	}
	return out
}
