package platform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Security struct {
	masterKey []byte
	jwtSecret []byte
	issuer    string
	jwtTTL    time.Duration
}

type AdminClaims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func NewSecurity(cfg Config) *Security {
	return &Security{
		masterKey: append([]byte(nil), cfg.MasterKey...),
		jwtSecret: append([]byte(nil), cfg.JWTSecret...),
		issuer:    cfg.JWTIssuer,
		jwtTTL:    cfg.JWTTTL,
	}
}

func (s *Security) Encrypt(scope string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, []byte(scope))
	result := make([]byte, 1+len(nonce)+len(sealed))
	result[0] = 1
	copy(result[1:], nonce)
	copy(result[1+len(nonce):], sealed)
	return result, nil
}

func (s *Security) Decrypt(scope string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}
	if ciphertext[0] != 1 {
		return nil, errors.New("unsupported ciphertext version")
	}
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 1+gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("ciphertext is truncated")
	}
	nonce := ciphertext[1 : 1+gcm.NonceSize()]
	payload := ciphertext[1+gcm.NonceSize():]
	return gcm.Open(nil, nonce, payload, []byte(scope))
}

func (s *Security) Digest(scope, value string) string {
	mac := hmac.New(sha256.New, s.masterKey)
	_, _ = mac.Write([]byte(scope))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Security) VerifyDigest(scope, value, expectedHex string) bool {
	actual, err := hex.DecodeString(s.Digest(scope, value))
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil || len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func (s *Security) PromptHMAC(text string) string {
	return s.Digest("prompt-hmac-v1", text)
}

func (s *Security) IssueAdminToken(user AdminUser) (string, error) {
	now := time.Now().UTC()
	claims := AdminClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   strconv.FormatInt(user.ID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.jwtTTL)),
			ID:        NewRequestID(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *Security) ParseAdminToken(raw string) (*AdminClaims, error) {
	claims := &AdminClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected JWT signing method %q", token.Method.Alg())
		}
		return s.jwtSecret, nil
	}, jwt.WithIssuer(s.issuer), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || token == nil || !token.Valid {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

func HashPassword(password string) (string, error) {
	if len(password) < 14 {
		return "", errors.New("password must contain at least 14 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(hash), err
}

func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func GenerateSecret(bytesCount int) (string, error) {
	if bytesCount < 16 {
		bytesCount = 16
	}
	buffer := make([]byte, bytesCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func NewRequestID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		now := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		copy(buffer, now[:16])
	}
	buffer[6] = (buffer[6] & 0x0f) | 0x40
	buffer[8] = (buffer[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(buffer)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32]
}

func TrackingCanonical(timestamp, nonce string, body []byte) string {
	digest := sha256.Sum256(body)
	return timestamp + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
}

func SignTracking(secret, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(TrackingCanonical(timestamp, nonce, body)))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyTrackingSignature(secret, timestamp, nonce string, body []byte, signature string) bool {
	signature = strings.TrimSpace(strings.TrimPrefix(signature, "sha256="))
	expected, err := hex.DecodeString(SignTracking(secret, timestamp, nonce, body))
	if err != nil {
		return false
	}
	actual, err := hex.DecodeString(signature)
	if err != nil || len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1
}
