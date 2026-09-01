package platform

import "strings"

func metadataKeyLooksSensitive(lowerKey string) bool {
	lowerKey = strings.ToLower(strings.TrimSpace(lowerKey))
	if lowerKey == "" {
		return false
	}
	for _, fragment := range []string{
		"password",
		"passwd",
		"secret",
		"authorization",
		"cookie",
		"private_key",
		"session_key",
		"request_body",
		"response_body",
	} {
		if strings.Contains(lowerKey, fragment) {
			return true
		}
	}
	if lowerKey == "token" ||
		strings.HasSuffix(lowerKey, "_token") ||
		strings.HasSuffix(lowerKey, "_api_key") ||
		strings.HasSuffix(lowerKey, "_apikey") ||
		strings.Contains(lowerKey, "bearer_token") {
		return true
	}
	if lowerKey == "prompt" ||
		strings.HasSuffix(lowerKey, "_prompt") ||
		lowerKey == "messages" ||
		strings.HasSuffix(lowerKey, "_messages") ||
		lowerKey == "content" ||
		strings.HasSuffix(lowerKey, "_content") ||
		lowerKey == "input" ||
		strings.HasSuffix(lowerKey, "_input") ||
		lowerKey == "instructions" ||
		strings.HasSuffix(lowerKey, "_instructions") {
		return true
	}
	return false
}
