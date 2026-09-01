package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"`
	} `json:"messages"`
}

func main() {
	address := os.Getenv("MOCK_ADDR")
	if address == "" {
		address = ":18081"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/audit/v1/chat/completions", auditHandler)
	mux.HandleFunc("/", providerHandler)
	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Printf("mock provider listening on %s", address)
	log.Fatal(server.ListenAndServe())
}

func auditHandler(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeChat(w, r)
	if !ok {
		return
	}
	text := strings.ToLower(messageText(request))
	decision := "allow"
	riskCode := ""
	category := "benign"
	confidence := 0.99
	reason := "deterministic mock allow"
	if strings.Contains(text, "model-audit-block") {
		decision = "block"
		riskCode = "CYBER_MOCK_MODEL_BLOCK"
		category = "mock_harm"
		reason = "deterministic mock block"
	}
	if strings.Contains(text, "model-audit-review") {
		decision = "review"
		riskCode = "CYBER_MOCK_REVIEW"
		category = "mock_review"
		confidence = 0.5
		reason = "deterministic mock review"
	}
	if strings.Contains(text, "model-audit-invalid-json") {
		writeJSON(w, http.StatusOK, map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]any{"role": "assistant", "content": "not-json"},
			}},
		})
		return
	}
	classification, _ := json.Marshal(map[string]any{
		"decision":   decision,
		"risk_code":  riskCode,
		"category":   category,
		"confidence": confidence,
		"reason":     reason,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "audit-mock",
		"choices": []any{map[string]any{
			"message": map[string]any{
				"role":    "assistant",
				"content": string(classification),
			},
		}},
	})
}

func providerHandler(w http.ResponseWriter, r *http.Request) {
	request, ok := decodeChat(w, r)
	if !ok {
		return
	}
	switch request.Model {
	case "upstream-http-error":
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": map[string]any{"message": "mock provider HTTP failure", "type": "server_error"},
		})
		return
	case "upstream-200-error":
		writeJSON(w, http.StatusOK, map[string]any{
			"error": map[string]any{"message": "mock provider logical failure", "type": "provider_error"},
		})
		return
	case "stream-first-error":
		streamFirstError(w)
		return
	case "stream-late-error":
		streamLateError(w)
		return
	case "stream-normal":
		streamNormal(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     "completion-mock",
		"object": "chat.completion",
		"choices": []any{map[string]any{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": "mock provider success"},
			"finish_reason": "stop",
		}},
	})
}

func decodeChat(w http.ResponseWriter, r *http.Request) (chatRequest, bool) {
	defer r.Body.Close()
	var request chatRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": map[string]any{"message": err.Error(), "type": "invalid_request_error"},
		})
		return chatRequest{}, false
	}
	return request, true
}

func messageText(request chatRequest) string {
	var builder strings.Builder
	for _, message := range request.Messages {
		builder.WriteString(message.Role)
		builder.WriteByte(':')
		switch content := message.Content.(type) {
		case string:
			builder.WriteString(content)
		default:
			encoded, _ := json.Marshal(content)
			builder.Write(encoded)
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}

func streamFirstError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "event: error\n")
	_, _ = fmt.Fprint(w, "data: {\"error\":{\"message\":\"first event failed\"}}\n\n")
	flush(w)
}

func streamLateError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n")
	flush(w)
	time.Sleep(20 * time.Millisecond)
	_, _ = fmt.Fprint(w, "event: error\n")
	_, _ = fmt.Fprint(w, "data: {\"error\":{\"message\":\"late stream failure\"}}\n\n")
	flush(w)
}

func streamNormal(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	writer := bufio.NewWriter(w)
	_, _ = writer.WriteString("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n")
	_, _ = writer.WriteString("data: [DONE]\n\n")
	_ = writer.Flush()
	flush(w)
}

func flush(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
