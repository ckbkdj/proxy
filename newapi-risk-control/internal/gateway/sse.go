package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type SSEProxyResult struct {
	Bytes          int64
	Status         int
	NormalizedCode int
	Outcome        string
}

func isSSE(contentType string, requestedStream bool) bool {
	return requestedStream || strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

// proxySSE keeps response headers uncommitted until it has inspected the first
// complete SSE event. After HTTP 200 has been committed, HTTP cannot change the
// status to 555; a standardized event:error carrying code 555 is emitted instead.
func proxySSE(
	w http.ResponseWriter,
	resp *http.Response,
	requestID string,
	maxFrameBytes int,
	gateBytes int,
	gateTimeout time.Duration,
) SSEProxyResult {
	_ = gateTimeout // The upstream request deadline is authoritative; the gate is event and byte bounded.
	if maxFrameBytes < 4096 {
		maxFrameBytes = 1 << 20
	}
	if gateBytes < 0 {
		gateBytes = 0
	}
	reader := bufio.NewReaderSize(resp.Body, minInt(maxFrameBytes, 64<<10))
	buffered := make([]byte, 0, minInt(gateBytes, maxFrameBytes))
	committed := false
	var written int64

	commit := func() {
		if committed {
			return
		}
		copyResponseHeaders(w.Header(), resp.Header)
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(resp.StatusCode)
		if len(buffered) > 0 {
			n, _ := w.Write(buffered)
			written += int64(n)
			buffered = buffered[:0]
		}
		flush(w)
		committed = true
	}

	for {
		frame, err := readSSEFrame(reader, maxFrameBytes)
		if len(frame) > 0 {
			if providerErrorFrame(frame) {
				if !committed {
					write555(w, requestID, "UPSTREAM_STREAM_ERROR")
					return SSEProxyResult{Status: RiskHTTPStatus, NormalizedCode: RiskHTTPStatus, Outcome: "stream_error_normalized"}
				}
				n := writeSSE555(w, requestID)
				written += int64(n)
				flush(w)
				return SSEProxyResult{Bytes: written, Status: resp.StatusCode, NormalizedCode: RiskHTTPStatus, Outcome: "stream_error_normalized_after_commit"}
			}
			if !committed {
				buffered = append(buffered, frame...)
				if containsSSEData(frame) || gateBytes == 0 || len(buffered) >= gateBytes {
					commit()
				}
			} else {
				n, writeErr := w.Write(frame)
				written += int64(n)
				flush(w)
				if writeErr != nil {
					return SSEProxyResult{Bytes: written, Status: resp.StatusCode, Outcome: "client_stream_closed"}
				}
			}
		}

		if err == nil {
			continue
		}
		if errors.Is(err, errSSEFrameTooLarge) {
			if !committed {
				write555(w, requestID, "UPSTREAM_STREAM_FRAME_TOO_LARGE")
				return SSEProxyResult{Status: RiskHTTPStatus, NormalizedCode: RiskHTTPStatus, Outcome: "stream_frame_rejected"}
			}
			n := writeSSE555(w, requestID)
			written += int64(n)
			flush(w)
			return SSEProxyResult{Bytes: written, Status: resp.StatusCode, NormalizedCode: RiskHTTPStatus, Outcome: "stream_frame_rejected_after_commit"}
		}
		if errors.Is(err, io.EOF) {
			if !committed {
				commit()
			}
			return SSEProxyResult{Bytes: written, Status: resp.StatusCode, Outcome: "allowed"}
		}
		if !committed {
			write555(w, requestID, "UPSTREAM_STREAM_READ_ERROR")
			return SSEProxyResult{Status: RiskHTTPStatus, NormalizedCode: RiskHTTPStatus, Outcome: "stream_read_error"}
		}
		return SSEProxyResult{Bytes: written, Status: resp.StatusCode, Outcome: "stream_read_error_after_commit"}
	}
}

var errSSEFrameTooLarge = errors.New("SSE frame exceeds configured limit")

func readSSEFrame(reader *bufio.Reader, max int) ([]byte, error) {
	var frame bytes.Buffer
	for {
		line, err := readLineLimited(reader, max-frame.Len())
		if len(line) > 0 {
			_, _ = frame.Write(line)
		}
		if frame.Len() > max {
			return frame.Bytes(), errSSEFrameTooLarge
		}
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(line) > 0 && len(trimmed) == 0 {
			return frame.Bytes(), nil
		}
		if err != nil {
			return frame.Bytes(), err
		}
	}
}

func readLineLimited(reader *bufio.Reader, remaining int) ([]byte, error) {
	if remaining <= 0 {
		return nil, errSSEFrameTooLarge
	}
	var out []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		out = append(out, fragment...)
		if len(out) > remaining {
			return out, errSSEFrameTooLarge
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return out, err
	}
}

func providerErrorFrame(frame []byte) bool {
	for _, line := range strings.Split(strings.ToLower(string(frame)), "\n") {
		if strings.TrimSpace(line) == "event: error" {
			return true
		}
	}
	dataParts := make([]string, 0, 2)
	for _, line := range strings.Split(string(frame), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data:") {
			dataParts = append(dataParts, strings.TrimSpace(strings.TrimPrefix(trimmed, "data:")))
		}
	}
	if len(dataParts) == 0 {
		return false
	}
	data := strings.Join(dataParts, "\n")
	if data == "[DONE]" {
		return false
	}
	var object map[string]interface{}
	if json.Unmarshal([]byte(data), &object) != nil {
		return false
	}
	if value, ok := object["error"]; ok && value != nil {
		return true
	}
	if kind, ok := object["type"].(string); ok && strings.Contains(strings.ToLower(kind), "error") {
		return true
	}
	return false
}

func containsSSEData(frame []byte) bool {
	for _, line := range strings.Split(string(frame), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "data:") {
			return true
		}
	}
	return false
}

func writeSSE555(w http.ResponseWriter, requestID string) int {
	body, _ := json.Marshal(map[string]interface{}{
		"error": map[string]interface{}{
			"message": "The upstream stream was terminated by the risk-control gateway.",
			"type":    "risk_control_error",
			"code":    RiskHTTPStatus,
		},
		"request_id": requestID,
	})
	n, _ := w.Write([]byte("event: error\ndata: " + string(body) + "\n\n"))
	return n
}

func flush(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
