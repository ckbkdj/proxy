package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSSEErrorBeforeCommitReturnsHTTP555(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader("event: error\ndata: {\"error\":{\"code\":\"overloaded_error\"}}\n\n")),
	}
	recorder := httptest.NewRecorder()
	result := proxySSE(recorder, response, "req-1", 1<<20, 64<<10, time.Second)
	if recorder.Code != RiskHTTPStatus || result.Status != RiskHTTPStatus || result.NormalizedCode != RiskHTTPStatus {
		t.Fatalf("expected HTTP 555, recorder=%d result=%+v", recorder.Code, result)
	}
	if !strings.Contains(recorder.Body.String(), `"code":555`) {
		t.Fatalf("standardized 555 body missing: %s", recorder.Body.String())
	}
}

func TestSSENormalStreamPassesThrough(t *testing.T) {
	input := "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n"
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(input)),
	}
	recorder := httptest.NewRecorder()
	result := proxySSE(recorder, response, "req-2", 1<<20, 64<<10, time.Second)
	if recorder.Code != http.StatusOK || result.Outcome != "allowed" {
		t.Fatalf("normal stream failed: recorder=%d result=%+v", recorder.Code, result)
	}
	if recorder.Body.String() != input {
		t.Fatalf("stream changed:\n%s", recorder.Body.String())
	}
}

func TestSSEErrorAfterCommitEmits555Event(t *testing.T) {
	input := "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\nevent: error\ndata: {\"error\":{\"code\":\"upstream_unavailable\"}}\n\n"
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(input)),
	}
	recorder := httptest.NewRecorder()
	result := proxySSE(recorder, response, "req-3", 1<<20, 64<<10, time.Second)
	if recorder.Code != http.StatusOK {
		t.Fatalf("already committed stream should remain HTTP 200, got %d", recorder.Code)
	}
	if result.NormalizedCode != RiskHTTPStatus || result.Outcome != "stream_error_normalized_after_commit" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(recorder.Body.String(), "event: error") || !strings.Contains(recorder.Body.String(), `"code":555`) {
		t.Fatalf("555 SSE error event missing: %s", recorder.Body.String())
	}
}

func TestSSEFrameLimit(t *testing.T) {
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader("data: " + strings.Repeat("x", 5000) + "\n\n")),
	}
	recorder := httptest.NewRecorder()
	result := proxySSE(recorder, response, "req-4", 4096, 4096, time.Second)
	if recorder.Code != RiskHTTPStatus || result.Outcome != "stream_frame_rejected" {
		t.Fatalf("oversized SSE frame was not rejected: recorder=%d result=%+v", recorder.Code, result)
	}
}
