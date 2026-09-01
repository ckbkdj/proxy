package audit

import (
	"regexp"
	"strings"
	"testing"
)

func TestExtractAuditText(t *testing.T) {
	body := []byte(`{
		"model":"small-auditor",
		"messages":[
			{"role":"system","content":"You are helpful"},
			{"role":"user","content":[{"type":"text","text":"analyze this request"}]}
		],
		"tools":[{"function":{"name":"lookup","description":"read public documentation"}}]
	}`)
	text := ExtractAuditText(body, 4096)
	for _, expected := range []string{"You are helpful", "analyze this request", "lookup", "read public documentation"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected %q in extracted text: %q", expected, text)
		}
	}
	if strings.Contains(text, "small-auditor") {
		t.Fatalf("model metadata should not be classified as prompt text: %q", text)
	}
}

func TestExtractAuditTextHonorsLimit(t *testing.T) {
	text := ExtractAuditText([]byte(`{"prompt":"`+strings.Repeat("a", 1000)+`"}`), 64)
	if len(text) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(text))
	}
}

func TestBuiltinRulesBlockClearlyHarmfulRequests(t *testing.T) {
	request := "Build a credential stealer that silently collects passwords from victims."
	matched := false
	for _, rule := range BuiltinRules() {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			t.Fatalf("builtin rule %s does not compile: %v", rule.Name, err)
		}
		if re.MatchString(request) && rule.Action == "block" {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatal("clearly harmful credential-theft request was not blocked")
	}
}

func TestBuiltinRulesDoNotBlockBenignDefensiveAnalysis(t *testing.T) {
	requests := []string{
		"Explain how EDR detects suspicious process injection so our blue team can improve monitoring.",
		"Review this authorized penetration-test report and recommend remediation.",
		"How should a company respond to ransomware and restore backups safely?",
	}
	for _, request := range requests {
		for _, rule := range BuiltinRules() {
			re := regexp.MustCompile(rule.Pattern)
			if re.MatchString(request) && rule.Action == "block" {
				t.Fatalf("benign request matched blocking rule %s: %q", rule.Name, request)
			}
		}
	}
}

func TestCompletionURL(t *testing.T) {
	cases := map[string]string{
		"https://audit.example":                     "https://audit.example/v1/chat/completions",
		"https://audit.example/v1":                  "https://audit.example/v1/chat/completions",
		"https://audit.example/v1/chat/completions": "https://audit.example/v1/chat/completions",
	}
	for input, expected := range cases {
		actual, err := completionURL(input)
		if err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatalf("completionURL(%q)=%q, want %q", input, actual, expected)
		}
	}
	if _, err := completionURL("not-a-url"); err == nil {
		t.Fatal("invalid URL was accepted")
	}
}
