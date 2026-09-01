package audit

import (
	"net"
	"testing"
)

func TestAuditForbiddenIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"10.0.0.1",
		"100.64.0.1",
		"169.254.169.254",
		"192.0.2.1",
		"198.18.0.1",
		"203.0.113.1",
		"::1",
		"fc00::1",
		"fe80::1",
		"2001:db8::1",
	}
	for _, raw := range blocked {
		if !auditForbiddenIP(net.ParseIP(raw)) {
			t.Fatalf("reserved address was allowed: %s", raw)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, raw := range allowed {
		if auditForbiddenIP(net.ParseIP(raw)) {
			t.Fatalf("public address was rejected: %s", raw)
		}
	}
}
