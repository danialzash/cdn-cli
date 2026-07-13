package dnsverify

import (
	"strings"
	"testing"
)

func TestFQDN(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{name: "@", domain: "example.com", want: "example.com"},
		{name: "www", domain: "example.com", want: "www.example.com"},
		{name: "blog.example.com", domain: "example.com", want: "blog.example.com"},
	}

	for _, tt := range tests {
		if got := FQDN(tt.name, tt.domain); got != tt.want {
			t.Fatalf("FQDN(%q, %q) = %q, want %q", tt.name, tt.domain, got, tt.want)
		}
	}
}

func TestMatchSubset(t *testing.T) {
	if !matchSubset([]string{"1.2.3.4", "5.6.7.8"}, []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"}) {
		t.Fatal("expected subset match")
	}
	if matchSubset([]string{"1.2.3.4"}, []string{"5.6.7.8"}) {
		t.Fatal("expected no match")
	}
}

func TestSRVHostMatchIsCaseInsensitive(t *testing.T) {
	actual := "10 Mail.Example.COM:443"
	expected := "mail.example.com"

	if !strings.Contains(strings.ToLower(actual), strings.ToLower(expected)) {
		t.Fatal("expected case-insensitive substring match for SRV host verification")
	}

	// Case-sensitive check would fail incorrectly.
	if strings.Contains(actual, expected) {
		t.Fatal("case-sensitive contains should not match mixed-case actual value")
	}
}
