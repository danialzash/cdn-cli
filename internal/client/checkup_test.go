package client

import "testing"

func TestCnameTargetMatches(t *testing.T) {
	tests := []struct {
		resolved, expected string
		want               bool
	}{
		{"edge.example.cdn.net", "edge.example.cdn.net", true},
		{"edge.example.cdn.net.", "edge.example.cdn.net", true},
		{"www.edge.example.cdn.net", "edge.example.cdn.net", true},
		{"wrong.example.com", "edge.example.cdn.net", false},
		{"", "edge.example.cdn.net", false},
	}
	for _, tc := range tests {
		if got := cnameTargetMatches(tc.resolved, tc.expected); got != tc.want {
			t.Fatalf("cnameTargetMatches(%q, %q) = %v, want %v", tc.resolved, tc.expected, got, tc.want)
		}
	}
}

func TestNormalizeCnameHost(t *testing.T) {
	if got := normalizeCnameHost("host.example.com."); got != "host.example.com" {
		t.Fatalf("got %q", got)
	}
}
