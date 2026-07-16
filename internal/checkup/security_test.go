package checkup

import (
	"testing"
)

func TestSecurityHeadersMissingIsWarn(t *testing.T) {
	check := &SecurityCheck{}
	findings := check.securityHeadersFinding(&State{
		HTTPSProbe: &HTTPProbeResult{
			Headers: map[string]string{"server": "nginx"},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Status != StatusWarn {
		t.Fatalf("expected warn, got %q", findings[0].Status)
	}
}

func TestSecurityHeadersPresentIsPass(t *testing.T) {
	check := &SecurityCheck{}
	findings := check.securityHeadersFinding(&State{
		HTTPSProbe: &HTTPProbeResult{
			Headers: map[string]string{
				"content-security-policy": "default-src 'self'",
				"x-content-type-options":  "nosniff",
				"referrer-policy":         "no-referrer",
				"permissions-policy":      "geolocation=()",
				"x-frame-options":         "DENY",
			},
		},
	})
	if len(findings) != 1 || findings[0].Status != StatusPass {
		t.Fatalf("expected pass, got %#v", findings)
	}
}
