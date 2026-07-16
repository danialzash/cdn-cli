package checkup

import (
	"strings"
	"testing"
)

func TestActivationCNAMEUsesResolvedTarget(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		Domain: DomainSummary{
			Name:        "app.example.com",
			Type:        "partial",
			CnameTarget: "edge.example.cdn.net",
		},
		CnameCheck: &CnameCheckResult{
			ResolvedTarget: "wrong.example.com",
			ExpectedTarget: "edge.example.cdn.net",
			LiveMatches:    false,
			APIStatus:      "pending",
		},
	})
	if len(findings) != 1 {
		t.Fatal(findings)
	}
	if findings[0].Status != StatusFail {
		t.Fatalf("expected fail, got %q", findings[0].Status)
	}
	if !strings.Contains(findings[0].Summary, "wrong.example.com") {
		t.Fatalf("summary missing resolved target: %q", findings[0].Summary)
	}
	if findings[0].Fix == nil {
		t.Fatal("expected fix plan for CNAME mismatch failure")
	}
}

func TestActivationCNAMEAPIActiveLiveMismatchFails(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		Domain: DomainSummary{Name: "app.example.com", Type: "partial", CnameTarget: "edge.example.cdn.net"},
		CnameCheck: &CnameCheckResult{
			APIStatus: "active", ResolvedTarget: "wrong.example.com", ExpectedTarget: "edge.example.cdn.net", LiveMatches: false,
		},
	})
	if findings[0].Status != StatusFail {
		t.Fatalf("expected fail, got %q", findings[0].Status)
	}
}

func TestActivationCNAMEPendingLiveMatchWarns(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		Domain: DomainSummary{Name: "app.example.com", Type: "partial", CnameTarget: "edge.example.cdn.net"},
		CnameCheck: &CnameCheckResult{
			APIStatus: "pending", ResolvedTarget: "edge.example.cdn.net", LiveMatches: true,
		},
	})
	if findings[0].Status != StatusWarn {
		t.Fatalf("expected warn, got %q", findings[0].Status)
	}
}

func TestActivationCNAMEUnavailableIsError(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		Domain: DomainSummary{Name: "app.example.com", Type: "partial", CnameTarget: "edge.example.cdn.net"},
	})
	if findings[0].Status != StatusError {
		t.Fatalf("expected error, got %q", findings[0].Status)
	}
	if findings[0].Fix != nil {
		t.Fatal("error case must not include a fix plan")
	}
}
