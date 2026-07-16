package checkup

import (
	"strings"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/client"
)

func TestActivationCNAMEUsesResolvedTarget(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		Domain: DomainSummary{
			Name:        "app.example.com",
			Type:        "partial",
			CnameTarget: "edge.example.cdn.net",
		},
		CnameCheck: &client.CnameCheckResult{
			ResolvedTarget: "wrong.example.com",
			ExpectedTarget: "edge.example.cdn.net",
			Matches:        false,
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
}
