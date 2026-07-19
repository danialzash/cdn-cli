package checkup

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestReportJSON(t *testing.T) {
	report := Report{
		Domain:      DomainSummary{Name: "example.com", ID: "id"},
		Options:     DefaultOptions(),
		StartedAt:   time.Now(),
		CompletedAt: time.Now(),
		Duration:    DurationJSON(time.Second),
		Findings: []Finding{{
			ID: "dns.apex-resolution", Category: "dns", Status: StatusPass,
			Severity: SeverityInfo, Summary: "ok",
		}},
		Summary:  Summary{Passed: 1},
		ExitCode: ExitOK,
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("\x1b[")) {
		t.Fatal("json must not contain ANSI")
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Findings[0].ID != "dns.apex-resolution" {
		t.Fatal("missing finding id")
	}
}

func TestGoldenFindingOrder(t *testing.T) {
	findings := []Finding{
		{ID: "dns.apex-resolution", Status: StatusPass},
		{ID: "cache.developer-mode", Status: StatusWarn},
		{ID: "tls.certificate-expiry", Status: StatusFail},
	}
	SortFindings(findings)
	if findings[0].Status != StatusFail {
		t.Fatalf("expected fail first, got %q", findings[0].Status)
	}
}

func TestCollectFixPlansSafeOnly(t *testing.T) {
	findings := []Finding{{
		Fix: &FixPlan{ID: "cache.developer-mode", Safety: FixSafetySafe, Automatic: true},
	}, {
		Fix: &FixPlan{ID: "activation.nameservers", Safety: FixSafetyExternal, Automatic: false},
	}}
	plans := CollectFixPlans(findings)
	if len(plans) != 1 || plans[0].ID != "cache.developer-mode" {
		t.Fatalf("got %#v", plans)
	}
}
