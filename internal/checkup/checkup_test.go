package checkup

import (
	"testing"
	"time"
)

func TestParseCategories(t *testing.T) {
	cats, err := ParseCategories([]string{"activation", "dns", "tls"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cats) != 3 {
		t.Fatalf("expected 3 categories, got %d", len(cats))
	}
	if _, err := ParseCategories([]string{"invalid"}); err == nil {
		t.Fatal("expected invalid category error")
	}
}

func TestOptionsValidate(t *testing.T) {
	opts := DefaultOptions()
	opts.Only = []Category{CategoryDNS}
	opts.Skip = []Category{CategoryTLS}
	if err := opts.Validate(); err == nil {
		t.Fatal("expected only/skip conflict")
	}

	opts = DefaultOptions()
	opts.Yes = true
	if err := opts.Validate(); err == nil {
		t.Fatal("expected yes requires fix")
	}

	opts = DefaultOptions()
	opts.DryRun = true
	if err := opts.Validate(); err == nil {
		t.Fatal("expected dry-run requires fix")
	}
}

func TestNormalizePath(t *testing.T) {
	if got := NormalizePath("healthz"); got != "/healthz" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizePath(""); got != "/" {
		t.Fatalf("got %q", got)
	}
}

func TestComputeExitCode(t *testing.T) {
	summary := Summary{Passed: 2}
	if code := ComputeExitCode(summary, false, nil, false); code != ExitOK {
		t.Fatalf("got %d", code)
	}
	summary.Warnings = 1
	if code := ComputeExitCode(summary, true, nil, false); code != ExitChecksFailed {
		t.Fatalf("got %d", code)
	}
	summary.Failed = 1
	if code := ComputeExitCode(summary, false, nil, false); code != ExitChecksFailed {
		t.Fatalf("got %d", code)
	}
	if code := ComputeExitCode(Summary{Errors: 1}, false, nil, false); code != ExitProbeError {
		t.Fatalf("errors should exit 3, got %d", code)
	}
}

func TestNormalizeSmartCheckStatus(t *testing.T) {
	if got := NormalizeSmartCheckStatus("safe"); got != StatusPass {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeSmartCheckStatus("unknown-thing"); got != StatusWarn {
		t.Fatalf("got %q", got)
	}
}

func TestSmartCheckStaleness(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	label, status := SmartCheckStaleness(now.Add(-2*time.Hour).Format(time.RFC3339), now)
	if label != "current" || status != StatusPass {
		t.Fatalf("got %q %q", label, status)
	}
	label, status = SmartCheckStaleness(now.Add(-72*time.Hour).Format(time.RFC3339), now)
	if label != "aging" || status != StatusWarn {
		t.Fatalf("got %q %q", label, status)
	}
	label, status = SmartCheckStaleness(now.Add(-240*time.Hour).Format(time.RFC3339), now)
	if label != "stale" || status != StatusWarn {
		t.Fatalf("got %q %q", label, status)
	}
}

func TestTLSExpirySeverity(t *testing.T) {
	status, severity := TLSExpirySeverity(4, false)
	if status != StatusFail || severity != SeverityHigh {
		t.Fatalf("got %q %q", status, severity)
	}
	status, severity = TLSExpirySeverity(-1, true)
	if status != StatusFail || severity != SeverityCritical {
		t.Fatalf("got %q %q", status, severity)
	}
}

func TestIsMailRelatedHostname(t *testing.T) {
	if !IsMailRelatedHostname("mail.example.com") {
		t.Fatal("expected mail hostname")
	}
	if IsMailRelatedHostname("www.example.com") {
		t.Fatal("expected non-mail hostname")
	}
}

func TestDetectEdgeEvidence(t *testing.T) {
	if ev := DetectEdgeEvidence(map[string]string{"x-poweredby": "VergeCloud"}); ev.Confidence != "strong" || !ev.Detected {
		t.Fatal("expected strong edge detection for powered-by")
	}
	if ev := DetectEdgeEvidence(map[string]string{"x-verge-request-id": "abc"}); ev.Confidence != "strong" {
		t.Fatal("expected strong edge detection for verge request id")
	}
	if ev := DetectEdgeEvidence(map[string]string{"x-request-id": "abc"}); ev.Confidence != "weak" || ev.Detected {
		t.Fatal("generic request id should be weak only")
	}
	if ev := DetectEdgeEvidence(map[string]string{"server": "nginx"}); ev.Confidence != "none" {
		t.Fatal("expected no edge detection for nginx")
	}
}

func TestSortFindingsDeterministic(t *testing.T) {
	findings := []Finding{
		{ID: "b", Category: "dns", Status: StatusPass, Severity: SeverityInfo},
		{ID: "a", Category: "activation", Status: StatusFail, Severity: SeverityHigh},
		{ID: "c", Category: "dns", Status: StatusWarn, Severity: SeverityMedium},
	}
	SortFindings(findings)
	if findings[0].Status != StatusFail {
		t.Fatalf("expected fail first, got %q", findings[0].Status)
	}
}

func TestRegistryDependencies(t *testing.T) {
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	checks, err := reg.ChecksForCategories(map[Category]bool{CategoryCDN: true})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(checks))
	for i, c := range checks {
		ids[i] = c.ID()
	}
	if len(checks) != 1 || checks[0].ID() != "cdn" {
		t.Fatalf("expected only cdn check, got %v", ids)
	}
}

func TestBoolRemediation(t *testing.T) {
	if got := BoolRemediation("cloud", false); got != "--cloud=false" {
		t.Fatalf("got %q", got)
	}
}

func TestNSSetsMatch(t *testing.T) {
	if !NSSetsMatch([]string{"ns1.example.com", "ns2.example.com"}, []string{"NS2.example.com.", "NS1.example.com"}) {
		t.Fatal("expected match")
	}
}
