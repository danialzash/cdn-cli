package output

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func TestPrintCheckupReportGolden(t *testing.T) {
	report := checkup.Report{
		Domain: checkup.DomainSummary{
			Name: "example.com", ID: "11111111-1111-1111-1111-111111111111",
			Type: "full", Status: "active",
		},
		Options:     checkup.Options{Path: "/"},
		StartedAt:   time.Date(2026, 7, 17, 10, 20, 31, 0, time.UTC),
		CompletedAt: time.Date(2026, 7, 17, 10, 20, 33, 0, time.UTC),
		Duration:    checkup.DurationJSON(1830 * time.Millisecond),
		Findings: []checkup.Finding{
			{ID: "dns.apex-resolution", Category: "dns", Status: checkup.StatusPass, Severity: checkup.SeverityInfo, Summary: "example.com resolves successfully."},
			{ID: "dns.mail-cloud-proxy", Category: "dns", Status: checkup.StatusWarn, Severity: checkup.SeverityMedium, Summary: "mail.example.com is cloud-enabled.", SuggestedCommands: []string{"verge dns update example.com rec1 --cloud=false"}},
			{ID: "tls.certificate-expiry", Category: "tls", Status: checkup.StatusFail, Severity: checkup.SeverityHigh, Summary: "Certificate expires in 4 days."},
		},
		Summary: checkup.Summary{Passed: 1, Warnings: 1, Failed: 1},
	}

	f, err := os.CreateTemp("", "checkup-out-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	p := &Printer{JSON: false, Out: f}
	if err := p.PrintCheckupReport(report); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	out := stripANSI(string(raw))
	if !strings.Contains(out, "Domain checkup: example.com") {
		t.Fatalf("missing header:\n%s", out)
	}
	if !strings.Contains(out, "dns.mail-cloud-proxy") {
		t.Fatalf("missing finding:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("must not contain ANSI when stripped test runs on raw - check strip")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	skip := false
	for _, r := range s {
		if r == '\x1b' {
			skip = true
			continue
		}
		if skip {
			if r == 'm' {
				skip = false
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
