package checkup

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/client"
)

func TestClassifyDNSErrorCases(t *testing.T) {
	cases := []struct {
		err  error
		want DNSLookupClassification
	}{
		{&net.DNSError{IsNotFound: true}, DNSLookupNotFound},
		{&net.DNSError{IsTimeout: true}, DNSLookupTimeout},
		{&net.DNSError{IsTemporary: true}, DNSLookupUnavailable},
		{context.Canceled, DNSLookupCancelled},
		{context.DeadlineExceeded, DNSLookupTimeout},
		{errors.New("connection refused"), DNSLookupUnavailable},
	}
	for _, tc := range cases {
		if got := ClassifyDNSError(tc.err); got != tc.want {
			t.Fatalf("%v: got %q want %q", tc.err, got, tc.want)
		}
	}
}

func TestApexNotFoundFailsNotProbeError(t *testing.T) {
	check := &DNSCheck{}
	findings := check.lookupFinding("dns.apex-resolution", "example.com", DNSLookupResult{
		Classification: DNSLookupNotFound,
	}, true)
	if findings[0].Status != StatusFail {
		t.Fatalf("got %q", findings[0].Status)
	}
	if DNSLookupNotFound.IsProbeError() {
		t.Fatal("not found should not be probe error")
	}
}

func TestResolverUnavailableIsProbeError(t *testing.T) {
	check := &DNSCheck{}
	findings := check.lookupFinding("dns.apex-resolution", "example.com", DNSLookupResult{
		Classification: DNSLookupUnavailable,
		Error:          "connection refused",
	}, true)
	if findings[0].Status != StatusError {
		t.Fatalf("got %q", findings[0].Status)
	}
}

func TestWAFAPIFailureDoesNotReportOff(t *testing.T) {
	check := &SecurityCheck{}
	findings := check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "waf", Error: "timeout"}},
			WAF:    client.WafInspect{Mode: "off"},
		},
		HTTPSProbe: &HTTPProbeResult{AnalysisHeaders: map[string]string{"x-frame-options": "DENY"}},
	})
	for _, f := range findings {
		if f.ID == "security.waf-mode" {
			t.Fatal("must not report WAF off when API failed")
		}
	}
	foundAPI := false
	for _, f := range findings {
		if f.ID == "security.waf-api" {
			foundAPI = true
		}
	}
	if !foundAPI {
		t.Fatal("expected waf api error finding")
	}
}

func TestDNSAPIFailureDoesNotReportEmpty(t *testing.T) {
	check := &DNSCheck{}
	findings := check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "dns", Error: "500"}},
			DNS:    client.DNSInspect{Count: 0},
		},
	})
	for _, f := range findings {
		if f.ID == "configuration.empty-dns" || f.ID == "dns.apex-resolution" {
			t.Fatalf("unexpected finding %q", f.ID)
		}
	}
	if len(findings) != 1 || findings[0].ID != "dns.api" {
		t.Fatalf("got %+v", findings)
	}
}

func TestCacheAPIFailureDoesNotReportDeveloperModePass(t *testing.T) {
	check := &CacheCheck{}
	findings := check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "cache", Error: "timeout"}},
			Cache:  client.CacheInspect{DeveloperMode: false, Status: "on"},
		},
		HTTPSProbe:       &HTTPProbeResult{Headers: map[string]string{"x-cache": "HIT"}},
		SecondHTTPSProbe: &HTTPProbeResult{Headers: map[string]string{"x-cache": "HIT"}},
	})
	for _, f := range findings {
		if f.ID == "cache.developer-mode" && f.Status == StatusPass {
			t.Fatal("must not pass developer mode when cache API failed")
		}
	}
}

func TestSSLAPIFailureBlocksRedirectConfigComparison(t *testing.T) {
	check := &HTTPCheck{}
	findings := check.redirectToHTTPSFinding(&State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "ssl", Error: "timeout"}},
			SSL:    client.SslInspect{HTTPSRedirect: true},
		},
		HTTPProbe:  &HTTPProbeResult{FinalURL: "http://example.com/", StatusCode: 200},
		HTTPSProbe: &HTTPProbeResult{StatusCode: 200},
		TLSProbe:   &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	if len(findings) != 1 || findings[0].ID != "http.ssl-api" {
		t.Fatalf("got %+v", findings)
	}
	if findings[0].Fix != nil {
		t.Fatal("must not offer automatic fix when SSL API is unavailable")
	}
}
