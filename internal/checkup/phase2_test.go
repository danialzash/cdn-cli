package checkup

import (
	"context"
	"strings"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

func TestActivationCNAMENXDOMAINFails(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		CnameCheck: &CnameCheckResult{
			ExpectedTarget: "edge.cdn.net",
			Classification: DNSLookupNotFound,
			ResolveError:   "NXDOMAIN",
		},
	})
	if findings[0].Status != StatusFail {
		t.Fatalf("got %q", findings[0].Status)
	}
}

func TestActivationCNAMETimeoutErrors(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		CnameCheck: &CnameCheckResult{
			ExpectedTarget: "edge.cdn.net",
			Classification: DNSLookupTimeout,
			ResolveError:   "timeout",
		},
	})
	if findings[0].Status != StatusError {
		t.Fatalf("got %q", findings[0].Status)
	}
}

func TestActivationCNAMEUsesExpectedTargetFromCheck(t *testing.T) {
	check := &ActivationCheck{}
	findings := check.checkCNAME(&State{
		Domain: DomainSummary{CnameTarget: "old.cdn.net"},
		CnameCheck: &CnameCheckResult{
			ExpectedTarget: "edge.cdn.net",
			ResolvedTarget: "wrong.cdn.net",
			Classification: DNSLookupFound,
			APIStatus:      "active",
		},
	})
	if findings[0].Status != StatusFail || !strings.Contains(findings[0].Summary, "edge.cdn.net") {
		t.Fatalf("got %+v", findings[0])
	}
}

func TestSSLAPIUnavailableProducesErrorNoFix(t *testing.T) {
	check := &HTTPCheck{}
	findings := check.redirectToHTTPSFinding(&State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "ssl", Error: "timeout"}},
			SSL:    client.SslInspect{HTTPSRedirect: false},
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

func TestRedirectObservedWithoutAPIOffersNoFix(t *testing.T) {
	check := &HTTPCheck{}
	findings := check.redirectToHTTPSFinding(&State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    &client.DomainInspect{SSL: client.SslInspect{HTTPSRedirect: false, Enabled: true}},
		HTTPProbe:  &HTTPProbeResult{FinalURL: "https://example.com/", StatusCode: 301},
		HTTPSProbe: &HTTPProbeResult{StatusCode: 200},
		TLSProbe:   &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	if findings[0].Fix != nil {
		t.Fatal("redirect already observed should not offer fix")
	}
}

func TestConfigurationDNSAPIErrorNoEmptyDNS(t *testing.T) {
	check := &ConfigurationCheck{}
	findings := check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "dns", Error: "500"}},
			DNS:    client.DNSInspect{Count: 0},
		},
	})
	for _, f := range findings {
		if f.ID == "configuration.empty-dns" {
			t.Fatal("must not warn about empty DNS when API failed")
		}
	}
}

func TestConfigurationSSLAPIErrorNoCertFinding(t *testing.T) {
	check := &ConfigurationCheck{}
	findings := check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "ssl", Error: "500"}},
			SSL:    client.SslInspect{Enabled: true},
		},
	})
	for _, f := range findings {
		if f.ID == "configuration.ssl-no-active-cert" {
			t.Fatal("must not fail cert check when SSL API failed")
		}
	}
}

func TestSecuritySSLAPIFailureStillAnalyzesHeaders(t *testing.T) {
	check := &SecurityCheck{}
	findings := check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "ssl", Error: "timeout"}},
		},
		HTTPSProbe: &HTTPProbeResult{
			StatusCode:      200,
			FinalURL:        "https://example.com/",
			URL:             "https://example.com/",
			AnalysisHeaders: map[string]string{"x-frame-options": "DENY", "strict-transport-security": "max-age=31536000"},
		},
		TLSProbe: &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	foundSSL := false
	foundHeaders := false
	for _, f := range findings {
		if f.ID == "security.ssl-api" {
			foundSSL = true
		}
		if f.ID == "security.response-headers" {
			foundHeaders = true
		}
	}
	if !foundSSL || !foundHeaders {
		t.Fatalf("got %+v", findings)
	}
}

func TestCacheSecondProbeMissingReportsError(t *testing.T) {
	check := &CacheCheck{}
	findings := check.Run(context.Background(), &State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    &client.DomainInspect{Cache: client.CacheInspect{Status: "on"}},
		HTTPSProbe: &HTTPProbeResult{Headers: map[string]string{"x-cache": "MISS"}},
	})
	found := false
	for _, f := range findings {
		if f.ID == "cache.repeated-request" && f.Status == StatusError {
			found = true
		}
	}
	if !found {
		t.Fatalf("got %+v", findings)
	}
}

func TestApexCloudRecordReusesHTTPSProbe(t *testing.T) {
	state := &State{
		Domain: DomainSummary{Name: "example.com", CnameTarget: "edge.cdn.net"},
		HTTPSProbe: &HTTPProbeResult{
			FinalURL:        "https://example.com/",
			AnalysisHeaders: map[string]string{"x-poweredby": "VergeCloud"},
		},
	}
	strong, source := cloudProxyStrongEvidenceForRecord(state, dnsverify.Result{Name: "@", Status: "ok"}, "example.com")
	if !strong || source != "hostname-edge-probe" {
		t.Fatalf("strong=%v source=%q", strong, source)
	}
}

func TestCnameTargetDoesNotSubstringMatch(t *testing.T) {
	if cnameTargetMatches("notedge.cdn.net", "edge.cdn.net") {
		t.Fatal("substring match must not count")
	}
	if !cnameTargetMatches("edge.cdn.net", "edge.cdn.net") {
		t.Fatal("exact match expected")
	}
	if !cnameTargetMatches("host.edge.cdn.net", "edge.cdn.net") {
		t.Fatal("suffix match expected")
	}
}

func TestCrossHostRedirectDoesNotProvideStrongEvidence(t *testing.T) {
	state := &State{
		Domain: DomainSummary{Name: "api.example.com"},
		HostEdgeProbes: map[string]*HTTPProbeResult{
			"api.example.com": {
				FinalURL:        "https://other.example/",
				AnalysisHeaders: map[string]string{"x-poweredby": "VergeCloud"},
				RedirectEvidence: RedirectEvidence{
					UnexpectedHosts: []string{"other.example"},
				},
			},
		},
	}
	strong, _ := hostnameEdgeProbeStrong(state, "api.example.com")
	if strong {
		t.Fatal("cross-host redirect must not provide strong evidence")
	}
}
