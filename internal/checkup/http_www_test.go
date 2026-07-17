package checkup

import (
	"testing"

	"github.com/vergecloud/cdn-cli/internal/client"
)

func TestHTTPSRedirectEnabledAndObservedPass(t *testing.T) {
	check := &HTTPCheck{}
	findings := check.redirectToHTTPSFinding(&State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    &client.DomainInspect{SSL: client.SslInspect{HTTPSRedirect: true}},
		HTTPProbe:  &HTTPProbeResult{FinalURL: "https://example.com/", StatusCode: 301, URL: "http://example.com/"},
		HTTPSProbe: &HTTPProbeResult{StatusCode: 200, FinalURL: "https://example.com/", URL: "https://example.com/"},
		TLSProbe:   &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	if len(findings) != 1 || findings[0].Status != StatusPass || findings[0].Fix != nil {
		t.Fatalf("got %+v", findings[0])
	}
}

func TestHTTPSRedirectEnabledNotObservedWarnNoFix(t *testing.T) {
	check := &HTTPCheck{}
	findings := check.redirectToHTTPSFinding(&State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    &client.DomainInspect{SSL: client.SslInspect{HTTPSRedirect: true}},
		HTTPProbe:  &HTTPProbeResult{FinalURL: "http://example.com/", StatusCode: 200, URL: "http://example.com/"},
		HTTPSProbe: &HTTPProbeResult{StatusCode: 200, FinalURL: "https://example.com/", URL: "https://example.com/"},
		TLSProbe:   &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	if findings[0].Status != StatusWarn || findings[0].Fix != nil {
		t.Fatalf("got %+v", findings[0])
	}
}

func TestHTTPSRedirectDisabledHealthyOffersFix(t *testing.T) {
	check := &HTTPCheck{}
	findings := check.redirectToHTTPSFinding(&State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    &client.DomainInspect{SSL: client.SslInspect{HTTPSRedirect: false, Enabled: true}},
		HTTPProbe:  &HTTPProbeResult{FinalURL: "http://example.com/", StatusCode: 200, URL: "http://example.com/"},
		HTTPSProbe: &HTTPProbeResult{StatusCode: 200, FinalURL: "https://example.com/", URL: "https://example.com/"},
		TLSProbe:   &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	if findings[0].Fix == nil || findings[0].Fix.ID != "ssl.https-redirect" {
		t.Fatalf("got %+v", findings[0])
	}
}

func TestHTTPSRedirectDisabledUnhealthySkipsFix(t *testing.T) {
	check := &HTTPCheck{}
	findings := check.redirectToHTTPSFinding(&State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    &client.DomainInspect{SSL: client.SslInspect{HTTPSRedirect: false}},
		HTTPProbe:  &HTTPProbeResult{FinalURL: "http://example.com/", StatusCode: 200},
		HTTPSProbe: &HTTPProbeResult{Error: "connection refused"},
	})
	if findings[0].Status != StatusSkip || findings[0].Fix != nil {
		t.Fatalf("got %+v", findings[0])
	}
}

func TestWWWNotRequiredWhenOnlyHTTPSRedirect(t *testing.T) {
	state := &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			SSL: client.SslInspect{HTTPSRedirect: true},
			DNS: client.DNSInspect{Records: []client.DNSRecord{{Name: "@", Type: "A"}}},
		},
	}
	if wwwRequired(state) {
		t.Fatal("HTTPS redirect alone must not require www")
	}
}

func TestWWWRequiredWhenRecordConfigured(t *testing.T) {
	state := &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			DNS: client.DNSInspect{Records: []client.DNSRecord{{Name: "www", Type: "CNAME"}}},
		},
	}
	if !wwwRequired(state) {
		t.Fatal("configured www record should require www resolution")
	}
}

func TestWWWNotRequiredFromSmartCheckDescription(t *testing.T) {
	state := &State{
		Domain: DomainSummary{Name: "example.com"},
		SmartCheck: &client.SmartCheck{
			Items: []client.SmartCheckItem{{ID: "dns_ok", Details: "No www hostname is required."}},
		},
	}
	if wwwRequired(state) {
		t.Fatal("description containing www must not trigger requirement")
	}
}

func TestShouldNotProbeMailHostname(t *testing.T) {
	if shouldProbeCloudHostname("A", "mail", "example.com") {
		t.Fatal("mail hostname should not be probed")
	}
	if !shouldProbeCloudHostname("A", "api", "example.com") {
		t.Fatal("api hostname should be probed")
	}
}
