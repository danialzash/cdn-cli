package checkup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

func assertNoRedirectFix(t *testing.T, findings []Finding) {
	t.Helper()
	for _, f := range findings {
		if f.ID == "http.redirect-to-https" && f.Fix != nil {
			t.Fatal("redirect fix must not be offered when HTTP behavior was not observed")
		}
	}
}

func healthyHTTPSState() *State {
	return &State{
		Domain:  DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{SSL: client.SslInspect{HTTPSRedirect: false, Enabled: true}},
		HTTPProbe: &HTTPProbeResult{
			FinalURL: "http://example.com/", URL: "http://example.com/", StatusCode: 200,
		},
		HTTPSProbe: &HTTPProbeResult{
			StatusCode: 200, FinalURL: "https://example.com/", URL: "https://example.com/",
		},
		TLSProbe: &TLSProbeResult{Connected: true, HostnameMatch: true},
	}
}

func TestRedirectNoFixOnHTTPConnectionRefused(t *testing.T) {
	state := healthyHTTPSState()
	state.HTTPProbe = &HTTPProbeResult{Error: "connection refused"}
	findings := (&HTTPCheck{}).redirectToHTTPSFinding(state)
	assertNoRedirectFix(t, findings)
}

func TestRedirectNoFixOnHTTPTimeout(t *testing.T) {
	state := healthyHTTPSState()
	state.HTTPProbe = &HTTPProbeResult{Error: "context deadline exceeded", TimedOut: true}
	findings := (&HTTPCheck{}).redirectToHTTPSFinding(state)
	assertNoRedirectFix(t, findings)
}

func TestRedirectNoFixOnHTTPDNSFailure(t *testing.T) {
	state := healthyHTTPSState()
	state.HTTPProbe = &HTTPProbeResult{Error: "no such host"}
	findings := (&HTTPCheck{}).redirectToHTTPSFinding(state)
	assertNoRedirectFix(t, findings)
}

func TestRedirectNoFixOnMissingHTTPProbe(t *testing.T) {
	state := healthyHTTPSState()
	state.HTTPProbe = nil
	findings := (&HTTPCheck{}).redirectToHTTPSFinding(state)
	assertNoRedirectFix(t, findings)
}

func TestRedirectMayOfferFixOnValidHTTPWithoutRedirect(t *testing.T) {
	state := healthyHTTPSState()
	state.HTTPProbe = &HTTPProbeResult{FinalURL: "http://example.com/", StatusCode: 200}
	findings := (&HTTPCheck{}).redirectToHTTPSFinding(state)
	if len(findings) != 1 || findings[0].Fix == nil {
		t.Fatalf("expected redirect fix, got %+v", findings)
	}
}

func TestOnlyCacheHTTPSFailureVisible(t *testing.T) {
	source := &categoryTestSource{}
	runner, err := NewRunner(source)
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultOptions()
	opts.Only = []Category{CategoryCache}
	opts.ProbeTimeout = DurationJSON(200 * time.Millisecond)
	result := runner.Run(context.Background(), "127.0.0.1", opts)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	found := false
	for _, f := range result.Report.Findings {
		if f.ID == "cache.repeated-request" && (f.Status == StatusFail || f.Status == StatusError) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected cache probe failure, got %+v", result.Report.Findings)
	}
	if result.Report.ExitCode == ExitOK {
		t.Fatalf("expected nonzero exit, got %d", result.Report.ExitCode)
	}
}

func TestOnlyCDNHTTPSFailureVisible(t *testing.T) {
	source := &categoryTestSource{}
	runner, _ := NewRunner(source)
	opts := DefaultOptions()
	opts.Only = []Category{CategoryCDN}
	opts.ProbeTimeout = DurationJSON(200 * time.Millisecond)
	result := runner.Run(context.Background(), "127.0.0.1", opts)
	found := false
	for _, f := range result.Report.Findings {
		if f.ID == "cdn.edge-detected" && (f.Status == StatusFail || f.Status == StatusError) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected cdn edge failure, got %+v", result.Report.Findings)
	}
	if result.Report.ExitCode == ExitOK {
		t.Fatal("expected nonzero exit")
	}
}

func TestOnlySecurityHTTPSFailureVisible(t *testing.T) {
	source := &categoryTestSource{}
	runner, _ := NewRunner(source)
	opts := DefaultOptions()
	opts.Only = []Category{CategorySecurity}
	opts.ProbeTimeout = DurationJSON(200 * time.Millisecond)
	result := runner.Run(context.Background(), "127.0.0.1", opts)
	foundHTTPS := false
	foundWAF := false
	for _, f := range result.Report.Findings {
		if f.ID == "security.https-probe" && (f.Status == StatusFail || f.Status == StatusError) {
			foundHTTPS = true
		}
		if f.ID == "security.waf-mode" {
			foundWAF = true
		}
	}
	if !foundHTTPS || !foundWAF {
		t.Fatalf("expected https probe and waf findings, got %+v", result.Report.Findings)
	}
	if result.Report.ExitCode == ExitOK {
		t.Fatal("expected nonzero exit")
	}
}

func TestCustomCNAMEChainStrongEvidence(t *testing.T) {
	custom := "customer.custom-verge.example"
	state := &State{
		Domain: DomainSummary{
			Name:        "api.example.com",
			CnameTarget: "edge.cdn.net",
			CustomCname: custom,
		},
		HostCNAMEChains: map[string][]string{
			"api.example.com": {custom},
		},
	}
	strong, source := cloudProxyStrongEvidenceForRecord(state, dnsverify.Result{Name: "api", Actual: "1.2.3.4", Status: "ok"}, "api.example.com")
	if !strong || source != "custom-cname-target" {
		t.Fatalf("strong=%v source=%q", strong, source)
	}
}

func TestNormalCNAMEChainStrongEvidence(t *testing.T) {
	target := "edge.cdn.net"
	state := &State{
		Domain: DomainSummary{Name: "api.example.com", CnameTarget: target},
		HostCNAMEChains: map[string][]string{
			"api.example.com": {target},
		},
	}
	strong, source := cloudProxyStrongEvidenceForRecord(state, dnsverify.Result{Name: "api", Actual: "1.2.3.4", Status: "ok"}, "api.example.com")
	if !strong || source != "cname-target" {
		t.Fatalf("strong=%v source=%q", strong, source)
	}
}

func TestDirectCustomCNAMEStrongEvidence(t *testing.T) {
	custom := "customer.custom-verge.example"
	state := &State{Domain: DomainSummary{CustomCname: custom}}
	strong, source := cloudProxyStrongEvidenceForRecord(state, dnsverify.Result{Actual: custom, Status: "ok"}, "api.example.com")
	if !strong || source != "custom-cname-target" {
		t.Fatalf("strong=%v source=%q", strong, source)
	}
}

func TestApexStrongEvidenceDoesNotValidateSubdomain(t *testing.T) {
	state := &State{
		Domain: DomainSummary{Name: "example.com", CnameTarget: "edge.cdn.net"},
		HTTPSProbe: &HTTPProbeResult{
			FinalURL:        "https://example.com/",
			AnalysisHeaders: map[string]string{"x-poweredby": "VergeCloud"},
		},
	}
	strong, _ := cloudProxyStrongEvidenceForRecord(state, dnsverify.Result{Actual: "1.2.3.4", Status: "ok"}, "api.example.com")
	if strong {
		t.Fatal("apex probe must not validate subdomain")
	}
}

func TestHTTPOriginHostHeaderNoTLSWording(t *testing.T) {
	check := &OriginCheck{}
	findings := check.hostHeaderFinding(&State{
		Domain:          DomainSummary{Name: "example.com"},
		OriginSelection: OriginSelection{Scheme: "http"},
		OriginProbe: &OriginProbeResult{
			HostHeader: "example.com", StatusCode: 404, Scheme: "http",
		},
		OriginHostProbe: &OriginProbeResult{
			HostHeader: "203.0.113.10", StatusCode: 200, Scheme: "http",
		},
		Options: Options{Path: "/"},
	})
	if len(findings) != 1 {
		t.Fatal(findings)
	}
	if strings.Contains(findings[0].Summary, "TLS") || strings.Contains(findings[0].Summary, "SNI") {
		t.Fatalf("summary must not mention TLS/SNI: %q", findings[0].Summary)
	}
	if _, ok := findings[0].Evidence["tls_sni"]; ok {
		t.Fatal("HTTP origin evidence must not include tls_sni")
	}
}

func TestHTTPSOriginHostHeaderIncludesTLS(t *testing.T) {
	check := &OriginCheck{}
	findings := check.hostHeaderFinding(&State{
		Domain:          DomainSummary{Name: "example.com"},
		OriginSelection: OriginSelection{Scheme: "https"},
		OriginProbe: &OriginProbeResult{
			HostHeader: "example.com", StatusCode: 404, Scheme: "https",
		},
		OriginHostProbe: &OriginProbeResult{
			HostHeader: "203.0.113.10", StatusCode: 200, Scheme: "https",
		},
		Options: Options{Path: "/"},
	})
	if findings[0].Evidence["tls_sni"] != "example.com" {
		t.Fatalf("expected tls_sni evidence, got %+v", findings[0].Evidence)
	}
	if !strings.Contains(findings[0].Summary, "TLS SNI") {
		t.Fatalf("summary = %q", findings[0].Summary)
	}
}

func TestHTTPOriginPassNoTLSWording(t *testing.T) {
	check := &OriginCheck{}
	findings := check.hostHeaderFinding(&State{
		Domain:          DomainSummary{Name: "example.com"},
		OriginSelection: OriginSelection{Scheme: "http"},
		OriginProbe: &OriginProbeResult{
			HostHeader: "example.com", StatusCode: 200, Scheme: "http",
		},
		OriginHostProbe: &OriginProbeResult{
			HostHeader: "203.0.113.10", StatusCode: 200, Scheme: "http",
		},
		Options: Options{Path: "/"},
	})
	if strings.Contains(findings[0].Summary, "TLS") || strings.Contains(findings[0].Summary, "SNI") {
		t.Fatalf("summary = %q", findings[0].Summary)
	}
}

func TestSmartCheckInspectNilNoDirectCall(t *testing.T) {
	var calls int32
	source := &smartCheckSource{onSmartCheck: func() { atomic.AddInt32(&calls, 1) }}
	runner, _ := NewRunner(source)
	state := &State{
		InspectRequestedSections: map[string]bool{"smartcheck": true},
		Inspect:                  &client.DomainInspect{SmartCheck: nil},
	}
	runner.prepareSmartCheck(context.Background(), state, "example.com")
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("expected 0 direct calls, got %d", calls)
	}
	if state.SmartCheckLoadStatus != SmartCheckNotFound {
		t.Fatalf("load status = %q", state.SmartCheckLoadStatus)
	}
}

func TestSmartCheckNotInInspectDirectCallOnce(t *testing.T) {
	var calls int32
	source := &smartCheckSource{onSmartCheck: func() { atomic.AddInt32(&calls, 1) }}
	runner, _ := NewRunner(source)
	state := &State{InspectRequestedSections: map[string]bool{}}
	runner.prepareSmartCheck(context.Background(), state, "example.com")
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 direct call, got %d", calls)
	}
}

func TestTLSProbeExecErrorIsErrorNotFail(t *testing.T) {
	findings := (&TLSCheck{}).certificatePresent(&State{
		TLSProbe: &TLSProbeResult{Connected: false, ProbeExecError: true, Error: "context canceled"},
	})
	if findings[0].Status != StatusError {
		t.Fatalf("got %q", findings[0].Status)
	}
}

func TestTLSConnectionRefusedIsFail(t *testing.T) {
	findings := (&TLSCheck{}).certificatePresent(&State{
		TLSProbe: &TLSProbeResult{Connected: false, Error: "connection refused"},
	})
	if findings[0].Status != StatusFail {
		t.Fatalf("got %q", findings[0].Status)
	}
}

func TestHSTSDecisionTable(t *testing.T) {
	check := &SecurityCheck{}
	cases := []struct {
		name   string
		state  *State
		status Status
	}{
		{
			name: "api enabled header missing healthy tls",
			state: &State{
				Domain:  DomainSummary{Name: "example.com"},
				Inspect: &client.DomainInspect{SSL: client.SslInspect{HSTS: true, Enabled: true}},
				HTTPSProbe: &HTTPProbeResult{
					StatusCode: 200,
					FinalURL:   "https://example.com/",
					URL:        "https://example.com/",
				},
				TLSProbe: &TLSProbeResult{Connected: true, HostnameMatch: true},
			},
			status: StatusWarn,
		},
		{
			name: "api disabled header present",
			state: &State{
				Domain:  DomainSummary{Name: "example.com"},
				Inspect: &client.DomainInspect{SSL: client.SslInspect{HSTS: false, Enabled: true}},
				HTTPSProbe: &HTTPProbeResult{
					StatusCode: 200,
					FinalURL:   "https://example.com/",
					URL:        "https://example.com/",
					Headers:    map[string]string{"strict-transport-security": "max-age=31536000"},
				},
				TLSProbe: &TLSProbeResult{Connected: true, HostnameMatch: true},
			},
			status: StatusPass,
		},
		{
			name: "https unavailable skip",
			state: &State{
				Domain:     DomainSummary{Name: "example.com"},
				Inspect:    &client.DomainInspect{SSL: client.SslInspect{HSTS: true, Enabled: true}},
				HTTPSProbe: &HTTPProbeResult{Error: "connection refused"},
			},
			status: StatusSkip,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := check.hstsFinding("example.com", tc.state)
			if findings[0].Status != tc.status {
				t.Fatalf("got %q want %q summary=%q", findings[0].Status, tc.status, findings[0].Summary)
			}
		})
	}
}

func TestOriginAutoTriesHTTPSBeforeHTTP(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	host, portStr, _ := splitHostPort(httpSrv.Listener.Addr().String())
	runner, _ := NewRunner(nil)
	state := &State{
		Options: Options{
			Origin:       host + ":" + portStr,
			OriginScheme: "auto",
			Path:         "/",
			ProbeTimeout: DurationJSON(2 * time.Second),
		},
		Domain: DomainSummary{Name: "example.com"},
	}
	selection := runner.selectOrigin(context.Background(), state, "example.com", "/")
	if len(selection.Attempts) < 2 {
		t.Fatalf("expected https then http attempts, got %+v", selection.Attempts)
	}
	if selection.Attempts[0].Scheme != "https" {
		t.Fatal("first auto attempt must probe https")
	}
	if selection.Scheme != "http" {
		t.Fatalf("expected http fallback, got %+v", selection)
	}
}

func TestOriginAutoSelectHTTPFallback(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	host, portStr, _ := splitHostPort(httpSrv.Listener.Addr().String())
	runner, _ := NewRunner(nil)
	state := &State{
		Options: Options{
			Origin:       host + ":" + portStr,
			OriginScheme: "auto",
			Path:         "/",
			ProbeTimeout: DurationJSON(2 * time.Second),
		},
		Domain: DomainSummary{Name: "example.com"},
	}
	selection := runner.selectOrigin(context.Background(), state, "example.com", "/")
	if selection.Scheme != "http" {
		t.Fatalf("expected http fallback, got %+v attempts=%+v", selection, selection.Attempts)
	}
}

func TestOriginRunUsesSelectedAddress(t *testing.T) {
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	runner, _ := NewRunner(nil)
	state := &State{
		Options: Options{
			Origin:       httpSrv.Listener.Addr().String(),
			OriginScheme: "http",
			Path:         "/",
			ProbeTimeout: DurationJSON(2 * time.Second),
		},
		Domain: DomainSummary{Name: "example.com"},
	}
	runner.runOriginProbes(context.Background(), state)
	if state.OriginSelection.Address == "" {
		t.Fatal("expected origin selection address")
	}
	if state.OriginProbe == nil || state.OriginProbe.Error != "" {
		t.Fatalf("origin probe failed: %+v", state.OriginProbe)
	}
	if state.OriginProbe.Address != state.OriginSelection.Address {
		t.Fatalf("probe address %q != selection %q", state.OriginProbe.Address, state.OriginSelection.Address)
	}
}

func splitHostPort(addr string) (string, string, error) {
	host, port, err := netSplitHostPort(addr)
	return host, port, err
}

func netSplitHostPort(addr string) (string, string, error) {
	if strings.HasPrefix(addr, "[") {
		i := strings.LastIndex(addr, "]:")
		if i < 0 {
			return "", "", fmt.Errorf("bad addr")
		}
		return addr[1:i], addr[i+2:], nil
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("bad addr")
	}
	return addr[:i], addr[i+1:], nil
}

type categoryTestSource struct{}

func (categoryTestSource) ResolveDomain(context.Context, string) (*client.DomainDetail, error) {
	return &client.DomainDetail{
		Domain: client.Domain{Name: "127.0.0.1", Type: "full", Status: "active"},
	}, nil
}

func (categoryTestSource) LoadInspect(context.Context, string, map[string]bool) (*client.DomainInspect, error) {
	return &client.DomainInspect{
		WAF:      client.WafInspect{Mode: "detect", Enabled: true},
		Firewall: client.FirewallInspect{Enabled: true, DefaultAction: "allow"},
		Cache:    client.CacheInspect{Status: "on"},
		SSL:      client.SslInspect{Enabled: true},
	}, nil
}

func (categoryTestSource) CheckNameservers(context.Context, string) (*client.NSCheckResult, error) {
	return &client.NSCheckResult{}, nil
}

func (categoryTestSource) FetchCnameSetupStatus(context.Context, string) (*client.CnameSetupStatus, error) {
	return nil, nil
}

func (categoryTestSource) GetLatestSmartCheck(context.Context, string) (*client.SmartCheck, error) {
	return nil, nil
}

type smartCheckSource struct {
	onSmartCheck func()
}

func (s *smartCheckSource) ResolveDomain(context.Context, string) (*client.DomainDetail, error) {
	return nil, nil
}
func (s *smartCheckSource) LoadInspect(context.Context, string, map[string]bool) (*client.DomainInspect, error) {
	return nil, nil
}
func (s *smartCheckSource) CheckNameservers(context.Context, string) (*client.NSCheckResult, error) {
	return nil, nil
}
func (s *smartCheckSource) FetchCnameSetupStatus(context.Context, string) (*client.CnameSetupStatus, error) {
	return nil, nil
}
func (s *smartCheckSource) GetLatestSmartCheck(context.Context, string) (*client.SmartCheck, error) {
	if s.onSmartCheck != nil {
		s.onSmartCheck()
	}
	return nil, nil
}
