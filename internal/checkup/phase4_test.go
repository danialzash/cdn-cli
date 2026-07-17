package checkup

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vergecloud/cdn-cli/internal/client"
)

func inspectForCategoryChecks() *client.DomainInspect {
	return &client.DomainInspect{
		WAF:      client.WafInspect{Mode: "detect", Enabled: true},
		Firewall: client.FirewallInspect{Enabled: true, DefaultAction: "allow"},
		Cache:    client.CacheInspect{Status: "on"},
		SSL:      client.SslInspect{Enabled: true},
	}
}

func httpsProbeWithStatus(status int) *HTTPProbeResult {
	return &HTTPProbeResult{
		StatusCode:      status,
		FinalURL:        "https://example.com/",
		Headers:         map[string]string{"x-poweredby": "VergeCloud"},
		AnalysisHeaders: map[string]string{"x-poweredby": "VergeCloud"},
		RedirectEvidence: RedirectEvidence{
			InitialURL:  "https://example.com/",
			FinalURL:    "https://example.com/",
			FinalStatus: status,
		},
	}
}

func exitCodeForFindings(findings []Finding) int {
	return ComputeExitCode(SummarizeFindings(findings), false, nil, false)
}

func TestCDNCheckHTTPS503Fails(t *testing.T) {
	findings := (&CDNCheck{}).Run(context.Background(), &State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    inspectForCategoryChecks(),
		HTTPSProbe: httpsProbeWithStatus(503),
	})
	if exitCodeForFindings(findings) != ExitChecksFailed {
		t.Fatalf("expected exit 2, got %d findings=%+v", exitCodeForFindings(findings), findings)
	}
	found := false
	for _, f := range findings {
		if f.ID == "cdn.edge-detected" && f.Status == StatusFail {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected edge failure, got %+v", findings)
	}
}

func TestCDNCheckHTTPS403Warns(t *testing.T) {
	findings := (&CDNCheck{}).Run(context.Background(), &State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    inspectForCategoryChecks(),
		HTTPSProbe: httpsProbeWithStatus(403),
	})
	if exitCodeForFindings(findings) == ExitChecksFailed {
		t.Fatal("403 should warn, not fail")
	}
	for _, f := range findings {
		if f.ID == "cdn.edge-detected" && f.Status == StatusFail {
			t.Fatalf("403 must not fail edge finding: %+v", f)
		}
	}
}

func TestCacheCheckFirstHTTPS500Fails(t *testing.T) {
	findings := (&CacheCheck{}).Run(context.Background(), &State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    inspectForCategoryChecks(),
		HTTPSProbe: httpsProbeWithStatus(500),
		SecondHTTPSProbe: &HTTPProbeResult{
			StatusCode: 200, FinalURL: "https://example.com/",
			RedirectEvidence: RedirectEvidence{FinalURL: "https://example.com/", FinalStatus: 200},
		},
	})
	if exitCodeForFindings(findings) != ExitChecksFailed {
		t.Fatalf("expected exit 2, got %d", exitCodeForFindings(findings))
	}
}

func TestCacheCheckSecondHTTPS503Fails(t *testing.T) {
	findings := (&CacheCheck{}).Run(context.Background(), &State{
		Domain:  DomainSummary{Name: "example.com"},
		Inspect: inspectForCategoryChecks(),
		HTTPSProbe: &HTTPProbeResult{
			StatusCode: 200, FinalURL: "https://example.com/",
			Headers:          map[string]string{"x-cache": "MISS"},
			RedirectEvidence: RedirectEvidence{FinalURL: "https://example.com/", FinalStatus: 200},
		},
		SecondHTTPSProbe: httpsProbeWithStatus(503),
	})
	if exitCodeForFindings(findings) != ExitChecksFailed {
		t.Fatalf("expected exit 2, got %d", exitCodeForFindings(findings))
	}
}

func TestSecurityCheckHTTPS503Fails(t *testing.T) {
	findings := (&SecurityCheck{}).Run(context.Background(), &State{
		Domain:     DomainSummary{Name: "example.com"},
		Inspect:    inspectForCategoryChecks(),
		HTTPSProbe: httpsProbeWithStatus(503),
		TLSProbe:   &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	if exitCodeForFindings(findings) != ExitChecksFailed {
		t.Fatalf("expected exit 2, got %d findings=%+v", exitCodeForFindings(findings), findings)
	}
}

func TestUnrelatedRedirectNoCDNSuccess(t *testing.T) {
	findings := (&CDNCheck{}).Run(context.Background(), &State{
		Domain:  DomainSummary{Name: "example.com"},
		Inspect: inspectForCategoryChecks(),
		HTTPSProbe: &HTTPProbeResult{
			StatusCode:      200,
			FinalURL:        "https://unrelated.example/",
			Headers:         map[string]string{"x-poweredby": "VergeCloud"},
			AnalysisHeaders: map[string]string{"x-poweredby": "VergeCloud"},
			RedirectEvidence: RedirectEvidence{
				FinalURL:        "https://unrelated.example/",
				FinalStatus:     200,
				UnexpectedHosts: []string{"unrelated.example"},
			},
		},
	})
	for _, f := range findings {
		if f.ID == "cdn.edge-detected" && f.Status == StatusPass {
			t.Fatal("must not pass edge detection for unrelated redirect")
		}
	}
}

func TestUnrelatedRedirectNoCacheSuccess(t *testing.T) {
	findings := (&CacheCheck{}).Run(context.Background(), &State{
		Domain:  DomainSummary{Name: "example.com"},
		Inspect: inspectForCategoryChecks(),
		HTTPSProbe: &HTTPProbeResult{
			StatusCode: 200, FinalURL: "https://unrelated.example/",
			Headers: map[string]string{"x-cache-status": "HIT"},
			RedirectEvidence: RedirectEvidence{
				FinalURL: "https://unrelated.example/", UnexpectedHosts: []string{"unrelated.example"},
			},
		},
		SecondHTTPSProbe: &HTTPProbeResult{
			StatusCode: 200, FinalURL: "https://unrelated.example/",
			Headers: map[string]string{"x-cache-status": "HIT"},
			RedirectEvidence: RedirectEvidence{
				FinalURL: "https://unrelated.example/", UnexpectedHosts: []string{"unrelated.example"},
			},
		},
	})
	for _, f := range findings {
		if f.ID == "cache.repeated-request" && f.Status == StatusPass {
			t.Fatal("must not report cache success for unrelated redirect")
		}
	}
}

func TestUnrelatedRedirectNoHSTSSuccess(t *testing.T) {
	findings := (&SecurityCheck{}).hstsFinding("example.com", &State{
		Domain:  DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{SSL: client.SslInspect{HSTS: false, Enabled: true}},
		HTTPSProbe: &HTTPProbeResult{
			StatusCode: 200,
			FinalURL:   "https://unrelated.example/",
			Headers:    map[string]string{"strict-transport-security": "max-age=31536000"},
			RedirectEvidence: RedirectEvidence{
				FinalURL:        "https://unrelated.example/",
				UnexpectedHosts: []string{"unrelated.example"},
			},
		},
		TLSProbe: &TLSProbeResult{Connected: true, HostnameMatch: true},
	})
	if len(findings) != 1 || findings[0].Status != StatusSkip {
		t.Fatalf("must not report HSTS success for unrelated redirect: %+v", findings)
	}
}

func TestHTTPRedirectsToRelatedHTTPS(t *testing.T) {
	cases := []struct {
		name     string
		finalURL string
		evidence RedirectEvidence
		want     bool
	}{
		{"apex", "https://example.com/", RedirectEvidence{}, true},
		{"www", "https://www.example.com/", RedirectEvidence{}, true},
		{"subdomain", "https://app.example.com/", RedirectEvidence{}, true},
		{"unrelated", "https://unrelated.example/", RedirectEvidence{UnexpectedHosts: []string{"unrelated.example"}}, false},
		{"downgrade", "https://example.com/", RedirectEvidence{DowngradeDetected: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := &HTTPProbeResult{FinalURL: tc.finalURL, RedirectEvidence: tc.evidence}
			if got := httpRedirectsToRelatedHTTPS(probe, "example.com"); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestFixVerifyRejectsUnrelatedHTTPSRedirect(t *testing.T) {
	probe := &HTTPProbeResult{
		FinalURL: "https://unrelated.example/",
		RedirectEvidence: RedirectEvidence{
			UnexpectedHosts: []string{"unrelated.example"},
		},
	}
	if httpRedirectsToRelatedHTTPS(probe, "example.com") {
		t.Fatal("unrelated redirect must not verify")
	}
}

func TestProbeHTTPClientTimeoutIsExecutionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewProbeHTTPClient(50 * time.Millisecond)
	result := ProbeHTTP(context.Background(), client, srv.URL, "")
	if !result.TimedOut || !result.ProbeExecError {
		t.Fatalf("expected timeout execution error, got %+v", result)
	}
	if exitCodeForFindings([]Finding{{
		ID: "probe", Status: probeFailureStatus(result), Category: string(CategoryHTTP),
	}}) != ExitProbeError {
		t.Fatal("timeout should exit 3")
	}
}

func TestOriginClientIgnoresProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("HTTP_PROXY", "127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "127.0.0.1:1")

	client := NewOriginProbeHTTPClient(time.Second, srv.Listener.Addr().String(), "")
	result := ProbeHTTP(context.Background(), client, "http://"+srv.Listener.Addr().String()+"/", "example.com")
	if result.Error != "" {
		t.Fatalf("origin client should reach server directly: %q", result.Error)
	}
}

func TestAutoOriginBothFailNoRetry(t *testing.T) {
	runner, _ := NewRunner(nil)
	state := &State{
		Options: Options{
			Origin:       "127.0.0.1:1",
			OriginScheme: "auto",
			Path:         "/",
			ProbeTimeout: DurationJSON(100 * time.Millisecond),
		},
		Domain: DomainSummary{Name: "example.com"},
	}
	selection := runner.selectOrigin(context.Background(), state, "example.com", "/")
	if selection.Scheme != "" || selection.Address != "" {
		t.Fatalf("expected empty selection, got %+v", selection)
	}
	if len(selection.Attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %+v", selection.Attempts)
	}
	runner.runOriginProbes(context.Background(), state)
	if state.OriginProbe != nil {
		t.Fatal("final origin probe should not run after auto selection failure")
	}
	findings := (&OriginCheck{}).connectivityFinding(state)
	if findings[0].Status != StatusFail && findings[0].Status != StatusError {
		t.Fatalf("got %+v", findings[0])
	}
}

func TestSmartCheckNotFoundIsSkipNotError(t *testing.T) {
	findings := (&SmartCheckCheck{}).Run(context.Background(), &State{
		SmartCheckLoadStatus: SmartCheckNotFound,
	})
	if len(findings) != 1 || findings[0].Status != StatusSkip {
		t.Fatalf("got %+v", findings)
	}
	if exitCodeForFindings(findings) != ExitOK {
		t.Fatal("not found should not fail command")
	}
}

func TestStrictOriginParsingRejects(t *testing.T) {
	cases := []string{
		"[2001:db8::1]:",
		"[2001:db8::1]garbage",
		"example.com/path",
		"bad host",
		"https://example.com",
	}
	for _, origin := range cases {
		if _, _, _, err := parseOriginHostPort(origin, 0, false); err == nil {
			t.Fatalf("expected error for %q", origin)
		}
	}
	opts := DefaultOptions()
	opts.OriginPortSet = true
	opts.OriginPort = 0
	if err := opts.Validate(); err == nil {
		t.Fatal("expected explicit port 0 error")
	}
	opts = DefaultOptions()
	opts.OriginPortSet = true
	opts.OriginPort = 8443
	if err := opts.Validate(); err == nil {
		t.Fatal("expected origin-port without origin error")
	}
}

func TestDefaultOriginHostHeaderPreservesCustomPort(t *testing.T) {
	if got := defaultOriginHostHeader("origin.example.com:8443", "https"); got != "origin.example.com:8443" {
		t.Fatalf("got %q", got)
	}
	if got := defaultOriginHostHeader("origin.example.com:443", "https"); got != "origin.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := defaultOriginHostHeader("origin.example.com:80", "http"); got != "origin.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := defaultOriginHostHeader("203.0.113.10:8443", "https"); got != "203.0.113.10:8443" {
		t.Fatalf("got %q", got)
	}
	if got := defaultOriginHostHeader("[2001:db8::1]:8443", "https"); got != "[2001:db8::1]:8443" {
		t.Fatalf("got %q", got)
	}
}

func TestCacheSecondProbeConnectionRefusedFails(t *testing.T) {
	f := cacheRepeatedProbeError(&State{
		HTTPSProbe: &HTTPProbeResult{StatusCode: 200},
	}, "failed", &HTTPProbeResult{Error: "connection refused"})
	if f.Status != StatusFail {
		t.Fatalf("got %q", f.Status)
	}
}

func TestCacheSecondProbeTimeoutErrors(t *testing.T) {
	f := cacheRepeatedProbeError(&State{
		HTTPSProbe: &HTTPProbeResult{StatusCode: 200},
	}, "failed", &HTTPProbeResult{Error: "timeout", ProbeExecError: true, TimedOut: true})
	if f.Status != StatusError {
		t.Fatalf("got %q", f.Status)
	}
}

func TestTLSConnectionRefusedCertificatePresentFails(t *testing.T) {
	findings := (&TLSCheck{}).certificatePresent(&State{
		TLSProbe: &TLSProbeResult{Connected: false, Error: "connection refused"},
	})
	if findings[0].Status != StatusFail {
		t.Fatalf("got %q", findings[0].Status)
	}
}

func TestTLSTimeoutIsError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}()
	result := ProbeTLS(context.Background(), ln.Addr().String(), "example.com", 50*time.Millisecond)
	if !result.ProbeExecError {
		t.Fatalf("expected execution error, got %+v", result)
	}
	if exitCodeForFindings([]Finding{{ID: "tls", Status: StatusError, Category: string(CategoryTLS)}}) != ExitProbeError {
		t.Fatal("expected exit 3")
	}
}

func TestFixApplierUsesConfiguredProbeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		http.Redirect(w, r, "https://example.com/", http.StatusFound)
	}))
	defer srv.Close()

	applier := NewClientFixApplier(nil)
	applier.ProbeTimeout = 30 * time.Millisecond
	start := time.Now()
	probe := ProbeHTTP(context.Background(), NewProbeHTTPClient(applier.ProbeTimeout), srv.URL, "")
	if time.Since(start) > 150*time.Millisecond {
		t.Fatal("probe timeout was not honored")
	}
	if probe.Error == "" {
		t.Fatal("expected timeout error")
	}
}
