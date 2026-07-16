package checkup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vergecloud/cdn-cli/internal/client"
	"github.com/vergecloud/cdn-cli/internal/dnsverify"
)

func TestCnameTargetMatches(t *testing.T) {
	if !cnameTargetMatches("edge.example.cdn.net.", "edge.example.cdn.net") {
		t.Fatal("expected match")
	}
	if cnameTargetMatches("wrong.example.com", "edge.example.cdn.net") {
		t.Fatal("expected mismatch")
	}
}

func TestFindingIDSanitizes(t *testing.T) {
	got := FindingID("DNS", " Cloud-Proxy ", "rec/1")
	if got != "dns.cloud-proxy.rec-1" {
		t.Fatalf("got %q", got)
	}
}

func TestClassifyHTTPStatus(t *testing.T) {
	cases := []struct {
		code int
		want Status
	}{
		{200, StatusPass}, {301, StatusPass}, {401, StatusWarn}, {404, StatusWarn},
		{429, StatusWarn}, {500, StatusFail}, {503, StatusFail},
	}
	for _, tc := range cases {
		status, _, _ := ClassifyHTTPStatus(tc.code, "/", false)
		if status != tc.want {
			t.Fatalf("code %d: got %q want %q", tc.code, status, tc.want)
		}
	}
	status, _, _ := ClassifyHTTPStatus(404, "/healthz", true)
	if status != StatusFail {
		t.Fatal("health path 404 should fail")
	}
}

func TestCloudProxyStrongEvidencePerHostname(t *testing.T) {
	apex := "example.com"
	apiHost := "api.example.com"
	withApexOnly := &State{
		Domain: DomainSummary{Name: apex, CnameTarget: "edge.cdn.net"},
		HostEdgeProbes: map[string]*HTTPProbeResult{
			apex: {AnalysisHeaders: map[string]string{"x-poweredby": "VergeCloud"}},
		},
	}
	strong, source := cloudProxyStrongEvidenceForRecord(withApexOnly, dnsverify.Result{Name: "api", Actual: "1.2.3.4", Status: "ok"}, apiHost)
	if strong || source != "none" {
		t.Fatalf("apex evidence must not validate api subdomain: strong=%v source=%q", strong, source)
	}

	withAPIProbe := &State{
		Domain: DomainSummary{Name: apex, CnameTarget: "edge.cdn.net"},
		HostEdgeProbes: map[string]*HTTPProbeResult{
			apiHost: {AnalysisHeaders: map[string]string{"x-poweredby": "VergeCloud"}},
		},
	}
	strong, source = cloudProxyStrongEvidenceForRecord(withAPIProbe, dnsverify.Result{Name: "api", Actual: "1.2.3.4", Status: "ok"}, apiHost)
	if !strong || source != "hostname-edge-probe" {
		t.Fatalf("api hostname probe should validate api only: strong=%v source=%q", strong, source)
	}

	withCNAME := &State{
		Domain: DomainSummary{Name: apex, CnameTarget: "edge.cdn.net"},
		HostCNAMEChains: map[string][]string{
			apiHost: {"edge.cdn.net"},
		},
	}
	strong, source = cloudProxyStrongEvidenceForRecord(withCNAME, dnsverify.Result{Name: "api", Actual: "edge.cdn.net", Status: "ok"}, apiHost)
	if !strong || source != "cname-target" {
		t.Fatalf("cname chain should be strong evidence: strong=%v source=%q", strong, source)
	}
}

func TestWWWResolutionOptional(t *testing.T) {
	check := &DNSCheck{}
	findings := check.lookupFinding("dns.www-resolution", "www.example.com", DNSLookupResult{Classification: DNSLookupNotFound}, false)
	if findings[0].Status != StatusSkip {
		t.Fatalf("got %q", findings[0].Status)
	}
	findings = check.lookupFinding("dns.www-resolution", "www.example.com", DNSLookupResult{Classification: DNSLookupNotFound}, true)
	if findings[0].Status != StatusFail {
		t.Fatalf("got %q", findings[0].Status)
	}
}

func TestSecurityHeadersDetectedFromAnalysisMap(t *testing.T) {
	check := &SecurityCheck{}
	findings := check.securityHeadersFinding(&State{
		HTTPSProbe: &HTTPProbeResult{
			Headers: map[string]string{"server": "nginx"},
			AnalysisHeaders: map[string]string{
				"content-security-policy": "default-src 'self'",
				"x-content-type-options":  "nosniff",
				"referrer-policy":         "strict-origin",
				"permissions-policy":      "geolocation=()",
				"x-frame-options":         "DENY",
			},
		},
	})
	if len(findings) != 1 || findings[0].Status != StatusPass {
		t.Fatalf("got %+v", findings)
	}
}

func TestFixUnknownIDReturnsError(t *testing.T) {
	applier := NewClientFixApplier(nil)
	err := applier.ApplyFix(context.Background(), "example.com", FixPlan{ID: "unknown.fix"})
	if err == nil || !strings.Contains(err.Error(), "unsupported automatic fix") {
		t.Fatalf("got %v", err)
	}
}

type mockFixApplier struct {
	applyErr  error
	verify    FixVerification
	verifyMsg string
	verifyErr error
}

func (m *mockFixApplier) ApplyFix(context.Context, string, FixPlan) error { return m.applyErr }
func (m *mockFixApplier) VerifyFix(context.Context, string, FixPlan) (FixVerification, string, error) {
	return m.verify, m.verifyMsg, m.verifyErr
}

func TestFixVerificationFailure(t *testing.T) {
	runner := NewFixRunner(&mockFixApplier{}, &mockFixApplier{verify: FixVerification{ConfigurationVerified: false}, verifyMsg: "still enabled"})
	results := runner.Apply(context.Background(), "example.com", []FixPlan{{ID: "cache.developer-mode", Description: "x", Safety: FixSafetySafe, Automatic: true}}, false)
	if len(results) != 1 || results[0].Verified || results[0].Error == "" {
		t.Fatalf("got %+v", results)
	}
	if !FixFailed(results) {
		t.Fatal("expected fix failed")
	}
}

func TestFixVerificationSuccess(t *testing.T) {
	runner := NewFixRunner(&mockFixApplier{}, &mockFixApplier{verify: FixVerification{ConfigurationVerified: true, BehaviorVerified: true}})
	results := runner.Apply(context.Background(), "example.com", []FixPlan{{ID: "cache.developer-mode", Description: "x", Safety: FixSafetySafe, Automatic: true}}, false)
	if len(results) != 1 || !results[0].Verified || results[0].Error != "" {
		t.Fatalf("got %+v", results)
	}
}

func TestHTTPSRedirectFixRequiresBehaviorVerification(t *testing.T) {
	runner := NewFixRunner(&mockFixApplier{}, &mockFixApplier{
		verify:    FixVerification{ConfigurationVerified: true, BehaviorVerified: false},
		verifyMsg: "live redirect missing",
	})
	results := runner.Apply(context.Background(), "example.com", []FixPlan{{ID: "ssl.https-redirect", Description: "Enable HTTPS redirect", Safety: FixSafetySafe, Automatic: true}}, false)
	if len(results) != 1 || results[0].Verified || !strings.Contains(results[0].Error, "live redirect") {
		t.Fatalf("got %+v", results)
	}
}

func TestReportUniqueFindingIDs(t *testing.T) {
	findings := []Finding{
		{ID: "dns.cloud-proxy-weak.r1"},
		{ID: "dns.cloud-proxy-weak.r2"},
		{ID: "dns.cloud-proxy-weak.r1"},
	}
	ensureUniqueFindingIDs(findings)
	seen := map[string]struct{}{}
	for _, f := range findings {
		if _, ok := seen[f.ID]; ok {
			t.Fatalf("duplicate id %q", f.ID)
		}
		seen[f.ID] = struct{}{}
	}
}

func TestOnlyOriginDoesNotIncludeHTTPCheck(t *testing.T) {
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	checks, err := reg.ChecksForCategories(map[Category]bool{CategoryOrigin: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Category() == CategoryHTTP {
			t.Fatal("http findings should not be visible with --only origin")
		}
	}
	req := RequirementsForCategories(map[Category]bool{CategoryOrigin: true})
	if !req.PublicHTTPS || !req.Origin {
		t.Fatal("origin should require internal https probes")
	}
}

func TestOnlyCacheDoesNotIncludeHTTPCheck(t *testing.T) {
	reg, _ := DefaultRegistry()
	checks, _ := reg.ChecksForCategories(map[Category]bool{CategoryCache: true})
	for _, c := range checks {
		if c.Category() == CategoryHTTP {
			t.Fatal("http findings should not be visible with --only cache")
		}
	}
}

func TestSmartCheckInspectFailureNoRetry(t *testing.T) {
	var calls int32
	source := &fakeSource{
		onSmartCheck: func() { atomic.AddInt32(&calls, 1) },
	}
	runner, _ := NewRunner(source)
	state := &State{
		Inspect: &client.DomainInspect{
			Errors: []client.InspectError{{Section: "smart_check", Error: "timeout"}},
		},
	}
	runner.prepareSmartCheck(context.Background(), state, "example.com")
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("expected 0 direct smartcheck calls, got %d", calls)
	}
	if len(state.ProbeErrors) != 1 {
		t.Fatalf("probe errors = %+v", state.ProbeErrors)
	}
}

func TestSmartCheckLoadedOnceFromInspect(t *testing.T) {
	var calls int32
	source := &fakeSource{
		smartCheck: &client.SmartCheck{ID: "sc1"},
		onSmartCheck: func() {
			atomic.AddInt32(&calls, 1)
		},
	}
	runner, err := NewRunner(source)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{
		Inspect: &client.DomainInspect{SmartCheck: &client.SmartCheck{ID: "sc1"}},
	}
	runner.prepareSmartCheck(context.Background(), state, "example.com")
	runner.prepareSmartCheck(context.Background(), state, "example.com")
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("expected 0 smartcheck API calls, got %d", calls)
	}
}

type fakeSource struct {
	smartCheck   *client.SmartCheck
	onSmartCheck func()
}

func (f *fakeSource) ResolveDomain(context.Context, string) (*client.DomainDetail, error) {
	return &client.DomainDetail{Domain: client.Domain{Name: "example.com"}}, nil
}
func (f *fakeSource) LoadInspect(context.Context, string, map[string]bool) (*client.DomainInspect, error) {
	return &client.DomainInspect{SmartCheck: f.smartCheck}, nil
}
func (f *fakeSource) CheckNameservers(context.Context, string) (*client.NSCheckResult, error) {
	return nil, nil
}
func (f *fakeSource) FetchCnameSetupStatus(context.Context, string) (*client.CnameSetupStatus, error) {
	return nil, nil
}
func (f *fakeSource) GetLatestSmartCheck(context.Context, string) (*client.SmartCheck, error) {
	if f.onSmartCheck != nil {
		f.onSmartCheck()
	}
	return f.smartCheck, nil
}

func TestTLSProbeRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := ProbeTLS(ctx, "127.0.0.1:1", "example.com", time.Second)
	if result.Error == "" {
		t.Fatal("expected error")
	}
}

func TestOriginHTTPSUsesCustomerSNIAndHost(t *testing.T) {
	var sni, host string
	cert := generateTestCert(t, "example.com")
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(x509Cert)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dialAddr := net.JoinHostPort("127.0.0.1", port)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddr)
		},
		TLSClientConfig: &tls.Config{ServerName: "example.com", RootCAs: pool},
	}
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	result := ProbeHTTP(context.Background(), httpClient, "https://"+dialAddr+"/", "example.com")
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	if sni != "example.com" {
		t.Fatalf("sni = %q", sni)
	}
	if host != "example.com" {
		t.Fatalf("host = %q", host)
	}
}

func generateTestCert(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestConfigurationActiveCertificateCount(t *testing.T) {
	check := &ConfigurationCheck{}
	findings := check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			SSL: client.SslInspect{
				Enabled: true,
				Certificates: []client.CertificateSummary{
					{Active: false}, {Active: true},
				},
			},
		},
	})
	foundPass := false
	for _, f := range findings {
		if f.ID == "configuration.ssl-no-active-cert" {
			t.Fatal("should not fail when active cert exists")
		}
		if f.ID == "configuration.ssl-active-cert" {
			foundPass = true
		}
	}
	if !foundPass {
		t.Fatal("expected active cert pass finding")
	}

	findings = check.Run(context.Background(), &State{
		Domain: DomainSummary{Name: "example.com"},
		Inspect: &client.DomainInspect{
			SSL: client.SslInspect{
				Enabled: true,
				Certificates: []client.CertificateSummary{
					{Active: false},
				},
			},
		},
	})
	if findings[0].ID != "configuration.ssl-no-active-cert" {
		t.Fatalf("got %v", findings[0].ID)
	}
}

func TestRedirectDowngradeDetected(t *testing.T) {
	ev := buildRedirectEvidence("https://example.com", []string{"http://example.com/"}, "http://example.com/", 200, nil, "example.com")
	if !ev.DowngradeDetected {
		t.Fatal("expected downgrade")
	}
}

func TestCacheRepeatedRequestWording(t *testing.T) {
	check := &CacheCheck{}
	findings := check.Run(context.Background(), &State{
		Domain:           DomainSummary{Name: "example.com"},
		Inspect:          &client.DomainInspect{Cache: client.CacheInspect{Status: "on", MaxAge: "3600"}},
		HTTPSProbe:       &HTTPProbeResult{Headers: map[string]string{"x-cache-status": "MISS"}},
		SecondHTTPSProbe: &HTTPProbeResult{Headers: map[string]string{"x-cache-status": "MISS"}},
	})
	for _, f := range findings {
		if f.ID == "cache.repeated-request" && strings.Contains(f.Summary, "broken") {
			t.Fatalf("bad wording: %q", f.Summary)
		}
	}
}
