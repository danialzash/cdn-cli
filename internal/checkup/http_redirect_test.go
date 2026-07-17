package checkup

import (
	"testing"

	"github.com/vergecloud/cdn-cli/internal/client"
)

func redirectFixFinding(t *testing.T, state *State) Finding {
	t.Helper()
	findings := (&HTTPCheck{}).redirectToHTTPSFinding(state)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	return findings[0]
}

func assertNoHTTPSRedirectFix(t *testing.T, f Finding) {
	t.Helper()
	if f.Fix != nil {
		t.Fatal("HTTPS redirect fix must not be offered when HTTP is unhealthy or untrusted")
	}
}

func healthyRedirectState() *State {
	return &State{
		Domain:  DomainSummary{Name: "example.com"},
		Options: DefaultOptions(),
		Inspect: &client.DomainInspect{SSL: client.SslInspect{HTTPSRedirect: false, Enabled: true}},
		HTTPProbe: &HTTPProbeResult{
			URL: "http://example.com/", FinalURL: "http://example.com/", StatusCode: 200,
		},
		HTTPSProbe: &HTTPProbeResult{
			URL: "https://example.com/", FinalURL: "https://example.com/", StatusCode: 200,
		},
		TLSProbe: &TLSProbeResult{Connected: true, HostnameMatch: true},
	}
}

func TestHTTPSRedirectFixOfferedWhenHealthy(t *testing.T) {
	f := redirectFixFinding(t, healthyRedirectState())
	if f.Fix == nil {
		t.Fatal("expected HTTPS redirect fix")
	}
}

func TestHTTPSRedirectFixNotOfferedOnHTTP503(t *testing.T) {
	state := healthyRedirectState()
	state.HTTPProbe.StatusCode = 503
	f := redirectFixFinding(t, state)
	assertNoHTTPSRedirectFix(t, f)
}

func TestHTTPSRedirectFixNotOfferedOnHTTP500(t *testing.T) {
	state := healthyRedirectState()
	state.HTTPProbe.StatusCode = 500
	f := redirectFixFinding(t, state)
	assertNoHTTPSRedirectFix(t, f)
}

func TestHTTPSRedirectFixNotOfferedOnHTTP403(t *testing.T) {
	state := healthyRedirectState()
	state.HTTPProbe.StatusCode = 403
	f := redirectFixFinding(t, state)
	assertNoHTTPSRedirectFix(t, f)
}

func TestHTTPSRedirectFixNotOfferedOnUnrelatedRedirect(t *testing.T) {
	state := healthyRedirectState()
	state.HTTPProbe.FinalURL = "https://unrelated.example/"
	state.HTTPProbe.RedirectEvidence = RedirectEvidence{
		FinalURL:        "https://unrelated.example/",
		UnexpectedHosts: []string{"unrelated.example"},
	}
	f := redirectFixFinding(t, state)
	assertNoHTTPSRedirectFix(t, f)
}

func TestHTTPSRedirectFixNotOfferedOnRedirectLoop(t *testing.T) {
	state := healthyRedirectState()
	state.HTTPProbe.RedirectEvidence = RedirectEvidence{LoopDetected: true}
	f := redirectFixFinding(t, state)
	assertNoHTTPSRedirectFix(t, f)
}

func TestHTTPSRedirectFixNotOfferedOnHTTPTimeout(t *testing.T) {
	state := healthyRedirectState()
	state.HTTPProbe = &HTTPProbeResult{
		Error: "context deadline exceeded", TimedOut: true, ProbeExecError: true,
	}
	f := redirectFixFinding(t, state)
	assertNoHTTPSRedirectFix(t, f)
}

func TestHTTPSRedirectFixNotOfferedOnHTTPConnectionRefused(t *testing.T) {
	state := healthyRedirectState()
	state.HTTPProbe = &HTTPProbeResult{Error: "connection refused"}
	f := redirectFixFinding(t, state)
	assertNoHTTPSRedirectFix(t, f)
}
