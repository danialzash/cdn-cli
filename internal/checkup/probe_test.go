package checkup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeHTTPRedirectLoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer srv.Close()

	client := NewProbeHTTPClient(5 * time.Second)
	result := ProbeHTTP(context.Background(), client, srv.URL, "")
	if !result.RedirectLoop && result.Error == "" {
		t.Fatalf("expected redirect issue, got %+v", result)
	}
}

func TestProbeHTTPVergeHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-PoweredBy", "VergeCloud")
		w.Header().Set("X-Request-Id", "abc123")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := NewProbeHTTPClient(5 * time.Second)
	result := ProbeHTTP(context.Background(), client, srv.URL, "")
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	if !IsVergeEdgeStrong(result.AnalysisHeaders) {
		t.Fatalf("expected strong edge evidence, got %#v", result.AnalysisHeaders)
	}
	ev := DetectEdgeEvidence(result.AnalysisHeaders)
	if ev.Confidence != "strong" {
		t.Fatalf("expected strong confidence, got %q", ev.Confidence)
	}
}

func TestProbeHTTPBoundedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", maxBodyRead+1024)))
	}))
	defer srv.Close()

	client := NewProbeHTTPClient(5 * time.Second)
	result := ProbeHTTP(context.Background(), client, srv.URL, "")
	if result.Error != "" {
		t.Fatal(result.Error)
	}
}

func TestFilterSafeHeadersExcludesCookies(t *testing.T) {
	h := http.Header{}
	h.Set("Set-Cookie", "secret=1")
	h.Set("Server", "nginx")
	safe := FilterSafeHeaders(h)
	if _, ok := safe["set-cookie"]; ok {
		t.Fatal("cookie header must not be exposed")
	}
	if safe["server"] != "nginx" {
		t.Fatal("expected server header")
	}
}

func TestProbeHTTPIndependentRedirectState(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()

	loopSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer loopSrv.Close()

	client := NewProbeHTTPClient(5 * time.Second)
	ctx := context.Background()

	okResult := ProbeHTTP(ctx, client, okSrv.URL, "")
	if okResult.Error != "" || okResult.RedirectLoop {
		t.Fatalf("ok server probe failed: %+v", okResult)
	}

	loopResult := ProbeHTTP(ctx, client, loopSrv.URL, "")
	if !loopResult.RedirectLoop && loopResult.Error == "" {
		t.Fatalf("expected redirect loop on second probe, got %+v", loopResult)
	}
	if okResult.RedirectLoop {
		t.Fatal("first probe redirect state was contaminated by second probe")
	}
}

func TestFilterAnalysisHeadersIncludesSecurityHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Set-Cookie", "secret=1")
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("Server", "nginx")
	analysis := FilterAnalysisHeaders(h)
	safe := FilterSafeHeaders(h)
	if _, ok := analysis["content-security-policy"]; !ok {
		t.Fatal("analysis must include CSP")
	}
	if _, ok := safe["content-security-policy"]; ok {
		t.Fatal("safe output must not include CSP")
	}
	if _, ok := safe["set-cookie"]; ok {
		t.Fatal("safe output must not include cookies")
	}
}

func TestCacheStatusFromHeaders(t *testing.T) {
	if got := CacheStatusFromHeaders(map[string]string{"x-cache-status": "HIT"}); got != "hit" {
		t.Fatalf("got %q", got)
	}
}
