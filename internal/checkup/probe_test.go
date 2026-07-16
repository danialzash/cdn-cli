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
	if !IsVergeEdgeHeader(result.Headers) {
		t.Fatalf("expected edge headers, got %#v", result.Headers)
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

func TestCacheStatusFromHeaders(t *testing.T) {
	if got := CacheStatusFromHeaders(map[string]string{"x-cache-status": "HIT"}); got != "hit" {
		t.Fatalf("got %q", got)
	}
}
