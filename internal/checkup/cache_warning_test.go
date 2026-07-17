package checkup

import (
	"context"
	"testing"
)

func cacheRepeatedFinding(t *testing.T, firstCode, secondCode int, firstCache, secondCache string) Finding {
	t.Helper()
	findings := (&CacheCheck{}).Run(context.Background(), &State{
		Domain:  DomainSummary{Name: "example.com"},
		Options: DefaultOptions(),
		Inspect: inspectForCategoryChecks(),
		HTTPSProbe: &HTTPProbeResult{
			StatusCode: firstCode,
			FinalURL:   "https://example.com/",
			URL:        "https://example.com/",
			Headers:    map[string]string{"x-cache": firstCache},
			RedirectEvidence: RedirectEvidence{
				FinalURL: "https://example.com/", FinalStatus: firstCode,
			},
		},
		SecondHTTPSProbe: &HTTPProbeResult{
			StatusCode: secondCode,
			FinalURL:   "https://example.com/",
			URL:        "https://example.com/",
			Headers:    map[string]string{"x-cache": secondCache},
			RedirectEvidence: RedirectEvidence{
				FinalURL: "https://example.com/", FinalStatus: secondCode,
			},
		},
	})
	for _, f := range findings {
		if f.ID == "cache.repeated-request" {
			return f
		}
	}
	t.Fatalf("cache.repeated-request not found in %+v", findings)
	return Finding{}
}

func TestCache403HitPreservesWarning(t *testing.T) {
	f := cacheRepeatedFinding(t, 403, 403, "MISS", "HIT")
	if f.Status != StatusWarn {
		t.Fatalf("expected warn, got %q summary=%q", f.Status, f.Summary)
	}
}

func TestCache401HitPreservesWarning(t *testing.T) {
	f := cacheRepeatedFinding(t, 401, 401, "MISS", "HIT")
	if f.Status != StatusWarn {
		t.Fatalf("expected warn, got %q", f.Status)
	}
}

func TestCache404HitPreservesWarning(t *testing.T) {
	f := cacheRepeatedFinding(t, 404, 404, "MISS", "HIT")
	if f.Status != StatusWarn {
		t.Fatalf("expected warn, got %q", f.Status)
	}
}

func TestCache429HitPreservesWarning(t *testing.T) {
	f := cacheRepeatedFinding(t, 429, 429, "MISS", "HIT")
	if f.Status != StatusWarn {
		t.Fatalf("expected warn, got %q", f.Status)
	}
}

func TestCache200HitRemainsPass(t *testing.T) {
	f := cacheRepeatedFinding(t, 200, 200, "MISS", "HIT")
	if f.Status != StatusPass {
		t.Fatalf("expected pass, got %q", f.Status)
	}
}

func TestCache500ResponseFails(t *testing.T) {
	findings := (&CacheCheck{}).Run(context.Background(), &State{
		Domain:  DomainSummary{Name: "example.com"},
		Options: DefaultOptions(),
		Inspect: inspectForCategoryChecks(),
		HTTPSProbe: &HTTPProbeResult{
			StatusCode: 500, FinalURL: "https://example.com/", URL: "https://example.com/",
			RedirectEvidence: RedirectEvidence{FinalURL: "https://example.com/", FinalStatus: 500},
		},
		SecondHTTPSProbe: &HTTPProbeResult{
			StatusCode: 200, FinalURL: "https://example.com/", URL: "https://example.com/",
			Headers:          map[string]string{"x-cache": "HIT"},
			RedirectEvidence: RedirectEvidence{FinalURL: "https://example.com/", FinalStatus: 200},
		},
	})
	for _, f := range findings {
		if f.ID == "cache.repeated-request" && f.Status != StatusFail {
			t.Fatalf("expected fail for 500, got %q", f.Status)
		}
	}
}

func TestCacheRepeatedRequestTimeoutErrors(t *testing.T) {
	findings := (&CacheCheck{}).Run(context.Background(), &State{
		Domain:  DomainSummary{Name: "example.com"},
		Options: DefaultOptions(),
		Inspect: inspectForCategoryChecks(),
		HTTPSProbe: &HTTPProbeResult{
			StatusCode: 200, FinalURL: "https://example.com/", URL: "https://example.com/",
			RedirectEvidence: RedirectEvidence{FinalURL: "https://example.com/", FinalStatus: 200},
		},
		SecondHTTPSProbe: &HTTPProbeResult{
			Error: "context deadline exceeded", TimedOut: true, ProbeExecError: true,
		},
	})
	for _, f := range findings {
		if f.ID == "cache.repeated-request" && f.Status != StatusError {
			t.Fatalf("expected error for timeout, got %q", f.Status)
		}
	}
}

func TestCache401Then200HitPreservesWarning(t *testing.T) {
	f := cacheRepeatedFinding(t, 401, 200, "MISS", "HIT")
	if f.Status != StatusWarn {
		t.Fatalf("expected warn, got %q", f.Status)
	}
}
