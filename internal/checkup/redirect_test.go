package checkup

import "testing"

func TestRedirectEvidenceFindingsHTTPSDowngrade(t *testing.T) {
	ev := buildRedirectEvidence("https://example.com", []string{"http://example.com/"}, "http://example.com/", 200, nil, "example.com")
	findings := redirectEvidenceFindings("https", CategoryHTTP, "example.com", ev)
	found := false
	for _, f := range findings {
		if f.ID == "https.redirect-downgrade" && f.Status == StatusFail {
			found = true
		}
	}
	if !found {
		t.Fatalf("got %+v", findings)
	}
}

func TestRedirectApexWWWAccepted(t *testing.T) {
	ev := buildRedirectEvidence("http://example.com", []string{"https://www.example.com/"}, "https://www.example.com/", 200, nil, "example.com")
	findings := redirectEvidenceFindings("http", CategoryHTTP, "example.com", ev)
	for _, f := range findings {
		if f.ID == "http.redirect-unexpected-host.www.example.com" && f.Status != StatusPass {
			t.Fatalf("www should be accepted: %+v", f)
		}
	}
}

func TestRedirectUnrelatedDomainWarns(t *testing.T) {
	ev := buildRedirectEvidence("http://example.com", []string{"https://other.com/"}, "https://other.com/", 200, nil, "example.com")
	findings := redirectEvidenceFindings("http", CategoryHTTP, "example.com", ev)
	found := false
	for _, f := range findings {
		if f.Status == StatusWarn && f.ID == "http.redirect-unexpected-host.other.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("got %+v", findings)
	}
}

func TestRedirectFinal503Fails(t *testing.T) {
	ev := buildRedirectEvidence("http://example.com", nil, "https://example.com/", 503, nil, "example.com")
	findings := redirectEvidenceFindings("http", CategoryHTTP, "example.com", ev)
	found := false
	for _, f := range findings {
		if f.ID == "http.redirect-final-error" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected final error finding")
	}
}

func TestNestedDowngradeLoopRegression(t *testing.T) {
	chain := []string{
		"https://example.com/a",
		"http://example.com/b",
		"https://example.com/c",
	}
	ev := buildRedirectEvidence("https://example.com", chain, "https://example.com/c", 200, nil, "example.com")
	if !ev.DowngradeDetected {
		t.Fatal("expected single downgrade detection across chain")
	}
}
