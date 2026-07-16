package client

import "testing"

func TestReportPathTraffic(t *testing.T) {
	path, err := ReportPath("traffic", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/reports/example.com/traffic" {
		t.Fatalf("path = %q, want /reports/example.com/traffic", path)
	}
}

func TestReportPathTrafficSaved(t *testing.T) {
	path, err := ReportPath("traffic-saved", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/reports/example.com/traffic/saved" {
		t.Fatalf("path = %q, want /reports/example.com/traffic/saved", path)
	}
}

func TestReportPathRequestSummary(t *testing.T) {
	path, err := ReportPath("request-summary", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/reports/example.com/traffic/saved" {
		t.Fatalf("path = %q, want /reports/example.com/traffic/saved", path)
	}
}

func TestReportPathTrafficSummary(t *testing.T) {
	path, err := ReportPath("traffic-summary", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/reports/example.com/traffic/saved" {
		t.Fatalf("path = %q, want /reports/example.com/traffic/saved", path)
	}
}

func TestReportPathTrafficGeo(t *testing.T) {
	path, err := ReportPath("traffic-geo", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/reports/example.com/traffic/geo-map" {
		t.Fatalf("path = %q, want /reports/example.com/traffic/geo-map", path)
	}
}
