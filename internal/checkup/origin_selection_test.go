package checkup

import (
	"context"
	"testing"
)

func TestOriginDefaultPort(t *testing.T) {
	if originDefaultPort("http") != 80 {
		t.Fatal("http should default to 80")
	}
	if originDefaultPort("https") != 443 {
		t.Fatal("https should default to 443")
	}
}

func TestParseOriginHostPortExplicitHTTPPort(t *testing.T) {
	host, port, fromOrigin := parseOriginHostPort("203.0.113.10", 8080)
	if host != "203.0.113.10" || port != 8080 || !fromOrigin {
		t.Fatalf("got %q %d %v", host, port, fromOrigin)
	}
}

func TestParseOriginHostPortEmbeddedPort(t *testing.T) {
	host, port, fromOrigin := parseOriginHostPort("203.0.113.10:8080", 0)
	if host != "203.0.113.10" || port != 8080 || !fromOrigin {
		t.Fatalf("got %q %d %v", host, port, fromOrigin)
	}
}

func TestExplicitHTTPSchemeDefaultsPort80(t *testing.T) {
	runner, _ := NewRunner(nil)
	state := &State{Options: Options{Origin: "203.0.113.10", OriginScheme: "http", Path: "/"}}
	selection := runner.selectOrigin(contextBackground(), state, "example.com", "/")
	if selection.Scheme != "http" || selection.Port != 80 {
		t.Fatalf("got %+v", selection)
	}
	if selection.Address != "203.0.113.10:80" {
		t.Fatalf("address = %q", selection.Address)
	}
}

func TestExplicitHTTPSSchemeDefaultsPort443(t *testing.T) {
	runner, _ := NewRunner(nil)
	state := &State{Options: Options{Origin: "203.0.113.10", OriginScheme: "https", Path: "/"}}
	selection := runner.selectOrigin(contextBackground(), state, "example.com", "/")
	if selection.Scheme != "https" || selection.Port != 443 || selection.Address != "203.0.113.10:443" {
		t.Fatalf("got %+v", selection)
	}
}

func contextBackground() context.Context {
	return context.Background()
}
