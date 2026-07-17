package checkup

import (
	"context"
	"testing"
)

func TestParseOriginHostPortTable(t *testing.T) {
	tests := []struct {
		name            string
		origin          string
		explicitPort    int
		explicitPortSet bool
		wantHost        string
		wantPort        int
		wantProvided    bool
		wantErr         bool
	}{
		{"ipv4 no port", "203.0.113.10", 0, false, "203.0.113.10", 0, false, false},
		{"ipv4 with port", "203.0.113.10:8080", 0, false, "203.0.113.10", 8080, true, false},
		{"hostname no port", "origin.example.com", 0, false, "origin.example.com", 0, false, false},
		{"hostname with port", "origin.example.com:8443", 0, false, "origin.example.com", 8443, true, false},
		{"bare ipv6", "2001:db8::1", 0, false, "2001:db8::1", 0, false, false},
		{"bracketed ipv6", "[2001:db8::1]", 0, false, "2001:db8::1", 0, false, false},
		{"bracketed ipv6 with port", "[2001:db8::1]:8443", 0, false, "2001:db8::1", 8443, true, false},
		{"invalid string port", "example.com:not-a-port", 0, false, "", 0, false, true},
		{"port suffix garbage", "example.com:80abc", 0, false, "", 0, false, true},
		{"empty port", "example.com:", 0, false, "", 0, false, true},
		{"missing closing bracket", "[2001:db8::1", 0, false, "", 0, false, true},
		{"bracket empty port", "[2001:db8::1]:", 0, false, "", 0, false, true},
		{"hostname with path", "example.com/path", 0, false, "", 0, false, true},
		{"explicit port override", "example.com:8080", 8443, true, "example.com", 8443, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, provided, err := parseOriginHostPort(tc.origin, tc.explicitPort, tc.explicitPortSet)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.wantHost || port != tc.wantPort || provided != tc.wantProvided {
				t.Fatalf("got host=%q port=%d provided=%v", host, port, provided)
			}
		})
	}
}

func TestValidatePortRejectsOutOfRange(t *testing.T) {
	if err := validatePort(0); err == nil {
		t.Fatal("expected port 0 error")
	}
	if err := validatePort(65536); err == nil {
		t.Fatal("expected port 65536 error")
	}
	opts := DefaultOptions()
	opts.Origin = "203.0.113.10"
	opts.OriginPortSet = true
	opts.OriginPort = 65536
	if err := opts.Validate(); err == nil {
		t.Fatal("expected origin-port validation error")
	}
}

func TestJoinOriginAddressIPv6Normalized(t *testing.T) {
	got := joinOriginAddress("2001:db8::1", 443)
	want := "[2001:db8::1]:443"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseOriginHostPortExplicitHTTPPort(t *testing.T) {
	host, port, fromOrigin, err := parseOriginHostPort("203.0.113.10", 8080, true)
	if err != nil || host != "203.0.113.10" || port != 8080 || !fromOrigin {
		t.Fatalf("got %q %d %v err=%v", host, port, fromOrigin, err)
	}
}

func TestParseOriginHostPortEmbeddedPort(t *testing.T) {
	host, port, fromOrigin, err := parseOriginHostPort("203.0.113.10:8080", 0, false)
	if err != nil || host != "203.0.113.10" || port != 8080 || !fromOrigin {
		t.Fatalf("got %q %d %v err=%v", host, port, fromOrigin, err)
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
