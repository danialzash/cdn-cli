package checkup

import "testing"

func TestValidateOriginHostRejectsWhitespace(t *testing.T) {
	cases := []string{
		"bad host",
		"bad\thost",
		"bad\nhost",
		"bad\rhost",
		"bad\u00a0host",
	}
	for _, host := range cases {
		if err := validateOriginHostString(host); err == nil {
			t.Fatalf("expected error for host %q", host)
		}
	}
}

func TestValidateOriginHostAcceptsValid(t *testing.T) {
	cases := []string{
		"origin.example.com",
		"203.0.113.10",
		"2001:db8::1",
	}
	for _, host := range cases {
		if err := validateOriginHostString(host); err != nil {
			t.Fatalf("unexpected error for host %q: %v", host, err)
		}
	}
}
