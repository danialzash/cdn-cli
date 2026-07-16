package dnsverify

import "testing"

func TestNormalizeResolverAddress(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"1.1.1.1", "1.1.1.1:53", false},
		{"1.1.1.1:53", "1.1.1.1:53", false},
		{"8.8.8.8", "8.8.8.8:53", false},
		{"[2606:4700:4700::1111]:53", "[2606:4700:4700::1111]:53", false},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53", false},
		{"dns.example.com", "dns.example.com:53", false},
		{"dns.example.com:5353", "dns.example.com:5353", false},
		{"", "", true},
		{"[::1", "", true},
		{":53", "", true},
	}
	for _, tc := range tests {
		got, err := NormalizeResolverAddress(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q: expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeResolversMultiple(t *testing.T) {
	got, err := NormalizeResolvers([]string{"1.1.1.1", "8.8.8.8:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "8.8.8.8:53" {
		t.Fatalf("got %v", got)
	}
}

func TestNormalizeResolverPortValidation(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"1.1.1.1:53", false},
		{"1.1.1.1:5353", false},
		{"1.1.1.1:0", true},
		{"1.1.1.1:65536", true},
		{"dns.example.com:not-a-port", true},
		{":53", true},
	}
	for _, tc := range cases {
		_, err := NormalizeResolverAddress(tc.in)
		if tc.wantErr && err == nil {
			t.Fatalf("%q: expected error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
	}
}
