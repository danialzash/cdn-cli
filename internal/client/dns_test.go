package client

import "testing"

func TestFormatDNSValue(t *testing.T) {
	got := formatDNSValue("a", []byte(`[{"ip":"198.51.100.42","weight":100,"country":"US"}]`))
	want := "198.51.100.42 (w=100) [US]"
	if got != want {
		t.Fatalf("formatDNSValue() = %q, want %q", got, want)
	}

	got = formatDNSValue("txt", []byte(`{"text":"v=spf1 include:_spf.example.com ~all"}`))
	want = "v=spf1 include:_spf.example.com ~all"
	if got != want {
		t.Fatalf("formatDNSValue() = %q, want %q", got, want)
	}

	got = formatDNSValue("mx", []byte(`{"host":"mail.example.com","priority":10}`))
	want = "10 mail.example.com"
	if got != want {
		t.Fatalf("formatDNSValue() = %q, want %q", got, want)
	}
}

func TestBuildDNSValue(t *testing.T) {
	raw, err := buildDNSValue(CreateDNSRecordInput{
		Type:  "a",
		Name:  "www",
		Value: "198.51.100.42",
	})
	if err != nil {
		t.Fatalf("buildDNSValue: %v", err)
	}
	if string(raw) != `[{"ip":"198.51.100.42"}]` {
		t.Fatalf("unexpected payload: %s", string(raw))
	}
}
