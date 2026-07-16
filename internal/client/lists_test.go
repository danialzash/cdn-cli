package client

import (
	"encoding/json"
	"testing"
)

func TestEncodeListValue(t *testing.T) {
	raw, err := encodeListValue("ip", "192.0.2.1")
	if err != nil {
		t.Fatalf("encodeListValue ip: %v", err)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s != "192.0.2.1" {
		t.Fatalf("ip value = %q, want 192.0.2.1", raw)
	}

	raw, err = encodeListValue("number", "42")
	if err != nil {
		t.Fatalf("encodeListValue number: %v", err)
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err != nil || n != 42 {
		t.Fatalf("number value = %v, want 42", raw)
	}
}

func TestFormatListItemValue(t *testing.T) {
	if got := formatListItemValue(json.RawMessage(`"abc"`)); got != "abc" {
		t.Fatalf("formatListItemValue string = %q, want abc", got)
	}
	if got := formatListItemValue(json.RawMessage(`42`)); got != "42" {
		t.Fatalf("formatListItemValue number = %q, want 42", got)
	}
}
