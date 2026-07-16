package sdk

import (
	"encoding/json"
	"testing"
)

func TestMergePageRuleUpdate(t *testing.T) {
	existing := json.RawMessage(`{"url":"/old","status":true,"cache_level":"uri"}`)
	updated, err := MergePageRuleUpdate(existing, map[string]any{
		"url": "/new",
	})
	if err != nil {
		t.Fatalf("MergePageRuleUpdate: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(updated, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["url"] != "/new" {
		t.Fatalf("url = %v, want /new", result["url"])
	}
	if result["status"] != true {
		t.Fatalf("status = %v, want true", result["status"])
	}
	if result["cache_level"] != "uri" {
		t.Fatalf("cache_level = %v, want uri", result["cache_level"])
	}
}
