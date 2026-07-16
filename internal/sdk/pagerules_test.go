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

func TestBuildCreatePageRuleBody(t *testing.T) {
	body, err := BuildCreatePageRuleBody("/api/*", true, 5, "uri", "1h")
	if err != nil {
		t.Fatalf("BuildCreatePageRuleBody: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["url"] != "/api/*" {
		t.Fatalf("url = %v, want /api/*", result["url"])
	}
	if result["status"] != true {
		t.Fatalf("status = %v, want true", result["status"])
	}
	if result["seq"] != float64(5) {
		t.Fatalf("seq = %v, want 5", result["seq"])
	}
	if result["cache_level"] != "uri" {
		t.Fatalf("cache_level = %v, want uri", result["cache_level"])
	}
	if result["cache_max_age"] != "1h" {
		t.Fatalf("cache_max_age = %v, want 1h", result["cache_max_age"])
	}
}
