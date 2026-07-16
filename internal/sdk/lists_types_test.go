package sdk

import (
	"encoding/json"
	"testing"
)

func TestDynamicFieldResponseUnmarshal(t *testing.T) {
	raw := `{
		"data": {
			"id": "11111111-1111-1111-1111-111111111111",
			"name": "blocked-ips",
			"type": "ip",
			"scope": "private",
			"values": []
		},
		"message": "List created successfully."
	}`

	var resp DynamicFieldResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Name != "blocked-ips" {
		t.Fatalf("name = %q, want blocked-ips", resp.Data.Name)
	}
	if resp.Message != "List created successfully." {
		t.Fatalf("message = %q, want List created successfully.", resp.Message)
	}
}
