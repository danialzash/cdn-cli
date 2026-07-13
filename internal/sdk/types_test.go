package sdk

import (
	"encoding/json"
	"testing"
)

func TestAPIErrorMessage(t *testing.T) {
	err := &APIError{Message: "Authentication not found"}
	if err.Error() != "Authentication not found" {
		t.Fatalf("error = %q", err.Error())
	}

	err = &APIError{Detail: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{Message: "invalid key"}}
	if err.Error() != "invalid key" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestDecodeDomainResponse(t *testing.T) {
	raw := `{
		"data": {
			"id": "11111111-1111-1111-1111-111111111111",
			"name": "example.com",
			"status": "active",
			"type": "full",
			"account_id": "9ecb9b97-dc4c-416a-8de5-fbb59ca05924",
			"created_at": "2026-05-19T18:51:17+00:00",
			"plan": {
				"id": "8e2b9441-a117-45bd-a69c-eaeceb24ff64",
				"name": "enterprise"
			}
		}
	}`

	var resp DomainResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Name != "example.com" {
		t.Fatalf("name = %q", resp.Data.Name)
	}
	if resp.Data.Plan.Name != "enterprise" {
		t.Fatalf("plan = %q", resp.Data.Plan.Name)
	}
}

func TestDecodeError(t *testing.T) {
	body := []byte(`{"success":false,"message":"Authentication not found","error":{"code":10234,"message":"Authentication not found"}}`)
	err := decodeError(body, 401)
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Message != "Authentication not found" {
		t.Fatalf("message = %q", apiErr.Message)
	}
}
