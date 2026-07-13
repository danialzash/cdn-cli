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
			"type": "full"
		}
	}`

	var resp DomainResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Data.Name != "example.com" {
		t.Fatalf("name = %q", resp.Data.Name)
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
