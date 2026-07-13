package dnsverify

import (
	"context"
	"testing"
)

func TestVerifyAllPreservesOrder(t *testing.T) {
	checker := NewChecker()
	jobs := []VerifyJob{
		{RecordID: "1", RecordType: "ptr", Name: "a", Domain: "example.com", Expected: "x"},
		{RecordID: "2", RecordType: "ptr", Name: "b", Domain: "example.com", Expected: "y"},
		{RecordID: "3", RecordType: "ptr", Name: "c", Domain: "example.com", Expected: "z"},
	}

	results := checker.VerifyAll(context.Background(), jobs, 2)
	if len(results) != 3 {
		t.Fatalf("len = %d, want 3", len(results))
	}
	if results[0].RecordID != "1" || results[1].RecordID != "2" || results[2].RecordID != "3" {
		t.Fatalf("order not preserved: %+v", results)
	}
	for _, result := range results {
		if result.Status != "skipped" {
			t.Fatalf("expected skipped status, got %q", result.Status)
		}
	}
}

func TestVerifyAllWorkersDefault(t *testing.T) {
	checker := NewChecker()
	results := checker.VerifyAll(context.Background(), nil, 0)
	if results != nil {
		t.Fatalf("expected nil results for empty jobs")
	}

	results = checker.VerifyAll(context.Background(), []VerifyJob{
		{RecordID: "1", RecordType: "ptr", Name: "a", Domain: "example.com"},
	}, 0)
	if len(results) != 1 {
		t.Fatalf("len = %d, want 1", len(results))
	}
}
