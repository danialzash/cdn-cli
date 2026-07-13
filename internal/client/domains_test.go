package client

import (
	"testing"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

func TestMapDomainIncludesPlan(t *testing.T) {
	mapped := mapDomain(sdk.Domain{
		Name:   "stormedge.cloud",
		Status: "active",
		Plan:   sdk.DomainPlan{Name: "enterprise"},
	})
	if mapped.Plan != "enterprise" {
		t.Fatalf("plan = %q, want enterprise", mapped.Plan)
	}
}
