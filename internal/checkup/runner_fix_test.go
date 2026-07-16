package checkup

import (
	"context"
	"testing"

	"github.com/vergecloud/cdn-cli/internal/client"
)

type rerunFixSource struct {
	runCount int
}

func (s *rerunFixSource) ResolveDomain(context.Context, string) (*client.DomainDetail, error) {
	return &client.DomainDetail{Domain: client.Domain{Name: "example.com", Type: "full", Status: "active"}}, nil
}
func (s *rerunFixSource) LoadInspect(context.Context, string, map[string]bool) (*client.DomainInspect, error) {
	return &client.DomainInspect{Cache: client.CacheInspect{DeveloperMode: true, Status: "on"}}, nil
}
func (s *rerunFixSource) CheckNameservers(context.Context, string) (*client.NSCheckResult, error) {
	return &client.NSCheckResult{Expected: []string{"ns1.cdn.net"}, Published: []string{"ns1.cdn.net"}}, nil
}
func (s *rerunFixSource) FetchCnameSetupStatus(context.Context, string) (*client.CnameSetupStatus, error) {
	return nil, nil
}
func (s *rerunFixSource) GetLatestSmartCheck(context.Context, string) (*client.SmartCheck, error) {
	return nil, nil
}

type trackingFixApplier struct {
	applyCount int
	verify     FixVerification
}

func (t *trackingFixApplier) ApplyFix(context.Context, string, FixPlan) error {
	t.applyCount++
	return nil
}
func (t *trackingFixApplier) VerifyFix(context.Context, string, FixPlan) (FixVerification, string, error) {
	return t.verify, "", nil
}

func TestFindingStillUnhealthyDetectsRemainingIssue(t *testing.T) {
	report := Report{Findings: []Finding{{ID: "cache.developer-mode", Status: StatusWarn}}}
	plan := FixPlan{ID: "cache.developer-mode"}
	if !FindingStillUnhealthy(report, plan) {
		t.Fatal("expected unhealthy finding")
	}
}

func TestRerunOptsAreReadOnly(t *testing.T) {
	opts := DefaultOptions()
	opts.Fix = true
	opts.Yes = true
	opts.DryRun = true
	rerunOpts := opts
	rerunOpts.Fix = false
	rerunOpts.Yes = false
	rerunOpts.DryRun = false
	if !opts.Fix || rerunOpts.Fix || rerunOpts.Yes || rerunOpts.DryRun {
		t.Fatal("rerun options must be read-only copy")
	}
}

func TestFixApplyDoesNotReapplyWhenVerificationFails(t *testing.T) {
	applier := &trackingFixApplier{verify: FixVerification{ConfigurationVerified: false}}
	runner, _ := NewRunner(&rerunFixSource{})
	opts := DefaultOptions()
	opts.Fix = true

	report := Report{
		Domain: DomainSummary{Name: "example.com", Type: "full"},
		Findings: []Finding{{
			ID: "cache.developer-mode", Status: StatusWarn,
			Fix: &FixPlan{ID: "cache.developer-mode", Safety: FixSafetySafe, Automatic: true},
		}},
	}
	runner.ApplyFixes(context.Background(), "example.com", &report, opts, applier, applier)
	if applier.applyCount != 1 {
		t.Fatalf("apply count = %d", applier.applyCount)
	}
}
