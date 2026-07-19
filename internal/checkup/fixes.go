package checkup

import (
	"context"
	"fmt"
)

type FixRunner struct {
	applier  FixApplier
	verifier FixVerifier
}

func NewFixRunner(applier FixApplier, verifier FixVerifier) *FixRunner {
	return &FixRunner{applier: applier, verifier: verifier}
}

func CollectFixPlans(findings []Finding) []FixPlan {
	var plans []FixPlan
	seen := map[string]struct{}{}
	for _, f := range findings {
		if f.Fix == nil || !f.Fix.Automatic || f.Fix.Safety != FixSafetySafe {
			continue
		}
		if _, ok := seen[f.Fix.ID]; ok {
			continue
		}
		seen[f.Fix.ID] = struct{}{}
		plans = append(plans, *f.Fix)
	}
	return plans
}

func (fr *FixRunner) Apply(ctx context.Context, domain string, plans []FixPlan, dryRun bool) []FixResult {
	results := make([]FixResult, 0, len(plans))
	for _, plan := range plans {
		result := FixResult{FixID: plan.ID, DryRun: dryRun}
		if dryRun {
			result.Applied = false
			result.Message = fmt.Sprintf("Would apply: %s", plan.Description)
			results = append(results, result)
			continue
		}
		if err := fr.applier.ApplyFix(ctx, domain, plan); err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		result.Applied = true
		if fr.verifier == nil {
			result.Error = "fix verification is not configured"
			results = append(results, result)
			continue
		}
		verification, message, err := fr.verifier.VerifyFix(ctx, domain, plan)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		result.Verification = verification
		if !verification.ConfigurationVerified || !verificationBehaviorRequired(plan, verification) {
			if message == "" {
				message = "expected state was not confirmed after applying fix"
			}
			result.Error = message
			results = append(results, result)
			continue
		}
		result.Verified = true
		result.Message = plan.Description + " applied and verified."
		results = append(results, result)
	}
	return results
}

func verificationBehaviorRequired(plan FixPlan, verification FixVerification) bool {
	switch plan.ID {
	case "ssl.https-redirect":
		return verification.BehaviorVerified
	default:
		return true
	}
}

func FixFailed(results []FixResult) bool {
	for _, r := range results {
		if r.Error != "" {
			return true
		}
	}
	return false
}
