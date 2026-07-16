package checkup

import (
	"context"
	"fmt"
)

type FixRunner struct {
	applier FixApplier
}

func NewFixRunner(applier FixApplier) *FixRunner {
	return &FixRunner{applier: applier}
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
		result.Verified = true
		result.Message = plan.Description + " applied successfully."
		results = append(results, result)
	}
	return results
}

func FixFailed(results []FixResult) bool {
	for _, r := range results {
		if r.Error != "" {
			return true
		}
	}
	return false
}
