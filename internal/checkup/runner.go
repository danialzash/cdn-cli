package checkup

import (
	"context"
	"fmt"
	"time"

	"github.com/vergecloud/cdn-cli/internal/client"
)

type Runner struct {
	source   DataSource
	registry *Registry
	prober   *Prober
}

type Prober struct {
	HTTPClient *HTTPClientFactory
}

type HTTPClientFactory struct {
	ProbeTimeout time.Duration
}

func NewRunner(source DataSource) (*Runner, error) {
	reg, err := DefaultRegistry()
	if err != nil {
		return nil, err
	}
	return &Runner{
		source:   source,
		registry: reg,
		prober:   &Prober{},
	}, nil
}

func (r *Runner) Run(ctx context.Context, domainArg string, opts Options) Result {
	started := time.Now()
	state := &State{Options: opts}

	enabled := opts.EnabledCategories()
	plan, err := r.registry.Plan(enabled)
	if err != nil {
		return Result{Err: err, ExitCode: ExitError}
	}
	state.VisibleCategories = plan.VisibleCategories
	state.Requirements = plan.Requirements

	if err := r.runDomainResolve(ctx, domainArg, state, plan.Requirements); err != nil {
		return Result{Err: err, ExitCode: ExitError}
	}
	r.prepareState(ctx, state, plan.Requirements)

	var findings []Finding
	for _, check := range plan.VisibleChecks {
		if ctx.Err() != nil {
			break
		}
		findings = append(findings, check.Run(ctx, state)...)
	}

	report := r.buildReport(state, opts, findings, started, false)
	return Result{
		Report:   report,
		ExitCode: report.ExitCode,
	}
}

func (r *Runner) buildReport(state *State, opts Options, findings []Finding, started time.Time, fixFailed bool) Report {
	SortFindings(findings)
	ensureUniqueFindingIDs(findings)
	summary := SummarizeFindings(findings)
	completed := time.Now()
	report := Report{
		Domain:      state.Domain,
		Options:     opts,
		StartedAt:   started,
		CompletedAt: completed,
		Duration:    DurationJSON(completed.Sub(started)),
		Findings:    findings,
		Summary:     summary,
		ProbeErrors: append([]ProbeError(nil), state.ProbeErrors...),
	}
	report.ExitCode = ComputeExitCode(summary, opts.Strict, report.ProbeErrors, fixFailed)
	return report
}

func ensureUniqueFindingIDs(findings []Finding) {
	seen := map[string]int{}
	for i := range findings {
		id := findings[i].ID
		if count, ok := seen[id]; ok {
			seen[id] = count + 1
			findings[i].ID = FindingID(id, fmt.Sprintf("%d", count+1))
		} else {
			seen[id] = 1
		}
	}
}

func (r *Runner) runDomainResolve(ctx context.Context, domainArg string, state *State, req Requirements) error {
	detail, err := r.source.ResolveDomain(ctx, domainArg)
	if err != nil {
		return fmt.Errorf("resolve domain: %w", err)
	}
	state.Domain = mapDomainSummary(*detail)
	sections := inspectSectionsFromRequirements(req)
	state.Inspect, err = r.source.LoadInspect(ctx, detail.Name, sections)
	if err != nil {
		return fmt.Errorf("load inspect data: %w", err)
	}
	return nil
}

// ApplyFixes applies safe fixes, verifies each change, and reruns checkup read-only when not dry-run.
func (r *Runner) ApplyFixes(ctx context.Context, domainArg string, report *Report, opts Options, applier FixApplier, verifier FixVerifier) {
	if !opts.Fix || applier == nil {
		return
	}
	plans := CollectFixPlans(report.Findings)
	if len(plans) == 0 {
		return
	}
	fixRunner := NewFixRunner(applier, verifier)
	fixResults := fixRunner.Apply(ctx, report.Domain.Name, plans, opts.DryRun)
	report.Fixes = fixResults
	fixFailed := FixFailed(fixResults) || fixVerificationFailed(fixResults)

	if opts.DryRun || !anyFixApplied(fixResults) {
		if fixFailed {
			report.ExitCode = ExitFixFailed
		}
		return
	}

	rerunOpts := opts
	rerunOpts.Fix = false
	rerunOpts.Yes = false
	rerunOpts.DryRun = false

	rerun := r.Run(ctx, domainArg, rerunOpts)
	if rerun.Err != nil {
		report.ExitCode = ExitError
		return
	}

	for i, result := range fixResults {
		if !result.Applied || result.DryRun {
			continue
		}
		plan := findPlan(plans, result.FixID)
		if plan == nil {
			continue
		}
		if FindingStillUnhealthy(rerun.Report, *plan) {
			fixResults[i].Verified = false
			fixResults[i].Verification.BehaviorVerified = false
			if fixResults[i].Error == "" {
				fixResults[i].Error = "expected finding still reports an issue after fix"
			}
			fixFailed = true
		}
	}

	rerun.Report.Fixes = fixResults
	rerun.Report.Options = opts
	*report = rerun.Report
	if fixFailed {
		report.ExitCode = ExitFixFailed
	} else {
		report.ExitCode = ComputeExitCode(report.Summary, opts.Strict, report.ProbeErrors, false)
	}
}

func findPlan(plans []FixPlan, id string) *FixPlan {
	for i := range plans {
		if plans[i].ID == id {
			return &plans[i]
		}
	}
	return nil
}

func anyFixApplied(results []FixResult) bool {
	for _, r := range results {
		if r.Applied {
			return true
		}
	}
	return false
}

func fixVerificationFailed(results []FixResult) bool {
	for _, r := range results {
		if r.Applied && (!r.Verified || r.Error != "") {
			return true
		}
	}
	return false
}

func mapDomainSummary(d client.DomainDetail) DomainSummary {
	return DomainSummary{
		ID:           d.ID,
		Name:         d.Name,
		Status:       d.Status,
		Type:         d.Type,
		CnameTarget:  d.CnameTarget,
		CustomCname:  d.CustomCname,
		NSKeys:       d.NSKeys,
		Restrictions: d.Restrictions,
	}
}

type DomainResolveCheck struct{}

func (c *DomainResolveCheck) ID() string             { return "domain.resolve" }
func (c *DomainResolveCheck) Category() Category     { return CategoryConfiguration }
func (c *DomainResolveCheck) Dependencies() []string { return nil }
func (c *DomainResolveCheck) Run(_ context.Context, _ *State) []Finding {
	return nil
}
