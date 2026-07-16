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
	checks, err := r.registry.ChecksForCategories(enabled)
	if err != nil {
		return Result{Err: err, ExitCode: ExitError}
	}

	var findings []Finding
	if err := r.runDomainResolve(ctx, domainArg, state); err != nil {
		return Result{Err: err, ExitCode: ExitError}
	}
	r.prepareState(ctx, state)

	for _, check := range checks {
		if ctx.Err() != nil {
			break
		}
		if check.ID() == "domain.resolve" {
			continue
		}
		findings = append(findings, check.Run(ctx, state)...)
	}

	SortFindings(findings)
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
	report.ExitCode = ComputeExitCode(summary, opts.Strict, report.ProbeErrors, false)

	return Result{
		Report:   report,
		ExitCode: report.ExitCode,
	}
}

func (r *Runner) runDomainResolve(ctx context.Context, domainArg string, state *State) error {
	detail, err := r.source.ResolveDomain(ctx, domainArg)
	if err != nil {
		return fmt.Errorf("resolve domain: %w", err)
	}
	state.Domain = mapDomainSummary(*detail)
	state.Inspect, err = r.source.LoadInspect(ctx, detail.Name, state.Options.EnabledCategories())
	if err != nil {
		return fmt.Errorf("load inspect data: %w", err)
	}
	return nil
}

func (r *Runner) ApplyFixes(ctx context.Context, domain string, report *Report, opts Options, applier FixApplier) {
	if !opts.Fix || applier == nil {
		return
	}
	plans := CollectFixPlans(report.Findings)
	if len(plans) == 0 {
		return
	}
	fixRunner := NewFixRunner(applier)
	report.Fixes = fixRunner.Apply(ctx, domain, plans, opts.DryRun)
	if FixFailed(report.Fixes) {
		report.ExitCode = ExitFixFailed
	}
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
