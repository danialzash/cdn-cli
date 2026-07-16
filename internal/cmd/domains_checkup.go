package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func newDomainsCheckupCmd() *cobra.Command {
	var (
		only         []string
		skip         []string
		path         string
		origin       string
		originPort   int
		originScheme string
		timeout      time.Duration
		probeTimeout time.Duration
		resolvers    []string
		strict       bool
		fix          bool
		yes          bool
		dryRun       bool
	)

	cmd := &cobra.Command{
		Use:     "checkup <domain>",
		Aliases: []string{"doctor", "diagnose"},
		Short:   "Diagnose domain configuration, DNS, TLS, CDN, cache, and origin health",
		Long: `Inspect a VergeCloud domain from multiple perspectives, explain detected
problems, suggest concrete solutions, and optionally apply safe fixes.

Combine VergeCloud configuration with live DNS, HTTP, TLS, cache, CDN, and optional
origin tests. Read-only by default; pass --fix to review and apply safe fixes.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			onlyCats, err := checkup.ParseCategories(only)
			exitOnError(err)
			skipCats, err := checkup.ParseCategories(skip)
			exitOnError(err)

			opts := checkup.DefaultOptions()
			opts.Only = onlyCats
			opts.Skip = skipCats
			opts.Path = checkup.NormalizePath(path)
			opts.Origin = strings.TrimSpace(origin)
			opts.OriginPort = originPort
			opts.OriginScheme = originScheme
			opts.Timeout = checkup.DurationJSON(timeout)
			opts.ProbeTimeout = checkup.DurationJSON(probeTimeout)
			opts.Resolvers = resolvers
			opts.Strict = strict
			opts.Fix = fix
			opts.Yes = yes
			opts.DryRun = dryRun

			if err := opts.Validate(); err != nil {
				exitOnError(err)
			}
			if jsonOutput && fix && !yes && !dryRun {
				exitOnError(fmt.Errorf("--json with --fix requires --yes or --dry-run"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			apiClient, err := newAPIClient(cfg)
			exitOnError(err)

			domainArg := args[0]
			source := checkup.NewClientSource(apiClient)
			runner, err := checkup.NewRunner(source)
			exitOnError(err)

			exitCode, err := withCheckupContext(opts.TimeoutDuration(), func(ctx context.Context) (int, error) {
				result := runner.Run(ctx, domainArg, opts)
				if result.Err != nil {
					return checkup.ExitError, result.Err
				}

				applier := checkup.NewClientFixApplier(apiClient)
				if opts.Fix {
					plans := checkup.CollectFixPlans(result.Report.Findings)
					if len(plans) > 0 {
						if !jsonOutput {
							printer().PrintCheckupFixPlans(plans)
						}
						shouldApply := opts.DryRun || opts.Yes
						if !shouldApply && !jsonOutput {
							ok, err := printer().Confirm("Apply safe fixes?")
							if err != nil {
								return checkup.ExitError, err
							}
							if !ok {
								printer().PrintMessage("Fixes not applied.")
							}
							shouldApply = ok
						}
						if shouldApply {
							runner.ApplyFixes(ctx, domainArg, &result.Report, opts, applier, applier)
						}
					}
				}

				if jsonOutput {
					if err := printer().PrintJSON(result.Report); err != nil {
						return checkup.ExitError, err
					}
				} else {
					if err := printer().PrintCheckupReport(result.Report); err != nil {
						return checkup.ExitError, err
					}
				}

				return result.Report.ExitCode, nil
			})
			finishCheckup(exitCode, err)
		},
	}

	cmd.Flags().StringSliceVar(&only, "only", nil, "Run only selected categories")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "Skip selected categories")
	cmd.Flags().StringVar(&path, "path", checkup.DefaultPath, "HTTP path to test")
	cmd.Flags().StringVar(&origin, "origin", "", "Origin IP or hostname for direct-origin comparison")
	cmd.Flags().IntVar(&originPort, "origin-port", 0, "Explicit origin port")
	cmd.Flags().StringVar(&originScheme, "origin-scheme", "auto", "Origin scheme: auto, http, https")
	cmd.Flags().DurationVar(&timeout, "timeout", checkup.DefaultTimeout, "Overall command timeout")
	cmd.Flags().DurationVar(&probeTimeout, "probe-timeout", checkup.DefaultProbeTimeout, "Per-probe timeout")
	cmd.Flags().StringSliceVar(&resolvers, "resolver", nil, "Custom DNS resolver addresses")
	cmd.Flags().BoolVar(&strict, "strict", false, "Treat warnings as failures")
	cmd.Flags().BoolVar(&fix, "fix", false, "Show and apply safe fixes")
	cmd.Flags().BoolVar(&yes, "yes", false, "Apply fixes without confirmation")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show fixes without applying")

	return cmd
}
