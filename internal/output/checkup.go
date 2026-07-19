package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/vergecloud/cdn-cli/internal/checkup"
)

func (p *Printer) PrintCheckupReport(report checkup.Report) error {
	if p.JSON {
		return p.PrintJSON(report)
	}

	fmt.Fprintf(p.Out, "%s\n", titleStyle.Render("Domain checkup: "+report.Domain.Name))
	fmt.Fprintf(p.Out, "Domain ID: %s\n", report.Domain.ID)
	fmt.Fprintf(p.Out, "Type: %s\n", report.Domain.Type)
	fmt.Fprintf(p.Out, "Status: %s\n", report.Domain.Status)
	fmt.Fprintf(p.Out, "Path: %s\n", report.Options.Path)
	fmt.Fprintf(p.Out, "Started: %s\n\n", report.StartedAt.Format("2006-01-02 15:04:05"))

	for _, f := range report.Findings {
		p.printFinding(f)
	}

	fmt.Fprintln(p.Out)
	fmt.Fprintln(p.Out, titleStyle.Render("Summary"))
	fmt.Fprintf(p.Out, "  Passed:   %d\n", report.Summary.Passed)
	fmt.Fprintf(p.Out, "  Warnings: %d\n", report.Summary.Warnings)
	fmt.Fprintf(p.Out, "  Failed:   %d\n", report.Summary.Failed)
	fmt.Fprintf(p.Out, "  Skipped:  %d\n", report.Summary.Skipped)
	fmt.Fprintf(p.Out, "  Errors:   %d\n", report.Summary.Errors)
	fmt.Fprintf(p.Out, "  Duration: %s\n", time.Duration(report.Duration))

	if len(report.Fixes) > 0 {
		fmt.Fprintln(p.Out)
		fmt.Fprintln(p.Out, titleStyle.Render("Fixes"))
		for _, fix := range report.Fixes {
			line := fix.Message
			if fix.Error != "" {
				line = fix.Error
			}
			fmt.Fprintf(p.Out, "  %s: %s\n", fix.FixID, line)
		}
	}

	return nil
}

func (p *Printer) printFinding(f checkup.Finding) {
	statusLine := fmt.Sprintf("%-5s %s", strings.ToUpper(string(f.Status)), f.ID)
	switch f.Status {
	case checkup.StatusPass:
		fmt.Fprintf(p.Out, "%s\n", okStyle.Render(statusLine))
	case checkup.StatusWarn:
		fmt.Fprintf(p.Out, "%s\n", warnStyle.Render(statusLine))
	case checkup.StatusFail, checkup.StatusError:
		fmt.Fprintf(p.Out, "%s\n", errStyle.Render(statusLine))
	default:
		fmt.Fprintf(p.Out, "%s\n", mutedStyle.Render(statusLine))
	}

	for _, line := range strings.Split(f.Summary, "\n") {
		fmt.Fprintf(p.Out, "      %s\n", line)
	}
	if f.Details != "" {
		for _, line := range strings.Split(f.Details, "\n") {
			fmt.Fprintf(p.Out, "      %s\n", mutedStyle.Render(line))
		}
	}
	for _, cmd := range f.SuggestedCommands {
		fmt.Fprintf(p.Out, "\n      Suggested command:\n      %s\n", cmd)
	}
	fmt.Fprintln(p.Out)
}
