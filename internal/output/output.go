package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
	"github.com/vergecloud/cdn-cli/internal/client"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

type Printer struct {
	JSON bool
	Out  *os.File
}

func New(json bool) *Printer {
	return &Printer{JSON: json, Out: os.Stdout}
}

func (p *Printer) PrintJSON(v any) error {
	enc := json.NewEncoder(p.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (p *Printer) PrintRawJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		_, err = fmt.Fprintln(p.Out, string(data))
		return err
	}
	return p.PrintJSON(v)
}

func (p *Printer) PrintDomains(domains []client.Domain) error {
	if p.JSON {
		return p.PrintJSON(domains)
	}

	table := p.newTable([]string{"ID", "NAME", "STATUS", "TYPE"})
	for _, d := range domains {
		table.Append([]string{d.ID, d.Name, d.Status, d.Type})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintDomain(d *client.Domain) error {
	if p.JSON {
		return p.PrintJSON(d)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Domain"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"ID", d.ID})
	table.Append([]string{"Name", d.Name})
	table.Append([]string{"Status", d.Status})
	table.Append([]string{"Type", d.Type})
	if len(d.NSKeys) > 0 {
		table.Append([]string{"NS Keys", strings.Join(d.NSKeys, ", ")})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintFirewallRules(rules []client.FirewallRule) error {
	if p.JSON {
		return p.PrintJSON(rules)
	}

	table := p.newTable([]string{"PRIORITY", "NAME", "ACTION", "ENABLED", "FILTER"})
	for _, r := range rules {
		enabled := "no"
		if r.Enabled {
			enabled = "yes"
		}
		filter := r.FilterExpr
		if len(filter) > 60 {
			filter = filter[:57] + "..."
		}
		table.Append([]string{
			fmt.Sprintf("%d", r.Priority),
			r.Name,
			r.Action,
			enabled,
			filter,
		})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintWafPackages(packages []client.WafPackage) error {
	if p.JSON {
		return p.PrintJSON(packages)
	}

	table := p.newTable([]string{"ID", "NAME", "MODE", "STATUS"})
	for _, pkg := range packages {
		table.Append([]string{pkg.ID, pkg.Name, pkg.Mode, pkg.Status})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintSmartCheck(check *client.SmartCheck) error {
	if p.JSON {
		return p.PrintJSON(check)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Smart Check"))
	fmt.Fprintf(p.Out, "%s %s\n", mutedStyle.Render("Run ID:"), check.ID)
	if check.CreatedAt != "" {
		fmt.Fprintf(p.Out, "%s %s\n", mutedStyle.Render("Created:"), check.CreatedAt)
	}
	fmt.Fprintf(p.Out, "%s %s  %s %s\n\n",
		okStyle.Render(fmt.Sprintf("%d safe", check.SafeCount)),
		mutedStyle.Render("·"),
		warnStyle.Render(fmt.Sprintf("%d issues", check.IssueCount)),
		mutedStyle.Render("found"),
	)

	table := p.newTable([]string{"CHECK", "STATUS", "DETAILS"})
	for _, item := range check.Items {
		status := item.Status
		switch item.Status {
		case "safe":
			status = okStyle.Render("safe")
		case "troubled":
			status = warnStyle.Render("troubled")
		default:
			status = errStyle.Render(item.Status)
		}
		table.Append([]string{item.ID, status, item.Details})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintAuthStatus(authenticated bool, apiURL string) error {
	if p.JSON {
		return p.PrintJSON(map[string]any{
			"authenticated": authenticated,
			"api_url":       apiURL,
		})
	}

	status := errStyle.Render("not authenticated")
	if authenticated {
		status = okStyle.Render("authenticated")
	}
	fmt.Fprintf(p.Out, "%s\n", titleStyle.Render("Auth Status"))
	fmt.Fprintf(p.Out, "  Status:  %s\n", status)
	fmt.Fprintf(p.Out, "  API URL: %s\n", apiURL)
	return nil
}

func (p *Printer) PrintMessage(msg string) {
	if p.JSON {
		_ = p.PrintJSON(map[string]string{"message": msg})
		return
	}
	fmt.Fprintln(p.Out, msg)
}

func (p *Printer) newTable(headers []string) *tablewriter.Table {
	table := tablewriter.NewWriter(p.Out)
	table.SetHeader(headers)
	table.SetBorder(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("  ")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetTablePadding("\t")
	table.SetNoWhiteSpace(true)
	return table
}
