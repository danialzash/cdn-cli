package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

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

	table := p.newTable([]string{"ID", "NAME", "STATUS", "TYPE", "PLAN", "ORGANIZATION_ID", "CREATED"})
	for _, d := range domains {
		created := "-"
		if !d.CreatedAt.IsZero() {
			created = d.CreatedAt.Format("2006-01-02 15:04")
		}
		table.Append([]string{
			d.ID,
			d.Name,
			d.Status,
			d.Type,
			d.Plan,
			d.OrganizationID,
			created,
		})
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
	if d.Plan != "" {
		table.Append([]string{"Plan", d.Plan})
	}
	if d.OrganizationID != "" {
		table.Append([]string{"Organization ID", d.OrganizationID})
	}
	if !d.CreatedAt.IsZero() {
		table.Append([]string{"Created", d.CreatedAt.Format(time.RFC3339)})
	}
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

func (p *Printer) PrintFirewallRule(rule *client.FirewallRule) error {
	if p.JSON {
		return p.PrintJSON(rule)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Firewall Rule"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"ID", rule.ID})
	table.Append([]string{"Name", rule.Name})
	table.Append([]string{"Action", rule.Action})
	table.Append([]string{"Priority", fmt.Sprintf("%d", rule.Priority)})
	table.Append([]string{"Enabled", boolLabel(rule.Enabled)})
	table.Append([]string{"Filter", rule.FilterExpr})
	if rule.Note != "" {
		table.Append([]string{"Note", rule.Note})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintCacheSettings(settings *client.CacheSettings) error {
	if p.JSON {
		return p.PrintJSON(settings)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Cache Settings"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"Status", cacheStatusLabel(settings.Status)})
	table.Append([]string{"Max Age", emptyDash(settings.MaxAge)})
	table.Append([]string{"Developer Mode", boolLabel(settings.DeveloperMode)})
	table.Append([]string{"Max Size", formatCacheSize(settings.MaxSize)})
	table.Append([]string{"Consistent Uptime", boolLabel(settings.ConsistentUptime)})
	if settings.PageAny != "" {
		table.Append([]string{"Page Any", settings.PageAny})
	}
	if settings.Browser != "" {
		table.Append([]string{"Browser", settings.Browser})
	}
	table.Append([]string{"Scheme", boolLabel(settings.Scheme)})
	table.Append([]string{"Bypass on Cookie", boolLabel(settings.BypassOnCookie)})
	if settings.Cookie != "" {
		table.Append([]string{"Cookie", settings.Cookie})
	}
	table.Append([]string{"Query Args", boolLabel(settings.Args)})
	if settings.Arg != "" {
		table.Append([]string{"Query Arg", settings.Arg})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintAccelerationSettings(settings *client.AccelerationSettings) error {
	if p.JSON {
		return p.PrintJSON(settings)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Acceleration Settings"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"Status", emptyDash(settings.Status)})
	extensions := "-"
	if len(settings.Extensions) > 0 {
		extensions = strings.Join(settings.Extensions, ", ")
	}
	table.Append([]string{"Extensions", extensions})
	table.Render()
	return nil
}

func (p *Printer) PrintImageResizeSettings(settings *client.ImageResizeSettings) error {
	if p.JSON {
		return p.PrintJSON(settings)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Image Resize Settings"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"Status", emptyDash(settings.Status)})
	table.Append([]string{"Height By", emptyDash(settings.HeightBy)})
	table.Append([]string{"Width By", emptyDash(settings.WidthBy)})
	table.Append([]string{"Mode", emptyDash(settings.Mode)})
	table.Append([]string{"Mode By", emptyDash(settings.ModeBy)})
	table.Append([]string{"Quality By", emptyDash(settings.QualityBy)})
	table.Render()
	return nil
}

func (p *Printer) PrintSslSettings(settings *client.SslSettings) error {
	if p.JSON {
		return p.PrintJSON(settings)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("SSL Settings"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"SSL Enabled", boolLabel(settings.Enabled)})
	table.Append([]string{"Certificate Mode", emptyDash(settings.CertificateMode)})
	table.Append([]string{"TLS Version", emptyDash(settings.TLSVersion)})
	table.Append([]string{"Fingerprint", boolLabel(settings.FingerprintEnabled)})
	table.Append([]string{"HSTS", boolLabel(settings.HSTSEnabled)})
	if settings.HSTSMaxAge != "" {
		table.Append([]string{"HSTS Max Age", settings.HSTSMaxAge})
	}
	table.Append([]string{"HSTS Subdomain", boolLabel(settings.HSTSSubdomain)})
	table.Append([]string{"HSTS Preload", boolLabel(settings.HSTSPreload)})
	table.Append([]string{"HTTPS Redirect", boolLabel(settings.HTTPSRedirect)})
	table.Append([]string{"Replace HTTP", boolLabel(settings.ReplaceHTTP)})
	table.Append([]string{"QUIC", boolLabel(settings.QUICEnabled)})
	table.Append([]string{"Verify SNI", boolLabel(settings.VerifySNI)})
	if settings.CertificateKeyType != "" {
		table.Append([]string{"Certificate Key Type", settings.CertificateKeyType})
	}
	table.Render()

	if len(settings.Certificates) > 0 {
		fmt.Fprintln(p.Out)
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("Certificates (%d)", len(settings.Certificates))))
		_ = p.PrintCertificates(settings.Certificates)
	}

	if len(settings.Orders) > 0 {
		fmt.Fprintln(p.Out)
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("Recent Orders (%d)", len(settings.Orders))))
		_ = p.PrintCertificateOrders(settings.Orders)
	}

	return nil
}

func (p *Printer) PrintCertificates(certs []client.Certificate) error {
	if p.JSON {
		return p.PrintJSON(certs)
	}

	table := p.newTable([]string{"ID", "TYPE", "ACTIVE", "DOMAINS", "ISSUER", "EXPIRES"})
	for _, cert := range certs {
		table.Append([]string{
			cert.ID,
			cert.Type,
			boolLabel(cert.Active),
			truncate(strings.Join(cert.DomainNames, ", "), 40),
			truncate(emptyDash(cert.Issuer), 20),
			emptyDash(cert.ExpiryDate),
		})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintCertificateDetail(cert *client.CertificateDetail) error {
	if p.JSON {
		return p.PrintJSON(cert)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Certificate"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"ID", cert.ID})
	table.Append([]string{"Type", cert.Type})
	table.Append([]string{"Active", boolLabel(cert.Active)})
	if cert.KeyType != "" {
		table.Append([]string{"Key Type", cert.KeyType})
	}
	table.Append([]string{"Domains", strings.Join(cert.DomainNames, ", ")})
	table.Append([]string{"Issuer", emptyDash(cert.Issuer)})
	table.Append([]string{"Revoked", boolLabel(cert.IsRevoked)})
	table.Append([]string{"Expires", emptyDash(cert.ExpiryDate)})
	if cert.CreatedAt != "" {
		table.Append([]string{"Created", cert.CreatedAt})
	}
	if cert.UpdatedAt != "" {
		table.Append([]string{"Updated", cert.UpdatedAt})
	}
	if cert.CertificatePEM != "" {
		table.Append([]string{"Certificate", fmt.Sprintf("(%d chars, base64)", len(cert.CertificatePEM))})
	}
	if cert.PrivateKeyPEM != "" {
		table.Append([]string{"Private Key", fmt.Sprintf("(%d chars, base64)", len(cert.PrivateKeyPEM))})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintCertificateOrders(orders []client.CertificateOrder) error {
	if p.JSON {
		return p.PrintJSON(orders)
	}

	table := p.newTable([]string{"ID", "ORDER", "STATUS", "DOMAINS", "EXPIRES"})
	for _, order := range orders {
		table.Append([]string{
			order.ID,
			emptyDash(order.OrderID),
			order.Status,
			truncate(strings.Join(order.DomainNames, ", "), 40),
			emptyDash(order.ExpiryDate),
		})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintCertificateOrder(order *client.CertificateOrder) error {
	if p.JSON {
		return p.PrintJSON(order)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Certificate Order"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"ID", order.ID})
	table.Append([]string{"Order ID", emptyDash(order.OrderID)})
	table.Append([]string{"Status", order.Status})
	table.Append([]string{"Domains", strings.Join(order.DomainNames, ", ")})
	table.Append([]string{"Expires", emptyDash(order.ExpiryDate)})
	if order.CreatedAt != "" {
		table.Append([]string{"Created", order.CreatedAt})
	}
	if order.UpdatedAt != "" {
		table.Append([]string{"Updated", order.UpdatedAt})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintLists(lists []client.List) error {
	if p.JSON {
		return p.PrintJSON(lists)
	}

	table := p.newTable([]string{"ID", "NAME", "TYPE", "SCOPE", "ITEMS", "DESCRIPTION"})
	for _, list := range lists {
		table.Append([]string{
			list.ID,
			list.Name,
			list.Type,
			emptyDash(list.Scope),
			fmt.Sprintf("%d", len(list.Items)),
			truncate(emptyDash(list.Description), 40),
		})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintList(list *client.List) error {
	if p.JSON {
		return p.PrintJSON(list)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("List"))
	info := p.newTable([]string{"FIELD", "VALUE"})
	info.Append([]string{"ID", list.ID})
	info.Append([]string{"Name", list.Name})
	info.Append([]string{"Type", list.Type})
	info.Append([]string{"Scope", emptyDash(list.Scope)})
	if list.Namespace != "" {
		info.Append([]string{"Namespace", list.Namespace})
	}
	if list.Description != "" {
		info.Append([]string{"Description", list.Description})
	}
	if list.CreatedAt != "" {
		info.Append([]string{"Created", list.CreatedAt})
	}
	if list.UpdatedAt != "" {
		info.Append([]string{"Updated", list.UpdatedAt})
	}
	info.Render()

	if len(list.Items) == 0 {
		fmt.Fprintln(p.Out, mutedStyle.Render("No items in this list."))
		return nil
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Items"))
	items := p.newTable([]string{"ID", "VALUE", "DESCRIPTION", "CREATED"})
	for _, item := range list.Items {
		items.Append([]string{
			item.ID,
			truncate(item.Value, 50),
			truncate(emptyDash(item.Desc), 30),
			emptyDash(item.CreatedAt),
		})
	}
	items.Render()
	return nil
}

func (p *Printer) PrintPageRules(rules []client.PageRule) error {
	if p.JSON {
		return p.PrintJSON(rules)
	}

	table := p.newTable([]string{"ID", "SEQ", "URL", "ENABLED", "CACHE", "PROTECTED"})
	for _, rule := range rules {
		table.Append([]string{
			rule.ID,
			fmt.Sprintf("%d", rule.Seq),
			truncate(rule.URL, 50),
			boolLabel(rule.Enabled),
			rule.CacheLevel,
			boolLabel(rule.IsProtected),
		})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintPageRule(rule *client.PageRule) error {
	if p.JSON {
		if len(rule.Raw) > 0 {
			return p.PrintRawJSON(rule.Raw)
		}
		return p.PrintJSON(rule)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Page Rule"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"ID", rule.ID})
	table.Append([]string{"Seq", fmt.Sprintf("%d", rule.Seq)})
	table.Append([]string{"URL", rule.URL})
	table.Append([]string{"Enabled", boolLabel(rule.Enabled)})
	table.Append([]string{"Protected", boolLabel(rule.IsProtected)})
	if rule.CacheLevel != "" {
		table.Append([]string{"Cache Level", rule.CacheLevel})
	}
	if rule.CacheMaxAge != "" {
		table.Append([]string{"Cache Max Age", rule.CacheMaxAge})
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

func (p *Printer) PrintAuthStatus(authenticated bool, apiURL, authMethod string) error {
	if p.JSON {
		return p.PrintJSON(map[string]any{
			"authenticated": authenticated,
			"api_url":       apiURL,
			"auth_method":   authMethod,
		})
	}

	status := errStyle.Render("not authenticated")
	if authenticated {
		status = okStyle.Render("authenticated")
	}
	fmt.Fprintf(p.Out, "%s\n", titleStyle.Render("Auth Status"))
	fmt.Fprintf(p.Out, "  Status:  %s\n", status)
	fmt.Fprintf(p.Out, "  Method:  %s\n", authMethod)
	fmt.Fprintf(p.Out, "  API URL: %s\n", apiURL)
	return nil
}

func (p *Printer) PrintDNSRecords(records []client.DNSRecord) error {
	if p.JSON {
		return p.PrintJSON(records)
	}

	table := p.newTable([]string{"ID", "NAME", "TYPE", "TTL", "CLOUD", "VALUE", "PROTECTED"})
	for _, record := range records {
		cloud := "no"
		if record.Cloud {
			cloud = "yes"
		}
		protected := "no"
		if record.IsProtected {
			protected = "yes"
		}
		value := record.Value
		table.Append([]string{
			record.ID,
			record.Name,
			record.Type,
			fmt.Sprintf("%d", record.TTL),
			cloud,
			value,
			protected,
		})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintDNSRecord(record *client.DNSRecord) error {
	if p.JSON {
		return p.PrintJSON(record)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("DNS Record"))
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"ID", record.ID})
	table.Append([]string{"Name", record.Name})
	table.Append([]string{"Type", record.Type})
	table.Append([]string{"TTL", fmt.Sprintf("%d", record.TTL)})
	table.Append([]string{"Cloud", boolLabel(record.Cloud)})
	table.Append([]string{"Value", record.Value})
	table.Append([]string{"Protected", boolLabel(record.IsProtected)})
	if len(record.Usage) > 0 {
		table.Append([]string{"Usage", strings.Join(record.Usage, ", ")})
	}
	if record.CreatedAt != "" {
		table.Append([]string{"Created", record.CreatedAt})
	}
	if record.UpdatedAt != "" {
		table.Append([]string{"Updated", record.UpdatedAt})
	}
	table.Render()
	return nil
}

func (p *Printer) PrintDNSVerifyResults(results []client.DNSVerifyResult) error {
	if p.JSON {
		return p.PrintJSON(results)
	}

	okCount, issueCount := 0, 0
	for _, result := range results {
		switch result.Status {
		case "ok":
			okCount++
		case "skipped":
			// not counted as issue
		default:
			issueCount++
		}
	}

	fmt.Fprintln(p.Out, titleStyle.Render("DNS Verification"))
	fmt.Fprintf(p.Out, "%s %s  %s %s\n\n",
		okStyle.Render(fmt.Sprintf("%d ok", okCount)),
		mutedStyle.Render("·"),
		warnStyle.Render(fmt.Sprintf("%d issues", issueCount)),
		mutedStyle.Render("found"),
	)

	table := p.newTable([]string{"NAME", "TYPE", "STATUS", "EXPECTED", "ACTUAL", "DETAIL"})
	for _, result := range results {
		status := result.Status
		switch result.Status {
		case "ok":
			status = okStyle.Render("ok")
		case "skipped":
			status = mutedStyle.Render("skipped")
		case "mismatch", "not_found", "error":
			status = warnStyle.Render(result.Status)
		}

		expected := result.Expected
		actual := result.Actual
		if len(expected) > 50 {
			expected = expected[:47] + "..."
		}
		if len(actual) > 50 {
			actual = actual[:47] + "..."
		}

		table.Append([]string{
			result.Name,
			result.Type,
			status,
			expected,
			actual,
			result.Detail,
		})
	}
	table.Render()
	return nil
}

func boolLabel(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func enabledLabel(value bool) string {
	if value {
		return okStyle.Render("enabled")
	}
	return mutedStyle.Render("disabled")
}

func (p *Printer) PrintDomainInspect(result *client.DomainInspect) error {
	if p.JSON {
		return p.PrintJSON(result)
	}

	d := result.Domain
	fmt.Fprintln(p.Out, titleStyle.Render("Domain Overview"))
	fmt.Fprintf(p.Out, "%s %s\n\n", mutedStyle.Render("Domain:"), d.Name)

	// Domain summary
	table := p.newTable([]string{"FIELD", "VALUE"})
	table.Append([]string{"ID", d.ID})
	table.Append([]string{"Status", d.Status})
	table.Append([]string{"Type", d.Type})
	if d.Plan != "" {
		table.Append([]string{"Plan", d.Plan})
	}
	if d.OrganizationID != "" {
		table.Append([]string{"Organization ID", d.OrganizationID})
	}
	if !d.CreatedAt.IsZero() {
		table.Append([]string{"Created", d.CreatedAt.Format(time.RFC3339)})
	}
	if d.UpdatedAt != "" {
		table.Append([]string{"Updated", d.UpdatedAt})
	}
	table.Append([]string{"DNS Cloud", boolLabel(d.DNSCloud)})
	if len(d.NSKeys) > 0 {
		table.Append([]string{"NS Keys", strings.Join(d.NSKeys, ", ")})
	}
	if len(d.CurrentNS) > 0 {
		table.Append([]string{"Current NS", strings.Join(d.CurrentNS, ", ")})
	}
	if d.CnameTarget != "" {
		table.Append([]string{"CNAME Target", d.CnameTarget})
	}
	if len(d.Restrictions) > 0 {
		table.Append([]string{"Restrictions", strings.Join(d.Restrictions, ", ")})
	}
	table.Render()
	fmt.Fprintln(p.Out)

	// Service status summary
	fmt.Fprintln(p.Out, titleStyle.Render("Services"))
	svc := p.newTable([]string{"SERVICE", "STATUS", "DETAILS"})
	svc.Append([]string{"Firewall", enabledLabel(result.Firewall.Enabled), fmt.Sprintf("%d rules · default %s", result.Firewall.RuleCount, emptyDash(result.Firewall.DefaultAction))})
	svc.Append([]string{"WAF", enabledLabel(result.WAF.Enabled), fmt.Sprintf("mode %s · %d packages", emptyDash(result.WAF.Mode), result.WAF.PackageCount)})
	svc.Append([]string{"DDoS", enabledLabel(result.DDoS.Enabled), fmt.Sprintf("%s · %d rules", emptyDash(result.DDoS.ProtectionMode), result.DDoS.RuleCount)})
	svc.Append([]string{"SSL", enabledLabel(result.SSL.Enabled), fmt.Sprintf("%s · %d certs · TLS %s", emptyDash(result.SSL.CertificateMode), result.SSL.CertificateCount, emptyDash(result.SSL.TLSVersion))})
	svc.Append([]string{"Caching", cacheStatusLabel(result.Cache.Status), fmt.Sprintf("max-age %s · dev mode %s", emptyDash(result.Cache.MaxAge), boolLabel(result.Cache.DeveloperMode))})
	svc.Append([]string{"Load Balancing", loadBalancingLabel(result.LoadBalancing.Count), fmt.Sprintf("%d balancers · protocol %s", result.LoadBalancing.Count, emptyDash(result.LoadBalancing.Protocol))})
	svc.Append([]string{"Rate Limit", fmt.Sprintf("%d rules", result.RateLimit.RuleCount), fmt.Sprintf("ddos detection %s", boolLabel(result.RateLimit.DdosDetection))})
	svc.Append([]string{"Page Rules", fmt.Sprintf("%d rules", result.PageRules.Count), ""})
	if result.Acceleration != nil {
		svc.Append([]string{"Acceleration", emptyDash(result.Acceleration.Status), strings.Join(result.Acceleration.Extensions, ", ")})
	}
	if result.SmartCheck != nil {
		svc.Append([]string{"Smart Check", fmt.Sprintf("%d safe / %d issues", result.SmartCheck.SafeCount, result.SmartCheck.IssueCount), result.SmartCheck.CreatedAt})
	}
	svc.Append([]string{"DNS Records", fmt.Sprintf("%d records", result.DNS.Count), ""})
	svc.Render()
	fmt.Fprintln(p.Out)

	if len(result.Firewall.Rules) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("Firewall Rules (%d)", result.Firewall.RuleCount)))
		_ = p.PrintFirewallRules(result.Firewall.Rules)
		fmt.Fprintln(p.Out)
	}

	if len(result.WAF.Packages) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("WAF Packages (%d)", result.WAF.PackageCount)))
		_ = p.PrintWafPackages(result.WAF.Packages)
		fmt.Fprintln(p.Out)
	}

	if len(result.DDoS.Rules) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("DDoS Rules (%d)", result.DDoS.RuleCount)))
		table := p.newTable([]string{"URL", "ACTION", "ENABLED"})
		for _, rule := range result.DDoS.Rules {
			table.Append([]string{truncate(rule.URLPattern, 50), rule.Action, boolLabel(rule.Enabled)})
		}
		table.Render()
		fmt.Fprintln(p.Out)
	}

	if len(result.PageRules.Rules) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("Page Rules (%d)", result.PageRules.Count)))
		table := p.newTable([]string{"ID", "SEQ", "URL", "ENABLED", "CACHE"})
		for _, rule := range result.PageRules.Rules {
			table.Append([]string{rule.ID, fmt.Sprintf("%d", rule.Seq), truncate(rule.URL, 50), boolLabel(rule.Enabled), rule.CacheLevel})
		}
		table.Render()
		fmt.Fprintln(p.Out)
	}

	if len(result.SSL.Certificates) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("SSL Certificates (%d)", result.SSL.CertificateCount)))
		table := p.newTable([]string{"TYPE", "ACTIVE", "DOMAINS", "EXPIRES"})
		for _, cert := range result.SSL.Certificates {
			domains := strings.Join(cert.DomainNames, ", ")
			table.Append([]string{cert.Type, boolLabel(cert.Active), truncate(domains, 40), cert.ExpiryDate})
		}
		table.Render()
		fmt.Fprintln(p.Out)
	}

	if len(result.LoadBalancing.Balancers) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("Load Balancers (%d)", result.LoadBalancing.Count)))
		table := p.newTable([]string{"NAME", "METHOD", "ENABLED", "POOLS"})
		for _, lb := range result.LoadBalancing.Balancers {
			table.Append([]string{lb.Name, lb.Method, boolLabel(lb.Enabled), fmt.Sprintf("%d", lb.PoolCount)})
		}
		table.Render()
		fmt.Fprintln(p.Out)
	}

	if len(result.RateLimit.Rules) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("Rate Limit Rules (%d)", result.RateLimit.RuleCount)))
		table := p.newTable([]string{"URL", "ACTION", "RATE", "ENABLED"})
		for _, rule := range result.RateLimit.Rules {
			table.Append([]string{truncate(rule.URLPattern, 50), rule.Action, fmt.Sprintf("%d", rule.Rate), boolLabel(rule.Enabled)})
		}
		table.Render()
		fmt.Fprintln(p.Out)
	}

	if len(result.DNS.Records) > 0 {
		fmt.Fprintln(p.Out, titleStyle.Render(fmt.Sprintf("DNS Records (%d)", result.DNS.Count)))
		_ = p.PrintDNSRecords(result.DNS.Records)
		fmt.Fprintln(p.Out)
	}

	if result.SmartCheck != nil && len(result.SmartCheck.Items) > 0 {
		_ = p.PrintSmartCheck(result.SmartCheck)
		fmt.Fprintln(p.Out)
	}

	if len(result.Errors) > 0 {
		fmt.Fprintln(p.Out, warnStyle.Render(fmt.Sprintf("Partial errors (%d sections failed):", len(result.Errors))))
		for _, item := range result.Errors {
			fmt.Fprintf(p.Out, "  %s: %s\n", item.Section, item.Error)
		}
	}

	return nil
}

func emptyDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max-3] + "..."
}

func cacheStatusLabel(status string) string {
	if status == "" || status == "off" {
		return mutedStyle.Render("off")
	}
	return okStyle.Render(status)
}

func formatCacheSize(bytes int64) string {
	if bytes <= 0 {
		return "-"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func loadBalancingLabel(count int) string {
	if count == 0 {
		return mutedStyle.Render("none")
	}
	return okStyle.Render(fmt.Sprintf("%d active", count))
}

func (p *Printer) PrintMessage(msg string) {
	if p.JSON {
		_ = p.PrintJSON(map[string]string{"message": msg})
		return
	}
	fmt.Fprintln(p.Out, msg)
}

func (p *Printer) Confirm(prompt string) (bool, error) {
	if p.JSON {
		return false, fmt.Errorf("confirmation required; re-run with --force")
	}

	in := os.Stdin
	if p.Out != os.Stdout && p.Out != os.Stderr {
		in = os.Stdin
	}

	fmt.Fprintf(p.Out, "%s [y/N] ", prompt)
	reader := bufio.NewReader(in)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
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
