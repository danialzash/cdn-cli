package output

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

type chartPoint struct {
	Label string
	Value float64
}

func (p *Printer) PrintReport(reportType string, data json.RawMessage) error {
	if p.JSON {
		return p.PrintRawJSON(data)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		_, err = fmt.Fprintln(p.Out, string(data))
		return err
	}

	fmt.Fprintln(p.Out, titleStyle.Render(reportTitle(reportType)))

	switch reportType {
	case "traffic-saved", "request-summary", "traffic-summary":
		return p.printSavedSummaryReport(reportType, payload)
	case "traffic", "visitors", "response-time", "transport-layer-proxy":
		return p.printStatisticsAndCharts(payload)
	case "status":
		return p.printStatusReport(payload)
	case "status-summary", "errors-chart":
		return p.printBreakdownCharts(payload)
	case "traffic-geo", "dns-geo", "attacks-geo":
		return p.printGeoReport(payload)
	case "high-request-ips", "errors", "attacks-detail", "attacks-attackers", "attacks-uri", "aggregated-details":
		return p.printReportTable(payload)
	case "attacks", "dns-requests", "error-details", "aggregated-charts", "aggregated-filters":
		return p.printGenericReport(payload)
	default:
		return p.printGenericReport(payload)
	}
}

func (p *Printer) PrintReportTypes(types []string) error {
	if p.JSON {
		return p.PrintJSON(types)
	}

	fmt.Fprintln(p.Out, titleStyle.Render("Available Report Types"))
	table := p.newTable([]string{"TYPE", "DESCRIPTION"})
	descriptions := map[string]string{
		"traffic":               "Total traffic and request time-series",
		"traffic-saved":         "Cache hit/miss/bypass breakdown",
		"request-summary":       "Request saved/missed/bypassed summary",
		"traffic-summary":       "Traffic saved/missed/bypassed summary",
		"traffic-geo":           "Traffic by country geo-map",
		"visitors":              "Unique visitors over time",
		"high-request-ips":      "IPs with highest request counts",
		"response-time":         "Average response time over time",
		"status":                "HTTP status code time-series",
		"status-summary":        "HTTP status code summary chart",
		"errors":                "Error log list",
		"errors-chart":          "Error log chart",
		"error-details":         "Details for a specific error message",
		"dns-requests":          "DNS request report",
		"dns-geo":               "DNS requests by geography",
		"attacks":               "Attack overview",
		"attacks-detail":        "Detailed attack events",
		"attacks-attackers":     "Attacker IP list",
		"attacks-geo":           "Attack geo-map",
		"attacks-uri":           "URLs under attack",
		"transport-layer-proxy": "Transport layer proxy traffic (requires proxy ID)",
		"domains-download":      "Download domains CSV report",
		"aggregated-details":    "Aggregated report details across domains",
		"aggregated-charts":     "Aggregated report charts across domains",
		"aggregated-filters":    "Aggregated report filter options",
	}
	for _, t := range types {
		table.Append([]string{t, descriptions[t]})
	}
	table.Render()
	return nil
}

func reportTitle(reportType string) string {
	switch reportType {
	case "request-summary":
		return "REQUEST SUMMARY"
	case "traffic-summary":
		return "TRAFFIC SUMMARY"
	default:
		return strings.ToUpper(strings.ReplaceAll(reportType, "-", " ")) + " REPORT"
	}
}

func (p *Printer) printSavedSummaryReport(reportType string, payload map[string]any) error {
	data, _ := payload["data"].(map[string]any)
	if data == nil {
		return p.printGenericReport(payload)
	}

	sections := []struct {
		key   string
		title string
		bytes bool
	}{
		{"request", "Request Summary", false},
		{"traffic", "Traffic Summary", true},
	}

	source, _ := data["statistics"].(map[string]any)
	if source == nil {
		source, _ = data["charts"].(map[string]any)
	}
	if source == nil {
		return p.printGenericReport(payload)
	}

	showAll := reportType == "traffic-saved"
	for _, section := range sections {
		if !showAll {
			if reportType == "request-summary" && section.key != "request" {
				continue
			}
			if reportType == "traffic-summary" && section.key != "traffic" {
				continue
			}
		}

		raw, ok := source[section.key]
		if !ok {
			continue
		}
		breakdown, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		if showAll {
			fmt.Fprintln(p.Out, titleStyle.Render(section.title))
		}
		p.printBreakdownSummary(breakdown, section.bytes)
		fmt.Fprintln(p.Out)
	}

	return nil
}

func (p *Printer) printBreakdownSummary(breakdown map[string]any, bytes bool) {
	total := toFloat(breakdown["total"])
	rows := []struct {
		label string
		key   string
	}{
		{"Saved", "saved"},
		{"Missed", "miss"},
		{"Bypassed", "bypass"},
	}

	table := p.newTable([]string{"METRIC", "VALUE", "PERCENT", "SHARE"})
	for _, row := range rows {
		value := toFloat(breakdown[row.key])
		pct := breakdownPercent(value, total)
		table.Append([]string{
			row.label,
			formatBreakdownValue(value, bytes),
			fmt.Sprintf("%.1f%%", pct),
			renderPercentBar(pct, 24),
		})
	}
	table.Append([]string{
		"Total",
		formatBreakdownValue(total, bytes),
		"100.0%",
		"",
	})
	table.Render()
}

func breakdownPercent(value, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return value / total * 100
}

func formatBreakdownValue(v float64, bytes bool) string {
	if bytes {
		return formatCacheSize(int64(v))
	}
	return formatNumber(v)
}

func renderPercentBar(pct float64, width int) string {
	if pct <= 0 {
		return mutedStyle.Render("—")
	}
	barLen := int(math.Round(pct / 100 * float64(width)))
	if barLen == 0 {
		barLen = 1
	}
	if barLen > width {
		barLen = width
	}
	return okStyle.Render(strings.Repeat("█", barLen))
}

func (p *Printer) printStatisticsAndCharts(payload map[string]any) error {
	data, _ := payload["data"].(map[string]any)
	if data == nil {
		return p.printGenericReport(payload)
	}

	if stats, ok := data["statistics"].(map[string]any); ok {
		fmt.Fprintln(p.Out, mutedStyle.Render("Statistics"))
		p.printStatBlocks(stats)
		fmt.Fprintln(p.Out)
	}

	if charts, ok := data["charts"].(map[string]any); ok {
		for name, raw := range charts {
			series := extractPointSeries(raw)
			if len(series) == 0 {
				continue
			}
			fmt.Fprintln(p.Out, titleStyle.Render(strings.ToUpper(strings.ReplaceAll(name, "_", " "))))
			fmt.Fprintln(p.Out, renderSparkline(series, 48))
			fmt.Fprintln(p.Out, renderSeriesSummary(series))
			fmt.Fprintln(p.Out)
		}
	}

	return nil
}

func (p *Printer) printStatusReport(payload map[string]any) error {
	data, _ := payload["data"].(map[string]any)
	if data == nil {
		return p.printGenericReport(payload)
	}

	if stats, ok := data["statistics"].(map[string]any); ok {
		points := statusCodePointsFromStats(stats)
		if len(points) > 0 {
			fmt.Fprintln(p.Out, titleStyle.Render("Status Code Summary"))
			fmt.Fprintln(p.Out, renderBarChart(points, 36))
			fmt.Fprintln(p.Out)
		}
	}

	if charts, ok := data["charts"].(map[string]any); ok {
		raw, ok := charts["status_code"]
		if !ok || !isStatusCodeTimeSeries(raw) {
			return nil
		}

		fmt.Fprintln(p.Out, titleStyle.Render("Status Code Over Time"))
		for _, key := range []string{"2xx", "3xx", "4xx", "5xx"} {
			series := extractStatusClassSeries(raw, key)
			if len(series) == 0 || seriesMax(series) == 0 {
				continue
			}
			fmt.Fprintln(p.Out, mutedStyle.Render(key))
			fmt.Fprintln(p.Out, renderSparkline(series, 48))
			fmt.Fprintln(p.Out, renderSeriesSummary(series))
			fmt.Fprintln(p.Out)
		}
	}

	return nil
}

func statusCodePointsFromStats(stats map[string]any) []chartPoint {
	codes, ok := stats["status_codes"].(map[string]any)
	if !ok {
		return nil
	}

	points := make([]chartPoint, 0, 4)
	for _, key := range []string{"2xx", "3xx", "4xx", "5xx"} {
		value := toFloat(codes[key+"_sum"])
		if value > 0 {
			points = append(points, chartPoint{Label: key, Value: value})
		}
	}
	return points
}

func isStatusCodeTimeSeries(raw any) bool {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return false
	}
	row, ok := items[0].(map[string]any)
	if !ok {
		return false
	}
	_, hasDate := row["date"]
	_, has2xx := row["2xx"]
	return hasDate && has2xx
}

func extractStatusClassSeries(raw any, class string) []float64 {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]float64, 0, len(items))
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, toFloat(row[class]))
	}
	return out
}

func seriesMax(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

func (p *Printer) printBreakdownCharts(payload map[string]any) error {
	data, _ := payload["data"].(map[string]any)
	if data == nil {
		return p.printGenericReport(payload)
	}

	if stats, ok := data["statistics"].(map[string]any); ok {
		fmt.Fprintln(p.Out, mutedStyle.Render("Statistics"))
		p.printNestedStats(stats, "")
		fmt.Fprintln(p.Out)
	}

	if charts, ok := data["charts"].(map[string]any); ok {
		for name, raw := range charts {
			var points []chartPoint
			if isStatusCodeTimeSeries(raw) {
				points = extractStatusSeriesTotals(raw)
			} else {
				points = extractNamedValues(raw)
				if len(points) == 0 {
					points = extractStatusSeriesTotals(raw)
				}
			}
			if len(points) == 0 {
				continue
			}
			fmt.Fprintln(p.Out, titleStyle.Render(strings.ToUpper(strings.ReplaceAll(name, "_", " "))))
			fmt.Fprintln(p.Out, renderBarChart(points, 36))
			fmt.Fprintln(p.Out)
		}
	}

	return nil
}

func (p *Printer) printGeoReport(payload map[string]any) error {
	data, _ := payload["data"].(map[string]any)
	if data == nil {
		return p.printGenericReport(payload)
	}

	if lists, ok := data["lists"].([]any); ok && len(lists) > 0 {
		table := p.newTable([]string{"COUNTRY", "CODE", "REQUESTS", "TRAFFIC"})
		for _, item := range lists {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			table.Append([]string{
				fmt.Sprintf("%v", row["country"]),
				fmt.Sprintf("%v", row["code"]),
				formatNumber(toFloat(row["requests"])),
				formatCacheSize(int64(toFloat(row["traffics"]))),
			})
		}
		table.Render()
		fmt.Fprintln(p.Out)
	}

	if charts, ok := data["charts"].(map[string]any); ok {
		for name, raw := range charts {
			points := extractGeoValues(raw)
			if len(points) == 0 {
				continue
			}
			sort.Slice(points, func(i, j int) bool { return points[i].Value > points[j].Value })
			if len(points) > 10 {
				points = points[:10]
			}
			fmt.Fprintln(p.Out, titleStyle.Render("Top Countries — "+strings.ToUpper(name)))
			labels := make([]chartPoint, len(points))
			for i, pt := range points {
				labels[i] = chartPoint{Label: pt.Label, Value: pt.Value}
			}
			fmt.Fprintln(p.Out, renderBarChart(labels, 32))
			fmt.Fprintln(p.Out)
		}
	}

	return nil
}

func (p *Printer) printReportTable(payload map[string]any) error {
	rows, headers := extractTableRows(payload)
	if len(rows) == 0 {
		return p.printGenericReport(payload)
	}

	table := p.newTable(headers)
	for _, row := range rows {
		table.Append(row)
	}
	table.Render()
	return nil
}

func (p *Printer) printGenericReport(payload map[string]any) error {
	data := payload["data"]
	if data == nil {
		return p.PrintJSON(payload)
	}

	switch typed := data.(type) {
	case map[string]any:
		table := p.newTable([]string{"FIELD", "VALUE"})
		keys := sortedKeys(typed)
		for _, key := range keys {
			table.Append([]string{key, formatAny(typed[key])})
		}
		table.Render()
	default:
		return p.PrintJSON(payload)
	}
	return nil
}

func (p *Printer) printStatBlocks(stats map[string]any) {
	for section, raw := range stats {
		block, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintln(p.Out, mutedStyle.Render(strings.ToUpper(section)))
		table := p.newTable([]string{"METRIC", "VALUE"})
		for _, key := range sortedKeys(block) {
			value := block[key]
			label := strings.ReplaceAll(key, "_", " ")
			switch key {
			case "total", "saved", "bypass", "miss", "bytes_in", "bytes_out", "connections":
				if strings.Contains(key, "bytes") {
					table.Append([]string{label, formatCacheSize(int64(toFloat(value)))})
				} else {
					table.Append([]string{label, formatNumber(toFloat(value))})
				}
			default:
				table.Append([]string{label, formatAny(value)})
			}
		}
		table.Render()
		fmt.Fprintln(p.Out)
	}
}

func (p *Printer) printNestedStats(stats map[string]any, prefix string) {
	table := p.newTable([]string{"METRIC", "VALUE"})
	rows := 0
	for _, key := range sortedKeys(stats) {
		value := stats[key]
		label := prefix + strings.ReplaceAll(key, "_", " ")
		switch typed := value.(type) {
		case map[string]any:
			p.printNestedStats(typed, label+" ")
		default:
			table.Append([]string{label, formatNumber(toFloat(value))})
			rows++
		}
	}
	if rows > 0 {
		table.Render()
	}
}

func extractPointSeries(raw any) []float64 {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]float64, 0, len(items))
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if total, ok := row["total"]; ok {
			out = append(out, toFloat(total))
			continue
		}
		for _, key := range []string{"2xx", "3xx", "4xx", "5xx", "count", "y"} {
			if v, ok := row[key]; ok {
				out = append(out, toFloat(v))
				break
			}
		}
	}
	return out
}

func extractNamedValues(raw any) []chartPoint {
	switch typed := raw.(type) {
	case []any:
		out := make([]chartPoint, 0, len(typed))
		for _, item := range typed {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			valueKey, value := firstNamedValue(row)
			if valueKey == "" {
				continue
			}
			name := fmt.Sprintf("%v", firstOf(row, "name", "label"))
			if name == "" {
				name = valueKey
			}
			out = append(out, chartPoint{Label: name, Value: value})
		}
		return out
	case map[string]any:
		out := make([]chartPoint, 0, len(typed))
		for key, item := range typed {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			label := fmt.Sprintf("%v", firstOf(row, "name", key))
			out = append(out, chartPoint{Label: label, Value: toFloat(firstOf(row, "value", "count", "y"))})
		}
		return out
	default:
		return nil
	}
}

func extractStatusSeriesTotals(raw any) []chartPoint {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	totals := map[string]float64{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"2xx", "3xx", "4xx", "5xx"} {
			totals[key] += toFloat(row[key])
		}
	}
	out := make([]chartPoint, 0, 4)
	for _, key := range []string{"2xx", "3xx", "4xx", "5xx"} {
		if totals[key] > 0 {
			out = append(out, chartPoint{Label: key, Value: totals[key]})
		}
	}
	return out
}

func extractGeoValues(raw any) []chartPoint {
	countries, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make([]chartPoint, 0, len(countries))
	for code, item := range countries {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		label := fmt.Sprintf("%v", firstOf(row, "name", code))
		out = append(out, chartPoint{Label: label, Value: toFloat(row["value"])})
	}
	return out
}

func extractTableRows(payload map[string]any) ([][]string, []string) {
	data := payload["data"]
	switch typed := data.(type) {
	case []any:
		if len(typed) == 0 {
			return nil, nil
		}
		first, ok := typed[0].(map[string]any)
		if !ok {
			return nil, nil
		}
		keys := sortedKeys(first)
		headers := make([]string, 0, len(keys))
		for _, key := range keys {
			headers = append(headers, strings.ToUpper(strings.ReplaceAll(key, "_", " ")))
		}
		rows := make([][]string, 0, len(typed))
		for _, item := range typed {
			row, ok := item.(map[string]any)
			if !ok {
				continue
			}
			line := make([]string, len(keys))
			for i, key := range keys {
				line[i] = truncate(formatAny(row[key]), 60)
			}
			rows = append(rows, line)
		}
		return rows, headers
	default:
		return nil, nil
	}
}

func renderSparkline(values []float64, width int) string {
	if len(values) == 0 {
		return mutedStyle.Render("no chart data")
	}
	if len(values) > width {
		step := float64(len(values)) / float64(width)
		compressed := make([]float64, width)
		for i := 0; i < width; i++ {
			idx := int(math.Round(float64(i) * step))
			if idx >= len(values) {
				idx = len(values) - 1
			}
			compressed[i] = values[idx]
		}
		values = compressed
	}

	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	blocks := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, v := range values {
		level := 0
		if max > min {
			level = int(math.Round((v - min) / (max - min) * float64(len(blocks)-1)))
		}
		b.WriteRune(blocks[level])
	}
	return okStyle.Render(b.String())
}

func renderSeriesSummary(values []float64) string {
	if len(values) == 0 {
		return ""
	}
	min, max, sum := values[0], values[0], 0.0
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
		sum += v
	}
	avg := sum / float64(len(values))
	return fmt.Sprintf("min %s · avg %s · max %s · points %d",
		formatNumber(min), formatNumber(avg), formatNumber(max), len(values))
}

func renderBreakdownSummary(breakdown map[string]any, bytes bool) string {
	total := toFloat(breakdown["total"])
	points := []chartPoint{
		{Label: "Saved", Value: toFloat(breakdown["saved"])},
		{Label: "Missed", Value: toFloat(breakdown["miss"])},
		{Label: "Bypassed", Value: toFloat(breakdown["bypass"])},
	}

	var b strings.Builder
	labelWidth := 10
	for _, pt := range points {
		pct := breakdownPercent(pt.Value, total)
		barLen := 0
		if total > 0 && pt.Value > 0 {
			barLen = int(math.Round(pt.Value / total * 36))
			if barLen == 0 {
				barLen = 1
			}
		}
		bar := strings.Repeat("█", barLen)
		fmt.Fprintf(&b, "%-*s %s %s %s\n",
			labelWidth, pt.Label,
			okStyle.Render(bar),
			mutedStyle.Render(formatBreakdownValue(pt.Value, bytes)),
			mutedStyle.Render(fmt.Sprintf("%.1f%%", pct)),
		)
	}
	fmt.Fprintf(&b, "%-*s %s\n", labelWidth, "Total", titleStyle.Render(formatBreakdownValue(total, bytes)))
	return strings.TrimRight(b.String(), "\n")
}

func renderBarChart(points []chartPoint, width int) string {
	if len(points) == 0 {
		return mutedStyle.Render("no data")
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Value > points[j].Value })

	max := points[0].Value
	for _, pt := range points {
		if pt.Value > max {
			max = pt.Value
		}
	}
	if max <= 0 {
		max = 1
	}

	var b strings.Builder
	labelWidth := 18
	for _, pt := range points {
		label := truncate(pt.Label, labelWidth)
		barLen := int(math.Round(pt.Value / max * float64(width)))
		if pt.Value > 0 && barLen == 0 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		fmt.Fprintf(&b, "%-*s %s %s\n", labelWidth, label, okStyle.Render(bar), mutedStyle.Render(formatNumber(pt.Value)))
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatNumber(v float64) string {
	switch {
	case v >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", v/1_000_000_000)
	case v >= 1_000_000:
		return fmt.Sprintf("%.1fM", v/1_000_000)
	case v >= 1_000:
		return fmt.Sprintf("%.1fK", v/1_000)
	case math.Mod(v, 1) == 0:
		return fmt.Sprintf("%.0f", v)
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

func formatAny(v any) string {
	switch typed := v.(type) {
	case nil:
		return "-"
	case float64:
		return formatNumber(typed)
	case json.Number:
		f, _ := typed.Float64()
		return formatNumber(f)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func toFloat(v any) float64 {
	switch typed := v.(type) {
	case float64:
		return typed
	case json.Number:
		f, _ := typed.Float64()
		return f
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	default:
		return 0
	}
}

func firstOf(row map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := row[key]; ok {
			return v
		}
	}
	return ""
}

func firstNamedValue(row map[string]any) (string, float64) {
	for _, key := range []string{"y", "count", "total", "value"} {
		if v, ok := row[key]; ok {
			return key, toFloat(v)
		}
	}
	return "", 0
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
