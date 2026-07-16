package output

import (
	"math"
	"strings"
	"testing"
)

func TestRenderSparkline(t *testing.T) {
	line := renderSparkline([]float64{1, 2, 5, 3, 8, 4}, 12)
	if line == "" {
		t.Fatal("expected sparkline output")
	}
}

func TestBreakdownPercent(t *testing.T) {
	if got := breakdownPercent(58690, 61365); math.Abs(got-95.6) > 0.1 {
		t.Fatalf("breakdownPercent = %.1f, want ~95.6", got)
	}
}

func TestIsStatusCodeTimeSeries(t *testing.T) {
	raw := []any{
		map[string]any{"date": "2026-01-01", "2xx": 10, "3xx": 0, "4xx": 1, "5xx": 0},
	}
	if !isStatusCodeTimeSeries(raw) {
		t.Fatal("expected status code time series")
	}
}

func TestStatusCodePointsFromStats(t *testing.T) {
	points := statusCodePointsFromStats(map[string]any{
		"status_codes": map[string]any{
			"2xx_sum": 100.0, "3xx_sum": 50.0, "4xx_sum": 0.0, "5xx_sum": 1.0,
		},
	})
	if len(points) != 3 {
		t.Fatalf("got %d points, want 3", len(points))
	}
}

func TestRenderBreakdownSummary(t *testing.T) {
	chart := renderBreakdownSummary(map[string]any{
		"saved": 58690, "miss": 283, "bypass": 2392, "total": 61365,
	}, false)
	if chart == "" || !strings.Contains(chart, "Saved") {
		t.Fatalf("expected breakdown summary, got %q", chart)
	}
}

func TestRenderBarChart(t *testing.T) {
	chart := renderBarChart([]chartPoint{
		{Label: "2xx", Value: 1000},
		{Label: "4xx", Value: 200},
		{Label: "5xx", Value: 50},
	}, 20)
	if chart == "" {
		t.Fatal("expected bar chart output")
	}
}
