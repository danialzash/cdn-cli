package sdk

import (
	"net/url"
	"strconv"
)

type ReportParams struct {
	Period       string
	Since        string
	Until        string
	Subdomain    string
	Page         int
	PerPage      int
	Error        string
	Domains      string
	ReportType   string
	CategoryType string
	Pops         string
	Asns         string
}

func (p ReportParams) Query() url.Values {
	query := url.Values{}
	if p.Period != "" {
		query.Set("period", p.Period)
	}
	if p.Since != "" {
		query.Set("since", p.Since)
	}
	if p.Until != "" {
		query.Set("until", p.Until)
	}
	if p.Subdomain != "" {
		query.Set("filter[subdomain]", p.Subdomain)
	}
	if p.Page > 0 {
		query.Set("page", strconv.Itoa(p.Page))
	}
	if p.PerPage > 0 {
		query.Set("per_page", strconv.Itoa(p.PerPage))
	}
	if p.Error != "" {
		query.Set("error", p.Error)
	}
	if p.Domains != "" {
		query.Set("domains", p.Domains)
	}
	if p.ReportType != "" {
		query.Set("report_type", p.ReportType)
	}
	if p.CategoryType != "" {
		query.Set("category_type", p.CategoryType)
	}
	if p.Pops != "" {
		query.Set("pops", p.Pops)
	}
	if p.Asns != "" {
		query.Set("asns", p.Asns)
	}
	return query
}
