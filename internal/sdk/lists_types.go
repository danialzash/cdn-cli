package sdk

import "encoding/json"

type DynamicField struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Description  *string             `json:"description"`
	Namespace    string              `json:"namespace"`
	Type         string              `json:"type"`
	Scope        string              `json:"scope"`
	Values       []DynamicFieldValue `json:"values"`
	AllowedPlans []int               `json:"allowed_plans"`
	CreatedAt    string              `json:"created_at"`
	UpdatedAt    string              `json:"updated_at"`
}

type DynamicFieldValue struct {
	ID        string          `json:"id"`
	Value     json.RawMessage `json:"value"`
	Desc      string          `json:"desc"`
	CreatedAt string          `json:"created_at"`
}

type DynamicFieldResponse struct {
	Data    DynamicField `json:"data"`
	Message string       `json:"message,omitempty"`
}

type DynamicFieldData struct {
	Data DynamicField `json:"data"`
}

type ListsResponse struct {
	Data  []DynamicField `json:"data"`
	Meta  PaginatedMeta  `json:"meta"`
	Links PaginatedLinks `json:"links"`
}

type CreateListRequest struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Description *string           `json:"description,omitempty"`
	Values      []CreateListValue `json:"values"`
}

type CreateListValue struct {
	Value json.RawMessage `json:"value"`
	Desc  string          `json:"desc,omitempty"`
}

type AddListItemsRequest struct {
	Values []CreateListValue `json:"values"`
}

type ListListsParams struct {
	Page    int
	PerPage int
	Scope   string
	Type    string
	Name    string
}
