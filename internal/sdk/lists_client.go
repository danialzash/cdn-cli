package sdk

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

func (c *Client) ListLists(ctx context.Context, params ListListsParams) (*ListsResponse, error) {
	query := url.Values{}
	if params.Page > 0 {
		query.Set("page", strconv.Itoa(params.Page))
	}
	if params.PerPage > 0 {
		query.Set("per_page", strconv.Itoa(params.PerPage))
	}
	if params.Scope != "" {
		query.Set("scope", params.Scope)
	}
	if params.Type != "" {
		query.Set("type", params.Type)
	}
	if params.Name != "" {
		query.Set("name", params.Name)
	}

	var resp ListsResponse
	if err := c.get(ctx, "/lists", query, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) CreateList(ctx context.Context, req CreateListRequest) (*DynamicField, error) {
	var resp DynamicFieldResponse
	if err := c.request(ctx, http.MethodPost, "/lists", req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) GetList(ctx context.Context, id string) (*DynamicField, error) {
	var resp DynamicFieldData
	path := "/lists/" + url.PathEscape(id)
	if err := c.get(ctx, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) DeleteList(ctx context.Context, id string) error {
	path := "/lists/" + url.PathEscape(id)
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}

func (c *Client) AddListItems(ctx context.Context, id string, req AddListItemsRequest) error {
	path := "/lists/" + url.PathEscape(id) + "/items"
	return c.request(ctx, http.MethodPost, path, req, nil)
}

func (c *Client) DeleteListItem(ctx context.Context, listID, itemID string) error {
	path := "/lists/" + url.PathEscape(listID) + "/items/" + url.PathEscape(itemID)
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}
