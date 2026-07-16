package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type List struct {
	ID          string
	Name        string
	Description string
	Namespace   string
	Type        string
	Scope       string
	Items       []ListItem
	CreatedAt   string
	UpdatedAt   string
}

type ListItem struct {
	ID        string
	Value     string
	Desc      string
	CreatedAt string
}

type ListListsOptions struct {
	Scope string
	Type  string
	Name  string
}

type CreateListInput struct {
	Name        string
	Type        string
	Description string
	Items       []CreateListItemInput
}

type CreateListItemInput struct {
	Value string
	Desc  string
}

func (c *Client) ListLists(ctx context.Context, opts ListListsOptions) ([]List, error) {
	var all []List
	page := 1

	for {
		resp, err := c.sdk.ListLists(ctx, sdk.ListListsParams{
			Page:    page,
			PerPage: defaultPerPage,
			Scope:   opts.Scope,
			Type:    opts.Type,
			Name:    opts.Name,
		})
		if err != nil {
			return nil, err
		}

		for _, item := range resp.Data {
			all = append(all, mapList(item))
		}

		if resp.Meta.LastPage == 0 || page >= resp.Meta.LastPage {
			break
		}
		page++
	}

	return all, nil
}

func (c *Client) CreateList(ctx context.Context, input CreateListInput) (*List, error) {
	values, err := encodeListValues(input.Type, input.Items)
	if err != nil {
		return nil, err
	}

	req := sdk.CreateListRequest{
		Name:   input.Name,
		Type:   strings.ToLower(input.Type),
		Values: values,
	}
	if input.Description != "" {
		req.Description = &input.Description
	}

	created, err := c.sdk.CreateList(ctx, req)
	if err != nil {
		return nil, err
	}
	mapped := mapList(*created)
	return &mapped, nil
}

func (c *Client) GetList(ctx context.Context, id string) (*List, error) {
	list, err := c.sdk.GetList(ctx, id)
	if err != nil {
		return nil, err
	}
	mapped := mapList(*list)
	return &mapped, nil
}

func (c *Client) DeleteList(ctx context.Context, id string) error {
	return c.sdk.DeleteList(ctx, id)
}

func (c *Client) AddListItems(ctx context.Context, listID string, items []CreateListItemInput) (*List, error) {
	list, err := c.sdk.GetList(ctx, listID)
	if err != nil {
		return nil, err
	}

	values, err := encodeListValues(list.Type, items)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one item is required")
	}

	if err := c.sdk.AddListItems(ctx, listID, sdk.AddListItemsRequest{Values: values}); err != nil {
		return nil, err
	}

	return c.GetList(ctx, listID)
}

func (c *Client) DeleteListItem(ctx context.Context, listID, itemID string) error {
	return c.sdk.DeleteListItem(ctx, listID, itemID)
}

func mapList(list sdk.DynamicField) List {
	items := make([]ListItem, 0, len(list.Values))
	for _, value := range list.Values {
		items = append(items, ListItem{
			ID:        value.ID,
			Value:     formatListItemValue(value.Value),
			Desc:      value.Desc,
			CreatedAt: value.CreatedAt,
		})
	}

	description := ""
	if list.Description != nil {
		description = *list.Description
	}

	return List{
		ID:          list.ID,
		Name:        list.Name,
		Description: description,
		Namespace:   list.Namespace,
		Type:        list.Type,
		Scope:       list.Scope,
		Items:       items,
		CreatedAt:   list.CreatedAt,
		UpdatedAt:   list.UpdatedAt,
	}
}

func encodeListValues(listType string, items []CreateListItemInput) ([]sdk.CreateListValue, error) {
	if len(items) == 0 {
		return []sdk.CreateListValue{}, nil
	}

	values := make([]sdk.CreateListValue, 0, len(items))
	for _, item := range items {
		encoded, err := encodeListValue(listType, item.Value)
		if err != nil {
			return nil, err
		}
		values = append(values, sdk.CreateListValue{
			Value: encoded,
			Desc:  item.Desc,
		})
	}
	return values, nil
}

func encodeListValue(listType, value string) (json.RawMessage, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("item value cannot be empty")
	}

	switch strings.ToLower(listType) {
	case "number":
		n, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number value %q: %w", value, err)
		}
		return json.Marshal(n)
	default:
		return json.Marshal(value)
	}
}

func formatListItemValue(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	return fmt.Sprintf("%v", value)
}
