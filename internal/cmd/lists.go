package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newListsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lists",
		Short: "Manage reusable IP, JA3, and number lists",
	}

	cmd.AddCommand(
		newListsListCmd(),
		newListsStoreCmd(),
		newListsGetCmd(),
		newListsDeleteCmd(),
		newListsAddCmd(),
	)
	return cmd
}

func newListsListCmd() *cobra.Command {
	var (
		scope string
		listType string
		name  string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available lists",
		Long: `List IP, JA3, or number lists available to your organization.

Examples:
  verge lists list
  verge lists list --scope private --type ip
  verge lists list --name blocked`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				lists, err := c.ListLists(ctx, client.ListListsOptions{
					Scope: strings.ToLower(scope),
					Type:  strings.ToLower(listType),
					Name:  name,
				})
				if err != nil {
					return fmt.Errorf("list lists: %w", err)
				}
				if jsonOutput {
					return printer().PrintJSON(lists)
				}
				if len(lists) == 0 {
					printer().PrintMessage("No lists found.")
					return nil
				}
				return printer().PrintLists(lists)
			})
		},
	}

	cmd.Flags().StringVar(&scope, "scope", "", "Filter by scope: private, public")
	cmd.Flags().StringVar(&listType, "type", "", "Filter by type: ip, bytes, number")
	cmd.Flags().StringVar(&name, "name", "", "Filter by list name")

	return cmd
}

func newListsStoreCmd() *cobra.Command {
	var (
		name        string
		listType    string
		description string
		items       []string
		value       string
		desc        string
	)

	cmd := &cobra.Command{
		Use:   "store",
		Short: "Create a new list",
		Long: `Create a new private list.

Examples:
  verge lists store --name "Blocked IPs" --type ip --description "Office blocklist" \
    --item "192.0.2.1|Office" --item "192.0.2.2|VPN"
  verge lists store --name "Bad JA3" --type bytes --item "abc123"
  verge lists store --name "Bad ASNs" --type number --value 12345 --desc "Example"`,
		Run: func(cmd *cobra.Command, args []string) {
			if name == "" || listType == "" {
				exitOnError(fmt.Errorf("--name and --type are required"))
			}

			parsedItems, err := parseListItemInputs(items, value, desc)
			exitOnError(err)

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			withContext(func(ctx context.Context) error {
				created, err := c.CreateList(ctx, client.CreateListInput{
					Name:        name,
					Type:        listType,
					Description: description,
					Items:       parsedItems,
				})
				if err != nil {
					return fmt.Errorf("create list: %w", err)
				}
				if jsonOutput {
					return printer().PrintJSON(created)
				}
				printer().PrintMessage("List created successfully.")
				return printer().PrintList(created)
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "List name")
	cmd.Flags().StringVar(&listType, "type", "", "List type: ip, bytes, number")
	cmd.Flags().StringVar(&description, "description", "", "List description")
	cmd.Flags().StringSliceVar(&items, "item", nil, "List item as value or value|description (repeatable)")
	cmd.Flags().StringVar(&value, "value", "", "Single item value")
	cmd.Flags().StringVar(&desc, "desc", "", "Description for --value")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")

	return cmd
}

func newListsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <list-id>",
		Short: "Get list details and values",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			listID := args[0]

			withContext(func(ctx context.Context) error {
				list, err := c.GetList(ctx, listID)
				if err != nil {
					return fmt.Errorf("get list %q: %w", listID, err)
				}
				return printer().PrintList(list)
			})
		},
	}
}

func newListsDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete <list-id> [item-id]",
		Aliases: []string{"rm"},
		Short:   "Delete a list or remove an item from a list",
		Long: `Delete an entire list, or delete a single item from a list.

Examples:
  verge lists delete <list-id>
  verge lists delete <list-id> <item-id>
  verge lists delete <list-id> --force`,
		Args: cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			listID := args[0]

			withContext(func(ctx context.Context) error {
				if len(args) == 1 {
					if !force {
						ok, err := printer().Confirm(fmt.Sprintf("Delete list %q?", listID))
						exitOnError(err)
						if !ok {
							printer().PrintMessage("Aborted.")
							return nil
						}
					}

					if err := c.DeleteList(ctx, listID); err != nil {
						return fmt.Errorf("delete list %q: %w", listID, err)
					}
					if jsonOutput {
						return printer().PrintJSON(map[string]any{
							"deleted": true,
							"id":      listID,
						})
					}
					printer().PrintMessage("List deleted successfully.")
					return nil
				}

				itemID := args[1]
				if !force {
					ok, err := printer().Confirm(fmt.Sprintf("Delete item %q from list %q?", itemID, listID))
					exitOnError(err)
					if !ok {
						printer().PrintMessage("Aborted.")
						return nil
					}
				}

				if err := c.DeleteListItem(ctx, listID, itemID); err != nil {
					return fmt.Errorf("delete item %q from list %q: %w", itemID, listID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"deleted": true,
						"list_id": listID,
						"item_id": itemID,
					})
				}
				printer().PrintMessage("List item deleted successfully.")
				return nil
			})
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Delete without confirmation")
	return cmd
}

func newListsAddCmd() *cobra.Command {
	var (
		items []string
		value string
		desc  string
	)

	cmd := &cobra.Command{
		Use:   "add <list-id>",
		Short: "Add items to a list",
		Long: `Add one or more items to an existing list.

Examples:
  verge lists add <list-id> --value 192.0.2.1 --desc "Office"
  verge lists add <list-id> --item "192.0.2.1|Office" --item "192.0.2.2|VPN"
  verge lists add <list-id> --item abc123def456`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			parsedItems, err := parseListItemInputs(items, value, desc)
			exitOnError(err)
			if len(parsedItems) == 0 {
				exitOnError(fmt.Errorf("at least one of --item or --value is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			listID := args[0]

			withContext(func(ctx context.Context) error {
				list, err := c.AddListItems(ctx, listID, parsedItems)
				if err != nil {
					return fmt.Errorf("add items to list %q: %w", listID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(list)
				}
				printer().PrintMessage(fmt.Sprintf("Added %d item(s) successfully.", len(parsedItems)))
				return printer().PrintList(list)
			})
		},
	}

	cmd.Flags().StringSliceVar(&items, "item", nil, "Item as value or value|description (repeatable)")
	cmd.Flags().StringVar(&value, "value", "", "Single item value")
	cmd.Flags().StringVar(&desc, "desc", "", "Description for --value")

	return cmd
}

func parseListItemInputs(items []string, value, desc string) ([]client.CreateListItemInput, error) {
	var out []client.CreateListItemInput

	for _, item := range items {
		parsed, err := parseListItemToken(item)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}

	if value != "" {
		out = append(out, client.CreateListItemInput{
			Value: value,
			Desc:  desc,
		})
	}

	return out, nil
}

func parseListItemToken(token string) (client.CreateListItemInput, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return client.CreateListItemInput{}, fmt.Errorf("item cannot be empty")
	}

	for _, sep := range []string{"|", ":"} {
		if idx := strings.Index(token, sep); idx >= 0 {
			return client.CreateListItemInput{
				Value: strings.TrimSpace(token[:idx]),
				Desc:  strings.TrimSpace(token[idx+1:]),
			}, nil
		}
	}

	return client.CreateListItemInput{Value: token}, nil
}
