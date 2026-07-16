package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newAccelerationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acceleration <domain>",
		Short: "Acceleration settings",
		Long: `Get acceleration settings for a domain.

Use subcommands to update settings or manage image resize:
  verge acceleration update <domain> ...
  verge acceleration image-resize <domain> ...`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				settings, err := c.GetAccelerationSettings(ctx, domain)
				if err != nil {
					return fmt.Errorf("get acceleration settings for %q: %w", domain, err)
				}
				return printer().PrintAccelerationSettings(settings)
			})
		},
	}

	cmd.AddCommand(
		newAccelerationUpdateCmd(),
		newAccelerationImageResizeCmd(),
	)
	return cmd
}

func newAccelerationUpdateCmd() *cobra.Command {
	var (
		status     string
		extensions []string
	)

	cmd := &cobra.Command{
		Use:   "update <domain>",
		Short: "Update acceleration settings",
		Long: `Update acceleration settings for a domain. Only pass flags you want to change.

Examples:
  verge acceleration update example.com --status on
  verge acceleration update example.com --status off
  verge acceleration update example.com --extensions css,js
  verge acceleration update example.com --extensions css --extensions js --status on`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !accelerationUpdateFlagsChanged(cmd) {
				exitOnError(fmt.Errorf("at least one of --status or --extensions is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			input := buildAccelerationUpdateInput(cmd, status, extensions)

			withContext(func(ctx context.Context) error {
				settings, err := c.UpdateAccelerationSettings(ctx, domain, input)
				if err != nil {
					return fmt.Errorf("update acceleration settings for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(settings)
				}
				printer().PrintMessage("Acceleration settings updated successfully.")
				return printer().PrintAccelerationSettings(settings)
			})
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "Acceleration status: on, off")
	cmd.Flags().StringSliceVar(&extensions, "extensions", nil, "File extensions to accelerate: css, gif, jpeg, js, png (repeatable or comma-separated)")

	return cmd
}

func newAccelerationImageResizeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "image-resize <domain>",
		Aliases: []string{"imageresize"},
		Short:   "Image resize settings",
		Long: `Get image resize settings for a domain.

Use the update subcommand to change settings:
  verge acceleration image-resize update <domain> ...`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				settings, err := c.GetImageResizeSettings(ctx, domain)
				if err != nil {
					return fmt.Errorf("get image resize settings for %q: %w", domain, err)
				}
				return printer().PrintImageResizeSettings(settings)
			})
		},
	}

	cmd.AddCommand(newAccelerationImageResizeUpdateCmd())
	return cmd
}

func newAccelerationImageResizeUpdateCmd() *cobra.Command {
	var (
		status    string
		heightBy  string
		widthBy   string
		mode      string
		modeBy    string
		qualityBy string
	)

	cmd := &cobra.Command{
		Use:   "update <domain>",
		Short: "Update image resize settings",
		Long: `Update image resize settings for a domain. Only pass flags you want to change.

Examples:
  verge acceleration image-resize update example.com --status on
  verge acceleration image-resize update example.com --status off
  verge acceleration image-resize update example.com --height-by height --width-by width
  verge acceleration image-resize update example.com --mode short-side --mode-by mode --quality-by quality`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !imageResizeUpdateFlagsChanged(cmd) {
				exitOnError(fmt.Errorf("at least one image resize setting flag is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			input := buildImageResizeUpdateInput(cmd, status, heightBy, widthBy, mode, modeBy, qualityBy)

			withContext(func(ctx context.Context) error {
				settings, err := c.UpdateImageResizeSettings(ctx, domain, input)
				if err != nil {
					return fmt.Errorf("update image resize settings for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(settings)
				}
				printer().PrintMessage("Image resize settings updated successfully.")
				return printer().PrintImageResizeSettings(settings)
			})
		},
	}

	cmd.Flags().StringVar(&status, "status", "", "Image resize status: on, off")
	cmd.Flags().StringVar(&heightBy, "height-by", "", "Query string variable for image height")
	cmd.Flags().StringVar(&widthBy, "width-by", "", "Query string variable for image width")
	cmd.Flags().StringVar(&mode, "mode", "", "Resize mode: freely, short-side, long-side")
	cmd.Flags().StringVar(&modeBy, "mode-by", "", "Query string variable for resize mode override")
	cmd.Flags().StringVar(&qualityBy, "quality-by", "", "Query string variable for image quality (1-100)")

	return cmd
}

func accelerationUpdateFlagsChanged(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("status") || cmd.Flags().Changed("extensions")
}

func buildAccelerationUpdateInput(cmd *cobra.Command, status string, extensions []string) client.UpdateAccelerationInput {
	input := client.UpdateAccelerationInput{}

	if cmd.Flags().Changed("status") {
		status = strings.ToLower(status)
		input.Status = &status
	}
	if cmd.Flags().Changed("extensions") {
		input.Extensions = normalizeListFlag(extensions)
	}

	return input
}

func imageResizeUpdateFlagsChanged(cmd *cobra.Command) bool {
	flags := []string{"status", "height-by", "width-by", "mode", "mode-by", "quality-by"}
	for _, flag := range flags {
		if cmd.Flags().Changed(flag) {
			return true
		}
	}
	return false
}

func buildImageResizeUpdateInput(cmd *cobra.Command, status, heightBy, widthBy, mode, modeBy, qualityBy string) client.UpdateImageResizeInput {
	input := client.UpdateImageResizeInput{}

	if cmd.Flags().Changed("status") {
		status = strings.ToLower(status)
		input.Status = &status
	}
	if cmd.Flags().Changed("height-by") {
		input.HeightBy = &heightBy
	}
	if cmd.Flags().Changed("width-by") {
		input.WidthBy = &widthBy
	}
	if cmd.Flags().Changed("mode") {
		mode = strings.ToLower(mode)
		input.Mode = &mode
	}
	if cmd.Flags().Changed("mode-by") {
		input.ModeBy = &modeBy
	}
	if cmd.Flags().Changed("quality-by") {
		input.QualityBy = &qualityBy
	}

	return input
}

func normalizeListFlag(values []string) []string {
	var out []string
	for _, item := range values {
		for _, part := range strings.Split(item, ",") {
			part = strings.TrimSpace(strings.ToLower(part))
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}
