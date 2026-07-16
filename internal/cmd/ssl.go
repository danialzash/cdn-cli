package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vergecloud/cdn-cli/internal/client"
)

func newSslCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssl <domain>",
		Short: "SSL/TLS settings and certificates",
		Long: `Get SSL/TLS settings for a domain.

Use subcommands to update settings, manage certificates, and handle managed orders:
  verge ssl update <domain> ...
  verge ssl certificates list <domain>
  verge ssl issue <domain>`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				settings, err := c.GetSslSettings(ctx, domain)
				if err != nil {
					return fmt.Errorf("get SSL settings for %q: %w", domain, err)
				}
				return printer().PrintSslSettings(settings)
			})
		},
	}

	cmd.AddCommand(
		newSslUpdateCmd(),
		newSslCertificatesCmd(),
		newSslOrdersCmd(),
		newSslIssueCmd(),
	)
	return cmd
}

func newSslUpdateCmd() *cobra.Command {
	var (
		enabled            bool
		fingerprintEnabled bool
		certificate        string
		tlsVersion         string
		hstsEnabled        bool
		hstsMaxAge         string
		hstsSubdomain      bool
		hstsPreload        bool
		httpsRedirect      bool
		replaceHTTP        bool
		quicEnabled        bool
		certificateKeyType string
	)

	cmd := &cobra.Command{
		Use:   "update <domain>",
		Short: "Update SSL/TLS settings",
		Long: `Update SSL/TLS settings for a domain. Only pass flags you want to change.

Examples:
  verge ssl update example.com --enabled
  verge ssl update example.com --certificate managed
  verge ssl update example.com --certificate <certificate-id>
  verge ssl update example.com --tls-version TLSv1.2 --hsts --hsts-max-age 12mo
  verge ssl update example.com --https-redirect --quic`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !sslUpdateFlagsChanged(cmd) {
				exitOnError(fmt.Errorf("at least one SSL setting flag is required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			input := buildSslUpdateInput(cmd, enabled, fingerprintEnabled, certificate, tlsVersion, hstsEnabled, hstsMaxAge, hstsSubdomain, hstsPreload, httpsRedirect, replaceHTTP, quicEnabled, certificateKeyType)

			withContext(func(ctx context.Context) error {
				settings, err := c.UpdateSslSettings(ctx, domain, input)
				if err != nil {
					return fmt.Errorf("update SSL settings for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(settings)
				}
				printer().PrintMessage("SSL settings updated successfully.")
				return printer().PrintSslSettings(settings)
			})
		},
	}

	cmd.Flags().BoolVar(&enabled, "enabled", false, "Enable SSL")
	cmd.Flags().BoolVar(&fingerprintEnabled, "fingerprint", false, "Enable TLS fingerprinting")
	cmd.Flags().StringVar(&certificate, "certificate", "", "Active certificate ID or managed")
	cmd.Flags().StringVar(&tlsVersion, "tls-version", "", "Minimum TLS version: TLSv1, TLSv1.1, TLSv1.2, TLSv1.3")
	cmd.Flags().BoolVar(&hstsEnabled, "hsts", false, "Enable HSTS")
	cmd.Flags().StringVar(&hstsMaxAge, "hsts-max-age", "", "HSTS max age: 1mo, 2mo, 3mo, 4mo, 5mo, 6mo, 12mo, 24mo")
	cmd.Flags().BoolVar(&hstsSubdomain, "hsts-subdomain", false, "Include subdomains in HSTS")
	cmd.Flags().BoolVar(&hstsPreload, "hsts-preload", false, "Enable HSTS preload")
	cmd.Flags().BoolVar(&httpsRedirect, "https-redirect", false, "Redirect HTTP to HTTPS")
	cmd.Flags().BoolVar(&replaceHTTP, "replace-http", false, "Replace HTTP with HTTPS in HTML/JS sources")
	cmd.Flags().BoolVar(&quicEnabled, "quic", false, "Enable QUIC")
	cmd.Flags().StringVar(&certificateKeyType, "certificate-key-type", "", "Managed certificate key type: rsa, ec")

	return cmd
}

func newSslCertificatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "certificates",
		Aliases: []string{"certs", "certificate"},
		Short:   "Manage SSL certificates",
	}

	cmd.AddCommand(
		newSslCertificatesListCmd(),
		newSslCertificatesGetCmd(),
		newSslCertificatesUploadCmd(),
		newSslCertificatesDeleteCmd(),
		newSslCertificatesRevokeCmd(),
	)
	return cmd
}

func newSslCertificatesListCmd() *cobra.Command {
	var types []string

	cmd := &cobra.Command{
		Use:   "list <domain>",
		Short: "List SSL certificates",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				certs, err := c.ListCertificates(ctx, domain, normalizeListFlag(types))
				if err != nil {
					return fmt.Errorf("list certificates for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(certs)
				}
				if len(certs) == 0 {
					printer().PrintMessage("No certificates found.")
					return nil
				}
				return printer().PrintCertificates(certs)
			})
		},
	}

	cmd.Flags().StringSliceVar(&types, "type", nil, "Filter by certificate type: user, verge, origin (repeatable or comma-separated)")
	return cmd
}

func newSslCertificatesGetCmd() *cobra.Command {
	var showPrivateKey bool

	cmd := &cobra.Command{
		Use:   "get <domain> <certificate-id>",
		Short: "Get certificate details",
		Long: `Get certificate details for a domain.

Use --show-private-key to include the private key in the response. When enabled,
the private key is permanently removed from VergeCloud and must be stored securely.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			certificateID := args[1]

			withContext(func(ctx context.Context) error {
				cert, err := c.GetCertificate(ctx, domain, certificateID, showPrivateKey)
				if err != nil {
					return fmt.Errorf("get certificate %q: %w", certificateID, err)
				}
				return printer().PrintCertificateDetail(cert)
			})
		},
	}

	cmd.Flags().BoolVar(&showPrivateKey, "show-private-key", false, "Include private key in response")
	return cmd
}

func newSslCertificatesUploadCmd() *cobra.Command {
	var (
		certificatePath string
		privateKeyPath  string
	)

	cmd := &cobra.Command{
		Use:   "upload <domain>",
		Short: "Upload a custom certificate",
		Long: `Upload a custom certificate and private key for a domain.

Examples:
  verge ssl certificates upload example.com --certificate cert.pem --private-key key.pem`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if certificatePath == "" || privateKeyPath == "" {
				exitOnError(fmt.Errorf("--certificate and --private-key are required"))
			}

			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				if err := c.UploadCertificate(ctx, domain, client.UploadCertificateInput{
					CertificatePath: certificatePath,
					PrivateKeyPath:  privateKeyPath,
				}); err != nil {
					return fmt.Errorf("upload certificate for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"uploaded": true,
						"domain":   domain,
					})
				}
				printer().PrintMessage("Certificate uploaded successfully.")
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&certificatePath, "certificate", "", "Path to certificate PEM file")
	cmd.Flags().StringVar(&privateKeyPath, "private-key", "", "Path to private key PEM file")
	_ = cmd.MarkFlagRequired("certificate")
	_ = cmd.MarkFlagRequired("private-key")

	return cmd
}

func newSslCertificatesDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete <domain> <certificate-id>",
		Aliases: []string{"rm"},
		Short:   "Delete an unused custom certificate",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			certificateID := args[1]

			if !force {
				ok, err := printer().Confirm(fmt.Sprintf("Delete certificate %q?", certificateID))
				exitOnError(err)
				if !ok {
					printer().PrintMessage("Aborted.")
					return
				}
			}

			withContext(func(ctx context.Context) error {
				if err := c.DeleteCertificate(ctx, domain, certificateID); err != nil {
					return fmt.Errorf("delete certificate %q: %w", certificateID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"deleted": true,
						"id":      certificateID,
					})
				}
				printer().PrintMessage("Certificate deleted successfully.")
				return nil
			})
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Delete without confirmation")
	return cmd
}

func newSslCertificatesRevokeCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "revoke <domain> <certificate-id>",
		Short: "Revoke a server certificate",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]
			certificateID := args[1]

			if !force {
				ok, err := printer().Confirm(fmt.Sprintf("Revoke certificate %q?", certificateID))
				exitOnError(err)
				if !ok {
					printer().PrintMessage("Aborted.")
					return
				}
			}

			withContext(func(ctx context.Context) error {
				if err := c.RevokeCertificate(ctx, domain, certificateID); err != nil {
					return fmt.Errorf("revoke certificate %q: %w", certificateID, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"revoked": true,
						"id":      certificateID,
					})
				}
				printer().PrintMessage("Certificate revoked successfully.")
				return nil
			})
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Revoke without confirmation")
	return cmd
}

func newSslOrdersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "orders",
		Short: "Managed certificate orders",
	}

	cmd.AddCommand(
		newSslOrdersListCmd(),
		newSslOrdersRetryCmd(),
	)
	return cmd
}

func newSslOrdersListCmd() *cobra.Command {
	var orderType string

	cmd := &cobra.Command{
		Use:   "list <domain>",
		Short: "List managed certificate orders",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				orders, err := c.ListCertificateOrders(ctx, domain, strings.ToLower(orderType))
				if err != nil {
					return fmt.Errorf("list certificate orders for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(orders)
				}
				if len(orders) == 0 {
					printer().PrintMessage("No certificate orders found.")
					return nil
				}
				return printer().PrintCertificateOrders(orders)
			})
		},
	}

	cmd.Flags().StringVar(&orderType, "type", "edge", "Order type: edge, origin")
	return cmd
}

func newSslOrdersRetryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "retry <domain>",
		Short: "Retry a previously killed managed certificate order",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				if err := c.RetryCertificateOrder(ctx, domain); err != nil {
					return fmt.Errorf("retry certificate order for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(map[string]any{
						"retried": true,
						"domain":  domain,
					})
				}
				printer().PrintMessage("Certificate order retry queued successfully.")
				return nil
			})
		},
	}
}

func newSslIssueCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "issue <domain>",
		Short: "Request managed SSL certificate issuance",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadRuntimeConfig()
			exitOnError(err)

			c, err := newAPIClient(cfg)
			exitOnError(err)

			domain := args[0]

			withContext(func(ctx context.Context) error {
				order, err := c.IssueCertificate(ctx, domain)
				if err != nil {
					return fmt.Errorf("issue certificate for %q: %w", domain, err)
				}
				if jsonOutput {
					return printer().PrintJSON(order)
				}
				printer().PrintMessage("Certificate issuance order placed successfully.")
				return printer().PrintCertificateOrder(order)
			})
		},
	}
}

func sslUpdateFlagsChanged(cmd *cobra.Command) bool {
	flags := []string{
		"enabled", "fingerprint", "certificate", "tls-version", "hsts", "hsts-max-age",
		"hsts-subdomain", "hsts-preload", "https-redirect", "replace-http", "quic", "certificate-key-type",
	}
	for _, flag := range flags {
		if cmd.Flags().Changed(flag) {
			return true
		}
	}
	return false
}

func buildSslUpdateInput(
	cmd *cobra.Command,
	enabled, fingerprintEnabled bool,
	certificate, tlsVersion string,
	hstsEnabled bool,
	hstsMaxAge string,
	hstsSubdomain, hstsPreload, httpsRedirect, replaceHTTP, quicEnabled bool,
	certificateKeyType string,
) client.UpdateSslSettingsInput {
	input := client.UpdateSslSettingsInput{}

	if cmd.Flags().Changed("enabled") {
		input.Enabled = &enabled
	}
	if cmd.Flags().Changed("fingerprint") {
		input.FingerprintEnabled = &fingerprintEnabled
	}
	if cmd.Flags().Changed("certificate") {
		input.Certificate = &certificate
	}
	if cmd.Flags().Changed("tls-version") {
		input.TLSVersion = &tlsVersion
	}
	if cmd.Flags().Changed("hsts") {
		input.HSTSEnabled = &hstsEnabled
	}
	if cmd.Flags().Changed("hsts-max-age") {
		input.HSTSMaxAge = &hstsMaxAge
	}
	if cmd.Flags().Changed("hsts-subdomain") {
		input.HSTSSubdomain = &hstsSubdomain
	}
	if cmd.Flags().Changed("hsts-preload") {
		input.HSTSPreload = &hstsPreload
	}
	if cmd.Flags().Changed("https-redirect") {
		input.HTTPSRedirect = &httpsRedirect
	}
	if cmd.Flags().Changed("replace-http") {
		input.ReplaceHTTP = &replaceHTTP
	}
	if cmd.Flags().Changed("quic") {
		input.QUICEnabled = &quicEnabled
	}
	if cmd.Flags().Changed("certificate-key-type") {
		keyType := strings.ToLower(certificateKeyType)
		input.CertificateKeyType = &keyType
	}

	return input
}
