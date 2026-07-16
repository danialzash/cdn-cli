package client

import (
	"context"

	"github.com/vergecloud/cdn-cli/internal/sdk"
)

type SslSettings struct {
	Enabled            bool
	FingerprintEnabled bool
	CertificateMode    string
	TLSVersion         string
	HSTSEnabled        bool
	HSTSMaxAge         string
	HSTSSubdomain      bool
	HSTSPreload        bool
	HTTPSRedirect      bool
	ReplaceHTTP        bool
	QUICEnabled        bool
	VerifySNI          bool
	CertificateKeyType string
	Certificates       []Certificate
	Orders             []CertificateOrder
}

type UpdateSslSettingsInput struct {
	Enabled            *bool
	FingerprintEnabled *bool
	Certificate        *string
	TLSVersion         *string
	HSTSEnabled        *bool
	HSTSMaxAge         *string
	HSTSSubdomain      *bool
	HSTSPreload        *bool
	HTTPSRedirect      *bool
	ReplaceHTTP        *bool
	QUICEnabled        *bool
	CertificateKeyType *string
}

type Certificate struct {
	ID          string
	Type        string
	Active      bool
	KeyType     string
	DomainNames []string
	Issuer      string
	IsRevoked   bool
	ExpiryDate  string
	CreatedAt   string
	UpdatedAt   string
}

type CertificateDetail struct {
	Certificate
	CertificatePEM string
	PrivateKeyPEM  string
}

type CertificateOrder struct {
	ID          string
	OrderID     string
	Status      string
	DomainNames []string
	ExpiryDate  string
	CreatedAt   string
	UpdatedAt   string
}

type UploadCertificateInput struct {
	CertificatePath string
	PrivateKeyPath  string
}

func (c *Client) GetSslSettings(ctx context.Context, domain string) (*SslSettings, error) {
	settings, err := c.sdk.GetSslSettings(ctx, domain)
	if err != nil {
		return nil, err
	}
	mapped := mapSslSettings(*settings)
	return &mapped, nil
}

func (c *Client) UpdateSslSettings(ctx context.Context, domain string, input UpdateSslSettingsInput) (*SslSettings, error) {
	settings, err := c.sdk.UpdateSslSettings(ctx, domain, sdk.UpdateSslRequest{
		FingerprintStatus:  input.FingerprintEnabled,
		SSLStatus:          input.Enabled,
		Certificate:        input.Certificate,
		TLSVersion:         input.TLSVersion,
		HSTSStatus:         input.HSTSEnabled,
		HSTSMaxAge:         input.HSTSMaxAge,
		HSTSSubdomain:      input.HSTSSubdomain,
		HSTSPreload:        input.HSTSPreload,
		HTTPSRedirect:      input.HTTPSRedirect,
		ReplaceHTTP:        input.ReplaceHTTP,
		QUICStatus:         input.QUICEnabled,
		CertificateKeyType: input.CertificateKeyType,
	})
	if err != nil {
		return nil, err
	}
	mapped := mapSslSettings(*settings)
	return &mapped, nil
}

func (c *Client) ListCertificates(ctx context.Context, domain string, types []string) ([]Certificate, error) {
	certs, err := c.sdk.ListCertificates(ctx, domain, types)
	if err != nil {
		return nil, err
	}
	return mapCertificates(certs), nil
}

func (c *Client) GetCertificate(ctx context.Context, domain, certificateID string, showPrivateKey bool) (*CertificateDetail, error) {
	cert, err := c.sdk.GetCertificate(ctx, domain, certificateID, showPrivateKey)
	if err != nil {
		return nil, err
	}
	mapped := mapCertificateDetail(*cert)
	return &mapped, nil
}

func (c *Client) UploadCertificate(ctx context.Context, domain string, input UploadCertificateInput) error {
	return c.sdk.UploadCertificate(ctx, domain, input.CertificatePath, input.PrivateKeyPath)
}

func (c *Client) DeleteCertificate(ctx context.Context, domain, certificateID string) error {
	return c.sdk.DeleteCertificate(ctx, domain, certificateID)
}

func (c *Client) RevokeCertificate(ctx context.Context, domain, certificateID string) error {
	return c.sdk.RevokeCertificate(ctx, domain, certificateID)
}

func (c *Client) ListCertificateOrders(ctx context.Context, domain, orderType string) ([]CertificateOrder, error) {
	orders, err := c.sdk.ListCertificateOrders(ctx, domain, orderType)
	if err != nil {
		return nil, err
	}
	return mapCertificateOrders(orders), nil
}

func (c *Client) IssueCertificate(ctx context.Context, domain string) (*CertificateOrder, error) {
	order, err := c.sdk.IssueCertificate(ctx, domain)
	if err != nil {
		return nil, err
	}
	mapped := mapCertificateOrder(*order)
	return &mapped, nil
}

func (c *Client) RetryCertificateOrder(ctx context.Context, domain string) error {
	return c.sdk.RetryCertificateOrder(ctx, domain)
}

func mapSslSettings(settings sdk.Ssl) SslSettings {
	return SslSettings{
		Enabled:            settings.SSLStatus,
		FingerprintEnabled: settings.FingerprintStatus,
		CertificateMode:    settings.CertificateMode,
		TLSVersion:         settings.TLSVersion,
		HSTSEnabled:        settings.HSTSStatus,
		HSTSMaxAge:         settings.HSTSMaxAge,
		HSTSSubdomain:      settings.HSTSSubdomain,
		HSTSPreload:        settings.HSTSPreload,
		HTTPSRedirect:      settings.HTTPSRedirect,
		ReplaceHTTP:        settings.ReplaceHTTP,
		QUICEnabled:        settings.QUICStatus,
		VerifySNI:          settings.VerifySNI,
		CertificateKeyType: settings.CertificateKeyType,
		Certificates:       mapCertificates(settings.Certificates),
		Orders:             mapCertificateOrders(settings.Orders),
	}
}

func mapCertificates(certs []sdk.Certificate) []Certificate {
	out := make([]Certificate, 0, len(certs))
	for _, cert := range certs {
		out = append(out, mapCertificate(cert))
	}
	return out
}

func mapCertificate(cert sdk.Certificate) Certificate {
	keyType := ""
	if cert.KeyType != nil {
		keyType = *cert.KeyType
	}
	return Certificate{
		ID:          cert.ID,
		Type:        cert.Type,
		Active:      cert.Active,
		KeyType:     keyType,
		DomainNames: cert.DomainNames,
		Issuer:      cert.Issuer,
		IsRevoked:   cert.IsRevoked,
		ExpiryDate:  cert.ExpiryDate,
		CreatedAt:   cert.CreatedAt,
		UpdatedAt:   cert.UpdatedAt,
	}
}

func mapCertificateDetail(cert sdk.CertificateDetail) CertificateDetail {
	return CertificateDetail{
		Certificate:    mapCertificate(cert.Certificate),
		CertificatePEM: cert.CertificatePEM,
		PrivateKeyPEM:  cert.PrivateKeyPEM,
	}
}

func mapCertificateOrders(orders []sdk.CertificateOrder) []CertificateOrder {
	out := make([]CertificateOrder, 0, len(orders))
	for _, order := range orders {
		out = append(out, mapCertificateOrder(order))
	}
	return out
}

func mapCertificateOrder(order sdk.CertificateOrder) CertificateOrder {
	return CertificateOrder{
		ID:          order.ID,
		OrderID:     order.OrderID,
		Status:      order.Status,
		DomainNames: order.DomainNames,
		ExpiryDate:  order.ExpiryDate,
		CreatedAt:   order.CreatedAt,
		UpdatedAt:   order.UpdatedAt,
	}
}
