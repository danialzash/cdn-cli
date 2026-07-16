package sdk

type Ssl struct {
	FingerprintStatus  bool               `json:"fingerprint_status"`
	SSLStatus          bool               `json:"ssl_status"`
	CertificateMode    string             `json:"certificate_mode"`
	TLSVersion         string             `json:"tls_version"`
	HSTSStatus         bool               `json:"hsts_status"`
	QUICStatus         bool               `json:"quic_status"`
	VerifySNI          bool               `json:"verify_sni"`
	HSTSMaxAge         string             `json:"hsts_max_age"`
	HSTSSubdomain      bool               `json:"hsts_subdomain"`
	HSTSPreload        bool               `json:"hsts_preload"`
	HTTPSRedirect      bool               `json:"https_redirect"`
	ReplaceHTTP        bool               `json:"replace_http"`
	CertificateKeyType string             `json:"certificate_key_type"`
	Certificates       []Certificate      `json:"certificates"`
	Orders             []CertificateOrder `json:"orders"`
}

type SslResponse struct {
	Data Ssl `json:"data"`
}

type UpdateSslRequest struct {
	FingerprintStatus  *bool   `json:"fingerprint_status,omitempty"`
	SSLStatus          *bool   `json:"ssl_status,omitempty"`
	Certificate        *string `json:"certificate,omitempty"`
	TLSVersion         *string `json:"tls_version,omitempty"`
	HSTSStatus         *bool   `json:"hsts_status,omitempty"`
	QUICStatus         *bool   `json:"quic_status,omitempty"`
	HSTSMaxAge         *string `json:"hsts_max_age,omitempty"`
	HSTSSubdomain      *bool   `json:"hsts_subdomain,omitempty"`
	HSTSPreload        *bool   `json:"hsts_preload,omitempty"`
	HTTPSRedirect      *bool   `json:"https_redirect,omitempty"`
	ReplaceHTTP        *bool   `json:"replace_http,omitempty"`
	CertificateKeyType *string `json:"certificate_key_type,omitempty"`
}

type Certificate struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Active      bool     `json:"active"`
	KeyType     *string  `json:"key_type"`
	DomainNames []string `json:"domain_names"`
	Issuer      string   `json:"issuer"`
	IsRevoked   bool     `json:"is_revoked"`
	ExpiryDate  string   `json:"expiry_date"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type CertificateDetail struct {
	Certificate
	CertificatePEM string `json:"certificate"`
	PrivateKeyPEM  string `json:"private_key"`
}

type CertificatesResponse struct {
	Data []Certificate `json:"data"`
}

type CertificateDetailResponse struct {
	Data CertificateDetail `json:"data"`
}

type CertificateOrder struct {
	ID          string   `json:"id"`
	OrderID     string   `json:"order_id"`
	Status      string   `json:"status"`
	DomainNames []string `json:"domain_names"`
	ExpiryDate  string   `json:"expiry_date"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type CertificateOrderResponse struct {
	Data CertificateOrder `json:"data"`
}

type CertificateOrdersResponse struct {
	Data []CertificateOrder `json:"data"`
}
