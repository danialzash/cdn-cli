package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

func (c *Client) GetSslSettings(ctx context.Context, domain string) (*Ssl, error) {
	var resp SslResponse
	if err := c.get(ctx, "/ssl/"+url.PathEscape(domain), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UpdateSslSettings(ctx context.Context, domain string, req UpdateSslRequest) (*Ssl, error) {
	var resp SslResponse
	path := "/ssl/" + url.PathEscape(domain)
	if err := c.request(ctx, http.MethodPatch, path, req, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) ListCertificates(ctx context.Context, domain string, types []string) ([]Certificate, error) {
	query := url.Values{}
	for _, t := range types {
		query.Add("types", t)
	}

	var resp CertificatesResponse
	path := "/ssl/" + url.PathEscape(domain) + "/certificates"
	if err := c.get(ctx, path, query, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) GetCertificate(ctx context.Context, domain, certificateID string, showPrivateKey bool) (*CertificateDetail, error) {
	query := url.Values{}
	if showPrivateKey {
		query.Set("show_private_key", "true")
	}

	var resp CertificateDetailResponse
	path := "/ssl/" + url.PathEscape(domain) + "/certificates/" + url.PathEscape(certificateID)
	if err := c.get(ctx, path, query, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) UploadCertificate(ctx context.Context, domain, certificatePath, privateKeyPath string) error {
	path := "/ssl/" + url.PathEscape(domain) + "/certificates"
	return c.uploadCertificateFiles(ctx, path, certificatePath, privateKeyPath)
}

func (c *Client) DeleteCertificate(ctx context.Context, domain, certificateID string) error {
	path := "/ssl/" + url.PathEscape(domain) + "/certificates/" + url.PathEscape(certificateID)
	return c.request(ctx, http.MethodDelete, path, nil, nil)
}

func (c *Client) RevokeCertificate(ctx context.Context, domain, certificateID string) error {
	path := "/ssl/" + url.PathEscape(domain) + "/certificates/" + url.PathEscape(certificateID) + "/revoke"
	return c.request(ctx, http.MethodPost, path, nil, nil)
}

func (c *Client) ListCertificateOrders(ctx context.Context, domain, orderType string) ([]CertificateOrder, error) {
	query := url.Values{}
	if orderType != "" {
		query.Set("type", orderType)
	}

	var resp CertificateOrdersResponse
	path := "/ssl/" + url.PathEscape(domain) + "/orders"
	if err := c.get(ctx, path, query, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *Client) IssueCertificate(ctx context.Context, domain string) (*CertificateOrder, error) {
	var resp CertificateOrderResponse
	path := "/ssl/" + url.PathEscape(domain) + "/issue"
	if err := c.request(ctx, http.MethodPost, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *Client) RetryCertificateOrder(ctx context.Context, domain string) error {
	path := "/ssl/" + url.PathEscape(domain) + "/orders/action/retry"
	return c.request(ctx, http.MethodPost, path, nil, nil)
}

func (c *Client) uploadCertificateFiles(ctx context.Context, path, certificatePath, privateKeyPath string) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if err := addFormFile(writer, "certificate", certificatePath); err != nil {
		return err
	}
	if err := addFormFile(writer, "private_key", privateKeyPath); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close multipart writer: %w", err)
	}

	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), &body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return decodeError(respBody, resp.StatusCode)
	}
	return nil
}

func addFormFile(writer *multipart.Writer, fieldName, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", filePath, err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile(fieldName, filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("create form file %s: %w", fieldName, err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("write form file %s: %w", fieldName, err)
	}
	return nil
}
