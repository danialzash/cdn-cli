package config

import "fmt"

const (
	AuthMethodAPIKey = "api_key"
	AuthMethodBearer = "bearer"
)

// NormalizeAuthMethod fills in auth_method for legacy configs that only store api_key.
func (c *Config) NormalizeAuthMethod() {
	if c.AuthMethod != "" {
		return
	}
	switch {
	case c.BearerToken != "":
		c.AuthMethod = AuthMethodBearer
	case c.APIKey != "":
		c.AuthMethod = AuthMethodAPIKey
	}
}

// IsAuthenticated reports whether stored credentials are present.
func (c *Config) IsAuthenticated() bool {
	c.NormalizeAuthMethod()
	switch c.AuthMethod {
	case AuthMethodBearer:
		return c.BearerToken != ""
	case AuthMethodAPIKey:
		return c.APIKey != ""
	default:
		return false
	}
}

// SetAPIKey stores an API key and clears any bearer token.
func (c *Config) SetAPIKey(key string) {
	c.AuthMethod = AuthMethodAPIKey
	c.APIKey = key
	c.BearerToken = ""
}

// SetBearerToken stores a bearer token and clears any API key.
func (c *Config) SetBearerToken(token string) {
	c.AuthMethod = AuthMethodBearer
	c.BearerToken = token
	c.APIKey = ""
}

// ClearCredentials removes all stored auth data.
func (c *Config) ClearCredentials() {
	c.AuthMethod = ""
	c.APIKey = ""
	c.BearerToken = ""
}

// AuthMethodLabel returns a human-readable auth method name.
func (c *Config) AuthMethodLabel() string {
	c.NormalizeAuthMethod()
	switch c.AuthMethod {
	case AuthMethodBearer:
		return "bearer"
	case AuthMethodAPIKey:
		return "api-key"
	default:
		return "none"
	}
}

// ValidateAuthMethod returns an error for unknown auth_method values.
func ValidateAuthMethod(method string) error {
	switch method {
	case "", AuthMethodAPIKey, AuthMethodBearer:
		return nil
	default:
		return fmt.Errorf("invalid auth_method %q: use api_key or bearer", method)
	}
}
