package config

import "testing"

func TestBearerSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg := &Config{
		APIURL: DefaultAPIURL,
	}
	cfg.SetBearerToken("jwt-token")

	if err := Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.AuthMethod != AuthMethodBearer {
		t.Fatalf("auth_method = %q, want %q", loaded.AuthMethod, AuthMethodBearer)
	}
	if loaded.BearerToken != "jwt-token" {
		t.Fatalf("bearer_token = %q", loaded.BearerToken)
	}
	if loaded.APIKey != "" {
		t.Fatalf("api_key should be empty, got %q", loaded.APIKey)
	}
}

func TestLegacyAPIKeyConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg := &Config{
		APIKey: "legacy-key",
		APIURL: DefaultAPIURL,
	}
	if err := Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !loaded.IsAuthenticated() {
		t.Fatal("expected authenticated legacy config")
	}
	if loaded.AuthMethod != AuthMethodAPIKey {
		t.Fatalf("auth_method = %q, want %q", loaded.AuthMethod, AuthMethodAPIKey)
	}
}

func TestSetAPIKeyClearsBearer(t *testing.T) {
	cfg := &Config{}
	cfg.SetBearerToken("token")
	cfg.SetAPIKey("key")

	if cfg.BearerToken != "" {
		t.Fatalf("bearer_token should be cleared")
	}
	if cfg.AuthMethod != AuthMethodAPIKey {
		t.Fatalf("auth_method = %q", cfg.AuthMethod)
	}
}
