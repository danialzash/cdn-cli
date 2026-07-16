package config

import (
	"testing"
)

func TestApplyEnvAPIKey(t *testing.T) {
	t.Setenv(EnvAPIKey, "vc_from_env")
	t.Setenv(EnvToken, "")
	t.Setenv(EnvAPIURL, "https://api.example.test/cdn")

	cfg := &Config{APIURL: DefaultAPIURL}
	if err := ApplyEnv(cfg); err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if !cfg.IsAuthenticated() || cfg.APIKey != "vc_from_env" {
		t.Fatalf("api_key = %q, authenticated = %v", cfg.APIKey, cfg.IsAuthenticated())
	}
	if cfg.APIURL != "https://api.example.test/cdn" {
		t.Fatalf("api_url = %q", cfg.APIURL)
	}
}

func TestApplyEnvBothCredentialsRejected(t *testing.T) {
	t.Setenv(EnvAPIKey, "vc_key")
	t.Setenv(EnvToken, "jwt_token")

	cfg := &Config{}
	if err := ApplyEnv(cfg); err == nil {
		t.Fatal("expected error when both env credentials are set")
	}
}
