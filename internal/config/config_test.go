package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg := &Config{
		APIURL: "https://api.example.test/cdn",
	}
	cfg.SetAPIKey("test-key")
	if err := Save(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.APIKey != cfg.APIKey {
		t.Fatalf("api_key = %q, want %q", loaded.APIKey, cfg.APIKey)
	}
	if loaded.APIURL != cfg.APIURL {
		t.Fatalf("api_url = %q, want %q", loaded.APIURL, cfg.APIURL)
	}

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadMissingUsesDefaults(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "missing"))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.APIURL != DefaultAPIURL {
		t.Fatalf("api_url = %q, want %q", cfg.APIURL, DefaultAPIURL)
	}
	if cfg.APIKey != "" {
		t.Fatalf("api_key = %q, want empty", cfg.APIKey)
	}
}

func TestClearRemovesConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := &Config{APIURL: DefaultAPIURL}
	cfg.SetAPIKey("x")
	if err := Save(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	exists, err := Exists()
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if exists {
		t.Fatal("config should not exist after clear")
	}
}
