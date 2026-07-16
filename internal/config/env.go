package config

import (
	"fmt"
	"os"
)

const (
	EnvAPIKey = "VERGECLOUD_API_KEY"
	EnvToken  = "VERGECLOUD_TOKEN"
	EnvAPIURL = "VERGECLOUD_API_URL"
)

// ApplyEnv overlays environment variables onto cfg.
// Flags take precedence when applied after this in loadRuntimeConfig.
func ApplyEnv(cfg *Config) error {
	envKey := os.Getenv(EnvAPIKey)
	envToken := os.Getenv(EnvToken)

	if envKey != "" && envToken != "" {
		return fmt.Errorf("set only one of %s or %s", EnvAPIKey, EnvToken)
	}
	if envKey != "" {
		cfg.SetAPIKey(envKey)
	}
	if envToken != "" {
		cfg.SetBearerToken(envToken)
	}
	if v := os.Getenv(EnvAPIURL); v != "" {
		cfg.APIURL = v
	}
	return nil
}
