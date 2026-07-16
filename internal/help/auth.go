package help

import "fmt"

const PanelURL = "https://panel.vergecloud.dev"

// APIKeyGuide returns step-by-step instructions for creating an API key.
func APIKeyGuide() string {
	return fmt.Sprintf(`How to get a VergeCloud API key

1. Sign in to the VergeCloud panel:
   %s

2. Open your organization (top-left org switcher if you belong to several).

3. Go to Organization settings → API Keys.

4. Create a new API key and copy it immediately (it is shown only once).

5. Log in with the CLI:
   verge auth login --api-key <your-api-key>

Alternative: use a JWT bearer token from your session:
   verge auth login --token <your-jwt>

Check authentication:
   verge auth status

Config file: ~/.config/vergecloud/config.yaml (mode 0600)
`, PanelURL)
}

// GettingStartedGuide returns install, update, auth, and first-command steps.
func GettingStartedGuide() string {
	return fmt.Sprintf(`Getting started with the VergeCloud CDN CLI

INSTALL

  curl -fsSL https://raw.githubusercontent.com/danialzash/cdn-cli/main/scripts/install.sh | sh

  Manual download: https://github.com/danialzash/cdn-cli/releases

UPDATE

  verge update --check
  verge update

AUTHENTICATE

  verge auth api-key
  verge auth login --api-key <key>
  verge auth login --token <jwt>
  verge auth status

API keys are created in the panel:
  %s → Organization → API Keys

FIRST COMMANDS

  verge domains list
  verge dns list example.com
  verge reports traffic example.com --period 24h
  verge --help
`, PanelURL)
}
