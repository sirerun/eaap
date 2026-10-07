package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config implements RFC Section 6 requirements: rate limiting jitter,
// sanitization, and allowlist enforcement.
type Config struct {
	ListenAddr         string              `json:"listen_addr"`
	LLMAPIURL          string              `json:"llm_api_url"`
	LLMAPIKeyEnv       string              `json:"llm_api_key_env"`
	LLMAPIKey          string              `json:"-"`
	LLMModel           string              `json:"llm_model"`
	AllowedOrigins     []string            `json:"allowed_origins"`  // RFC 6.4 SSRF allowlist
	JitterMinMs        int                 `json:"jitter_min_ms"`    // RFC 6.2, default 2000
	JitterMaxMs        int                 `json:"jitter_max_ms"`    // RFC 6.2, default 5000
	SanitizeHeaders    []string            `json:"sanitize_headers"` // RFC 6.3
	ExtensionWSOrigin  string              `json:"extension_ws_origin"`
	PairingCredentials []PairingCredential `json:"pairing_credentials"`
	PromotedOperations []PromotedOperation `json:"promoted_operations"`
	PairingStateRoot   string              `json:"pairing_state_root"`
}

type PairingCredential struct {
	TokenEnv     string    `json:"token_env"`
	Token        string    `json:"-"`
	TenantID     string    `json:"tenant_id"`
	AccountID    string    `json:"account_id"`
	Provider     string    `json:"provider"`
	ConnectionID string    `json:"connection_id"`
	Generation   uint64    `json:"generation"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:        ":8080",
		LLMAPIURL:         "https://api.openai.com/v1/chat/completions",
		LLMAPIKeyEnv:      "EAAP_LLM_API_KEY",
		LLMModel:          "gpt-4o",
		AllowedOrigins:    []string{"https://app.internal.example.com"},
		JitterMinMs:       2000,
		JitterMaxMs:       5000,
		SanitizeHeaders:   []string{"authorization", "cookie", "x-api-key", "proxy-authorization"},
		ExtensionWSOrigin: "chrome-extension://eaap-extension",
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, err
		}
	}
	for i := range cfg.PairingCredentials {
		name := cfg.PairingCredentials[i].TokenEnv
		if name == "" {
			return nil, fmt.Errorf("pairing credential %d has no token_env", i)
		}
		cfg.PairingCredentials[i].Token = os.Getenv(name)
	}
	if cfg.PairingStateRoot == "" {
		return nil, fmt.Errorf("pairing_state_root must be owner configured")
	}
	if err := validateGatewayConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
