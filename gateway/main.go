package main

import (
	"log"
	"os"
)

func main() {
	cfgPath := os.Getenv("EAAP_CONFIG")
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	gw := NewGateway(cfg)

	log.Printf("[EAAP Gateway] listening on %s", cfg.ListenAddr)
	log.Printf("[EAAP Gateway] SSRF allowlist: %v", cfg.AllowedOrigins)

	if err := gw.Run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}
