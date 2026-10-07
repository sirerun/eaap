package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Gateway struct {
	cfg        *Config
	llm        *LLMClient
	bridge     *ExtensionBridge
	mu         sync.RWMutex
	candidates map[string]map[string]interface{}
	operations map[string]PromotedOperation
}

// PromotedOperation is server-owned executable metadata. Discovery candidates
// never enter this registry automatically; T4.2 must also gate execution.
type PromotedOperation struct {
	ID            string
	Version       string
	Origin        string
	Method        string
	RequestSchema map[string]interface{}
}

func NewGateway(cfg *Config) *Gateway {
	return &Gateway{
		cfg:        cfg,
		llm:        NewLLMClient(cfg),
		bridge:     NewExtensionBridge(cfg.PairingCredentials),
		candidates: make(map[string]map[string]interface{}),
		operations: make(map[string]PromotedOperation),
	}
}

func (g *Gateway) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/extension", g.handleExtension)
	mux.HandleFunc("/internal/discovery", g.handleDiscoveryIngest)
	mux.HandleFunc("/api/", g.handleExternalRequest)
	mux.HandleFunc("/spec", g.handleGetSpec)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return http.ListenAndServe(g.cfg.ListenAddr, mux)
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

type DiscoveryBatch struct {
	Samples []TrafficSample `json:"samples"`
}

func (g *Gateway) handleDiscoveryIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var batch DiscoveryBatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&batch); err != nil {
		http.Error(w, "invalid discovery batch: "+err.Error(), http.StatusBadRequest)
		return
	}

	allowed := make([]TrafficSample, 0, len(batch.Samples))
	for i := range batch.Samples {
		s := &batch.Samples[i]
		if s.Template == "" {
			s.Template = s.URLTemplate
		}
		s.Template = normalizeRequestPath(s.Template)
		if !isAllowedOrigin(g.cfg.AllowedOrigins, s.Host) {
			continue
		}
		s.RequestHead = SanitizeHeaders(s.RequestHead, g.cfg.SanitizeHeaders)
		s.RequestBody = SanitizeBody(s.RequestBody, 4096)
		s.ResponseBody = SanitizeBody(s.ResponseBody, 4096)
		allowed = append(allowed, *s)
	}

	grouped := GroupSamples(allowed, 3)
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()

	for key, samples := range grouped {
		spec, err := g.llm.InferSpec(ctx, samples)
		if err != nil {
			log.Printf("[EAAP] inference failed for %s: %v", key, err)
			continue
		}
		g.mu.Lock()
		g.candidates[key] = spec
		g.mu.Unlock()
		log.Printf("[EAAP] schema inferred for route %s", key)
	}
	w.WriteHeader(http.StatusAccepted)
}

func (g *Gateway) handleGetSpec(w http.ResponseWriter, _ *http.Request) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	merged := map[string]interface{}{
		"openapi": "3.0.3",
		"info":    map[string]interface{}{"title": "EaaP Inferred API", "version": "1.0.0"},
		"paths":   map[string]interface{}{},
	}
	paths := merged["paths"].(map[string]interface{})
	for _, frag := range g.candidates {
		if fp, ok := frag["paths"].(map[string]interface{}); ok {
			for p, def := range fp {
				paths[p] = def
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(merged)
}

func (g *Gateway) handleExternalRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "no explicitly promoted operation has an enabled T4.2 durable grant gate", http.StatusServiceUnavailable)
}

func normalizeRequestPath(path string) string {
	template, _ := NormalizeURL(path)
	return template
}

func isAllowedOrigin(allowed []string, candidate string) bool {
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	origin := parsed.Scheme + "://" + parsed.Host
	for _, value := range allowed {
		if origin == strings.TrimRight(value, "/") {
			return true
		}
	}
	return false
}

func (g *Gateway) handleExtension(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != g.cfg.ExtensionWSOrigin {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	g.bridge.HandleExtension(w, r, g.cfg.ExtensionWSOrigin)
}
