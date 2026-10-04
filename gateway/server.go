package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Gateway struct {
	cfg          *Config
	llm          *LLMClient
	queue        *ActionQueue
	bridge       *ExtensionBridge
	mu           sync.RWMutex
	specs        map[string]map[string]interface{}
	routeOrigins map[string]string
}

func NewGateway(cfg *Config) *Gateway {
	return &Gateway{
		cfg:          cfg,
		llm:          NewLLMClient(cfg),
		queue:        NewActionQueue(cfg),
		bridge:       NewExtensionBridge(),
		specs:        make(map[string]map[string]interface{}),
		routeOrigins: make(map[string]string),
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
		g.specs[key] = spec
		g.routeOrigins[key] = samples[0].Host
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
	for _, frag := range g.specs {
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
	routeKey := strings.ToUpper(r.Method) + " " + normalizeRequestPath(r.URL.Path)
	g.mu.RLock()
	_, known := g.specs[routeKey]
	origin := g.routeOrigins[routeKey]
	g.mu.RUnlock()
	if !known {
		http.Error(w, fmt.Sprintf("no inferred schema for %s", routeKey), http.StatusNotFound)
		return
	}
	if !isAllowedOrigin(g.cfg.AllowedOrigins, origin) {
		http.Error(w, "route origin is not allowlisted", http.StatusForbidden)
		return
	}

	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
	}

	env := EaaPEnvelope{
		EnvelopeID:    newID(),
		ExecutionMode: ModeSyntheticFetch,
		TargetURL:     origin + r.URL.RequestURI(),
		Method:        r.Method,
		Headers:       buildForwardHeaders(r),
		Body:          body,
		TimeoutMs:     30000,
		Origin:        origin,
	}
	if r.Header.Get("X-EAAP-Mode") == "dom-simulation" {
		env.ExecutionMode = ModeDOMSimulation
		env.CSSTarget = r.Header.Get("X-EAAP-CSS-Target")
		env.TriggerEvent = "click"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var response *EaaPResponse
	if err := g.queue.Enqueue(ctx, func() error {
		var err error
		response, err = g.bridge.Dispatch(ctx, env)
		return err
	}); err != nil {
		http.Error(w, "execution failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if response == nil {
		http.Error(w, "extension returned no response", http.StatusBadGateway)
		return
	}
	if response.Error != "" {
		http.Error(w, response.Error, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	status := response.StatusCode
	if status < 100 || status > 599 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(response.Body)
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

func buildForwardHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	for k, values := range r.Header {
		key := strings.ToLower(k)
		if key == "host" || key == "connection" || key == "x-eaap-mode" ||
			key == "x-eaap-css-target" || key == "content-length" {
			continue
		}
		headers[k] = strings.Join(values, ",")
	}
	return headers
}

func (g *Gateway) handleExtension(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != g.cfg.ExtensionWSOrigin {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	g.bridge.HandleExtension(w, r, g.cfg.ExtensionWSOrigin)
}
