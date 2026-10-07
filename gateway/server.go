package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
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
	ID            string                  `json:"id"`
	Version       string                  `json:"version"`
	Path          string                  `json:"path"`
	Origin        string                  `json:"origin"`
	Method        string                  `json:"method"`
	RequestSchema map[string]RequestField `json:"request_schema"`
}

type JSONValueType string

const (
	JSONString  JSONValueType = "string"
	JSONNumber  JSONValueType = "number"
	JSONInteger JSONValueType = "integer"
	JSONBoolean JSONValueType = "boolean"
	JSONObject  JSONValueType = "object"
	JSONArray   JSONValueType = "array"
)

type RequestField struct {
	Type       JSONValueType           `json:"type"`
	Required   bool                    `json:"required"`
	Properties map[string]RequestField `json:"properties,omitempty"`
	Items      *RequestField           `json:"items,omitempty"`
}

func NewGateway(cfg *Config) *Gateway {
	gw := &Gateway{
		cfg:        cfg,
		llm:        NewLLMClient(cfg),
		bridge:     NewExtensionBridge(cfg.PairingCredentials, cfg.PairingStateRoot),
		candidates: make(map[string]map[string]interface{}),
		operations: make(map[string]PromotedOperation),
	}
	for _, operation := range cfg.PromotedOperations {
		gw.operations[operationKey(operation.Method, operation.Path)] = operation
	}
	return gw
}

func validateGatewayConfig(cfg *Config) error {
	seen := make(map[string]bool, len(cfg.PromotedOperations))
	for _, operation := range cfg.PromotedOperations {
		if err := validatePromotedOperation(cfg, operation); err != nil {
			return fmt.Errorf("invalid promoted operation %q: %w", operation.ID, err)
		}
		key := operationKey(operation.Method, operation.Path)
		if seen[key] {
			return fmt.Errorf("duplicate promoted operation route %q", key)
		}
		seen[key] = true
	}
	for i, credential := range cfg.PairingCredentials {
		if credential.Token == "" || len(credential.Token) < 32 || credential.TenantID == "" || credential.AccountID == "" || credential.Provider == "" || credential.ConnectionID == "" || credential.Generation == 0 || credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(time.Now()) {
			return fmt.Errorf("invalid pairing credential %d", i)
		}
	}
	return nil
}

func operationKey(method, path string) string { return strings.ToUpper(method) + " " + path }

func validatePromotedOperation(cfg *Config, operation PromotedOperation) error {
	if operation.ID == "" || operation.Version == "" || operation.Path == "" || !strings.HasPrefix(operation.Path, "/api/") || strings.ContainsAny(operation.Path, "?#") {
		return fmt.Errorf("operation identity and exact /api path are required")
	}
	method := strings.ToUpper(operation.Method)
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return fmt.Errorf("unsupported operation method")
	}
	if !isAllowedOrigin(cfg.AllowedOrigins, operation.Origin) {
		return fmt.Errorf("operation origin is not allowlisted")
	}
	reserved := map[string]bool{
		"origin": true, "target_url": true, "headers": true, "mode": true, "executionmode": true,
		"selector": true, "css_target": true, "input_fields": true, "session": true, "session_generation": true,
		"tenant_id": true, "account_id": true, "provider": true, "connection_id": true, "principal_id": true,
		"operation": true, "operation_id": true, "operation_version": true, "destination_id": true,
	}
	if operation.RequestSchema == nil {
		return fmt.Errorf("request schema is required")
	}
	if err := validateRequestSchema(operation.RequestSchema, reserved); err != nil {
		return err
	}
	return nil
}

func validateRequestSchema(schema map[string]RequestField, reserved map[string]bool) error {
	for name, field := range schema {
		if name == "" || reserved[strings.ToLower(name)] {
			return fmt.Errorf("request field %q is reserved", name)
		}
		switch field.Type {
		case JSONString, JSONNumber, JSONInteger, JSONBoolean:
			if field.Properties != nil || field.Items != nil {
				return fmt.Errorf("scalar field %q cannot define children", name)
			}
		case JSONObject:
			if field.Properties == nil || field.Items != nil {
				return fmt.Errorf("object field %q requires properties", name)
			}
			if err := validateRequestSchema(field.Properties, reserved); err != nil {
				return err
			}
		case JSONArray:
			if field.Items == nil || field.Properties != nil {
				return fmt.Errorf("array field %q requires an item schema", name)
			}
			if err := validateRequestSchema(map[string]RequestField{"item": *field.Items}, reserved); err != nil {
				return err
			}
		default:
			return fmt.Errorf("request field %q has unsupported type", name)
		}
	}
	return nil
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
		s.ParamValues = nil
		s.RequestHead = discoveryHeaderShape(s.RequestHead)
		s.RequestBody = discoveryBodyShape(s.RequestBody)
		s.ResponseHead = nil
		s.ResponseBody = ""
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
	key := operationKey(r.Method, r.URL.Path)
	g.mu.RLock()
	operation, exists := g.operations[key]
	g.mu.RUnlock()
	if !exists {
		http.Error(w, "no promoted operation matches this method and path", http.StatusNotFound)
		return
	}
	if !isAllowedOrigin(g.cfg.AllowedOrigins, operation.Origin) {
		http.Error(w, "promoted operation origin is not allowlisted", http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not part of the promoted typed request", http.StatusBadRequest)
		return
	}
	for name := range r.Header {
		key := strings.ToLower(name)
		if key != "content-type" && key != "accept" {
			http.Error(w, "caller execution overrides are prohibited", http.StatusBadRequest)
			return
		}
	}
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "typed request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
	}
	fields, err := decodeTypedRequest(raw, operation.RequestSchema)
	if err != nil {
		http.Error(w, "invalid typed operation request: "+err.Error(), http.StatusBadRequest)
		return
	}
	_ = fields // Typed admission is complete; T4.2 still forbids effect dispatch.
	http.Error(w, "external effects disabled pending T4.2 durable grant gate", http.StatusServiceUnavailable)
}

func decodeTypedRequest(raw []byte, schema map[string]RequestField) (map[string]json.RawMessage, error) {
	values := make(map[string]json.RawMessage)
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		if err := decoder.Decode(&values); err != nil {
			return nil, fmt.Errorf("body must be a JSON object: %w", err)
		}
		var extra interface{}
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("body contains trailing JSON data")
		}
	}
	if err := validateObjectValues(values, schema); err != nil {
		return nil, err
	}
	return values, nil
}

func validateObjectValues(values map[string]json.RawMessage, schema map[string]RequestField) error {
	for name := range values {
		if _, ok := schema[name]; !ok {
			return fmt.Errorf("unknown field %q", name)
		}
	}
	for name, field := range schema {
		rawValue, ok := values[name]
		if !ok {
			if field.Required {
				return fmt.Errorf("required field %q is missing", name)
			}
			continue
		}
		var value interface{}
		decoder := json.NewDecoder(bytes.NewReader(rawValue))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("field %q is invalid JSON", name)
		}
		valid := false
		switch field.Type {
		case JSONString:
			_, valid = value.(string)
		case JSONNumber:
			_, valid = value.(json.Number)
		case JSONInteger:
			if n, ok := value.(json.Number); ok {
				_, err := n.Int64()
				valid = err == nil
			}
		case JSONBoolean:
			_, valid = value.(bool)
		case JSONObject:
			if _, ok := value.(map[string]interface{}); ok {
				var nested map[string]json.RawMessage
				if err := json.Unmarshal(rawValue, &nested); err == nil && validateObjectValues(nested, field.Properties) == nil {
					valid = true
				}
			}
		case JSONArray:
			if array, ok := value.([]interface{}); ok {
				valid = true
				for _, item := range array {
					encoded, err := json.Marshal(item)
					if err != nil || validateObjectValues(map[string]json.RawMessage{"item": encoded}, map[string]RequestField{"item": *field.Items}) != nil {
						valid = false
						break
					}
				}
			}
		}
		if !valid {
			return fmt.Errorf("field %q does not match its strict %s schema", name, field.Type)
		}
	}
	return nil
}

func normalizeRequestPath(path string) string {
	template, _ := NormalizeURL(path)
	return template
}

func discoveryHeaderShape(headers map[string]string) map[string]string {
	result := map[string]string{}
	for name, value := range headers {
		if strings.EqualFold(name, "content-type") {
			mediaType := strings.TrimSpace(strings.Split(value, ";")[0])
			if len(mediaType) <= 80 && regexp.MustCompile(`^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$`).MatchString(mediaType) {
				result["content-type"] = mediaType
			}
		}
	}
	return result
}

func discoveryBodyShape(raw string) string {
	if raw == "" {
		return ""
	}
	var value interface{}
	if json.Unmarshal([]byte(raw), &value) != nil {
		return `"unstructured"`
	}
	shape := func(v interface{}) interface{} { return bodyValueType(v) }
	encoded, err := json.Marshal(shape(value))
	if err != nil {
		return `"unknown"`
	}
	return string(encoded)
}

func bodyValueType(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for key, child := range v {
			if sensitiveDiscoveryName(key) || !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`).MatchString(key) {
				out["<sensitive-field>"] = bodyValueType(child)
			} else {
				out[key] = bodyValueType(child)
			}
		}
		return out
	case []interface{}:
		if len(v) == 0 {
			return "array<unknown>"
		}
		return "array<" + fmt.Sprint(bodyValueType(v[0])) + ">"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

func sensitiveDiscoveryName(name string) bool {
	n := strings.ToLower(name)
	for _, part := range []string{"password", "passwd", "token", "secret", "auth", "cookie", "credential", "api_key", "apikey", "email", "phone"} {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
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
