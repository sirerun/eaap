package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ExecutionMode per RFC Section 4.
type ExecutionMode string

const (
	ModeSyntheticFetch ExecutionMode = "SYNTHETIC_FETCH"
	ModeDOMSimulation  ExecutionMode = "DOM_SIMULATION"
)

// EaaPEnvelope is the wire format sent to the Extension (RFC 3.2 Phase 2).
type EaaPEnvelope struct {
	EnvelopeID    string            `json:"envelope_id"`
	ExecutionMode ExecutionMode     `json:"executionMode"`
	TargetURL     string            `json:"target_url"`
	Method        string            `json:"method"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          json.RawMessage   `json:"body,omitempty"`
	CSSTarget     string            `json:"css_target,omitempty"`   // DOM_SIMULATION
	InputFields   map[string]string `json:"input_fields,omitempty"` // DOM_SIMULATION
	TriggerEvent  string            `json:"trigger_event,omitempty"`
	TimeoutMs     int               `json:"timeout_ms"`
	Origin        string            `json:"origin"` // validated against allowlist
}

// EaaPResponse is the Extension's reply.
type EaaPResponse struct {
	EnvelopeID  string            `json:"envelope_id"`
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        json.RawMessage   `json:"body,omitempty"`
	Error       string            `json:"error,omitempty"`
	DOMMutation string            `json:"dom_mutation,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // extension origin checked manually
}

// ExtensionBridge manages the single authenticated browser session connection.
type ExtensionBridge struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func NewExtensionBridge() *ExtensionBridge { return &ExtensionBridge{} }

// HandleExtension accepts the extension's persistent WS connection.
func (eb *ExtensionBridge) HandleExtension(w http.ResponseWriter, r *http.Request, allowedOrigin string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	if allowedOrigin != "" && r.Header.Get("Origin") != allowedOrigin {
		conn.Close()
		return
	}
	eb.mu.Lock()
	if eb.conn != nil {
		eb.conn.Close()
	}
	eb.conn = conn
	eb.mu.Unlock()
	log.Printf("[EAAP] Extension connected")
}

// Dispatch sends an envelope and awaits the matching response (RFC Phase 2, step 3-4).
func (eb *ExtensionBridge) Dispatch(ctx context.Context, env EaaPEnvelope) (*EaaPResponse, error) {
	eb.mu.Lock()
	conn := eb.conn
	eb.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("no extension session connected")
	}

	respCh := make(chan EaaPResponse, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var resp EaaPResponse
			if json.Unmarshal(raw, &resp) == nil && resp.EnvelopeID == env.EnvelopeID {
				select {
				case respCh <- resp:
				default:
				}
				return
			}
		}
	}()

	eb.mu.Lock()
	err := conn.WriteJSON(env)
	eb.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("dispatch: %w", err)
	}

	select {
	case resp := <-respCh:
		return &resp, nil
	case <-done:
		return nil, fmt.Errorf("extension disconnected")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
