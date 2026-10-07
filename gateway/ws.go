package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type SessionIdentity struct {
	TenantID     string `json:"tenant_id"`
	AccountID    string `json:"account_id"`
	Provider     string `json:"provider"`
	ConnectionID string `json:"connection_id"`
	Generation   uint64 `json:"generation"`
}

type pairingHello struct {
	Token string `json:"pairing_token"`
}
type sessionKey struct{ tenant, account, provider string }
type bridgeSession struct {
	conn     *websocket.Conn
	identity SessionIdentity
}

type ExtensionBridge struct {
	mu          sync.RWMutex
	sessions    map[sessionKey]*bridgeSession
	generations map[sessionKey]uint64
	usedTokens  map[string]bool
	credentials []PairingCredential
}

func NewExtensionBridge(credentials []PairingCredential) *ExtensionBridge {
	return &ExtensionBridge{sessions: make(map[sessionKey]*bridgeSession), generations: make(map[sessionKey]uint64), usedTokens: make(map[string]bool), credentials: credentials}
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") != "" }}

func (eb *ExtensionBridge) HandleExtension(w http.ResponseWriter, r *http.Request, allowedOrigin string) {
	if allowedOrigin == "" || r.Header.Get("Origin") != allowedOrigin {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(4096)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		_ = conn.Close()
		return
	}
	var hello pairingHello
	if json.Unmarshal(raw, &hello) != nil || hello.Token == "" {
		_ = conn.Close()
		return
	}
	digest := sha256.Sum256([]byte(hello.Token))
	tokenID := hex.EncodeToString(digest[:])
	eb.mu.Lock()
	if eb.usedTokens[tokenID] {
		eb.mu.Unlock()
		_ = conn.Close()
		return
	}
	var credential *PairingCredential
	for i := range eb.credentials {
		if eb.credentials[i].Token != "" && hello.Token == eb.credentials[i].Token {
			credential = &eb.credentials[i]
			break
		}
	}
	if credential == nil || credential.Generation == 0 || credential.TenantID == "" || credential.AccountID == "" || credential.Provider == "" || credential.ConnectionID == "" {
		eb.mu.Unlock()
		_ = conn.Close()
		return
	}
	key := sessionKey{credential.TenantID, credential.AccountID, credential.Provider}
	if credential.Generation <= eb.generations[key] {
		eb.mu.Unlock()
		_ = conn.Close()
		return
	}
	identity := SessionIdentity{credential.TenantID, credential.AccountID, credential.Provider, credential.ConnectionID, credential.Generation}
	session := &bridgeSession{conn: conn, identity: identity}
	eb.usedTokens[tokenID] = true
	eb.generations[key] = credential.Generation
	if old := eb.sessions[key]; old != nil {
		_ = old.conn.Close()
	}
	eb.sessions[key] = session
	eb.mu.Unlock()
	if err := conn.WriteJSON(map[string]string{"type": "pairing_accepted"}); err != nil {
		eb.mu.Lock()
		if eb.sessions[key] == session {
			delete(eb.sessions, key)
		}
		eb.mu.Unlock()
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
	eb.mu.Lock()
	if eb.sessions[key] == session {
		delete(eb.sessions, key)
	}
	eb.mu.Unlock()
	_ = conn.Close()
}

var ErrNoSession = errors.New("no matching paired extension session")

func (eb *ExtensionBridge) Dispatch(ctx context.Context, identity SessionIdentity, env EaaPEnvelope) (*EaaPResponse, error) {
	key := sessionKey{identity.TenantID, identity.AccountID, identity.Provider}
	eb.mu.RLock()
	session := eb.sessions[key]
	eb.mu.RUnlock()
	if session == nil || session.identity.ConnectionID != identity.ConnectionID || session.identity.Generation != identity.Generation {
		return nil, ErrNoSession
	}
	return nil, errors.New("external-effect dispatch disabled pending durable T4.2 grant gate")
}

type ExecutionMode string
type EaaPEnvelope struct {
	EnvelopeID    string            `json:"envelope_id"`
	ExecutionMode ExecutionMode     `json:"executionMode"`
	TargetURL     string            `json:"target_url"`
	Method        string            `json:"method"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          json.RawMessage   `json:"body,omitempty"`
	TimeoutMs     int               `json:"timeout_ms"`
	Origin        string            `json:"origin"`
}
type EaaPResponse struct {
	EnvelopeID string            `json:"envelope_id"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       json.RawMessage   `json:"body,omitempty"`
	Error      string            `json:"error,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}
