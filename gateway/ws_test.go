package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestPairingIsIdentityScopedSingleUseAndGenerationFenced(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-pairing-state")
	bridge := NewExtensionBridge([]PairingCredential{
		{Token: "fixture-one", TenantID: "tenant-a", AccountID: "account-a", Provider: "fixture", ConnectionID: "connection-a", Generation: 1, ExpiresAt: time.Now().Add(time.Hour)},
		{Token: "fixture-two", TenantID: "tenant-b", AccountID: "account-b", Provider: "fixture", ConnectionID: "connection-b", Generation: 3, ExpiresAt: time.Now().Add(time.Hour)},
	}, root)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridge.HandleExtension(w, r, "chrome-extension://fixture")
	}))
	t.Cleanup(server.Close)
	connect := func(token, origin string) (*websocket.Conn, error) {
		headers := http.Header{"Origin": []string{origin}}
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), headers)
		if err == nil {
			err = conn.WriteJSON(pairingHello{Token: token})
		}
		return conn, err
	}
	first, err := connect("fixture-one", "chrome-extension://fixture")
	if err != nil {
		t.Fatalf("first pairing: %v", err)
	}
	defer func() { _ = first.Close() }()
	second, err := connect("fixture-two", "chrome-extension://fixture")
	if err != nil {
		t.Fatalf("second pairing: %v", err)
	}
	defer func() { _ = second.Close() }()
	waitForSessions(t, bridge, 2)

	if rejected := pairingRejected(connect, "fixture-one", "chrome-extension://fixture"); !rejected {
		t.Fatal("pairing replay was accepted")
	}
	if rejected := pairingRejected(connect, "forged", "chrome-extension://fixture"); !rejected {
		t.Fatal("forged pairing was accepted")
	}
	if rejected := pairingRejected(connect, "fixture-one", "https://wrong.example"); !rejected {
		t.Fatal("wrong origin was accepted")
	}

	ctx := context.Background()
	base := EaaPEnvelope{EnvelopeID: "fixture", TargetURL: "https://app.fixture.invalid/write", Method: "POST"}
	if _, err := bridge.Dispatch(ctx, SessionIdentity{TenantID: "tenant-a", AccountID: "account-a", Provider: "fixture", ConnectionID: "connection-a", Generation: 1}, base); err == nil || !strings.Contains(err.Error(), "T4.2") {
		t.Fatalf("effect dispatch did not fail closed: %v", err)
	}
	for _, identity := range []SessionIdentity{
		{TenantID: "wrong", AccountID: "account-a", Provider: "fixture", ConnectionID: "connection-a", Generation: 1},
		{TenantID: "tenant-a", AccountID: "wrong", Provider: "fixture", ConnectionID: "connection-a", Generation: 1},
		{TenantID: "tenant-a", AccountID: "account-a", Provider: "wrong", ConnectionID: "connection-a", Generation: 1},
		{TenantID: "tenant-a", AccountID: "account-a", Provider: "fixture", ConnectionID: "wrong", Generation: 1},
		{TenantID: "tenant-a", AccountID: "account-a", Provider: "fixture", ConnectionID: "connection-a", Generation: 2},
	} {
		if _, err := bridge.Dispatch(ctx, identity, base); !errors.Is(err, ErrNoSession) {
			t.Fatalf("mismatched identity/generation dispatched: %v", err)
		}
	}
}

func pairingRejected(connect func(string, string) (*websocket.Conn, error), token, origin string) bool {
	conn, err := connect(token, origin)
	if err != nil {
		return true
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	_, _, err = conn.ReadMessage()
	return err != nil
}

func waitForSessions(t *testing.T, bridge *ExtensionBridge, count int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		bridge.mu.RLock()
		got := len(bridge.sessions)
		bridge.mu.RUnlock()
		if got == count {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("sessions=%d, want %d", got, count)
		case <-ticker.C:
		}
	}
}

func TestExternalRequestsNeverDispatchCallerOverrides(t *testing.T) {
	g := NewGateway(&Config{
		AllowedOrigins: []string{"https://app.fixture.invalid"},
		PromotedOperations: []PromotedOperation{{
			ID: "fixture.publish", Version: "1", Path: "/api/post", Origin: "https://app.fixture.invalid", Method: http.MethodPost,
			RequestSchema: map[string]RequestField{"text": {Type: JSONString, Required: true}},
		}},
	})
	tests := []struct {
		name, path, body string
		header           bool
		want             int
	}{
		{name: "caller overrides", path: "/api/post", body: `{"text":"safe","origin":"https://attacker.invalid","mode":"DOM_SIMULATION","selector":"#submit"}`, want: http.StatusBadRequest},
		{name: "query override", path: "/api/post?origin=https://attacker.invalid", body: `{"text":"safe"}`, want: http.StatusBadRequest},
		{name: "override header", path: "/api/post", body: `{"text":"safe"}`, header: true, want: http.StatusBadRequest},
		{name: "valid typed request remains gated", path: "/api/post", body: `{"text":"fixture"}`, want: http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			if tc.header {
				req.Header.Set("X-EAAP-Mode", "dom-simulation")
			}
			recorder := httptest.NewRecorder()
			g.handleExternalRequest(recorder, req)
			if recorder.Code != tc.want {
				t.Fatalf("status=%d, want %d", recorder.Code, tc.want)
			}
		})
	}
}

func TestTypedRequestRejectsUnknownWrongAndNestedFields(t *testing.T) {
	schema := map[string]RequestField{
		"text":     {Type: JSONString, Required: true},
		"metadata": {Type: JSONObject, Properties: map[string]RequestField{"role": {Type: JSONString, Required: true}}},
	}
	for _, tc := range []struct{ name, body string }{
		{name: "unknown field", body: `{"text":"ok","mode":"DOM_SIMULATION"}`},
		{name: "wrong scalar type", body: `{"text":42}`},
		{name: "missing required field", body: `{"metadata":{"role":"fixture"}}`},
		{name: "unknown nested field", body: `{"text":"ok","metadata":{"role":"fixture","selector":"#submit"}}`},
		{name: "trailing JSON", body: `{"text":"ok"} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeTypedRequest([]byte(tc.body), schema); err == nil {
				t.Fatal("invalid request was accepted")
			}
		})
	}
	if _, err := decodeTypedRequest([]byte(`{"text":"ok","metadata":{"role":"fixture"}}`), schema); err != nil {
		t.Fatalf("valid strict request rejected: %v", err)
	}
}

func TestPairingConsumptionAndInstallationAreOrdered(t *testing.T) {
	bridge := NewExtensionBridge([]PairingCredential{
		{Token: "old-token", TenantID: "tenant", AccountID: "account", Provider: "fixture", ConnectionID: "old", Generation: 8, ExpiresAt: time.Now().Add(time.Hour)},
		{Token: "new-token", TenantID: "tenant", AccountID: "account", Provider: "fixture", ConnectionID: "new", Generation: 9, ExpiresAt: time.Now().Add(time.Hour)},
	}, filepath.Join(t.TempDir(), "state"))
	oldConsumed, newAttempt, releaseOld := make(chan struct{}), make(chan struct{}), make(chan struct{})
	bridge.pairingHook = func(stage string, generation uint64) {
		if stage == "after-consume" && generation == 8 {
			close(oldConsumed)
			<-releaseOld
		}
		if stage == "before-consume" && generation == 9 {
			close(newAttempt)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bridge.HandleExtension(w, r, "chrome-extension://fixture")
	}))
	defer server.Close()
	defer func() {
		select {
		case <-releaseOld:
		default:
			close(releaseOld)
		}
	}()
	connect := func(token string) *websocket.Conn {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), http.Header{"Origin": []string{"chrome-extension://fixture"}})
		if err != nil {
			t.Fatal(err)
		}
		if err = conn.WriteJSON(pairingHello{Token: token}); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	old := connect("old-token")
	defer func() { _ = old.Close() }()
	select {
	case <-oldConsumed:
	case <-time.After(2 * time.Second):
		t.Fatal("old pairing did not consume")
	}
	newer := connect("new-token")
	defer func() { _ = newer.Close() }()
	newAcknowledged := make(chan error, 1)
	go func() { _, _, err := newer.ReadMessage(); newAcknowledged <- err }()
	select {
	case <-newAttempt:
	case <-time.After(2 * time.Second):
		close(releaseOld)
		t.Fatal("new pairing did not attempt")
	}
	// Holding the earlier consume/install section must prevent the newer one
	// from acknowledging before the earlier section has completed.
	select {
	case err := <-newAcknowledged:
		close(releaseOld)
		t.Fatalf("new pairing bypassed paused consume/install section: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseOld)
	select {
	case err := <-newAcknowledged:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new pairing not acknowledged")
	}
	bridge.mu.RLock()
	current := bridge.sessions[sessionKey{"tenant", "account", "fixture"}]
	bridge.mu.RUnlock()
	if current == nil || current.identity.Generation != 9 {
		t.Fatalf("newest generation not retained: %+v", current)
	}
}
