package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestPairingIsIdentityScopedSingleUseAndGenerationFenced(t *testing.T) {
	bridge := NewExtensionBridge([]PairingCredential{
		{Token: "fixture-one", TenantID: "tenant-a", AccountID: "account-a", Provider: "fixture", ConnectionID: "connection-a", Generation: 1},
		{Token: "fixture-two", TenantID: "tenant-b", AccountID: "account-b", Provider: "fixture", ConnectionID: "connection-b", Generation: 3},
	})
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
	defer first.Close()
	second, err := connect("fixture-two", "chrome-extension://fixture")
	if err != nil {
		t.Fatalf("second pairing: %v", err)
	}
	defer second.Close()
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
	defer conn.Close()
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
	g := NewGateway(DefaultConfig())
	for _, path := range []string{"/api/post", "/api/post?origin=https://attacker.invalid"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"operation":"publish","origin":"https://attacker.invalid","mode":"DOM_SIMULATION","selector":"#submit"}`))
		req.Header.Set("X-EAAP-Mode", "dom-simulation")
		req.Header.Set("X-EAAP-CSS-Target", "#submit")
		recorder := httptest.NewRecorder()
		g.handleExternalRequest(recorder, req)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d, want fail-closed 503", recorder.Code)
		}
	}
}
