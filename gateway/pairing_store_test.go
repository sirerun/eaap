package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPairingConsumptionAndGenerationSurviveRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	c := PairingCredential{Token: "not-a-real-token-fixture", TenantID: "tenant", AccountID: "account", Provider: "provider", ConnectionID: "connection-1", Generation: 7, ExpiresAt: time.Now().Add(time.Hour)}
	first, err := newPairingStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.consume(c.Token, c); err != nil {
		t.Fatal(err)
	}
	restarted, err := newPairingStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.consume(c.Token, c); err == nil {
		t.Fatal("replayed token accepted after store restart")
	}
	c.Token, c.ConnectionID, c.Generation = "another-fixture-token", "connection-2", 7
	if err := restarted.consume(c.Token, c); err == nil {
		t.Fatal("same generation accepted for another connection")
	}
	c.Token, c.Generation = "next-fixture-token", 8
	if err := restarted.consume(c.Token, c); err != nil {
		t.Fatalf("next generation rejected: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "pairing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || strings.Contains(string(raw), c.Token) || strings.Contains(string(raw), "not-a-real-token-fixture") {
		t.Fatal("pairing state is empty or contains raw token")
	}
}

func TestPairingStateFailsClosedWhenCorruptOrExpired(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	s, err := newPairingStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pairing.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	c := PairingCredential{Token: "expired-fixture", TenantID: "t", AccountID: "a", Provider: "p", ConnectionID: "c", Generation: 1, ExpiresAt: time.Now().Add(-time.Minute)}
	if err := s.consume(c.Token, c); err == nil {
		t.Fatal("expired token accepted")
	}
	c.ExpiresAt = time.Now().Add(time.Hour)
	if err := s.consume(c.Token, c); err == nil {
		t.Fatal("corrupt state was reset")
	}
}
