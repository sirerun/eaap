package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

// The operator supplies an independently produced synthetic fixture out of band.
// No producer implementation, fixture bytes, or private signing material is vendored.
func TestExternalExecutorGrantInteroperability(t *testing.T) {
	path := os.Getenv("EAAP_GRANT_INTEROP_FIXTURE")
	if path == "" {
		t.Skip("requires an independent synthetic interoperability fixture")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Compact   string
		Expected  executorGrant
		KeyID     string
		Now       int64
		PublicKey string
	}
	var wire map[string]json.RawMessage
	if err = json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for key, out := range map[string]any{"compact": &f.Compact, "expected": &f.Expected, "key_id": &f.KeyID, "now": &f.Now, "public_key": &f.PublicKey} {
		if err = json.Unmarshal(wire[key], out); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
	}
	pub, err := base64.RawURLEncoding.DecodeString(f.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	g, c := f.Expected.Grant, f.Expected.Claims
	binding := GrantExecutionBinding{TenantID: g.TenantID, AccountID: g.AccountID, ConnectionID: g.ConnectionID, SessionGeneration: g.SessionGeneration, AdapterName: g.Adapter.Name, AdapterVersion: g.Adapter.Version, AdapterTransport: g.Adapter.Transport, ProviderAPIVersion: g.Adapter.ProviderAPIVersion, Operation: g.Operation, OperationVersion: g.OperationVersion, DestinationID: g.DestinationID, DestinationHash: g.DestinationHash, ContentHash: g.ContentHash}
	cfg := GrantConsumerConfig{Issuer: c.Issuer, Audience: c.Audience, TenantID: c.TenantID, Keys: []GrantPublicKey{{KeyID: f.KeyID, PublicKey: ed25519.PublicKey(pub)}}}
	verified, err := VerifyExecutorGrant(f.Compact, cfg, binding, time.Unix(f.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	var got executorGrant
	if err = json.Unmarshal(verified, &got); err != nil || !reflect.DeepEqual(got, f.Expected) {
		t.Fatal("verified fixture tuple differs")
	}
}
