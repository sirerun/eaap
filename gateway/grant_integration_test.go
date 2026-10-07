package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestGrantRejectsInvalidNonceAndChangedConnection(t *testing.T) {
	token, cfg, binding, now := grantTestVector(t)
	parts := strings.Split(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	for _, tc := range []struct {
		name string
		mut  func(*executorGrant)
	}{
		{"invalid nonce", func(m *executorGrant) { m.Claims.JTI = "invalid nonce"; m.Grant.Nonce = m.Claims.JTI }},
		{"changed connection", func(m *executorGrant) { m.Grant.ConnectionID = "another-connection" }},
		{"changed provider API version", func(m *executorGrant) { m.Grant.Adapter.ProviderAPIVersion = "another-version" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m executorGrant
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			tc.mut(&m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			signed := signGrantPayload(ed25519.NewKeyFromSeed(grantTestSeed[:]), string(b), string(header))
			if _, err = VerifyExecutorGrant(signed, cfg, binding, now); err == nil {
				t.Fatal("accepted invalid or foreign execution binding")
			}
		})
	}
}
