package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Fixed synthetic seed authored for this consumer's test. It is not producer
// material and conveys no production trust.
var grantTestSeed = sha256.Sum256([]byte("EAAP independent synthetic executor-grant test key v1"))

func grantTestVector(t *testing.T) (string, GrantConsumerConfig, GrantExecutionBinding, time.Time) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(grantTestSeed[:])
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Unix(1800000000, 0).UTC()
	m := executorGrant{Claims: controlClaims{"jarmee.control.v1", "issuer-test", "eaap", "tenant-a", "nonce-test", 1800000000, 1800000030}}
	m.Grant = dispatchGrant{SchemaVersion: "jarmee.dispatch.v2", IntentID: "intent-test", TenantID: "tenant-a", PrincipalID: "principal-test", ConnectionID: "connection-test", AccountID: "account-test", SessionGeneration: 3, Adapter: grantAdapter{Name: "synthetic", Version: "1", Transport: "eaap"}, Operation: "publish", OperationVersion: "1", DestinationID: "destination-test", DestinationHash: strings.Repeat("a", 64), ContentHash: strings.Repeat("b", 64), AttemptID: "attempt-test", PolicyEpoch: 2, RecoveryEpoch: 4, Authority: "jarmee_managed", Conversation: &grantConversation{Kind: "first_contact", RecipientID: "recipient-test"}, ExpiresAt: time.Unix(1800000030, 0).UTC(), Nonce: "nonce-test"}
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte(`{"alg":"Ed25519","kid":"test-key","typ":"jarmee.executor-grant.v1+jws"}`)
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(header) + "." + enc(payload)
	token := signing + "." + enc(ed25519.Sign(priv, []byte(signing)))
	cfg := GrantConsumerConfig{Issuer: "issuer-test", Audience: "eaap", TenantID: "tenant-a", Keys: []GrantPublicKey{{"test-key", pub}}}
	binding := GrantExecutionBinding{ConnectionID: "connection-test", TenantID: "tenant-a", AccountID: "account-test", SessionGeneration: 3, AdapterName: "synthetic", AdapterVersion: "1", AdapterTransport: "eaap", Operation: "publish", OperationVersion: "1", DestinationID: "destination-test", DestinationHash: strings.Repeat("a", 64), ContentHash: strings.Repeat("b", 64)}
	return token, cfg, binding, now
}

func TestVerifyExecutorGrantSyntheticInteroperability(t *testing.T) {
	token, cfg, binding, now := grantTestVector(t)
	if _, err := VerifyExecutorGrant(token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
	// Signature verification alone is repeatable; this API deliberately makes
	// no replay-consumption claim and callers cannot treat it as admission.
	if _, err := VerifyExecutorGrant(token, cfg, binding, now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyExecutorGrantRejectsUntrustedAndMalformedInputs(t *testing.T) {
	token, cfg, binding, now := grantTestVector(t)
	priv := ed25519.NewKeyFromSeed(grantTestSeed[:])
	for _, bad := range []string{"", token + ".", "!" + token[1:], strings.Replace(token, ".", "=.", 1)} {
		if _, err := VerifyExecutorGrant(bad, cfg, binding, now); err == nil {
			t.Errorf("accepted malformed compact token %q", bad)
		}
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	parts := strings.Split(token, ".")
	badSig := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := VerifyExecutorGrant(badSig, cfg, binding, now); err == nil {
		t.Fatal("accepted tampered signature")
	}
	otherSeed := sha256.Sum256([]byte("wrong synthetic key"))
	otherPub := ed25519.NewKeyFromSeed(otherSeed[:]).Public().(ed25519.PublicKey)
	wrongKeyCfg := cfg
	wrongKeyCfg.Keys = []GrantPublicKey{{KeyID: "test-key", PublicKey: otherPub}}
	if _, err := VerifyExecutorGrant(token, wrongKeyCfg, binding, now); err == nil {
		t.Fatal("accepted wrong pinned key")
	}
	unknownKid := signGrantPayload(priv, string(payload), `{"alg":"Ed25519","kid":"unknown-key","typ":"jarmee.executor-grant.v1+jws"}`)
	if _, err := VerifyExecutorGrant(unknownKid, cfg, binding, now); err == nil {
		t.Fatal("accepted token-selected key id")
	}
	for name, bad := range map[string]string{
		"malformed json":       `{"claims":`,
		"duplicate nested key": strings.Replace(string(payload), `"account_id":"account-test"`, `"account_id":"account-test","account_id":"other"`, 1),
		"unknown nested key":   strings.Replace(string(payload), `"account_id":"account-test"`, `"account_id":"account-test","selector":"button"`, 1),
		"null conversation":    strings.Replace(string(payload), `"conversation":{"kind":"first_contact","recipient_id":"recipient-test","inbound_generation":0}`, `"conversation":null`, 1),
		"excessive json depth": strings.Repeat("[", grantMaxJSONDepth+2) + "0" + strings.Repeat("]", grantMaxJSONDepth+2),
		"oversized payload":    strings.Repeat(" ", grantMaxPayloadBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == string(payload) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := VerifyExecutorGrant(signGrantPayload(priv, bad, `{"alg":"Ed25519","kid":"test-key","typ":"jarmee.executor-grant.v1+jws"}`), cfg, binding, now); err == nil {
				t.Fatal("accepted malformed signed JSON")
			}
		})
	}
	for name, header := range map[string]string{
		"wrong type":       `{"alg":"Ed25519","kid":"test-key","typ":"jarmee.authorization-request.v1+jws"}`,
		"wrong algorithm":  `{"alg":"ES256","kid":"test-key","typ":"jarmee.executor-grant.v1+jws"}`,
		"extra header":     `{"alg":"Ed25519","kid":"test-key","typ":"jarmee.executor-grant.v1+jws","jku":"https://evil.invalid"}`,
		"duplicate header": `{"alg":"Ed25519","alg":"Ed25519","kid":"test-key","typ":"jarmee.executor-grant.v1+jws"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyExecutorGrant(signGrantPayload(priv, string(payload), header), cfg, binding, now); err == nil {
				t.Fatal("accepted invalid header")
			}
		})
	}
	for name, clock := range map[string]time.Time{"grant expiry boundary": time.Unix(1800000030, 0), "grant expired": time.Unix(1800000031, 0), "future issued": time.Unix(1799999994, 0)} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyExecutorGrant(token, cfg, binding, clock); err == nil {
				t.Fatal("accepted invalid time")
			}
		})
	}
	for name, mut := range map[string]func(*GrantExecutionBinding){"account": func(b *GrantExecutionBinding) { b.AccountID = "elsewhere" }, "session": func(b *GrantExecutionBinding) { b.SessionGeneration++ }, "adapter": func(b *GrantExecutionBinding) { b.AdapterName = "other" }, "operation": func(b *GrantExecutionBinding) { b.Operation = "delete_published" }, "destination": func(b *GrantExecutionBinding) { b.DestinationHash = strings.Repeat("c", 64) }, "content": func(b *GrantExecutionBinding) { b.ContentHash = strings.Repeat("c", 64) }} {
		t.Run(name, func(t *testing.T) {
			bb := binding
			mut(&bb)
			if _, err := VerifyExecutorGrant(token, cfg, bb, now); err == nil {
				t.Fatal("binding mismatch accepted")
			}
		})
	}
}

func signGrantPayload(key ed25519.PrivateKey, payload, header string) string {
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc([]byte(header)) + "." + enc([]byte(payload))
	return signing + "." + enc(ed25519.Sign(key, []byte(signing)))
}
