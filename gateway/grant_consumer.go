package main

// This file is an independent, source-only consumer of Jarmee's pinned
// executor-grant wire contract. Verification never performs or admits effects.
import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
)

const (
	grantType            = "jarmee.executor-grant.v1+jws"
	grantMaxPayloadBytes = 64 * 1024
	grantMaxCompactBytes = 2 * grantMaxPayloadBytes
	grantMaxJSONDepth    = 32
)

var errInvalidGrant = errors.New("invalid executor grant")

// GrantConsumerConfig contains operator-supplied trust anchors. No value in a
// token can add or select an issuer, tenant, audience, or public key.
type GrantConsumerConfig struct {
	Issuer   string
	Audience string
	TenantID string
	Keys     []GrantPublicKey
}
type GrantPublicKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

// GrantExecutionBinding is the immutable execution tuple independently
// resolved from server-owned configuration and current session state.
type GrantExecutionBinding struct {
	TenantID, AccountID, ConnectionID             string
	SessionGeneration                             uint64
	AdapterName, AdapterVersion, AdapterTransport string
	ProviderAPIVersion                            string
	Operation, OperationVersion                   string
	DestinationID, DestinationHash, ContentHash   string
}

type executorGrant struct {
	Claims controlClaims `json:"claims"`
	Grant  dispatchGrant `json:"grant"`
}
type controlClaims struct {
	SchemaVersion string `json:"schema_version"`
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	TenantID      string `json:"tenant_id"`
	JTI           string `json:"jti"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}
type grantAdapter struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	Transport          string `json:"transport"`
	ProviderAPIVersion string `json:"provider_api_version,omitempty"`
}
type grantConversation struct {
	Kind                string `json:"kind"`
	ConversationID      string `json:"conversation_id,omitempty"`
	RecipientID         string `json:"recipient_id,omitempty"`
	InboundGeneration   uint64 `json:"inbound_generation"`
	ParentInteractionID string `json:"parent_interaction_id,omitempty"`
}
type dispatchGrant struct {
	SchemaVersion             string             `json:"schema_version"`
	IntentID                  string             `json:"intent_id"`
	TenantID                  string             `json:"tenant_id"`
	PrincipalID               string             `json:"principal_id"`
	ConnectionID              string             `json:"connection_id"`
	AccountID                 string             `json:"account_id"`
	SessionGeneration         uint64             `json:"session_generation"`
	Adapter                   grantAdapter       `json:"adapter"`
	Operation                 string             `json:"operation"`
	OperationVersion          string             `json:"operation_version"`
	DestinationID             string             `json:"destination_id"`
	DestinationHash           string             `json:"destination_hash"`
	ContentHash               string             `json:"content_hash"`
	AttemptID                 string             `json:"attempt_id"`
	PolicyEpoch               uint64             `json:"policy_epoch"`
	RecoveryEpoch             uint64             `json:"recovery_epoch"`
	Authority                 string             `json:"authority"`
	Conversation              *grantConversation `json:"conversation"`
	ExternalAuthorizationID   string             `json:"external_authorization_id,omitempty"`
	ExternalAuthorizationHash string             `json:"external_authorization_hash,omitempty"`
	ExpiresAt                 time.Time          `json:"expires_at"`
	Nonce                     string             `json:"nonce"`
}

// VerifyExecutorGrant verifies the configured Ed25519 compact-JWS profile,
// claims, full v2 shape, and immutable execution binding. It has no replay
// store and must never be treated as effect authorization by itself.
func VerifyExecutorGrant(compact string, cfg GrantConsumerConfig, binding GrantExecutionBinding, now time.Time) (json.RawMessage, error) {
	if len(compact) == 0 || len(compact) > grantMaxCompactBytes || cfg.Issuer == "" || cfg.Audience == "" || cfg.TenantID == "" || now.IsZero() {
		return nil, errInvalidGrant
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errInvalidGrant
	}
	enc := base64.RawURLEncoding.Strict()
	headerBytes, err := decodeGrantPart(enc, parts[0], 2048)
	if err != nil {
		return nil, errInvalidGrant
	}
	payload, err := decodeGrantPart(enc, parts[1], grantMaxPayloadBytes)
	if err != nil {
		return nil, errInvalidGrant
	}
	sig, err := decodeGrantPart(enc, parts[2], ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errInvalidGrant
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if strictGrantJSON(headerBytes, reflect.TypeOf(h)) != nil || json.Unmarshal(headerBytes, &h) != nil || h.Alg != "Ed25519" || h.Kid == "" || h.Typ != grantType {
		return nil, errInvalidGrant
	}
	var key ed25519.PublicKey
	for _, k := range cfg.Keys {
		if k.KeyID == h.Kid {
			if key != nil || len(k.PublicKey) != ed25519.PublicKeySize {
				return nil, errInvalidGrant
			}
			key = k.PublicKey
		}
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errInvalidGrant
	}
	var msg executorGrant
	if strictGrantJSON(payload, reflect.TypeOf(msg)) != nil {
		return nil, errInvalidGrant
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if d.Decode(&msg) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errInvalidGrant
	}
	if !validGrant(msg, cfg, binding, now) {
		return nil, errInvalidGrant
	}
	return append(json.RawMessage(nil), payload...), nil
}

func decodeGrantPart(enc *base64.Encoding, part string, max int) ([]byte, error) {
	if part == "" || len(part) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, errInvalidGrant
	}
	b, err := enc.DecodeString(part)
	if err != nil || len(b) > max || enc.EncodeToString(b) != part {
		return nil, errInvalidGrant
	}
	return b, nil
}

func validGrant(m executorGrant, c GrantConsumerConfig, b GrantExecutionBinding, now time.Time) bool {
	x, g := m.Claims, m.Grant
	if x.SchemaVersion != "jarmee.control.v1" || x.Issuer != c.Issuer || x.Audience != c.Audience || x.TenantID != c.TenantID || x.TenantID != b.TenantID || !grantID(x.JTI) || x.IssuedAt <= 0 || x.ExpiresAt <= x.IssuedAt || x.ExpiresAt-x.IssuedAt > 60 || x.IssuedAt > now.Unix()+5 || x.ExpiresAt < now.Unix()-5 {
		return false
	}
	if g.SchemaVersion != "jarmee.dispatch.v2" || !grantID(g.IntentID) || !grantID(g.TenantID) || g.TenantID != x.TenantID || !grantID(g.PrincipalID) || !grantID(g.ConnectionID) || !grantID(g.AccountID) || !grantID(g.DestinationID) || !grantHash(g.DestinationHash) || !grantHash(g.ContentHash) || !grantID(g.AttemptID) || g.Nonce == "" || g.Conversation == nil {
		return false
	}
	if g.SessionGeneration == 0 || g.PolicyEpoch == 0 || g.RecoveryEpoch == 0 || !validGrantOperation(g.Operation) || g.OperationVersion == "" || g.ExpiresAt.IsZero() || g.Adapter.Name == "" || g.Adapter.Version == "" || g.Adapter.Transport == "" {
		return false
	}
	if g.Authority != "jarmee_managed" && g.Authority != "externally_authorized" {
		return false
	}
	if g.Authority == "externally_authorized" {
		if !grantID(g.ExternalAuthorizationID) || !grantHash(g.ExternalAuthorizationHash) {
			return false
		}
	} else if g.ExternalAuthorizationID != "" || g.ExternalAuthorizationHash != "" {
		return false
	}
	v := g.Conversation
	if v.Kind != "first_contact" && v.Kind != "follow_up" && v.Kind != "reply" || (v.ConversationID == "" && v.RecipientID == "") || (v.ConversationID != "" && !grantID(v.ConversationID)) || (v.RecipientID != "" && !grantID(v.RecipientID)) || (v.ParentInteractionID != "" && !grantID(v.ParentInteractionID)) {
		return false
	}
	if x.JTI != g.Nonce || time.Unix(x.ExpiresAt, 0).After(g.ExpiresAt) || !g.ExpiresAt.After(time.Unix(x.IssuedAt, 0)) || !g.ExpiresAt.After(now) {
		return false
	}
	return g.TenantID == b.TenantID && g.ConnectionID == b.ConnectionID && g.Adapter.ProviderAPIVersion == b.ProviderAPIVersion && g.AccountID == b.AccountID && g.SessionGeneration == b.SessionGeneration && g.Adapter.Name == b.AdapterName && g.Adapter.Version == b.AdapterVersion && g.Adapter.Transport == b.AdapterTransport && g.Operation == b.Operation && g.OperationVersion == b.OperationVersion && g.DestinationID == b.DestinationID && g.DestinationHash == b.DestinationHash && g.ContentHash == b.ContentHash
}

func grantID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (i > 0 && (c == '.' || c == '_' || c == ':' || c == '@' || c == '-')) {
			continue
		}
		return false
	}
	return true
}
func grantHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func validGrantOperation(s string) bool {
	switch s {
	case "create_draft", "publish", "schedule_locally", "schedule_remotely", "update", "cancel_pending", "delete_published", "send_email", "receive_email", "list_interactions", "reply", "send_dm", "receive_dm", "read_metrics":
		return true
	}
	return false
}

// strictGrantJSON enforces exact case-sensitive tags, required fields, recursive
// duplicates/null/unknown rejection and bounded nesting before encoding/json.
func strictGrantJSON(data []byte, typ reflect.Type) error {
	if len(data) == 0 || len(data) > grantMaxPayloadBytes {
		return errInvalidGrant
	}
	if err := rejectGrantDuplicates(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errInvalidGrant
	}
	return exactGrantValue(value, typ, 0)
}

func rejectGrantDuplicates(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > grantMaxJSONDepth {
			return errInvalidGrant
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch x := t.(type) {
		case json.Delim:
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					ks, ok := k.(string)
					if !ok || seen[ks] {
						return errInvalidGrant
					}
					seen[ks] = true
					if err = value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errInvalidGrant
				}
			case '[':
				for d.More() {
					if err = value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errInvalidGrant
				}
			default:
				return errInvalidGrant
			}
		case nil:
			return errInvalidGrant
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errInvalidGrant
	}
	return nil
}
func exactGrantValue(v any, t reflect.Type, depth int) error {
	if depth > grantMaxJSONDepth || v == nil {
		return errInvalidGrant
	}
	if t == reflect.TypeOf(time.Time{}) {
		if _, ok := v.(string); !ok {
			return errInvalidGrant
		}
		return nil
	}
	for t.Kind() == reflect.Pointer {
		if v == nil {
			return errInvalidGrant
		}
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		o, ok := v.(map[string]any)
		if !ok {
			return errInvalidGrant
		}
		fields := map[string]reflect.StructField{}
		required := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			bits := strings.Split(f.Tag.Get("json"), ",")
			n := bits[0]
			fields[n] = f
			req := true
			for _, b := range bits[1:] {
				if b == "omitempty" {
					req = false
				}
			}
			required[n] = req
		}
		for k, x := range o {
			f, ok := fields[k]
			if !ok || x == nil {
				return fmt.Errorf("%w: field", errInvalidGrant)
			}
			if err := exactGrantValue(x, f.Type, depth+1); err != nil {
				return err
			}
		}
		for k, req := range required {
			if req {
				if _, ok := o[k]; !ok {
					return errInvalidGrant
				}
			}
		}
	case reflect.String:
		if _, ok := v.(string); !ok {
			return errInvalidGrant
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return errInvalidGrant
		}
	case reflect.Int64, reflect.Uint64:
		if _, ok := v.(json.Number); !ok {
			return errInvalidGrant
		}
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return errInvalidGrant
		}
		for _, x := range a {
			if err := exactGrantValue(x, t.Elem(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
