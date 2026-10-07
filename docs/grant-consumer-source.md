# Executor grant consumer source checkpoint

This source implements an independent EAAP consumer for the pinned Jarmee
executor grant contract in `jarmee-contract-pin.md`. It uses the producer's
actual compact-JWS profile: `alg` is `Ed25519`, `kid` selects an operator-pinned
public key, and `typ` is `jarmee.executor-grant.v1+jws`. The compact segments
use unpadded canonical base64url. The signing input is the original encoded
protected-header and payload segments joined by a period. No Jarmee module,
producer schema, private implementation, or producer fixture is imported.

`VerifyExecutorGrant` requires configured issuer, audience, tenant and key
material, then checks the complete DispatchGrant v2 envelope, claims lifetime
and identity ties, exact recursively closed JSON, duplicate keys, nulls,
resource bounds, signature, and the caller-supplied immutable execution
binding. Its return value is authenticated source data only. Verification does
not consume a nonce or authorize an effect; current route handlers still return
503 while durable T4.2 admission is absent.

The fixed signing seed in `gateway/grant_consumer_test.go` exists only to make
independent synthetic tests repeatable. It is not a production trust anchor.

## Open gates

- Durable atomic nonce consumption and attempt identity conflict handling.
- Durable admission across restart, uncertain-attempt recovery, and fencing.
- Binding to the currently promoted operation, live session and current
  authority after pacing and immediately before preparation.
- Pacing, preparation, effect observation/readback and unknown-effect recovery.
- Independent exact-head review, merge, and landed verification.

No live grant, provider, deployment, or external effect was used or enabled by
this checkpoint.
