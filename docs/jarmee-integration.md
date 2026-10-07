# Jarmee executor integration

Status: source preflight; implementation and independent review remain open.

## Source custody

The preserved local EAAP source contained 20 files with no prior local commit or remote and no in-progress Git operation. Its content was transferred to an isolated DGX source-custody directory and verified file by file. Every file matches canonical `sirerun/eaap` revision `bb6011e8c8e003d715b70c3a1bbc53c362a72b41`; no overlay was needed. Original copies are preserved.

The source-only transfer archive SHA-256 is `f2461566d3b0b1f23fc2a7bb1f8de3a2c4b0e288b6b2f66bc654149993dbc424`. Credential stores, environment secrets and signing keys were excluded. The coordinator owns the isolated executor branch and task-local DGX caches. Coding and checks execute on Linux, with no Apple validation claim.

Baseline checks at that revision passed on DGX: `go test -race ./...` in `gateway` and `node --test extension/background.test.js` (two tests). These check the existing source and normalization fixtures, not browser execution or platform acceptance.

## Delivery ownership and contract boundary

Jarmee's [E4 plan](https://github.com/ionogram/jarmee/blob/main/docs/plans/E4-eaap.md) owns the cross-repository dependency obligations T4.0–T4.6. EAAP changes are implemented, independently reviewed, merged and verified in this repository, then consumed by an exact pinned revision. The source-custody claim is T-JARMEE.0; it does not grant live account access or authorize external effects.

### Frozen handoff: Jarmee control PR #3 (`20a2d4a48186e0fe8317d982b12a3b9710d933ed`)

The source is readable locally in the Jarmee `landed-control` checkout. This is a field-level compatibility freeze for EAAP; it does not add a cross-repository Go import and does not mean EAAP verifies or consumes grants yet. Jarmee owns signing and durable grant issuance. EAAP T4.2 must implement that gate before any external-effect execution is enabled.

| Frozen contract | Fields | EAAP mapping |
|---|---|---|
| `jarmee.dispatch.v2` `DispatchGrant` | `intent_id`, `tenant_id`, `principal_id`, `connection_id`, `account_id`, `session_generation`, `adapter` (provider identity), `operation`, `operation_version`, `destination_id`, `destination_hash`, `content_hash`, `attempt_id`, `policy_epoch`, `recovery_epoch`, `authority`, `conversation`, optional external-authorization ID/hash, `expires_at`, `nonce` | Future adapter input; tenant/account/provider/session generation select one paired session. Operation/version and destination are resolved only from a server-owned promoted registry. Attempt, epochs, hashes, expiry and nonce bind one exact execution. T4.1 carries no grant and rejects all effect dispatches. |
| `Outcome` | `kind` (`accepted`, `rejected`, `unknown`, `unsupported_capability`, `held`), `code`, `message`, `correlation_id`, optional intent/attempt IDs, `retry` (`never`, `safe_transient`, `reconcile_first`), optional retry-after/effect/evidence refs/provider ref/effect observations | Future adapter result; every result is correlated to the same intent and attempt. Unknown means reconcile first; it never authorizes retry or mode switching. HTTP/DOM success alone is not publication evidence. T4.1 returns no effect outcome. |
| Session/account binding | `tenant_id`, `account_id`, provider identity (`adapter`), `connection_id`, `session_generation`; connection lifecycle carries expected generation | T4.1 pairing binds tenant/account/provider and a monotonically fenced generation to one live bridge. Reconnect cannot replace a different identity, and stale generations cannot dispatch. Jarmee retains authority to issue and revoke these bindings. |

Nonce single-use consumption, signature/authenticity validation, durable attempt admission, fence checks, restart recovery and pre-effect grant verification are explicitly T4.2 work. The mapping above is frozen against the landed revision named here; no shared private package is imported.

T4.0 contract mapping is recorded above. T4.1 and T4.2 implement the following requirements, with their verification children and T4.3–T4.6 review/merge/landed gates retained in the canonical plan:

- Server-owned, explicitly promoted operation registry with complete typed request validation. Inference is discovery only; callers cannot override target origin, selectors, mode, headers or session.
- Authenticated single-use pairing scoped to tenant, account, actual provider identity and session generation. A new connection cannot displace another account's session.
- Durable single-use grant admission and nonce/fence checks after pacing and immediately before a possible external effect. A committed attempt survives disconnect and restart; an uncertain outcome cannot trigger a write retry or mode switch.
- Structured effect observations and readback tied to the same attempt, account and content. A click or successful HTTP exchange alone is not proof of publication.
- Controlled local browser fixtures covering capture redaction, forged/replayed pairing, two simultaneous sessions, wrong identity/origin, prohibited overrides, crashes and lost acknowledgements. No social login is required for these source gates.

EAAP T4.1 source now keeps inferred schemas in a discovery candidate map, with a separate empty server-owned promoted-operation registry; no caller route or request can promote a candidate. Pairing credentials are configured server-side by environment-variable name and bind tenant, account, provider, connection ID and generation. Their token is accepted once per process, then removed from extension local storage after submission; origin is checked against the configured extension origin. The external REST surface and extension executor both fail closed until T4.2. Pairing consumption is currently in-memory and must gain restart-safe replay protection if the T4.2 storage design requires it.

## Baseline gaps

The existing gateway uses a singleton browser bridge, in-memory queue/spec state and incomplete request validation. The legacy execution surface accepts caller-selected execution details. These are source gaps to close before Jarmee can use the executor; the baseline README's architectural intent is not qualification evidence.

No controlled social account, provider action, deployment or release is authorized here. Live grants will be supplied later. Source work and local fixtures continue independently of those later gates.
