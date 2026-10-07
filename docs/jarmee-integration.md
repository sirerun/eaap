# Jarmee executor integration

Status: operation-registry/session source and controlled capture fixture implemented; independent review and durable grant execution remain open.

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

EAAP T4.1 source keeps inferred schemas in a discovery candidate map, separate from explicitly configured server-owned promoted operations. Each promoted operation declares exact method/path/origin and a recursively typed, closed request schema; config validation rejects unallowlisted origins, duplicate routes and fields that could override target, selectors, mode or session. Caller query strings and non-content headers are rejected; unknown, missing, mistyped and nested extra body fields are rejected. No candidate is promoted by inference. Pairing credentials are configured server-side by environment-variable name and bind tenant, account, provider, connection ID, exact generation and expiry. A stable absolute `pairing_state_root` is required; the owner must configure a private, non-symlink directory. Pairing token SHA-256 digests and consumed identities are committed under an OS file lock with fsync and atomic rename. Missing, malformed, unsafe or inaccessible state rejects pairing. No raw pairing token is written to the journal. No token is provisioned by this source lane. Active websocket sessions remain in memory, while replay and generation fences survive restart. The extension clears its one-shot local token after submission. Extension capture uses configured exact allowed origins, refuses a missing or unapproved initiator, and stores only URL templates, value-free typed body shape and header metadata; the gateway repeats the metadata-only transformation before inference. Query values, path identifiers, response bodies, arbitrary request values and header values are not buffered or sent. The external REST surface and extension executor continue to fail closed until T4.2.

`node scripts/browser-fixture.mjs` is the repeatable Chrome 151 `Extensions.loadUnpacked` pipe fixture. It creates two isolated profiles, loads the EAAP extension, and checks each actual service-worker target. Each profile must load the actual service worker with all four webRequest listeners and deliver its own captured POST to the local discovery endpoint. Both profile pages reach complete state, and query/header/body secret markers are absent from the captured payload. This controlled capture gate passed on native ARM64 Chrome 151.0.7922.137 on DGX.

The initial run loaded the extension but navigation stalled. A fresh Chrome profile without EAAP reproduced that failure. Selecting --password-store=basic made the baseline request complete, then made both EAAP profile captures pass. This setting applies only to newly created synthetic fixture profiles; it never reads or changes an existing user profile or keyring. Chromium documents that this selects plaintext storage, so these disposable profiles must never contain real credentials. Short private DGX temporary directories are required for Chrome's Unix singleton socket length limit; cleanup removes only directories created by the fixture.

Evidence: task receipts browser-network-debug.log (initial failure), chrome-network-baseline.log (without extension, no request), chrome-network-basic-store.log (baseline pass), browser-profile-assertions.log (two separate capture passes). Node unit tests and gateway race/vet checks are separate source checks. This does not prove concurrent real account routing, durable grant consumption, browser action execution or any social platform acceptance.

Primary browser reference: [Chromium Linux password storage](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/password_storage.md).


## Baseline gaps

The existing gateway uses a singleton browser bridge, in-memory queue/spec state and incomplete request validation. The legacy execution surface accepts caller-selected execution details. These are source gaps to close before Jarmee can use the executor; the baseline README's architectural intent is not qualification evidence.

No controlled social account, provider action, deployment or release is authorized here. Live grants will be supplied later. Source work and local fixtures continue independently of those later gates.

## Independent review repairs

The independent review of e37f1e47d51d3647e73c77b9b546f4986ea3036b requested changes (EAAP-F1 through F3). The coordinator accepted all three findings. Durable pairing consumption and in-memory installation now share one ordering lock. A deterministic paused-generation test fails on the previous implementation and passes after the repair. This orders one bridge instance; cross-process dispatch authorization remains a T4.2 obligation.

Capture checks the number and aggregate byte length of raw body parts before allocating a copy (64 parts, 64 KiB). Shape depth/field counts are bounded. Pending metadata is limited to 200 requests and 30 seconds, removed on errors, and pruned during flushes. Completed and retry buffers are bounded; only one discovery flush runs at a time with a five-second timeout. Eight Node tests cover the resource and error lifecycle regressions.

A stronger real Chrome assertion exposed an additional capture gap (EAAP-C1): the header listeners did not request requestHeaders/responseHeaders, so header metadata was absent even though secret-marker exclusion passed. Both listeners now request their corresponding metadata. The fixture requires each profile's captured POST to include the value-free body shape, authorization presence and media type. It failed before this repair and passes afterward; no header secret value is retained.

Evidence receipts: pairing-order-red.log, capture-size-red.log and capture-abort-red.log preserve failing regressions; browser-header-metadata-red.log preserves the actual browser failure. eaap-review-final-verify.log records passing Go race tests, vet and lint (zero issues); capture-review-final.log records eight passing Node tests; browser-header-metadata-green.log records both controlled Chrome profiles passing. These repairs require a fresh independent exact-head review. They do not enable execution, qualify live accounts, or complete T4.2.

Primary metadata reference: [Chrome webRequest API](https://developer.chrome.com/docs/extensions/reference/api/webRequest).
