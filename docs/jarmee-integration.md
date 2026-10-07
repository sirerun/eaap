# Jarmee executor integration

Status: source preflight; implementation and independent review remain open.

## Source custody

The preserved local EAAP source contained 20 files with no prior local commit or remote and no in-progress Git operation. Its content was transferred to an isolated DGX source-custody directory and verified file by file. Every file matches canonical `sirerun/eaap` revision `bb6011e8c8e003d715b70c3a1bbc53c362a72b41`; no overlay was needed. Original copies are preserved.

The source-only transfer archive SHA-256 is `f2461566d3b0b1f23fc2a7bb1f8de3a2c4b0e288b6b2f66bc654149993dbc424`. Credential stores, environment secrets and signing keys were excluded. The coordinator owns the isolated executor branch and task-local DGX caches. Coding and checks execute on Linux, with no Apple validation claim.

Baseline checks at that revision passed on DGX: `go test -race ./...` in `gateway` and `node --test extension/background.test.js` (two tests). These check the existing source and normalization fixtures, not browser execution or platform acceptance.

## Delivery ownership and contract boundary

Jarmee's [E4 plan](https://github.com/ionogram/jarmee/blob/main/docs/plans/E4-eaap.md) owns the cross-repository dependency obligations T4.0–T4.6. EAAP changes are implemented, independently reviewed, merged and verified in this repository, then consumed by an exact pinned revision. The source-custody claim is T-JARMEE.0; it does not grant live account access or authorize external effects.

The executor must consume a frozen version of Jarmee's dispatch, outcome and session contracts before coding their integration. Jarmee PR #3 currently proposes dispatch v2 recovery/external-authorization bindings; it is not yet a landed contract. No production consumer is authorized by that proposal or this document.

T4.0 remains open until the exact compatible dispatch/outcome/session contract is recorded here. T4.1 and T4.2 then implement the following requirements, with their verification children and T4.3–T4.6 review/merge/landed gates retained in the canonical plan:

- Server-owned, explicitly promoted operation registry with complete typed request validation. Inference is discovery only; callers cannot override target origin, selectors, mode, headers or session.
- Authenticated single-use pairing scoped to tenant, account, actual provider identity and session generation. A new connection cannot displace another account's session.
- Durable single-use grant admission and nonce/fence checks after pacing and immediately before a possible external effect. A committed attempt survives disconnect and restart; an uncertain outcome cannot trigger a write retry or mode switch.
- Structured effect observations and readback tied to the same attempt, account and content. A click or successful HTTP exchange alone is not proof of publication.
- Controlled local browser fixtures covering capture redaction, forged/replayed pairing, two simultaneous sessions, wrong identity/origin, prohibited overrides, crashes and lost acknowledgements. No social login is required for these source gates.

## Baseline gaps

The existing gateway uses a singleton browser bridge, in-memory queue/spec state and incomplete request validation. The legacy execution surface accepts caller-selected execution details. These are source gaps to close before Jarmee can use the executor; the baseline README's architectural intent is not qualification evidence.

No controlled social account, provider action, deployment or release is authorized here. Live grants will be supplied later. Source work and local fixtures continue independently of those later gates.
