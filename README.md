# Enterprise-as-a-API (EAAP)

EAAP is a source foundation for discovering browser API shapes and governing access to explicitly configured operations. External browser execution is currently disabled.

The Chrome extension captures value-free request shapes and header metadata from configured origins. The gateway keeps inferred candidates separate from its server-owned promoted operation registry. Promoted operations use closed, typed request validation; callers cannot select a target origin, execution mode, headers, selectors or browser session.

Single-use pairing credentials bind a connection to a tenant, account, provider and generation. Consumed token hashes and generation fences persist across gateway restart. Active websocket sessions remain in memory. Pairing is a source component, not proof of a qualified provider account.

## Current boundary

Valid external operation requests still fail closed. Durable signed grant admission, final authority and session-fence checks, attempt recovery and effect readback must land before any browser action is enabled. Discovery and HTTP success do not prove a message was sent or published.

The [Jarmee integration record](docs/jarmee-integration.md) describes the frozen contract, controlled fixtures, review findings and remaining gates. There is no production deployment or live platform acceptance claim.

## Source verification

From the gateway directory:

    go test -race ./...
    go vet ./...

From the repository root:

    node --test extension/background.test.js
    node scripts/browser-fixture.mjs

The browser fixture uses two disposable synthetic Chrome profiles and local servers. It checks the actual extension service worker, capture metadata and secret redaction. It does not use existing browser profiles or authenticate to social platforms. See the integration record for the qualified Chrome version and fixture requirements.

## Configuration

Gateway startup requires an owner-configured private pairing-state directory and validated operation, origin and pairing settings. Pairing tokens and the optional inference API credential are referenced by environment-variable name; they are not stored in configuration JSON. The extension configuration supplied here targets local fixtures.

Real provider identities, credential custody, permissions and permitted actions require separate operator configuration and qualification. No real account is provisioned by this repository.
