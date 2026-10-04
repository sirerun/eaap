# Enterprise-as-a-API (EaaP)

Turns an authenticated browser session into a governed, OpenAPI-described
REST API — no target-system code changes required.

## Architecture

    [External Client] --REST--> [Gateway :8080] --WS--> [Chrome Extension] --> [Target Web App]
                                     |
                                     +--> LLM (schema inference from captured traffic)

- **Phase 1 (Discovery):** the Extension passively captures XHR/fetch traffic,
  normalizes URLs into parameterized templates, sanitizes secrets, and pushes
  batches to the Gateway. An LLM infers OpenAPI 3.0.3 fragments.
- **Phase 2 (Execution):** external REST calls are validated against the
  inferred spec, queued with human-like jitter, wrapped in EaaP envelopes, and
  executed in-browser via SYNTHETIC_FETCH or DOM_SIMULATION.

## Run

    cd gateway && go run .            # gateway on :8080
    # load extension/ unpacked into Chrome; it auto-connects
    go run ./cmd/epp --spec           # view inferred API

## Security model (see RFC §6)

1. Secrets never leave the browser — sanitized at the Extension and again at
   the Gateway before LLM transmission.
2. Target origins are double-allowlisted (Gateway + Extension).
3. All browser actions are serialized with 2–5s randomized jitter.
4. Requests are validated against the LLM-generated OpenAPI schema before
   execution; unknown routes are rejected.

## Known limitations

- Gateway `routeOrigins` mapping is stubbed (see server.go note).
- OpenAPI request validation uses a placeholder; wire in `kin-openapi`'s
  `openapi3filter` for full validation.
- MV3 service worker sleep may drop the WS; reconnect logic handles it, but
  long-running DOM_SIMULATION jobs should pin an automation tab.
