# Jarmee executor contract source pin

Pin recorded 2026-10-07 after Jarmee PR6 independent complete review, guarded merge and landed checks.

- Producer repository: ionogram/jarmee (existing repository access is required).
- Exact landed revision: 5c43844072d88034f63e6d615a4f8cbbd3c8dbe0.
- Reviewed predecessor: a7b07942a4078ffd76832f75b011115d7cda5461; reviewed base caa302b5884129161ecd554c67a1145d7ccc1218.
- Reviewed and landed tree: ee23d601bc2aa57bd3154a41bc331b6bfa930048.
- [Source contract ADR014](https://github.com/ionogram/jarmee/blob/5c43844072d88034f63e6d615a4f8cbbd3c8dbe0/docs/adr/014-executor-grant-envelope.md): protected type jarmee.executor-grant.v1+jws, ExecutorGrant with ControlClaims and DispatchGrant v2.
- [Synthetic interoperability vector](https://github.com/ionogram/jarmee/blob/5c43844072d88034f63e6d615a4f8cbbd3c8dbe0/controlwire/testdata/executor-grant.json), SHA-256 2df49fad834840dc76b8c1d165483f47f7e8eb19d495453b3ddc4daefb2fc8c4. This fixture contains public verification material and fixed synthetic claims; no signing private key is retained.
- [Independent review](https://github.com/ionogram/jarmee/pull/6#issuecomment-6037001585) approved the complete current-base candidate with AW-F1 resolved. Landed DGX checks passed full source parity/116 conformance/build/vet/race/lint, actual account ordinary/race/restart, and complete schema5 storage migration/restart.

This pins the producer source only. EAAP has not implemented or qualified signature verification, durable nonce/attempt consumption, current authority/session fences, pacing/preparation, recovery or effect observation. Existing external-effect execution remains disabled. No fixture supplies a production trust anchor or permission to execute. A consumer implementation must use operator-configured issuer/audience/public keys and preserve all durable replay, binding and unknown-effect boundaries before any separately authorized runtime qualification.
