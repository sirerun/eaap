# Grant journal source checkpoint

`gateway/grant_journal.go` adds a durable replay and attempt observation journal
for the synthetic, source-only EAAP grant consumer. Operators must configure a
private absolute StateRoot. InitializeGrantJournal explicitly enrolls a new
root using exclusive directory creation and a parent-directory sync; it refuses
any existing root. NewGrantJournal only opens established storage and never
creates or initializes it. Ordinary startup must never fall back to enrollment
when opening fails. Construction rejects symlinked ancestors, unsafe
ancestor ownership/modes, and a root that is not owned by the effective user
with private directory permissions. The journal uses a stable 0600 lock file,
exclusive `flock`, cancellable acquisition, and a maximum 30 second lock wait.
The initialization marker binds the lock file's device and inode; missing or
replaced lock identity is rejected, including replacement while an old inode
remains locked.

`Observe` calls the landed `VerifyExecutorGrant` before recording anything. It
indexes nonce by issuer and tenant and attempt by issuer and tenant, stores only
digests for nonce/attempt/tuple identity, and never persists compact tokens or
credential inputs. Repeating the exact observation returns its existing
evidence state. A reused nonce, refreshed nonce for the same attempt, or changed
tuple for the same attempt cannot create a new observation. Capacity is bounded
at 10,000 entries and 16 MiB; exhaustion fails closed without pruning consumed
nonce or attempt history.

Records are versioned `observation`, `prepared`, `unknown`, `accepted`, or
`rejected` evidence. Transition uses an expected version. Unknown and terminal
states remain immutable across reopen. Atomic replacement uses a same-directory
exclusive temporary file with mode 0600, file sync, rename, and directory sync.
An initialization marker is durably written before the initial state file, so
every initialized store has a mandatory marker; a crash between those writes
fails closed for operator recovery rather than treating an established root as
new. Malformed, missing-after-initialization, unsafe, or oversized state fails
closed. A failed replacement leaves the previous complete state file in
place until atomic rename; after rename, directory-sync errors are surfaced and
the complete new file remains available for conservative reopen handling.

This journal is not authorization. It has no dispatch method and does not
implement current-authority/session-fence transactions, pacing, final guards,
preparation, effect readback, release, automatic resend, or restart recovery.
Gateway effect routes remain 503. T4.2 remains open; journal success must never
be interpreted as permission to perform an external effect. Tests use only the
consumer's synthetic Ed25519 key and metadata.


## Coordinator integration repair

GJ-C1 was reproduced in grant-journal-rootloss-red.log: moving away the entire established directory let ordinary NewGrantJournal reopen create a fresh journal and accept the same signed grant as new. An empty configured directory also initialized implicitly. The explicit-enrollment/open split now denies both cases; grant-journal-rootloss-green.log passes full gateway race tests, vet and lint0, and grant-journal-integrated-node.log passes11 extension tests. Existing directory initialization is refused without changing stored history. Recovery of lost storage remains an explicit operator decision; no automatic enrollment fallback exists.

Exact replays skip replacement while retaining lock-release/close errors, rather than masking those errors behind a replay sentinel. This journal remains observation evidence only; production effect admission and routes are unchanged.
