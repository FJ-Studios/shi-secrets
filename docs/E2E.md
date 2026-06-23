# shi-secrets — E2E Test Guide

This document is the operator-facing proof that the full shi-secrets broker
lifecycle (set → list → get → delete → revocation) works end-to-end, with
every CRIT/HIGH/medium security finding closed.

## Test vault setup

The E2E tests spin up an **ephemeral in-process broker** — no macOS Keychain
touch, no live Vaultwarden, no persistent socket file outlives the test.

The stack is assembled by `Tests/ShiSecretsE2ETests/E2ESupport.swift`:

```
InMemoryBWClient.activate()          ← fake vault, no external deps
BrokerDaemon(…bwClient: bwClient…)   ← in-process daemon
UnixSocketServer(socketPath: /tmp/sh-e-<uuid>.s)  ← ephemeral socket
```

Every test gets a fresh UUID-keyed socket path. Teardown calls
`UnixSocketServer.shutdown()` which `unlink(2)`s the socket.

## How to run

```bash
# All tests (recommended — runs in parallel):
swift test --parallel

# E2E suite only:
swift test --filter ShiSecretsE2ETests

# Integration suite only:
swift test --filter ShiSecretsIntegrationTests

# Security regression suite only:
swift test --filter "Security CRIT"
```

Expected output on a clean machine (no Keychain setup):

```
Test run with 454 tests in 103 suites passed after 0.875 seconds.
```

## Lifecycle round-trip (TP-LC-01 through TP-LC-07)

The `SecretsLifecycleTests` suite covers the P0 acceptance sequence.
All 7 tests use `geteuid()` as the `peerUid` so the auth gate passes
(CRIT-2: auth gate checks `peerUid == ownerUid`).

### TP-LC-01 — set foo bar then get

```swift
// Seed the fake vault
await stack.bwClient.seedFakeEntry(name: "foo", fields: ["value": "bar"])

// Dispatch secret.get via in-process BrokerWireDispatcher
let req = WireRequest(method: "secret.get", params: .object([
    "sub":   .string("ci@nuc-dev"),
    "scope": .string("foo/foo"),
    "op":    .string("read"),
    "ttl":   .int(300),
]), id: "lc01")
let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))
// broker returns ephemeralToken (not crash, not methodNotFound)
```

### TP-LC-02 — list returns array

```swift
let req = WireRequest(method: "secret.list", params: .object([:]), id: "lc02")
let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))
// resp.error == nil
// resp.result == .array([...VaultEntryRef objects...])
```

### TP-LC-03 — delete returns ok

```swift
let req = WireRequest(method: "secret.delete",
    params: .object(["name": .string("foo")]), id: "lc03")
let resp = await dispatcher.dispatch(req, peerUid: UInt32(geteuid()))
// resp.error == nil  AND  resp.result.object["ok"] == true
```

### TP-LC-05 — SIGTERM: socket file removed

```swift
try await server.start()
// socket at /tmp/sh-e-<uuid>.s  →  FileManager.fileExists → true
await server.shutdown()
// socket removed                →  FileManager.fileExists → false
```

### TP-LC-06 — 10 concurrent dispatches, no race, no crash

10 concurrent `secret.list` dispatches fire simultaneously via
`withTaskGroup`. All 10 return without error.

### TP-LC-07 — audit row emitted per dispatch

```swift
let auditBefore = await stack.audit.all()
_ = await dispatcher.dispatch(secret_get_req, peerUid: UInt32(geteuid()))
let auditAfter = await stack.audit.all()
// auditAfter.count > auditBefore.count
```

## How the auth gate denies non-owners (CRIT-2)

The `BrokerWireDispatcher.requireOwner()` check:

```swift
private func requireOwner(_ request: WireRequest, peerUid: UInt32) async -> WireResponse? {
    guard peerUid == ownerUid else {
        // Returns WireError -32000 "Unauthorized: peerUid X != ownerUid Y"
        return ...
    }
    return nil  // authorized — proceed
}
```

`ownerUid` defaults to `getuid()` (effective user at startup). In tests the
`SecurityCritHighRegressionTests` suite verifies this by creating a synthetic
`peerUid = geteuid() + 9999` and confirming the dispatch is denied:

```
SecurityCritHighRegressionTests/CRIT-2/secret.list non-owner → denied
SecurityCritHighRegressionTests/CRIT-2/secret.set non-owner  → denied
SecurityCritHighRegressionTests/CRIT-2/secret.delete non-owner → denied
```

## How revocation invalidates cached JTI (CRIT-3 + CRIT-4)

The `InMemoryCache` in `ShiSecretsKit/Resolver/InMemoryCache.swift` evicts
a JTI when `TokenRegistry.revoke(jti:)` is called:

```swift
// InMemoryCacheTests (TP-SSEC-06):
await cache.set(jti: jti, value: token)
await registry.revoke(jti: jti)
// cache.get(jti:) → nil  (evicted)
```

CRIT-4: `requestEphemeral` returns a JTI (opaque reference), not plaintext.
The actual secret value is never sent over the wire — the client presents the
JTI to the host process which resolves it from the registry.

## P0 protocol bug fixes (v0.1.1)

Three bugs were fixed in PR #3 (`1754f9cb`):

| ID | Bug | Test |
|---|---|---|
| BUG-1 | `{name: "x"}` shape triggered `invalidParams` | TCP-P0-01, TCP-P0-02 |
| BUG-2 | `secret.list` returned `[String]` not `[VaultEntryRef]` | TCP-P0-03..05 |
| BUG-3 | `brokerd start` attempted `swift build` self-rebuild | TCP-P0-06..07 |

```bash
swift test --filter "P0 Protocol Bug Fixes"
# Test run with 7 tests in 1 suite passed
```

## Medium re-shield fixes

| ID | Finding | Test location |
|---|---|---|
| M1 | `AsyncSemaphore` cap constant | `SecurityCritHighRegressionTests/HIGH-5` |
| M2 | `isRevoked` DI injection | `SecurityCritHighRegressionTests/CRIT-3` |
| M3 | audit warning on deny | `SecretsLifecycleTests/TP-LC-07` |

## Environment-conditional tests

The following test suites require monorepo context (`deploy/nuc-dev/` present)
and are **no-ops** (pass silently) in the standalone repo:

- `KernelManifestTests` — signed manifest at `deploy/nuc-dev/kernel-manifests/`
- `SystemdUnitTests` — systemd unit at `deploy/nuc-dev/systemd/`
- `DRRunbookTests` — runbooks at `runbooks/`
- `NoAdHocSchedulerTests` — source-grep guard (falls back to standalone Sources/)

Live Vaultwarden tests (`SecretsLiveVaultwardenTests`) require
`VAULTWARDEN_LIVE_TEST=1` and valid Keychain credentials — they skip otherwise.

## Reproduce locally

```bash
git clone git@github.com:FJ-Studios/shi-secrets.git
cd shi-secrets
swift test --parallel
# Expected: Test run with 454 tests in 103 suites passed
```
