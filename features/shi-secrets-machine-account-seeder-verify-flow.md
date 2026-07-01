---
id: shi-secrets-machine-account-seeder-verify-flow
title: "MachineAccountSeeder — verify-flow: credential verification before Keychain write"
status: draft
scope: shi-secrets
wave: W-next
priority: P1
created: 2026-07-01
author: Jeoffrey Thirot
deferred_until: post-v0.5.2
---

# shi-secrets-machine-account-seeder-verify-flow

## WHY

`MachineAccountSeeder.seed(...)` calls `VaultCredentialsSeeder.seed(..., verify: false)` —
`verify` is hardcoded to `false`. This means:

- A typo'd `clientSecret`, revoked API key, or wrong `serverURL` is silently written to
  the Keychain.
- The error only surfaces at the next `shi secrets brokerd start`, which may be hours later,
  in a daemon process, producing a cryptic auth-failure log.
- Operators lose the seed-time feedback loop. A failed verify at wizard time is far cheaper
  than a failed broker boot at 3 AM.

## WHAT

Add a `--verify` flag to the `shi secrets setup wizard` seeder step. When set,
`MachineAccountSeeder.seed` passes `verify: true` down the stack to
`VaultCredentialsSeeder.seed`. On verification failure, the wizard emits a clear
operator message and exits non-zero without writing to the Keychain.

Default stays `verify: false` — offline installs (air-gapped, dev laptop without VPN)
must continue to work without a live vault reachable at seed time.

## HOW

### 1. `SecretsSetupWizardCommand`

Add `--verify` option (default `false`):

```swift
@Flag(help: "Verify credentials against the vault before writing to Keychain. Requires live network access to <server-url>.")
var verify: Bool = false
```

Pass to the seeder:

```swift
let outcome = await seeder.seed(
    candidateSystemName: systemName,
    clientID: clientID,
    clientSecret: clientSecret,
    serverURL: serverURL,
    force: force,
    verify: verify       // NEW
)
```

### 2. `MachineAccountSeeder.seed(..., verify: Bool = false)`

Add `verify: Bool = false` parameter (default preserves existing behaviour):

```swift
public func seed(
    candidateSystemName: String,
    clientID: String,
    clientSecret: String,
    serverURL: String,
    force: Bool,
    verify: Bool = false   // NEW — default false = current behaviour
) async -> Outcome {
```

Thread through to `VaultCredentialsSeeder.seed`:

```swift
let seedResult = await seeder.seed(
    clientID: clientID,
    clientSecret: clientSecret,
    serverURL: serverURL,
    boundSystemName: systemName,
    force: force,
    verify: verify          // was hardcoded false
)
```

### 3. Operator-facing failure message

On `.verifyFailed(let message)` from `VaultCredentialsSeeder`, surface:

```
Error: Credentials failed verification against <serverURL>.
  Not written to Keychain. Check clientID / clientSecret and retry.
  Detail: <message>
```

### 4. `MachineAccountSeeder.Outcome`

No new cases needed — `verifyFailed` already maps to `.underlyingFailure(message:)` in the
existing switch. The CLI layer surfaces this as a non-zero exit.

## WHO

- Maintainer: shi-secrets (Jeoffrey Thirot)
- Reviewer: operator

## WHEN

- W-next — after v0.5.2 ships
- Deferred because: v0.5.2 is a pure fix release (no new flags); `--verify` is a
  UX enhancement, not a correctness fix.

---

## Acceptance Criteria

| ID | Criterion |
|----|-----------|
| AC-1 | `shi secrets setup wizard --verify` invokes the verification path before Keychain write |
| AC-2 | Verify failure → non-zero exit, nothing written to Keychain, clear operator message |
| AC-3 | Verify success → credentials written as today (identical existing behaviour) |
| AC-4 | Default (no `--verify`) preserves current behaviour: no network call, always writes if inputs are valid |

---

## Test Plan

### T-verify-01 — `seeder_verify_true_fails_fast_on_bad_credentials`

```swift
@Test("verify:true + bad creds → .underlyingFailure, nothing stored")
func seeder_verify_true_fails_fast_on_bad_credentials() async {
    let store = MAMockVaultCredentialStore()
    // VaultCredentialsSeeder with a MockVerifier that throws on verify
    let seeder = MachineAccountSeeder(store: store, systemNameWriter: InMemorySystemNameWriter())
    let outcome = await seeder.seed(
        candidateSystemName: "mac-laptop-shikki",
        clientID: "user.00000000-0000-0000-0000-000000000000",
        clientSecret: "bad-secret",
        serverURL: "https://vw.obyw.one",
        force: false,
        verify: true
    )
    if case .underlyingFailure = outcome { /* ok */ }
    else { Issue.record("expected .underlyingFailure, got \(outcome)") }
    let stored = await store.peek()
    #expect(stored == nil, "nothing should be written on verify failure")
}
```

### T-verify-02 — `seeder_verify_true_succeeds_and_writes`

```swift
@Test("verify:true + good creds → .seeded, credential written")
func seeder_verify_true_succeeds_and_writes() async {
    let store = MAMockVaultCredentialStore()
    // MockVerifier that succeeds
    let seeder = MachineAccountSeeder(store: store, systemNameWriter: InMemorySystemNameWriter())
    let outcome = await seeder.seed(
        candidateSystemName: "mac-laptop-shikki",
        clientID: "user.00000000-0000-0000-0000-000000000000",
        clientSecret: "valid-token",
        serverURL: "https://vw.obyw.one",
        force: false,
        verify: true
    )
    if case .seeded = outcome { /* ok */ }
    else { Issue.record("expected .seeded, got \(outcome)") }
    let stored = await store.peek()
    #expect(stored != nil, "credential must be written on verify success")
}
```

### T-verify-03 — `seeder_verify_default_false_skips_network`

```swift
@Test("verify:false (default) → no verify path called, writes immediately")
func seeder_verify_default_false_skips_network() async {
    // MockVerifier that records calls — assert it was NOT called
    let store = MAMockVaultCredentialStore()
    let seeder = MachineAccountSeeder(store: store, systemNameWriter: InMemorySystemNameWriter())
    let outcome = await seeder.seed(
        candidateSystemName: "mac-laptop-shikki",
        clientID: "user.00000000-0000-0000-0000-000000000000",
        clientSecret: "any-token",
        serverURL: "https://vw.obyw.one",
        force: false
        // verify: false (default — omitted intentionally to prove default)
    )
    if case .seeded = outcome { /* ok */ }
    else { Issue.record("expected .seeded, got \(outcome)") }
}
```

---

## Open Questions

None — deferred to W-next after operator review of v0.5.2 fix release.
