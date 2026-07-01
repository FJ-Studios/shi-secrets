---
id: shi-secrets-machine-account-seeder-verify-flow
title: "MachineAccountSeeder — verify-flow: credential verification before Keychain write"
status: validated
scope: shi-secrets
wave: W-next
priority: P1
created: 2026-07-01
updated: 2026-07-01
validated: 2026-07-01
validated_by: operator
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

Add a `--verify` / `--no-verify` flag pair to the `shi secrets setup wizard` seeder step,
and mirror it on `shi secrets login --reauth` (same seeder path). When `--verify` is set
(the default), `MachineAccountSeeder.seed` calls `VaultCredentialsSeeder.seed` with
`verify: true`. On verification failure, the wizard emits a clear operator message and
exits non-zero without writing to the Keychain.

**Default: `--verify` ON** — fail-loud is the shi convention. Bad credentials must not
land in the Keychain silently.

**Escape hatch: `--no-verify`** — offline installs (air-gapped, dev laptop without VPN,
setup-before-vault-provisioning) skip the network probe. Emits a structured telemetry
event marked `verify: "skipped"` so the silent-write path stays observable.

Every seed emits a structured telemetry event (`shi.secrets.seed.verify` — success,
failure, or skipped) so `shi doctor` can surface credential-health drift over time.

## HOW

### 1. `SecretsSetupWizardCommand`

Add `--verify` / `--no-verify` flag pair (default ON) using ArgumentParser's inverted-Bool
convention:

```swift
@Flag(inversion: .prefixedNo,
      help: "Verify credentials against the vault before writing to Keychain. Requires network access to <server-url>. Use --no-verify for offline installs.")
var verify: Bool = true
```

Pass to the seeder:

```swift
let outcome = await seeder.seed(
    candidateSystemName: systemName,
    clientID: clientID,
    clientSecret: clientSecret,
    serverURL: serverURL,
    force: force,
    verify: verify       // NEW — defaults ON
)
```

### 2. `SecretsLoginCommand --reauth`

Mirror the same flag on the sibling `--reauth` path (which shares the seeder). `--reauth`
is functionally a partial wizard re-run for credential rotation; the verify contract MUST
match the wizard's:

```swift
@Flag(inversion: .prefixedNo, help: "See --verify on setup wizard.")
var verify: Bool = true
```

Thread through to the same `MachineAccountSeeder.seed(..., verify: verify)` call.

### 3. `MachineAccountSeeder.seed(..., verify: Bool = true)`

Add `verify: Bool = true` parameter (default ON — matches CLI default):

```swift
public func seed(
    candidateSystemName: String,
    clientID: String,
    clientSecret: String,
    serverURL: String,
    force: Bool,
    verify: Bool = true   // NEW — fail-loud default
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

### 4. Operator-facing failure message

On `.verifyFailed(let message)` from `VaultCredentialsSeeder`, surface:

```
Error: Credentials failed verification against <serverURL>.
  Not written to Keychain. Check clientID / clientSecret and retry.
  Detail: <message>

  If you are setting up before the vault is reachable (air-gapped install,
  vault-first-boot), re-run with --no-verify to write without verification.
```

The `--no-verify` hint is intentional — telling operators the escape hatch exists
at the moment they need it is friendlier than making them dig through `--help`.

### 5. Verify telemetry

Emit a structured event on every seed attempt, regardless of `verify` value. Route via
the existing shi-secrets logging seam (JSON one-liner to stderr, matching the
`SessionFingerprint` pattern; upgrade to `Logger` if the module later gains one):

```json
{
  "event": "shi.secrets.seed.verify",
  "systemName": "<canonical>",
  "clientIDPrefix": "<12-char-mask>",
  "serverURL": "<host-only>",
  "verify": "requested" | "skipped" | "success" | "failed",
  "latencyMs": <int>,
  "outcome": "seeded" | "underlyingFailure" | "invalidClientID" | ...
}
```

`shi doctor` will consume this event stream to surface:
- % of seeds using `--no-verify` (should be low; a spike suggests operators ignoring
  the safety default — worth investigating)
- Verify-latency distribution (vault health signal)
- Verify-failure rate over time (credential-rotation drift)

**Field `clientSecret` MUST NEVER appear in telemetry, logs, or errors.** Enforced by
test T-verify-06.

### 6. `MachineAccountSeeder.Outcome`

No new cases needed — `verifyFailed` already maps to `.underlyingFailure(message:)` in the
existing switch. The CLI layer surfaces this as a non-zero exit.

## WHO

- Maintainer: shi-secrets (Jeoffrey Thirot)
- Reviewer: operator

## WHEN

- W-next — after v0.5.2 ships
- Deferred because: v0.5.2 is a pure fix release (no new flags or behavior changes);
  the default-ON flip in this spec IS a behavior change and deserves its own release
  cadence (v0.6.0 minor bump).

---

## Acceptance Criteria

| ID | Criterion |
|----|-----------|
| AC-1 | `shi secrets setup wizard` (no explicit flag) DEFAULTS to `--verify` and calls the verification path |
| AC-2 | `shi secrets setup wizard --no-verify` skips the network probe and writes as today (offline path) |
| AC-3 | Verify failure → non-zero exit, nothing written to Keychain, clear operator message INCLUDING the `--no-verify` escape-hatch hint |
| AC-4 | Verify success → credentials written as today (identical existing behaviour) |
| AC-5 | `shi secrets login --reauth` mirrors the same `--verify` / `--no-verify` contract with the same default (ON) |
| AC-6 | Every seed emits `shi.secrets.seed.verify` telemetry event with correct `verify:` state (requested / skipped / success / failed), latency, masked clientID, host-only serverURL — and NEVER the clientSecret |
| AC-7 | `--no-verify` telemetry event carries explicit `verify: "skipped"` marker so `shi doctor` can distinguish operator opt-out from success/failure |

---

## Test Plan

### T-verify-01 — `seeder_verify_true_fails_fast_on_bad_credentials`

```swift
@Test("verify:true + bad creds → .underlyingFailure, nothing stored")
func seeder_verify_true_fails_fast_on_bad_credentials() async {
    let store = MAMockVaultCredentialStore()
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

### T-verify-03 — `seeder_verify_default_is_on` **[regression guard for default flip]**

```swift
@Test("verify param default is TRUE (fail-loud-by-default)")
func seeder_verify_default_is_on() async {
    let store = MAMockVaultCredentialStore()
    let recorder = MockVerifierRecorder()
    let seeder = MachineAccountSeeder(
        store: store,
        systemNameWriter: InMemorySystemNameWriter(),
        verifier: recorder
    )
    _ = await seeder.seed(
        candidateSystemName: "mac-laptop-shikki",
        clientID: "user.00000000-0000-0000-0000-000000000000",
        clientSecret: "any-token",
        serverURL: "https://vw.obyw.one",
        force: false
        // verify: omitted — MUST default to true
    )
    #expect(recorder.verifyCallCount == 1, "default must call verify path")
}
```

### T-verify-04 — `seeder_no_verify_skips_network_and_writes`

```swift
@Test("verify:false (--no-verify) → no verify call, writes immediately")
func seeder_no_verify_skips_network_and_writes() async {
    let store = MAMockVaultCredentialStore()
    let recorder = MockVerifierRecorder()
    let seeder = MachineAccountSeeder(
        store: store,
        systemNameWriter: InMemorySystemNameWriter(),
        verifier: recorder
    )
    let outcome = await seeder.seed(
        candidateSystemName: "mac-laptop-shikki",
        clientID: "user.00000000-0000-0000-0000-000000000000",
        clientSecret: "any-token",
        serverURL: "https://vw.obyw.one",
        force: false,
        verify: false
    )
    if case .seeded = outcome { /* ok */ }
    else { Issue.record("expected .seeded, got \(outcome)") }
    #expect(recorder.verifyCallCount == 0, "--no-verify MUST skip verify")
    let stored = await store.peek()
    #expect(stored != nil, "--no-verify must still write the credential")
}
```

### T-verify-05 — `reauth_command_defaults_to_verify_on` **[regression guard for --reauth mirror]**

```swift
@Test("shi secrets login --reauth defaults to --verify ON")
func reauth_command_defaults_to_verify_on() async throws {
    // Command-level: parse ["login", "--reauth"] with no --verify flag.
    // Assert parsed command.verify == true.
    // Assert the seeder path invoked from --reauth threads verify:true.
    let command = try SecretsLoginCommand.parseAsRoot(["login", "--reauth"])
    #expect((command as? SecretsLoginCommand)?.verify == true,
            "--reauth must default to verify: true, matching wizard")
}
```

### T-verify-06 — `seeder_emits_telemetry_event_on_every_path`

Cover all 3 verify states + assert no secret leakage.

```swift
@Test("seeder emits shi.secrets.seed.verify event with correct state + no clientSecret leak")
func seeder_emits_telemetry_event_on_every_path() async {
    // Iterate:
    //   (verify: true,  good creds)  → verify: "success"
    //   (verify: true,  bad creds)   → verify: "failed"
    //   (verify: false)              → verify: "skipped"
    // For each: assert emitted event has:
    //   - correct verify: field
    //   - masked clientID (12-char prefix)
    //   - host-only serverURL (no scheme/path)
    //   - latencyMs present
    //   - NO clientSecret substring anywhere in the event JSON
}
```

---

## Open Questions

None — resolved during 2026-07-01 draft review:

- **Default ON** — fail-loud-by-default matches shi convention. `--no-verify` is the
  offline escape hatch, not the default. The default flip is the load-bearing behavior
  change and gates this into a v0.6.0 (minor bump), not a v0.5.x patch.
- **Telemetry required** — every seed emits `shi.secrets.seed.verify` for `shi doctor`
  visibility over time. `clientSecret` NEVER appears in the event; enforced by test.
- **`--reauth` mirrors the flag** — same default (ON), same telemetry, same contract.
  Regression guard T-verify-05 enforces symmetry so future edits to one path can't
  silently diverge from the other.
