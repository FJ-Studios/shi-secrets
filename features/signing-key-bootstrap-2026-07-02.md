# shi-secrets first-run signing-key bootstrap (P0 beta blocker)

**Backlog:** `8cc9c1f0-32cb-418f-80d5-824b0abb339d` (shikki-db)
**Companion of:** shikki #1290 (CREDENTIALS_DIRECTORY plist env var, merged 2026-07-01)

## Problem

`shi secrets brokerd start` on a fresh install → the daemon fires, `Bootstrap.unseal()` calls `loadSigningKey()`, which:
1. Reads `$CREDENTIALS_DIRECTORY/broker-signing-key` — file DOES NOT EXIST on a fresh install
2. On production macOS/Linux → throws `BootstrapError.signingKeyMissing`
3. Daemon crashes → `launchd` restarts it → crash-loops forever

The stderr log accumulates thousands of `signingKeyMissing` lines (1.8 MB on my box). Nothing in the setup flow ever generates the key file. The operator has to `head -c 32 /dev/urandom > ~/.shikki/credentials/broker-signing-key && chmod 600 …` by hand.

## Solution

Add a small, standalone `BrokerSigningKeyProvisioner` that generates the 32-byte Ed25519 seed if absent (`0600` perms) and wire it as an explicit step in `SecretsSetupWizardCommand`. Also add a check to `DoctorCommand` so a broken install surfaces the missing key clearly instead of via the daemon's opaque crash-loop.

## Contract

```swift
public enum BrokerSigningKeyProvisioner {
    /// Ensure a 32-byte Ed25519 seed exists at CREDENTIALS_DIRECTORY/broker-signing-key.
    /// - Generates a fresh key iff the file is absent OR empty.
    /// - Always sets file mode to 0o600 (owner-read-only).
    /// - Returns `.provisioned` when a new key was written, `.alreadyPresent` when kept as-is.
    /// - Throws on FileManager / write failure.
    public static func provisionIfNeeded(
        credentialsDir: URL,
        keyName: String = "broker-signing-key",
        random: @Sendable () -> Data = { Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }
    ) throws -> ProvisionOutcome
}

public enum ProvisionOutcome: Sendable, Equatable {
    case provisioned    // new key generated + written
    case alreadyPresent // existing key kept unchanged
}
```

The `random` closure defaults to `UInt8.random(in:)` (system CSPRNG) but is injectable so the test can pin a deterministic seed.

## Files

- `Sources/ShiSecretsBrokerd/BrokerSigningKeyProvisioner.swift` — NEW, ~60 LOC.
- `Sources/ShiSecrets/Commands/SecretsSetupWizardCommand.swift` — invoke `provisionIfNeeded` before the plist-bootstrap step.
- `Sources/ShiSecrets/Commands/DoctorCommand.swift` — add "signing key present?" check with a clear "regenerate via `shi secrets setup keys`" hint on miss.
- `Tests/ShiSecretsBrokerdTests/BrokerSigningKeyProvisionerTests.swift` — NEW, 3 tests.

## Test plan

1. **RED**: `provisioned when file absent` — call `provisionIfNeeded` on empty temp dir → returns `.provisioned`, file at `dir/broker-signing-key` exists with 32 bytes + 0600 perms. FAILS before the new type exists.
2. **GREEN pass**: `alreadyPresent when file exists` — pre-seed the file, call `provisionIfNeeded` → returns `.alreadyPresent`, file bytes unchanged.
3. **GREEN pass**: `0600 permissions enforced` — pre-seed with 0644, call `provisionIfNeeded` → file mode is fixed to 0600.

## Risk

**Low.** Standalone utility with clean DI (random-closure + credentialsDir URL). The daemon's `loadSigningKey()` is unchanged — this only adds a provisioning step BEFORE the daemon starts. If the provisioner ever fails, the wizard surfaces the error at setup time instead of the daemon crash-looping silently.

## Step-verify plan

```
1. Write mini-spec (this file)                             → verify: exists
2. Write RED tests for the 3 provisioner behaviors         → verify: swift test FAIL (type missing)
3. Add BrokerSigningKeyProvisioner.provisionIfNeeded       → verify: swift test PASS (3/3)
4. Wire into SecretsSetupWizardCommand                     → verify: swift build clean
5. Add doctor check + hint                                 → verify: swift build clean
6. Self-review git diff                                    → verify: 4 files, matches spec
7. Commit + PR                                             → verify: PR URL
```
