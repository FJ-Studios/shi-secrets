# tech-expert — /🛡️ Panel Report pr-1-1bc3fd71

**Target:** pr/1 @ 1bc3fd71ae40757c0ed3c0e16b06347c5fa056ba
**Branch:** feat/setup-install-fix-and-dev-mode
**Scope:** dev-mode broker (313c028) + dev-mode hang fix (1bc3fd7) + the standing v0.1.0 extraction (38e5f91) viewed through tech-expert lens (idiom, tests, error handling, perf, operability).

## Verdict
- **2 Critical** — block merge.
- **3 Dangerous** — should land follow-ups before tagging v0.1.x.
- **6 Suspect** — corroborate with security/operability before escalating.

---

## Critical

### C1 — Production boot calls `Bootstrap.unseal()` twice
- **Where:** `Sources/ShiSecretsBrokerd/Main.swift:94` (first call) + `Sources/ShiSecretsBrokerd/BrokerDaemon.swift:195` (second call inside `start()`)
- **Evidence:** Main.swift's prod branch already does `(prodVault, signingKey) = try await bootstrap.unseal()`, then constructs `BrokerDaemon(... bootstrap: bootstrap, ...)`. `BrokerDaemon.start()` then runs `if !devMode { let (vaultClient, _) = try await bootstrap.unseal() ... }` — a second unseal against the same `Bootstrap` instance.
- **Why it matters:** Each `Bootstrap.unseal()` hits Keychain (read-by-ACL prompt risk on macOS), reconstructs `VaultwardenClient`, and re-authenticates with Vaultwarden. Side effects: a) two keychain ACL prompts per cold boot, b) double Vaultwarden auth (rate-limit risk + audit-log doubling), c) a different vault state can be returned on the second call (TOCTOU), d) network flakes turn boots into 50/50 failures because either unseal can throw.
- **Root cause:** The dev-mode fix in 1bc3fd7 added `if !devMode { ... bootstrap.unseal() ... }` to `BrokerDaemon.start()` but did NOT remove the pre-existing prod call in Main.swift (Main.swift:94). The intent of the fix was to *skip* unseal in dev-mode, but it left the prod path doing it twice.
- **Fix:** Either (a) remove the unseal call from `BrokerDaemon.start()` entirely (Main.swift already produces the wired `ProductionBWClient`), or (b) remove the unseal call from `Main.swift:94` and stop reading `signingKey` from it (compute `signingKey` inside `start()` instead). Option (a) is the minimal change and matches the dev-mode invariant (bwClient arrives pre-wired in both branches).

### C2 — `adminVerifier` is never wired in production; `revokeAllBots(signedBy:)` always refuses
- **Where:** `Sources/ShiSecretsBrokerd/Main.swift:156-172` (BrokerDaemon init), `Sources/ShiSecretsBrokerd/BrokerDaemon.swift:119,555`
- **Evidence:** `BrokerDaemon.init(... adminVerifier: AdminActionVerifier? = nil, ...)` — the prod entrypoint never passes one. `revokeAllBots(signedBy:)` guards with `guard let verifier = adminVerifier else { ... throw .adminSignatureInvalid }`. So every passkey-signed admin action fails at the broker.
- **Why it matters:** The BR-F-08/-09/-10/-11 contract is silently disabled in shipped binaries. Operators wiring the ceremony binary will see signed envelopes rejected with `adminSignatureRequired` and have no in-code path to fix without recompiling. The docstring on `adminVerifier` even says "production wiring is required by `ShiSecretsModule`" — but Main.swift hand-wires and bypasses ShiSecretsModule entirely.
- **Fix:** Either thread `AdminActionVerifier(pinnedAdminKey: ...)` into Main.swift's BrokerDaemon init, or replace the hand-wire in Main.swift with `ShikkiSecretsModule.boot()` so the documented wiring path actually runs.

---

## Dangerous

### D1 — Shadowed `let bootstrap` in Main.swift's prod branch
- **Where:** `Sources/ShiSecretsBrokerd/Main.swift:64` (outer) vs `Main.swift:91` (inner, inside `else` branch)
- **Evidence:** `let bootstrap = Bootstrap()` is declared twice. The outer (line 64) is what gets passed into `BrokerDaemon(... bootstrap: bootstrap, ...)`. The inner (line 91) shadows it for the immediate unseal at line 94.
- **Why it matters:** Today `Bootstrap()` is parameterless and stateless, so the two instances are interchangeable. The day `Bootstrap` gains state (cached session, retry budget, signing-key cache), the outer instance handed to BrokerDaemon will diverge from the inner one that actually ran unseal — silent invariant break. This is a textbook refactor-hazard smell.
- **Fix:** Remove the inner `let bootstrap = Bootstrap()` and use the outer.

### D2 — `prodVaultClient` is dead-stored / dead-read
- **Where:** `Sources/ShiSecretsBrokerd/Main.swift:59,82,102,106`
- **Evidence:** Declared `let prodVaultClient: VaultwardenClient?`, assigned `nil` in dev branch and `prodVault` in prod branch, then escaped via `_ = prodVaultClient  // suppress unused warning when dev-mode`. The value is never read after the if/else.
- **Why it matters:** Either this is a debug-removal victim (in which case the code path it represented is now silently missing) or it's deliberate scaffolding (in which case `_ =` is the wrong idiom — a comment explaining "kept for future MCP bridge wire" would communicate that). The `_ =` line is invisible to grep for "unused" and reads as a code-smell shrug.
- **Fix:** Delete `prodVaultClient` everywhere, or wire it to whatever was supposed to consume it (likely `MCPBridge` or the kernel job set).

### D3 — Launchd detection is a fragile substring heuristic
- **Where:** `Sources/ShiSecretsBrokerd/DevMode.swift:101-108`
- **Evidence:** `if let xpc = env["XPC_SERVICE_NAME"], xpc.contains(".") { throw .launchdLaunchRefused(...) }`. Comment claims real launchd services use reverse-DNS (containing a dot) while XCTest uses sentinel "0".
- **Why it matters:** Launchd is free to issue services with non-reverse-DNS names — `Bootstrap`, `system_legacy_xpc`, anything an operator hand-rolls. A `com.example.svc` matches; `comExample` doesn't. The refusal is the LAST safety gate before dev seed creds get bound to a launchd-managed socket, so a false-negative is high-impact.
- **Fix:** Replace heuristic with multi-signal check: refuse if `getppid() == 1` AND `isatty(STDIN_FILENO) == 0`, OR if `LAUNCHD_SOCKET` is set, OR if the binary's path starts with `/Library/LaunchAgents/` or `~/Library/LaunchAgents/`. The substring check can stay as a belt, but it must not be the suspenders.

---

## Suspect

### S1 — `assertSocketSafe` does not resolve symlinks
- **Where:** `DevMode.swift:84-93`
- **Evidence:** `let absolute = (path as NSString).expandingTildeInPath` followed by `absolute.contains("/.shikki/run/")`. No `URL.resolvingSymlinksInPath()` or `realpath(3)`.
- **Why suspect:** An attacker (or honest mistake) creating a symlink at `/tmp/dev.sock → ~/.shikki/run/secrets-brokerd.sock` defeats the check — dev-mode binds to the symlinked production path. The dev seed creds would then be served from the production socket inode. To corroborate as Dangerous: test whether dev-mode actually binds through a symlink (a unit test creating the symlink + asserting throw would settle it).

### S2 — Tests never bind a socket; coverage gap on the real boot path
- **Where:** `Tests/ShiSecretsBrokerdTests/DevModeTests.swift` (entire file)
- **Evidence:** All tests use `/tmp/...sock` socketPaths but stop at `DevModeBootstrap.unseal()` — none exercise `UnixSocketServer.start()` or a real socket bind/connect under dev-mode. The commit message substitutes "LIVE evidence" copy-paste.
- **Why suspect:** Idiomatic Swift integration tests can bind a socket under `XCTestCase.setUp` (Wave-1 broker tests already do this — `BrokerDaemonTests.swift` lives in the same target). The dev-mode happy-path is asserted only by hand-typed shell evidence in commit messages, which goes stale invisibly. A 5-line "boot dev-mode, connect, call `list`, assert dev-* creds" test would close this.

### S3 — Hand-rolled arg parser duplicates env-var parsing surface
- **Where:** `DevMode.swift:152-178`, `Main.swift:70-72`
- **Evidence:** `DevModeArgs.parse` recognizes `--dev-mode`, `--socket`, `--socket=`. `Main.swift` then also reads `SHIKKI_BROKER_SOCKET` env and falls back to `/tmp/shi-secrets-dev-<uid>.sock`. The arg parser silently ignores all unknown args including `--help`.
- **Why suspect:** Three sources of truth (flag, env, default) with no `--help` and no rejection of unknown flags. The codebase elsewhere uses argument-parser; this divergence is a maintainer trap. Either add `--help` + reject unknown args, or move to swift-argument-parser.

### S4 — `BrokerDaemon.start()` socket preflight inverts try/catch
- **Where:** `BrokerDaemon.swift:221-225`
- **Evidence:**
  ```swift
  do {
      try await socket.verifyOnDiskInvariant()
  } catch {
      try await socket.start()
  }
  ```
- **Why suspect:** This says "if verify fails for ANY reason, bind a new socket." If `verifyOnDiskInvariant` throws because of *wrong permissions* on an existing socket (rather than the socket-doesn't-exist case), this swallows the perm error and tries to `start()` on top — which will throw a different error. The intent is "bind if not bound" — but the code conflates "not bound" with "any verify error." A typed switch on the throw kind would make the intent explicit. (Not blocking but operationally confusing during incident response.)

### S5 — Codesign script documents `SHI_CODESIGN_KEYCHAIN` but never uses it
- **Where:** `scripts/codesign-admin-key-ceremony.sh:16` (doc) — no consumer
- **Evidence:** Usage comment promises `SHI_CODESIGN_KEYCHAIN — keychain to search (default: login.keychain-db)`. No `--keychain` flag is passed to `codesign` or `security`. Operators setting this env will see no behavior change.
- **Why suspect:** Documentation lie. Either wire `security default-keychain -s "$SHI_CODESIGN_KEYCHAIN"` (with restore in `trap`), or delete the doc.

### S6 — `--force` on codesign in the release ceremony script
- **Where:** `scripts/codesign-admin-key-ceremony.sh:53`
- **Evidence:** `codesign --sign ... --force "$BINARY"` — silently overwrites any existing signature.
- **Why suspect:** Useful for dev iteration, risky for release. A release path that has already produced a notarized signature can be re-signed over (and de-notarized) without warning. Idiomatic release scripts check `codesign -dv "$BINARY"` first and refuse to re-sign unless `SHI_CODESIGN_REPLACE=1` is set.

---

## Operability notes (not classified as findings; surface to operator)
- The dev-mode boot prints `--dev-mode ACTIVE` to stderr but uses unstructured text. The broker target has no `AppLog` wired (acknowledged at BrokerDaemon.swift:499 with a TODO-style comment). Until that lands, `shi-secrets-brokerd` dev-mode boots can't be machine-parsed by the kernel session log.
- The fresh Ed25519 signing key on every dev boot (DevMode.swift:143) means dev SBTs minted in session A won't verify in session B. Expected, but worth a one-line note in the spec so operators don't chase phantom verifier bugs.
- No `--help` on `shi-secrets-brokerd`. Hand-rolled parser silently accepts any unknown flag. Discoverability concern.

---

## Machine-readable findings (REQUIRED)

```json
[
  {"severity": "Critical", "title": "Production Bootstrap.unseal() runs twice on every boot", "evidence": "Main.swift:94 calls unseal then BrokerDaemon.start():195 calls it again on the same Bootstrap instance. Double keychain access + double Vaultwarden auth + TOCTOU window. Dev-mode fix (1bc3fd7) added the second call without removing the first.", "file": "Sources/ShiSecretsBrokerd/BrokerDaemon.swift", "line": 195},
  {"severity": "Critical", "title": "adminVerifier never wired in Main.swift, revokeAllBots silently disabled in prod", "evidence": "BrokerDaemon init at Main.swift:156-172 omits adminVerifier; defaults to nil; revokeAllBots(signedBy:) at BrokerDaemon.swift:555 refuses every signed action with adminSignatureRequired. BR-F-08/-09/-10/-11 contract not enforceable.", "file": "Sources/ShiSecretsBrokerd/Main.swift", "line": 156},
  {"severity": "Dangerous", "title": "Shadow let bootstrap in Main.swift prod branch", "evidence": "Outer Bootstrap() at line 64 is what BrokerDaemon receives; inner Bootstrap() at line 91 is what actually runs unseal. Harmless today because Bootstrap is stateless; breaks the day Bootstrap gains a cached session.", "file": "Sources/ShiSecretsBrokerd/Main.swift", "line": 91},
  {"severity": "Dangerous", "title": "prodVaultClient is dead-stored and silenced with _ = assignment", "evidence": "Declared at line 59, conditionally assigned, never read. _ = prodVaultClient at line 106 hides the unused warning instead of removing the dead code or wiring the intended consumer.", "file": "Sources/ShiSecretsBrokerd/Main.swift", "line": 106},
  {"severity": "Dangerous", "title": "Launchd detection is a substring heuristic; bypassable by non-reverse-DNS service names", "evidence": "xpc.contains('.') refuses 'com.example.svc' but allows 'Bootstrap' or any launchd service without a dot. This is the last gate before dev-* seed creds bind to a launchd-managed socket.", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 102},
  {"severity": "Suspect", "title": "assertSocketSafe does not resolve symlinks", "evidence": "expandingTildeInPath only; no realpath. A symlink at /tmp/dev.sock → ~/.shikki/run/secrets-brokerd.sock defeats the production-path check.", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 85},
  {"severity": "Suspect", "title": "DevMode tests never bind a real socket — coverage gap", "evidence": "All 15 tests stop at DevModeBootstrap.unseal(); no UnixSocketServer.start()+connect+list assertion under dev-mode. Live evidence in commit message substitutes for a test.", "file": "Tests/ShiSecretsBrokerdTests/DevModeTests.swift", "line": 1},
  {"severity": "Suspect", "title": "Hand-rolled arg parser silently accepts unknown flags; no --help", "evidence": "DevModeArgs.parse only recognizes --dev-mode/--socket. Three sources of socket truth (flag, SHIKKI_BROKER_SOCKET env, default). No --help. Diverges from codebase argument-parser usage.", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 158},
  {"severity": "Suspect", "title": "BrokerDaemon.start socket preflight inverts try/catch and swallows non-rebind errors", "evidence": "do { try verifyOnDiskInvariant() } catch { try start() } — if verify throws because of wrong permissions on an existing socket, the catch tries to bind on top instead of surfacing the perm error.", "file": "Sources/ShiSecretsBrokerd/BrokerDaemon.swift", "line": 221},
  {"severity": "Suspect", "title": "Codesign script documents SHI_CODESIGN_KEYCHAIN env override but never uses it", "evidence": "Usage comment at line 16 promises keychain selection; no --keychain flag is passed to codesign or security. Documentation lies to operators.", "file": "scripts/codesign-admin-key-ceremony.sh", "line": 16},
  {"severity": "Suspect", "title": "codesign --force in release ceremony script silently overwrites existing signatures", "evidence": "Line 53 uses --force unconditionally; a notarized binary can be re-signed (and de-notarized) without warning. Release ceremonies should refuse re-sign unless an explicit override env is set.", "file": "scripts/codesign-admin-key-ceremony.sh", "line": 53}
]
```
