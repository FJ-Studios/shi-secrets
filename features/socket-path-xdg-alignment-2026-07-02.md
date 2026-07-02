# shi-secrets socket-path XDG alignment (P0 beta blocker)

**Backlog:** `209d7d6c-4a23-48f2-8d71-fdb962f1eb16` (shikki-db)
**Companion of:** shikki #1290 (CREDENTIALS_DIRECTORY plist fix, merged 2026-07-01)

## Problem

`shi secrets doctor` reports:

```
Broker socket: /Users/jeoffrey/.shikki/run/secrets-brokerd.sock
  (source: default — ~/.shikki/run/secrets-brokerd.sock)
```

but the daemon actually binds `/Users/jeoffrey/.local/share/shikki/run/secrets-brokerd.sock` (shikki's `LaunchAgentManager` passes the XDG path via `--socket` in `ProgramArguments`). Client and server look at different paths → **"broker unavailable"** every fresh install, even when the daemon is `RUNNING`.

Current workaround: hand-symlink `~/.shikki/run/... → ~/.local/share/shikki/run/...`. Fragile — new machines / fresh installs hit this every time.

## Solution

Align every hardcoded client-side default to shikki's XDG-native path:

```
~/.shikki/run/secrets-brokerd.sock  →  ~/.local/share/shikki/run/secrets-brokerd.sock
```

The env override `SHIKKI_SECRETS_BROKERD_SOCKET` (used via `??`) stays; only the fallback default changes. Daemon-side default (`ShiSecretsBrokerd/Main.swift:112`) also updated so a standalone `shikki-secrets-brokerd` invocation (no `--socket`) binds the same path the client will look for.

## Files (7)

- `Sources/ShiSecretsClient/SocketConnection.swift` — client library default
- `Sources/ShiSecretsBrokerd/Main.swift` — daemon default + comment
- `Sources/ShiSecrets/Commands/StatusCommand.swift`
- `Sources/ShiSecrets/Commands/LoginCommand.swift`
- `Sources/ShiSecrets/Commands/DoctorCommand.swift` — 2 refs (description string + default)
- `Sources/ShiSecrets/PluginRegistration.swift`
- `Sources/ShiSecrets/Commands/SecretsSetupWizardCommand.swift` — 3 refs

Test target: extend an existing `Tests/ShiSecretsClientTests/` or add `Tests/SocketConnectionDefaultPathTests/`.

## Test plan

1. RED: assert `SocketConnection.defaultSocketPath()` (or equivalent) returns `~/.local/share/shikki/run/secrets-brokerd.sock` — will fail against pre-fix code.
2. GREEN: change 10 sites → assertion passes.

## Risk

**Low.** Path constant change; env override path unchanged. Any operator who relied on the old `~/.shikki/run/` default keeps working via the symlink they may already have (my session's workaround), or drops it — either way non-breaking. Fresh installs finally work first-try.

## Step-verify plan

```
1. Write mini-spec (this file)                            → verify: user approves
2. Write RED test on SocketConnection default path        → verify: kagami/swift test RED
3. Change 10 site defaults + daemon fallback              → verify: kagami test GREEN
4. Regen Package.resolved if needed (no dep changes)      → verify: swift build clean
5. Self-review git diff                                   → verify: 7 files, 10 mechanical swaps, no scope creep
6. Commit + PR to develop                                 → verify: commit hash exists + PR URL
```
