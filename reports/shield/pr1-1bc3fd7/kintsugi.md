# Kintsugi — /🛡️ Panel Report pr1-1bc3fd7

**Target:** pr/1 @ `1bc3fd71ae40757c0ed3c0e16b06347c5fa056ba`
**Branch:** `feat/setup-install-fix-and-dev-mode` → `main`
**Range:** `38e5f91..1bc3fd7` (3 commits, +469 / −28, 5 files)
**Lens:** philosophy, value alignment, long-tail design honesty

---

## Verdict (one line)

Functionally honest and well-tested, but ships with avoidable AI-marketing emoji slop, dual-path Main.swift complexity that will bit-rot, and a critical-path test plan with the end-to-end checkbox still unchecked while the PR is being landed.

---

## Findings

### Dangerous

**D-1 — AI-marketing emoji `🤖` in PR body violates emoji-whitelist policy**
The PR description footer carries `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. The Shikki emoji whitelist is `★ ⊘ 🌸 ❌ ❤️ 🇫🇷` (per `feedback_emoji-whitelist-extended-shikki-philosophy.md`). The robot emoji is exactly the "AI slop" the rule was written to keep out of the project's public surface. PR bodies are user-facing.

**D-2 — Shell-script glyphs `✘ ✓ →` operator-facing, off-whitelist**
`scripts/codesign-admin-key-ceremony.sh:25,28,46,50,54,62,68,70` prints `✘`, `✓`, and `→` to stdout/stderr. The script is invoked by `shi secrets setup install` so its output is operator-facing. Whitelist permits `❌` (not `✘`), and there is no whitelisted equivalent of `✓` or `→`. Either drop the glyphs or replace `✘`→`❌` and use ASCII for the rest.

**D-3 — Spec referenced via scratch path `~/.shikki/tmp/specs/...`**
PR body `[spec]: ~/.shikki/tmp/specs/shi-secrets-setup-install-fix-and-dev-mode-2026-06-19.md` and `DevMode.swift:1` cite a path under `~/.shikki/tmp/` — by convention scratch space, not durable. Anyone reading the PR in 3 months (post-rebase, post-`shi mop`) will follow a dead link. The spec belongs in `@db` (`shi_save_plan`/`shi_save_decision`) per `[[db-is-truth-no-files-flying-on-computer]]` — cite the @db key, not the tmp path. Same risk in `BrokerDaemon.swift:127` ("spec shi-secrets-setup-install-fix-and-dev-mode-2026-06-19 RC-3").

**D-4 — "shipped" claim against an unchecked end-to-end checkbox**
PR body says "Closes 4 root causes blocking `shi secrets setup install`" but the test-plan checkboxes for **(3) operator runs provisioning script in dev-mode → verify get/set roundtrip** and **(4) run against prod broker once kernel companion PR merges** are unchecked. Per `feedback_shipped-means-running-in-user-env.md`, the close-claim is premature: the daemon's `start()` path was modified (`BrokerDaemon.swift:189-204`) and only T1-T9 unit tests exercise it — no end-to-end live boot of the *modified* daemon is recorded in the PR. The "Live evidence" block in the body proves dev-mode comes up; it does not prove the prod path still works after the `if !devMode` rewrap.

### Suspect

**S-1 — Dual boot paths in `Main.swift` are a long-tail bit-rot magnet**
`Main.swift:52-110` is now two parallel init flows (dev / prod) that allocate `Bootstrap()` twice (the outer `let bootstrap = Bootstrap()` at line ~56 plus a shadowed re-declaration in the prod branch). The dev branch then constructs a real `Bootstrap()` that `BrokerDaemon` will never call (since `start()` gates on `if !devMode`). Three forces will rot this:
  - Every future preflight (manifest preload, kernel-job change, signing-key rotation) must remember to add a `if !devMode` skip in `start()` — easy to miss, silent in dev tests.
  - The shadowed `let bootstrap = Bootstrap()` is a footgun: a future reader who pulls the outer one will think they're rewiring both branches.
  - `_ = prodVaultClient  // suppress unused warning when dev-mode` (Main.swift:107) is a dead binding kept alive only by a comment. Honest design: make `Bootstrap` optional in `BrokerDaemon.init`, drop the `prodVaultClient` var, and stop allocating a `Bootstrap()` in the dev branch.

**S-2 — Pinned team identifier `SH7MZH647S` encoded as magic string in 3 places**
`scripts/codesign-admin-key-ceremony.sh:42,64` and PR title pin `SH7MZH647S` (OBYW.ONE). If the Apple Developer team is re-enrolled, ownership transfers, or the cert expires and is reissued under a new team ID, the script silently exits 70 ("team identifier mismatch") and the operator override `SHI_CODESIGN_IDENTITY` must be supplied. No `@db` decision reference embedded in the script error message — operator will not know *why* the team ID was pinned or where to find the rotation procedure. Add: the failure message should cite `@db key 2026-06-19` and the rationale ("matches the broker daemon's TeamIdentifier — both must rotate together").

**S-3 — `DevModeConfig` carries `[(name: String, value: String)]` tuples requiring hand-rolled `Equatable`**
`DevMode.swift:60-72` defines a custom `==` over a tuple array because Swift tuples are not `Equatable`. The "right" representation is a small `Sendable` struct (`DevSeed { name; value }`). Every future field added to a seed entry (e.g., `note`, `kind`) forces a re-hand-roll. This is petty design debt that compounds.

**S-4 — Ephemeral signing key per dev-mode boot, no operator warning**
`DevMode.swift:138` mints a fresh `Curve25519.Signing.PrivateKey()` on every dev-mode start. Any token minted against it dies the moment the daemon restarts — fine for dev, but the activation log line ("dev-mode ACTIVE — seeded 6 dev-* creds, socket=…") says nothing about this. A dev-mode operator restarting between an integration test's set/get round-trips will get cryptic "invalid signature" errors. One extra log line: `signing-key: ephemeral (regenerated per boot)`.

**S-5 — `assertSocketSafe` uses `.contains()` not `.hasPrefix()`**
`DevMode.swift:96` refuses any path containing `/.shikki/run/` anywhere — paranoid, which is good. But this also refuses a legitimate test fixture like `/tmp/.shikki/run/test-fixture.sock`. Low practical impact, worth a one-line comment ("intentionally over-refuses; .contains by design") so a future reader doesn't "fix" it to `.hasPrefix`.

**S-6 — `DevModeError.productionSocketPathRefused` swallows the original tilde**
`DevMode.swift:30` reports the expanded absolute path (`/Users/jeoffrey/.shikki/run/…`) but never the input the operator typed (`~/.shikki/run/…`). Trivial but matters for debug copy-paste.

### Sovereignty note (not a finding, surface only)

**N-1 — Apple Distribution dependency is unavoidable but worth a sentence**
The codesign path locks the project to the Apple Developer Program (US/Cupertino). There is no sovereign alternative for macOS Gatekeeper, so this is not a finding — but a one-liner in the script preamble acknowledging the trade-off (per Shikki sovereignty discipline: name your foreign deps openly, do not pretend they're not there) would honor the philosophy.

---

## What the PR gets right

- **Reuses `InMemoryBWClient` — no new noun spawned** (`DevMode.swift:17`). Honors `[[ai-spawns-new-noun-when-primitive-already-exists]]`.
- **4 layered safety guards** (`DevModeSafety.assertSocketSafe`, `assertEnvSafe`, `assertSeedSafe`) — defense in depth, each guarded by an XCTest.
- **`SHI_SECRETS_PRODUCTION=1` env opt-out** — operator has an explicit "no dev-mode here" kill-switch.
- **`dev-` prefix grep-discipline on seed values** — if a real password ever leaks into the seed list, the test (`test_T9_refuses_seed_value_not_dev_prefixed`) fails loudly. This is wabi-sabi: accept that humans will paste real values by accident, design the fence for it.
- **Brand integrity intact** — no `shiki` (single-k) regression in any modified file.

---

## Recommendation

**Hold for one revision** addressing D-1 (strip `🤖` from PR body), D-2 (replace `✘`/`✓`/`→` glyphs in the codesign script), and D-4 (run the end-to-end checkbox or downgrade the "Closes 4 root causes" language to "unblocks"). S-1 (dual-path bit-rot) and S-2 (team-ID hardcoding) should be filed as follow-up backlog items via `shi_save_backlog_item`, not blockers.

## Machine-readable findings

```json
[
  {"severity": "Dangerous", "title": "AI-marketing emoji 🤖 in PR body off whitelist", "evidence": "PR #1 body footer: '🤖 Generated with [Claude Code]'", "file": null, "line": null},
  {"severity": "Dangerous", "title": "Off-whitelist glyphs ✘ ✓ → in operator-facing codesign script", "evidence": "echo '✘ binary not found' / '✓ codesign complete' / '→ codesigning' — whitelist allows ❌ only", "file": "scripts/codesign-admin-key-ceremony.sh", "line": 25},
  {"severity": "Dangerous", "title": "Spec cited via scratch path ~/.shikki/tmp/specs/ — dead link risk", "evidence": "PR body [spec]: ~/.shikki/tmp/specs/shi-secrets-setup-install-fix-and-dev-mode-2026-06-19.md ; also DevMode.swift comment", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 1},
  {"severity": "Dangerous", "title": "'Closes 4 root causes' claim while test-plan end-to-end checkbox is unchecked", "evidence": "PR body claims close, checkboxes (3) provisioning script roundtrip + (4) prod-broker run unchecked", "file": null, "line": null},
  {"severity": "Suspect", "title": "Dual boot paths in Main.swift will bit-rot; shadowed Bootstrap + dead prodVaultClient binding", "evidence": "Main.swift constructs Bootstrap() twice (outer + prod-branch shadow); _ = prodVaultClient suppression line", "file": "Sources/ShiSecretsBrokerd/Main.swift", "line": 56},
  {"severity": "Suspect", "title": "Team ID SH7MZH647S hardcoded with no @db rotation pointer in error message", "evidence": "Script exits 70 on mismatch but error text lacks the @db decision reference operators would need to rotate", "file": "scripts/codesign-admin-key-ceremony.sh", "line": 64},
  {"severity": "Suspect", "title": "DevModeConfig uses tuple array forcing hand-rolled Equatable; refactor debt compounds per added field", "evidence": "[(name: String, value: String)] requires custom == in DevModeConfig", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 60},
  {"severity": "Suspect", "title": "Ephemeral Ed25519 signing key per boot, no operator-facing warning", "evidence": "Curve25519.Signing.PrivateKey() minted per call; activation log line omits 'ephemeral'", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 138},
  {"severity": "Suspect", "title": "assertSocketSafe uses .contains() not .hasPrefix() — intentional paranoia, mark it as such", "evidence": "absolute.contains(productionSocketPrefix) would refuse /tmp/.shikki/run/ fixture paths; needs comment", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 96},
  {"severity": "Suspect", "title": "productionSocketPathRefused reports expanded path only, drops operator-typed tilde", "evidence": "Error description shows /Users/jeoffrey/.shikki/run/… not original ~/.shikki/run/…", "file": "Sources/ShiSecretsBrokerd/DevMode.swift", "line": 30}
]
```
