#!/usr/bin/env bash
# codesign-admin-key-ceremony.sh — RC-2 closure of spec
# shi-secrets-setup-install-fix-and-dev-mode-2026-06-19.
#
# Codesigns the built shi-admin-key-ceremony binary with hardened
# runtime + the AdminKeyCeremony.entitlements + the OBYW.ONE Apple
# Distribution identity (SH7MZH647S — pinned per @db decision
# 2026-06-19; matches the broker daemon's TeamIdentifier).
#
# Usage:
#   codesign-admin-key-ceremony.sh <binary-path>
#
# Env overrides:
#   SHI_CODESIGN_IDENTITY    — codesigning identity name or team id
#                              (default: Apple Distribution: OBYW.ONE — SH7MZH647S)
#   SHI_CODESIGN_KEYCHAIN    — keychain to search (default: login.keychain-db)
#   SHI_CODESIGN_VERIFY      — set to 0 to skip post-sign verify (default: 1)

set -euo pipefail

BINARY="${1:-}"
if [[ -z "$BINARY" ]]; then
  echo "usage: $0 <binary-path>" >&2
  exit 64
fi
if [[ ! -f "$BINARY" ]]; then
  echo "✘ binary not found: $BINARY" >&2
  exit 66
fi

# Resolve the entitlements bundled alongside the AdminKeyCeremony source.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENT="$REPO_ROOT/Sources/AdminKeyCeremony/AdminKeyCeremony.entitlements"
if [[ ! -f "$ENT" ]]; then
  echo "✘ entitlements missing: $ENT" >&2
  exit 65
fi

# Identity — default to OBYW.ONE Apple Distribution per @db decision
# 2026-06-19. The broker daemon already runs with TeamIdentifier=SH7MZH647S.
IDENTITY="${SHI_CODESIGN_IDENTITY:-Apple Distribution: OBYW.ONE (SH7MZH647S)}"

echo "→ codesigning $BINARY"
echo "  identity:     $IDENTITY"
echo "  entitlements: $ENT"
# The shi verb greps this exact prefix to surface to the operator.
echo "Codesigning with: $IDENTITY"

codesign \
  --sign "$IDENTITY" \
  --entitlements "$ENT" \
  --options runtime \
  --timestamp \
  --force \
  "$BINARY"

if [[ "${SHI_CODESIGN_VERIFY:-1}" != "0" ]]; then
  echo "→ verifying signature"
  codesign --verify --strict --verbose=2 "$BINARY"
  echo
  echo "→ signature summary"
  codesign -dv "$BINARY" 2>&1 | sed 's/^/  /'
  echo
  TEAM=$(codesign -dv "$BINARY" 2>&1 | awk -F'=' '/TeamIdentifier/ {print $2}')
  if [[ "$TEAM" != "SH7MZH647S" && -z "${SHI_CODESIGN_IDENTITY:-}" ]]; then
    echo "✘ team identifier mismatch — expected SH7MZH647S (OBYW.ONE), got '$TEAM'" >&2
    echo "  (override with SHI_CODESIGN_IDENTITY env)" >&2
    exit 70
  fi
fi

echo "✓ codesign complete — $BINARY"
