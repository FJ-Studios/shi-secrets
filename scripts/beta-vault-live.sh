#!/usr/bin/env bash
# Vault-live e2e — touches your real Vaultwarden + Keychain. NOT for CI.
# Part of Master Spec §1.4 — shi-secrets-hanko-beta cluster.
set -euo pipefail
echo "WARNING: this script touches your live Vault credentials."
echo "Press Ctrl-C in 5s to abort, or wait to proceed..."
sleep 5
kagami test --strict --scope e2e-brokerd-vault-live
