# shi-secrets Broker Wire Date Format

**Spec:** e8c4a921-7d3b-4f5e-9a2c-1d6b8f4e3a91 (shi-secrets + hanko one-click vault system)
**Wave:** W0 — Wire format canonicalization
**Operator mandate:** 2026-06-24 — "we don't care, I'm the only one to use it now so fucking kill it and have only one SoT!"

---

## Canonical format

All date fields in broker wire messages use **ISO 8601 RFC 3339 UTC, whole-second precision**:

```
"2026-06-24T08:30:00Z"
```

### Rules

- **String** — always a JSON string, never a number.
- **UTC** — always `Z` suffix. No local offsets, no `+HH:MM`.
- **Whole-second** — fractional seconds (`.sss`) are accepted on decode but
  never emitted. Producers MUST NOT emit sub-second precision.
- **Required** — date fields are non-optional. A missing or null `last_rotated`
  / `rotation_due` is a protocol error and will throw `DecodingError`.

### Encoder configuration (all call sites)

```swift
let encoder = JSONEncoder()
encoder.dateEncodingStrategy = .iso8601
```

### Decoder configuration (all call sites)

```swift
let decoder = JSONDecoder()
decoder.dateDecodingStrategy = .iso8601
```

---

## Affected fields

| Field | Type | Struct | Wire key |
|-------|------|--------|----------|
| `lastRotated` | `Date` | `VaultEntryRef` | `last_rotated` |
| `rotationDue` | `Date` | `VaultEntryRef` | `rotation_due` |

---

## Exception list — JWT / SBT fields

The following date fields follow **RFC 7519 Section 4.1** (Unix integer seconds)
and are explicitly excluded from the ISO 8601 mandate:

| Field | Type | Struct | Notes |
|-------|------|--------|-------|
| `iat` | Unix int | `ShikkiSBT` | Issued-at, JWT standard |
| `nbf` | Unix int | `ShikkiSBT` | Not-before, JWT standard |
| `exp` / `dies_at` | Unix int | `ShikkiSBT` | Expiry, JWT standard |

These fields live in `Sources/ShiSecretsKit/Token/` and are handled with
`dateEncodingStrategy = .iso8601` on the SBT envelope, but the JWT payload
sub-claims use raw integer encoding per the JWT spec.

---

## What was removed (W0)

### `decodeFlexibleDate` (eliminated entirely)

The former `VaultEntryRef.decodeFlexibleDate` helper attempted three fallback
paths:

1. ISO 8601 string — parse with `ISO8601DateFormatter`
2. Unix epoch `Double` — convert with `Date(timeIntervalSince1970:)`
3. Null / missing — return `Date.distantPast`

**All three non-canonical paths are removed.** The struct now uses synthesized
`Codable` conformance. Callers that set `dateDecodingStrategy = .iso8601` will
decode ISO 8601 strings transparently. A `Double` or `null` input is a
`DecodingError` — not a silent fallback.

---

## Migration note

Prior broker versions (pre-W0) may have emitted `Double` values for
`last_rotated`. These values are **invalid** as of W0. Since this is a
single-operator deployment, no migration window is provided. Any stored
`Double` dates in upstream systems must be re-written as ISO 8601 strings
before connecting to a W0+ broker.

---

## Regression tests

See `Tests/ShiSecretsKitTests/BrokerWireDateFormatTests.swift`:

| Test ID | Description |
|---------|-------------|
| T-W0-01 | Encode produces ISO 8601 string (not Double) |
| T-W0-02 | Decode accepts ISO 8601 string |
| T-W0-03 | Decode **throws** on Double input |
| T-W0-04 | Decode **throws** on null input |
| T-W0-05 | All serialization sites use `.iso8601` dateEncodingStrategy |
| T-W0-06 | Regression guard — no `secondsSince1970` in non-JWT code |
