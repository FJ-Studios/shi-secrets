// ShiSecretsKit — Wave 1 scaffold marker.
//
// This module aggregates token envelope, rotation engine, audit + seams
// writers, scope validation, and manifest verification. Wave 1 delivers
// DB migration SQL (as resources) and the foundational enums / structs.
// Later waves layer on TokenRegistry, RotationEngine, ManifestVerifier,
// etc. Keep this file intentionally empty of logic so accidental
// top-level state cannot leak across test suites.

public enum ShiSecretsKit {
    /// Semantic version string for build-time diagnostics.
    public static let version = "0.1.0"
}
