import Foundation
import ShiSecretsKit
import ShiSecretsClient

// BlastRadiusGraph — `shi secret blast-radius <jti>` scope graph (T60 — BR-F-05).
//
// Renders a read-only tree view over the TokenRegistry: "if this jti is
// compromised, what other scopes / tokens share a parent sub?". The
// engine does NOT mutate any state — it only reads. A snapshot test
// pins the rendered shape so CLI UI drift is caught.
//
// Tree shape (plain ASCII; no ANSI colors in the snapshot form).
// Review finding #11 — prefix(4) + suffix(4) so ellipsis form stays
// symmetric: `01JC…0K7P` instead of `01JC…K7P`.
//
//   root  jti=01JC…0K7P  sub=ci@nuc-dev  scope=ovh/dns/*
//   ├─ 01JC…0K7Q  scope=ovh/dns/*          op=read
//   ├─ 01JC…0X9M  scope=ovh/compute/*      op=read
//   └─ 01JC…0P2F  scope=ovh/billing/*      op=rotate

public enum BlastRadiusGraph {

    /// Renders a BlastRadiusReport as a tree. Pure function — the test
    /// pins a fixed report and compares against an inline string literal.
    public static func render(_ report: BlastRadiusReport) -> String {
        var lines: [String] = []
        lines.append("root  jti=\(shorten(report.rootJti))  sub=\(report.sub)  scope=\(report.scope)")
        let count = report.dependents.count
        for (i, dep) in report.dependents.enumerated() {
            let glyph = (i == count - 1) ? "└─" : "├─"
            lines.append("\(glyph) \(shorten(dep.jti))  scope=\(dep.scope)")
        }
        if report.dependents.isEmpty {
            lines.append("(no dependents — blast radius contained to this token)")
        }
        return lines.joined(separator: "\n")
    }

    /// Compute a blast-radius report from a `TokenRegistry` snapshot.
    /// Pure + read-only — never mutates registry state. "Dependents" are
    /// other tokens under the same `sub`.
    public static func compute(
        rows: [TokenRegistry.Row],
        rootJti: String
    ) -> BlastRadiusReport? {
        guard let root = rows.first(where: { $0.jti == rootJti }) else {
            return nil
        }
        let deps = rows
            .filter { $0.sub == root.sub && $0.jti != root.jti }
            .map { BlastRadiusReport.Dependent(jti: $0.jti, scope: $0.scope) }
            .sorted(by: { $0.jti < $1.jti })
        return BlastRadiusReport(
            rootJti: root.jti,
            sub: root.sub,
            scope: root.scope,
            dependents: deps
        )
    }

    /// Display-only: `01JC…0K7P`-style 4-prefix + 4-suffix ellipsis.
    /// Review finding #11 — symmetric 4/4 slice.
    private static func shorten(_ jti: String) -> String {
        guard jti.count > 8 else { return jti }
        let prefix = jti.prefix(4)
        let suffix = jti.suffix(4)
        return "\(prefix)…\(suffix)"
    }
}
