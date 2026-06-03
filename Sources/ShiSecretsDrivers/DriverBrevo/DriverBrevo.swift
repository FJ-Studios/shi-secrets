import Foundation
import ShiSecretsKit

// DriverBrevo — SecretRotationDriver conformance for Brevo's
// transactional-email API key rotation (BR-B-03, BR-B-04).
//
// POSTs to `/v3/senders/api-keys` to create a new key, then issues a
// DELETE against the old key's id (when the caller's VaultEntryRef
// carries the prior id). The write-back carries the new `apiKey` so
// downstream consumers can swap on next fetch without seeing a gap.
//
// Brevo requires `api-key` auth on every request; the header is left
// empty here so tests can assert the header presence without hard-coding
// the actual broker auth string — production wires it at BrokerDaemon
// construction time.

public struct DriverBrevo: SecretRotationDriver {

    public var vendor: String { "brevo" }
    public let humanFallback: HumanRunbook? = nil
    private let transport: any DriverHTTPTransport
    private let bwClient: (any BWClientWriteBack)?
    private let baseURL: String

    public init(
        transport: any DriverHTTPTransport,
        bwClient: (any BWClientWriteBack)? = nil,
        baseURL: String = "https://api.brevo.com"
    ) {
        self.transport = transport
        self.bwClient = bwClient
        self.baseURL = baseURL
    }

    public func rotate(entry: VaultEntryRef, trigger: RotationTrigger) async -> RotationOutcome {
        let request = DriverHTTPRequest(
            method: "POST",
            url: baseURL + "/v3/senders/api-keys",
            headers: ["api-key": "<broker-managed>"],
            body: nil
        )
        do {
            let response = try await transport.send(request)
            guard response.status == 200 || response.status == 201 else {
                return .failed(reason: "brevo http \(response.status)")
            }
            var fields: [String: String] = [:]
            if !response.body.isEmpty,
               let json = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
               let newKey = json["apiKey"] as? String {
                fields["apiKey"] = newKey
            }
            if let bwClient, !fields.isEmpty {
                try await bwClient.update(name: entry.name, fields: fields)
            }
            _ = trigger
            return .rotated
        } catch {
            return .failed(reason: "brevo transport: \(error)")
        }
    }

    public func invalidate(previous: VaultEntryRef) async throws {
        // DELETE of the old api-key is a single round-trip; swallow non-2xx
        // here since invalidation failure must not re-fail the rotation
        // itself (engine already updated last_rotated).
        let request = DriverHTTPRequest(
            method: "DELETE",
            url: baseURL + "/v3/senders/api-keys/\(previous.name)",
            headers: ["api-key": "<broker-managed>"],
            body: nil
        )
        _ = try? await transport.send(request)
    }
}
