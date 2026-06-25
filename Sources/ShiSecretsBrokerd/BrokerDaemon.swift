import Crypto
import Foundation
import ShiSecretsDrivers
import ShiSecretsKit

// BrokerDaemon — the actor that wires Bootstrap → UnixSocketServer →
// MCPBridge → TokenMinter → AuditWriter → BWClient into a single
// lifecycle surface.
//
// `start()`:
//   1. Runs Bootstrap.unseal (BR-I-01, -02, -04)
//   2. Socket-preflight via UnixSocketServer.start (BR-D-02)
//   3. Registers exactly 6 ShikkiKernel jobs (T53 — BR-C-0X):
//      - secrets.rotation.hot       interval=300s   qos=hot
//      - secrets.rotation.warm      interval=1800s  qos=warm
//      - secrets.rotation.cool      interval=7200s  qos=cool
//      - secrets.rotation.external  interval=21600s qos=external
//      - secrets.anomaly.listener   onEvent         qos=hot
//      - secrets.conversation.sweep interval=900s   qos=warm
//
// `handleRequest(_:)`:
//   - scope-validates the caller's pattern
//   - mints via TokenMinter (op-gated vs signed manifest)
//   - writes audit row + returns the BrokerResponse envelope
//
// `handleHUP()`:
//   - reloads the MCP manifest; on bad sig the ManifestStore keeps the
//     previously pinned copy and appends a seams row (BR-H-02d).
//
// BWClient.invalidateSession is propagated so any new issuance
// immediately refuses (BR-F-07); outstanding tokens continue to work
// against `TokenRegistry.isRevoked` until dies_at.

public struct BrokerRequest: Sendable, Equatable {
    public let sub: String
    public let scope: String
    public let op: ShikkiSBT.Op
    public let ttl: Int
    public let toolName: String?
    public init(sub: String, scope: String, op: ShikkiSBT.Op, ttl: Int, toolName: String?) {
        self.sub = sub
        self.scope = scope
        self.op = op
        self.ttl = ttl
        self.toolName = toolName
    }
}

public enum BrokerDaemonError: Swift.Error, Sendable, Equatable {
    case socketPreflightFailed
    case notStarted
    /// Review finding U13 — the broker refuses to enter the runtime loop
    /// when Bootstrap.unseal throws. BR-I-04 materially-wired.
    case bootstrapUnsealFailed
    /// Review finding U7 — ManifestStore.loadInitial must succeed before
    /// the daemon binds its socket. `.manifestLoadFailed` surfaces the
    /// refusal so ops runbooks can machine-detect the cause.
    case manifestLoadFailed
    /// Item #9 (BR-F-08 / BR-F-09 / BR-F-10 / BR-F-11) — an admin
    /// action envelope failed verification (bad signature, bad domain,
    /// stale timestamp, or a replayed nonce). Single error case — the
    /// specific reason is distinguished by the audit row written
    /// alongside: `.adminBadSignature`, `.adminStale`, or
    /// `.adminReplay`.
    case adminSignatureInvalid
    /// Item #9 — the admin envelope's domain verified but the signed
    /// `action` value does not match the command the caller invoked.
    /// Defense-in-depth; in practice the enum constraint on
    /// `AdminAction.ActionKind` makes this unreachable today, but a
    /// future action family + a v1.x CLI dispatcher collision must
    /// surface here.
    case adminActionMismatch
}

/// Pair of bytes + signature injected at daemon construction so
/// `ManifestStore.loadInitial` can run as part of `start()` without
/// reaching into Bundle.module from the actor (tests supply deterministic
/// bytes; production wiring ships the bundled manifest).
public struct ManifestSource: Sendable {
    public let bytes: Data
    public let signature: Data
    public init(bytes: Data, signature: Data) {
        self.bytes = bytes
        self.signature = signature
    }
}

/// The daemon — a reference type so BrokerDaemon can be passed into
/// kernel jobs via its shared reference without copy-semantic surprises.
public actor BrokerDaemon {

    // MARK: - Wired collaborators (DI'd at construction)
    public let kernel: ShikkiKernel
    public let audit: AuditWriter
    public let seams: SeamsWriter
    public let registry: TokenRegistry
    public let drivers: DriverRegistry
    public let engine: RotationEngine
    public let manifestStore: ManifestStore
    public let scopeValidator: ScopeValidator
    /// Per-system blast-radius isolation (W6.5c F-PSA-3, CRIT-1 fix
    /// 2026-06-25). Wires `ScopePolicy.canRead(path:)` into the request
    /// path so a brokerd install reads ONLY `shi/system/<self>/**` +
    /// `shi/shared/**`. `nil` disables the secondary check (Wave-4 tests
    /// + Linux nodes pre-W6.5c). Production wiring required.
    public let systemScopePolicy: ScopePolicy?
    public let bridge: MCPBridge
    public let socket: UnixSocketServer
    public let bwClient: any BWClient
    public let minter: TokenMinter
    /// Review finding U13 — BrokerDaemon.start calls bootstrap.unseal as
    /// its VERY first action. A failing bootstrap refuses the start; no
    /// socket is bound, no kernel jobs are registered, no audit/mint path
    /// ever runs. BR-I-04 materially wired.
    public let bootstrap: any BootstrapProvider
    /// Review finding U7 — pinned manifest source loaded right after
    /// bootstrap.unseal. `nil` disables the preload (in-process tests that
    /// already drive manifest via handleHUP).
    public let manifestSource: ManifestSource?
    /// Item #9 — verifier for passkey-signed admin-action envelopes
    /// (currently: `revokeAllBots`). Optional so the Wave 4 test
    /// daemons that never call `revokeAllBots(signedBy:)` can stay
    /// green without wiring an extra key; production wiring is
    /// required by `ShiSecretsModule`.
    public let adminVerifier: AdminActionVerifier?

    // Cached kernel collaborators used by T53 registration.
    private let anomalyStaging: AnomalyStaging
    private let activeSessions: ActiveSessions

    private var started = false

    /// Dev-mode gate (spec shi-secrets-setup-install-fix-and-dev-mode-2026-06-19
    /// RC-3). When true, `start()` skips bootstrap.unseal + kernel job
    /// registration so the daemon binds the socket against the
    /// pre-wired InMemoryBWClient without prod-side preflight.
    public let devMode: Bool

    public init(
        kernel: ShikkiKernel,
        audit: AuditWriter,
        seams: SeamsWriter,
        registry: TokenRegistry,
        drivers: DriverRegistry,
        engine: RotationEngine,
        manifestStore: ManifestStore,
        scopeValidator: ScopeValidator,
        systemScopePolicy: ScopePolicy? = nil,
        bridge: MCPBridge,
        socket: UnixSocketServer,
        bwClient: any BWClient,
        minter: TokenMinter,
        bootstrap: any BootstrapProvider,
        manifestSource: ManifestSource? = nil,
        adminVerifier: AdminActionVerifier? = nil,
        anomalyStaging: AnomalyStaging = AnomalyStaging(),
        activeSessions: ActiveSessions = ActiveSessions(),
        devMode: Bool = false
    ) {
        self.kernel = kernel
        self.audit = audit
        self.seams = seams
        self.registry = registry
        self.drivers = drivers
        self.engine = engine
        self.manifestStore = manifestStore
        self.scopeValidator = scopeValidator
        self.systemScopePolicy = systemScopePolicy
        self.bridge = bridge
        self.socket = socket
        self.bwClient = bwClient
        self.minter = minter
        self.bootstrap = bootstrap
        self.manifestSource = manifestSource
        self.adminVerifier = adminVerifier
        self.anomalyStaging = anomalyStaging
        self.activeSessions = activeSessions
        self.devMode = devMode
    }

    // MARK: - start

    /// Wires the daemon up — unseal → manifest preload → socket preflight
    /// → 6 kernel jobs. Does NOT enter the accept() loop (that's Wave 5
    /// runtime work). Throws on any preflight failure so the executable's
    /// main can exit non-zero.
    ///
    /// Review finding U13: bootstrap.unseal runs FIRST. On throw, no socket
    /// is bound, no kernel jobs are registered, and `started` stays false.
    /// Review finding U7: ManifestStore.loadInitial runs right after unseal
    /// when a `manifestSource` was injected — a broker MUST NOT enter the
    /// accept path with an unpinned manifest (BR-H-02/e).
    public func start() async throws {
        // 1. Bootstrap (BR-I-04, W1 update). Load Vaultwarden credentials from
        // Keychain and connect. On throw, the daemon refuses to run — no socket
        // is bound, no kernel jobs registered.
        //
        // Dev-mode SKIP — bwClient is already an activated InMemoryBWClient
        // seeded with dev-* creds by DevModeBootstrap. No Vaultwarden
        // contact, no Keychain unseal, no kernel job preflight.
        if !devMode {
            do {
                let (vaultClient, _) = try await bootstrap.unseal()
                if let prodClient = bwClient as? ProductionBWClient {
                    await prodClient.wire(client: vaultClient)
                }
            } catch {
                throw BrokerDaemonError.bootstrapUnsealFailed
            }
        }

        // 2. Manifest preload (BR-H-02/e). When a source was injected,
        // load + verify before the socket ever binds. Failure refuses
        // start — a broker with an unpinned manifest cannot serve MCP
        // requests.
        if let source = manifestSource {
            do {
                try await manifestStore.loadInitial(
                    bytes: source.bytes,
                    signature: source.signature
                )
            } catch {
                throw BrokerDaemonError.manifestLoadFailed
            }
        }

        // 3. Socket preflight. If the socket is already bound (e.g. a prior
        // test run left it live), verify the invariant; otherwise bind now.
        do {
            try await socket.verifyOnDiskInvariant()
        } catch {
            try await socket.start()
        }
        // 4. Register exactly 6 kernel jobs (T53). Dev-mode SKIP — no
        // ShikkiKernel job loop running in standalone dev.
        if !devMode {
            try await registerKernelJobs()
        }
        started = true
    }

    public func isStarted() -> Bool { started }

    // MARK: - T53 kernel-job registration

    /// Registers all six kernel jobs in a single transaction. Throws on
    /// any duplicate id.
    public func registerKernelJobs() async throws {
        let tiers: [(QoSTrackTier, QoSTrack, TimeInterval)] = [
            (.hot,      .hot,      RotationIntervals.hotSeconds),
            (.warm,     .warm,     RotationIntervals.warmSeconds),
            (.cool,     .cool,     RotationIntervals.coolSeconds),
            (.external, .external, RotationIntervals.externalSeconds),
        ]
        for (tier, qos, interval) in tiers {
            let job = RotationTickJob(track: tier, engine: engine)
            try await kernel.register(
                id: "secrets.rotation.\(tier.rawValue)",
                job: job,
                schedule: .interval(interval),
                qos: qos
            )
        }
        let anomalyJob = AnomalySignalListenerJob(engine: engine, staging: anomalyStaging)
        try await kernel.register(
            id: "secrets.anomaly.listener",
            job: anomalyJob,
            schedule: .onEvent("shikki.secrets.anomaly"),
            qos: .hot
        )
        let sweepJob = ConversationSweepJob(engine: engine, activeSessions: activeSessions)
        try await kernel.register(
            id: "secrets.conversation.sweep",
            job: sweepJob,
            schedule: .interval(ConversationSweepJob.maxSweepIntervalSeconds),
            qos: .warm
        )
    }

    // MARK: - handleRequest

    /// Orchestrates a single request: scope → minter → audit → response.
    ///
    /// Caller-type dispatch (W4.2 — BR-H-01):
    ///   • local-unix + !llm_touched → `.boundPlaintext(jti, plaintext)`
    ///     The jti comes from the freshly-minted token; the plaintext is
    ///     fetched from the vault under the secret name derived from scope.
    ///     The same jti is in the audit allow row written before the vault
    ///     fetch (T02 invariant).
    ///   • MCP / llm_touched → `.ephemeralToken(SBT)` (existing behavior)
    ///
    /// Fail-closed audit (review finding #1 — hardens BR-G-01): if the
    /// audit append throws, the request is refused with
    /// `.auditWriteFailed` so the "one audit row BEFORE plaintext is
    /// returned" invariant cannot be bypassed by a silently-swallowed
    /// writer error.
    public func handleRequest(
        _ request: BrokerRequest,
        wrapped: WrappedRequest,
        now: Date = Date()
    ) async -> BrokerResponse {
        // Scope-validate the caller's pattern (BR-H-04, -H-06, finding #8).
        do {
            try scopeValidator.validate(pattern: request.scope)
        } catch ScopeValidator.ValidationError.scopeTooLong {
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopeTooLong
            ) { return resp }
            return .deny(.scopeTooLong)
        } catch ScopeValidator.ValidationError.scopePatternDenied {
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopePatternDenied
            ) { return resp }
            return .deny(.scopePatternDenied)
        } catch ScopeValidator.ValidationError.regexSyntaxForbidden {
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopePatternDenied
            ) { return resp }
            return .deny(.scopePatternDenied)
        } catch {
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopeDenied
            ) { return resp }
            return .deny(.scopeDenied)
        }

        // W6.5c CRIT-1 fix: secondary blast-radius enforcement via
        // per-system ScopePolicy. The toml allowlist (ScopeValidator above)
        // can be operator-misconfigured; this check is the architectural
        // guarantee that a compromised brokerd cannot read another system's
        // collection even if the allowlist accidentally permits it.
        if let policy = systemScopePolicy, !policy.canRead(path: request.scope) {
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .scopePatternDenied
            ) { return resp }
            return .deny(.scopePatternDenied)
        }

        // BWClient session must still be valid — BR-F-07. Review finding #3:
        // the bw-session-invalid path was previously overloaded onto
        // `.incidentBypass`; surface it as its own dedicated reason so
        // audit/TUI can distinguish operator-initiated bw revoke from a
        // generic incident bypass.
        // Review finding U5 — capture the bw-session epoch now and
        // re-check after mint so a concurrent invalidateSession cannot
        // slip through while we're signing.
        let preMintSessionEpoch = await bwClient.sessionEpoch
        guard await bwClient.isSessionValid else {
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .brokerSessionInvalid
            ) { return resp }
            return .deny(.brokerSessionInvalid)
        }

        // Mint — op-gate vs signed manifest happens inside TokenMinter.
        // Review finding U1 + U2: split into prepare (sign only) →
        // audit.append (allow row) → persist (registry.insert). Signing
        // is the irreversible step; if it throws no registry row exists.
        // If audit fails, the registry is never touched.
        let prepared: TokenMinter.Prepared
        do {
            prepared = try await minter.prepare(
                request: .init(
                    sub: request.sub,
                    scope: request.scope,
                    op: request.op,
                    ttl: request.ttl,
                    toolName: request.toolName
                ),
                transport: wrapped.transport,
                now: now
            )
        } catch TokenMinter.MintError.opMismatch {
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .opMismatch
            ) { return resp }
            return .deny(.opMismatch)
        } catch {
            // Review finding U3 — catch-all uses `.internalError`, not
            // `.incidentBypass` (reserved for `--force` revoke path).
            if let resp = await writeDenyOrFailClosed(
                jti: "unminted", request: request, wrapped: wrapped,
                now: now, reason: .internalError
            ) { return resp }
            return .deny(.internalError)
        }

        // Review finding U1 — allow audit row BEFORE registry.insert.
        // If audit fails we never insert; no phantom token exists.
        let row = AuditRow(
            ts: now,
            tokenJti: prepared.token.claims.jti,
            callerUid: wrapped.peerUid.map { Int32(bitPattern: $0) },
            callerTransport: wrapped.transport,
            secretName: deriveSecretName(from: request.scope),
            op: request.op,
            allow: .allow,
            reason: nil,
            llmTouched: wrapped.llmTouched
        )
        do {
            try await audit.append(row)
        } catch {
            Self.logAuditFailClosed(error: error, context: "allow row, jti=\(prepared.token.claims.jti)")
            return .deny(.auditWriteFailed)
        }

        // Persist — now that the audit row is in, commit the registry
        // entry. If this throws (extremely rare in-memory, possible in
        // v1.1 DB swap), run the compensating revoke so the over-audited
        // allow row is reconciled to a revoked jti.
        do {
            try await minter.persist(prepared: prepared)
        } catch {
            await compensateRevoke(
                jti: prepared.token.claims.jti, scope: request.scope, now: now
            )
            if let resp = await writeDenyOrFailClosed(
                jti: prepared.token.claims.jti, request: request, wrapped: wrapped,
                now: now, reason: .internalError
            ) { return resp }
            return .deny(.internalError)
        }

        // Review finding U5 — re-check the bw-session epoch. If the
        // session was invalidated concurrently with mint, revoke the
        // freshly-issued jti and deny.
        let postMintSessionEpoch = await bwClient.sessionEpoch
        let postMintSessionValid = await bwClient.isSessionValid
        if postMintSessionEpoch != preMintSessionEpoch || !postMintSessionValid {
            await compensateRevoke(
                jti: prepared.token.claims.jti, scope: request.scope, now: now
            )
            if let resp = await writeDenyOrFailClosed(
                jti: prepared.token.claims.jti, request: request, wrapped: wrapped,
                now: now, reason: .brokerSessionInvalid
            ) { return resp }
            return .deny(.brokerSessionInvalid)
        }

        // W4.2 — caller-type dispatch (BR-H-01).
        // Local unix callers that are NOT llm-touched get the plaintext back
        // (bound to the jti from the minted token). MCP / llm-touched callers
        // always get the safer ephemeralToken path.
        //
        // Note: never log plaintext (ShikkiSecretsLogger / BR-G-01).
        let jti = prepared.token.claims.jti
        if wrapped.transport == .unix && !wrapped.llmTouched {
            let secretName = deriveSecretName(from: request.scope)
            do {
                let fields = try await bwClient.get(name: secretName)
                if let plaintext = fields["value"], !plaintext.isEmpty {
                    return .boundPlaintext(jti: jti, plaintext: plaintext)
                }
                // Vault entry missing or empty field — fall through to token.
            } catch {
                // Vault unavailable — fall through to token path so callers
                // can still obtain a token for async re-fetch via MCP.
            }
        }

        return .ephemeralToken(ShikkiSBT(claims: prepared.token.claims))
    }

    /// 3rd-pass validator I2 — compensating revoke with seam observability.
    ///
    /// Two outcomes:
    ///   * The jti was registered before persist failed → normal revoke.
    ///     No seam (success-case, not worth logging).
    ///   * The jti was NOT registered (persist threw before insert) →
    ///     registry throws `.invalidJti`. Emit `persistCompensationNoOp`
    ///     so ops can correlate the over-audited allow row with a
    ///     deliberately-skipped revoke.
    ///   * The revoke threw something else (a real bug) → emit
    ///     `persistCompensationFailed` with the error description.
    ///
    /// Previously this path was a silent `try?` inside
    /// `TokenMinter.compensateRevoke`; the 3rd-pass validator flagged
    /// that any unexpected error would be invisible to ops.
    private func compensateRevoke(jti: String, scope: String, now: Date) async {
        do {
            try await registry.revoke(jti: jti, at: now)
        } catch ShikkiSBT.Error.invalidJti {
            // Persist failed before insert — no registry row to revoke.
            // This is the EXPECTED path for a persist-before-insert
            // throw; emit the seam so ops can see "compensation happened
            // but there was nothing to compensate".
            try? await seams.append(
                signal: .persistCompensationNoOp(scope: scope),
                secret: deriveSecretName(from: scope),
                outcome: .bypassed,
                ts: now,
                notes: "compensateRevoke called but jti \(jti) never registered"
            )
        } catch {
            // Unexpected — audit so it does not disappear.
            try? await seams.append(
                signal: .persistCompensationFailed(
                    scope: scope,
                    error: String(describing: error)
                ),
                secret: deriveSecretName(from: scope),
                outcome: .failed,
                ts: now,
                notes: "compensateRevoke failed unexpectedly for jti \(jti)"
            )
        }
    }

    /// Writes a deny audit row. On append failure returns a
    /// `.deny(.auditWriteFailed)` response so callers can early-return
    /// without double-appending; on success returns nil and callers
    /// proceed with their intended deny reason.
    private func writeDenyOrFailClosed(
        jti: String,
        request: BrokerRequest,
        wrapped: WrappedRequest,
        now: Date,
        reason: AuditRow.DenyReason
    ) async -> BrokerResponse? {
        let row = AuditRow(
            ts: now,
            tokenJti: jti,
            callerUid: wrapped.peerUid.map { Int32(bitPattern: $0) },
            callerTransport: wrapped.transport,
            secretName: deriveSecretName(from: request.scope),
            op: request.op,
            allow: .deny,
            reason: reason,
            llmTouched: wrapped.llmTouched
        )
        do {
            try await audit.append(row)
            return nil
        } catch {
            Self.logAuditFailClosed(error: error, context: "deny row (\(reason.rawValue))")
            return .deny(.auditWriteFailed)
        }
    }

    /// Fail-closed logging hook. Until CoreKit's AppLog is wired into the
    /// broker target, we write to stderr. Finding #1 spec calls out
    /// `AppLog.fatal(...)`; the behavioral contract (surface to the host
    /// supervisor) is preserved — CoreKit dep wiring is deferred to v1.1.
    private static func logAuditFailClosed(error: Swift.Error, context: String) {
        let message = "shikki-brokerd: audit write failed, failing closed — \(context): \(error)\n"
        if let data = message.data(using: .utf8) {
            try? FileHandle.standardError.write(contentsOf: data)
        }
    }

    private nonisolated func deriveSecretName(from scope: String) -> String {
        let trimmed = String(scope.prefix(AuditWriter.maxSecretNameLength))
        return trimmed.isEmpty ? "unknown" : trimmed
    }

    // MARK: - handleHUP

    /// Delegates to ManifestStore.reload. Fail-safe on bad sig — the store
    /// already appends the seams row; the daemon simply passes through.
    public func handleHUP(bytes: Data, signature: Data) async {
        do {
            try await manifestStore.reload(bytes: bytes, signature: signature)
        } catch {
            // ManifestStore.reload is fail-safe (no rethrow on bad sig);
            // any error here is unexpected and logged via AppLog in Wave 5.
        }
    }

    // MARK: - BWClient session revoke propagation

    public func revokeBWSession() async {
        await bwClient.invalidateSession()
    }

    // MARK: - Admin-gated revokeAllBots (item #9)

    /// Passkey-signed `revokeAllBots` — BR-F-08 / BR-F-09 / BR-F-10 /
    /// BR-F-11. Replaces the legacy `--force` filesystem-permission-
    /// only gate.
    ///
    /// Flow:
    ///   1. `adminVerifier.verify(signed)` — rejects bad signature,
    ///      bad domain, stale timestamp, or replayed nonce. Each
    ///      refusal writes a distinct deny audit row so ops can
    ///      machine-detect WHICH guard tripped.
    ///   2. Sanity-check the returned action kind matches
    ///      `.revokeAllBots` (defensive; the enum already constrains
    ///      this at the type level today).
    ///   3. Append a seams `.incidentBypass` row carrying the
    ///      actor + nonce — NOT the signature bytes.
    ///   4. Delegate to `registry.revokeAllBots()`.
    public func revokeAllBots(
        signedBy signed: SignedAdminAction,
        now: Date = Date()
    ) async throws -> Int {
        guard let verifier = adminVerifier else {
            // No verifier wired → broker refuses. Write the audit
            // row with `.adminSignatureRequired` so ops see the
            // misconfiguration surface instead of a silent 500.
            await writeAdminDeny(
                reason: .adminSignatureRequired,
                actor: signed.envelope.actor,
                now: now
            )
            throw BrokerDaemonError.adminSignatureInvalid
        }

        let action: AdminAction.ActionKind
        do {
            action = try await verifier.verify(signed)
        } catch AdminActionVerifier.VerifyError.badSignature {
            await writeAdminDeny(
                reason: .adminBadSignature,
                actor: signed.envelope.actor,
                now: now
            )
            throw BrokerDaemonError.adminSignatureInvalid
        } catch AdminActionVerifier.VerifyError.badDomain {
            // Domain separation — BR-F-09. A manifest-class signature
            // cannot be replayed as an admin action.
            await writeAdminDeny(
                reason: .adminBadSignature,
                actor: signed.envelope.actor,
                now: now
            )
            throw BrokerDaemonError.adminSignatureInvalid
        } catch AdminActionVerifier.VerifyError.stale {
            await writeAdminDeny(
                reason: .adminStale,
                actor: signed.envelope.actor,
                now: now
            )
            throw BrokerDaemonError.adminSignatureInvalid
        } catch AdminActionVerifier.VerifyError.replay {
            await writeAdminDeny(
                reason: .adminReplay,
                actor: signed.envelope.actor,
                now: now
            )
            throw BrokerDaemonError.adminSignatureInvalid
        } catch {
            await writeAdminDeny(
                reason: .adminBadSignature,
                actor: signed.envelope.actor,
                now: now
            )
            throw BrokerDaemonError.adminSignatureInvalid
        }

        guard action == .revokeAllBots else {
            // The domain was right but the signed action is something
            // else — reject without running the revoke. Unreachable
            // for v1 (enum has one case) but guards future expansion.
            throw BrokerDaemonError.adminActionMismatch
        }

        // Seam row — capture actor + nonce for post-incident review.
        // Signature bytes are NEVER logged (BR-G-02 — audit/seam rows
        // carry no token bytes; same hygiene applied here).
        try? await seams.append(
            signal: .adminActionExecuted(
                action: action.rawValue,
                actor: signed.envelope.actor,
                nonce: signed.envelope.nonce
            ),
            secret: "*all-bots*",
            outcome: .bypassed,
            ts: now,
            notes: "signed by admin, actor=\(signed.envelope.actor), nonce=\(signed.envelope.nonce)"
        )

        return try await registry.revokeAllBots(at: now)
    }

    /// Write a deny audit row for a refused admin action. `*all-bots*`
    /// is used as the pseudo `secret_name` so ops filtering by name
    /// can find every admin refusal in one query.
    private func writeAdminDeny(
        reason: AuditRow.DenyReason,
        actor: String,
        now: Date
    ) async {
        let row = AuditRow(
            ts: now,
            tokenJti: "admin-\(reason.rawValue)",
            callerUid: nil,
            callerTransport: .unix,
            secretName: "*all-bots*",
            op: .read,
            allow: .deny,
            reason: reason,
            llmTouched: false
        )
        do {
            try await audit.append(row)
        } catch {
            Self.logAuditFailClosed(
                error: error,
                context: "admin deny row (\(reason.rawValue)), actor=\(actor)"
            )
        }
    }
}
