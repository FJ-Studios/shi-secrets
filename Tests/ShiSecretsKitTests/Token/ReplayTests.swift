import Foundation
import Testing
@testable import ShiSecretsKit

// Replay tests (Task 16 — BR-A-11).
//
// Each jti is single-use for op=rotate. First presentation is accepted
// (markRotateUsed inserts into the rotate-used set). Second presentation
// throws `replay(jti:)` and isReplay returns true thereafter.

@Suite("Replay")
struct ReplayTests {

    private static let jti = "01JABCDEFGHJKMNPQRSTVWXYZ0"

    @Test("rotate op — first presentation accepted")
    func token_rotateOp_firstPresentation_accepted() async throws {
        let reg = TokenRegistry()
        try await reg.markRotateUsed(jti: Self.jti)
        #expect(await reg.isReplay(jti: Self.jti) == true)
    }

    @Test("rotate op — second presentation rejected as replay")
    func token_rotateOp_secondPresentation_rejectedAsReplay() async throws {
        let reg = TokenRegistry()
        try await reg.markRotateUsed(jti: Self.jti)
        await #expect(throws: ShikkiSBT.Error.replay(jti: Self.jti)) {
            try await reg.markRotateUsed(jti: Self.jti)
        }
    }

    @Test("isReplay query — false before markRotateUsed, true after")
    func token_rotateOp_isReplay() async throws {
        let reg = TokenRegistry()
        #expect(await reg.isReplay(jti: Self.jti) == false)
        try await reg.markRotateUsed(jti: Self.jti)
        #expect(await reg.isReplay(jti: Self.jti) == true)
    }
}
