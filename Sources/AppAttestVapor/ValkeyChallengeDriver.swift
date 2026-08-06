import Dependencies
import Foundation
import Vapor
import VaporValkey

struct ValkeyChallengeDriver: Sendable {
    var issue: @Sendable (Request, String, Int) async throws -> String
    var get: @Sendable (Request, String) async throws -> String?
    var delete: @Sendable (Request, String) async throws -> Bool

    static func makeChallenge() -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<32).map { _ in
            UInt8.random(in: .min ... .max, using: &generator)
        }
        return Data(bytes).base64EncodedString()
    }

    static func storageKey(for keyID: String) -> String {
        "app-attest:challenge:\(keyID)"
    }

    static func deleteSucceeded(count: Int) -> Bool {
        count == 1
    }
}

extension ValkeyChallengeDriver: DependencyKey {
    static let liveValue = Self(
        issue: { request, keyID, ttl in
            let challenge = makeChallenge()
            try await request.valkey.setex(
                .init(storageKey(for: keyID)),
                seconds: ttl,
                value: challenge
            )
            return challenge
        },
        get: { request, keyID in
            try await request.valkey
                .get(.init(storageKey(for: keyID)))
                .map(String.init)
        },
        delete: { request, keyID in
            let count = try await request.valkey.del(
                keys: [.init(storageKey(for: keyID))]
            )
            return deleteSucceeded(count: count)
        }
    )
}

extension DependencyValues {
    var appAttestChallengeDriver: ValkeyChallengeDriver {
        get { self[ValkeyChallengeDriver.self] }
        set { self[ValkeyChallengeDriver.self] = newValue }
    }
}
