import Dependencies
import DependenciesTestSupport
import Foundation
import Testing
import VaporTesting
@testable import AppAttestVapor

@Test
func challengeDriverCanUseInMemoryStorage() async throws {
    let storage = InMemoryChallenges()
    let driver = ValkeyChallengeDriver(
        issue: { _, keyID, ttl in
            await storage.issue(keyID: keyID, ttl: ttl)
        },
        get: { _, keyID in
            await storage.get(keyID: keyID)
        },
        delete: { _, keyID in
            await storage.deleteCount(keyID: keyID) == 1
        }
    )

    try await withApp { app in
        let request = Request(
            application: app,
            method: .GET,
            url: "/",
            peerCertificateChain: nil,
            on: app.eventLoopGroup.next()
        )

        try await withDependencies {
            $0.appAttestChallengeDriver = driver
        } operation: {
            @Dependency(\.appAttestChallengeDriver) var challengeDriver

            let challenge = try await challengeDriver.issue(request, "key-id", 60)

            #expect(try await challengeDriver.get(request, "key-id") == challenge)
            #expect(await storage.ttl(keyID: "key-id") == 60)
            #expect(try await challengeDriver.delete(request, "key-id"))
            #expect(try await !challengeDriver.delete(request, "key-id"))
        }
    }
}

@Test
func generatedChallengeContains32Bytes() {
    let challenge = ValkeyChallengeDriver.makeChallenge()

    #expect(Data(base64Encoded: challenge)?.count == 32)
}

@Test
func challengeUsesNamespacedKey() {
    #expect(
        ValkeyChallengeDriver.storageKey(for: "key-id")
            == "app-attest:challenge:key-id"
    )
}

@Test(arguments: [(0, false), (1, true), (2, false)])
func deleteSucceedsOnlyForOneDeletedKey(count: Int, expected: Bool) {
    #expect(ValkeyChallengeDriver.deleteSucceeded(count: count) == expected)
}

private actor InMemoryChallenges {
    struct Entry: Sendable {
        let challenge: String
        let ttl: Int
    }

    private var entries: [String: Entry] = [:]

    func issue(keyID: String, ttl: Int) -> String {
        let challenge = Data(repeating: 7, count: 32).base64EncodedString()
        entries[keyID] = Entry(challenge: challenge, ttl: ttl)
        return challenge
    }

    func get(keyID: String) -> String? {
        entries[keyID]?.challenge
    }

    func ttl(keyID: String) -> Int? {
        entries[keyID]?.ttl
    }

    func deleteCount(keyID: String) -> Int {
        entries.removeValue(forKey: keyID) == nil ? 0 : 1
    }
}
