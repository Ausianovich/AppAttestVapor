import Dependencies
import Foundation
import Testing
import VaporTesting
@testable import AppAttestVapor

@Test
func configurationRegistersChallengeRoute() async throws {
    let recorder = ChallengeIssueRecorder()
    let challenge = Data(repeating: 2, count: 32).base64EncodedString()

    try await withDependencies {
        $0.appAttestChallengeDriver = .recording(
            recorder: recorder,
            challenge: challenge
        )
    } operation: {
        try await withApp { app in
            app.appAttest.configure(
                AppAttestConfiguration(
                    teamID: "TEAMID",
                    bundleID: "com.example.app",
                    environment: .production,
                    routePrefix: "/security/app-attest"
                )
            )

            let keyID = Data(repeating: 1, count: 32).base64EncodedString()
            try await app.testing().test(
                .POST,
                "/security/app-attest/challenge"
            ) { request in
                try request.content.encode(ChallengeRequest(keyID: keyID))
            } afterResponse: { response in
                #expect(response.status == .ok)
                let content = try response.content.decode(ChallengeResponse.self)
                #expect(content == ChallengeResponse(challenge: challenge))
            }

            #expect(await recorder.keyID == keyID)
            #expect(await recorder.ttl == 60)
        }
    }
}

@Test(arguments: [
    "not-base64",
    Data(repeating: 1, count: 31).base64EncodedString(),
])
func challengeRouteRejectsInvalidKeyID(keyID: String) async throws {
    let recorder = ChallengeIssueRecorder()

    try await withDependencies {
        $0.appAttestChallengeDriver = .recording(
            recorder: recorder,
            challenge: "unused"
        )
    } operation: {
        try await withApp { app in
            app.appAttest.configure(testConfiguration)

            try await app.testing().test(.POST, "/app-attest/challenge") { request in
                try request.content.encode(ChallengeRequest(keyID: keyID))
            } afterResponse: { response in
                #expect(response.status == .badRequest)
                let content = try response.content.decode(ErrorResponse.self)
                #expect(content == ErrorResponse(code: "app_attest_invalid"))
            }

            #expect(await recorder.issueCount == 0)
        }
    }
}

@Test
func challengeRouteMapsDriverFailureToUnavailable() async throws {
    try await withDependencies {
        $0.appAttestChallengeDriver = ValkeyChallengeDriver(
            issue: { _, _, _ in throw DriverFailure() },
            get: { _, _ in nil },
            delete: { _, _ in false }
        )
    } operation: {
        try await withApp { app in
            app.appAttest.configure(testConfiguration)
            let keyID = Data(repeating: 1, count: 32).base64EncodedString()

            try await app.testing().test(.POST, "/app-attest/challenge") { request in
                try request.content.encode(ChallengeRequest(keyID: keyID))
            } afterResponse: { response in
                #expect(response.status == .serviceUnavailable)
                let content = try response.content.decode(ErrorResponse.self)
                #expect(content == ErrorResponse(code: "app_attest_unavailable"))
            }
        }
    }
}

private let testConfiguration = AppAttestConfiguration(
    teamID: "TEAMID",
    bundleID: "com.example.app",
    environment: .production
)

private struct ChallengeRequest: Content {
    let keyID: String
}

private struct ChallengeResponse: Decodable, Equatable {
    let challenge: String
}

private struct ErrorResponse: Decodable, Equatable {
    let code: String
}

private struct DriverFailure: Error {}

private actor ChallengeIssueRecorder {
    private(set) var keyID: String?
    private(set) var ttl: Int?
    private(set) var issueCount = 0

    func record(keyID: String, ttl: Int) {
        self.keyID = keyID
        self.ttl = ttl
        issueCount += 1
    }
}

private extension ValkeyChallengeDriver {
    static func recording(
        recorder: ChallengeIssueRecorder,
        challenge: String
    ) -> Self {
        Self(
            issue: { _, keyID, ttl in
                await recorder.record(keyID: keyID, ttl: ttl)
                return challenge
            },
            get: { _, _ in nil },
            delete: { _, _ in false }
        )
    }
}
