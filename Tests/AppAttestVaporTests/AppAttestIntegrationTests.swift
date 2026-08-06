import Dependencies
import Foundation
import Testing
import Vapor
import VaporTesting
@testable import AppAttestVapor

@Test
func serviceRoutesRemainOutsideProtectedRouteGroup() async throws {
    let recorder = IntegrationRecorder()
    let challenge = Data(repeating: 2, count: 32).base64EncodedString()

    try await withDependencies {
        $0.appAttestChallengeDriver = ValkeyChallengeDriver(
            issue: { _, _, _ in
                await recorder.recordChallengeIssue()
                return challenge
            },
            get: { _, _ in nil },
            delete: { _, _ in false }
        )
    } operation: {
        try await withApp { app in
            app.appAttest.configure(
                AppAttestConfiguration(
                    teamID: "TEAMID",
                    bundleID: "com.example.app",
                    environment: .production
                )
            )
            app.grouped(AppAttestMiddleware()).post("protected") { _ in
                await recorder.recordProtectedHandler()
                return Response(status: .noContent)
            }

            let keyID = Data(repeating: 1, count: 32).base64EncodedString()
            let serviceResponse = try await app.testing().sendRequest(
                .POST,
                "/app-attest/challenge"
            ) { request in
                try request.content.encode(ChallengeRequest(keyID: keyID))
            }
            let protectedResponse = try await app.testing().sendRequest(
                .POST,
                "/protected"
            )

            #expect(serviceResponse.status == .ok)
            #expect(protectedResponse.status == .forbidden)
            #expect(await recorder.challengeIssueCount == 1)
            #expect(await recorder.protectedHandlerCount == 0)
        }
    }
}

private actor IntegrationRecorder {
    private(set) var challengeIssueCount = 0
    private(set) var protectedHandlerCount = 0

    func recordChallengeIssue() {
        challengeIssueCount += 1
    }

    func recordProtectedHandler() {
        protectedHandlerCount += 1
    }
}

private struct ChallengeRequest: Content {
    let keyID: String
}
