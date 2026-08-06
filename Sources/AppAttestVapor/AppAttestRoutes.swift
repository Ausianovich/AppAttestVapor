import AppAttestCore
import Dependencies
import Foundation
import Vapor

enum AppAttestRoutes {
    static func register(
        on application: Application,
        configuration: AppAttestConfiguration
    ) {
        let prefix = configuration.routePrefix
            .split(separator: "/")
            .map { PathComponent.constant(String($0)) }

        application.grouped(prefix).post("challenge") { request async throws -> Response in
            @Dependency(\.appAttestChallengeDriver) var challengeDriver

            let payload: AppAttestChallengeRequest
            do {
                payload = try request.content.decode(AppAttestChallengeRequest.self)
            } catch {
                return try AppAttestError.invalid.response()
            }

            guard
                let keyID = Data(base64Encoded: payload.keyID),
                keyID.count == 32
            else {
                return try AppAttestError.invalid.response()
            }

            let challenge: String
            do {
                challenge = try await challengeDriver.issue(
                    request,
                    payload.keyID,
                    configuration.challengeTTL
                )
            } catch {
                return try AppAttestError.unavailable.response()
            }

            let response = Response(status: .ok)
            try response.content.encode(
                AppAttestChallengeResponse(challenge: challenge),
                as: .json
            )
            return response
        }
    }
}
