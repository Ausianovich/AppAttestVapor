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

        application.grouped(prefix).post("attestation") { request async throws -> Response in
            @Dependency(\.appAttestChallengeDriver) var challengeDriver
            @Dependency(\.appAttestationVerification) var attestationVerification
            @Dependency(\.appAttestCredential) var credential

            let payload: AppAttestAttestationRequest
            do {
                payload = try request.content.decode(AppAttestAttestationRequest.self)
            } catch {
                return try AppAttestError.invalidProof.response()
            }

            guard
                let keyID = Data(base64Encoded: payload.keyID),
                keyID.count == 32,
                let challenge = Data(base64Encoded: payload.challenge),
                challenge.count == 32,
                let attestationObject = Data(base64Encoded: payload.attestationObject),
                !attestationObject.isEmpty
            else {
                return try AppAttestError.invalidProof.response()
            }

            let storedChallenge: String?
            do {
                storedChallenge = try await challengeDriver.get(request, payload.keyID)
            } catch {
                return try AppAttestError.unavailable.response()
            }
            guard storedChallenge == payload.challenge else {
                return try AppAttestError.challengeMissing.response()
            }

            let verification: AppAttestationVerification
            do {
                verification = try await attestationVerification.verify(
                    configuration,
                    attestationObject,
                    keyID,
                    challenge
                )
            } catch {
                return try AppAttestError.invalidProof.response()
            }

            let deleted: Bool
            do {
                deleted = try await challengeDriver.delete(request, payload.keyID)
            } catch {
                return try AppAttestError.unavailable.response()
            }
            guard deleted else {
                return try AppAttestError.invalidProof.response()
            }

            do {
                try await credential.saveCredential(
                    payload.keyID,
                    verification.publicKey,
                    verification.initialCounter
                )
            } catch {
                return try AppAttestError.unavailable.response()
            }

            return Response(status: .noContent)
        }
    }
}

struct AppAttestationVerificationClient: Sendable {
    var verify: @Sendable (
        AppAttestConfiguration,
        Data,
        Data,
        Data
    ) async throws -> AppAttestationVerification
}

extension AppAttestationVerificationClient: DependencyKey {
    static let liveValue = Self { configuration, attestationObject, keyID, challenge in
        try await AppAttestationVerifier(
            configuration: configuration,
            certificateVerifier: AppAttestCertificateVerifier()
        ).verify(
            attestationObject: attestationObject,
            keyID: keyID,
            challenge: challenge
        )
    }
}

extension DependencyValues {
    var appAttestationVerification: AppAttestationVerificationClient {
        get { self[AppAttestationVerificationClient.self] }
        set { self[AppAttestationVerificationClient.self] = newValue }
    }
}
