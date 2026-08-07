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
                request.logger.appAttestError(stage: "challenge-request", error: error)
                return try AppAttestError.invalid.response()
            }

            guard
                let keyID = Data(base64Encoded: payload.keyID),
                keyID.count == 32
            else {
                request.logger.appAttestError(stage: "challenge-key-id")
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
                request.logger.appAttestError(stage: "challenge-issue", error: error)
                return try AppAttestError.unavailable.response()
            }

            let response = Response(status: .ok)
            try response.content.encode(
                AppAttestChallengeResponse(challenge: challenge),
                as: .json
            )
            request.logger.appAttestDebug(stage: "challenge-issue")
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
                request.logger.appAttestError(stage: "attestation-request", error: error)
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
                request.logger.appAttestError(stage: "attestation-request")
                return try AppAttestError.invalidProof.response()
            }

            let storedChallenge: String?
            do {
                storedChallenge = try await challengeDriver.get(request, payload.keyID)
            } catch {
                request.logger.appAttestError(
                    stage: "attestation-challenge-read",
                    error: error
                )
                return try AppAttestError.unavailable.response()
            }
            guard storedChallenge == payload.challenge else {
                request.logger.appAttestError(stage: "attestation-challenge")
                return try AppAttestError.challengeMissing.response()
            }

            let verification: AppAttestationVerification
            do {
                verification = try await attestationVerification.verify(
                    configuration,
                    attestationObject,
                    keyID,
                    challenge,
                    request.logger
                )
            } catch is AppAttestationError {
                return try AppAttestError.invalidProof.response()
            } catch {
                request.logger.appAttestError(
                    stage: "attestation-verification",
                    error: error
                )
                return try AppAttestError.invalidProof.response()
            }

            let deleted: Bool
            do {
                deleted = try await challengeDriver.delete(request, payload.keyID)
            } catch {
                request.logger.appAttestError(
                    stage: "attestation-challenge-delete",
                    error: error
                )
                return try AppAttestError.unavailable.response()
            }
            guard deleted else {
                request.logger.appAttestError(stage: "attestation-challenge-delete")
                return try AppAttestError.invalidProof.response()
            }

            do {
                try await credential.saveCredential(
                    payload.keyID,
                    verification.publicKey,
                    verification.initialCounter
                )
            } catch {
                request.logger.appAttestError(
                    stage: "attestation-credential-save",
                    error: error
                )
                return try AppAttestError.unavailable.response()
            }

            request.logger.appAttestDebug(stage: "attestation")
            return Response(status: .noContent)
        }
    }
}

struct AppAttestationVerificationClient: Sendable {
    var verify: @Sendable (
        AppAttestConfiguration,
        Data,
        Data,
        Data,
        Logger
    ) async throws -> AppAttestationVerification
}

extension AppAttestationVerificationClient: DependencyKey {
    static let liveValue = Self { configuration, attestationObject, keyID, challenge, logger in
        try await AppAttestationVerifier(
            configuration: configuration,
            certificateVerifier: AppAttestCertificateVerifier(),
            logger: logger
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
