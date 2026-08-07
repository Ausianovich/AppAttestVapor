import AppAttestCore
import Dependencies
import Foundation
import Vapor

public struct AppAttestMiddleware: AsyncMiddleware {
    public init() {}

    public func respond(
        to request: Request,
        chainingTo next: AsyncResponder
    ) async throws -> Response {
        guard
            let configuration = request.application.appAttest.configuration,
            let keyID = request.headers.first(name: AppAttestHeaders.keyID),
            Data(base64Encoded: keyID)?.count == 32,
            let challenge = request.headers.first(name: AppAttestHeaders.challenge),
            let challengeData = Data(base64Encoded: challenge),
            challengeData.count == 32,
            let assertionValue = request.headers.first(name: AppAttestHeaders.assertion),
            let assertion = Data(base64Encoded: assertionValue),
            !assertion.isEmpty
        else {
            request.logger.appAttestError(stage: "assertion-request")
            return try AppAttestError.invalidProof.response()
        }

        @Dependency(\.appAttestChallengeDriver) var challengeDriver
        @Dependency(\.appAttestCredential) var credential

        let storedChallenge: String?
        do {
            storedChallenge = try await challengeDriver.get(request, keyID)
        } catch {
            request.logger.appAttestError(
                stage: "assertion-challenge-read",
                error: error
            )
            return try AppAttestError.unavailable.response()
        }
        guard storedChallenge == challenge else {
            request.logger.appAttestError(stage: "assertion-challenge")
            return try AppAttestError.challengeMissing.response()
        }

        let publicKey: Data
        let storedCounter: UInt32
        var credentialStage = "assertion-public-key-read"
        do {
            guard let loadedPublicKey = try await credential.getPublicKey(keyID) else {
                request.logger.appAttestError(stage: credentialStage)
                return try AppAttestError.credentialMissing.response()
            }
            publicKey = loadedPublicKey
            credentialStage = "assertion-counter-read"
            guard let loadedCounter = try await credential.getCounter(keyID) else {
                request.logger.appAttestError(stage: credentialStage)
                return try AppAttestError.credentialMissing.response()
            }
            storedCounter = loadedCounter
        } catch {
            request.logger.appAttestError(stage: credentialStage, error: error)
            return try AppAttestError.unavailable.response()
        }

        let body = request.body.data.map { Data($0.readableBytesView) } ?? Data()
        let newCounter: UInt32
        var verificationStage = "assertion-client-data"
        do {
            let clientData = try SignedRequest.clientData(
                challenge: challengeData,
                method: request.method.rawValue,
                pathAndQuery: request.url.string,
                body: body
            )
            verificationStage = "assertion-verification"
            newCounter = try AppAssertionVerifier(
                configuration: configuration,
                logger: request.logger
            ).verify(
                assertionObject: assertion,
                publicKey: publicKey,
                clientData: clientData,
                storedCounter: storedCounter
            )
        } catch is AppAssertionError {
            return try AppAttestError.invalidProof.response()
        } catch {
            request.logger.appAttestError(stage: verificationStage, error: error)
            return try AppAttestError.invalidProof.response()
        }

        var persistenceStage = "assertion-challenge-delete"
        do {
            guard try await challengeDriver.delete(request, keyID) else {
                request.logger.appAttestError(stage: persistenceStage)
                return try AppAttestError.invalidProof.response()
            }
            persistenceStage = "assertion-counter-advance"
            guard try await credential.advanceCounter(keyID, newCounter) else {
                request.logger.appAttestError(stage: persistenceStage)
                return try AppAttestError.invalidProof.response()
            }
        } catch {
            request.logger.appAttestError(stage: persistenceStage, error: error)
            return try AppAttestError.unavailable.response()
        }

        request.logger.appAttestDebug(stage: "assertion")
        return try await next.respond(to: request)
    }
}
