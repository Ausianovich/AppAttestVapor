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
            return try AppAttestError.invalidProof.response()
        }

        @Dependency(\.appAttestChallengeDriver) var challengeDriver
        @Dependency(\.appAttestCredential) var credential

        let storedChallenge: String?
        do {
            storedChallenge = try await challengeDriver.get(request, keyID)
        } catch {
            return try AppAttestError.unavailable.response()
        }
        guard storedChallenge == challenge else {
            return try AppAttestError.challengeMissing.response()
        }

        let publicKey: Data
        let storedCounter: UInt32
        do {
            guard
                let loadedPublicKey = try await credential.getPublicKey(keyID),
                let loadedCounter = try await credential.getCounter(keyID)
            else {
                return try AppAttestError.credentialMissing.response()
            }
            publicKey = loadedPublicKey
            storedCounter = loadedCounter
        } catch {
            return try AppAttestError.unavailable.response()
        }

        let body = request.body.data.map { Data($0.readableBytesView) } ?? Data()
        let newCounter: UInt32
        do {
            let clientData = try SignedRequest.clientData(
                challenge: challengeData,
                method: request.method.rawValue,
                pathAndQuery: request.url.string,
                body: body
            )
            newCounter = try AppAssertionVerifier(
                configuration: configuration
            ).verify(
                assertionObject: assertion,
                publicKey: publicKey,
                clientData: clientData,
                storedCounter: storedCounter
            )
        } catch {
            return try AppAttestError.invalidProof.response()
        }

        do {
            guard try await challengeDriver.delete(request, keyID) else {
                return try AppAttestError.invalidProof.response()
            }
            guard try await credential.advanceCounter(keyID, newCounter) else {
                return try AppAttestError.invalidProof.response()
            }
        } catch {
            return try AppAttestError.unavailable.response()
        }

        return try await next.respond(to: request)
    }
}
