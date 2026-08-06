import Dependencies
import Foundation
import Testing
import Vapor
import VaporTesting
@testable import AppAttestVapor

@Test
func attestationRouteVerifiesDeletesAndSavesCredential() async throws {
    let result = try await sendAttestation(routePrefix: "/security/app-attest")

    #expect(result.status == .noContent)
    #expect(result.events == [.get, .verify, .delete, .save])
    #expect(
        result.verification
            == VerificationArguments(
                attestationObject: validAttestation,
                keyID: validKeyID,
                challenge: validChallenge
            )
    )
    #expect(
        result.savedCredential
            == SavedCredential(
                keyID: validKeyIDString,
                publicKey: verifiedPublicKey,
                counter: 0
            )
    )
}

@Test
func attestationRouteRejectsMissingChallengeBeforeVerification() async throws {
    let result = try await sendAttestation(
        behavior: RouteBehavior(storedChallenge: nil)
    )

    expectError(result, status: .unauthorized, code: "app_attest_challenge_missing")
    #expect(result.events == [.get])
    #expect(result.savedCredential == nil)
}

@Test
func attestationRouteRejectsMismatchedChallengeBeforeVerification() async throws {
    let result = try await sendAttestation(
        behavior: RouteBehavior(storedChallenge: Data(repeating: 9, count: 32).base64EncodedString())
    )

    expectError(result, status: .unauthorized, code: "app_attest_challenge_missing")
    #expect(result.events == [.get])
    #expect(result.savedCredential == nil)
}

@Test
func attestationRouteRejectsInvalidAttestationBeforeDelete() async throws {
    let result = try await sendAttestation(
        behavior: RouteBehavior(verificationFails: true)
    )

    expectError(result, status: .forbidden, code: "app_attest_invalid")
    #expect(result.events == [.get, .verify])
    #expect(result.savedCredential == nil)
}

@Test
func attestationRouteRejectsConsumedChallengeBeforeSave() async throws {
    let result = try await sendAttestation(
        behavior: RouteBehavior(deleteSucceeds: false)
    )

    expectError(result, status: .forbidden, code: "app_attest_invalid")
    #expect(result.events == [.get, .verify, .delete])
    #expect(result.savedCredential == nil)
}

@Test
func attestationRouteMapsMalformedInputToForbidden() async throws {
    let result = try await sendAttestation(
        payload: AttestationRequest(
            keyID: "not-base64",
            challenge: validChallengeString,
            attestationObject: "not-base64"
        )
    )

    expectError(result, status: .forbidden, code: "app_attest_invalid")
    #expect(result.events.isEmpty)
    #expect(result.savedCredential == nil)
}

@Test(arguments: [StorageFailure.get, .delete])
func attestationRouteMapsStorageFailureToUnavailable(
    failure: StorageFailure
) async throws {
    let result = try await sendAttestation(
        behavior: RouteBehavior(storageFailure: failure)
    )

    expectError(result, status: .serviceUnavailable, code: "app_attest_unavailable")
    #expect(result.savedCredential == nil)
    #expect(
        result.events
            == (failure == .get ? [.get] : [.get, .verify, .delete])
    )
}

@Test
func attestationRouteMapsCredentialFailureToUnavailable() async throws {
    let result = try await sendAttestation(
        behavior: RouteBehavior(saveFails: true)
    )

    expectError(result, status: .serviceUnavailable, code: "app_attest_unavailable")
    #expect(result.events == [.get, .verify, .delete, .save])
}

private let routeConfiguration = AppAttestConfiguration(
    teamID: "TESTTEAMID",
    bundleID: "com.example.app",
    environment: .development
)

private let validKeyIDString = "IY3ms15eBehq6vIUoONV8+9dzuxS4gabPUPIWwk0Qog="
private let validChallengeString = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
private let validKeyID = Data(base64Encoded: validKeyIDString)!
private let validChallenge = Data(base64Encoded: validChallengeString)!
private let validAttestation = try! fixture("valid-attestation.cbor")
private let verifiedPublicKey = Data(repeating: 7, count: 65)

private struct AttestationRequest: Content {
    let keyID: String
    let challenge: String
    let attestationObject: String
}

private struct ErrorResponse: Decodable, Equatable {
    let code: String
}

private enum RouteEvent: Equatable, Sendable {
    case get
    case verify
    case delete
    case save
}

enum StorageFailure: Equatable, Sendable {
    case get
    case delete
}

private struct RouteBehavior: Sendable {
    var storedChallenge: String? = validChallengeString
    var verificationFails = false
    var deleteSucceeds = true
    var storageFailure: StorageFailure?
    var saveFails = false
}

private struct VerificationArguments: Equatable, Sendable {
    let attestationObject: Data
    let keyID: Data
    let challenge: Data
}

private struct SavedCredential: Equatable, Sendable {
    let keyID: String
    let publicKey: Data
    let counter: UInt32
}

private struct RouteResult: Sendable {
    let status: HTTPStatus
    let error: ErrorResponse?
    let events: [RouteEvent]
    let verification: VerificationArguments?
    let savedCredential: SavedCredential?
}

private actor RouteRecorder {
    private var events: [RouteEvent] = []
    private var verification: VerificationArguments?
    private var savedCredential: SavedCredential?
    private var status: HTTPStatus?
    private var error: ErrorResponse?

    func record(_ event: RouteEvent) {
        events.append(event)
    }

    func recordVerification(_ arguments: VerificationArguments) {
        events.append(.verify)
        verification = arguments
    }

    func recordSave(_ credential: SavedCredential) {
        events.append(.save)
        savedCredential = credential
    }

    func recordResponse(status: HTTPStatus, error: ErrorResponse?) {
        self.status = status
        self.error = error
    }

    func result() throws -> RouteResult {
        guard let status else { throw TestFailure() }
        return RouteResult(
            status: status,
            error: error,
            events: events,
            verification: verification,
            savedCredential: savedCredential
        )
    }
}

private func sendAttestation(
    behavior: RouteBehavior = RouteBehavior(),
    payload: AttestationRequest? = nil,
    routePrefix: String = "/app-attest"
) async throws -> RouteResult {
    let recorder = RouteRecorder()
    let payload = payload ?? AttestationRequest(
        keyID: validKeyIDString,
        challenge: validChallengeString,
        attestationObject: validAttestation.base64EncodedString()
    )

    return try await withDependencies {
        $0.appAttestChallengeDriver = ValkeyChallengeDriver(
            issue: { _, _, _ in "unused" },
            get: { _, _ in
                await recorder.record(.get)
                if behavior.storageFailure == .get { throw TestFailure() }
                return behavior.storedChallenge
            },
            delete: { _, _ in
                await recorder.record(.delete)
                if behavior.storageFailure == .delete { throw TestFailure() }
                return behavior.deleteSucceeds
            }
        )
        $0.appAttestationVerification = AppAttestationVerificationClient(
            verify: { _, attestationObject, keyID, challenge in
                await recorder.recordVerification(
                    VerificationArguments(
                        attestationObject: attestationObject,
                        keyID: keyID,
                        challenge: challenge
                    )
                )
                if behavior.verificationFails { throw AppAttestationError.invalidAttestation }
                return AppAttestationVerification(
                    publicKey: verifiedPublicKey,
                    initialCounter: 0
                )
            }
        )
        $0.appAttestCredential = AppAttestCredentialClient(
            saveCredential: { keyID, publicKey, counter in
                await recorder.recordSave(
                    SavedCredential(keyID: keyID, publicKey: publicKey, counter: counter)
                )
                if behavior.saveFails { throw TestFailure() }
            },
            getPublicKey: { _ in nil },
            getCounter: { _ in nil },
            advanceCounter: { _, _ in false }
        )
    } operation: {
        try await withApp { application in
            application.appAttest.configure(
                AppAttestConfiguration(
                    teamID: routeConfiguration.teamID,
                    bundleID: routeConfiguration.bundleID,
                    environment: routeConfiguration.environment,
                    routePrefix: routePrefix
                )
            )

            try await application.testing().test(
                .POST,
                "\(routePrefix)/attestation"
            ) { request in
                try request.content.encode(payload)
            } afterResponse: { response in
                await recorder.recordResponse(
                    status: response.status,
                    error: try? response.content.decode(ErrorResponse.self)
                )
            }
        }
        return try await recorder.result()
    }
}

private func expectError(
    _ result: RouteResult,
    status: HTTPStatus,
    code: String
) {
    #expect(result.status == status)
    #expect(result.error == ErrorResponse(code: code))
}

private func fixture(_ name: String) throws -> Data {
    guard let url = Bundle.module.url(
        forResource: name,
        withExtension: nil,
        subdirectory: "Fixtures"
    ) else {
        throw TestFailure()
    }
    return try Data(contentsOf: url)
}

private struct TestFailure: Error {}
