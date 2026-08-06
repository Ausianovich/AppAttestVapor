import Crypto
import Dependencies
import Foundation
import Testing
import Vapor
import VaporTesting
@testable import AppAttestVapor

@Test
func middlewareVerifiesRequestBeforeCallingHandler() async throws {
    let result = try await sendMiddlewareRequest()

    #expect(result.status == .noContent)
    #expect(
        result.events
            == [
                .getChallenge(middlewareKeyID),
                .getPublicKey(middlewareKeyID),
                .getCounter(middlewareKeyID),
                .deleteChallenge(middlewareKeyID),
                .advanceCounter(middlewareKeyID, 5),
                .downstream,
            ]
    )
}

@Test(arguments: MiddlewareHeaders.invalidCases)
func middlewareRejectsMissingOrMalformedHeaders(
    headers: MiddlewareHeaders
) async throws {
    let result = try await sendMiddlewareRequest(headers: headers)

    expectMiddlewareError(result, status: .forbidden, code: "app_attest_invalid")
    #expect(result.events.isEmpty)
}

@Test(arguments: [nil, Data(repeating: 9, count: 32).base64EncodedString()])
func middlewareRejectsMissingOrMismatchedChallenge(
    storedChallenge: String?
) async throws {
    let result = try await sendMiddlewareRequest(
        behavior: MiddlewareBehavior(storedChallenge: storedChallenge)
    )

    expectMiddlewareError(
        result,
        status: .unauthorized,
        code: "app_attest_challenge_missing"
    )
    #expect(result.events == [.getChallenge(middlewareKeyID)])
}

@Test(arguments: [MissingCredential.publicKey, .counter])
func middlewareRejectsMissingCredential(
    missing: MissingCredential
) async throws {
    let result = try await sendMiddlewareRequest(
        behavior: MiddlewareBehavior(missingCredential: missing)
    )

    expectMiddlewareError(
        result,
        status: .unauthorized,
        code: "app_attest_credential_missing"
    )
}

@Test
func middlewareRejectsInvalidAssertion() async throws {
    let result = try await sendMiddlewareRequest(
        behavior: MiddlewareBehavior(invalidAssertion: true)
    )

    expectMiddlewareError(result, status: .forbidden, code: "app_attest_invalid")
}

@Test
func middlewareRejectsConsumedChallenge() async throws {
    let result = try await sendMiddlewareRequest(
        behavior: MiddlewareBehavior(deleteSucceeds: false)
    )

    expectMiddlewareError(result, status: .forbidden, code: "app_attest_invalid")
}

@Test
func middlewareRejectsFailedCounterAdvance() async throws {
    let result = try await sendMiddlewareRequest(
        behavior: MiddlewareBehavior(advanceSucceeds: false)
    )

    expectMiddlewareError(result, status: .forbidden, code: "app_attest_invalid")
}

@Test(arguments: MiddlewareStorageFailure.allCases)
func middlewareMapsStorageFailuresToUnavailable(
    failure: MiddlewareStorageFailure
) async throws {
    let result = try await sendMiddlewareRequest(
        behavior: MiddlewareBehavior(storageFailure: failure)
    )

    expectMiddlewareError(
        result,
        status: .serviceUnavailable,
        code: "app_attest_unavailable"
    )
}

private let middlewareConfiguration = AppAttestConfiguration(
    teamID: "TESTTEAMID",
    bundleID: "com.example.app",
    environment: .development
)
private let middlewareKeyID = Data(repeating: 1, count: 32).base64EncodedString()
private let middlewareChallenge = Data(0..<32)
private let middlewareChallengeString = middlewareChallenge.base64EncodedString()
private let middlewarePrivateKey = try! P256.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0, count: 31) + Data([1])
)

private enum MiddlewareEvent: Equatable, Sendable {
    case getChallenge(String)
    case getPublicKey(String)
    case getCounter(String)
    case deleteChallenge(String)
    case advanceCounter(String, UInt32)
    case downstream
}

enum MiddlewareHeaders: CaseIterable, Equatable, Sendable {
    case valid
    case missingKeyID
    case malformedKeyID
    case missingChallenge
    case malformedChallenge
    case missingAssertion
    case malformedAssertion

    static var invalidCases: [Self] {
        allCases.filter { $0 != .valid }
    }
}

enum MissingCredential: Equatable, Sendable {
    case publicKey
    case counter
}

enum MiddlewareStorageFailure: CaseIterable, Equatable, Sendable {
    case getChallenge
    case getPublicKey
    case getCounter
    case deleteChallenge
    case advanceCounter
}

private struct MiddlewareBehavior: Sendable {
    var storedChallenge: String? = middlewareChallengeString
    var missingCredential: MissingCredential?
    var invalidAssertion = false
    var deleteSucceeds = true
    var advanceSucceeds = true
    var storageFailure: MiddlewareStorageFailure?
}

private struct MiddlewareErrorResponse: Decodable, Equatable, Sendable {
    let code: String
}

private struct MiddlewareResult: Sendable {
    let status: HTTPStatus
    let error: MiddlewareErrorResponse?
    let events: [MiddlewareEvent]
}

private actor MiddlewareRecorder {
    private(set) var events: [MiddlewareEvent] = []

    func record(_ event: MiddlewareEvent) {
        events.append(event)
    }
}

private func sendMiddlewareRequest(
    behavior: MiddlewareBehavior = MiddlewareBehavior(),
    headers: MiddlewareHeaders = .valid
) async throws -> MiddlewareResult {
    let recorder = MiddlewareRecorder()
    let body = Data(#"{"value":1}"#.utf8)
    let clientData = try middlewareClientData(
        challenge: middlewareChallenge,
        method: "POST",
        pathAndQuery: "/protected?value=a%20b",
        body: body
    )
    let assertion = try middlewareAssertion(clientData: clientData, counter: 5)

    let response = try await withDependencies {
        $0.appAttestChallengeDriver = ValkeyChallengeDriver(
            issue: { _, _, _ in "unused" },
            get: { _, keyID in
                await recorder.record(.getChallenge(keyID))
                if behavior.storageFailure == .getChallenge { throw MiddlewareTestError.storage }
                return behavior.storedChallenge
            },
            delete: { _, keyID in
                await recorder.record(.deleteChallenge(keyID))
                if behavior.storageFailure == .deleteChallenge { throw MiddlewareTestError.storage }
                return behavior.deleteSucceeds
            }
        )
        $0.appAttestCredential = AppAttestCredentialClient(
            saveCredential: { _, _, _ in },
            getPublicKey: { keyID in
                await recorder.record(.getPublicKey(keyID))
                if behavior.storageFailure == .getPublicKey { throw MiddlewareTestError.storage }
                return behavior.missingCredential == .publicKey
                    ? nil
                    : middlewarePrivateKey.publicKey.x963Representation
            },
            getCounter: { keyID in
                await recorder.record(.getCounter(keyID))
                if behavior.storageFailure == .getCounter { throw MiddlewareTestError.storage }
                return behavior.missingCredential == .counter ? nil : 4
            },
            advanceCounter: { keyID, counter in
                await recorder.record(.advanceCounter(keyID, counter))
                if behavior.storageFailure == .advanceCounter { throw MiddlewareTestError.storage }
                return behavior.advanceSucceeds
            }
        )
    } operation: {
        try await withApp { application in
            application.appAttest.configure(middlewareConfiguration)
            application.grouped(AppAttestMiddleware()).post("protected") { _ in
                await recorder.record(.downstream)
                return Response(status: .noContent)
            }

            return try await application.testing().sendRequest(
                .POST,
                "/protected?value=a%20b"
            ) { request in
                addMiddlewareHeaders(
                    headers,
                    assertion: behavior.invalidAssertion ? Data([0xFF]) : assertion,
                    to: &request.headers
                )
                request.body = ByteBuffer(data: body)
            }
        }
    }

    return MiddlewareResult(
        status: response.status,
        error: try? response.content.decode(MiddlewareErrorResponse.self),
        events: await recorder.events
    )
}

private func addMiddlewareHeaders(
    _ selection: MiddlewareHeaders,
    assertion: Data,
    to headers: inout HTTPHeaders
) {
    if selection != .missingKeyID {
        headers.add(
            name: "X-App-Attest-Key-ID",
            value: selection == .malformedKeyID ? "not-base64" : middlewareKeyID
        )
    }
    if selection != .missingChallenge {
        headers.add(
            name: "X-App-Attest-Challenge",
            value: selection == .malformedChallenge
                ? "not-base64"
                : middlewareChallengeString
        )
    }
    if selection != .missingAssertion {
        headers.add(
            name: "X-App-Attest-Assertion",
            value: selection == .malformedAssertion
                ? "not-base64"
                : assertion.base64EncodedString()
        )
    }
}

private func expectMiddlewareError(
    _ result: MiddlewareResult,
    status: HTTPStatus,
    code: String
) {
    #expect(result.status == status)
    #expect(result.error == MiddlewareErrorResponse(code: code))
    #expect(!result.events.contains(.downstream))
}

private func middlewareClientData(
    challenge: Data,
    method: String,
    pathAndQuery: String,
    body: Data
) throws -> Data {
    var data = Data([0x01])
    try appendMiddlewareField(challenge, to: &data)
    try appendMiddlewareField(Data(method.utf8), to: &data)
    try appendMiddlewareField(Data(pathAndQuery.utf8), to: &data)
    data.append(contentsOf: SHA256.hash(data: body))
    return data
}

private func appendMiddlewareField(_ field: Data, to data: inout Data) throws {
    guard let length = UInt32(exactly: field.count) else {
        throw MiddlewareTestError.fieldTooLarge
    }
    data.append(contentsOf: [
        UInt8(truncatingIfNeeded: length >> 24),
        UInt8(truncatingIfNeeded: length >> 16),
        UInt8(truncatingIfNeeded: length >> 8),
        UInt8(truncatingIfNeeded: length),
    ])
    data.append(field)
}

private func middlewareAssertion(clientData: Data, counter: UInt32) throws -> Data {
    var authenticatorData = Data(
        SHA256.hash(data: Data("TESTTEAMID.com.example.app".utf8))
    )
    authenticatorData.append(0x01)
    authenticatorData.append(contentsOf: [
        UInt8(truncatingIfNeeded: counter >> 24),
        UInt8(truncatingIfNeeded: counter >> 16),
        UInt8(truncatingIfNeeded: counter >> 8),
        UInt8(truncatingIfNeeded: counter),
    ])

    var nonceInput = authenticatorData
    nonceInput.append(contentsOf: SHA256.hash(data: clientData))
    let signature = try middlewarePrivateKey.signature(
        for: SHA256.hash(data: nonceInput)
    ).derRepresentation

    return Data(
        [0xA2]
            + middlewareCBORText("signature")
            + middlewareCBORBytes(signature)
            + middlewareCBORText("authenticatorData")
            + middlewareCBORBytes(authenticatorData)
    )
}

private func middlewareCBORText(_ value: String) -> [UInt8] {
    let bytes = Array(value.utf8)
    return middlewareCBORLength(major: 0x60, count: bytes.count) + bytes
}

private func middlewareCBORBytes(_ value: Data) -> [UInt8] {
    middlewareCBORLength(major: 0x40, count: value.count) + value
}

private func middlewareCBORLength(major: UInt8, count: Int) -> [UInt8] {
    count < 24
        ? [major | UInt8(count)]
        : [major | 0x18, UInt8(count)]
}

private enum MiddlewareTestError: Error {
    case fieldTooLarge
    case storage
}
