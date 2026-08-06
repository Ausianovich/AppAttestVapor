import Dependencies
import Foundation
import HTTPTypes
import KeyChain
import LocalAuthentication
import OpenAPIRuntime
import Testing
@testable import AppAttestDevice

@Test
func challengeMissingRetriesPreparationOnlyOnce() async throws {
    let state = RecoveryState(
        protectedResponses: [.error(.unauthorized, "app_attest_challenge_missing"),
                             .error(.unauthorized, "app_attest_challenge_missing")]
    )

    let (_, body) = try await sendRecoveryRequest(state: state)

    #expect(await state.challengeCount == 2)
    #expect(await state.assertionCount == 2)
    #expect(await state.protectedKeyIDs == [oldRecoveryKeyID, oldRecoveryKeyID])
    #expect(await state.generatedKeyCount == 0)
    #expect(await state.storedKeyID == oldRecoveryKeyID)
    #expect(try await collected(body) == errorBody("app_attest_challenge_missing"))
}

@Test
func credentialMissingRegistersNewKeyAndRetriesRequestOnce() async throws {
    let state = RecoveryState(
        protectedResponses: [.error(.unauthorized, "app_attest_credential_missing"),
                             .success]
    )

    let (response, _) = try await sendRecoveryRequest(state: state)

    #expect(response.status == .noContent)
    #expect(await state.deletedKeyCount == 1)
    #expect(await state.generatedKeyCount == 1)
    #expect(await state.attestationCount == 1)
    #expect(await state.protectedKeyIDs == [oldRecoveryKeyID, newRecoveryKeyID])
    #expect(await state.storedKeyID == newRecoveryKeyID)
}

@Test(arguments: RecoveryServerFailure.allCases)
func serverFailureIsNotRetriedAndResponseBodyRemainsReadable(
    failure: RecoveryServerFailure
) async throws {
    let state = RecoveryState(protectedResponses: [failure.response])

    let (response, body) = try await sendRecoveryRequest(state: state)

    #expect(response.status == failure.status)
    #expect(await state.challengeCount == 1)
    #expect(await state.assertionCount == 1)
    #expect(await state.protectedKeyIDs == [oldRecoveryKeyID])
    #expect(await state.deletedKeyCount == 0)
    #expect(await state.storedKeyID == oldRecoveryKeyID)
    #expect(try await collected(body) == errorBody(failure.code))
}

@Test
func unsupportedDeviceDoesNotSendOrRemoveStoredKey() async {
    let state = RecoveryState(isSupported: false)

    await #expect(throws: AppAttestDeviceError.unsupported) {
        try await sendRecoveryRequest(state: state)
    }

    #expect(await state.networkCallCount == 0)
    #expect(await state.deletedKeyCount == 0)
    #expect(await state.storedKeyID == oldRecoveryKeyID)
}

@Test
func keychainReadFailureIsNotRetried() async {
    let state = RecoveryState(keychainReadFails: true)

    await #expect(throws: RecoveryTestError.keychain) {
        try await sendRecoveryRequest(state: state)
    }

    #expect(await state.keychainReadCount == 1)
    #expect(await state.networkCallCount == 0)
    #expect(await state.storedKeyID == oldRecoveryKeyID)
}

@Test
func keychainDeleteFailureDoesNotStartRegistration() async {
    let state = RecoveryState(
        keychainDeleteFails: true,
        protectedResponses: [.error(.unauthorized, "app_attest_credential_missing")]
    )

    await #expect(throws: RecoveryTestError.keychain) {
        try await sendRecoveryRequest(state: state)
    }

    #expect(await state.protectedKeyIDs == [oldRecoveryKeyID])
    #expect(await state.generatedKeyCount == 0)
    #expect(await state.storedKeyID == oldRecoveryKeyID)
}

@Test
func assertionFailureDoesNotRetryOrRemoveStoredKey() async {
    let state = RecoveryState(assertionFails: true)

    await #expect(throws: RecoveryTestError.deviceCheck) {
        try await sendRecoveryRequest(state: state)
    }

    #expect(await state.challengeCount == 1)
    #expect(await state.assertionCount == 1)
    #expect(await state.protectedKeyIDs.isEmpty)
    #expect(await state.deletedKeyCount == 0)
    #expect(await state.storedKeyID == oldRecoveryKeyID)
}

@Test
func reattestationFailureLeavesDeletedOldKeyUnstored() async {
    let state = RecoveryState(
        attestationFails: true,
        protectedResponses: [.error(.unauthorized, "app_attest_credential_missing")]
    )

    await #expect(throws: RecoveryTestError.deviceCheck) {
        try await sendRecoveryRequest(state: state)
    }

    #expect(await state.protectedKeyIDs == [oldRecoveryKeyID])
    #expect(await state.deletedKeyCount == 1)
    #expect(await state.generatedKeyCount == 1)
    #expect(await state.attestationCount == 0)
    #expect(await state.storedKeyID == nil)
}

private let recoveryBaseURL = URL(string: "https://example.com/api")!
private let oldRecoveryKeyID = Data(repeating: 1, count: 32).base64EncodedString()
private let newRecoveryKeyID = Data(repeating: 2, count: 32).base64EncodedString()
private let recoveryKeyIDHeader = HTTPField.Name("X-App-Attest-Key-ID")!

enum RecoveryServerFailure: CaseIterable, Sendable {
    case forbidden
    case unavailable

    var status: HTTPResponse.Status {
        switch self {
        case .forbidden: .forbidden
        case .unavailable: .serviceUnavailable
        }
    }

    var code: String {
        switch self {
        case .forbidden: "app_attest_invalid"
        case .unavailable: "app_attest_unavailable"
        }
    }

    fileprivate var response: RecoveryResponse { .error(status, code) }
}

private struct RecoveryResponse: Sendable {
    let status: HTTPResponse.Status
    let body: Data?

    static let success = Self(status: .noContent, body: nil)

    static func error(_ status: HTTPResponse.Status, _ code: String) -> Self {
        Self(status: status, body: errorBody(code))
    }
}

private actor RecoveryState {
    private(set) var storedKeyID: String?
    private(set) var keychainReadCount = 0
    private(set) var deletedKeyCount = 0
    private(set) var generatedKeyCount = 0
    private(set) var challengeCount = 0
    private(set) var assertionCount = 0
    private(set) var attestationCount = 0
    private(set) var protectedKeyIDs: [String] = []

    private let isSupportedValue: Bool
    private let keychainReadFails: Bool
    private let keychainDeleteFails: Bool
    private let assertionFails: Bool
    private let attestationFails: Bool
    private var protectedResponses: [RecoveryResponse]

    init(
        storedKeyID: String? = oldRecoveryKeyID,
        isSupported: Bool = true,
        keychainReadFails: Bool = false,
        keychainDeleteFails: Bool = false,
        assertionFails: Bool = false,
        attestationFails: Bool = false,
        protectedResponses: [RecoveryResponse] = [.success]
    ) {
        self.storedKeyID = storedKeyID
        self.isSupportedValue = isSupported
        self.keychainReadFails = keychainReadFails
        self.keychainDeleteFails = keychainDeleteFails
        self.assertionFails = assertionFails
        self.attestationFails = attestationFails
        self.protectedResponses = protectedResponses
    }

    var networkCallCount: Int {
        challengeCount + attestationCount + protectedKeyIDs.count
    }

    func isSupported() -> Bool { isSupportedValue }

    func readKeyID() throws -> Data {
        keychainReadCount += 1
        if keychainReadFails { throw RecoveryTestError.keychain }
        guard let storedKeyID else { throw KeychainError.itemNotFound }
        return Data(storedKeyID.utf8)
    }

    func deleteKeyID() throws {
        if keychainDeleteFails { throw RecoveryTestError.keychain }
        deletedKeyCount += 1
        storedKeyID = nil
    }

    func writeKeyID(_ data: Data) {
        storedKeyID = String(decoding: data, as: UTF8.self)
    }

    func generateKey() -> String {
        generatedKeyCount += 1
        return newRecoveryKeyID
    }

    func attestKey() throws {
        if attestationFails { throw RecoveryTestError.deviceCheck }
    }

    func generateAssertion() throws -> Data {
        assertionCount += 1
        if assertionFails { throw RecoveryTestError.deviceCheck }
        return Data([7, 8, 9])
    }

    func send(request: HTTPRequest) throws -> (HTTPResponse, HTTPBody?) {
        switch request.path {
        case "/app-attest/challenge":
            challengeCount += 1
            let challenge = Data(repeating: UInt8(challengeCount), count: 32)
            return (
                HTTPResponse(status: .ok),
                HTTPBody(errorBodyValue(challenge.base64EncodedString()))
            )

        case "/app-attest/attestation":
            attestationCount += 1
            return (HTTPResponse(status: .noContent), nil)

        default:
            guard
                let keyID = request.headerFields[recoveryKeyIDHeader],
                !protectedResponses.isEmpty
            else { throw RecoveryTestError.unexpectedCall }
            protectedKeyIDs.append(keyID)
            let response = protectedResponses.removeFirst()
            return (
                HTTPResponse(status: response.status),
                response.body.map(HTTPBody.init)
            )
        }
    }
}

private struct RecoveryTransport: ClientTransport {
    let state: RecoveryState

    func send(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String
    ) async throws -> (HTTPResponse, HTTPBody?) {
        try await state.send(request: request)
    }
}

private func sendRecoveryRequest(
    state: RecoveryState
) async throws -> (HTTPResponse, HTTPBody?) {
    let isSupported = await state.isSupported()
    return try await withDependencies {
        $0.keychain = KeychainClient(
            upsert: { data, _ in await state.writeKeyID(data) },
            read: { _, _, _ in try await state.readKeyID() },
            delete: { _ in try await state.deleteKeyID() }
        )
        $0.appAttestService = AppAttestServiceClient(
            isSupported: { isSupported },
            generateKey: { await state.generateKey() },
            attestKey: { _, _ in
                try await state.attestKey()
                return Data([4, 5, 6])
            },
            generateAssertion: { _, _ in try await state.generateAssertion() }
        )
    } operation: {
        try await AppAttestTransport(base: RecoveryTransport(state: state)).send(
            HTTPRequest(
                method: .get,
                scheme: nil,
                authority: nil,
                path: "/protected"
            ),
            body: nil,
            baseURL: recoveryBaseURL,
            operationID: "protected"
        )
    }
}

private func collected(_ body: HTTPBody?) async throws -> Data? {
    guard let body else { return nil }
    return try await Data(collecting: body, upTo: .max)
}

private func errorBody(_ code: String) -> Data {
    Data(#"{"code":"\#(code)"}"#.utf8)
}

private func errorBodyValue(_ challenge: String) -> Data {
    Data(#"{"challenge":"\#(challenge)"}"#.utf8)
}

private enum RecoveryTestError: Error {
    case deviceCheck
    case keychain
    case unexpectedCall
}
