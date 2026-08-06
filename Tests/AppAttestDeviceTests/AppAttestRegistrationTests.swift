import CryptoKit
import Dependencies
import Foundation
import HTTPTypes
import KeyChain
import LocalAuthentication
import OpenAPIRuntime
import Testing
@testable import AppAttestDevice

@Test
func unsupportedDeviceFailsBeforeRegistrationWork() async {
    let recorder = RegistrationRecorder()

    await #expect(throws: AppAttestDeviceError.unsupported) {
        try await withRegistrationTransport(
            recorder: recorder,
            isSupported: false
        ) { transport in
            try await transport.ensureRegistered(baseURL: registrationBaseURL)
        }
    }

    #expect(await recorder.events.isEmpty)
}

@Test
func storedKeyIDSkipsGenerationAndAttestation() async throws {
    let recorder = RegistrationRecorder(storedKeyID: registrationKeyID)

    let keyID = try await withRegistrationTransport(recorder: recorder) { transport in
        try await transport.ensureRegistered(baseURL: registrationBaseURL)
    }

    #expect(keyID == registrationKeyID)
    #expect(await recorder.events == [.readKeyID])
}

@Test
func missingKeyRegistersBeforeWritingKeychain() async throws {
    let recorder = RegistrationRecorder()

    let keyID = try await withRegistrationTransport(recorder: recorder) { transport in
        try await transport.ensureRegistered(baseURL: registrationBaseURL)
    }

    #expect(keyID == registrationKeyID)
    #expect(
        await recorder.events
            == [
                .readKeyID,
                .generateKey,
                .challengeRequest(registrationKeyID),
                .attestKey(
                    registrationKeyID,
                    Data(SHA256.hash(data: registrationChallenge))
                ),
                .attestationRequest(
                    keyID: registrationKeyID,
                    challenge: registrationChallengeString,
                    attestation: registrationAttestation.base64EncodedString()
                ),
                .writeKeyID(registrationKeyID),
            ]
    )
}

@Test
func challengeFailureDoesNotWriteKeychain() async {
    let recorder = RegistrationRecorder(challengeFailures: 1)

    await #expect(throws: AppAttestDeviceError.registrationFailed) {
        try await withRegistrationTransport(recorder: recorder) { transport in
            try await transport.ensureRegistered(baseURL: registrationBaseURL)
        }
    }

    #expect(!(await recorder.events).contains(.writeKeyID(registrationKeyID)))
}

@Test
func deviceAttestationFailureDoesNotWriteKeychain() async {
    let recorder = RegistrationRecorder()

    await #expect(throws: RegistrationTestError.deviceCheck) {
        try await withRegistrationTransport(
            recorder: recorder,
            attestationFails: true
        ) { transport in
            try await transport.ensureRegistered(baseURL: registrationBaseURL)
        }
    }

    #expect(!(await recorder.events).contains(.writeKeyID(registrationKeyID)))
}

@Test
func serverRejectionDoesNotWriteKeychain() async {
    let recorder = RegistrationRecorder(rejectAttestation: true)

    await #expect(throws: AppAttestDeviceError.registrationFailed) {
        try await withRegistrationTransport(recorder: recorder) { transport in
            try await transport.ensureRegistered(baseURL: registrationBaseURL)
        }
    }

    #expect(!(await recorder.events).contains(.writeKeyID(registrationKeyID)))
}

@Test
func failedRegistrationReusesGeneratedKeyID() async throws {
    let recorder = RegistrationRecorder(challengeFailures: 1)

    try await withRegistrationTransport(recorder: recorder) { transport in
        await #expect(throws: AppAttestDeviceError.registrationFailed) {
            try await transport.ensureRegistered(baseURL: registrationBaseURL)
        }
        _ = try await transport.ensureRegistered(baseURL: registrationBaseURL)
    }

    #expect(await recorder.events.filter { $0 == .generateKey }.count == 1)
    #expect(await recorder.events.last == .writeKeyID(registrationKeyID))
}

private let registrationBaseURL = URL(string: "https://example.com/api")!
private let registrationKeyID = Data(repeating: 1, count: 32).base64EncodedString()
private let registrationChallenge = Data(0..<32)
private let registrationChallengeString = registrationChallenge.base64EncodedString()
private let registrationAttestation = Data([7, 8, 9])

private enum RegistrationEvent: Equatable, Sendable {
    case readKeyID
    case generateKey
    case challengeRequest(String)
    case attestKey(String, Data)
    case attestationRequest(keyID: String, challenge: String, attestation: String)
    case writeKeyID(String)
}

private actor RegistrationRecorder {
    private(set) var events: [RegistrationEvent] = []
    private let storedKeyID: String?
    private var challengeFailures: Int
    private let rejectAttestation: Bool

    init(
        storedKeyID: String? = nil,
        challengeFailures: Int = 0,
        rejectAttestation: Bool = false
    ) {
        self.storedKeyID = storedKeyID
        self.challengeFailures = challengeFailures
        self.rejectAttestation = rejectAttestation
    }

    func readKeyID() throws -> Data {
        events.append(.readKeyID)
        guard let storedKeyID else { throw KeychainError.itemNotFound }
        return Data(storedKeyID.utf8)
    }

    func generateKey() -> String {
        events.append(.generateKey)
        return registrationKeyID
    }

    func attestKey(_ keyID: String, hash: Data) {
        events.append(.attestKey(keyID, hash))
    }

    func writeKeyID(_ data: Data) {
        events.append(.writeKeyID(String(decoding: data, as: UTF8.self)))
    }

    func send(
        request: HTTPRequest,
        body: Data,
        baseURL: URL,
        operationID: String
    ) throws -> (HTTPResponse, HTTPBody?) {
        guard
            request.method == .post,
            request.headerFields[.contentType] == "application/json",
            baseURL == registrationBaseURL
        else {
            throw RegistrationTestError.invalidRequest
        }

        switch request.path {
        case "/app-attest/challenge":
            guard operationID == "appAttestChallenge" else {
                throw RegistrationTestError.invalidRequest
            }
            let payload = try JSONDecoder().decode(ChallengeRequest.self, from: body)
            events.append(.challengeRequest(payload.keyID))
            if challengeFailures > 0 {
                challengeFailures -= 1
                return (HTTPResponse(status: .serviceUnavailable), nil)
            }
            return (
                HTTPResponse(status: .ok),
                HTTPBody(try JSONEncoder().encode(
                    ChallengeResponse(challenge: registrationChallengeString)
                ))
            )

        case "/app-attest/attestation":
            guard operationID == "appAttestAttestation" else {
                throw RegistrationTestError.invalidRequest
            }
            let payload = try JSONDecoder().decode(AttestationRequest.self, from: body)
            events.append(
                .attestationRequest(
                    keyID: payload.keyID,
                    challenge: payload.challenge,
                    attestation: payload.attestationObject
                )
            )
            return (
                HTTPResponse(status: rejectAttestation ? .forbidden : .noContent),
                nil
            )

        default:
            throw RegistrationTestError.invalidRequest
        }
    }
}

private struct RegistrationTransport: ClientTransport {
    let recorder: RegistrationRecorder

    func send(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String
    ) async throws -> (HTTPResponse, HTTPBody?) {
        let data: Data
        if let body {
            data = try await Data(collecting: body, upTo: .max)
        } else {
            data = Data()
        }
        return try await recorder.send(
            request: request,
            body: data,
            baseURL: baseURL,
            operationID: operationID
        )
    }
}

private func withRegistrationTransport<Result: Sendable>(
    recorder: RegistrationRecorder,
    isSupported: Bool = true,
    attestationFails: Bool = false,
    operation: (AppAttestTransport<RegistrationTransport>) async throws -> Result
) async rethrows -> Result {
    try await withDependencies {
        $0.keychain = KeychainClient(
            upsert: { data, query in
                guard query == registrationKeychainQuery else {
                    throw RegistrationTestError.invalidRequest
                }
                await recorder.writeKeyID(data)
            },
            read: { query, _, _ in
                guard query == registrationKeychainQuery else {
                    throw RegistrationTestError.invalidRequest
                }
                return try await recorder.readKeyID()
            },
            delete: { _ in }
        )
        $0.appAttestService = AppAttestServiceClient(
            isSupported: { isSupported },
            generateKey: { await recorder.generateKey() },
            attestKey: { keyID, hash in
                await recorder.attestKey(keyID, hash: hash)
                if attestationFails { throw RegistrationTestError.deviceCheck }
                return registrationAttestation
            },
            generateAssertion: { _, _ in Data() }
        )
    } operation: {
        try await operation(
            AppAttestTransport(base: RegistrationTransport(recorder: recorder))
        )
    }
}

private let registrationKeychainQuery = KeychainQuery.genericPassword(
    account: "app-attest-key-id",
    service: "AppAttestDevice"
)

private struct ChallengeRequest: Decodable {
    let keyID: String
}

private struct ChallengeResponse: Encodable {
    let challenge: String
}

private struct AttestationRequest: Decodable {
    let keyID: String
    let challenge: String
    let attestationObject: String
}

private enum RegistrationTestError: Error {
    case deviceCheck
    case invalidRequest
}
