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
func transportSignsRequestAndPreservesBody() async throws {
    let recorder = TransportRecorder()
    let body = Data(#"{"value":1}"#.utf8)
    let request = testRequest(method: .post, path: "/protected?value=a%20b")

    _ = try await withTestTransport(recorder: recorder) { transport in
        try await transport.send(
            request,
            body: HTTPBody(body),
            baseURL: transportBaseURL,
            operationID: "protected"
        )
    }

    let protected = try #require(await recorder.protectedRequests.first)
    #expect(protected.body == body)
    #expect(protected.request.path == "/protected?value=a%20b")
    #expect(protected.request.headerFields.count == 3)
    #expect(protected.request.headerFields[transportKeyIDHeader] == transportKeyID)
    #expect(
        protected.request.headerFields[transportChallengeHeader]
            == transportChallenge.base64EncodedString()
    )
    #expect(
        protected.request.headerFields[transportAssertionHeader]
            == transportAssertion.base64EncodedString()
    )

    let expectedClientData = try transportClientData(
        challenge: transportChallenge,
        method: "POST",
        pathAndQuery: "/protected?value=a%20b",
        body: body
    )
    #expect(
        await recorder.assertions
            == [AssertionCall(
                keyID: transportKeyID,
                clientDataHash: Data(SHA256.hash(data: expectedClientData))
            )]
    )
}

@Test
func transportPreservesNilBody() async throws {
    let recorder = TransportRecorder()

    _ = try await withTestTransport(recorder: recorder) { transport in
        try await transport.send(
            testRequest(method: .get, path: "/empty"),
            body: nil,
            baseURL: transportBaseURL,
            operationID: "empty"
        )
    }

    let protected = try #require(await recorder.protectedRequests.first)
    #expect(protected.body == nil)
    let expectedClientData = try transportClientData(
        challenge: transportChallenge,
        method: "GET",
        pathAndQuery: "/empty",
        body: Data()
    )
    #expect(
        await recorder.assertions.first?.clientDataHash
            == Data(SHA256.hash(data: expectedClientData))
    )
}

@Test
func transportSerializesProtectedRequests() async throws {
    let recorder = TransportRecorder(suspendFirstProtectedRequest: true)

    try await withTestTransport(recorder: recorder) { transport in
        let first = Task {
            try await transport.send(
                testRequest(method: .get, path: "/first"),
                body: nil,
                baseURL: transportBaseURL,
                operationID: "first"
            )
        }
        await recorder.waitForFirstProtectedRequest()

        let secondStarted = TestSignal()
        let second = Task {
            await secondStarted.signal()
            return try await transport.send(
                testRequest(method: .get, path: "/second"),
                body: nil,
                baseURL: transportBaseURL,
                operationID: "second"
            )
        }
        await secondStarted.wait()
        for _ in 0..<10 { await Task.yield() }

        #expect(await recorder.challengeCount == 1)
        await recorder.releaseFirstProtectedRequest()
        _ = try await first.value
        _ = try await second.value
    }

    #expect(await recorder.challengeCount == 2)
    #expect(
        await recorder.protectedRequests.map(\.request.path)
            == ["/first", "/second"]
    )
}

private let transportBaseURL = URL(string: "https://example.com/api")!
private let transportKeyID = Data(repeating: 1, count: 32).base64EncodedString()
private let transportChallenge = Data(0..<32)
private let transportAssertion = Data([7, 8, 9])
private let transportKeyIDHeader = HTTPField.Name("X-App-Attest-Key-ID")!
private let transportChallengeHeader = HTTPField.Name("X-App-Attest-Challenge")!
private let transportAssertionHeader = HTTPField.Name("X-App-Attest-Assertion")!

private func testRequest(method: HTTPRequest.Method, path: String) -> HTTPRequest {
    HTTPRequest(method: method, scheme: nil, authority: nil, path: path)
}

private struct AssertionCall: Equatable, Sendable {
    let keyID: String
    let clientDataHash: Data
}

private struct ProtectedRequest: Sendable {
    let request: HTTPRequest
    let body: Data?
}

private actor TransportRecorder {
    private(set) var challengeCount = 0
    private(set) var assertions: [AssertionCall] = []
    private(set) var protectedRequests: [ProtectedRequest] = []
    private let suspendFirstProtectedRequest: Bool
    private var firstProtectedRequestReached = false
    private var reachedWaiters: [CheckedContinuation<Void, Never>] = []
    private var firstProtectedRelease: CheckedContinuation<Void, Never>?

    init(suspendFirstProtectedRequest: Bool = false) {
        self.suspendFirstProtectedRequest = suspendFirstProtectedRequest
    }

    func recordAssertion(keyID: String, clientDataHash: Data) {
        assertions.append(AssertionCall(keyID: keyID, clientDataHash: clientDataHash))
    }

    func send(request: HTTPRequest, body: Data?) async throws -> (HTTPResponse, HTTPBody?) {
        if request.path == "/app-attest/challenge" {
            challengeCount += 1
            return (
                HTTPResponse(status: .ok),
                HTTPBody(try JSONEncoder().encode(
                    ChallengeResponse(challenge: transportChallenge.base64EncodedString())
                ))
            )
        }

        protectedRequests.append(ProtectedRequest(request: request, body: body))
        if suspendFirstProtectedRequest, protectedRequests.count == 1 {
            firstProtectedRequestReached = true
            let waiters = reachedWaiters
            reachedWaiters.removeAll()
            waiters.forEach { $0.resume() }
            await withCheckedContinuation { firstProtectedRelease = $0 }
        }
        return (HTTPResponse(status: .noContent), nil)
    }

    func waitForFirstProtectedRequest() async {
        if firstProtectedRequestReached { return }
        await withCheckedContinuation { reachedWaiters.append($0) }
    }

    func releaseFirstProtectedRequest() {
        firstProtectedRelease?.resume()
        firstProtectedRelease = nil
    }
}

private struct TestTransport: ClientTransport {
    let recorder: TransportRecorder

    func send(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String
    ) async throws -> (HTTPResponse, HTTPBody?) {
        let data: Data?
        if let body {
            data = try await Data(collecting: body, upTo: .max)
        } else {
            data = nil
        }
        return try await recorder.send(request: request, body: data)
    }
}

private actor TestSignal {
    private var didSignal = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func signal() {
        didSignal = true
        let currentWaiters = waiters
        waiters.removeAll()
        currentWaiters.forEach { $0.resume() }
    }

    func wait() async {
        if didSignal { return }
        await withCheckedContinuation { waiters.append($0) }
    }
}

private func withTestTransport<Result: Sendable>(
    recorder: TransportRecorder,
    operation: (AppAttestTransport<TestTransport>) async throws -> Result
) async rethrows -> Result {
    try await withDependencies {
        $0.keychain = KeychainClient(
            upsert: { _, _ in },
            read: { _, _, _ in Data(transportKeyID.utf8) },
            delete: { _ in }
        )
        $0.appAttestService = AppAttestServiceClient(
            isSupported: { true },
            generateKey: { throw TransportTestError.unexpectedCall },
            attestKey: { _, _ in throw TransportTestError.unexpectedCall },
            generateAssertion: { keyID, clientDataHash in
                await recorder.recordAssertion(
                    keyID: keyID,
                    clientDataHash: clientDataHash
                )
                return transportAssertion
            }
        )
    } operation: {
        try await operation(AppAttestTransport(base: TestTransport(recorder: recorder)))
    }
}

private func transportClientData(
    challenge: Data,
    method: String,
    pathAndQuery: String,
    body: Data
) throws -> Data {
    var data = Data([0x01])
    try appendTransportField(challenge, to: &data)
    try appendTransportField(Data(method.utf8), to: &data)
    try appendTransportField(Data(pathAndQuery.utf8), to: &data)
    data.append(contentsOf: SHA256.hash(data: body))
    return data
}

private func appendTransportField(_ field: Data, to data: inout Data) throws {
    guard let length = UInt32(exactly: field.count) else {
        throw TransportTestError.fieldTooLarge
    }
    data.append(contentsOf: [
        UInt8(truncatingIfNeeded: length >> 24),
        UInt8(truncatingIfNeeded: length >> 16),
        UInt8(truncatingIfNeeded: length >> 8),
        UInt8(truncatingIfNeeded: length),
    ])
    data.append(field)
}

private struct ChallengeResponse: Encodable {
    let challenge: String
}

private enum TransportTestError: Error {
    case fieldTooLarge
    case unexpectedCall
}
