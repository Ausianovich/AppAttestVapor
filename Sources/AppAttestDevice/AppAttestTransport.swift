import AppAttestCore
import CryptoKit
import Dependencies
import Foundation
import HTTPTypes
import OpenAPIRuntime

public actor AppAttestTransport<Base: ClientTransport>: ClientTransport {
    private let serviceHTTP: AppAttestServiceHTTP<Base>
    private let keyIDStore = AppAttestKeyIDStore()
    private var pendingKeyID: String?
    private var isSending = false
    private var sendWaiters: [CheckedContinuation<Void, Never>] = []

    // ponytail: one global gate matches the v1 sequential contract; replace it only when parallel requests are designed.

    @Dependency(\.appAttestService) private var service

    public init(base: Base, routePrefix: String = "/app-attest") {
        serviceHTTP = AppAttestServiceHTTP(
            base: base,
            routePrefix: routePrefix
        )
    }

    public func send(
        _ request: HTTPRequest,
        body: HTTPBody?,
        baseURL: URL,
        operationID: String
    ) async throws -> (HTTPResponse, HTTPBody?) {
        await acquireSendGate()
        defer { releaseSendGate() }

        let keyID = try await ensureRegistered(baseURL: baseURL)
        let bodyData: Data
        let forwardedBody: HTTPBody?
        if let body {
            bodyData = try await Data(collecting: body, upTo: .max)
            forwardedBody = HTTPBody(bodyData)
        } else {
            bodyData = Data()
            forwardedBody = nil
        }
        let challenge = try await serviceHTTP.challenge(
            keyID: keyID,
            baseURL: baseURL
        )
        let clientData = try SignedRequest.clientData(
            challenge: challenge.data,
            method: request.method.rawValue,
            pathAndQuery: request.path ?? "/",
            body: bodyData
        )
        let assertion = try await service.generateAssertion(
            keyID,
            Data(SHA256.hash(data: clientData))
        )

        var signedRequest = request
        signedRequest.headerFields[HTTPField.Name(AppAttestHeaders.keyID)!] = keyID
        signedRequest.headerFields[HTTPField.Name(AppAttestHeaders.challenge)!]
            = challenge.encoded
        signedRequest.headerFields[HTTPField.Name(AppAttestHeaders.assertion)!]
            = assertion.base64EncodedString()
        return try await serviceHTTP.base.send(
            signedRequest,
            body: forwardedBody,
            baseURL: baseURL,
            operationID: operationID
        )
    }

    func ensureRegistered(baseURL: URL) async throws -> String {
        guard service.isSupported() else {
            throw AppAttestDeviceError.unsupported
        }
        if let keyID = try await keyIDStore.read() {
            return keyID
        }

        let keyID: String
        if let pendingKeyID {
            keyID = pendingKeyID
        } else {
            keyID = try await service.generateKey()
            pendingKeyID = keyID
        }

        let challenge = try await serviceHTTP.challenge(
            keyID: keyID,
            baseURL: baseURL
        )
        let attestationObject = try await service.attestKey(
            keyID,
            Data(SHA256.hash(data: challenge.data))
        )
        try await serviceHTTP.attest(
            keyID: keyID,
            challenge: challenge.encoded,
            attestationObject: attestationObject,
            baseURL: baseURL
        )
        try await keyIDStore.write(keyID)
        pendingKeyID = nil
        return keyID
    }

    private func acquireSendGate() async {
        guard isSending else {
            isSending = true
            return
        }
        await withCheckedContinuation { sendWaiters.append($0) }
    }

    private func releaseSendGate() {
        guard !sendWaiters.isEmpty else {
            isSending = false
            return
        }
        sendWaiters.removeFirst().resume()
    }
}
