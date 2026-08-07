import AppAttestCore
import CryptoKit
import Dependencies
import Foundation
import HTTPTypes
import OSLog
import OpenAPIRuntime

private let appAttestLogger = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "AppAttestDevice",
    category: "validation"
)

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

        var stage: String?
        do {
            var keyID = try await ensureRegistered(baseURL: baseURL)
            stage = "request-body"
            let bodyData: Data
            let hasBody: Bool
            if let body {
                bodyData = try await Data(collecting: body, upTo: .max)
                hasBody = true
            } else {
                bodyData = Data()
                hasBody = false
            }
            var retriesRemaining = 1

            while true {
                stage = "challenge"
                let challenge = try await serviceHTTP.challenge(
                    keyID: keyID,
                    baseURL: baseURL
                )
                appAttestLogger.debug("App Attest request challenge received")
                stage = "client-data"
                let clientData = try SignedRequest.clientData(
                    challenge: challenge.data,
                    method: request.method.rawValue,
                    pathAndQuery: request.path ?? "/",
                    body: bodyData
                )
                stage = "assertion"
                let assertion = try await service.generateAssertion(
                    keyID,
                    Data(SHA256.hash(data: clientData))
                )
                appAttestLogger.debug("App Attest assertion generated")

                var signedRequest = request
                signedRequest.headerFields[HTTPField.Name(AppAttestHeaders.keyID)!]
                    = keyID
                signedRequest.headerFields[HTTPField.Name(AppAttestHeaders.challenge)!]
                    = challenge.encoded
                signedRequest.headerFields[HTTPField.Name(AppAttestHeaders.assertion)!]
                    = assertion.base64EncodedString()
                stage = "transport"
                let (response, responseBody) = try await serviceHTTP.base.send(
                    signedRequest,
                    body: hasBody ? HTTPBody(bodyData) : nil,
                    baseURL: baseURL,
                    operationID: operationID
                )
                stage = "response"
                let inspected = try await serviceHTTP.inspect(
                    response: response,
                    body: responseBody
                )
                guard retriesRemaining > 0, let recovery = inspected.recovery else {
                    appAttestLogger.debug("App Attest protected request completed")
                    return (response, inspected.body)
                }
                retriesRemaining -= 1
                appAttestLogger.debug(
                    "App Attest recovery started: \(String(describing: recovery), privacy: .public)"
                )

                if recovery == .credentialMissing {
                    stage = "keychain-delete"
                    try await keyIDStore.delete()
                    pendingKeyID = nil
                }
                stage = nil
                keyID = try await ensureRegistered(baseURL: baseURL)
            }
        } catch {
            if let stage {
                let errorType = String(reflecting: type(of: error))
                appAttestLogger.error(
                    "App Attest protected request failed at \(stage, privacy: .public): \(errorType, privacy: .public)"
                )
            }
            throw error
        }
    }

    func ensureRegistered(baseURL: URL) async throws -> String {
        var stage = "support"
        do {
            guard service.isSupported() else {
                throw AppAttestDeviceError.unsupported
            }
            stage = "keychain-read"
            if let keyID = try await keyIDStore.read() {
                appAttestLogger.debug("App Attest credential loaded")
                return keyID
            }

            let keyID: String
            if let pendingKeyID {
                keyID = pendingKeyID
            } else {
                stage = "key-generation"
                keyID = try await service.generateKey()
                pendingKeyID = keyID
                appAttestLogger.debug("App Attest key generated")
            }

            stage = "registration-challenge"
            let challenge = try await serviceHTTP.challenge(
                keyID: keyID,
                baseURL: baseURL
            )
            appAttestLogger.debug("App Attest registration challenge received")
            stage = "apple-attestation"
            let attestationObject = try await service.attestKey(
                keyID,
                Data(SHA256.hash(data: challenge.data))
            )
            appAttestLogger.debug("App Attest attestation generated")
            stage = "server-attestation"
            try await serviceHTTP.attest(
                keyID: keyID,
                challenge: challenge.encoded,
                attestationObject: attestationObject,
                baseURL: baseURL
            )
            stage = "keychain-write"
            try await keyIDStore.write(keyID)
            pendingKeyID = nil
            appAttestLogger.debug("App Attest registration completed")
            return keyID
        } catch {
            let errorType = String(reflecting: type(of: error))
            appAttestLogger.error(
                "App Attest registration failed at \(stage, privacy: .public): \(errorType, privacy: .public)"
            )
            throw error
        }
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
