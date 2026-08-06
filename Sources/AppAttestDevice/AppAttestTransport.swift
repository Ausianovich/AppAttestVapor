import CryptoKit
import Dependencies
import Foundation
import OpenAPIRuntime

public actor AppAttestTransport<Base: ClientTransport> {
    private let serviceHTTP: AppAttestServiceHTTP<Base>
    private let keyIDStore = AppAttestKeyIDStore()
    private var pendingKeyID: String?

    @Dependency(\.appAttestService) private var service

    public init(base: Base, routePrefix: String = "/app-attest") {
        serviceHTTP = AppAttestServiceHTTP(
            base: base,
            routePrefix: routePrefix
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
}
