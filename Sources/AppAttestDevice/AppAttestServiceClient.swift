import Dependencies
import DeviceCheck
import Foundation

struct AppAttestServiceClient: Sendable {
    var isSupported: @Sendable () -> Bool
    var generateKey: @Sendable () async throws -> String
    var attestKey: @Sendable (String, Data) async throws -> Data
    var generateAssertion: @Sendable (String, Data) async throws -> Data
}

extension AppAttestServiceClient: DependencyKey {
    static var liveValue: Self {
        Self(
            isSupported: { DCAppAttestService.shared.isSupported },
            generateKey: { try await DCAppAttestService.shared.generateKey() },
            attestKey: { keyID, clientDataHash in
                try await DCAppAttestService.shared.attestKey(
                    keyID,
                    clientDataHash: clientDataHash
                )
            },
            generateAssertion: { keyID, clientDataHash in
                try await DCAppAttestService.shared.generateAssertion(
                    keyID,
                    clientDataHash: clientDataHash
                )
            }
        )
    }
}

extension DependencyValues {
    var appAttestService: AppAttestServiceClient {
        get { self[AppAttestServiceClient.self] }
        set { self[AppAttestServiceClient.self] = newValue }
    }
}
