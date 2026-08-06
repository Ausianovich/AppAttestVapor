import Dependencies
import Foundation

public enum AppAttestCredentialError: Error, Equatable {
    case unavailable
}

public struct AppAttestCredentialClient: Sendable {
    /// Inserts a credential. The implementation must not overwrite an existing credential.
    public var saveCredential: @Sendable (String, Data, UInt32) async throws -> Void
    public var getPublicKey: @Sendable (String) async throws -> Data?
    public var getCounter: @Sendable (String) async throws -> UInt32?
    /// Atomically succeeds only when `newValue` is greater than the stored value.
    public var advanceCounter: @Sendable (String, UInt32) async throws -> Bool

    public init(
        saveCredential: @escaping @Sendable (String, Data, UInt32) async throws -> Void,
        getPublicKey: @escaping @Sendable (String) async throws -> Data?,
        getCounter: @escaping @Sendable (String) async throws -> UInt32?,
        advanceCounter: @escaping @Sendable (String, UInt32) async throws -> Bool
    ) {
        self.saveCredential = saveCredential
        self.getPublicKey = getPublicKey
        self.getCounter = getCounter
        self.advanceCounter = advanceCounter
    }
}

extension AppAttestCredentialClient: DependencyKey {
    public static let liveValue = Self(
        saveCredential: { _, _, _ in throw AppAttestCredentialError.unavailable },
        getPublicKey: { _ in throw AppAttestCredentialError.unavailable },
        getCounter: { _ in throw AppAttestCredentialError.unavailable },
        advanceCounter: { _, _ in throw AppAttestCredentialError.unavailable }
    )
}

extension DependencyValues {
    public var appAttestCredential: AppAttestCredentialClient {
        get { self[AppAttestCredentialClient.self] }
        set { self[AppAttestCredentialClient.self] = newValue }
    }
}
