import Dependencies
import KeyChain

struct AppAttestKeyIDStore: Sendable {
    @Dependency(\.keychain) private var keychain

    func read() async throws -> String? {
        do {
            return try await keychain.readString(for: Self.query)
        } catch KeychainError.itemNotFound {
            return nil
        }
    }

    func write(_ keyID: String) async throws {
        try await keychain.upsert(keyID, for: Self.query)
    }

    func delete() async throws {
        try await keychain.delete(Self.query)
    }

    private static let query = KeychainQuery.genericPassword(
        account: "app-attest-key-id",
        service: "AppAttestDevice"
    )
}
