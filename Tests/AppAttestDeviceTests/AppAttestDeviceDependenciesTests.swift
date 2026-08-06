import Dependencies
import Foundation
import KeyChain
import LocalAuthentication
import Testing
@testable import AppAttestDevice

@Test
func appAttestServiceReportsSupport() {
    let supported = withDependencies {
        $0.appAttestService = testAppAttestService(isSupported: { false })
    } operation: {
        @Dependency(\.appAttestService) var service
        return service.isSupported()
    }

    #expect(!supported)
}

@Test
func appAttestServiceGeneratesKey() async throws {
    let keyID = try await withDependencies {
        $0.appAttestService = testAppAttestService(generateKey: { "key-id" })
    } operation: {
        @Dependency(\.appAttestService) var service
        return try await service.generateKey()
    }

    #expect(keyID == "key-id")
}

@Test
func appAttestServiceAttestsKey() async throws {
    let recorder = DeviceServiceRecorder()
    let hash = Data(repeating: 1, count: 32)
    let attestation = try await withDependencies {
        $0.appAttestService = testAppAttestService(
            attestKey: { keyID, clientDataHash in
                await recorder.record(keyID: keyID, hash: clientDataHash)
                return Data([2])
            }
        )
    } operation: {
        @Dependency(\.appAttestService) var service
        return try await service.attestKey("key-id", hash)
    }

    #expect(attestation == Data([2]))
    #expect(await recorder.arguments == .init(keyID: "key-id", hash: hash))
}

@Test
func appAttestServiceGeneratesAssertion() async throws {
    let recorder = DeviceServiceRecorder()
    let hash = Data(repeating: 3, count: 32)
    let assertion = try await withDependencies {
        $0.appAttestService = testAppAttestService(
            generateAssertion: { keyID, clientDataHash in
                await recorder.record(keyID: keyID, hash: clientDataHash)
                return Data([4])
            }
        )
    } operation: {
        @Dependency(\.appAttestService) var service
        return try await service.generateAssertion("key-id", hash)
    }

    #expect(assertion == Data([4]))
    #expect(await recorder.arguments == .init(keyID: "key-id", hash: hash))
}

@Test
func keyIDStoreReadsStoredKeyID() async throws {
    let recorder = KeychainRecorder()
    let keyID = try await withDependencies {
        $0.keychain = testKeychain(
            read: { query, _, _ in
                await recorder.recordRead(query)
                return Data("stored-key-id".utf8)
            }
        )
    } operation: {
        try await AppAttestKeyIDStore().read()
    }

    #expect(keyID == "stored-key-id")
    #expect(await recorder.readQuery == expectedKeyIDQuery)
}

@Test
func keyIDStoreMapsItemNotFoundToNil() async throws {
    let keyID = try await withDependencies {
        $0.keychain = testKeychain(
            read: { _, _, _ in throw KeychainError.itemNotFound }
        )
    } operation: {
        try await AppAttestKeyIDStore().read()
    }

    #expect(keyID == nil)
}

@Test
func keyIDStorePreservesOtherReadErrors() async {
    await #expect(throws: KeychainError.authenticationFailed) {
        try await withDependencies {
            $0.keychain = testKeychain(
                read: { _, _, _ in throw KeychainError.authenticationFailed }
            )
        } operation: {
            try await AppAttestKeyIDStore().read()
        }
    }
}

@Test
func keyIDStoreWritesKeyID() async throws {
    let recorder = KeychainRecorder()

    try await withDependencies {
        $0.keychain = testKeychain(
            upsert: { data, query in
                await recorder.recordWrite(data: data, query: query)
            }
        )
    } operation: {
        try await AppAttestKeyIDStore().write("new-key-id")
    }

    #expect(await recorder.writtenData == Data("new-key-id".utf8))
    #expect(await recorder.writeQuery == expectedKeyIDQuery)
}

@Test
func keyIDStoreDeletesKeyID() async throws {
    let recorder = KeychainRecorder()

    try await withDependencies {
        $0.keychain = testKeychain(
            delete: { query in await recorder.recordDelete(query) }
        )
    } operation: {
        try await AppAttestKeyIDStore().delete()
    }

    #expect(await recorder.deleteQuery == expectedKeyIDQuery)
}

private let expectedKeyIDQuery = KeychainQuery.genericPassword(
    account: "app-attest-key-id",
    service: "AppAttestDevice"
)

private struct DeviceServiceArguments: Equatable, Sendable {
    let keyID: String
    let hash: Data
}

private actor DeviceServiceRecorder {
    private(set) var arguments: DeviceServiceArguments?

    func record(keyID: String, hash: Data) {
        arguments = DeviceServiceArguments(keyID: keyID, hash: hash)
    }
}

private actor KeychainRecorder {
    private(set) var readQuery: KeychainQuery?
    private(set) var writtenData: Data?
    private(set) var writeQuery: KeychainQuery?
    private(set) var deleteQuery: KeychainQuery?

    func recordRead(_ query: KeychainQuery) {
        readQuery = query
    }

    func recordWrite(data: Data, query: KeychainQuery) {
        writtenData = data
        writeQuery = query
    }

    func recordDelete(_ query: KeychainQuery) {
        deleteQuery = query
    }
}

private func testAppAttestService(
    isSupported: @escaping @Sendable () -> Bool = { true },
    generateKey: @escaping @Sendable () async throws -> String = { "unused" },
    attestKey: @escaping @Sendable (String, Data) async throws -> Data = { _, _ in Data() },
    generateAssertion: @escaping @Sendable (String, Data) async throws -> Data = { _, _ in Data() }
) -> AppAttestServiceClient {
    AppAttestServiceClient(
        isSupported: isSupported,
        generateKey: generateKey,
        attestKey: attestKey,
        generateAssertion: generateAssertion
    )
}

private func testKeychain(
    upsert: @escaping @Sendable (Data, KeychainQuery) async throws -> Void = { _, _ in },
    read: @escaping @Sendable (KeychainQuery, String?, sending LAContext?) async throws -> Data = {
        _, _, _ in throw KeychainError.itemNotFound
    },
    delete: @escaping @Sendable (KeychainQuery) async throws -> Void = { _ in }
) -> KeychainClient {
    KeychainClient(upsert: upsert, read: read, delete: delete)
}
