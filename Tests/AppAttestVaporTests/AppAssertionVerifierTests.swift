import Crypto
import Foundation
import Testing
@testable import AppAttestVapor

@Test
func verifiesValidAssertionAndReturnsNewCounter() throws {
    let counter = try verifier.verify(
        assertionObject: makeAssertion(counter: 5),
        publicKey: fixedPrivateKey.publicKey.x963Representation,
        clientData: clientData,
        storedCounter: 4
    )

    #expect(counter == 5)
}

@Test
func rejectsMalformedAssertionCBOR() {
    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: Data([0xFF]),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 4
        )
    }
}

@Test
func logsMalformedAssertionStage() {
    let logs = TestLogRecorder()
    let verifier = AppAssertionVerifier(
        configuration: assertionConfiguration,
        logger: logs.logger
    )

    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: Data([0xFF]),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 4
        )
    }
    #expect(
        logs.entries.contains {
            $0.level == .error
                && $0.metadata["stage"] == "assertion-object"
        }
    )
}

@Test
func rejectsMalformedDERSignature() throws {
    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: makeAssertion(
                counter: 5,
                signature: Data([0x30, 0x00])
            ),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 4
        )
    }
}

@Test
func rejectsWrongAssertionSignature() throws {
    let signature = try fixedPrivateKey.signature(
        for: SHA256.hash(data: Data("wrong nonce".utf8))
    ).derRepresentation

    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: makeAssertion(counter: 5, signature: signature),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 4
        )
    }
}

@Test
func rejectsAssertionRPIDMismatch() throws {
    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: makeAssertion(
                rpIDHash: Data(repeating: 0, count: 32),
                counter: 5
            ),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 4
        )
    }
}

@Test
func rejectsZeroAssertionCounter() throws {
    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: makeAssertion(counter: 0),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 0
        )
    }
}

@Test
func rejectsAssertionCounterNotGreaterThanStoredValue() throws {
    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: makeAssertion(counter: 5),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 5
        )
    }
}

private let assertionConfiguration = AppAttestConfiguration(
    teamID: "TESTTEAMID",
    bundleID: "com.example.app",
    environment: .development
)

private let verifier = AppAssertionVerifier(configuration: assertionConfiguration)
private let clientData = Data("fixed-client-data".utf8)
private let fixedPrivateKey = try! P256.Signing.PrivateKey(
    rawRepresentation: Data(repeating: 0, count: 31) + Data([1])
)

private func makeAssertion(
    rpIDHash: Data = Data(SHA256.hash(data: Data("TESTTEAMID.com.example.app".utf8))),
    counter: UInt32,
    signature: Data? = nil
) throws -> Data {
    var authenticatorData = rpIDHash
    authenticatorData.append(0x01)
    authenticatorData.append(contentsOf: [
        UInt8(truncatingIfNeeded: counter >> 24),
        UInt8(truncatingIfNeeded: counter >> 16),
        UInt8(truncatingIfNeeded: counter >> 8),
        UInt8(truncatingIfNeeded: counter),
    ])

    var nonceInput = authenticatorData
    nonceInput.append(contentsOf: SHA256.hash(data: clientData))
    let signature = try signature ?? fixedPrivateKey.signature(
        for: SHA256.hash(data: nonceInput)
    ).derRepresentation

    return Data(
        [0xA2]
            + cborText("signature")
            + cborBytes(signature)
            + cborText("authenticatorData")
            + cborBytes(authenticatorData)
    )
}

private func cborText(_ value: String) -> [UInt8] {
    let bytes = Array(value.utf8)
    return cborLength(major: 0x60, count: bytes.count) + bytes
}

private func cborBytes(_ value: Data) -> [UInt8] {
    cborLength(major: 0x40, count: value.count) + value
}

private func cborLength(major: UInt8, count: Int) -> [UInt8] {
    count < 24
        ? [major | UInt8(count)]
        : [major | 0x18, UInt8(count)]
}
