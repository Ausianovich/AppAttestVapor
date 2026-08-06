import Crypto
import Foundation
import Testing
import X509
@testable import AppAttestVapor

@Test
func validatesCertificateChainAndAppleNonce() async throws {
    let verifier = try AppAttestCertificateVerifier(
        rootCertificate: fixture("AttestationTestRoot.pem")
    )

    let result = try await verifier.verify(
        certificateChain: [
            fixture("AttestationTestLeaf.der"),
            fixture("AttestationTestIntermediate.der"),
        ],
        expectedNonce: Data(repeating: 0xAB, count: 32)
    )

    #expect(result.publicKeyX963.count == 65)
    #expect(result.publicKeyX963 == Data(result.publicKey.x963Representation))
}

@Test
func rejectsUntrustedCertificateChain() async throws {
    let verifier = try AppAttestCertificateVerifier(
        rootCertificate: fixture("AttestationTestRoot.pem")
    )

    await #expect(throws: AppAttestCertificateError.self) {
        try await verifier.verify(
            certificateChain: [fixture("AttestationTestLeaf.der")],
            expectedNonce: Data(repeating: 0xAB, count: 32)
        )
    }
}

@Test
func rejectsWrongNonce() async throws {
    let verifier = try AppAttestCertificateVerifier(
        rootCertificate: fixture("AttestationTestRoot.pem")
    )

    await #expect(throws: AppAttestCertificateError.self) {
        try await verifier.verify(
            certificateChain: [
                fixture("AttestationTestLeaf.der"),
                fixture("AttestationTestIntermediate.der"),
            ],
            expectedNonce: Data(repeating: 0x00, count: 32)
        )
    }
}

@Test(arguments: [
    ([1, 2, 3], validNonceDER),
    (AppAttestNonceExtension.oid, replacing(validNonceDER, at: 2, with: 0xA2)),
    (AppAttestNonceExtension.oid, replacing(validNonceDER, at: 1, with: 0x23)),
    (AppAttestNonceExtension.oid, validNonceDER + [0x00]),
])
func rejectsMalformedNonceExtension(oid: [UInt], value: [UInt8]) {
    #expect(throws: AppAttestCertificateError.self) {
        try AppAttestNonceExtension.parse(oid: oid, value: value)
    }
}

@Test
func pinsAppleRootCertificate() throws {
    let pem = try AppAttestCertificateVerifier.appleRootCertificateData()
    let base64 = String(decoding: pem, as: UTF8.self)
        .components(separatedBy: .newlines)
        .filter { !$0.hasPrefix("-----") }
        .joined()
    let der = try #require(Data(base64Encoded: base64))
    let digest = SHA256.hash(
        data: der
    )

    #expect(
        digest.map { String(format: "%02x", $0) }.joined()
            == "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"
    )
}

private let validNonceDER =
    [0x30, 0x24, 0xA1, 0x22, 0x04, 0x20]
    + [UInt8](repeating: 0xAB, count: 32)

private func replacing(_ bytes: [UInt8], at index: Int, with byte: UInt8) -> [UInt8] {
    var bytes = bytes
    bytes[index] = byte
    return bytes
}

private func fixture(_ name: String) throws -> Data {
    let url = try #require(
        Bundle.module.url(
            forResource: name,
            withExtension: nil,
            subdirectory: "Fixtures"
        )
    )
    return try Data(contentsOf: url)
}
