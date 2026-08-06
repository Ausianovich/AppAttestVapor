import Foundation
import Testing
@testable import AppAttestVapor

@Test
func verifiesValidAttestation() async throws {
    let result = try await testVerifier().verify(
        attestationObject: fixture("valid-attestation.cbor"),
        keyID: validKeyID,
        challenge: validChallenge
    )

    #expect(result.publicKey == validPublicKey)
    #expect(result.initialCounter == 0)
}

@Test
func rejectsUntrustedAttestationCertificateChain() async throws {
    let verifier = try AppAttestationVerifier(
        configuration: configuration,
        certificateVerifier: AppAttestCertificateVerifier()
    )

    await #expect(throws: AppAttestationError.invalidAttestation) {
        try await verifier.verify(
            attestationObject: fixture("valid-attestation.cbor"),
            keyID: validKeyID,
            challenge: validChallenge
        )
    }
}

@Test
func rejectsAttestationNonceMismatch() async throws {
    await #expect(throws: AppAttestationError.invalidAttestation) {
        try await testVerifier().verify(
            attestationObject: fixture("valid-attestation.cbor"),
            keyID: validKeyID,
            challenge: Data(repeating: 0xFF, count: 32)
        )
    }
}

@Test
func rejectsPublicKeyHashMismatch() throws {
    var publicKey = validPublicKey
    publicKey[1] ^= 0xFF

    #expect(throws: AppAttestationError.invalidAttestation) {
        try AppAttestationVerifier.validate(
            authenticatorData: validAuthenticatorData(),
            keyID: validKeyID,
            publicKey: publicKey,
            configuration: configuration
        )
    }
}

@Test
func rejectsRPIDMismatch() throws {
    let data = try replacing(
        validAuthenticatorData(),
        rpIDHash: Data(repeating: 0x00, count: 32)
    )

    #expect(throws: AppAttestationError.invalidAttestation) {
        try AppAttestationVerifier.validate(
            authenticatorData: data,
            keyID: validKeyID,
            publicKey: validPublicKey,
            configuration: configuration
        )
    }
}

@Test
func rejectsNonzeroInitialCounter() throws {
    let data = try replacing(validAuthenticatorData(), counter: 1)

    #expect(throws: AppAttestationError.invalidAttestation) {
        try AppAttestationVerifier.validate(
            authenticatorData: data,
            keyID: validKeyID,
            publicKey: validPublicKey,
            configuration: configuration
        )
    }
}

@Test
func rejectsEnvironmentAAGUIDMismatch() throws {
    #expect(throws: AppAttestationError.invalidAttestation) {
        try AppAttestationVerifier.validate(
            authenticatorData: validAuthenticatorData(),
            keyID: validKeyID,
            publicKey: validPublicKey,
            configuration: AppAttestConfiguration(
                teamID: "TESTTEAMID",
                bundleID: "com.example.app",
                environment: .production
            )
        )
    }
}

@Test
func rejectsCredentialIDMismatch() throws {
    let data = try replacing(
        validAuthenticatorData(),
        credentialID: Data(repeating: 0x00, count: 32)
    )

    #expect(throws: AppAttestationError.invalidAttestation) {
        try AppAttestationVerifier.validate(
            authenticatorData: data,
            keyID: validKeyID,
            publicKey: validPublicKey,
            configuration: configuration
        )
    }
}

private let configuration = AppAttestConfiguration(
    teamID: "TESTTEAMID",
    bundleID: "com.example.app",
    environment: .development
)

private let validKeyID = Data(
    base64Encoded: "IY3ms15eBehq6vIUoONV8+9dzuxS4gabPUPIWwk0Qog="
)!

private let validChallenge = Data(
    base64Encoded: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
)!

private let validPublicKey = Data(
    base64Encoded: "BFFxT4DZ6+qPnvA7Y6TtJat0OCPTOWyb0l83K6xtNNpSMSXsMqvCXbT6+PGJYcaAcSfxPUI5/SjHF4DmlrVnjJs="
)!

private func testVerifier() throws -> AppAttestationVerifier {
    try AppAttestationVerifier(
        configuration: configuration,
        certificateVerifier: AppAttestCertificateVerifier(
            rootCertificate: fixture("AttestationTestRoot.pem")
        )
    )
}

private func validAuthenticatorData() throws -> AuthenticatorData {
    try AuthenticatorData.parseAttestation(
        AttestationObject.parse(fixture("valid-attestation.cbor")).authenticatorData
    )
}

private func replacing(
    _ data: AuthenticatorData,
    rpIDHash: Data? = nil,
    counter: UInt32? = nil,
    credentialID: Data? = nil
) throws -> AuthenticatorData {
    let credential = try #require(data.attestedCredential)
    return AuthenticatorData(
        rpIDHash: rpIDHash ?? data.rpIDHash,
        flags: data.flags,
        counter: counter ?? data.counter,
        attestedCredential: .init(
            aaguid: credential.aaguid,
            credentialID: credentialID ?? credential.credentialID,
            publicKey: credential.publicKey
        )
    )
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
