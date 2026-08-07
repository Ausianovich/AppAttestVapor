import Foundation
import Testing
@testable import AppAttestVapor

@Test
func parsesAttestationObject() throws {
    let authData = makeAttestationAuthenticatorData()
    let certificates: [[UInt8]] = [[0x30, 0x01], [0x30, 0x02]]
    let object = try AttestationObject.parse(
        Data(makeAttestationObject(authData: authData, certificates: certificates))
    )

    #expect(object.certificateChain == certificates.map { Data($0) })
    #expect(object.authenticatorData == Data(authData))
}

@Test
func parsesAssertionObject() throws {
    let authData = makeAssertionAuthenticatorData()
    let signature: [UInt8] = [0x30, 0x03, 0x01, 0x02, 0x03]
    let object = try AssertionObject.parse(
        Data(cborMap([
            ("signature", cborBytes(signature)),
            ("authenticatorData", cborBytes(authData)),
        ]))
    )

    #expect(object.signature == Data(signature))
    #expect(object.authenticatorData == Data(authData))
}

@Test
func parsesAttestationAuthenticatorData() throws {
    let data = try AuthenticatorData.parseAttestation(
        Data(makeAttestationAuthenticatorData(counter: 0x0102_0304))
    )

    #expect(data.rpIDHash == Data(repeating: 0x11, count: 32))
    #expect(data.flags == 0x41)
    #expect(data.counter == 0x0102_0304)
    #expect(data.attestedCredential?.aaguid == Data(repeating: 0x22, count: 16))
    #expect(data.attestedCredential?.credentialID == Data([0x31, 0x32, 0x33]))
    #expect(data.attestedCredential?.publicKey == Data(appleCOSEPublicKey))
}

@Test
func parsesVariableLengthCOSEPublicKey() throws {
    let publicKey = [0xB8, 0x05] + Array(appleCOSEPublicKey.dropFirst())
    let data = try AuthenticatorData.parseAttestation(
        Data(makeAttestationAuthenticatorData(publicKey: publicKey))
    )

    #expect(data.attestedCredential?.publicKey == Data(publicKey))
}

@Test
func parsesAssertionAuthenticatorData() throws {
    let data = try AuthenticatorData.parseAssertion(
        Data(makeAssertionAuthenticatorData(counter: 9))
    )

    #expect(data.rpIDHash == Data(repeating: 0x44, count: 32))
    #expect(data.flags == 0x01)
    #expect(data.counter == 9)
    #expect(data.attestedCredential == nil)
}

@Test
func parsesAppleAssertionWithoutUserPresenceFlag() throws {
    let data = try AuthenticatorData.parseAssertion(
        Data(makeAssertionAuthenticatorData(flags: 0x00, counter: 9))
    )

    #expect(data.flags == 0x00)
    #expect(data.counter == 9)
}

@Test
func parsesAttestationWithoutValidatingNonStructuralFlags() throws {
    let data = try AuthenticatorData.parseAttestation(
        Data(makeAttestationAuthenticatorData(flags: 0x44))
    )

    #expect(data.flags == 0x44)
}

@Test
func parsesAssertionWithoutValidatingNonStructuralFlags() throws {
    let data = try AuthenticatorData.parseAssertion(
        Data(makeAssertionAuthenticatorData(flags: 0x04))
    )

    #expect(data.flags == 0x04)
}

@Test
func acceptsWellFormedAuthenticatorExtensions() throws {
    let attestation = try AuthenticatorData.parseAttestation(
        Data(makeAttestationAuthenticatorData(flags: 0xC1) + [0xA0])
    )
    let assertion = try AuthenticatorData.parseAssertion(
        Data(makeAssertionAuthenticatorData(flags: 0x81) + [0xA0])
    )

    #expect(attestation.flags == 0xC1)
    #expect(assertion.flags == 0x81)
}

@Test
func parsesAppleAuthenticatorExtensionsWithoutEDFlag() throws {
    let extensions = cborMap([
        ("apple_bundle_version_01", cborText("1")),
        ("apple_validation_category_01", cborBytes([1, 0, 0, 0])),
    ])
    let data = try AuthenticatorData.parseAttestation(
        Data(makeAttestationAuthenticatorData(flags: 0x40) + extensions)
    )

    #expect(data.flags == 0x40)
}

@Test
func rejectsWrongAttestationFormat() {
    let bytes = makeAttestationObject(
        authData: makeAttestationAuthenticatorData(),
        format: "packed"
    )

    #expect(throws: AppAttestParsingError.invalidFormat) {
        try AttestationObject.parse(Data(bytes))
    }
}

@Test(arguments: ["attStmt", "x5c", "authData"])
func rejectsMissingAttestationField(field: String) {
    let bytes = makeAttestationObject(
        authData: makeAttestationAuthenticatorData(),
        omittedField: field
    )

    #expect(throws: AppAttestParsingError.missingField) {
        try AttestationObject.parse(Data(bytes))
    }
}

@Test(arguments: ["signature", "authenticatorData"])
func rejectsMissingAssertionField(field: String) {
    var fields = [
        ("signature", cborBytes([0x30, 0x00])),
        ("authenticatorData", cborBytes(makeAssertionAuthenticatorData())),
    ]
    fields.removeAll { $0.0 == field }

    #expect(throws: AppAttestParsingError.missingField) {
        try AssertionObject.parse(Data(cborMap(fields)))
    }
}

@Test
func rejectsTruncatedAuthenticatorData() {
    let truncated = makeAttestationAuthenticatorData().dropLast()

    #expect(throws: AppAttestParsingError.invalidAuthenticatorData) {
        try AuthenticatorData.parseAttestation(Data(truncated))
    }
}

@Test
func rejectsAttestedCredentialFlagMismatch() {
    #expect(throws: AppAttestParsingError.invalidAuthenticatorData) {
        try AuthenticatorData.parseAttestation(
            Data(makeAttestationAuthenticatorData(flags: 0x01))
        )
    }
    #expect(throws: AppAttestParsingError.invalidAuthenticatorData) {
        try AuthenticatorData.parseAssertion(
            Data(makeAssertionAuthenticatorData(flags: 0x40))
        )
    }
}

@Test
func rejectsMalformedAuthenticatorExtensions() {
    #expect(throws: AppAttestParsingError.invalidAuthenticatorData) {
        try AuthenticatorData.parseAttestation(
            Data(makeAttestationAuthenticatorData(flags: 0xC1) + [0xA1])
        )
    }
}

@Test
func rejectsTopLevelTrailingGarbage() {
    let attestation = makeAttestationObject(
        authData: makeAttestationAuthenticatorData()
    ) + [0x00]
    let assertion = cborMap([
        ("signature", cborBytes([0x30, 0x00])),
        ("authenticatorData", cborBytes(makeAssertionAuthenticatorData())),
    ]) + [0x00]

    #expect(throws: AppAttestParsingError.invalidCBOR) {
        try AttestationObject.parse(Data(attestation))
    }
    #expect(throws: AppAttestParsingError.invalidCBOR) {
        try AssertionObject.parse(Data(assertion))
    }
}

private let appleCOSEPublicKey: [UInt8] =
    [0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
    + [UInt8](repeating: 0x55, count: 32)
    + [0x22, 0x58, 0x20]
    + [UInt8](repeating: 0x66, count: 32)

private func makeAttestationAuthenticatorData(
    flags: UInt8 = 0x41,
    counter: UInt32 = 7,
    publicKey: [UInt8] = appleCOSEPublicKey
) -> [UInt8] {
    [UInt8](repeating: 0x11, count: 32)
        + [flags]
        + bigEndian(counter)
        + [UInt8](repeating: 0x22, count: 16)
        + [0x00, 0x03]
        + [0x31, 0x32, 0x33]
        + publicKey
}

private func makeAssertionAuthenticatorData(
    flags: UInt8 = 0x01,
    counter: UInt32 = 7
) -> [UInt8] {
    [UInt8](repeating: 0x44, count: 32) + [flags] + bigEndian(counter)
}

private func bigEndian(_ value: UInt32) -> [UInt8] {
    [
        UInt8(truncatingIfNeeded: value >> 24),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value),
    ]
}

private func makeAttestationObject(
    authData: [UInt8],
    certificates: [[UInt8]] = [[0x30, 0x01]],
    format: String = "apple-appattest",
    omittedField: String? = nil
) -> [UInt8] {
    var attestationStatement: [(String, [UInt8])] = [
        ("x5c", cborArray(certificates.map(cborBytes))),
        ("receipt", cborBytes([0x99])),
    ]
    if omittedField == "x5c" {
        attestationStatement.removeAll { $0.0 == "x5c" }
    }

    var fields: [(String, [UInt8])] = [
        ("fmt", cborText(format)),
        ("attStmt", cborMap(attestationStatement)),
        ("authData", cborBytes(authData)),
    ]
    fields.removeAll { $0.0 == omittedField }
    return cborMap(fields)
}

private func cborMap(_ fields: [(String, [UInt8])]) -> [UInt8] {
    [0xA0 + UInt8(fields.count)]
        + fields.flatMap { cborText($0.0) + $0.1 }
}

private func cborArray(_ values: [[UInt8]]) -> [UInt8] {
    [0x80 + UInt8(values.count)] + values.flatMap { $0 }
}

private func cborText(_ value: String) -> [UInt8] {
    let bytes = [UInt8](value.utf8)
    return switch bytes.count {
    case 0..<24:
        [0x60 + UInt8(bytes.count)] + bytes
    case 24...255:
        [0x78, UInt8(bytes.count)] + bytes
    default:
        [0x79, UInt8(bytes.count >> 8), UInt8(bytes.count)] + bytes
    }
}

private func cborBytes(_ value: [UInt8]) -> [UInt8] {
    switch value.count {
    case 0..<24:
        [0x40 + UInt8(value.count)] + value
    case 24...255:
        [0x58, UInt8(value.count)] + value
    default:
        [0x59, UInt8(value.count >> 8), UInt8(value.count)] + value
    }
}
