import Foundation
import CryptoKit
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
func parsesAppleValidationGuideAttestationObject() throws {
    let encoded = try #require(Data(
        base64Encoded: appleValidationGuideAttestationObject,
        options: .ignoreUnknownCharacters
    ))
    let object = try AttestationObject.parse(encoded)
    let authenticatorData = try AuthenticatorData.parseAttestation(
        object.authenticatorData
    )

    #expect(object.certificateChain.count == 2)
    #expect(object.authenticatorData.count == 226)
    #expect(authenticatorData.rpIDHash == Data(
        base64Encoded: "9EZtaPketsEGIMt+Y8coMkRoXuHWRntUFg51MXIFfwM="
    ))
    #expect(authenticatorData.flags == 0x40)
    #expect(authenticatorData.counter == 0)
    #expect(authenticatorData.attestedCredential?.aaguid ==
        Data("appattest".utf8) + Data(repeating: 0, count: 7))
    #expect(authenticatorData.attestedCredential?.credentialID == Data(
        base64Encoded: "zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0="
    ))
    #expect(authenticatorData.attestedCredential?.publicKey.count == 77)
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
func parsesAppleAssertionWithObservedFlag() throws {
    let data = try AuthenticatorData.parseAssertion(
        Data(makeAssertionAuthenticatorData(flags: 0x40, counter: 9))
    )

    #expect(data.flags == 0x40)
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
func rejectsAttestationWithoutAttestedCredentialFlag() {
    #expect(throws: AppAttestParsingError.invalidAuthenticatorData) {
        try AuthenticatorData.parseAttestation(
            Data(makeAttestationAuthenticatorData(flags: 0x01))
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

// Source: https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
private let appleValidationGuideAttestationObject = """
o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZBCEwggQdMIIDo6ADAgECAgYBnbE/C04wCgYIKoZIzj0EAwIwTzEj
MCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3Ju
aWEwHhcNMjYwNDIwMTgxMzEyWhcNMjYwNDIzMTgxMzEyWjCBkTFJMEcGA1UEAwxAY2UwNDk4ZjU4NDgzZmJiNGRhMGQ3YjJjNjNh
NWE1MzhmNTUyZDRhZGNiOWE0ZmE5MTYxOTVjNDk2MTNlNjU1ZDEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoM
CkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARDMlRKzzI9t3REPKrzOfVu
fpXHJPrCwUJZ82XiRFZQsrX7KFvPVJvLYFlEEudoKiQn7q2p+1Lf7QsasX7Qn6m9o4ICJjCCAiIwDAYDVR0TAQH/BAIwADAOBgNV
HQ8BAf8EBAMCBPAwFAYDVR0lBA0wCwYJKoZIhvdjZAQYMHoGCSqGSIb3Y2QIBQRtMGukAwIBCr+JMAMCAQC/iTEDAgEAv4kyAwIB
AL+JMwMCAQC/iTQeBBwxMjM0NTY3ODkwLmNvbS5leGFtcGxlLm15YXBwv4k2AwIBBL+JNwMCAQC/iTkDAgEAv4k6AwIBAL+JOwMC
AQCqAwIBADCB4AYJKoZIhvdjZAgHBIHSMIHPv4p4BgQEMjcuML+IUAMCAQK/inkJBAcxLjAuMjE2v4p7CQQHMjRBMzI1Yr+KfAYE
BDI3LjC/in0GBAQyNy4wv4p+AwIBAL+KfwMCAQC/iwADAgEAv4sBAwIBAL+LAgMCAQC/iwMDAgEAv4sEAwIBAb+LBQMCAQC/iwoQ
BA4yNC4xLjMyNS4wLjIsML+LCxAEDjI0LjEuMzI1LjAuMiwwv4sMEAQOMjQuMS4zMjUuMC4yLDC/iAIKBAhpcGhvbmVvc7+IBQoE
CEludGVybmFsMDMGCSqGSIb3Y2QIAgQmMCShIgQgh7fQbZOkKU5G8BHma2zEAPC6sgcpl2xhlYC0KuYL/24wWAYJKoZIhvdjZAgG
BEswSaNHBEUwQwwCMTEwPTAKDANva2ShAwEB/zAJDAJvYaEDAQH/MAsMBG9zZ26hAwEB/zALDARvZGVsoQMBAf8wCgwDb2NroQMB
Af8wCgYIKoZIzj0EAwIDaAAwZQIwIbzHaPbRKcm2sa4JvDWyTX40yz9U2byxFxTho+HIM0HeYwF3HLyA3Nrqv3WDy/UdAjEApOox
L7zeQV0yhvasPe31+c1ZYuEDxEU6rDrheFcVMRZepvV10+hFxgIWVMSpQu09WQJHMIICQzCCAcigAwIBAgIQCbrF4bxAGtnUU5W8
OBoIVDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUg
SW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM5NTVaFw0zMDAzMTMwMDAwMDBaME8xIzAhBgNVBAMMGkFwcGxl
IEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAErls3oHdNebI1j0Dn0fImJvHCX+8XgC3qs4JqWYdP+NKtFSV4mqJmBBkSSLY8uWcGnpjTY71eNw+/oI4ynoBz
qYXndG6jWaL2bynbMq9FXiEWWNVnr54mfrJhTcIaZs6Zo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFKyREFMz
vb5oQf+nDKnl+url5YqhMB0GA1UdDgQWBBQ+410cBBmpybQx+IR01uHhV3LjmzAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMD
aQAwZgIxALu+iI1zjQUCz7z9Zm0JV1A1vNaHLD+EMEkmKe3R+RToeZkcmui1rvjTqFQz97YNBgIxAKs47dDMge0ApFLDukT5k2Nl
U/7MKX8utN+fXr5aSsq2mVxLgg35BDhveAe7WJQ5t2dyZWNlaXB0WQ+JMIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQME
AgEFADCABgkqhkiG9w0BBwGggCSABIID6DGCBUEwJAIBAgIBAQQcMTIzNDU2Nzg5MC5jb20uZXhhbXBsZS5teWFwcDCCBCsCAQMC
AQEEggQhMIIEHTCCA6OgAwIBAgIGAZ2xPwtOMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBD
QSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI2MDQyMDE4MTMxMloXDTI2MDQyMzE4MTMx
MlowgZExSTBHBgNVBAMMQGNlMDQ5OGY1ODQ4M2ZiYjRkYTBkN2IyYzYzYTVhNTM4ZjU1MmQ0YWRjYjlhNGZhOTE2MTk1YzQ5NjEz
ZTY1NWQxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlh
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQzJUSs8yPbd0RDyq8zn1bn6VxyT6wsFCWfNl4kRWULK1+yhbz1Sby2BZRBLnaCok
J+6tqftS3+0LGrF+0J+pvaOCAiYwggIiMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QE
GDB6BgkqhkiG92NkCAUEbTBrpAMCAQq/iTADAgEAv4kxAwIBAL+JMgMCAQC/iTMDAgEAv4k0HgQcMTIzNDU2Nzg5MC5jb20uZXhh
bXBsZS5teWFwcL+JNgMCAQS/iTcDAgEAv4k5AwIBAL+JOgMCAQC/iTsDAgEAqgMCAQAwgeAGCSqGSIb3Y2QIBwSB0jCBz7+KeAYE
BDI3LjC/iFADAgECv4p5CQQHMS4wLjIxNr+KewkEBzI0QTMyNWK/inwGBAQyNy4wv4p9BgQEMjcuML+KfgMCAQC/in8DAgEAv4sA
AwIBAL+LAQMCAQC/iwIDAgEAv4sDAwIBAL+LBAMCAQG/iwUDAgEAv4sKEAQOMjQuMS4zMjUuMC4yLDC/iwsQBA4yNC4xLjMyNS4w
LjIsML+LDBAEDjI0LjEuMzI1LjAuMiwwv4gCCgQIaXBob25lb3O/iAUKBAhJbnRlcm5hbDAzBgkqhkiG92NkCAIEJjAkoSIEIIe3
0G2TpClORvAR5mtsxADwurIHKZdsYZWAtCrmC/9uMFgGCSqGSIb3Y2QIBgRLMEmjRwRFMEMMAjExMD0wCgwDb2tkoQMBAf8wCQwC
b2GhAwEB/zALDARvc2duoQMBAf8wCwwEb2RlbKEDAQH/MAoMA29ja6EDAQH/MAoGCCoEggFdhkjOPQQDAgNoADBlAjAhvMdo9tEp
ybaxrgm8NbJNfjTLP1TZvLEXFOGj4cgzQd5jAXccvIDc2uq/dYPL9R0CMQCk6jEvvN5BXTKG9qw97fX5zVli4QPERTqsOuF4VxUx
Fl6m9XXT6EXGAhZUxKlC7T0wIAIBBAIBAQQYZXhhbXBsZV9zZXJ2ZXJfY2hhbGxlbmdlMGACAQUCAQEEWHJia3RNcTg5bXZEcFJD
Sy84bGNQaGRMNGRXUXo5T1hJd0hHZGU1eFFmU3VJS3NOM09qT1dGOHUrdjBVQTRxOHZqQ1JnRUVKVGxjOUJ3aUl6TlNOT0hRPT0w
DgIBBgIBAQQGQVRURVNUMBICAQcCAQEECnByb2R1Y3Rpb24wIAIBDAIBAQQYMjAyNi0wNC0yMVQxODoxMzoxMi4xNTNaMCACARUC
AQEEGDIwMjYtMDctMjBUMTg6MTM6MTIuMTUzWgAAAAAAAKCAMIIDrjCCA1SgAwIBAgIQZgI4gAAUJvddiw4VLF9uQzAKBggqhkjO
PQQDAjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENl
cnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yNjAxMjAyMDIxMDlaFw0y
NzAyMTgxODU4MzlaMFoxNjA0BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9uIEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEG
A1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ7GK7OxRmtilNRtEBEtKMDmVe0
zb1bhR/gGm/t4o3vsPqww2oCpB9EbgBtWA5WimeAiQfzSICRQ4sgzqpMndxWo4IB2DCCAdQwDAYDVR0TAQH/BAIwADAfBgNVHSME
GDAWgBTZF/5LZ5A4S5L0287VV4AUC489yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLmFwcGxlLmNv
bS9vY3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEPMIIBCwYJKoZIhvdjZAUBMIH9MIHDBggrBgEFBQcCAjCBtgyBs1Jl
bGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBs
aWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1
dGhvcml0eTAdBgNVHQ4EFgQUNFWJcHRgDiLSumfPpVtpwiPxyigwDgYDVR0PAQH/BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAwCgYI
KoZIzj0EAwIDSAAwRQIgHGeXuYJF0dbccgS3mwI8r/h78u/4k33XIMReiuRlwusCIQD8yFmEzsmhLMKGqdSSdv3w0vYl3HX8fPiH
RWl75h6qtDCCAvkwggJ/oAMCAQICEFb7g9Qr/43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBD
QSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UE
BhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAwMDAwWjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3Jh
dGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMu
MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7HOGv+wSUgJGs9jHfpssoNW9ES+Eh5Vfd
Eo2NuoJ8lb5J+r4zyq7NBBnxL0Ml+vS+s8uDfrqjgfcwgfQwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBS7sN6hWDOImqSK
md6+veuv2sskqzBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVy
b290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWczLmNybDAdBgNVHQ4EFgQU
2Rf+S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCN
b6afoeDk7FtOc4qSfz14U5iP9NofWB7DdUr+OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw
4WG+gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F/IjSxUuVMAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxl
IFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4x
CzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4MTkwNloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEcz
MSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHFo05x3BQW2Q7lpgUqd2R7X04407scRLV/9R+2MmJdyemE
W08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc7SudeyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6+veuv
2sskqzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg+nBxBZeGl00GNnt7/RsDgBG
S7jfskYRxQ/95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E/NjUM+tIpjpTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgY
A+eisigAADGB/TCB+gIBATCBkDB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAk
BgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUwIQZgI4
gAAUJvddiw4VLF9uQzANBglghkgBZQMEAgEFADAKBggqhkjOPQQDAgRHMEUCIFp+GIuJm5vqJhLtDX40gGP90KJtLoPyzcLEuKHY
Mr9zAiEAgPafgwU16p2N6GvCC3Gj4BAb66R38+IP+Arn3QYbD9QAAAAAAABoYXV0aERhdGFY4vRGbWj5HrbBBiDLfmPHKDJEaF7h
1kZ7VBYOdTFyBX8DQAAAAABhcHBhdHRlc3QAAAAAAAAAACDOBJj1hIP7tNoNeyxjpaU49VLUrcuaT6kWGVxJYT5lXaUBAgMmIAEh
WCBDMlRKzzI9t3REPKrzOfVufpXHJPrCwUJZ82XiRFZQsiJYILX7KFvPVJvLYFlEEudoKiQn7q2p+1Lf7QsasX7Qn6m9ondhcHBs
ZV9idW5kbGVfdmVyc2lvbl8wMWExeBxhcHBsZV92YWxpZGF0aW9uX2NhdGVnb3J5XzAxRAEAAAA=
"""

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
