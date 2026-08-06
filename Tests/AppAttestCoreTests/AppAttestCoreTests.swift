import Foundation
import Testing

@testable import AppAttestCore

@Test
func headersUseExactWireNames() {
    #expect(AppAttestHeaders.keyID == "X-App-Attest-Key-ID")
    #expect(AppAttestHeaders.challenge == "X-App-Attest-Challenge")
    #expect(AppAttestHeaders.assertion == "X-App-Attest-Assertion")
}

@Test
func payloadsUseExactWireKeys() throws {
    #expect(
        try encodedObject(AppAttestChallengeRequest(keyID: "key"))
            == ["keyID": "key"]
    )
    #expect(
        try encodedObject(AppAttestChallengeResponse(challenge: "challenge"))
            == ["challenge": "challenge"]
    )
    #expect(
        try encodedObject(
            AppAttestAttestationRequest(
                keyID: "key",
                challenge: "challenge",
                attestationObject: "attestation"
            )
        )
            == [
                "keyID": "key",
                "challenge": "challenge",
                "attestationObject": "attestation",
            ]
    )
    #expect(
        try encodedObject(AppAttestErrorResponse(code: "code"))
            == ["code": "code"]
    )
}

@Test
func clientDataMatchesNonEmptyBodyGoldenVector() throws {
    let expected = Data([
        0x01,
        0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb,
        0x00, 0x00, 0x00, 0x04, 0x50, 0x4f, 0x53, 0x54,
        0x00, 0x00, 0x00, 0x0f,
        0x2f, 0x76, 0x31, 0x2f, 0x69, 0x74, 0x65, 0x6d,
        0x73, 0x3f, 0x71, 0x3d, 0x25, 0x32, 0x46,
        0x44, 0x13, 0x6f, 0xa3, 0x55, 0xb3, 0x67, 0x8a,
        0x11, 0x46, 0xad, 0x16, 0xf7, 0xe8, 0x64, 0x9e,
        0x94, 0xfb, 0x4f, 0xc2, 0x1f, 0xe7, 0x7e, 0x83,
        0x10, 0xc0, 0x60, 0xf6, 0x1c, 0xaa, 0xff, 0x8a,
    ])

    let clientData = try SignedRequest.clientData(
        challenge: Data([0xaa, 0xbb]),
        method: "POST",
        pathAndQuery: "/v1/items?q=%2F",
        body: Data("{}".utf8)
    )

    #expect(clientData == expected)
}

@Test
func clientDataMatchesEmptyBodyGoldenVector() throws {
    let expected = Data([
        0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, 0x47, 0x45, 0x54,
        0x00, 0x00, 0x00, 0x01, 0x2f,
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ])

    let clientData = try SignedRequest.clientData(
        challenge: Data(),
        method: "GET",
        pathAndQuery: "/",
        body: Data()
    )

    #expect(clientData == expected)
}

@Test
func lengthPrefixRejectsValuesLargerThanUInt32() {
    let byteCount = Int(UInt32.max) + 1

    #expect(throws: SignedRequestError.fieldTooLarge(byteCount: byteCount)) {
        try SignedRequest.lengthPrefix(forByteCount: byteCount)
    }
}

private func encodedObject<Value: Encodable>(
    _ value: Value
) throws -> [String: String] {
    try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(value))
            as? [String: String]
    )
}
