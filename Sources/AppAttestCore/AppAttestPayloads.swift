package struct AppAttestChallengeRequest: Codable, Equatable, Sendable {
    package let keyID: String

    package init(keyID: String) {
        self.keyID = keyID
    }
}

package struct AppAttestChallengeResponse: Codable, Equatable, Sendable {
    package let challenge: String

    package init(challenge: String) {
        self.challenge = challenge
    }
}

package struct AppAttestAttestationRequest: Codable, Equatable, Sendable {
    package let keyID: String
    package let challenge: String
    package let attestationObject: String

    package init(
        keyID: String,
        challenge: String,
        attestationObject: String
    ) {
        self.keyID = keyID
        self.challenge = challenge
        self.attestationObject = attestationObject
    }
}

package struct AppAttestErrorResponse: Codable, Equatable, Sendable {
    package let code: String

    package init(code: String) {
        self.code = code
    }
}
