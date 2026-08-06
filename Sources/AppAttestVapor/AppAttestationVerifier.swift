import Crypto
import Foundation

enum AppAttestationError: Error, Equatable {
    case invalidAttestation
}

struct AppAttestationVerification: Equatable, Sendable {
    let publicKey: Data
    let initialCounter: UInt32
}

struct AppAttestationVerifier: Sendable {
    let configuration: AppAttestConfiguration
    let certificateVerifier: AppAttestCertificateVerifier

    func verify(
        attestationObject data: Data,
        keyID: Data,
        challenge: Data
    ) async throws -> AppAttestationVerification {
        do {
            let object = try AttestationObject.parse(data)
            let authenticatorData = try AuthenticatorData.parseAttestation(
                object.authenticatorData
            )
            var nonceInput = object.authenticatorData
            nonceInput.append(contentsOf: SHA256.hash(data: challenge))
            let certificate = try await certificateVerifier.verify(
                certificateChain: object.certificateChain,
                expectedNonce: Data(SHA256.hash(data: nonceInput))
            )

            return try Self.validate(
                authenticatorData: authenticatorData,
                keyID: keyID,
                publicKey: certificate.publicKeyX963,
                configuration: configuration
            )
        } catch {
            throw AppAttestationError.invalidAttestation
        }
    }

    static func validate(
        authenticatorData: AuthenticatorData,
        keyID: Data,
        publicKey: Data,
        configuration: AppAttestConfiguration
    ) throws -> AppAttestationVerification {
        let appID = "\(configuration.teamID).\(configuration.bundleID)"
        let expectedAAGUID = switch configuration.environment {
        case .development:
            Data("appattestdevelop".utf8)
        case .production:
            Data("appattest".utf8) + Data(repeating: 0, count: 7)
        }

        guard
            let credential = authenticatorData.attestedCredential,
            Data(SHA256.hash(data: publicKey)) == keyID,
            authenticatorData.rpIDHash == Data(SHA256.hash(data: Data(appID.utf8))),
            authenticatorData.counter == 0,
            credential.aaguid == expectedAAGUID,
            credential.credentialID == keyID
        else {
            throw AppAttestationError.invalidAttestation
        }

        return AppAttestationVerification(
            publicKey: publicKey,
            initialCounter: authenticatorData.counter
        )
    }
}
