import Crypto
import Foundation
import Vapor

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
    let logger: Logger?

    init(
        configuration: AppAttestConfiguration,
        certificateVerifier: AppAttestCertificateVerifier,
        logger: Logger? = nil
    ) {
        self.configuration = configuration
        self.certificateVerifier = certificateVerifier
        self.logger = logger
    }

    func verify(
        attestationObject data: Data,
        keyID: Data,
        challenge: Data
    ) async throws -> AppAttestationVerification {
        let authenticatorData: AuthenticatorData
        let publicKey: Data
        var stage = "attestation-object"
        do {
            let object = try AttestationObject.parse(data)
            stage = "attestation-authenticator-data"
            authenticatorData = try AuthenticatorData.parseAttestation(
                object.authenticatorData
            )
            var nonceInput = object.authenticatorData
            nonceInput.append(contentsOf: SHA256.hash(data: challenge))
            do {
                stage = "attestation-certificate"
                let certificate = try await certificateVerifier.verify(
                    certificateChain: object.certificateChain,
                    expectedNonce: Data(SHA256.hash(data: nonceInput))
                )
                publicKey = certificate.publicKeyX963
            } catch let error as AppAttestCertificateError {
                stage = switch error {
                case .invalidCertificate:
                    "attestation-certificate"
                case .invalidCertificateChain:
                    "attestation-certificate-chain"
                case .invalidNonceExtension:
                    "attestation-nonce-extension"
                case .nonceMismatch:
                    "attestation-nonce"
                case .unsupportedPublicKey:
                    "attestation-public-key"
                }
                throw error
            }
        } catch {
            logger?.appAttestError(stage: stage, error: error)
            throw AppAttestationError.invalidAttestation
        }

        return try Self.validate(
            authenticatorData: authenticatorData,
            keyID: keyID,
            publicKey: publicKey,
            configuration: configuration,
            logger: logger
        )
    }

    static func validate(
        authenticatorData: AuthenticatorData,
        keyID: Data,
        publicKey: Data,
        configuration: AppAttestConfiguration,
        logger: Logger? = nil
    ) throws -> AppAttestationVerification {
        let appID = "\(configuration.teamID).\(configuration.bundleID)"
        let expectedAAGUID = switch configuration.environment {
        case .development:
            Data("appattestdevelop".utf8)
        case .production:
            Data("appattest".utf8) + Data(repeating: 0, count: 7)
        }

        var stage = "attestation-credential"
        do {
            guard let credential = authenticatorData.attestedCredential else {
                throw AppAttestationError.invalidAttestation
            }
            stage = "attestation-public-key-hash"
            guard Data(SHA256.hash(data: publicKey)) == keyID else {
                throw AppAttestationError.invalidAttestation
            }
            stage = "attestation-app-id"
            guard
                authenticatorData.rpIDHash
                    == Data(SHA256.hash(data: Data(appID.utf8)))
            else {
                throw AppAttestationError.invalidAttestation
            }
            stage = "attestation-counter"
            guard authenticatorData.counter == 0 else {
                throw AppAttestationError.invalidAttestation
            }
            stage = "attestation-aaguid"
            guard credential.aaguid == expectedAAGUID else {
                throw AppAttestationError.invalidAttestation
            }
            stage = "attestation-credential-id"
            guard credential.credentialID == keyID else {
                throw AppAttestationError.invalidAttestation
            }
        } catch {
            logger?.appAttestError(stage: stage, error: error)
            throw AppAttestationError.invalidAttestation
        }

        return AppAttestationVerification(
            publicKey: publicKey,
            initialCounter: authenticatorData.counter
        )
    }
}
