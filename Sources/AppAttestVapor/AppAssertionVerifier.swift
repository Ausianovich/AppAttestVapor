import Crypto
import Foundation
import Vapor

enum AppAssertionError: Error, Equatable {
    case invalidAssertion
}

struct AppAssertionVerifier: Sendable {
    let configuration: AppAttestConfiguration
    let logger: Logger?

    init(configuration: AppAttestConfiguration, logger: Logger? = nil) {
        self.configuration = configuration
        self.logger = logger
    }

    func verify(
        assertionObject data: Data,
        publicKey publicKeyData: Data,
        clientData: Data,
        storedCounter: UInt32
    ) throws -> UInt32 {
        var stage = "assertion-object"
        do {
            let object = try AssertionObject.parse(data)
            stage = "assertion-authenticator-data"
            let authenticatorData = try AuthenticatorData.parseAssertion(
                object.authenticatorData
            )
            stage = "assertion-public-key"
            let publicKey = try P256.Signing.PublicKey(
                x963Representation: publicKeyData
            )
            stage = "assertion-signature"
            let signature = try P256.Signing.ECDSASignature(
                derRepresentation: object.signature
            )

            var nonceInput = object.authenticatorData
            nonceInput.append(contentsOf: SHA256.hash(data: clientData))
            let nonce = SHA256.hash(data: nonceInput)
            let appID = "\(configuration.teamID).\(configuration.bundleID)"

            stage = "assertion-signature-verification"
            guard publicKey.isValidSignature(signature, for: nonce) else {
                throw AppAssertionError.invalidAssertion
            }
            stage = "assertion-app-id"
            guard
                authenticatorData.rpIDHash
                    == Data(SHA256.hash(data: Data(appID.utf8)))
            else {
                throw AppAssertionError.invalidAssertion
            }
            stage = "assertion-counter-positive"
            guard authenticatorData.counter > 0 else {
                throw AppAssertionError.invalidAssertion
            }
            stage = "assertion-counter-monotonic"
            guard authenticatorData.counter > storedCounter else {
                throw AppAssertionError.invalidAssertion
            }

            return authenticatorData.counter
        } catch {
            logger?.appAttestError(stage: stage, error: error)
            throw AppAssertionError.invalidAssertion
        }
    }
}
