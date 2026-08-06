import Crypto
import Foundation

enum AppAssertionError: Error, Equatable {
    case invalidAssertion
}

struct AppAssertionVerifier: Sendable {
    let configuration: AppAttestConfiguration

    func verify(
        assertionObject data: Data,
        publicKey publicKeyData: Data,
        clientData: Data,
        storedCounter: UInt32
    ) throws -> UInt32 {
        do {
            let object = try AssertionObject.parse(data)
            let authenticatorData = try AuthenticatorData.parseAssertion(
                object.authenticatorData
            )
            let publicKey = try P256.Signing.PublicKey(
                x963Representation: publicKeyData
            )
            let signature = try P256.Signing.ECDSASignature(
                derRepresentation: object.signature
            )

            var nonceInput = object.authenticatorData
            nonceInput.append(contentsOf: SHA256.hash(data: clientData))
            let nonce = SHA256.hash(data: nonceInput)
            let appID = "\(configuration.teamID).\(configuration.bundleID)"

            guard
                publicKey.isValidSignature(signature, for: nonce),
                authenticatorData.rpIDHash
                    == Data(SHA256.hash(data: Data(appID.utf8))),
                authenticatorData.counter > 0,
                authenticatorData.counter > storedCounter
            else {
                throw AppAssertionError.invalidAssertion
            }

            return authenticatorData.counter
        } catch {
            throw AppAssertionError.invalidAssertion
        }
    }
}
