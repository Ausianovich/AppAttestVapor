import Foundation
import SwiftCBOR

struct AssertionObject: Equatable, Sendable {
    let signature: Data
    let authenticatorData: Data

    static func parse(_ data: Data) throws -> Self {
        let decoded = try decodeStrictCBOR(data)
        guard case let .map(root) = decoded else {
            throw AppAttestParsingError.invalidCBOR
        }
        guard let signatureValue = root["signature"] else {
            throw AppAttestParsingError.missingField
        }
        guard case let .byteString(signatureBytes) = signatureValue else {
            throw AppAttestParsingError.invalidCBOR
        }
        guard let authenticatorValue = root["authenticatorData"] else {
            throw AppAttestParsingError.missingField
        }
        guard case let .byteString(authenticatorBytes) = authenticatorValue else {
            throw AppAttestParsingError.invalidCBOR
        }

        return Self(
            signature: Data(signatureBytes),
            authenticatorData: Data(authenticatorBytes)
        )
    }
}
