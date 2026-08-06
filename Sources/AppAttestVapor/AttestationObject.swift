import Foundation
import SwiftCBOR

struct AttestationObject: Equatable, Sendable {
    let certificateChain: [Data]
    let authenticatorData: Data

    static func parse(_ data: Data) throws -> Self {
        let decoded = try decodeStrictCBOR(data)
        guard case let .map(root) = decoded else {
            throw AppAttestParsingError.invalidCBOR
        }
        guard root["fmt"] != nil else {
            throw AppAttestParsingError.missingField
        }
        guard root["fmt"] == .utf8String("apple-appattest") else {
            throw AppAttestParsingError.invalidFormat
        }
        guard let statementValue = root["attStmt"] else {
            throw AppAttestParsingError.missingField
        }
        guard case let .map(statement) = statementValue else {
            throw AppAttestParsingError.invalidCBOR
        }
        guard let chainValue = statement["x5c"] else {
            throw AppAttestParsingError.missingField
        }
        guard case let .array(chainItems) = chainValue, !chainItems.isEmpty else {
            throw AppAttestParsingError.invalidCBOR
        }
        let certificateChain = try chainItems.map { item in
            guard case let .byteString(bytes) = item else {
                throw AppAttestParsingError.invalidCBOR
            }
            return Data(bytes)
        }
        guard let authenticatorValue = root["authData"] else {
            throw AppAttestParsingError.missingField
        }
        guard case let .byteString(authenticatorBytes) = authenticatorValue else {
            throw AppAttestParsingError.invalidCBOR
        }

        return Self(
            certificateChain: certificateChain,
            authenticatorData: Data(authenticatorBytes)
        )
    }
}
