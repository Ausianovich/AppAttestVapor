import Foundation
import SwiftCBOR

enum AppAttestParsingError: Error, Equatable {
    case invalidCBOR
    case invalidFormat
    case missingField
    case invalidAuthenticatorData
}

struct AuthenticatorData: Equatable, Sendable {
    struct AttestedCredential: Equatable, Sendable {
        let aaguid: Data
        let credentialID: Data
        let publicKey: Data
    }

    let rpIDHash: Data
    let flags: UInt8
    let counter: UInt32
    let attestedCredential: AttestedCredential?

    static func parseAttestation(_ data: Data) throws -> Self {
        do {
            var reader = ByteReader(data)
            let rpIDHash = try reader.read(32)
            let flags = try reader.readByte()
            guard flags == 0x41 || flags == 0xC1 else {
                throw AppAttestParsingError.invalidAuthenticatorData
            }
            let counter = try reader.readUInt32()
            let aaguid = try reader.read(16)
            let credentialLength = Int(try reader.readUInt16())
            let credentialID = try reader.read(credentialLength)
            let publicKey = try reader.read(77)
            guard case .map = try decodeStrictCBOR(publicKey) else {
                throw AppAttestParsingError.invalidAuthenticatorData
            }
            try validateExtensions(flags: flags, reader: &reader)

            return Self(
                rpIDHash: rpIDHash,
                flags: flags,
                counter: counter,
                attestedCredential: AttestedCredential(
                    aaguid: aaguid,
                    credentialID: credentialID,
                    publicKey: publicKey
                )
            )
        } catch {
            throw AppAttestParsingError.invalidAuthenticatorData
        }
    }

    static func parseAssertion(_ data: Data) throws -> Self {
        do {
            var reader = ByteReader(data)
            let rpIDHash = try reader.read(32)
            let flags = try reader.readByte()
            guard flags == 0x01 || flags == 0x81 else {
                throw AppAttestParsingError.invalidAuthenticatorData
            }
            let counter = try reader.readUInt32()
            try validateExtensions(flags: flags, reader: &reader)

            return Self(
                rpIDHash: rpIDHash,
                flags: flags,
                counter: counter,
                attestedCredential: nil
            )
        } catch {
            throw AppAttestParsingError.invalidAuthenticatorData
        }
    }

    private static func validateExtensions(
        flags: UInt8,
        reader: inout ByteReader
    ) throws {
        guard flags & 0x80 != 0 else {
            guard reader.isAtEnd else {
                throw AppAttestParsingError.invalidAuthenticatorData
            }
            return
        }

        guard case .map = try decodeStrictCBOR(reader.readRemaining()) else {
            throw AppAttestParsingError.invalidAuthenticatorData
        }
    }
}

func decodeStrictCBOR(_ data: Data) throws -> CBOR {
    let decoder = CBORDecoder(input: [UInt8](data))
    let value: CBOR
    do {
        guard let decoded = try decoder.decodeItem() else {
            throw AppAttestParsingError.invalidCBOR
        }
        value = decoded
    } catch {
        throw AppAttestParsingError.invalidCBOR
    }

    do {
        _ = try decoder.decodeItem()
    } catch CBORError.unfinishedSequence {
        return value
    } catch {
        throw AppAttestParsingError.invalidCBOR
    }
    throw AppAttestParsingError.invalidCBOR
}

private struct ByteReader {
    private let bytes: [UInt8]
    private var index = 0

    init(_ data: Data) {
        bytes = [UInt8](data)
    }

    var isAtEnd: Bool {
        index == bytes.count
    }

    mutating func readByte() throws -> UInt8 {
        guard index < bytes.count else {
            throw AppAttestParsingError.invalidAuthenticatorData
        }
        defer { index += 1 }
        return bytes[index]
    }

    mutating func read(_ count: Int) throws -> Data {
        guard count >= 0, index <= bytes.count - count else {
            throw AppAttestParsingError.invalidAuthenticatorData
        }
        defer { index += count }
        return Data(bytes[index..<(index + count)])
    }

    mutating func readUInt16() throws -> UInt16 {
        UInt16(try readByte()) << 8 | UInt16(try readByte())
    }

    mutating func readUInt32() throws -> UInt32 {
        UInt32(try readByte()) << 24
            | UInt32(try readByte()) << 16
            | UInt32(try readByte()) << 8
            | UInt32(try readByte())
    }

    mutating func readRemaining() -> Data {
        defer { index = bytes.count }
        return Data(bytes[index...])
    }
}
