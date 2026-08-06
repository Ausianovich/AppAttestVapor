import Foundation
import X509

enum AppAttestCertificateError: Error {
    case invalidCertificate
    case invalidCertificateChain
    case invalidNonceExtension
    case nonceMismatch
    case unsupportedPublicKey
}

enum AppAttestNonceExtension {
    static let oid: [UInt] = [1, 2, 840, 113635, 100, 8, 2]

    static func parse(from certificate: Certificate) throws -> Data {
        guard let appleNonce = certificate.extensions.first(where: {
            $0.oid.oidComponents == oid
        }) else {
            throw AppAttestCertificateError.invalidNonceExtension
        }
        return try parse(oid: appleNonce.oid.oidComponents, value: Array(appleNonce.value))
    }

    static func parse(oid: [UInt], value: [UInt8]) throws -> Data {
        guard oid == Self.oid else {
            throw AppAttestCertificateError.invalidNonceExtension
        }

        var root = DERReader(value)
        var sequence = try root.read(tag: 0x30)
        try root.requireEnd()
        var context = try sequence.read(tag: 0xA1)
        try sequence.requireEnd()
        var octetString = try context.read(tag: 0x04)
        try context.requireEnd()
        let nonce = try octetString.readRemaining()
        guard nonce.count == 32 else {
            throw AppAttestCertificateError.invalidNonceExtension
        }
        return Data(nonce)
    }
}

private struct DERReader {
    private let bytes: [UInt8]
    private var index = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    mutating func read(tag: UInt8) throws -> Self {
        guard try readByte() == tag else {
            throw AppAttestCertificateError.invalidNonceExtension
        }
        let length = try readLength()
        guard length <= bytes.count - index else {
            throw AppAttestCertificateError.invalidNonceExtension
        }
        defer { index += length }
        return Self(Array(bytes[index..<(index + length)]))
    }

    mutating func readRemaining() throws -> [UInt8] {
        defer { index = bytes.count }
        return Array(bytes[index...])
    }

    func requireEnd() throws {
        guard index == bytes.count else {
            throw AppAttestCertificateError.invalidNonceExtension
        }
    }

    private mutating func readByte() throws -> UInt8 {
        guard index < bytes.count else {
            throw AppAttestCertificateError.invalidNonceExtension
        }
        defer { index += 1 }
        return bytes[index]
    }

    private mutating func readLength() throws -> Int {
        let first = try readByte()
        guard first >= 0x80 else { return Int(first) }

        let byteCount = Int(first & 0x7F)
        guard byteCount > 0, byteCount <= MemoryLayout<Int>.size else {
            throw AppAttestCertificateError.invalidNonceExtension
        }

        var length = 0
        for offset in 0..<byteCount {
            let byte = try readByte()
            guard offset != 0 || byte != 0 else {
                throw AppAttestCertificateError.invalidNonceExtension
            }
            guard length <= (Int.max - Int(byte)) >> 8 else {
                throw AppAttestCertificateError.invalidNonceExtension
            }
            length = (length << 8) | Int(byte)
        }
        guard length >= 0x80 else {
            throw AppAttestCertificateError.invalidNonceExtension
        }
        return length
    }
}
