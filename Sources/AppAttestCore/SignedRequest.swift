import Crypto
import Foundation

package enum SignedRequestError: Error, Equatable {
    case fieldTooLarge(byteCount: Int)
}

package enum SignedRequest {
    package static func clientData(
        challenge: Data,
        method: String,
        pathAndQuery: String,
        body: Data
    ) throws -> Data {
        var result = Data([0x01])
        try append(challenge, to: &result)
        try append(Data(method.utf8), to: &result)
        try append(Data(pathAndQuery.utf8), to: &result)
        result.append(contentsOf: SHA256.hash(data: body))
        return result
    }

    package static func lengthPrefix(
        forByteCount byteCount: Int
    ) throws -> [UInt8] {
        guard let length = UInt32(exactly: byteCount) else {
            throw SignedRequestError.fieldTooLarge(byteCount: byteCount)
        }
        return [
            UInt8(truncatingIfNeeded: length >> 24),
            UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length),
        ]
    }

    private static func append(_ field: Data, to result: inout Data) throws {
        result.append(contentsOf: try lengthPrefix(forByteCount: field.count))
        result.append(field)
    }
}
