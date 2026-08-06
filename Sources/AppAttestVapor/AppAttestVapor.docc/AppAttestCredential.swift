import Fluent
import Foundation

final class AppAttestCredential: Model, @unchecked Sendable {
    static let schema = "app_attest_credentials"

    @ID(custom: "key_id", generatedBy: .user)
    var id: String?

    @Field(key: "public_key")
    var publicKey: Data

    @Field(key: "counter")
    var counter: Int64

    init() {}

    init(keyID: String, publicKey: Data, counter: UInt32) {
        self.id = keyID
        self.publicKey = publicKey
        self.counter = Int64(counter)
    }
}
