import AppAttestVapor
import Fluent
import SQLKit

enum AppAttestCredentialPersistenceError: Error {
    case requiresSQLDatabase
    case invalidCounter(Int64)
}

extension AppAttestCredentialClient {
    static func database(_ database: any Database) -> Self {
        Self(
            saveCredential: { keyID, publicKey, counter in
                try await AppAttestCredential(
                    keyID: keyID,
                    publicKey: publicKey,
                    counter: counter
                ).create(on: database)
            },
            getPublicKey: { keyID in
                try await AppAttestCredential.find(
                    keyID,
                    on: database
                )?.publicKey
            },
            getCounter: { keyID in
                guard let storedCounter = try await AppAttestCredential.find(
                    keyID,
                    on: database
                )?.counter else {
                    return nil
                }
                guard let counter = UInt32(exactly: storedCounter) else {
                    throw AppAttestCredentialPersistenceError.invalidCounter(
                        storedCounter
                    )
                }
                return counter
            },
            advanceCounter: { keyID, newCounter in
                guard let sql = database as? any SQLDatabase else {
                    throw AppAttestCredentialPersistenceError.requiresSQLDatabase
                }

                let row = try await sql.raw("""
                    UPDATE \(ident: AppAttestCredential.schema)
                    SET \(ident: "counter") = \(bind: Int64(newCounter))
                    WHERE \(ident: "key_id") = \(bind: keyID)
                      AND \(ident: "counter") < \(bind: Int64(newCounter))
                    RETURNING \(ident: "counter")
                    """).first()

                return row != nil
            }
        )
    }
}
