import Fluent

struct CreateAppAttestCredential: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(AppAttestCredential.schema)
            .field(
                "key_id",
                .string,
                .required,
                .identifier(auto: false)
            )
            .field("public_key", .data, .required)
            .field("counter", .int64, .required)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(AppAttestCredential.schema).delete()
    }
}
