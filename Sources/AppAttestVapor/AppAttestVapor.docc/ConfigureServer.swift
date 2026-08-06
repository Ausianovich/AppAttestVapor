import AppAttestVapor
import Dependencies
import Fluent
import FluentPostgresDriver
import Valkey
import Vapor
import VaporValkey

public func configure(_ app: Application) async throws {
    let databaseURL = Environment.get("DATABASE_URL")
        ?? "postgres://postgres:postgres@127.0.0.1:5432/app_attest"

    app.databases.use(
        try .postgres(url: databaseURL),
        as: .psql
    )
    app.migrations.add(CreateAppAttestCredential())

    app.valkey = ValkeyClient(
        .hostname("127.0.0.1", port: 6379),
        eventLoopGroup: app.eventLoopGroup,
        logger: app.logger
    )

    prepareDependencies {
        $0.appAttestCredential = .database(app.db)
    }

    app.appAttest.configure(
        AppAttestConfiguration(
            teamID: "YOUR_TEAM_ID",
            bundleID: "com.example.app",
            environment: .development
        )
    )

    try routes(app)
}
