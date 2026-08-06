---
title: AppAttestVapor Server Integration
type: runbook
status: active
created: 2026-08-06
updated: 2026-08-06
tags: [runbook]
keywords: [AppAttestVapor, AppAttestCredentialClient, AppAttestCredential, CreateAppAttestCredential, AppAttestMiddleware, prepareDependencies, FluentPostgresDriver, SQLKit, VaporValkey, DATABASE_URL]
related: [app_attest_vapor.md, app_attest_integration.md]
---

## TL;DR
Complete empty-server integration: PostgreSQL persists credentials, Valkey persists 60-second challenges, middleware protects selected routes.
Read when: adding AppAttestVapor to a Vapor host | implementing AppAttestCredentialClient | diagnosing an undefined credential store

## Summary
Host server owns credential persistence because `AppAttestVapor` does not impose a database schema. Fluent creates the runtime database handle as `app.db`; `AppAttestCredentialClient.database(app.db)` captures it in the four required operations. PostgreSQL stores public keys and counters across restarts; Valkey stores only short-lived challenges. Configuration order matters: database -> migration -> Valkey -> dependency client -> App Attest routes -> application routes.

---

## Quick ref

| Value | Source | Use |
|---|---|---|
| `app` | `Application.make(environment)` | Vapor application |
| `app.db` | Fluent after `app.databases.use(...)` | Concrete credential database; replaces any undefined `credentials` placeholder |
| `.database(app.db)` | Host extension in step 5 | Concrete `AppAttestCredentialClient` |
| `prepareDependencies` | Public function from Point-Free product `Dependencies` | Installs credential client once during startup |
| `app.valkey` | Host-created `ValkeyClient` | Challenge storage only |
| Team ID | Apple Developer account | `AppAttestConfiguration.teamID` |
| Bundle ID | Protected Apple application target | `AppAttestConfiguration.bundleID` |

## Preconditions

- Empty Vapor executable target named `App`.
- Swift 6.2+, macOS 26+ deployment target.
- PostgreSQL database `app_attest` reachable through `DATABASE_URL`.
- Valkey reachable at `127.0.0.1:6379`.
- Local package checkout at `../AppAttestVapor`; adjust path for host layout.
- Apple Team ID, application Bundle ID, matching App Attest environment.

## Trigger

- New Vapor host requires App Attest service routes and protected handlers.
- Existing integration contains unresolved placeholders such as `credentials.insert(...)`.

## Procedure

### 1. Configure the server package

Use direct dependencies for every imported module. This repository has no release tag; local integration uses `.package(path:)`.

```swift
// Package.swift
// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "Server",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(path: "../AppAttestVapor"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.121.4"),
        .package(url: "https://github.com/vapor/fluent.git", from: "4.0.0"),
        .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.12.0"),
        .package(url: "https://github.com/vapor/sql-kit.git", from: "3.0.0"),
        // Provides the `Dependencies` product and `prepareDependencies`.
        .package(url: "https://github.com/pointfreeco/swift-dependencies", from: "1.14.1"),
        .package(url: "https://github.com/vapor-community/valkey.git", from: "1.2.0"),
        .package(url: "https://github.com/valkey-io/valkey-swift.git", from: "1.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "App",
            dependencies: [
                .product(name: "AppAttestVapor", package: "appattestvapor"),
                .product(name: "Dependencies", package: "swift-dependencies"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
                .product(name: "SQLKit", package: "sql-kit"),
                .product(name: "Valkey", package: "valkey-swift"),
                .product(name: "Vapor", package: "vapor"),
                .product(name: "VaporValkey", package: "valkey"),
            ]
        ),
    ]
)
```

### 2. Add the Vapor entry point

File must not be named `main.swift` when it contains `@main`.

```swift
// Sources/App/entrypoint.swift
import Logging
import Vapor

@main
struct Entrypoint {
    static func main() async throws {
        var environment = try Environment.detect()
        try LoggingSystem.bootstrap(from: &environment)

        let app = try await Application.make(environment)
        do {
            try await configure(app)
            try await app.execute()
            try await app.asyncShutdown()
        } catch {
            try? await app.asyncShutdown()
            throw error
        }
    }
}
```

### 3. Define durable credential storage

`keyID` is the primary key. PostgreSQL `BIGINT` stores the full `UInt32` counter range.

```swift
// Sources/App/Models/AppAttestCredential.swift
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
```

### 4. Add the migration

Insert-only primary key prevents a second attestation from overwriting an existing credential.

```swift
// Sources/App/Migrations/CreateAppAttestCredential.swift
import Fluent

struct CreateAppAttestCredential: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(AppAttestCredential.schema)
            .field("key_id", .string, .required, .identifier(auto: false))
            .field("public_key", .data, .required)
            .field("counter", .int64, .required)
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(AppAttestCredential.schema).delete()
    }
}
```

### 5. Implement `AppAttestCredentialClient`

This is the concrete replacement for the old `credentials.*` placeholder. A parameterless static value cannot own `app.db`: Vapor creates the database handle at runtime. Static factory `.database(_:)` receives that handle once and captures it in all four closures.

```swift
// Sources/App/Clients/AppAttestCredentialClient+Database.swift
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
                try await AppAttestCredential.find(keyID, on: database)?.publicKey
            },
            getCounter: { keyID in
                guard let stored = try await AppAttestCredential.find(
                    keyID,
                    on: database
                )?.counter else {
                    return nil
                }
                guard let counter = UInt32(exactly: stored) else {
                    throw AppAttestCredentialPersistenceError.invalidCounter(stored)
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
```

Operation mapping:

| Closure | Called when | Database operation |
|---|---|---|
| `saveCredential` | Initial attestation accepted | Insert public key and initial counter; never overwrite |
| `getPublicKey` | Middleware verifies assertion | Select by `keyID`; missing row -> `nil` |
| `getCounter` | Middleware verifies monotonic counter | Select and exactly convert `Int64` to `UInt32` |
| `advanceCounter` | Signature and challenge accepted | Atomic conditional update; stale/replayed value -> `false` |

### 6. Configure the application

`prepareDependencies` is a public function from Point-Free `swift-dependencies`. It becomes available because step 1 adds product `Dependencies` to target `App` and this file uses `import Dependencies`. It installs `$0.appAttestCredential` for the application lifetime; call it once before App Attest handles any request.

Order is intentional. `app.databases.use` must precede `.database(app.db)`; Valkey and credential dependency must exist before requests reach App Attest routes.

```swift
// Sources/App/configure.swift
import AppAttestVapor
import Dependencies
import Fluent
import FluentPostgresDriver
import Valkey
import Vapor
import VaporValkey

func configure(_ app: Application) async throws {
    let databaseURL = Environment.get("DATABASE_URL")
        ?? "postgres://postgres:postgres@127.0.0.1:5432/app_attest"

    app.databases.use(try .postgres(url: databaseURL), as: .psql)
    app.migrations.add(CreateAppAttestCredential())

    app.valkey = ValkeyClient(
        .hostname("127.0.0.1", port: 6379),
        eventLoopGroup: app.eventLoopGroup,
        logger: app.logger
    )

    // From the Point-Free `Dependencies` module imported above.
    prepareDependencies {
        // Property from AppAttestVapor; value from the host extension in step 5.
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
```

Replace `YOUR_TEAM_ID` and `com.example.app`; use `.development` or `.production` to match the application entitlement.

### 7. Protect only application routes

`app.appAttest.configure(...)` already registers `/app-attest/challenge` and `/app-attest/attestation` directly on `app`. Never put those routes behind `AppAttestMiddleware`.

```swift
// Sources/App/routes.swift
import AppAttestVapor
import Vapor

func routes(_ app: Application) throws {
    app.get("health") { _ in
        "OK"
    }

    let protected = app.grouped(AppAttestMiddleware())
    protected.get("private") { _ in
        "Protected response"
    }
}
```

Generated OpenAPI server: construct host-owned `VaporTransport` with the same `protected` group, then register generated handlers on that transport. Host target must depend on `swift-openapi-vapor`; `AppAttestVapor` does not provide `VaporTransport`.

### 8. Migrate and start

```sh
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/app_attest \
  swift run App migrate

DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/app_attest \
  swift run App serve
```

## Validation

1. Health route bypasses middleware:

   ```sh
   curl -i http://127.0.0.1:8080/health
   # Expected: 200 OK
   ```

2. Challenge route is reachable without App Attest headers:

   ```sh
   curl -i -X POST http://127.0.0.1:8080/app-attest/challenge \
     -H 'content-type: application/json' \
     -d '{"keyID":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
   # Expected: 200 and {"challenge":"<base64-32-bytes>"}
   ```

3. Protected route rejects unsigned request before handler execution:

   ```sh
   curl -i http://127.0.0.1:8080/private
   # Expected: 403 and {"code":"app_attest_invalid"}
   ```

4. Real iOS client completes attestation and sends signed protected request through `AppAttestTransport`.

## Rollback

- Remove `AppAttestMiddleware` from route groups first -> routes become unprotected; security-impacting change requires explicit approval.
- Remove `app.appAttest.configure(...)` -> service routes disappear.
- Keep `app_attest_credentials` table unless credential loss is intentional; deleting it forces every device to register a new key.
- Reverting `CreateAppAttestCredential` deletes all stored credentials.

## Notes

- PostgreSQL credentials survive Vapor and Valkey restarts.
- Valkey key `app-attest:challenge:<keyID>` expires after `challengeTTL`; default `60` seconds.
- `advanceCounter` must remain one atomic conditional update; read-then-write permits concurrent replay.
- TLS and application/user authentication remain required.

## Related

- [AppAttestVapor API](../api/app_attest_vapor.md)
- [App Attest integration architecture](../architecture/app_attest_integration.md)
