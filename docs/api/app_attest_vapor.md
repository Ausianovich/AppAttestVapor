---
title: AppAttestVapor API
type: api
status: active
created: 2026-08-06
updated: 2026-08-06
tags: [api, security, vapor]
keywords: [AppAttestVapor, AppAttestConfiguration, AppAttestMiddleware, AppAttestCredentialClient, prepareDependencies, VaporTransport, VaporValkey, ValkeyClient, advanceCounter, app_attest_unavailable]
related: [app_attest_integration.md]
---

## TL;DR
Vapor service routes register directly on `Application`; `AppAttestMiddleware` protects only selected route groups.
Read when: configuring a Vapor host | connecting Valkey or PostgreSQL | protecting generated OpenAPI handlers

## Summary
`AppAttestVapor` owns challenge issuance, initial attestation verification, and per-request assertion verification. Valkey stores only 60-second challenges; the host supplies durable public-key and counter operations through `AppAttestCredentialClient`. Service routes remain outside protected groups to avoid middleware recursion. Invalid requests never reach protected handlers.

---

## Quick ref

| API | Contract |
|---|---|
| `app.appAttest.configure(configuration)` | Stores configuration and registers both service routes |
| `AppAttestMiddleware()` | Verifies App Attest headers before calling downstream handler |
| `AppAttestConfiguration` | Team ID, Bundle ID, environment, route prefix, challenge TTL |
| `DependencyValues.appAttestCredential` | Four host-owned durable credential closures |
| `prepareDependencies` | Public startup function from Point-Free `Dependencies`; installs host implementation before first request |

Defaults: route prefix `/app-attest`; challenge TTL `60` seconds.

## Consumers

Complete empty-server integration, including package dependencies, Fluent model, migration, concrete credential client, configuration, routes, and validation: [AppAttestVapor server integration](../runbooks/vapor_server_integration.md).

`prepareDependencies` does not come from Vapor or `AppAttestVapor`. Host target imports it from the Point-Free package `swift-dependencies`:

```swift
// Package.swift
dependencies: [
    .package(
        url: "https://github.com/pointfreeco/swift-dependencies",
        from: "1.14.1"
    ),
]

.executableTarget(
    name: "App",
    dependencies: [
        .product(
            name: "Dependencies",
            package: "swift-dependencies"
        ),
    ]
)
```

After implementing `AppAttestCredentialClient.database(_:)`, configure every dependency inside the server's existing `configure(_:)` function:

```swift
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

    // `prepareDependencies` comes from `import Dependencies`.
    prepareDependencies {
        // `appAttestCredential` is exposed by AppAttestVapor.
        // `.database(app.db)` is the host implementation from the runbook.
        $0.appAttestCredential = .database(app.db)
    }

    app.appAttest.configure(
        AppAttestConfiguration(
            teamID: "TEAMID",
            bundleID: "com.example.app",
            environment: .production
        )
    )

    try routes(app)
}
```

Origin of each non-local symbol:

| Symbol | Defined by | Created or called where |
|---|---|---|
| `prepareDependencies` | Product `Dependencies` from `swift-dependencies` | Called once in `configure(_:)` |
| `$0.appAttestCredential` | `AppAttestVapor` extension on `DependencyValues` | Assigned inside `prepareDependencies` |
| `app.db` | Fluent | Available after `app.databases.use(...)` |
| `.database(app.db)` | Host extension implemented in runbook | Creates concrete `AppAttestCredentialClient` |

`prepareDependencies` changes the process-wide dependency value for the application lifetime. Call it once during startup, before App Attest routes or middleware can access `appAttestCredential`.

Protect generated OpenAPI handlers by passing the grouped routes to the host-owned `VaporTransport`:

```swift
import OpenAPIVapor

let protectedRoutes = app.grouped(AppAttestMiddleware())
let transport = VaporTransport(routesBuilder: protectedRoutes)
try Handler().registerHandlers(
    on: transport,
    serverURL: URL(string: "/api")!
)
```

The host target, not this package, depends on `swift-openapi-vapor`.

## Endpoints

| Method and path | Success | Purpose |
|---|---|---|
| `POST /app-attest/challenge` | `200` JSON | Issues and stores one challenge for `keyID` |
| `POST /app-attest/attestation` | `204` | Verifies initial attestation and saves credential |

Changing `routePrefix` changes both paths. Register these routes with `configure` before creating protected route groups.

## Request shape

- Challenge: `{"keyID":"<base64-32-bytes>"}`.
- Attestation: `{"keyID":"…","challenge":"…","attestationObject":"…"}`.
- Protected requests: `X-App-Attest-Key-ID`, `X-App-Attest-Challenge`, `X-App-Attest-Assertion`.

## Response shape

- Challenge: `{"challenge":"<base64-32-bytes>"}`.
- Errors: `{"code":"<stable-code>"}`.

| Code | HTTP | Client action |
|---|---:|---|
| `app_attest_challenge_missing` | 401 | Recreate challenge/assertion once |
| `app_attest_credential_missing` | 401 | Delete local key, register a new key, retry once |
| `app_attest_invalid` | 400 or 403 | Do not retry |
| `app_attest_unavailable` | 503 | Preserve local key; do not retry |

## Constraints

Credential closures use `keyID` only:

```sql
-- saveCredential: insert-only; key_id has a unique/primary-key constraint
INSERT INTO app_attest_credentials (key_id, public_key, counter)
VALUES ($1, $2, $3);

SELECT public_key FROM app_attest_credentials WHERE key_id = $1;
SELECT counter FROM app_attest_credentials WHERE key_id = $1;

-- advanceCounter returns true only when this statement returns one row
UPDATE app_attest_credentials
SET counter = $2
WHERE key_id = $1 AND counter < $2
RETURNING counter;
```

- Public key and counter must survive Vapor/Valkey redeploys.
- Valkey stores `app-attest:challenge:<keyID>` with `SETEX`; it never stores credentials.
- No Fluent model or PostgreSQL schema is provided by this package.
- TLS and application-level authentication remain required.

## Failures

- Missing credential implementation -> `503 app_attest_unavailable`.
- Valkey/durable-store error -> `503`; protected handler not called.
- Invalid, replayed, or stale assertion -> `403`; protected handler not called.
- Challenge expiry/deletion -> recoverable `401`; client retry remains bounded to one.

## Related

- [AppAttestVapor server integration](../runbooks/vapor_server_integration.md)
- [App Attest integration](../architecture/app_attest_integration.md)
- [AppAttestDevice API](app_attest_device.md)
