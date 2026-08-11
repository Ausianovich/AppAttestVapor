---
title: AppAttestVapor API
type: api
status: active
created: 2026-08-06
updated: 2026-08-11
tags: [api, security, vapor]
keywords: [AppAttestVapor, AppAttestConfiguration, AppAttestMiddleware, AppAttestCredentialClient, prepareDependencies, VaporTransport, VaporValkey, ValkeyClient, advanceCounter, app_attest_unavailable]
related: [app_attest_integration.md]
---

## TL;DR
Vapor service routes are registered directly on `Application`; `AppAttestMiddleware` protects only selected route groups.
Read when: wiring OpenAPI handlers | deploying a production host | debugging server-side App Attest validation

## Summary
`AppAttestVapor` provides challenge issuance, initial attestation verification, and protected-route assertion verification.
Valkey stores only one short-lived challenge per `keyID` (`60` seconds default).  
The host supplies durable credential persistence through `AppAttestCredentialClient`.

## Consumers

- Vapor applications exposing App Attest service routes
- Protected route groups using `AppAttestMiddleware`
- Durable credential stores implementing `AppAttestCredentialClient`

## Quick ref

| API | Contract |
|---|---|
| `app.appAttest.configure(configuration)` | Stores configuration and registers both service routes on application root |
| `AppAttestMiddleware()` | Verifies key ID, challenge, and assertion before calling handler |
| `app.appAttest` | Lazily exposes `AppAttest` config helper on `Application` |
| `AppAttestConfiguration` | Team ID, Bundle ID, environment, route prefix, challenge TTL |
| `DependencyValues.appAttestCredential` | Host credential persistence contract |
| `prepareDependencies { ... }` | Point-Free startup function to install concrete credential client |

## Step-by-step server integration

### 1. Prepare startup dependencies

1. Configure PostgreSQL or your durable DB access.
2. Add and initialize Valkey.
3. Install `AppAttestCredentialClient` into `Dependencies`.
4. Call `app.appAttest.configure(...)`.
5. Register regular routes and OpenAPI handlers afterward.

### 2. Ensure correct package modules are available

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/vapor/vapor.git", from: "4.121.4"),
    .package(url: "https://github.com/pointfreeco/swift-dependencies", from: "1.14.1"),
    .package(path: "../AppAttestVapor"),
    // ...
]

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
        .product(name: "Valkey", package: "valkey-swift"),
    ]
)
```

### 3. Install credential client before first request

```swift
import AppAttestVapor
import Dependencies
import Fluent
import FluentPostgresDriver
import Valkey
import Vapor
import VaporValkey

func configure(_ app: Application) async throws {
    app.databases.use(try .postgres(url: "postgres://postgres:postgres@127.0.0.1:5432/app_attest"), as: .psql)
    app.migrations.add(CreateAppAttestCredential())

    app.valkey = ValkeyClient(
        .hostname("127.0.0.1", port: 6379),
        eventLoopGroup: app.eventLoopGroup,
        logger: app.logger
    )

    // prepareDependencies comes from swift-dependencies
    prepareDependencies {
        // Host concrete credential client; expects host-provided DB handle.
        $0.appAttestCredential = .database(app.db)
    }

    app.appAttest.configure(
        AppAttestConfiguration(
            teamID: "YOUR_TEAM_ID",
            bundleID: "com.example.app",
            environment: .production,
            routePrefix: "/app-attest",
            challengeTTL: 60
        )
    )

    try routes(app)
}
```

`prepareDependencies` is shared process state and should be called once in startup.

### 4. Register middleware only on protected routes

```swift
let protected = app.grouped(AppAttestMiddleware())
protected.post("private", ":id") { req in
    "ok"
}
```

Service endpoints remain outside `protected`:

```swift
app.get("health") { _ in "OK" }
```

### 5. Register OpenAPI handlers against protected transport

```swift
import OpenAPIVapor

let transport = VaporTransport(routesBuilder: protected)
try Handler().registerHandlers(on: transport, serverURL: URL(string: "/api")!)
```

## Endpoints

| Method and path | Success | Meaning |
|---|---|---|
| `POST /app-attest/challenge` | `200` | Creates/stores challenge for `keyID` |
| `POST /app-attest/attestation` | `204` | Verifies attestation and saves credential |

`routePrefix` changes both paths. Keep prefix equal to the same value passed to client `AppAttestTransport`.

## Request shape

- Challenge request: `{"keyID":"<base64-32-bytes>"}`
- Attestation request:
  - `{"keyID":"...","challenge":"...","attestationObject":"..."}`

## Response shape

- Challenge response: `{"challenge":"<base64-32-bytes>"}`
- Error response: `{"code":"<stable-code>"}`

## Server side verification stages

### Challenge endpoint
1. Decode and validate `keyID` (`Data(base64Encoded: keyID)?.count == 32`).
2. Ask `appAttestChallengeDriver.issue` for signed challenge value.
3. Persist to Valkey with TTL.
4. Return challenge response.

### Attestation endpoint
1. Decode attestation request and validate payload shape.
2. Load challenge and compare it exactly.
3. Run `AppAttestationVerifier` (certificate chain + Apple root checks + challenge binding).
4. Delete challenge using atomic delete semantics.
5. Save credential (`keyID`, public key, initial counter).

### Middleware endpoint check
1. Validate request headers and base64 shape.
2. Read and delete challenge from Valkey.
3. Resolve public key + counter from `appAttestCredential`.
4. Rebuild signed data and verify assertion.
5. Atomically advance monotonic counter.
6. Invoke next handler only when all checks succeed.

## Failures

| Condition | HTTP | Error code | Retry |
|---|---:|---|---|
| Missing challenge payload | 401 | `app_attest_challenge_missing` | Transport retries once |
| Missing credential | 401 | `app_attest_credential_missing` | Transport deletes local key and re-attests once |
| Invalid proof / signature / env / replay | 400 or 403 | `app_attest_invalid` | No retry |
| Storage/dependency issue | 503 | `app_attest_unavailable` | No retry |

`DEL` returning `0` is treated as replay/race and mapped to invalid proof.

## Storage contract

`AppAttestCredentialClient` must be implemented only with `keyID`, never with user identifiers.

```sql
-- Save: insert-only saveCredential; key_id is unique/primary-key.
INSERT INTO app_attest_credentials (key_id, public_key, counter)
VALUES ($1, $2, $3);

-- Read:
SELECT public_key FROM app_attest_credentials WHERE key_id = $1;
SELECT counter FROM app_attest_credentials WHERE key_id = $1;

-- Advance (one atomic statement):
UPDATE app_attest_credentials
SET counter = $2
WHERE key_id = $1 AND counter < $2
RETURNING counter;
```

Use the same row and data types for server restarts and crash recovery.

## Constraints

- Credential storage must be durable and survive app/container restarts.
- Valkey must only store ephemeral challenge data.
- No middleware recursion on `/app-attest/*`.
- `routePrefix` must match both host and client.
- No user IDs are stored by this package.

## Related

- [AppAttestVapor API](../api/app_attest_vapor.md)
- [App Attest integration](../architecture/app_attest_integration.md)
- [AppAttestDevice API](app_attest_device.md)
- [AppAttestVapor server integration](../runbooks/vapor_server_integration.md)
