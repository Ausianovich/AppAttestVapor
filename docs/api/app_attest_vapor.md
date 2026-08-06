---
title: AppAttestVapor API
type: api
status: active
created: 2026-08-06
updated: 2026-08-06
tags: [api, security, vapor]
keywords: [AppAttestVapor, AppAttestConfiguration, AppAttestMiddleware, AppAttestCredentialClient, prepareDependencies, VaporTransport, VaporValkey, ValkeyClient, advanceCounter, app_attest_unavailable]
related: []
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

Defaults: route prefix `/app-attest`; challenge TTL `60` seconds.

## Consumers

Configure Valkey and durable credentials before the first request:

```swift
import AppAttestVapor
import Dependencies
import Foundation
import Valkey
import Vapor
import VaporValkey

let app = try await Application.make(.detect)
app.valkey = ValkeyClient(
    .hostname("localhost", port: 6379),
    eventLoopGroup: app.eventLoopGroup,
    logger: app.logger
)

prepareDependencies {
    $0.appAttestCredential = AppAttestCredentialClient(
        saveCredential: { keyID, publicKey, counter in
            try await credentials.insert(keyID, publicKey, counter)
        },
        getPublicKey: { keyID in try await credentials.publicKey(keyID) },
        getCounter: { keyID in try await credentials.counter(keyID) },
        advanceCounter: { keyID, newCounter in
            try await credentials.advanceCounter(keyID, to: newCounter)
        }
    )
}

app.appAttest.configure(
    AppAttestConfiguration(
        teamID: "TEAMID",
        bundleID: "com.example.app",
        environment: .production
    )
)
```

`credentials` is host code backed by durable storage. `prepareDependencies` must run once, before any dependency access.

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

- [App Attest integration](../architecture/app_attest_integration.md)
- [AppAttestDevice API](app_attest_device.md)
