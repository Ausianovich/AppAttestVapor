---
title: App Attest Integration
type: architecture
status: active
created: 2026-08-05
updated: 2026-08-11
tags: [architecture, security]
keywords: [AppAttestVapor, AppAttestDevice, AppAttestTransport, AppAttestMiddleware, VaporValkey, ClientTransport, DCAppAttestService, keyID, challenge, assertion, attestation]
related: []
---

## TL;DR
App Attest protects selected OpenAPI routes with per-request signed proofs. The client proves possession of a valid, non-revoked App Attest key; the server verifies challenge freshness, signature, counter monotonicity, and application identity before running protected handlers.

Read when: implementing AppAttestDevice/AppAttestVapor | changing request signing contract | onboarding a new team into App Attest integration.

## Summary
`AppAttestDevice` wraps any Swift OpenAPI `ClientTransport`, performs initial attestation, and adds signed proof headers to protected requests. `AppAttestVapor` provides service endpoints and middleware to verify those proofs.  
Valkey stores only short-lived challenges.  
Durable credentials (`publicKey`, `counter`) are host-owned and stored through `AppAttestCredentialClient`.

## What each side is responsible for

- Client side:
  - Creates and stores a `keyID` in Keychain only after server accepts attestation.
  - Requests challenges and attests keys when needed.
  - Builds canonical client data and generates assertions for every protected request.
  - Performs bounded recovery on server recoverable codes (`app_attest_challenge_missing`, `app_attest_credential_missing`).
  - Re-registers once when `DCAppAttestService.generateAssertion` reports `DCError.invalidKey` or `DCError.invalidInput`, including after app reinstallation.
- Server side:
  - Issues one challenge per `keyID` request with short TTL.
  - Verifies attestation object, then persists `(keyID, publicKey, counter)` once.
  - Verifies each protected request proof and rejects everything that is stale, malformed, replayed, or mismatched.
  - Manages challenge and counter replay resistance by delete-first persistence checks.
- Infrastructure side:
  - Provides trustworthy TLS, app authentication, and runtime services (Valkey + durable DB).
  - Must keep challenge TTL short and credential storage durable.

## Integration flow at a glance

### Phase 1: registration flow
1. Transport checks `DCAppAttestService.isSupported`.
2. Transport reads `keyID` from Keychain.
3. If missing, transport generates a key and asks server for a challenge.
4. Transport calls Apple attestation with `SHA256(challenge)` and sends `keyID`, `challenge`, and attestation object to `/app-attest/attestation`.
5. Server checks:
   - challenge format + challenge match with Valkey state,
   - challenge deletion succeeds exactly once,
   - Apple attestation chain, challenge binding, App ID, environment, key ID, and initial counter.
6. Server stores the credential and returns `204`.
7. Transport writes `keyID` to Keychain and retries the original request path.

### Phase 2: protected request flow
1. Transport buffers request body in memory.
2. Transport asks for a new challenge for that `keyID`.
3. Transport computes client data (`version`, `challenge`, method, path+query, body hash).
4. Transport signs data and sends three headers:
   - `X-App-Attest-Key-ID`
   - `X-App-Attest-Challenge`
   - `X-App-Attest-Assertion`
5. Middleware checks required headers and challenge shape.
6. Middleware reads `challenge(keyID)` from Valkey and deletes it immediately.
7. Middleware loads `publicKey` and `counter`, reconstructs client data, and verifies assertion signature.
8. Middleware atomically advances the counter (`newValue > stored`) and only then calls protected handler.

## Scope

- Device platforms: iOS 26+, macOS 26+; `DCAppAttestService.isSupported` controls local support.
- macOS 26 compiles but protected requests are still unsupported at runtime.
- One configured Team ID, Bundle ID, and App Attest environment per server instance.
- Protection applies only to explicitly selected Vapor route groups.
- Request bodies are buffered; streaming uploads are unsupported.
- One protected request in flight per `AppAttestTransport` actor.
- `validationCategory`, `bundleVersion`, App Attest receipts, and iOS 27+ fraud checks are intentionally excluded.

## Step-by-step implementation plan

### 1. Shared constants
Configure these shared values consistently:

- `teamID`
- `bundleID`
- environment (`.development` or `.production`)
- `routePrefix` (default `/app-attest`)
- `challengeTTL` (default `60`)

### 2. Configure server routes and middleware order
1. In `configure(_:)`, set up database and Valkey before protected logic.
2. Register App Attest dependencies (`appAttestCredential`) before routes are hit.
3. Call `app.appAttest.configure(...)` to register service endpoints.
4. Group protected routes via `app.grouped(AppAttestMiddleware())`.
5. Keep health and service endpoints outside this middleware.

### 3. Implement durable credential operations
Host must provide all closure operations:

- `saveCredential(keyID, publicKey, initialCounter)`
- `getPublicKey(keyID)`
- `getCounter(keyID)`
- `advanceCounter(keyID, newValue) -> Bool`

`saveCredential` must never overwrite an existing key row.  
`advanceCounter` must be atomic and return `true` only when it actually advanced.

### 4. Configure OpenAPI transport on both sides
- Client: `Client(transport: AppAttestTransport(base: URLSessionTransport(), routePrefix: ...))`
- Server: register handlers using `VaporTransport(routesBuilder: app.grouped(AppAttestMiddleware()))`
- Server services stay on ungrouped routes.

## Main elements

| Element | Responsibility |
|---|---|
| `AppAttestCore` | Shared versioned signed-data encoding |
| `AppAttestTransport<Base: ClientTransport>` | Client registration, request signing, bounded recovery |
| Keychain store | Persists accepted `keyID` only |
| `AppAttestConfiguration` | Team ID, Bundle ID, environment, route prefix, challenge TTL |
| Service routes | `POST /app-attest/challenge`, `POST /app-attest/attestation` |
| `AppAttestMiddleware` | Verifies app attestation proof before protected handler |
| Valkey challenge driver | Stores one challenge per `keyID`, TTL-managed |
| `AppAttestCredentialClient` | Durable host operations for public key + counter |
| Attestation verifier | Verifies challenge binding, Apple chain, environment, credential metadata |
| Assertion verifier | Verifies signature, counter monotonicity, and request body binding |

## Interactions

### Initial attestation

1. Transport checks support and local key state.
2. If key absent, transport requests challenge.
3. Transport calls Apple attestation.
4. Transport sends attestation payload to server.
5. Server validates challenge match + challenge deletion + attestation.
6. Server saves credential and returns `204`.
7. Transport writes `keyID` to Keychain.

### Protected request

1. Transport buffers body and fetches fresh challenge.
2. Transport creates canonical client data and assertion.
3. Transport sends signed request.
4. Middleware validates required headers and lengths.
5. Middleware reads and deletes challenge.
6. Middleware fetches public key and stored counter.
7. Middleware verifies assertion and compares `request.path`/`query` + body hash.
8. Middleware advances counter using atomic compare-and-set.
9. Middleware runs protected handler only if all checks pass.

## OpenAPI integration

- Client side: generated client uses `AppAttestTransport`.
- Server side: generated handlers register on `VaporTransport(routesBuilder: app.grouped(AppAttestMiddleware()))`.
- Do not place service routes behind middleware.
- Route prefix must be byte-for-byte equal between service client and configuration.

## Request/response behavior

| Condition | Client behavior | Server HTTP status | Server code |
|---|---|---|---|
| No local support | Local typed error | - | - |
| Missing/expired challenge | Retry once | `401` | `app_attest_challenge_missing` |
| Credential missing | Delete Keychain key, re-register once | `401` | `app_attest_credential_missing` |
| Local App Attest key invalid | Delete Keychain key ID, re-register once | - | `DCError.invalidKey` or `DCError.invalidInput` |
| Invalid signature/shape/env/counter | Return without retry | `400` or `403` | `app_attest_invalid` |
| Infrastructure error | Return no retry, preserve local key | `503` | `app_attest_unavailable` |

## Constraints

- Missing, malformed, expired, replayed, or unverifiable App Attest data fails closed.
- TLS and regular auth remain required.
- Credential storage must survive app and challenge store restarts.
- Valkey deletion (`DEL`) is part of anti-replay protection.
- Signed-data format is versioned and must remain synchronized across device and server packages.
- Concurrency model is sequential for protected transport calls.

## Trade-offs

- Sequential transport lowers concurrency complexity and preserves counter ordering.
- Single active challenge per `keyID` matches current transport contract.
- Direct verifier avoids external verification dependency but requires explicit crypto-level coverage.
- Host-owned credential storage decouples persistence and database choice.
- Storing only `keyID` in Keychain lowers mobile secret surface.

## Verification coverage

- Shared fixtures and verification logic are split by phase:
  - Attestation success/failure (certificate, nonce, App ID, environment, key IDs)
  - Assertion success/failure (challenge, method/path/body/hash, signature, replay)
  - Route tests validate middleware blocks invalid signed paths.

## Related

- [AppAttestVapor API](app_attest_vapor.md)
- [AppAttestDevice API](app_attest_device.md)
- [AppAttestVapor server integration](../runbooks/vapor_server_integration.md)
