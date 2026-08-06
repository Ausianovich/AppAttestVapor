---
title: App Attest Integration
type: architecture
status: active
created: 2026-08-05
updated: 2026-08-06
tags: [architecture, security]
keywords: [AppAttestVapor, AppAttestDevice, AppAttestTransport, AppAttestMiddleware, VaporValkey, ClientTransport, DCAppAttestService, keyID, challenge, assertion, attestation]
related: [app_attest_vapor.md, app_attest_device.md]
---

## TL;DR
Reusable App Attest protection for OpenAPI clients and Vapor servers, with Valkey challenges and host-owned durable credentials.
Read when: implementing AppAttestDevice/AppAttestVapor | changing signed-request format | integrating OpenAPI or credential storage

## Summary
`AppAttestDevice` wraps any Swift OpenAPI `ClientTransport`, performs initial attestation, and adds an assertion to each protected request. `AppAttestVapor` registers attestation routes and exposes middleware for selected Vapor route groups, including groups used by `VaporTransport`. Valkey stores short-lived challenges; a Point-Free dependency implemented by the host server stores public keys and counters durably. The package implements Apple attestation and assertion verification directly instead of depending on a third-party App Attest verifier.

---

## Scope

- Device platforms: iOS 26+, macOS 26+; App Attest requests fail locally when `DCAppAttestService.isSupported == false`.
- macOS 26 compiles but does not perform protected requests; current Apple support begins with macOS 27.
- Server platforms: Linux and macOS.
- One configured Team ID, Bundle ID, and App Attest environment per server instance.
- Protection applied only to explicitly grouped Vapor routes.
- Buffered request bodies only; streaming uploads excluded.
- One protected request in flight per `AppAttestTransport`; parallel requests excluded.
- `validationCategory`, `bundleVersion`, receipt storage, and fraud assessment excluded.

## Main elements

| Element | Responsibility |
|---|---|
| `AppAttestCore` | Shared, versioned encoding of signed client data; no platform or framework integration |
| `AppAttestTransport<Base: ClientTransport>` | Serializes protected requests, manages key lifecycle, obtains challenges, creates assertions, delegates network I/O to `Base` |
| KeyChain integration | Stores `keyID` only after server accepts initial attestation |
| `AppAttestConfiguration` | Team ID, Bundle ID, environment, service route prefix, challenge TTL; default TTL 60 seconds |
| Service routes | `POST /app-attest/challenge` and `POST /app-attest/attestation`; prefix configurable |
| `AppAttestMiddleware` | Verifies request assertion before invoking downstream Vapor/OpenAPI handler |
| VaporValkey storage | Stores one library-generated active challenge per `keyID`; applies TTL; supports get/delete |
| Credential dependency | Host-provided durable persistence for public key and monotonic counter |
| Attestation verifier | CBOR decoding; Apple certificate-chain, nonce, App ID, environment, credential ID, key ID, and initial counter validation |
| Assertion verifier | Signature, App ID, challenge, and monotonic counter validation |

Credential dependency operations:

```swift
saveCredential(keyID, publicKey, initialCounter)
getPublicKey(keyID)
getCounter(keyID)
advanceCounter(keyID, to: newValue) -> Bool
```

`advanceCounter` must atomically succeed only when `newValue` is greater than the stored value. PostgreSQL/Fluent is the expected host implementation; the package does not own a database schema.

## Interactions

### Initial attestation

1. Transport checks `isSupported` and Keychain.
2. Missing `keyID` -> `generateKey`.
3. Device requests challenge for generated `keyID`.
4. Device calls `attestKey` using SHA-256 of challenge.
5. Device posts `keyID`, challenge, and attestation object to `/app-attest/attestation`.
6. Server loads challenge from Valkey, compares it, and deletes it; delete must report success.
7. Server performs full agreed attestation verification.
8. Server calls `saveCredential(keyID, publicKey, 0)`.
9. Successful response -> device stores `keyID` in Keychain.

### Protected request

1. Actor-isolated transport buffers body and obtains a new challenge.
2. `AppAttestCore` encodes format version, challenge, HTTP method, path/query, and SHA-256 body hash.
3. Device creates assertion and adds `X-App-Attest-Key-ID`, `X-App-Attest-Challenge`, and `X-App-Attest-Assertion` headers.
4. Middleware loads and compares challenge, loads public key/counter, reconstructs signed data, and verifies assertion.
5. Middleware deletes challenge; a zero delete count rejects concurrent replay.
6. Middleware calls atomic `advanceCounter`; failure rejects request.
7. Middleware invokes downstream handler only after every check succeeds.

### OpenAPI integration

- Device: generated `Client` receives `AppAttestTransport(base: URLSessionTransport(), ...)` as its `ClientTransport`.
- Server: `VaporTransport` receives `app.grouped(AppAttestMiddleware())` as its `RoutesBuilder`.
- `/app-attest/*` routes register directly on `Application`, outside protected group -> no middleware recursion.
- Concrete OpenAPI transports remain host dependencies; this package depends only on `OpenAPIRuntime`.

## Constraints

- Missing, malformed, expired, replayed, or unverifiable App Attest data fails closed on server.
- `isSupported == false`, Keychain failure, or DeviceCheck failure -> no protected network request.
- TLS remains required; App Attest does not replace transport security or user authentication.
- Credential storage must survive Vapor and Valkey redeploys.
- Valkey challenge deletion must be observable (`DEL` result) to reject concurrent replay.
- Canonical signed-data format must be identical across device/server and versioned before release.
- No GCD; concurrency uses async/await and actor isolation.

## Trade-offs

- Sequential transport prevents counter reordering but limits protected-request concurrency.
- One active challenge per `keyID` matches sequential transport but cannot support future parallel sends.
- Direct verifier avoids an unversioned third-party security library but requires comprehensive cryptographic fixtures.
- Host-owned credential persistence preserves database choice but requires four dependency closures.
- Saving `keyID` only after server acceptance avoids extra lifecycle state; interruption may leave an unreachable generated key.
- Ignoring iOS/macOS 27 validation extensions keeps v1 scoped to requested checks but omits those newer risk signals.

## Error handling

| Condition | Result |
|---|---|
| Unsupported device or local preparation failure | Local typed error; base transport not called |
| Missing/expired challenge | Machine-readable recoverable error; transport retries preparation once |
| Credential not found | Transport removes local `keyID`, performs fresh attestation, retries request once |
| Invalid signature, App ID, environment, or counter | `403`; no retry; handler not called |
| Valkey or credential dependency unavailable | `503`; preserve local key; no automatic re-attestation |

Server errors use a short JSON body with stable `code`; status and code distinguish recovery from cryptographic rejection.

## Verification

- Shared signed-data vectors consumed by device and server tests.
- Attestation fixtures cover success and failures for chain, nonce, App ID, environment, credential ID, key ID, and counter.
- Assertion fixtures cover signature, challenge, App ID, replay, and monotonic counter.
- Vapor tests prove protected handler is unreachable on failure.
- Transport tests use fake DeviceCheck, Keychain, and base transport for registration, assertion, recovery, serialization, and no-network failures.
- Automated tests make no live Apple requests.

## Related

- [AppAttestVapor API](../api/app_attest_vapor.md)
- [AppAttestDevice API](../api/app_attest_device.md)
