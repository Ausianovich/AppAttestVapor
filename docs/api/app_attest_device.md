---
title: AppAttestDevice API
type: api
status: active
created: 2026-08-06
updated: 2026-08-06
tags: [api, security, device]
keywords: [AppAttestDevice, AppAttestTransport, ClientTransport, URLSessionTransport, DCAppAttestService, KeyChain, keyID, generateAssertion, app_attest_challenge_missing, app_attest_credential_missing]
related: [app_attest_vapor.md]
---

## TL;DR
`AppAttestTransport` wraps any OpenAPI `ClientTransport`, registers one App Attest key, and signs protected requests sequentially.
Read when: configuring a generated client | diagnosing registration or recovery | evaluating device platform behavior

## Summary
`AppAttestDevice` uses `DCAppAttestService` and stores only the accepted `keyID` in Keychain. Every protected request receives a fresh server challenge and an Apple assertion over canonical method, path/query, and body data. Requests are buffered and serialized to preserve assertion-counter order. Recovery is limited to one retry for the two stable recoverable server codes.

---

## Quick ref

| API | Contract |
|---|---|
| `AppAttestTransport(base:routePrefix:)` | Public actor conforming to `ClientTransport` |
| `routePrefix` | Defaults to `/app-attest`; must match server configuration |
| `AppAttestDeviceError.unsupported` | App Attest unavailable; base transport not called |
| `AppAttestDeviceError.invalidResponse` | Invalid challenge response |
| `AppAttestDeviceError.registrationFailed` | Server rejected registration |

## Consumers

The host application supplies the concrete network transport:

```swift
import AppAttestDevice
import Foundation
import OpenAPIURLSession

let transport = AppAttestTransport(base: URLSessionTransport())
let client = Client(
    serverURL: URL(string: "https://api.example.com")!,
    transport: transport
)
```

The host target, not this package, depends on `swift-openapi-urlsession`. Generated `Client` is supplied by the host's OpenAPI target.

## Endpoints

The transport calls service routes directly through its base transport:

| Method and path | When |
|---|---|
| `POST /app-attest/challenge` | Initial registration and every protected attempt |
| `POST /app-attest/attestation` | No accepted key exists in Keychain |

Service calls bypass `AppAttestTransport.send` recursion.

## Request shape

- Initial attestation: generated `keyID`, 32-byte challenge, attestation object.
- Protected request client data: format byte `0x01`, length-prefixed challenge/method/path-query, SHA-256 body digest.
- Protected headers: key ID, challenge, assertion; other headers are not signed in v1.
- Nil bodies sign an empty digest; non-nil bodies are collected and rebuilt unchanged.

## Response shape

- Successful registration: `204`; only then is `keyID` written to Keychain.
- Protected response: passed through from base transport.
- Inspected error bodies are buffered and rebuilt before return.

## Constraints

- iOS 26+: runtime App Attest support determined by `DCAppAttestService.isSupported`.
- macOS 26: package compiles, but Apple App Attest support begins with macOS 27 -> `.unsupported`, no protected network request.
- Exactly one protected request in flight per transport actor; no parallel assertions.
- Request bodies buffered in memory; streaming uploads unsupported.
- Keychain stores only `keyID`; no user ID, public key, counter, receipt, or fraud assessment.
- No `bundleVersion`, `validationCategory`, or other iOS/macOS 27-only validation.

## Failures

| Condition | Behavior |
|---|---|
| `app_attest_challenge_missing` | Fresh challenge/assertion; retry original request once |
| `app_attest_credential_missing` | Delete Keychain key; generate/register new key; retry once |
| `403 app_attest_invalid` | Return response; preserve key; no retry |
| `503 app_attest_unavailable` | Return response; preserve key; no retry |
| Keychain or DeviceCheck failure | Throw locally; no automatic retry |

If fresh attestation fails after `credential_missing`, the deleted old key remains absent and a new key is not persisted.

## Related

- [App Attest integration](../architecture/app_attest_integration.md)
- [AppAttestVapor API](app_attest_vapor.md)
