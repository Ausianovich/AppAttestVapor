---
title: AppAttestDevice API
type: api
status: active
updated: 2026-08-07
created: 2026-08-06
tags: [api, security, device]
keywords: [AppAttestDevice, AppAttestTransport, ClientTransport, URLSessionTransport, DCAppAttestService, KeyChain, keyID, generateAssertion, app_attest_challenge_missing, app_attest_credential_missing]
related: [app_attest_vapor.md]
---

## TL;DR
`AppAttestTransport` wraps any OpenAPI `ClientTransport`, performs one-time attestation, then signs each protected request.

Use this page when wiring a generated OpenAPI client, debugging registration failures, or tuning retry behavior.

## Summary
The transport performs all App Attest state transitions locally:

- Checks local support
- Loads or creates `keyID`
- Requests server challenge
- Generates attestation/assertion with `DCAppAttestService`
- Sends signed protected request

Proof generation runs in an actor and is intentionally sequential (`isSending` gate), so protected requests are serialized and counters stay monotonic.

## Quick reference

| API | Contract |
|---|---|
| `AppAttestTransport(base:routePrefix:)` | Wraps any `ClientTransport` and injects App Attest headers |
| `routePrefix` | Must match `AppAttestConfiguration.routePrefix` on server |
| `AppAttestDeviceError.unsupported` | Local support is false; protected send is rejected |
| `AppAttestTransport.ensureRegistered(baseURL:)` | Internal function used before every attempt |
| `AppAttestDeviceError.challengeMissing` | Server says challenge invalid/replayed |
| `AppAttestDeviceError.credentialMissing` | Server says credential not found for keyID |

## Step-by-step client integration

### 1. Create transport

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

Pass the same `routePrefix` as the server if it is customized.

### 2. First call and automatic registration

On first protected request:

1. `send` acquires the actor gate, so only one protected call can sign at a time.
2. It calls `ensureRegistered`.
3. `ensureRegistered` reads `keyID` from Keychain.
4. If absent, it:
   - requests `/app-attest/challenge`,
   - calls `DCAppAttestService.attestKey(keyID, SHA256(challenge))`,
   - posts attestation to `/app-attest/attestation`,
   - stores `keyID` in Keychain only after `204`.

### 3. Signing a protected call

For a protected request:

1. Request body is collected to memory (empty payload becomes empty `Data()`).
2. A fresh challenge is requested via `/app-attest/challenge`.
3. Canonical request data is built with:
   - format version,
   - challenge,
   - HTTP method,
   - path and query (`request.url.string`),
   - SHA-256 body.
4. `DCAppAttestService.generateAssertion` signs the hash.
5. Transport sends request with headers:
   - `X-App-Attest-Key-ID`
   - `X-App-Attest-Challenge`
   - `X-App-Attest-Assertion`

### 4. Error inspection and bounded retry

`inspect` parses error responses before returning:

- `401` + `app_attest_challenge_missing` -> retry once with fresh challenge/assertion.
- `401` + `app_attest_credential_missing` -> delete local key, re-run registration, retry once.
- Any other `401/403/400` -> no transport retry.
- `503` or transport failures in registration are surfaced to caller; local key is preserved unless explicitly deleted by credential-missing recovery.

The retry counter is one; each failure path resets `stage` and re-evaluates through registration if needed.

## Endpoints used by the transport

| Method and path | Purpose | Called from |
|---|---|---|
| `POST /app-attest/challenge` | Issue challenge | Registration and every protected send |
| `POST /app-attest/attestation` | Initial attestation exchange | Registration only |

Challenge/attestation calls are made through the same base transport but outside `send` recursion (service helper methods bypass `send` wrapper path).

## Error types

| Error | Meaning | Next behavior |
|---|---|---|
| `unsupported` | Device does not support App Attest | no retry |
| `challengeMissing` | server reported missing/expired/replayed challenge | recoverable: retry once |
| `credentialMissing` | server has no credential for keyID | recoverable: delete key + re-register |
| `invalidResponse` | malformed server payload | local throw |
| `registrationFailed` | attestation endpoint returned non-success | local throw |

## Constraint notes

- `iOS 26+`: runtime support check is dynamic.
- `macOS 26`: compiles, but protected requests may return `unsupported`.
- No parallel protected send by design; serialization avoids counter reorder races.
- `KeyChain` stores only `keyID`; no user data or public key.
- Streaming upload requests are not supported because request bodies are collected.

## Request/response payloads

- Attestation payload to client service:
  - key ID
  - base64 challenge
  - base64 attestation object
- Protected request metadata:
  - key ID + challenge + assertion in headers
- Protected response:
  - normal OpenAPI result is returned on success
  - on guarded errors, response body may be replayed after buffering

## Related

- [App Attest integration](../architecture/app_attest_integration.md)
- [AppAttestVapor API](app_attest_vapor.md)
