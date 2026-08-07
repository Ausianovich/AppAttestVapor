---
title: App Attest Validation Logging
type: decision
status: active
created: 2026-08-07
updated: 2026-08-07
tags: [decision, security, observability]
keywords: [AppAttestDevice, AppAttestVapor, OSLog, SwiftLog, request.logger, LOG_LEVEL, validation-stage]
related: [app_attest_device.md, app_attest_vapor.md, app_attest_integration.md]
---

## TL;DR
Device diagnostics use `OSLog.Logger`; Linux/Vapor diagnostics use request-scoped SwiftLog with stable validation stages.
Read when: adding App Attest validation | diagnosing registration or assertion failures | changing logging levels or metadata

## Summary
`AppAttestDevice` records registration, assertion, recovery, and failure boundaries through Apple unified logging. `AppAttestVapor` records route, storage, attestation, and assertion outcomes through `Request.logger`, preserving Vapor's request ID. Failure messages identify the validation stage without exposing proof material. Existing HTTP responses, retry behavior, and public APIs remain unchanged.

---

## Context

- App Attest validation currently maps internal failures to stable, intentionally generic HTTP errors.
- Generic client/server errors do not reveal whether parsing, certificate, nonce, identity, signature, or counter validation failed.
- `OSLog` is unavailable on the Linux host used by DigitalOcean.

## Decision

| Target | Logger | Success | Failure |
|---|---|---|---|
| `AppAttestDevice` | `OSLog.Logger` | `debug` at registration, challenge, assertion, recovery boundaries | `error` with operation stage and error type |
| `AppAttestVapor` | `Request.logger` / SwiftLog | `debug` after challenge issue, attestation acceptance, assertion acceptance | `error` with `component=app-attest`, `stage`, and error type |

Server stage values distinguish at least:

- request/header decoding
- challenge read, comparison, and deletion
- credential read, save, and atomic counter advance
- attestation object and authenticator-data parsing
- certificate chain, nonce, public key, App ID, counter, AAGUID, and credential ID
- assertion object, authenticator data, public key, signature, App ID, and monotonic counter

Never log `keyID`, challenge, attestation object, assertion, public key, signed body, request body, or their hashes. HTTP status, stable server error code, operation ID, and validation-stage names are safe.

## Rationale

- Vapor already depends on SwiftLog and supplies request IDs through `Request.logger`.
- OSLog is native and dependency-free for the Apple-only device target.
- Stage metadata keeps production responses opaque while making operational failures searchable.
- `LOG_LEVEL=debug` enables successful-stage events on the Vapor host; error events remain visible at production levels.

## Alternatives

- SwiftLog on both targets: rejected; adds a direct device dependency and loses the requested native OSLog path.
- Conditional OSLog on the server: rejected; produces no validation diagnostics on Linux.
- New cross-platform logging abstraction: rejected; no second implementation or configuration need justifies it.

## Consequences

- Logging is diagnostic-only: validation, persistence, recovery, and HTTP behavior do not change.
- One server test captures a representative failure stage through the real request logger; the complete package suite checks behavior remains unchanged.
- Device OSLog output is verified by compilation and existing integration tests; no production logger abstraction is added solely to capture OSLog in tests.

## Related

- [AppAttestDevice API](../api/app_attest_device.md)
- [AppAttestVapor API](../api/app_attest_vapor.md)
- [App Attest integration](../architecture/app_attest_integration.md)
