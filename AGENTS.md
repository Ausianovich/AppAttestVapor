# AGENTS.md

## Project purpose

This Swift package protects requests between an application and a Vapor server with Apple App Attest:

- `AppAttestDevice` is installed as the client-side Swift OpenAPI transport.
- `AppAttestVapor` registers service endpoints and provides middleware for protected routes.

## Read before integrating

1. [Architecture and request sequence](docs/architecture/app_attest_integration.md)
2. [AppAttestVapor integration](docs/api/app_attest_vapor.md)
3. [AppAttestDevice integration](docs/api/app_attest_device.md)
4. [Documentation index](docs/INDEX.md)

## Vapor integration

- Configure Valkey before calling `app.appAttest.configure(...)`.
- Provide an `AppAttestCredentialClient` with four durable-storage operations: save the credential, get the public key, get the counter, and atomically advance the counter.
- Store public keys and counters in durable storage such as PostgreSQL. Valkey is used only for challenges with a 60-second TTL.
- Add `AppAttestMiddleware()` only to the protected route group.
- Pass that group to the `VaporTransport` used by the generated OpenAPI server.
- Do not place the `/app-attest/*` service routes behind `AppAttestMiddleware`.

See the [AppAttestVapor documentation](docs/api/app_attest_vapor.md) for the exact APIs and a configuration example.

## Application integration

- Create the application's concrete transport, such as `URLSessionTransport`.
- Wrap it in `AppAttestTransport` and pass the result to the generated OpenAPI client.
- Use the same `routePrefix` on the client and server.
- The library stores only `keyID` in Keychain and handles registration and request signing internally.
- Requests are performed sequentially. Streaming uploads are unsupported.
- On macOS 26, the package compiles, but a protected request fails with `unsupported` before reaching the network.

See the [AppAttestDevice documentation](docs/api/app_attest_device.md) for the exact APIs and a configuration example.

## Constraints and change rules

- Do not add `userID`; `keyID` identifies the credential.
- Do not store credentials in Valkey or discard them when the server restarts.
- Do not add streaming uploads, App Attest receipts, or checks available only on iOS 27+ without an explicit requirement.
- Do not add production dependencies without user confirmation.
- Verify APIs in source code or official documentation before using them.
- Use modern Swift concurrency (`async`/`await`) only; do not use GCD.
