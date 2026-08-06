# AppAttestVapor

Swift package for protecting requests to a Vapor server with Apple App Attest.

The package provides two libraries:

- `AppAttestDevice` wraps a client-side Swift OpenAPI transport, registers an App Attest key, and signs protected requests.
- `AppAttestVapor` registers the App Attest service endpoints and verifies protected Vapor routes through middleware.

Challenges are stored in Valkey for 60 seconds. The server must keep public keys and assertion counters in durable storage such as PostgreSQL.

## Integration

- [Architecture and complete request flow](docs/architecture/app_attest_integration.md)
- [Vapor integration](docs/api/app_attest_vapor.md)
- [iOS application integration](docs/api/app_attest_device.md)
- [Documentation index](docs/INDEX.md)

Supported platforms are iOS 26+ and macOS 26+. The package compiles on macOS, but App Attest is unavailable at runtime.
