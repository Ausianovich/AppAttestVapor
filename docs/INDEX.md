# Index

<!-- Types: component, feature, architecture, decision, runbook, api, design -->
<!-- Files go to: docs/{type}s/ (or docs/design/ for the design system; root doc is DESIGN.md) -->

| Title | Type | Status | File | Keywords | Description |
|---|---|---|---|---|---|
| AppAttestDevice API | api | active | api/app_attest_device.md | AppAttestDevice, AppAttestTransport, ClientTransport, URLSessionTransport, DCAppAttestService, DCError.invalidKey, DCError.invalidInput, KeyChain, keyID, generateAssertion, app_attest_challenge_missing, app_attest_credential_missing | OpenAPI client transport, registration, request signing, bounded recovery |
| AppAttestVapor API | api | active | api/app_attest_vapor.md | AppAttestVapor, AppAttestConfiguration, AppAttestMiddleware, AppAttestCredentialClient, prepareDependencies, VaporTransport, VaporValkey, ValkeyClient, advanceCounter, app_attest_unavailable | Vapor routes, middleware, Valkey challenges, durable credential contract |
| App Attest Integration | architecture | active | architecture/app_attest_integration.md | AppAttestVapor, AppAttestDevice, AppAttestTransport, AppAttestMiddleware, VaporValkey, ClientTransport, DCAppAttestService, keyID, challenge, assertion, attestation | App Attest transport, Vapor middleware, Valkey challenges, durable credentials |
| App Attest Validation Logging | decision | active | decisions/app_attest_validation_logging.md | AppAttestDevice, AppAttestVapor, OSLog, SwiftLog, request.logger, LOG_LEVEL, validation-stage | OSLog on device and request-scoped SwiftLog validation diagnostics on Vapor |
| AppAttestVapor Server Integration | runbook | active | runbooks/vapor_server_integration.md | AppAttestVapor, AppAttestCredentialClient, AppAttestCredential, CreateAppAttestCredential, AppAttestMiddleware, prepareDependencies, FluentPostgresDriver, SQLKit, VaporValkey, DATABASE_URL | Empty Vapor server to PostgreSQL credentials, Valkey challenges, and protected routes |
