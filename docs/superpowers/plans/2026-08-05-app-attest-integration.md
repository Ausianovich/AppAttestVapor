# App Attest Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a reusable `AppAttestDevice` OpenAPI transport and `AppAttestVapor` middleware that perform initial Apple App Attest registration and verify every protected request.

**Architecture:** `AppAttestCore` owns one deterministic signed-request format. The device actor obtains Valkey-backed challenges through the package service routes, uses `DCAppAttestService`, and delegates the final request to any OpenAPI `ClientTransport`. Vapor service routes verify initial attestation; middleware verifies assertions before calling the protected handler. Valkey stores only 60-second challenges, while the host server supplies durable public-key and counter operations through Point-Free Dependencies.

**Tech Stack:** Swift 6.3, iOS 26+, macOS 26+, Vapor 4, Swift OpenAPI Runtime, DeviceCheck, Point-Free Dependencies, KeyChain, VaporValkey/valkey-swift, Swift Crypto, Swift Certificates, SwiftCBOR, Swift Testing.

## Global Constraints

- Execute exactly one task at a time, show its diff and verification result, then wait for the user's next command.
- Do not add dependencies beyond the already approved list in Task 1.
- Use only async/await; no GCD.
- Keep `AppAttestDevice` independent of `swift-openapi-urlsession` and `AppAttestVapor` independent of `swift-openapi-vapor`; host applications provide those transports.
- Keep PostgreSQL/Fluent schemas outside this package.
- Treat `keyID` as the only installation identifier; do not add `userID`.
- Buffer request bodies; do not implement streaming uploads.
- Permit only one protected request in flight per `AppAttestTransport`.
- Do not implement receipt handling, fraud assessment, `validationCategory`, or `bundleVersion` checks.
- No live Apple or Valkey service is required by the automated unit tests.
- Each implementation task follows red-green-refactor and is intended to become one commit only after user review.

## Fixed Wire Contract

- Service routes: `POST /app-attest/challenge` and `POST /app-attest/attestation`; `/app-attest` is configurable.
- Challenge request: `{"keyID":"<base64>"}`.
- Challenge response: `{"challenge":"<base64>"}`; decoded challenge length is 32 bytes.
- Attestation request: `{"keyID":"<base64>","challenge":"<base64>","attestationObject":"<base64>"}`.
- Successful attestation response: HTTP `204`.
- Protected request headers: `X-App-Attest-Key-ID`, `X-App-Attest-Challenge`, `X-App-Attest-Assertion`.
- Error response: `{"code":"<stable-code>"}`.
- Recoverable codes: `app_attest_challenge_missing` and `app_attest_credential_missing` with HTTP `401`.
- Cryptographic or malformed proof: `app_attest_invalid` with HTTP `403`.
- Valkey or durable-store failure: `app_attest_unavailable` with HTTP `503`.

The signed client-data byte format is deliberately small and binary:

1. one byte format version (`0x01`);
2. challenge as a UInt32 big-endian length followed by raw bytes;
3. HTTP method as a UInt32 big-endian length followed by its exact UTF-8 bytes;
4. path plus query as a UInt32 big-endian length followed by its exact UTF-8 bytes;
5. the 32-byte SHA-256 request-body digest.

No headers other than the three App Attest headers are signed in v1.

---

### Task 1: Wire the approved packages and targets

**Files:**

- Modify: `Package.swift`
- Create: `Sources/AppAttestCore/AppAttestCore.swift`
- Create: `Tests/AppAttestCoreTests/AppAttestCoreTests.swift`

- [ ] Add a compile-only `AppAttestCoreTests` test importing `AppAttestCore` and run `swift test --filter AppAttestCoreTests`; confirm it fails because the target does not exist.
- [ ] Set package platforms to iOS 26 and macOS 26.
- [ ] Add only these approved packages: Vapor `4.121.4+`, VaporValkey `1.2.0+`, Swift OpenAPI Runtime `1.12.0+`, Swift Crypto `4.5.1+`, Swift Certificates `1.19.4+`, SwiftCBOR `0.6.0..<0.7.0`, and KeyChain `2.0.0+` using `git@github.com:Ausianovich/KeyChain.git`.
- [ ] Add the internal `AppAttestCore` target and `AppAttestCoreTests` target.
- [ ] Give `AppAttestCore` only the `Crypto` product.
- [ ] Give `AppAttestDevice` only `AppAttestCore`, `Dependencies`, `KeyChain`, and `OpenAPIRuntime`.
- [ ] Give `AppAttestVapor` only `AppAttestCore`, `Dependencies`, `Crypto`, `SwiftCBOR`, `Vapor`, `VaporValkey`, and `X509`.
- [ ] Add only the direct test products actually imported by each test target, including `DependenciesTestSupport` and `VaporTesting`.
- [ ] Run `swift package resolve` and `swift test --filter AppAttestCoreTests`; expect success.
- [ ] Show the manifest diff and resolved versions; stop for review.

### Task 2: Define the shared signed-request contract

**Files:**

- Create: `Sources/AppAttestCore/AppAttestHeaders.swift`
- Create: `Sources/AppAttestCore/AppAttestPayloads.swift`
- Create: `Sources/AppAttestCore/SignedRequest.swift`
- Modify: `Tests/AppAttestCoreTests/AppAttestCoreTests.swift`

- [ ] Add failing tests for the three exact header names and Codable challenge, attestation, and error payload keys.
- [ ] Add a failing golden-vector test for the v1 length-prefixed client-data format, including an empty body, a non-empty body, and an escaped query string.
- [ ] Add `package` shared constants and payload types; do not expose a third public library product.
- [ ] Implement `SignedRequest.clientData(challenge:method:pathAndQuery:body:)` using UInt32 big-endian lengths and SHA-256.
- [ ] Reject a field whose encoded byte count is larger than UInt32 through a typed core error.
- [ ] Run `swift test --filter AppAttestCoreTests`; expect all vectors to pass.
- [ ] Show the diff and the golden bytes; stop for review.

### Task 3: Add server configuration and durable credential dependency

**Files:**

- Create: `Sources/AppAttestVapor/AppAttestConfiguration.swift`
- Create: `Sources/AppAttestVapor/AppAttestCredentialClient.swift`
- Create: `Sources/AppAttestVapor/Application+AppAttest.swift`
- Create: `Tests/AppAttestVaporTests/AppAttestConfigurationTests.swift`

- [ ] Add failing tests for the default `/app-attest` prefix, the 60-second challenge TTL, development/production environments, and storage on a Vapor `Application`.
- [ ] Define `AppAttestConfiguration(teamID:bundleID:environment:routePrefix:challengeTTL:)` with only the agreed fields.
- [ ] Define public async credential operations named `saveCredential`, `getPublicKey`, `getCounter`, and `advanceCounter` under a Point-Free dependency key.
- [ ] Document in API comments that `saveCredential` is insert-only and `advanceCounter` atomically succeeds only when `newValue > storedValue`.
- [ ] Make missing live credential implementations throw an unavailable error rather than silently succeeding.
- [ ] Add `app.appAttest.configure(_:)` storage without registering routes yet.
- [ ] Run `swift test --filter AppAttestConfigurationTests`; expect success.
- [ ] Show the public API diff; stop for review.

### Task 4: Implement the internal Valkey challenge driver

**Files:**

- Create: `Sources/AppAttestVapor/ValkeyChallengeDriver.swift`
- Create: `Tests/AppAttestVaporTests/ValkeyChallengeDriverTests.swift`

- [ ] Add failing tests with an in-memory closure fake for issue, get, TTL, and delete-count behavior.
- [ ] Define one internal Point-Free dependency value with `issue(request:keyID:ttl:)`, `get(request:keyID:)`, and `delete(request:keyID:)` closures; this is the only test seam around Valkey.
- [ ] Implement the live driver using the confirmed APIs `request.valkey.setex`, `request.valkey.get`, and `request.valkey.del(keys:) -> Int`.
- [ ] Generate 32 random bytes with `SystemRandomNumberGenerator`; store the base64 value under `app-attest:challenge:<keyID>` for the configured TTL.
- [ ] Return `true` from delete only when Valkey reports exactly one deleted key.
- [ ] Run `swift test --filter ValkeyChallengeDriverTests`; expect success without a running Valkey server.
- [ ] Show the diff; stop for review.

### Task 5: Register and test the challenge endpoint

**Files:**

- Create: `Sources/AppAttestVapor/AppAttestRoutes.swift`
- Create: `Sources/AppAttestVapor/AppAttestError.swift`
- Modify: `Sources/AppAttestVapor/Application+AppAttest.swift`
- Create: `Tests/AppAttestVaporTests/AppAttestChallengeRouteTests.swift`

- [ ] Add Vapor tests proving configuration registers `POST <prefix>/challenge`, returns one base64 32-byte challenge, passes the configured 60-second TTL to the driver, and rejects malformed/non-32-byte key IDs.
- [ ] Add tests mapping driver failures to HTTP `503` and `app_attest_unavailable`.
- [ ] Implement short Codable error responses and the challenge handler.
- [ ] Register the service route directly on `Application`, not on a protected group.
- [ ] Run `swift test --filter AppAttestChallengeRouteTests`; expect success.
- [ ] Show the route diff; stop for review.

### Task 6: Parse App Attest CBOR and authenticator data

**Files:**

- Create: `Sources/AppAttestVapor/AttestationObject.swift`
- Create: `Sources/AppAttestVapor/AssertionObject.swift`
- Create: `Sources/AppAttestVapor/AuthenticatorData.swift`
- Create: `Tests/AppAttestVaporTests/AppAttestObjectParsingTests.swift`

- [ ] Add failing CBOR tests for the exact `apple-appattest` format, `x5c`, `authData`, assertion signature, and assertion authenticator data.
- [ ] Add failing binary-parser tests for RP ID, flags, UInt32 big-endian counter, AAGUID, credential length, credential ID, and the 77-byte Apple COSE public key.
- [ ] Add truncation, wrong-format, missing-field, wrong-flag, and top-level trailing-garbage failure tests.
- [ ] Implement strict parsers with `SwiftCBOR`; retain only fields used by the agreed verification steps and ignore receipt contents.
- [ ] Accept but do not inspect well-formed authenticator extension bytes after the COSE key, because v1 intentionally omits iOS/macOS 27 extension checks.
- [ ] Run `swift test --filter AppAttestObjectParsingTests`; expect success.
- [ ] Show the parser diff; stop for review.

### Task 7: Verify the certificate chain and Apple nonce extension

**Files:**

- Modify: `Package.swift`
- Create: `Sources/AppAttestVapor/Resources/Apple_App_Attestation_Root_CA.pem`
- Create: `Sources/AppAttestVapor/AppAttestCertificateVerifier.swift`
- Create: `Sources/AppAttestVapor/AppAttestNonceExtension.swift`
- Create: `Tests/AppAttestVaporTests/AppAttestCertificateVerifierTests.swift`
- Create: `Tests/AppAttestVaporTests/Fixtures/AttestationTestRoot.pem`
- Create: `Tests/AppAttestVaporTests/Fixtures/AttestationTestIntermediate.der`
- Create: `Tests/AppAttestVaporTests/Fixtures/AttestationTestLeaf.der`

- [ ] Add the official Apple App Attestation root from `https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem` as a processed server resource and pin its SHA-256 in a test.
- [ ] Add a failing test that validates the checked-in test leaf/intermediate chain against an injected test root with `Verifier(rootCertificates:)` and `RFC5280Policy()`.
- [ ] Implement chain validation with `Verifier.validate(leaf:intermediates:)`; do not use the deprecated `leafCertificate:` overload.
- [ ] Add strict DER tests for Apple nonce OID `1.2.840.113635.100.8.2`, including wrong OID, wrong nesting, wrong length, and trailing bytes.
- [ ] Implement only the small DER reader required for the nonce extension; do not add a new ASN.1 dependency.
- [ ] Expose the leaf `P256.Signing.PublicKey` and its X9.63 uncompressed bytes through an internal verified-certificate result.
- [ ] Run `swift test --filter AppAttestCertificateVerifierTests`; expect success.
- [ ] Show the resource fingerprint and verifier diff; stop for review.

### Task 8: Complete initial attestation verification

**Files:**

- Create: `Sources/AppAttestVapor/AppAttestationVerifier.swift`
- Create: `Tests/AppAttestVaporTests/Fixtures/valid-attestation.cbor`
- Create: `Tests/AppAttestVaporTests/AppAttestationVerifierTests.swift`

- [ ] Add a success fixture whose injected test certificate chain, nonce, authenticator data, key ID, and challenge agree.
- [ ] Add one failing mutation test for each agreed check: certificate chain, nonce, SHA-256 public-key/key-ID match, RP ID, counter zero, environment AAGUID, and credential ID.
- [ ] Compute App ID as `teamID + "." + bundleID` and RP ID as its SHA-256.
- [ ] Compute attestation nonce as SHA-256 of `authenticatorData + SHA256(challenge)`.
- [ ] Verify the leaf key hash against decoded `keyID`, require counter `0`, and match the configured development or production AAGUID.
- [ ] Return only the 65-byte X9.63 P-256 public key and initial counter; ignore the receipt.
- [ ] Run `swift test --filter AppAttestationVerifierTests`; expect success.
- [ ] Show the verification diff and covered rejection list; stop for review.

### Task 9: Add the initial attestation endpoint

**Files:**

- Modify: `Sources/AppAttestVapor/AppAttestRoutes.swift`
- Modify: `Sources/AppAttestVapor/AppAttestError.swift`
- Create: `Tests/AppAttestVaporTests/AppAttestationRouteTests.swift`

- [ ] Add a success test proving `POST <prefix>/attestation` loads and compares the challenge, verifies the object, deletes the challenge, saves `(keyID, publicKey, 0)`, and returns `204`.
- [ ] Add tests proving the credential is not saved for a missing/mismatched challenge, invalid attestation, or zero delete count.
- [ ] Add tests mapping malformed or cryptographically invalid input to `403`, and Valkey/credential dependency failures to `503`.
- [ ] Implement the agreed order: get challenge, compare, verify attestation, delete challenge and require success, then call insert-only `saveCredential`.
- [ ] Register this service route outside all `AppAttestMiddleware` groups.
- [ ] Run `swift test --filter AppAttestationRouteTests`; expect success.
- [ ] Show the endpoint diff; stop for review.

### Task 10: Verify assertion objects

**Files:**

- Create: `Sources/AppAttestVapor/AppAssertionVerifier.swift`
- Create: `Tests/AppAttestVaporTests/AppAssertionVerifierTests.swift`

- [ ] Add a valid assertion vector signed by a fixed test P-256 private key.
- [ ] Add failures for malformed CBOR, malformed DER signature, wrong signature, wrong RP ID, counter `0`, and counter not greater than the stored value.
- [ ] Decode stored keys with `P256.Signing.PublicKey(x963Representation:)` and signatures with `P256.Signing.ECDSASignature(derRepresentation:)`.
- [ ] Compute nonce as SHA-256 of `authenticatorData + SHA256(clientData)` and call the digest overload `isValidSignature(_:for:)` to avoid hashing the nonce twice.
- [ ] Return the new UInt32 counter only after every assertion check passes.
- [ ] Run `swift test --filter AppAssertionVerifierTests`; expect success.
- [ ] Show the verifier diff; stop for review.

### Task 11: Protect Vapor routes with middleware

**Files:**

- Create: `Sources/AppAttestVapor/AppAttestMiddleware.swift`
- Create: `Tests/AppAttestVaporTests/AppAttestMiddlewareTests.swift`

- [ ] Add a success test proving middleware reconstructs client data from `request.method`, `request.url.string`, and collected `request.body.data`, then invokes the downstream handler once.
- [ ] Add failures for missing/malformed headers, missing/mismatched challenge, missing public key/counter, invalid assertion, zero challenge-delete count, and failed atomic counter advance.
- [ ] Prove in every failure test that the downstream handler is never called.
- [ ] Implement the order: load/compare challenge, load credential, verify assertion, delete challenge, atomically advance counter, then call `next.respond(to:)`.
- [ ] Map a missing credential to `401 app_attest_credential_missing`, a missing challenge to `401 app_attest_challenge_missing`, proof failures to `403`, and storage failures to `503`.
- [ ] Run `swift test --filter AppAttestMiddlewareTests`; expect success.
- [ ] Show the middleware diff; stop for review.

### Task 12: Add DeviceCheck and Keychain dependency adapters

**Files:**

- Create: `Sources/AppAttestDevice/AppAttestServiceClient.swift`
- Create: `Sources/AppAttestDevice/AppAttestKeyIDStore.swift`
- Create: `Sources/AppAttestDevice/AppAttestDeviceError.swift`
- Create: `Tests/AppAttestDeviceTests/AppAttestDeviceDependenciesTests.swift`

- [ ] Add dependency tests for `isSupported`, `generateKey`, `attestKey`, and `generateAssertion` closures.
- [ ] Implement the live client with the SDK-verified async methods `DCAppAttestService.shared.generateKey()`, `attestKey(_:clientDataHash:)`, and `generateAssertion(_:clientDataHash:)`.
- [ ] Add tests for reading, writing, and deleting only `keyID` through `@Dependency(\.keychain)`.
- [ ] Use the confirmed KeyChain methods `readString(for:)`, `upsert(_:for:)`, and `delete(_:)` with one generic-password query (`account: "app-attest-key-id"`, `service: "AppAttestDevice"`).
- [ ] Map `KeychainError.itemNotFound` to no stored key and preserve all other errors.
- [ ] Run `swift test --filter AppAttestDeviceDependenciesTests`; expect success with fake dependencies.
- [ ] Show the adapter diff; stop for review.

### Task 13: Implement initial device registration

**Files:**

- Create: `Sources/AppAttestDevice/AppAttestTransport.swift`
- Create: `Sources/AppAttestDevice/AppAttestServiceHTTP.swift`
- Create: `Tests/AppAttestDeviceTests/AppAttestRegistrationTests.swift`

- [ ] Add a fake `ClientTransport` that records service calls and returns controlled JSON responses.
- [ ] Add a test proving `isSupported == false` fails locally before Keychain, DeviceCheck mutation, or base transport calls.
- [ ] Add a stored-key test proving no generation or attestation occurs.
- [ ] Add a missing-key test proving the order: generate key, request challenge through the base transport, call `attestKey` with SHA-256 of raw challenge, post attestation, then write the key ID to Keychain only after HTTP `204`.
- [ ] Add failure tests proving no Keychain write occurs when challenge, DeviceCheck attestation, or server validation fails.
- [ ] Implement service requests directly through `Base.send`; do not recursively call the App Attest wrapper and do not add URLSession dependencies.
- [ ] Keep an uncommitted generated key ID in actor memory until the server accepts it.
- [ ] Run `swift test --filter AppAttestRegistrationTests`; expect success.
- [ ] Show the registration flow diff; stop for review.

### Task 14: Sign and serialize protected OpenAPI requests

**Files:**

- Modify: `Sources/AppAttestDevice/AppAttestTransport.swift`
- Create: `Tests/AppAttestDeviceTests/AppAttestTransportTests.swift`

- [ ] Add a test for `ClientTransport.send(_:body:baseURL:operationID:)` proving nil and non-empty bodies are buffered, hashed, rebuilt as `HTTPBody`, and delivered unchanged to the base transport.
- [ ] Add a test proving the transport requests a fresh challenge, uses shared canonical client data, calls `generateAssertion`, and adds exactly the three agreed headers.
- [ ] Add a path/query escaping test shared with the server golden vector.
- [ ] Add a concurrent-call test that suspends the first base request and proves the second request cannot request its challenge until the first completes.
- [ ] Implement a small actor-local FIFO continuation gate around the full protected send. Add `// ponytail: one global gate matches the v1 sequential contract; replace it only when parallel requests are designed.`
- [ ] Collect `HTTPBody` with `Data(collecting:upTo: .max)` and recreate it with `HTTPBody(data)`; this is the explicit non-streaming v1 behavior.
- [ ] Run `swift test --filter AppAttestTransportTests`; expect success.
- [ ] Show the transport diff; stop for review.

### Task 15: Add bounded automatic recovery

**Files:**

- Modify: `Sources/AppAttestDevice/AppAttestTransport.swift`
- Modify: `Sources/AppAttestDevice/AppAttestServiceHTTP.swift`
- Modify: `Sources/AppAttestDevice/AppAttestDeviceError.swift`
- Create: `Tests/AppAttestDeviceTests/AppAttestRecoveryTests.swift`

- [ ] Add a test proving `app_attest_challenge_missing` causes exactly one fresh challenge/assertion attempt.
- [ ] Add a test proving `app_attest_credential_missing` removes the Keychain key, performs one fresh registration, and retries the original request once.
- [ ] Add tests proving `403`, `503`, unsupported-device, Keychain, and DeviceCheck failures are not retried and preserve or remove the local key exactly as agreed.
- [ ] When inspecting an error response, buffer and reconstruct its `HTTPBody` so non-retried responses remain readable by generated OpenAPI code.
- [ ] Implement one explicit retry budget; do not use recursion without a decreasing budget and do not add generic retry/backoff machinery.
- [ ] Run `swift test --filter AppAttestRecoveryTests`; expect success and exact base-call counts.
- [ ] Show the recovery diff; stop for review.

### Task 16: Verify integration and document host usage

**Files:**

- Modify: `docs/architecture/app_attest_integration.md`
- Create: `docs/api/app_attest_vapor.md`
- Create: `docs/api/app_attest_device.md`
- Modify: `docs/INDEX.md`

- [ ] Add a Vapor integration test showing `app.appAttest.configure(...)`, `app.grouped(AppAttestMiddleware())`, and a protected route; prove service routes remain outside the middleware.
- [ ] Add a compile-focused example showing `VaporTransport(routesBuilder: protectedRoutes)` without adding `swift-openapi-vapor` to this package.
- [ ] Add a compile-focused device example showing `AppAttestTransport(base: URLSessionTransport())` without adding `swift-openapi-urlsession` to this package.
- [ ] Document the four host credential closures and include a PostgreSQL-style atomic `UPDATE ... WHERE counter < newCounter` example without adding Fluent or a schema.
- [ ] Document Valkey configuration, the default route prefix, 60-second TTL, stable error codes, sequential requests, and unsupported macOS 26 behavior.
- [ ] Use the `librarian` skill to update the documentation index and lint the changed docs.
- [ ] Run `swift test` on macOS, `swift build --product AppAttestVapor`, `xcodebuild -scheme AppAttestDevice -destination 'generic/platform=iOS' build`, and `git diff --check`.
- [ ] Confirm there are no live Apple calls in tests, no streaming implementation, no user ID, no receipt persistence, and no v27-only checks.
- [ ] Show the final verification output and full diff; stop for review before any release or commit action.

## Completion Criteria

- A host Vapor server can configure the package, register its two service routes, and protect only selected route groups, including a Swift OpenAPI `VaporTransport` group.
- A generated OpenAPI client can wrap any `ClientTransport`, perform initial attestation once, store only the accepted key ID in Keychain, and serialize protected requests.
- Invalid, replayed, or stale assertions never reach the downstream handler.
- Challenges expire in Valkey after 60 seconds; public keys and counters are accessed only through the host's durable dependency.
- Counter advancement is atomic at the host persistence boundary.
- Every security check has a deterministic offline test.
