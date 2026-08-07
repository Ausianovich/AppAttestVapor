# App Attest Validation Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add stage-specific App Attest diagnostics through OSLog on Apple devices and request-scoped SwiftLog on the Linux Vapor server.

**Architecture:** Vapor code uses a tiny internal `Logger` extension to attach consistent `component` and `stage` metadata without exposing proof data. Validators receive the existing request logger so deep parsing, certificate, signature, identity, and counter failures retain the Vapor request ID. `AppAttestDevice` uses one native OSLog logger and tracks the current registration/request stage without adding dependencies or a logger abstraction.

**Tech Stack:** Swift 6.3, Swift Testing, Vapor 4 / SwiftLog, OSLog, modern Swift concurrency

## Global Constraints

- Work in the current branch; do not create a worktree or branch.
- Do not add production dependencies.
- Never log `keyID`, challenge, attestation object, assertion, public key, signed body, request body, or their hashes.
- Successful boundaries use `debug`; failures use `error`.
- HTTP responses, retry behavior, persistence behavior, and public APIs remain unchanged.
- Use `async`/`await`; do not add GCD.

---

### Task 1: Server validation-stage logging

**Files:**
- Create: `Sources/AppAttestVapor/AppAttestLogger.swift`
- Modify: `Sources/AppAttestVapor/AppAssertionVerifier.swift`
- Modify: `Sources/AppAttestVapor/AppAttestationVerifier.swift`
- Create: `Tests/AppAttestVaporTests/TestLogRecorder.swift`
- Modify: `Tests/AppAttestVaporTests/AppAssertionVerifierTests.swift`

**Interfaces:**
- Produces: `Logger.appAttestDebug(stage:)` and `Logger.appAttestError(stage:error:)` internal helpers.
- Produces: optional `Logger` inputs on both verifier types; existing call sites remain source-compatible through default `nil` values where practical.

- [x] **Step 1: Write the failing stage-log test**

Add a real SwiftLog `LogHandler` backed by `Synchronization.Mutex`, then inject its logger into `AppAssertionVerifier`:

```swift
@Test
func logsMalformedAssertionStage() {
    let logs = TestLogRecorder()
    let verifier = AppAssertionVerifier(
        configuration: assertionConfiguration,
        logger: logs.logger
    )

    #expect(throws: AppAssertionError.invalidAssertion) {
        try verifier.verify(
            assertionObject: Data([0xFF]),
            publicKey: fixedPrivateKey.publicKey.x963Representation,
            clientData: clientData,
            storedCounter: 4
        )
    }
    #expect(logs.entries.contains { entry in
        entry.level == .error && entry.metadata?["stage"] == "assertion-object"
    })
}
```

- [x] **Step 2: Verify RED**

Run: `swift test --filter logsMalformedAssertionStage`

Expected: compile failure because the verifier has no `logger` parameter and no log entry exists.

- [x] **Step 3: Add minimal server logging primitives and validator stages**

Implement fixed-message helpers with metadata only:

```swift
extension Logger {
    func appAttestDebug(stage: String) {
        debug("App Attest stage succeeded", metadata: [
            "component": "app-attest",
            "stage": "\(stage)",
        ])
    }

    func appAttestError(stage: String, error: (any Error)? = nil) {
        var metadata: Logger.Metadata = [
            "component": "app-attest",
            "stage": "\(stage)",
        ]
        if let error {
            metadata["error_type"] = "\(String(reflecting: type(of: error)))"
        }
        self.error("App Attest stage failed", metadata: metadata)
    }
}
```

In each verifier, update a local `stage` immediately before every parsing or validation operation, log the caught error type, then preserve the existing generic thrown error. Split combined semantic guards so stages distinguish signature, App ID, counter, public-key hash, AAGUID, and credential ID failures.

- [x] **Step 4: Verify GREEN**

Run: `swift test --filter 'AppAssertionVerifierTests|AppAttestationVerifierTests'`

Expected: all selected tests pass and the new test sees `stage=assertion-object`.

### Task 2: Vapor route and middleware boundaries

**Files:**
- Modify: `Sources/AppAttestVapor/AppAttestMiddleware.swift`
- Modify: `Sources/AppAttestVapor/AppAttestRoutes.swift`
- Modify: `Tests/AppAttestVaporTests/AppAttestationRouteTests.swift`

**Interfaces:**
- Consumes: `Logger.appAttestDebug(stage:)` and `Logger.appAttestError(stage:error:)`.
- Modifies internal `AppAttestationVerificationClient.verify` to receive the request logger and pass it to the live verifier.

- [x] **Step 1: Write a failing request-boundary log test**

Inject `TestLogRecorder.logger` into the Vapor test application and assert a malformed attestation produces an error entry with `stage=attestation-request` while preserving the existing 403 response.

- [x] **Step 2: Verify RED**

Run: `swift test --filter attestationRouteLogsMalformedRequestStage`

Expected: test fails because the route emits no App Attest log entry.

- [x] **Step 3: Log each existing branch without changing control flow**

Before every current error response, emit one `appAttestError` with the branch stage and only the caught error type. After challenge issuance, attestation persistence, and middleware assertion/counter completion, emit `appAttestDebug`. Pass `request.logger` into both live validators so deep validation logs share the request ID.

- [x] **Step 4: Verify GREEN**

Run: `swift test --filter 'AppAttestMiddlewareTests|AppAttestationRouteTests|AppAttestChallengeRouteTests'`

Expected: selected route and middleware tests pass with unchanged HTTP expectations.

### Task 3: Device OSLog stages

**Files:**
- Modify: `Sources/AppAttestDevice/AppAttestTransport.swift`

**Interfaces:**
- Consumes: native `OSLog.Logger` only.
- Preserves: `AppAttestTransport` public initializer and `ClientTransport.send` behavior.

- [x] **Step 1: Add the native logger and stage tracking**

Create one private logger using the host bundle identifier fallback:

```swift
private let appAttestLogger = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "AppAttestDevice",
    category: "validation"
)
```

Track a static stage name around support checks, Keychain access, key generation, challenge retrieval, Apple attestation/assertion generation, server attestation, protected transport, response inspection, and bounded recovery. Log successful boundaries at `debug`; on catch log only public stage and error type, then rethrow the unchanged error.

- [x] **Step 2: Verify device behavior and compile OSLog interpolation**

Run: `swift test --filter AppAttestDeviceTests`

Expected: all device tests pass; OSLog calls compile on the package's Apple platform targets.

### Task 4: Full verification and commit

**Files:**
- Verify all modified source, test, and documentation files.

- [x] **Step 1: Run documentation and diff checks**

Run:

```bash
swift /Users/kanstantsinausianovich/.codex/skills/librarian/scripts/lint_docs.swift . --json
git diff --check
```

Expected: zero documentation findings and no whitespace errors.

- [x] **Step 2: Run the complete package suite**

Run: `swift test`

Expected: all package tests pass with zero failures.

- [x] **Step 3: Commit implementation in the current branch**

```bash
git add Sources/AppAttestDevice/AppAttestTransport.swift Sources/AppAttestVapor Tests/AppAttestVaporTests docs/superpowers/plans/2026-08-07-app-attest-validation-logging.md
git commit -m "feat: log App Attest validation stages"
```
