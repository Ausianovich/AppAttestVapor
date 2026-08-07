// App Attest end-to-end flow.
// 1. Client registration
let routePrefix = "/app-attest"
let isFeatureAvailable = true

// 2. Challenge -> attestation -> Keychain key ID persistence
// 3. Every protected request signs: method + path/query + body hash + challenge
// 4. Middleware verifies proof and advances monotonic counter
let sequence = [
    "POST /app-attest/challenge",
    "POST /app-attest/attestation",
    "Protected request with X-App-Attest-* headers",
]
print(sequence)
