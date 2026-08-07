// Explicit request lifecycle for review and testing.
let flow: [(String, String)] = [
    ("client", "load keyID from keychain"),
    ("client", "POST /app-attest/challenge"),
    ("client", "POST /app-attest/attestation with attestationObject"),
    ("server", "verify attestation and persist publicKey + counter"),
    ("client", "POST protected request with assertion headers"),
    ("server", "verify signature, challenge, and counter"),
    ("server", "advance counter atomically"),
    ("server", "invoke protected handler"),
]

for step in flow { print(step) }
