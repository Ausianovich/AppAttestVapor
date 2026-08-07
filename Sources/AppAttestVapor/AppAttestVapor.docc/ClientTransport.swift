import AppAttestDevice
import OpenAPIURLSession
import OpenAPIRuntime

let transport = AppAttestTransport(base: URLSessionTransport())
let client = Client(
    serverURL: URL(string: "https://api.example.com")!,
    transport: transport
)

// The first protected call triggers registration + attestation.
// Repeated calls reuse the stored keyID and generate assertions per request.
Task {
    // let response = try await client.getPrivate()
    print("Use generated client transport in all protected calls")
}
