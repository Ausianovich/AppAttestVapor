import Foundation
import Testing
import VaporTesting
@testable import AppAttestVapor

@Test
func configurationUsesServiceDefaults() {
    let configuration = AppAttestConfiguration(
        teamID: "TEAMID",
        bundleID: "com.example.app",
        environment: .production
    )

    #expect(configuration.routePrefix == "/app-attest")
    #expect(configuration.challengeTTL == 60)
    #expect(configuration.environment == .production)
}

@Test
func configurationSupportsDevelopmentEnvironment() {
    let configuration = AppAttestConfiguration(
        teamID: "TEAMID",
        bundleID: "com.example.app",
        environment: .development
    )

    #expect(configuration.environment == .development)
}

@Test
func applicationStoresConfiguration() async throws {
    let configuration = AppAttestConfiguration(
        teamID: "TEAMID",
        bundleID: "com.example.app",
        environment: .production,
        routePrefix: "/security",
        challengeTTL: 30
    )

    try await withApp { app in
        app.appAttest.configure(configuration)

        #expect(app.appAttest.configuration == configuration)
    }
}

@Test
func missingCredentialImplementationThrowsUnavailable() async {
    let client = AppAttestCredentialClient.liveValue

    await #expect(throws: AppAttestCredentialError.unavailable) {
        try await client.saveCredential("key", Data(), 0)
    }
    await #expect(throws: AppAttestCredentialError.unavailable) {
        try await client.getPublicKey("key")
    }
    await #expect(throws: AppAttestCredentialError.unavailable) {
        try await client.getCounter("key")
    }
    await #expect(throws: AppAttestCredentialError.unavailable) {
        try await client.advanceCounter("key", 1)
    }
}
