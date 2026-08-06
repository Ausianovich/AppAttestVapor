public struct AppAttestConfiguration: Equatable, Sendable {
    public enum Environment: Equatable, Sendable {
        case development
        case production
    }

    public let teamID: String
    public let bundleID: String
    public let environment: Environment
    public let routePrefix: String
    public let challengeTTL: Int

    public init(
        teamID: String,
        bundleID: String,
        environment: Environment,
        routePrefix: String = "/app-attest",
        challengeTTL: Int = 60
    ) {
        self.teamID = teamID
        self.bundleID = bundleID
        self.environment = environment
        self.routePrefix = routePrefix
        self.challengeTTL = challengeTTL
    }
}
