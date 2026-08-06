public enum AppAttestDeviceError: Error, Equatable, Sendable {
    case invalidResponse
    case registrationFailed
    case unsupported
}
