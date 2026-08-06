public enum AppAttestDeviceError: Error, Equatable, Sendable {
    case challengeMissing
    case credentialMissing
    case invalidResponse
    case registrationFailed
    case unsupported
}
