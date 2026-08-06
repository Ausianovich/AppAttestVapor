import AppAttestCore
import Vapor

enum AppAttestError: Error {
    case invalid
    case invalidProof
    case challengeMissing
    case credentialMissing
    case unavailable

    private var status: HTTPStatus {
        switch self {
        case .invalid:
            .badRequest
        case .invalidProof:
            .forbidden
        case .challengeMissing, .credentialMissing:
            .unauthorized
        case .unavailable:
            .serviceUnavailable
        }
    }

    private var code: String {
        switch self {
        case .invalid, .invalidProof:
            "app_attest_invalid"
        case .challengeMissing:
            "app_attest_challenge_missing"
        case .credentialMissing:
            "app_attest_credential_missing"
        case .unavailable:
            "app_attest_unavailable"
        }
    }

    func response() throws -> Response {
        let response = Response(status: status)
        try response.content.encode(AppAttestErrorResponse(code: code), as: .json)
        return response
    }
}
