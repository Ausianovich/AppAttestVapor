import AppAttestCore
import Vapor

enum AppAttestError: Error {
    case invalid
    case unavailable

    private var status: HTTPStatus {
        switch self {
        case .invalid:
            .badRequest
        case .unavailable:
            .serviceUnavailable
        }
    }

    private var code: String {
        switch self {
        case .invalid:
            "app_attest_invalid"
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
