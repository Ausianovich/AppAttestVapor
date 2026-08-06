import AppAttestCore
import Foundation
import HTTPTypes
import OpenAPIRuntime

struct AppAttestServiceHTTP<Base: ClientTransport>: Sendable {
    let base: Base
    let routePrefix: String

    func challenge(keyID: String, baseURL: URL) async throws -> Challenge {
        let payload = AppAttestChallengeRequest(keyID: keyID)
        let (response, body) = try await send(
            path: "\(routePrefix)/challenge",
            payload: payload,
            baseURL: baseURL,
            operationID: "appAttestChallenge"
        )
        guard response.status == .ok else {
            throw AppAttestDeviceError.registrationFailed
        }
        guard let body else {
            throw AppAttestDeviceError.invalidResponse
        }

        let responseData = try await Data(collecting: body, upTo: .max)
        let responsePayload: AppAttestChallengeResponse
        do {
            responsePayload = try JSONDecoder().decode(
                AppAttestChallengeResponse.self,
                from: responseData
            )
        } catch {
            throw AppAttestDeviceError.invalidResponse
        }
        guard
            let data = Data(base64Encoded: responsePayload.challenge),
            data.count == 32
        else {
            throw AppAttestDeviceError.invalidResponse
        }
        return Challenge(encoded: responsePayload.challenge, data: data)
    }

    func attest(
        keyID: String,
        challenge: String,
        attestationObject: Data,
        baseURL: URL
    ) async throws {
        let payload = AppAttestAttestationRequest(
            keyID: keyID,
            challenge: challenge,
            attestationObject: attestationObject.base64EncodedString()
        )
        let (response, _) = try await send(
            path: "\(routePrefix)/attestation",
            payload: payload,
            baseURL: baseURL,
            operationID: "appAttestAttestation"
        )
        guard response.status == .noContent else {
            throw AppAttestDeviceError.registrationFailed
        }
    }

    func inspect(
        response: HTTPResponse,
        body: HTTPBody?
    ) async throws -> (recovery: AppAttestDeviceError?, body: HTTPBody?) {
        guard response.status.code >= 400, let body else {
            return (nil, body)
        }
        let data = try await Data(collecting: body, upTo: .max)
        let rebuiltBody = HTTPBody(data)
        guard
            response.status == .unauthorized,
            let error = try? JSONDecoder().decode(
                AppAttestErrorResponse.self,
                from: data
            )
        else {
            return (nil, rebuiltBody)
        }

        switch error.code {
        case "app_attest_challenge_missing":
            return (.challengeMissing, rebuiltBody)
        case "app_attest_credential_missing":
            return (.credentialMissing, rebuiltBody)
        default:
            return (nil, rebuiltBody)
        }
    }

    private func send<Payload: Encodable>(
        path: String,
        payload: Payload,
        baseURL: URL,
        operationID: String
    ) async throws -> (HTTPResponse, HTTPBody?) {
        var request = HTTPRequest(
            method: .post,
            scheme: nil,
            authority: nil,
            path: path
        )
        request.headerFields[.contentType] = "application/json"
        return try await base.send(
            request,
            body: HTTPBody(try JSONEncoder().encode(payload)),
            baseURL: baseURL,
            operationID: operationID
        )
    }

    struct Challenge: Sendable {
        let encoded: String
        let data: Data
    }
}
