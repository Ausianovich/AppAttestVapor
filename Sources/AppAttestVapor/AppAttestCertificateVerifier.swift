import Crypto
import Foundation
import X509

struct AppAttestVerifiedCertificate: Sendable {
    let publicKey: P256.Signing.PublicKey
    let publicKeyX963: Data
}

struct AppAttestCertificateVerifier: Sendable {
    private let rootCertificates: CertificateStore

    init() throws {
        try self.init(rootCertificate: Self.appleRootCertificateData())
    }

    init(rootCertificate data: Data) throws {
        guard let pem = String(data: data, encoding: .utf8) else {
            throw AppAttestCertificateError.invalidCertificate
        }
        do {
            rootCertificates = CertificateStore([try Certificate(pemEncoded: pem)])
        } catch {
            throw AppAttestCertificateError.invalidCertificate
        }
    }

    func verify(
        certificateChain: [Data],
        expectedNonce: Data
    ) async throws -> AppAttestVerifiedCertificate {
        guard let leafData = certificateChain.first else {
            throw AppAttestCertificateError.invalidCertificateChain
        }

        let leaf: Certificate
        let intermediates: [Certificate]
        do {
            leaf = try Certificate(derEncoded: Array(leafData))
            intermediates = try certificateChain.dropFirst().map {
                try Certificate(derEncoded: Array($0))
            }
        } catch {
            throw AppAttestCertificateError.invalidCertificate
        }

        var verifier = Verifier(rootCertificates: rootCertificates) {
            RFC5280Policy()
        }
        guard case .validCertificate = await verifier.validate(
            leaf: leaf,
            intermediates: CertificateStore(intermediates)
        ) else {
            throw AppAttestCertificateError.invalidCertificateChain
        }

        guard try AppAttestNonceExtension.parse(from: leaf) == expectedNonce else {
            throw AppAttestCertificateError.nonceMismatch
        }
        guard let publicKey = P256.Signing.PublicKey(leaf.publicKey) else {
            throw AppAttestCertificateError.unsupportedPublicKey
        }
        let publicKeyX963 = Data(publicKey.x963Representation)
        guard publicKeyX963.count == 65 else {
            throw AppAttestCertificateError.unsupportedPublicKey
        }
        return AppAttestVerifiedCertificate(
            publicKey: publicKey,
            publicKeyX963: publicKeyX963
        )
    }

    static func appleRootCertificateData() throws -> Data {
        guard let url = Bundle.module.url(
            forResource: "Apple_App_Attestation_Root_CA",
            withExtension: "pem"
        ) else {
            throw AppAttestCertificateError.invalidCertificate
        }
        return try Data(contentsOf: url)
    }
}
