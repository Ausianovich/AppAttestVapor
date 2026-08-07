import Vapor

extension Logger {
    func appAttestDebug(stage: String) {
        debug(
            "App Attest stage succeeded",
            metadata: [
                "component": "app-attest",
                "stage": "\(stage)",
            ]
        )
    }

    func appAttestError(
        stage: String,
        error: (any Error)? = nil,
        metadata additionalMetadata: Logger.Metadata = [:]
    ) {
        var metadata: Logger.Metadata = additionalMetadata.merging([
            "component": "app-attest",
            "stage": "\(stage)",
        ]) { _, value in value }
        if let error {
            metadata["error_type"] = "\(String(reflecting: type(of: error)))"
        }
        self.error("App Attest stage failed", metadata: metadata)
    }
}
