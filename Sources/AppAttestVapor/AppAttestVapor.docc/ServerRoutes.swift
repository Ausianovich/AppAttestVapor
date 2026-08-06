import AppAttestVapor
import Vapor

func routes(_ app: Application) throws {
    app.get("health") { _ in
        "OK"
    }

    let protected = app.grouped(AppAttestMiddleware())
    protected.get("private") { _ in
        "Protected response"
    }
}
