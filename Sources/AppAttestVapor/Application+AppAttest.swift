import Vapor

extension Application {
    public var appAttest: AppAttest {
        AppAttest(application: self)
    }

    public struct AppAttest: Sendable {
        private struct ConfigurationKey: StorageKey {
            typealias Value = AppAttestConfiguration
        }

        private let application: Application

        fileprivate init(application: Application) {
            self.application = application
        }

        public func configure(_ configuration: AppAttestConfiguration) {
            application.storage[ConfigurationKey.self] = configuration
            AppAttestRoutes.register(
                on: application,
                configuration: configuration
            )
        }

        var configuration: AppAttestConfiguration? {
            application.storage[ConfigurationKey.self]
        }
    }
}
