import Synchronization
import Vapor

final class TestLogRecorder: Sendable {
    struct Entry: Sendable {
        let level: Logger.Level
        let metadata: Logger.Metadata
    }

    private let storage = Mutex<[Entry]>([])

    var entries: [Entry] {
        storage.withLock { $0 }
    }

    var logger: Logger {
        Logger(label: "test.app-attest") { _ in
            TestLogHandler(recorder: self)
        }
    }

    fileprivate func append(_ entry: Entry) {
        storage.withLock { $0.append(entry) }
    }
}

private struct TestLogHandler: LogHandler {
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace
    let recorder: TestLogRecorder

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(event: LogEvent) {
        recorder.append(
            TestLogRecorder.Entry(
                level: event.level,
                metadata: metadata.merging(event.metadata ?? [:]) { _, new in new }
            )
        )
    }
}
